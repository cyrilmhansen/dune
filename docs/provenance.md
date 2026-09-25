# Semantic provenance v0

`Analysis.Provenance` is a live shadow analysis beside the concrete CPU. It
consumes each successful `Step`, uses its recorded memory accesses as the
authoritative dynamic addresses, and never writes concrete state. The arena
contains immutable nodes addressed by integer IDs; shadow registers, flags and
64 KiB memory cells hold a concrete shadow value and either a node reference or
`Untracked`.

Source leaves identify where a value entered the observed computation:

- `File_byte` carries CP/M drive, user, canonical filename, logical byte offset
  and value. Each successful BDOS READ injects leaves at DMA memory, including
  overlay and temporary-file records.
- `Command_tail_byte` records a command-tail offset and value. Callers can also
  map a command-tail range to derived launch memory such as default FCB name
  bytes.
- `Initial_memory_byte` distinguishes system, runner and unclassified initial
  bytes. Deterministic initial registers use `Initial_register`.
- `External_result` represents BDOS register/FCB updates, I/O input, and
  explicitly reconciled host values.

Operation nodes carry a semantic operation tag, concrete result and width,
CPU step index, optional stable producer coordinate
`{image, file offset, runtime PC}`, and typed input edges. `Value`, `Address`
and `Flag` are separate roles; `Control` is reserved for a later control-
dependence milestone and is not emitted in v0. Conditional branch observations
retain step, PC, condition, taken/target result, and the consumed flag root, but
do not add that flag as a dependency of later values. Pure register copies such as
`MOV B,C` alias the existing root. Loads, stores, arithmetic, flags, stack
transfers, and address-sensitive memory operations create semantic nodes.
Address roots remain distinct from the selected memory byte's value root.

Every instruction transfer is checked against the post-instruction register
and flag snapshot. Independently computed byte results and every recorded CPU
memory write are checked too; disagreement raises `Provenance_error` with the
step, opcode, location, predicted value and concrete value. The evaluator
covers the currently decoded opcode space, including EI/DI. It does not
re-execute or change an instruction.

BDOS is outside the CPU. Runner therefore exposes live BDOS record events and
factual external effects. A successful READ replaces shadow cells at the DMA
range with file-byte leaves. Register return aliases and guest-visible FCB
updates become explicit external-result leaves, including same-value writes
to fields a service defines as outputs. A successful WRITE snapshots all 128
bytes' current roots into an output history keyed by CP/M file and logical
offset. Rewrites are retained as ordered observations; deleting an INT file
does not erase its historical writes. If a DMA byte has no current root, the
sink records an explicitly classified initial/unclassified or external
reconciliation leaf rather than leaving a missing output root.

For a selected output root, `slice` returns the reachable DAG in deterministic
node-ID order. `source_leaves`, `producer_nodes`, and `source_summary` provide
typed queries without exposing hash-table internals. `slice_json` /`write_slice_json`
emit a deterministic, selected-slice export headed `RUNES_PROVENANCE_SLICE 1`;
it includes sink observations, source identities, typed edges and producer
coordinates, never the complete run history by default.

Execution Map and provenance answer different questions. Execution Map records
whether runtime memory still corresponds to an image byte; a CPU write makes
that image origin `Unknown`. Provenance instead records what produced the
current data value. Thus the same byte can have unknown image origin while its
shadow root is a `Store8` operation. A CP/M READ can establish both an image
origin and a provenance file leaf, but the maps remain independent.

There are no branch-predicate dependencies in v0. A conditional branch's flag
provenance is retained, but values later computed on the selected path do not
yet acquire a `Control` edge. This is a single concrete run, not path forking,
SMT, taint, full provenance, or a complete semantic slice. An unobserved byte
or instruction is not thereby dead. CPU PC itself has no ordinary value root;
producer step and image coordinates are metadata.

## Small example

For a seeded COM containing `MVI A,41h; ADI 01h; STA 0200h`, the byte at
`0200h` has a root of the form:

```text
Store8(value -> ALU.ADD(value -> MVI(value -> File_byte(COM, immediate)),
                        value -> File_byte(COM, ADI immediate)),
       address -> File_byte(COM, STA low/high address bytes))
```

The operation nodes retain their dynamic step and producer image/file
coordinates. The two address bytes are not merged into the stored-value path.

## First `PLI OPTIMIST` measurement

Using the local, untracked PL/I-80 v1.4 files, the parallel analyses completed
the established run with **2,535,509 CPU steps**, both passes reporting no
errors, and `END COMPILATION`. Execution Map still attributed 2,533,573 steps;
the other 1,936 were the synthetic RET at the runner's BDOS entry. Provenance
created **6,632,716 nodes / 12,200,515 typed edges** in this run. `/usr/bin/time`
reported 9.32 seconds wall, 8.50 seconds user CPU and 2,332,468 KiB peak RSS
for the Dune invocation on this host, including backward-slice construction
and selected JSON exports. This is a substantial v0 memory cost and should be
re-measured/optimized before scaling far beyond this workload. The engine
stores aggregate shadow state and DAG nodes, not the 2.5 million `Step` objects.

The generated `OPTIMIST.REL` was 1,408 bytes, SHA-256
`5fca1ffe38d11c30d20cfb99a23fe2baf002c569790bda83e09151cf36032b15`,
byte-identical to the accepted reference; `OPTIMIST.INT` was absent at
termination. All 1,408 final REL bytes had explicit roots, none were untracked,
and none were rewritten. Sample final-byte observations:

| REL offset | Value | Write step | Slice nodes | Producer nodes | Source leaves |
|---:|---:|---:|---:|---:|---:|
| `0000h` | `85h` | 840,539 | 12,020 | 11,983 | 37 |
| `02C0h` | `48h` | 1,987,517 | 241,984 | 241,123 | 861 |
| `057Fh` | `00h` | 2,533,978 | 295,853 | 294,253 | 1,600 |

Across those three slices, the distinct file source bytes were `OPTIMIST.PLI`
(51), `PLI.COM` (232), `PLI0.OVL` (616), `PLI1.OVL` (592), `PLI2.OVL` (404),
and the subsequently deleted `OPTIMIST.INT` (4). Two initial-memory bytes
also appeared. No command-tail leaf occurred in those sampled output slices;
that is an observation about these selected bytes, not a claim that command
tails cannot influence other runs. File identity keeps compiler input,
compiler code/overlays and intermediate data distinct.

The map retained the overlapping overlay identities and measured their first
executions at runtime `2200h`, file offset `0000h`: PLI0 at step 14,310; PLI1
at 670,277; PLI2 at 1,663,710. Their image sizes and execution totals remain
the Execution Map report's responsibility; this provenance layer only uses
its optional stable instruction-origin resolver.

The persistent AT8TRACE v1 format is unchanged. Provenance is live state and
selected-slice export; no attempt is made to reconstruct it later from AT8TRACE.

## Provenance Explorer v0

`Analysis.Provenance_report` projects caller-selected final output-byte roots
from the exact arena without materializing another verbose full slice. The
versioned `RUNES_PROVENANCE_REPORT 1` JSON contains complete output-byte
metadata, but embeds compact source/producer/operation aggregates and a
bounded exact neighborhood only for explicitly selected sinks. The caller
can regenerate a projection for any output offset; an unselected byte is
metadata-only in an existing static bundle. The existing
`RUNES_PROVENANCE_SLICE 1` export is unchanged.

The report distinguishes:

* a static producer location (`image + file offset + runtime PC`) from the
  distinct dynamic producer steps observed there;
* operation-node count from producer-step count (one instruction may emit
  multiple semantic nodes);
* distinct source byte offsets from source-leaf node occurrences (the same
  file byte may be read into memory more than once);
* source file offset from its optional linear virtual offset in the ordered
  Execution Report image space.

Source classifications such as `program input`, `intermediate`, `program
image`, and `output` are caller-supplied presentation metadata. They do not
change source identity or provenance semantics. Exact source offsets remain
available in JSON and are compressed into contiguous ranges for display.

The offline explorer has three complementary visualization primitives:

* the custom linear byte heatmap retains image/file coordinate space and can
  switch among execution heat, slice participation, distinct producer-step
  density, Value/Address/Flag edge densities, and source influence;
* Perspective (`@perspective-dev/*` 5.5.1, Apache-2.0) provides virtualized,
  grouped/sortable/filterable tables for producers, source leaves and ranges,
  operations, and output-byte metadata;
* G6 (`@antv/g6` 5.1.1, MIT) displays only the bounded exact neighborhood,
  grouped/collapsible by source/operation, image, producer location, and
  operation kind. Typed Value, Address, Flag, and Control edges have separate
  colors. It never receives the full historical slice.

The static report bundle includes its own JavaScript, CSS, Perspective WASM,
G6 code, and generated report JSON; no CDN or network resource is used. Build
the reproducible frontend with `npm ci && npm run build` in
`tools/provenance-explorer`. Place `provenance-report.json` beside the built
`provenance-explorer.html` and serve that directory locally (for example,
`python3 -m http.server`) because browser WASM loading is not generally
permitted from `file://`. This local server does not require network access.

The exact DAG preview defaults to depth 6 and at most 250 nodes. Its displayed
omitted-frontier count makes truncation explicit; the preview is not the
whole slice. Perspective tables and the G6 neighborhood are projections,
never replacements for the exact arena or selected-slice export. For the
three historical REL samples, producer locations compress 12,020, 241,984
and 295,853 slice nodes to 308, 3,482 and 4,346 static locations; the three
bounded graph instances contain fewer than 50 nodes each. Execution heat and
provenance participation/density are separate measures. The historical
Control-edge counts are zero: branch flag observations do not make later
values control-dependent. A provenance slice is exact for the observed
execution, but it is not a counterfactual causal proof.

### Historical explorer measurement

The explorer was generated from the same successful local `PLI OPTIMIST`
run (2,535,509 CPU steps; 1,408-byte `OPTIMIST.REL`, SHA-256
`5fca1ffe38d11c30d20cfb99a23fe2baf002c569790bda83e09151cf36032b15`; all
final output bytes had roots). The ordered linear image ranges were computed,
not hard-coded:

| Image | Virtual range (half-open) | Span | Unique fetched / known |
|---|---:|---:|---:|
| `PLI.COM` | `00000h–01F80h` | 8,064 | 4,034 / 8,064 (50.02%) |
| `PLI0.OVL` | `01F80h–06600h` | 18,048 | 7,181 / 18,048 (39.79%) |
| `PLI1.OVL` | `06600h–0EE00h` | 34,816 | 15,317 / 34,816 (43.99%) |
| `PLI2.OVL` | `0EE00h–17200h` | 33,792 | 10,127 / 33,792 (29.97%) |

The ranges are analysis coordinates, not physical memory. Each overlay first
executed at runtime `2200h`, file offset `0000h`; first execution steps were
14,310 (`PLI0.OVL`), 670,277 (`PLI1.OVL`) and 1,663,710 (`PLI2.OVL`).

| REL byte | Value | Write step | Raw slice nodes / source leaves | Static producers / producer steps | Value / Address / Flag / Control edges | Preview nodes / edges / omitted |
|---:|---:|---:|---:|---:|---:|---:|
| `0000h` | `85h` | 840,539 | 12,020 / 37 | 308 / 11,265 | 394 / 11,843 / 1 / 0 | 40 / 43 / 7 |
| `02C0h` | `48h` | 1,987,517 | 241,984 / 861 | 3,482 / 208,230 | 68,423 / 230,947 / 188 / 0 | 38 / 41 / 10 |
| `057Fh` | `00h` | 2,533,978 | 295,853 / 1,600 | 4,346 / 253,228 | 89,335 / 282,239 / 227 / 0 | 38 / 41 / 10 |

The raw-operation-node to static-producer-location compression is about
39.0:1, 69.5:1 and 68.1:1 for those sinks. At `02C0h`, the 13
`OPTIMIST.PLI` leaves occupy five ranges (`003Ah–003Dh`, `00DBh–00DCh`,
`016Eh`, `029Dh–02A0h`, `0402h–0403h`). At `057Fh`, 1,600 file/initial leaf
occurrences reduce to 1,592 distinct source offsets; `OPTIMIST.PLI` has 46
distinct bytes in 54 occurrences, demonstrating why both counts are retained.

Perspective loaded five tables (producer, source leaf, operation, source
range, output-byte metadata): row counts were respectively 308/37/30/23/1,408
for `0000h`, 3,482/861/46/503/1,408 for `02C0h`, and
4,346/1,600/48/884/1,408 for `057Fh`. Group-by, sort, filtering, and virtual
scrolling were smoke-tested. G6 received only the bounded preview: respectively
40/43, 38/41 and 38/41 node/edge pairs, with grouped combos; never the
241,984- or 295,853-node full slices. Switching selected sinks, edge-role
heat modes, producer/table selections and graph selections was smoke-tested in
local Chromium. The three role maps can differ while retaining their own raw
counts. No external requests were made.

Projection of all three slices took about 0.95 s of process CPU; JSON writing
took about 0.05 s and produced 9,173,753 bytes. The HTML is 2,893 bytes and
the generated static JS/CSS/WASM plus JSON bundle was about 15 MB (bundle size
varies slightly with pinned Vite output hashes). The historical test process
reported about 3.7 s for run/provenance construction; peak RSS was 2,390,108
KiB (~2.28 GiB), about 2.5% above the earlier 2,332,468 KiB provenance-only
measurement. This remains a material memory cost. The UI keeps only compact
selected projections, not multiple full slice copies.
