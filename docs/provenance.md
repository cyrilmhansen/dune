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
