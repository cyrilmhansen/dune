# Runes annotated assembly V0

These four sources accumulate reconstruction of the historical Digital Research
PL/I-80 v1.4 compiler. The historical binaries remain the authority. Verification
requires originals supplied separately; it never reconstructs its oracle from
these sources. No binaries or runtime reports need to be added to the repository.

## Verify and test

Prerequisites: Python 3, Node.js (tested with v26.10.0), npm, and the four original
images in one directory. Tests additionally use Linux `sha256sum`.
Install the single pinned assembler dependency once:

```sh
npm ci --prefix tools/annotated-assembly --ignore-scripts --no-audit --no-fund
```

One command verifies all images, section hashes, full-image hashes, exact byte
equality, manifest partitions, evidence bytes, and source/runtime mappings:

```sh
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
```

On this lab machine, the historical directory is
`/home/john/pli/cpm/pli80/DISK1`. A discrepancy exits nonzero with
`VERIFICATION FAILED` and the affected image/range or source line. It does not
rewrite sources, hashes, or the manifest to make a discrepancy pass.

Run the bounded infrastructure tests against the same independent originals:

```sh
python3 tools/annotated-assembly/test_verify.py --images /path/to/DISK1 -v
```

The tests cover all four round trips, one-byte corruption of a source and an
original, gaps/overlaps, source layout gaps, stable labels/runtime bases,
independent `sha256sum` checks of every section, forged section hashes with
unchanged full images, evidence stack-byte matching, and preservation of RAW
branches. Historical-image tests are separate from `dune runtest` because the
originals are external fixtures, not repository dependencies.

To regenerate the compact durable reports after intentional status changes:

```sh
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1 --write-progress
```

[progress.md](progress.md) and [progress.json](progress.json) contain byte counts
and percentages in mutually exclusive statuses. These measure reconstruction,
not dynamic execution coverage. They are generated only after verification
succeeds. Assembly runs entirely in memory; no reconstructed binary, cache,
listing, or report is placed in `/tmp`. Tests use small automatically cleaned
`/tmp/atlas-annotated-assembly-test-*` directories.

## Coordinates and manifest

`manifest.json` schema version 1 stores an ordered list of four images, each
with its exact SHA-256, descriptive historical version, byte length, source,
original filename, runtime base, stable-label prefix, and ordered sections.
Identity is **image SHA-256 + file offset**. Filenames and semantic aliases alone
are insufficient to identify a version.

All offsets are integers in JSON. Ranges are **start inclusive, end exclusive**;
length is `end_offset - start_offset`. Every image's sections partition
`[0, image.length)` with no overlaps or gaps. Each section retains image SHA-256,
start/end offsets, length, status, original/reassembled slice SHA-256,
`exact_match`, runtime start/end, and evidence references. References such as
`evidence.json#seeds/PLI2.OVL+7701` identify the seed by its `id` field, not by
its position in the evidence array.

| Status | Meaning |
|---|---|
| RAW | Byte-exact source representation only; explicit `DB` directives. |
| DECODED | Established documented 8080 instruction representation; semantics not structured. |
| STRUCTURED | Procedure/block/control-flow structure supported by evidence. |
| UNDERSTOOD | Evidence-backed behavioral contract / semantic description. |

Runtime address equals runtime base plus file offset. PLI.COM's base is `0100H`;
overlay bases are `2200H`. These were checked against existing Runes canonical
instruction contexts, including each image's observed offset-zero instruction,
and the [execution-map measurement](../../docs/execution-map.md). The compact
load-base observations and historical-image hashes are retained in
[evidence.json](evidence.json). Sharing `2200H` does not make overlays the same
image. For example, stable `PLI2_7701` denotes PLI2.OVL file offset `7701H`,
which executes at `9901H`; `PLI_119E` executes at `129EH`.

Sources use runtime `ORG`, runtime operands, and labels whose suffixes are file
offsets. Each emitted line has a stable label and an offset/runtime comment.
Section-start labels and every emitted line are checked against assembler
symbols and structured listings. Adding a semantic alias must preserve the
stable label. Splitting a RAW line to introduce a new stable label is safe when
its bytes and offsets remain identical.

## Assembler decision

Repository inspection found an OCaml decoder/executor and static listings, but
no configured 8080 assembler. `asm80`, `z80asm`, `pasmo`, and `as8080` were not
installed. Installed `nasm`/`yasm` target x86; `z80dasm` is a disassembler. Local
historical `.asm`/`.lst` reports include linear 8085 interpretations of data and
are not authoritative reconstruction sources.

The selected [asm8080 upstream](https://github.com/begoon/asm8) package is
version **1.0.34**, approximately 83 KiB unpacked, MIT licensed, and has **zero
runtime dependencies**. The tool-local package manifest and npm lockfile pin
the version and package integrity. It accepts Intel 8080 mnemonics and explicit
`DB`, and exposes source addresses, symbols, and bytes through its Node API.
This avoids writing another general assembler or introducing a large build
system. The verifier rejects the wrong installed version. Its output is treated
as a candidate, checked independently against every original slice and full
image. Exact equality, rather than trust in an assembler's opcode behavior, is
the acceptance criterion. Undocumented/alias opcodes remain RAW.

## Seed evidence and limits

The seed excerpt retains instruction bytes, decoded text, runtime addresses,
per-run counts and first/last steps from existing MINIMAL, FIZZBUZ, FACTOR, and
OPTIMIST reports. It also retains observed callers and one checked OPTIMIST
CALL/RET stack-byte sample per RET-ending seed. Source paths and report hashes
record extraction provenance. Verification uses the durable excerpts, not the
large external reports. Those report hashes identify their sources; verifying
an excerpt's fidelity against the external report requires that report to be
available. No new compiler execution or broad automatic disassembly was used.

| Image | Seed file range (exclusive end) |
|---|---|
| PLI.COM | `[0EF6,0F2D)` INT append/flush |
| PLI.COM | `[1140,119E)` REL bit writer |
| PLI.COM | `[119E,11C3)` counted-bit serializer, ending at observed `+11C2` RET |
| PLI.COM | `[19BB,19D7)` shared guarded BDOS bridge, ending after `+19D4` JMP 0005H |
| PLI2.OVL | `[6821,682B)` 5 × AD0A helper |
| PLI2.OVL | `[682B,684A)` indexed external-name selection path |
| PLI2.OVL | `[7557,756D)` absolute REL item emission use |
| PLI2.OVL | `[7701,77BF)` CHAIN EXTERNAL construction hypothesis |
| PLI2.OVL | `[8225,8248)` external CALL reference wrapper hypothesis |
| PLI2.OVL | `[8248,8258)` adapter |

Unobserved branches within seed envelopes remain separate RAW sections.
Instruction starts were imported only within these established seed ranges and
only when fetched bytes matched the original image. At V0, PLI0/PLI1 were entirely
RAW. The counted serializer and four fully witnessed PLI2 wrappers have
STRUCTURED sequences supported by a matched stack pair. In V0, only the ten-byte
arithmetic helper was UNDERSTOOD: its whole documented sequence establishes
`A = 5 * byte[AD0AH] mod 256`, `HL = AD0AH`, no guest memory writes, unchanged
B/C/D/E, and flags from the final `ADD M`.

The retained OPTIMIST event capture predates the later slot-aware return update
and reports 372 global context mismatches. This is explicit counterevidence to
trusting its global procedure ownership. The nine retained local pairs were
checked directly for CALL-written stack addresses/bytes, RET-read bytes,
balanced SP, and return target; no global ownership claim follows. One matched
invocation does not establish all possible exits. The BDOS bridge is a tail
transfer and has no local matched RET. Unobserved guard failures and mode/error
branches remain unresolved. A comment's `HYPOTHESIS` semantic name does not
promote bytes to UNDERSTOOD.

## Accumulating reconstruction

1. Add a fixture or new execution evidence through the existing Runes workflow.
2. Identify the newly exercised region using exact image hash and file offsets.
3. Establish a procedure hypothesis from entries, caller sites, matched exits,
   inputs/effects, downstream helpers, cross-run agreement, and counterevidence.
4. Replace RAW/DECODED source only where code boundaries and encodings are
   justified. Keep data, aliases, and uncertain bytes as explicit `DB`.
5. Annotate a compact contract, separating OBSERVED, DEDUCED, and HYPOTHESIS.
   Retain enough durable evidence and document references to review it.
6. Update the section partition/status without promoting adjacent bytes. Add
   structured or understood claims only with supporting evidence/contracts.
7. Compute and review both section hashes against independent historical slices;
   confirm exact slice equality. Do not fix a source discrepancy by accepting a
   new expected hash for the same historical identity.
8. Run the verifier for whole-image byte identity and mapping, then tests and
   progress regeneration. Review the source, evidence, manifest, and metric diff
   together.

Runtime analysis remains evidence. Annotated assembly becomes the accumulating
reconstruction. V0's evidence field shapes deliberately match its small imported
corpus; expanding to non-RET blocks or new contract types should extend the
versioned evidence checks explicitly, without changing CPU or trace semantics.

The [MINIMAL baseline](../minimal-baseline/README.md) extends these seeds with
ten reviewed helper families, explicit secondary entries, local RET alternatives,
and the guarded BDOS bridge's specific external hardware return at `0005H`.
It retains separate execution coverage and reconstruction-status measurements.

[MINIMAL pass 1](../minimal-baseline/pass-1/README.md) adds scoped reader/filter
contracts, the PLI0 bound/tag predicate, the PLI2 save/dispatch/restore shape, and
a separate PLI1 constructor with an explicit argument-consuming software-return
proof. Unobserved paths and unresolved PCHL handler bodies remain RAW.

[MINIMAL pass 2](../minimal-baseline/pass-2/README.md) adds a STRUCTURED descriptor
predicate and nine low-level contracts for immediate helpers and the remaining
priority anchors. Bounds/flags/polling interpretations are explicit, and all
newly promoted bytes came from existing MINIMAL execution.
