# Dynamic Structure Map v0

`Analysis.Dynamic_structure` is a live, generic structural analysis beside
`Step` and Execution Map. It reports observed function-like **routine
candidates**, directed transitions between them, and a **narrative traversal**
of each pair's first observation. A candidate is a runtime hypothesis supported
by an entry event, not a recovered source-language function.

## Evidence and identity

Candidates are created at the initial executed instruction, a taken `CALL`, a
`RST` target, or the first execution in an image not previously executed.
Execution Map supplies the current byte origin. Candidate identity is
`(drive, user, image name, image offset, runtime entry PC)` when known; unknown
origins retain their runtime PC and receive an `unresolved-origin` tag. Thus
different overlays at `2200h` remain distinct candidates even when their file
offset and runtime entry address overlap.

The caller of `pli80-analyze` can opt in with `--structure`; it requires
`--analysis execution`, `data`, or `path`. No Step history is retained. The
report is `dynamic-structure.json`, headed `RUNES_DYNAMIC_STRUCTURE 1`, and
contains candidate metrics, the aggregate transition graph, the narrative,
and grouped anomalies. Routine IDs are deterministic within a run (`R000`,
`R001`, ... in discovery order), not persistent semantic names. The generated
display label is `Rnnn · IMAGE+OFFSET`.

## Stack and transition model

Taken `CALL` and `RST` create/resolve the target candidate, record a call-like
edge, and push a caller plus expected return PC. Only a taken `RETURN` pops.
Return target mismatches restore the observed saved caller but add an explicit
anomaly; returns with an empty stack are also retained as anomalies. A taken
jump does not create a candidate. A jump to an already-known candidate entry
may produce an `Other_observed` edge and an anomaly, but does not mutate the
routine stack. These choices intentionally avoid guessing tail calls or
internal routine boundaries.

If execution first enters a new image without a `CALL`-discovered target, a
candidate is made at the first executed byte. An `Image_entry` edge is added
only when the immediately preceding observed transfer targets that PC; absent
that evidence, the candidate is retained and an anomaly records the missing
transfer. The active stack is not reconstructed from guessed control flow.

Transitions aggregate by the directed candidate pair, independently of kind.
Their count, first/last step, and all observed kinds are retained. Self calls
mark a candidate recursive and increment `self_call_count`, but do not create
a self edge in the narrative. Mutual calls remain ordinary directed edges.
Returns are first-class reverse-direction transitions.

The narrative's uniqueness key is exactly `(source routine, target routine)`.
The first occurrence appends an entry with its first step and kind; later
occurrences only update aggregate metadata. Frequency therefore cannot reorder
or duplicate the narrative. For example:

```text
trace:      A B C B C B D A E A
narrative:  A -> B
            B -> C
            C -> B
            B -> D
            D -> A
            A -> E
            E -> A
```

This is the first structural discovery order, **not execution frequency**.
Repeated `B -> C` observations affect the aggregate count only.

## Metrics and anomalies

Candidates include discovery ordinal, stable image coordinate, runtime entry,
first/last executing step, dynamic instruction count while active, distinct
executed starts, distinct incoming/outgoing routine neighbors, received call
count, return count, self-call count, recursion flag, and factual tags. Tags
include `entry`, `image-entry`, `called`, `returns`, `recursive`, and
`unresolved-origin`.

Anomalies are compacted by kind, runtime PC, and detail; each row retains the
first/last step and observation count. This keeps repeated synthetic CP/M trap
steps from bloating the report while preserving their frequency. In the
current CP/M runner, the synthetic `RET` at `0005h` has no executable-file
origin, so it contributes an unresolved-origin observation rather than being
misidentified as compiler image code.

## Initial compiler measurements

These one-host wall measurements use the same `analysis=execution` run with
and without structure collection. The difference is a rough incremental cost
estimate, not a separately timed CPU phase; live structure work happens at
each Step callback. All compiler outputs and instruction counts matched their
accepted compilation runs.

| Input | Steps | Candidates | Narrative pairs | Aggregate pairs | Recursive | Anomaly groups / observations | Execution only | With structure | Approx. delta | JSON bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `MINIMAL.PLI` | 441,855 | 395 | 1,543 | 1,543 | 3 | 70 / 2,037 | 0.257 s | 0.287 s | 0.030 s | 381,967 |
| `FIZZBUZ.PLI` | 1,145,517 | 530 | 2,362 | 2,362 | 6 | 107 / 2,401 | 0.553 s | 0.732 s | 0.179 s | 564,474 |
| `FACTOR.PLI` | 838,415 | 551 | 2,549 | 2,549 | 6 | 109 / 2,226 | 0.402 s | 0.549 s | 0.147 s | 600,295 |
| `OPTIMIST.PLI` | 2,535,509 | 599 | 2,940 | 2,940 | 6 | 202 / 2,805 | 1.182 s | 1.692 s | 0.510 s | 701,700 |

The structural report contains a few thousand aggregate relationships rather
than millions of Step records. These routine counts are conservative dynamic
candidate counts, not counts of PL/I procedures. In particular, the
`FACTOR.PLI` run is executing the compiler, not the generated factorial REL;
its six recursive candidates describe observed compiler self-calls only.

The first twenty OPTIMIST narrative relationships were:

```text
000 R000 PLI.COM+0000 -> R001 PLI.COM+1A40 CALL
001 R001 PLI.COM+1A40 -> R000 PLI.COM+0000 RETURN
002 R000 PLI.COM+0000 -> R002 PLI.COM+0FCC CALL
003 R002 PLI.COM+0FCC -> R000 PLI.COM+0000 RETURN
004 R000 PLI.COM+0000 -> R003 PLI.COM+1A38 CALL
005 R003 PLI.COM+1A38 -> R000 PLI.COM+0000 RETURN
006 R000 PLI.COM+0000 -> R004 PLI.COM+19A5 CALL
007 R004 PLI.COM+19A5 -> R000 PLI.COM+0000 RETURN
008 R000 PLI.COM+0000 -> R005 PLI.COM+0692 CALL
009 R005 PLI.COM+0692 -> R006 PLI.COM+062A CALL
010 R006 PLI.COM+062A -> R007 PLI.COM+02FE CALL
011 R007 PLI.COM+02FE -> R008 PLI.COM+02EE CALL
012 R008 PLI.COM+02EE -> R009 PLI.COM+19BB CALL
013 R009 PLI.COM+19BB -> R010 PLI.COM+1A0F CALL
014 R010 PLI.COM+1A0F -> R009 PLI.COM+19BB RETURN
015 R009 PLI.COM+19BB -> R008 PLI.COM+02EE RETURN
016 R008 PLI.COM+02EE -> R007 PLI.COM+02FE RETURN
017 R007 PLI.COM+02FE -> R006 PLI.COM+062A RETURN
018 R006 PLI.COM+062A -> R009 PLI.COM+19BB CALL
019 R009 PLI.COM+19BB -> R006 PLI.COM+062A RETURN
```

The implementation has synthetic coverage for three distinct overlays loaded
at the same `2200h` runtime address and for `PLI0.OVL`, `PLI1.OVL`, and
`PLI2.OVL` retaining separate identities. No compiler routine names are
inferred from these measurements.

## Observed basic blocks v0

When `--structure` is enabled, the experiment also emits
`dynamic-blocks.json`, headed `RUNES_DYNAMIC_BLOCKS 1`. The routine report
above remains `RUNES_DYNAMIC_STRUCTURE 1`; its meaning and JSON schema are
unchanged. Basic-block collection consumes the routine ID attributed to each
executed Step by `Dynamic_structure`, so it does not maintain a second routine
stack.

The collector retains one node per distinct observed instruction identity and
variant, plus aggregated instruction-to-instruction transitions. It does not
retain Step history. Instruction identity includes routine candidate, current
image/file identity and offset when resolved, and runtime PC. Unknown and
mixed-origin instructions remain explicitly identified as such. A repeated
identity with different fetched bytes produces an anomaly and separate
variant nodes instead of silently merging the observations.

Blocks are materialized after execution from the complete observed graph.
Routine entries, reached branch targets/fallthroughs, call/return
continuations, and multi-predecessor instructions establish boundaries.
Observed control-transfer instructions end their block whether conditional
flow was taken or not. Straight-line instructions are joined only when the
observed successor is unambiguous, has one predecessor, remains in the same
routine, has no entry evidence, and has compatible contiguous runtime and
image coordinates. A late-discovered target can therefore split an earlier
apparent straight-line chain.

Every image-backed block is checked during materialization: all of its
instructions must have the same image identity, file offsets must be
contiguous, and runtime PCs must be contiguous modulo 16 bits. Origin changes,
non-contiguous offsets, mixed-origin instructions, or byte variants force a
boundary or are represented explicitly as unresolved/variant observations;
they are never silently reported as one image span.

For canonical image-backed code, the report retains each block's image,
starting file offset, and byte length, with per-instruction relative offset,
length, and dynamic counters. Fetched bytes are checked against Execution Map's
current image bytes before being stored this way. Instruction decoding and
formatting are reconstructed on query or serialization from a compact snapshot
of those referenced image bytes. Unknown, mixed, interrupt-supplied, changed,
and origin-variant instructions retain observed bytes instead; the typed block
API marks these as observed-byte representations and they have no canonical
image span. The `RUNES_DYNAMIC_BLOCKS 1` JSON fields remain compatible:
ordinary image records retain the existing bytes/text fields, while exceptional
blocks have null image coordinates and retain their origin/tags rather than
claiming an image span.

Block IDs (`R017.B003`) are run-local and ordered by the first observed
execution of each eventual block entry. Blocks retain an ordered instruction
sequence with fetched bytes, deterministic Intel 8080 text, per-instruction
counts and first/last steps. The report aggregates block transitions and, per
routine, a first-observation narrative of unique directed block pairs.
Transition counts are metadata and do not reorder that narrative. A recursive
CALL remains a factual block-level call edge while the routine-level view
continues to collapse self-recursion.

The block map is dynamic only. Unobserved instructions are not classified;
this is not static disassembly, complete CFG recovery, or source-level
function recovery. The exact report contains observed instruction records,
aggregated edges, blocks, local narratives and structural anomalies, but no
provenance DAG or raw Step sequence.

### Initial compiler block measurements

These runs used `--analysis execution --report none --structure`; the source
examples are compiled, not executed as generated programs. Runtime is the
CLI's online execution plus live-analysis timer. The block report size is the
uncompressed `dynamic-blocks.json` size.

| Input | Routine candidates | Blocks | Distinct instructions | Block transitions | Backward-edge targets | PLI.COM / PLI0 / PLI1 / PLI2 blocks | Online time | Block report |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `MINIMAL.PLI` | 395 | 2,443 | 11,115 | 3,251 | 119 | 426 / 465 / 787 / 764 | 0.515 s | 5,197,719 B |
| `FIZZBUZ.PLI` | 530 | 3,641 | 16,221 | 5,011 | 140 | 459 / 629 / 1,370 / 1,182 | 1.070 s | 7,712,487 B |
| `FACTOR.PLI` | 551 | 3,851 | 16,989 | 5,373 | 155 | 437 / 748 / 1,411 / 1,254 | 0.828 s | 8,097,870 B |
| `OPTIMIST.PLI` | 599 | 4,651 | 19,774 | 6,660 | 189 | 509 / 815 / 1,750 / 1,576 | 2.363 s | 9,679,321 B |

Each row also has one unresolved synthetic-system block. OPTIMIST retained its
accepted `2,535,509` compiler steps and successful output. On the same host,
the previous structure-only online measurement was 1.692 s; the current
structure-plus-block online measurement is 2.363 s, an approximate 0.671 s
increment for observed instruction/edge aggregation. Post-run materialization
and serialization added roughly 0.13 s to total CLI wall time (2.497 s). These
are simple wall-clock comparisons, not a dedicated benchmark harness.

Representative OPTIMIST blocks from the generated report:

```text
R000.B000 · PLI.COM+0000
    0100  JMP 02EDH

R001.B000 · PLI.COM+1A40
    1B40  MOV L,A
    ...
    1B4A  RET

R014.B000 · PLI0.OVL+0000
    2200  JMP 23B0H
```

The `PLI0.OVL` sample and the per-image counts demonstrate that the same
runtime address space remains separated by current image origin. Block IDs
are report-local; image/file coordinates are the durable coordinates.

## Deferred

This remains short of static disassembly, full routine-boundary recovery,
complete CFG recovery, or cycle condensation. It does not infer tail calls,
split routine candidates on jumps, reconstruct memory objects, or attach
semantic routine names. The dynamic active-routine model can misattribute
instructions after unusual non-structured flow; anomalies expose observed
mismatches rather than hiding them. Routine and block narratives are
projections of their aggregate graphs, not replacements for them.
