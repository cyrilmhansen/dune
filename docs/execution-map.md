# Execution Map v0

Execution Map is a live, bounded analysis layered beside `Step`. It answers
which known file bytes were fetched as instructions, how often, at which
runtime addresses, and which dynamic control-flow transfers were observed. It
does not use runtime PC alone as code identity: several CP/M overlays can occupy
the same RAM range successively.

Each of the 65,536 runtime addresses has a current origin, either `Unknown` or
`{ CP/M drive, user, canonical filename, file offset }`. The caller seeds an
already-loaded image explicitly (for example a COM at `0100h`); this does not
write guest memory. After a successful BDOS sequential READ, the live record
event maps its 128 bytes to the file's logical offset `record * 128`, at the
current DMA address with 16-bit bus wrapping. Successful writes publish copied
record data too, but do not claim that the record is currently loaded in RAM.

For a memory-origin `Step`, fetched-byte origins are resolved before its data
writes are applied. An instruction is attributed to an image offset only when
all of its fetched bytes belong to that image at consecutive offsets. All
unknown bytes produce an unknown-runtime execution; partial or incompatible
origins produce a mixed/unresolved execution. Interrupt-acknowledge bytes are
counted separately and are not mistaken for memory fetches. After attribution,
CPU data writes invalidate the written addresses' file origins. BDOS record
events and CPU instruction fetches remain separate observations.

Per-image queries expose known seeded size (or `None` when only logical records
have been observed), observed record numbers, per-byte fetched counts,
instruction-start counts, instruction entries, first/last steps and observed
runtime PCs. `unique_fetched_byte_count` counts distinct image offsets fetched
at least once; the older `fetched_byte_count` is the **dynamic total**, including
repeated fetches. These metrics are not interchangeable. A zero fetch count
means only “not observed as an instruction byte”; it does **not** establish
dead code (the bytes may be data, padding, unreachable, or simply unexercised).

Control-flow observations are dynamic only: taken/not-taken Jump, Call, Return,
Restart and Halt outcomes are counted, with runtime targets and currently
resolvable target origins. Cross-image transitions are derived from these
observed transfers; there is no recursive disassembly, static CFG, or inference
of unobserved edges. BDOS sites are associated with the immediately preceding
non-sequential Step that reached `0005h`, when available. This captures a
common `JMP 0005h` bridge as well as direct CALLs without guessing a higher-level
caller.

Execution Map consumes live `Step`/Runner/BDOS callbacks and is independent of
AT8TRACE v1. It adds no persistent trace records. It stores aggregate counters
and distinct origins/edges, not every Step. Current limitations include no
data provenance for CPU writes, no generated-code origin, no interrupt replay,
and no distinction between multiple versions of the same CP/M filename beyond
the instruction-byte conflict error when an already-seen instruction origin
changes.

## First `PLI OPTIMIST` measurement

This local run used the untracked historical PL/I-80 v1.4 artifacts, seeded
`PLI.COM` at `0100h`, and fed successful BDOS READ events into the map. It
completed unchanged: warm boot after 2,535,509 CPU steps, both compiler passes
reported no errors, `END COMPILATION`; `OPTIMIST.REL` was 1,408 bytes with SHA-256
`5fca1ffe38d11c30d20cfb99a23fe2baf002c569790bda83e09151cf36032b15`, and
`OPTIMIST.INT` was absent. The output REL is byte-identical to the established
CP/M 2.2 reference. The measured `dune exec` wall time, including Dune startup,
was about 1.6 seconds.

| Image | Bytes known/observed | Unique fetched bytes | Known-byte coverage | Dynamic fetched-byte total | Unique starts | Executions | First / last step | First runtime PC / file offset |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `A:0:PLI.COM` | 8,064 | 4,034 | 50.02% | 2,697,677 | 1,894 | 1,347,482 | 0 / 2,535,508 | `0100h` / `0000h` |
| `A:0:PLI0.OVL` | 18,048 (141 records) | 7,181 | 39.79% | 419,943 | 3,675 | 219,649 | 14,310 / 643,847 | `2200h` / `0000h` |
| `A:0:PLI1.OVL` | 34,816 (272 records) | 15,317 | 43.99% | 919,934 | 7,627 | 486,720 | 670,277 / 1,638,028 | `2200h` / `0000h` |
| `A:0:PLI2.OVL` | 33,792 (264 records) | 10,127 | 29.97% | 948,326 | 4,941 | 479,722 | 1,663,710 / 2,505,487 | `2200h` / `0000h` |

The three overlays loaded in that order. Their record-load step ranges were
`644–14,084`, `644,035–670,051`, and `1,638,236–1,663,484`. Each began
executing at runtime `2200h`, file offset `0000h`, shortly after its last record
was read. The first PLI1 record overwrote a PLI0-origin byte at step 644,035;
the last earlier PLI0 execution was step 643,847 (`PC=23DDh`, offset `01DDh`).
The first PLI2 record overwrote PLI1 at step 1,638,236; its preceding last
execution was step 1,638,028 (`PC=2338h`, offset `0138h`). PLI2 was not replaced
before warm boot.

Of the 2,535,509 instructions, 2,533,573 were image-attributed, 1,936 were
unknown, none were mixed/unresolved, and none were interrupt-acknowledge steps.
The unknown steps are the synthetic RET instructions executed at the runner's
BDOS trap address `0005h`; they are runner machinery, not historical file code.
The 357 distinct cross-image transfer observations totaled 22,564 executions.
Among the most frequent directed edges were `PLI.COM+1A3Fh →
PLI0.OVL+1A61h` and `PLI0.OVL+1A5Eh → PLI.COM+1A33h` (1,587 each);
`PLI.COM+1A28h → PLI1.OVL+79F7h` and `PLI1.OVL+79F4h → PLI.COM+1A1Ch`
(1,240 each); and `PLI.COM+1A28h → PLI0.OVL+43B8h` /
`PLI0.OVL+43B5h → PLI.COM+1A1Ch` (1,055 each). These are dynamic addresses,
not newly assigned routine names.

All observed BDOS calls were attributed to the resident transfer instruction
at `PLI.COM+19D4h` (`PC=1AD4h`), matching the previously documented common
`JMP 0005h` bridge. Counts by function were: 2:425, 11:18, 12:1, 15:7, 16:5,
19:3, 20:712, 21:15, 22:2, 26:747, 108:1 (1,936 calls total). The map
distinguishes overlay identity despite the repeated `2200h` entry address.

## Visualization and report coordinates

`Analysis.Execution_report` consumes an `Execution_map.t` and an explicit image
order. It assigns each image a contiguous **linear virtual offset** range for
comparison and visualization only. This creates no claim about historical RAM
layout. Keep these coordinates distinct:

| Coordinate | Meaning |
|---|---|
| Runtime address / PC | Address in the 8080's 64 KiB memory during this run |
| Image/file offset | Byte position within one COM or CP/M file |
| Linear virtual offset | Analysis-only offset in the caller-ordered concatenation of images |
| Execution step index | Dynamic instruction order, beginning at zero |

The HTML grid uses a configurable row width (default 64), byte-level log-scaled
dynamic heat `log(1 + count) / log(1 + maximum)`, and a separate instruction-start
outline. Unknown bytes and known-but-unfetched bytes have distinct neutral fills.
The compact whole-image strip aggregates each bucket by its **maximum** byte
fetch count. When live BDOS record events include their step index, the timeline
also shows the first-to-last record-read interval separately from execution.
The timeline does not infer compiler passes. The JSON contract is versioned as
`RUNES_EXECUTION_MAP_REPORT 1`; byte arrays are offset-indexed and contain known
value, dynamic count, instruction-start count and fetched status. It includes
all aggregated dynamic edges, not only the top transitions shown in HTML.

For the first PL/I ordering (`PLI.COM`, `PLI0.OVL`, `PLI1.OVL`, `PLI2.OVL`),
the computed analysis ranges are `00000h–01F7Fh`, `01F80h–065FFh`,
`06600h–0EDFFh`, and `0EE00h–171FFh`. Their spans are respectively 8,064,
18,048, 34,816 and 33,792 bytes. The overlays' identical runtime entry at
`2200h` remains distinct from all four file offsets and virtual ranges.
The report timeline also received successful-read step indexes: PLI0 records
were read from steps 644–14,084, PLI1 from 644,035–670,051, and PLI2 from
1,638,236–1,663,484. These are BDOS observation intervals, not inferred pass
boundaries. The historical JSON contained all 5,908 aggregated dynamic control
edges; the self-contained HTML was 5,436,525 bytes and JSON 5,420,941 bytes.
Both were generated locally and are not repository fixtures.
