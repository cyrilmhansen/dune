# Pass 25: bounded faithful native +7D53

Baseline: `3dda1aa4ab3f81abcdb9747cf679f69536247094`.

`Pli80_host.Range_processing` expresses the historical reverse processing and
forward emission algorithm using shared byte-addressed state and native child
operations. `Pli80.Range_processing_bridge` constructs the path-specific machine
result, proves static internal CALLs and PSW saves, and builds one ordered
`Apply_host_program`. `Native_range_processing` independently proves every root
against an actual historical CALL/original-slot RET before enabling replacement.
No historical annotation, procedure completeness, Runner, CP/M, CPU or packet
representation changes are required.

## Supported scope

Equal range returns immediately with the actual end/begin CMP flags, A=end,
HL=AE34, and preserved BC/DE. Nonempty gate returns execute RAR: A includes the
incoming carry from the preceding CMP, outgoing carry is original AA1A.bit0,
and NZPA/AC remain those of CMP. Both early paths leave memory unchanged.

Work requires 202B.bit0 clear and 2011 zero. Reverse processing predecrements the
fresh cursor, publishes it, saves its actual DCR PSW, rereads/decrements begin,
restores the cursor through POP B/MOV C,B, and compares with the sentinel. Reverse
00->FF sentinel behavior is supported. Non-sentinel mapped bytes must be below
F7. Recursive_mapped executes at the current outer cursor; its direct returned A
is published at AE50. A separate Balance_scan at that same outer cursor supplies
the replacement cursor. Existing recursive special-state/alias restrictions
remain intact.

Forward processing freshly resets from begin and freshly compares u8(end-1)
against cursor every iteration. Mapping and mapped-byte emission precede the
fresh F7 comparison. Only attributes 2,3,4,6 are supported. The historical
primary read still occurs for attribute6, but its emission is suppressed; both
word emitters still run. Recycling follows all emission channels and performs
its independent position-map reread. Forward wrap is rejected. Normal exit
freshly publishes begin into end and retains endpoint comparison flags.

| Attribute | Observed native channel order |
|---|---|
| 2 | mapped byte, mapped-word low, mapped-word high |
| 3 | mapped byte, second auxiliary, primary auxiliary |
| 4 | mapped byte, primary auxiliary |
| 6 | mapped byte, mapped-word low, mapped-word high; primary read/cache retained |

Primary emission sets C from the fresh AE51 carrier while A retains the attribute
comparison byte; the complete child entry/return state is checked at each ordinal
CALL boundary.

Unsupported shortcuts, mapped>=F7, attributes0/1/5/7, forward wrap, existing
recursive unsupported cases, emitter failures/guards and invalid aliases reject
private state before commit. No recursion/iteration bound or cycle detector is
added. Conditional termination remains historical; cyclic malformed synthetic
states are not run. Alias preconditions are tested before potentially looping
children where applicable. No source/hash/step/snapshot membership selects
native semantics.

## Independent natural proof

All roots were rederived from actual guest CALL/RET execution and independently
joined to the existing corrected witness captures:

- MINIMAL: `_build/minimal-baseline/capture`;
- FIZZBUZ: `_build/evidence-packet-cross-run/fizzbuz-capture`;
- PICTURE: `_build/discriminator-pass-15/selected-capture`.

| Source | Roots | Equal / gate / work | Reverse selections | Forward iterations | Attr2 / 3 / 4 / 6 | Logical emitter calls |
|---|---:|---|---:|---:|---|---:|
| MINIMAL | 21 | 12 / 2 / 7 | 9 | 16 | 7 / 1 / 8 / 0 | 40 |
| FIZZBUZ | 77 | 40 / 8 / 29 | 35 | 102 | 42 / 7 / 53 / 0 | 253 |
| PICTURE | 23 | 12 / 1 / 10 | 11 | 22 | 10 / 0 / 10 / 2 | 56 |

Every one of 121 roots matches A/B/C/D/E/H/L, SP/PC, all five flags, all 65,536
memory bytes, live DMA, and the complete filesystem. Logical writes are checked
against actual instruction writes; each final planned writer/value is checked
against actual historical last writers with no omitted guest write destination.
Root PUSH PSW bytes and high-before-low chronology are checked independently on
every iteration. Child CALL chronology is checked at composition boundaries;
existing Packed_scan arithmetic-helper repetitions and recursive Balance_scan
helper repetitions remain represented by their native loop results and existing
final-residue proofs, not fabricated instruction events. Equal register tuples
never select a child: the independent checker pairs exact ordinal CALL ancestry.

Maximum recursive node levels below the root are 3/5/3; minimum surviving stack
write offsets are -29/-43/-29. `stack-compatibility.json` retains relative
addresses, derived values, exact runtime writers, logical nesting depth and
planned overwrite ancestry, including logical frame cells. Its journal is a
compatibility plan, not an instruction-by-instruction CPU trace. Nothing is
copied from historical post-memory to implement residue.

## One transaction and real CP/M services

All compiler writes, native recursive/helper writes, compatibility writes and
ordered emitter services are staged as one root program. A service-bearing
prefix is previewed through the existing generic Runner transaction to obtain
actual CP/M post-state needed by subsequent native operations. Prefix preview
clones the original live RAM/process/filesystem and replays the ordered native
prefix; it commits nothing and emits no callbacks. Final validation checks the
complete prepared memory, DMA, filesystem and service chronology before the
single commit. There is no second transaction engine and no duplicate BDOS/FCB
implementation.

FIZZBUZ root entry **472977**, caller **PLI1+7ED3**, return **478475**, contains the
record0 flush: real BDOS26 sets DMA from FD7E to 1D8C, index reset follows DMA,
and BDOS21 consumes FCB1CA2/current DMA. Its exact 128-byte record and FCB writes
are retained in `host-service-summary.json`. Other roots have no flush. Complete
cumulative runs have DMA/write service pairs 1/3/1, split inside/outside +7D53 as
0+1, 1+2, 0+1. Preview services do not count as committed services or guest steps.

## Cumulative migration

Vector order: +7D53, external +7C1B, +7BBF, +7B7A, +7BA2, +7AD5, +7B64,
+7ABF, +0EF6, +7A79, +7E46, +7E56.

- MINIMAL: `21,0,0,7,0,18,0,13,88,1,0,0`.
- FIZZBUZ: `77,0,0,58,5,140,7,106,131,28,0,0`.
- PICTURE: `23,0,0,8,0,28,3,19,72,3,0,0`.

All suppressed children execute internally natively. Enabled guest bodies are
absent under canonical image-aware dispatch; overlay PC collisions are not
confused. The +7D53-only runs independently make 21/77/23 root transitions.
Every entry/resume, ordered INT/REL record, normalized file-event sequence and
final filesystem matches. PASS1/PASS2/END COMPILATION and warm boot are exact.

| Source | REL bytes | SHA256 |
|---|---:|---|
| MINIMAL | 256 | 7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119 |
| FIZZBUZ | 768 | 68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203 |
| PICTURE | 256 | c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1 |

INT records remain ordered and exact (files are normally deleted after PASS2):
MINIMAL 128 bytes / 713dec081e73c533164b9fe151114d1d7dc29acb8017bb0fc226e9ae72658aec;
FIZZBUZ 384 / caa57d65c9ac6c606519300c2b7ccc137089b5b677804430ba468a56fc413fb7;
PICTURE 128 / f23cb615e2222183e89119bd2579b7900143d1c7e4dc8ddc21d204fc0d24791c.

## Validation and next boundary

See `validation.json` for final test totals. Native units cover all65,536 begin/end
pairs, 16,384 unary byte/flag cases, all32 PSW encodings, actual historical CALL
entry, private rejection after a staged flush, bad code/aliases/continuation,
missing-file BDOS21 failure, guard mismatch and reordered/duplicated services.
The latter cases prove live memory/registers/DMA/filesystem/callbacks unchanged.
Existing recursive special, extra/omitted invocation and canonical collision
regressions remain in the full suite. Historical reconstruction is byte-exact:
**94,720 bytes**. Contract remains stable/complete/partial; no archaeology
correction, pragmatic divergence or fidelity debt.

For Pass26 prefer the smallest remaining complete reusable publication primitive
cluster: +7AF0 mapped-word publication and +7B49 second-auxiliary publication
(+7B2E already has an internal native primitive). This prepares +7E5F without
hiding its unobserved +7E70 threshold arm or producer/alias scope. +8048 is a larger
composition with a still-RAW +805C..+8068 gate arm, complete +7A93/+7B13 primitives
not yet native, and +7E5F's partial scope. Defer both parents until these child
primitives are proved; do not choose a larger parent merely because +7D53 is now
native. No new fixture or FACTOR investigation was performed.

Reproduce the native proofs under ignored build state:

```
dune exec pli80-native-range-processing -- --toolchain /path/to/DISK1 --output-dir _build/pass25-new-proof
python3 tools/annotated-assembly/test_native_7d53_pass_25.py --images /path/to/DISK1 -v
```
