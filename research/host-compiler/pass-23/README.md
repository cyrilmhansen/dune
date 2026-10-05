# Faithful native resident INT emitter — Pass23

Baseline: `f5c0e4eeb54109ce246138e71fdc6738d316cfd7`.

Native resident `PLI.COM+0EF6` now reproduces the demonstrated non-flush and
successful-record-flush operations. All 640 independent natural invocations pass
full 64 KiB/register/flag/DMA/filesystem shadows. Emitter-only and cumulative
hybrids compile MINIMAL, FIZZBUZ and PICTURE with exact output records and final
filesystems. No historical annotation, contract, completeness or byte status was
changed. No emitter error path, global resident-wrapper replacement, word-emission
wrapper or +7D53 replacement was added.

## Historical algorithm and native boundary

`Pli80_host.Int_emitter` owns only compiler-memory behavior. Its ordered plan
retains scratch 20B0, the paired 1E0C/1E0D read and discarded neighbor, low-byte
addressing, fresh 20B0 reread, unconditional1D8C+i publication, fresh index reread,
u8 increment and publication before the CPI80 decision. The supported natural
producer domain is index 00..7F; wider states fail closed.

The flush plan orders Set_dma(1D8C), index reset00, Sequential_write(1CA2).
It never clears the physical 128-byte buffer. `Pli80.Int_emitter_bridge` adds
historical wrapper scratch (high2060 then low205F; high2066 then low2065), exact
service call/resume states, original outer CALL proof and independently derived
CALL/PUSH compatibility bytes. The core has no I8080, Runner or CP/M dependency.

Non-flush returns A=i+1, BC=1D8C, entry DE, HL=1D8C+i, original continuation and
SP=entry+2. Flags come from exact CPI80. Flush returns actual supported service
state A=0, BC=0015, DE=1CA2, HL=0000, followed by CPI00 flags S0 Z1 AC1 P1 CY0.
All individual register and flag fields are compared; no universal BDOS
preservation rule is assumed.

## Real CP/M services and transaction

Runner's generic `Apply_host_program` keeps ordered Memory_write/Dispatch_bdos
operations. `preview_host_program` stages them against deep copies of the actual
PRE-state RAM, CP/M process/DMA and complete filesystem, including physical record
storage and logical sizes. Services call the existing
`Cpm.Personality.dispatch_with_file_events` implementation. FCB mutation, record
numbering, DMA, record bytes and returned registers are produced by that runtime,
not by a second host-compiler implementation or copied post-state oracle.

All service resume checks and final validation run before live mutation.
Unsupported status, service failure, bounds, order or final-validation outcomes
discard the staged state and buffered callbacks. Success commits staged state,
then delivers factual record/file/external-effect callbacks in their original
order. After-commit observers are not rollback participants. Native service
metadata retains exact before/after snapshots for validation. No guest BDOS
entry, synthetic Step, RET, instruction count or t-state is fabricated;
`host_bdos_services` counts committed native services independently.

An existing native integration restriction rejected the first hybrid because
resident buffer/FCB cells initially have historical image origins. Ordered host
programs now invalidate origins for actual committed writes, including
same-valued writes and real FCB service effects. They add no historical execution
or provenance. The old simple Apply_host_transition restriction remains intact.
CPU, Trace and packet models are unchanged.

The emitter adapter validates the demonstrated +19BB stub/sentinel guards before
preparing a transition. A real BDOS21 nonzero result is rejected in the private
transaction; +0EA0 is never guessed, emulated or used as fallback.
[host-service-design.json](host-service-design.json) retains these boundaries.

## Independent operation and compilation oracles

Fresh historical execution discovers every actual CALL and original RET.
All 640 native previews compare full RAM and the complete physical/logical
filesystem, including 635 non-flushes and 5 real-service flushes. Historical
runtime 0005 post-dispatch boundaries independently match the native service
memory, registers/flags and DMA. Logical scratch/buffer/index/wrapper writes and
exact final stack writer coordinates are checked separately.

The last flush stack words below entrySP are derived from immutable code:
S-2=1024 (+0F21 CALL), S-4=0437 (+0334 CALL), S-6=1C15 (+19BB PUSH B),
S-8=1CA2 (+19BC PUSH D), S-10=1AC6 (+19C3 CALL). Earlier DMA-call residue is
overwritten in historical order. Non-flush paths have no body stack writes.
No compatibility bytes come from historical post-memory.

| Source | Shadow / emitter transitions | Non-flush | Flush | Native BDOS26 /21 |
|---|---:|---:|---:|---:|
| MINIMAL |128|127|1|1 /1|
| FIZZBUZ |384|381|3|3 /3|
| PICTURE |128|127|1|1 /1|

Cumulative Runner counts in order
+7C1B, +7BBF, +7B7A, +7BA2, +7AD5, +7B64, +7ABF, +0EF6:

- MINIMAL:9,0,16,16,18,16,14,128.
- FIZZBUZ:35,0,93,107,140,109,113,384.
- PICTURE:11,0,19,22,28,25,19,128.

Recursive, Packed_scan/Balance_scan and publication children retain their native
hierarchy; no enabled historical body executes. Every resume compares full RAM
and returned state. Every output record, full file-event sequence and final
filesystem matches historical execution. DMA is 1D8C at each native record write;
INT records are0 /0,1,2 /0. Actual FCB effects and exact128-byte data are retained
per flush in [emitter-native-cases.json](emitter-native-cases.json).

INT is historically deleted after PASS2, rather than retained as a final file.
The complete produced INT is compared through ordered record events, its later
read/file lifecycle, per-operation filesystems and final absence. Produced INT
size/hash is retained in [external-state-summary.json](external-state-summary.json).
All REL records remain ordered and exact:

| Source | REL bytes | SHA256 |
|---|---:|---|
| MINIMAL |256|7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119|
| FIZZBUZ |768|68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203|
| PICTURE |256|c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1|

Every complete hybrid has PASS1 success, PASS2 success, END COMPILATION and warm
boot. Large private snapshots remain in process; generated evidence stays
ignored under `_build`. No full-memory dump or raw capture is committed.

## Tests, scope and next increment

```sh
RUNES_HOST_IMAGES=/path/to/DISK1 dune runtest
dune exec pli80-native-int-emitter -- --toolchain /path/to/DISK1 --output-dir _build/pass23-new
python3 tools/annotated-assembly/test_native_int_emitter_pass_23.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
```

Unit tests cover 32,768 index/append plans and 4,064 index/entry-flag comparisons
against the independent8080 ALU, plus actual CP/M transaction success/failure,
service order, premature reset, invalid bounds, rejected final state, missing
file/nonzero status, original-call proof, malformed continuation, changed code,
wrong images, guarded unsupported state and alias rejection. Failed transactions
leave RAM/DMA/filesystem/callbacks untouched. Source proof and expected invocation
accounting reuse the existing fail-closed native dispatcher. Independent Python
checks compare every fresh case with Pass22's corrected witnesses and exact
records. [validation.json](validation.json) records the broad regressions and
exact 94,720-byte reconstruction.

+0EF6 remains stable/complete/**partial**. Guard failures, write-error semantics
and unsupported aliases are outside this implementation. No archaeology
correction, pragmatic divergence or fidelity debt was needed.

Recommend Pass24 **B: extract complete reusable +7A79 and compose +7E46/+7E56 in
one bounded word-emission pass**, using the now-proven native emitter internally.
A smaller extraction alone is valid but would not remove a historical emission
wrapper. Direct +7D53 migration is premature: its unresolved shortcut/mapped
states, attr>=5 alternative and partial scope remain separate proof obligations.
Preserve fresh mapped-word lookup, AE52/AE53 cache publication, low emission,
fresh cache reread and high emission; derive suppressed helper/emitter stack
residue and cumulative service counts before hybrid use.
