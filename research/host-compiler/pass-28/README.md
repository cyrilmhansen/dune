# Pass28 — bounded native PLI1+8048

Baseline: `42b81ee665ef70e3de21ce64893e1774dba315f7`.

`Pli80_host.Mapped_control.read/publish` adds the complete AC73 historical family.
Read publishes C at AE39, genuinely reads/discards AE3A, then freshly selects
position_map[C] and AC73+j. Publication saves E at AE42 **before** C at AE41,
reads the pair, freshly selects the same distinct numeric table, reloads saved E
and writes unconditionally. Both preserve DE/NZPA, return A=value, BC=j,
HL=AC73+j and CY=0. No body stack residue is manufactured for these leaves.
AC73 remains separate from packed attributes, mapped bytes, primary and secondary
auxiliary tables. Shared State mutations remain visible to subsequent reads.

`Pli80_host.Input_processing` implements the +8048 chronology using callbacks to
existing native historical operations. Semantics depend on current registers and
shared memory; source-bound oracle snapshots belong only to the proof harness.

* C<=DD: save input at AE6A, call bounded Range_publication(+7E5F) with DE=0.
  Independently reload AE32, decrement with u8/DCR flags, read the predecessor
  channel, freshly read AE32/AE33, then publish at the current position. The
  three pairs are AC73 control, AD08 primary auxiliary, AD9D secondary auxiliary.
* C>DD, AA1A.bit0 clear: retain the exact RAR with incoming CY from DD-C, invoke
  bounded Range_processing(+7D53), freshly read AE6A/AE6B, emit the low saved
  byte through native Int_emitter. **The returned +7D53 A is not emission input.**
* C>DD, AA1A.bit0 set: reject. RAW +805C..+8068 is neither decoded nor implemented.

All inherited child nonaliasing and bounded-domain checks apply. Parent-cache
aliases are rejected. Each root is one private staged transaction, including
all logical writes, proven stack effects and actual CP/M services. Unsupported
children, a late unsupported attribute, missing file/nonzero BDOS status, guard
failure, altered code, malformed entry/CALL/continuation, duplicate/reordered
services and proof/count mismatches cannot mutate live RAM/DMA/files or deliver
callbacks. Runner, CPU, CP/M and packet infrastructure are unchanged.

## Independent natural oracles

Fresh historical executions capture private entry/post states for every duplicate
invocation. Independent tests reconstruct corrected CALL/return windows from
existing MINIMAL, FIZZBUZ and PICTURE event-witness captures.

| Source | +7A93 read | +7B13 publish | +8048 roots | Low | High |
|---|---:|---:|---:|---:|---:|
| MINIMAL | 13 | 22 | 22 | 12 | 10 |
| FIZZBUZ | 106 | 197 | 108 | 78 | 30 |
| PICTURE | 19 | 39 | 26 | 16 | 10 |

All **552** shadows match every register and flag, SP/actual continuation,
**65,536 RAM bytes**, logical-write ordering and proven stack writers. Root
shadows additionally match DMA, the full physical/logical filesystem, factual
record events/data and file-event order. Cases retain memory and deterministic
filesystem hashes; source/callers/steps remain evidence keys, never semantics.

Root caller distribution:

| Source | Caller coordinates and counts |
|---|---|
| MINIMAL | 2519:8; 80B3:4; 80BF:10 |
| FIZZBUZ | 0FB7:1; 24F9:1; 2519:64; 80B3:17; 80BF:25 |
| PICTURE | 24F9:1; 2519:9; 2581:1; 80B3:4; 80BF:11 |

Every natural high child takes +7D53's equal-range return. Tests additionally
compose a terminating +7D53 work child, including real flush services, and prove
a late attribute rejection discards the entire transaction. They also mutate
AE32 between channel test doubles to prove independent predecessor/current reads,
and mutate the saved byte in a high-route dependency test. These are ordering
checks, not new compiler-semantic observations.

## ABI and stack proof

Every direct child entry and return state is compared with historical CALL/RET
chronology. Low returns retain the secondary publisher ABI and NZPA/AC from the
third DCR; its DAD leaves CY=0. High returns retain the emitter ABI. RET consumes
the actual original outer CALL word, with SP=S+2.

For natural low roots, final S-2/S-1 holds A2B0 from +80AD; S-4/S-3 holds A0B5
from +7EB2 inside native +7E5F; S-6/S-5 holds the destination derived by +7AF0's
PUSH at +7B09. The latter is not confused with the two CALL depths above it.
For high roots, +8070 overwrites the +8069 continuation at S-2/S-1 with A273.
Successful flushes add the already-proven resident wrapper/bridge residue below
the emitter entry. Every surviving byte, writer coordinate, depth and overwrite
ancestry is retained in `stack-compatibility.json`; no oracle post-byte is copied.

## Native hierarchy and outputs

Each low root internally invokes +7E5F and its four publishers, then the three
independent read/publication pairs. Each high root internally invokes +7D53 and
Int_emitter. Internal children never become Runner transitions.

Cumulative vector order:
`8048,7E5F,7D53,7C1B,7BBF,7B7A,7BA2,7AD5,7B64,7ABF,0EF6,7A79,7E46,7E56,7AF0,7B49,7A93,7B13`.
All entries after +8048 count residual external roots.

| Source | Residual transition vector | BDOS26 / BDOS21 |
|---|---|---|
| MINIMAL | 22,4,11,0,0,7,0,2,0,1,78,1,0,0,10,10,1,10 | 1 / 1 |
| FIZZBUZ | 108,29,47,0,0,58,5,33,7,28,101,28,0,0,102,119,28,119 | 3 / 3 |
| PICTURE | 26,6,13,0,0,8,0,6,3,3,62,3,0,0,19,23,3,23 | 1 / 1 |

Nested +7E5F counts are 12/78/16; nested +7D53 and direct emitter counts are
10/30/10. FIZZBUZ has one native +8048 flush (entry step 609444, caller +80B3),
executing BDOS26 then BDOS21. Other natural +8048 emissions do not flush.
The remaining services occur outside +8048. `host-service-summary.json` identifies
the precise root; the generic transaction uses actual existing CP/M services.

All nine standalone and three cumulative compilations preserve ordered INT/REL
records, file-event order and final filesystem identity. Every enabled native
body is absent from guest execution, checked by canonical image+offset rather
than runtime PC alone. PASS1/PASS2 report no errors, END COMPILATION is observed,
and every run terminates at warm boot. No synthetic Steps/t-states are produced.

| Source | REL bytes | SHA256 |
|---|---:|---|
| MINIMAL | 256 | 7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119 |
| FIZZBUZ | 768 | 68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203 |
| PICTURE | 256 | c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1 |

## Validation and next boundary

```
RUNES_HOST_IMAGES=/path/to/DISK1 dune runtest
python3 tools/annotated-assembly/test_native_8048_pass_28.py --images /path/to/DISK1 -v
dune exec pli80-native-input-processing -- --toolchain /path/to/DISK1 --output-dir _build/new-pass28-results
```

All 263 Python tests and 32 Dune test stanzas pass, alongside the 552 operation
shadows and 12 complete hybrids. Exact 94,720-byte reconstruction is retained in
`validation.json`. All prior regressions, including the 109 MINIMAL and 27 packet/
continuation tests, pass. Archaeological bytes/statuses/contracts remain unchanged;
there is no correction, pragmatic divergence or fidelity debt.

Recommend **Pass29: reusable bounded +7EC0 together with its +80B7 parent**.
The gate has 18/89/21 natural invocations and delegates 7/25/8 to +7D53. The
+80B7 parent has 10/25/11 roots and independently reloads its saved byte between
+8048 and +7EC0. This absorbs a useful established subtree in one pass. Defer
+2511 until its partial +240A adapter and selected dependencies have a proven
native scope. No speculative backend or IR interface is introduced.
