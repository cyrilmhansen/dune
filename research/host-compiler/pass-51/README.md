# Pass51 — resident +1272 pending REL finalization

Baseline/full checkpoint `f7b744e2560c0de8ac1115cf91d4beb190f2e7c2`.
Fresh corrected ancestry shows +011E is a CALL site in non-returning PLI1 startup,
not an enclosing ordinary procedure. Separate startup/file-opening, canonical
+0C75 input driving, output/statistics, console PASS summary and resident REL
finalization lifecycles. +1272 is one coherent root per source, all from resident
+02E3. It is independent of console +0D09 and excludes startup +1031, overlay
loading +0692 and the PLI2 generation phase. No upward widening.

Fresh1D05 bit0 must be set and fresh2029 bit0 clear. At each iteration form two
independent zero-equality masks from fresh1D8A and1D8B through wrapping SUI00,
ADIFF and SBB A. Preserve the first through PSW/POP B/MOV C,B; OR and RAR decide
whether to call canonical +1140 with C0. The indices are reread after every child.
The canonical bit writer shifts the actual retained REL byte and appends C.bit0,
increments bit index modulo8, advances byte index and flushes exactly at128.
Compose canonical SetDMA with1D0A, sequential-write withFCB1CE4, require actual
successful status, and clear1D8A only after the service/CPI00. Termination follows
both indices becoming zero; observed padding counts665/961/609 are consequences
of entry indices44:7 /7:7 /51:7. Synthetic0:0,127:7,127:1,1:0 states distinguish
state-driven termination without guest/oracle queries.

Then +064C saves originalBC=1CE4 on the historical stack; +02FE restoresDMA0080
through canonical +02EE. Independently read the saved low/high word intoDE,
C16 invokes canonical +19BB and real staged BDOS close. CPIFF flags survive
POP H and RET. ReturnedA0/BC0010/DE1CE4/HL1CE4 andS0 Z0 AC0 P0 CY1 are actual
child/comparison channels. Original root continuation03E6 remains untouched;
RET12AD yields entrySP+2. Child CALLs, PSW and FCB saves derive all residue.
The deepest service frame is sixteen bytes below rootSP; the historical BDOS
sentinelFDFE is outside active frames. No recursion, N2/N8 or XTHL is reached in
this root, and canonical acquisition parents remain independent outside it.

New bounded contracts: +1272 (53 RAW bytes), +064C (23), +02FE (7).
Extend +1140 successful-flush and +0328 successful-service scopes with no new RAW
bytes for either. Existing bit arithmetic and resident service machinery remain
canonical. All five contracts remain partial in semantic/global scope; +02FE and
+0328 have complete local CFG, while finalizer/close/bit-writer sibling guards and
errors remain RAW. No arbitrary error, allocator, capacities or file failure law.

Independent shadows cover required +1140 children665/961/609, all +064C calls5
per source, all +0328 calls3/9/3 and all +02FE calls20 per source. Three root shadows
match registers/flags, SP/PC, all65536 RAM bytes, ordered logical writes, stack
last writers, child CALL chronology, DMA/filesystem and ordered service/record
state. Actual service order is26,21,26,16; final record indices1/5/1. Preparation
stages copied RAM/filesystem/DMA, validates the whole bounded operation and never
falls back after partial live mutation. Corruptions and unsupported scopes reject
without changing live state. Full compiler runs preserve console, filesystem,
INT/REL chronology, compiler milestones, warm boot and exact golden REL hashes.

The fresh post50 hierarchy has only +0C75, +80B7 and resident INT emitter external
native calls. All other canonical external root counts are zero. These roots
remain unchanged; the new +1272 absorbs zero already-native transitions. Actual
whole-run counts, not candidate inclusive windows, establish savings:

| Source | Pre51 guest | Post51 guest | Saved | Pre host | Post host |
|---|---:|---:|---:|---:|---:|
| MINIMAL | 380445 | 349253 | 31192 | 72 | 73 |
| FIZZBUZ | 838187 | 793194 | 44993 | 95 | 96 |
| PICTURE | 428026 | 399445 | 28581 | 56 | 57 |

Compact packet, hashes and summaries are durable; full journals/snapshots stay
ignored under `_build/host-compiler-pass-51`. The deterministic driver batches
residual discovery, component CFG, contracts, packet, shadows, hybrids and final
validation. Pass46 catalog hash assertions now explicitly use their historical
epoch; no historical fact was corrected. Incremental receipt is validation.json;
Pass50 remains the FULL checkpoint. All94720 historical bytes reconstruct exactly.
Zero new oracle queries; bounded archaeology extension, no historical correction,
pragmatic divergence or fidelity debt. scripts/view-optimist.sh is untouched.
RecommendedPass52: rank the repeated resident bit-field emission parents around
+119E separately from the PLI2 compiler-generation family and console summaries.
