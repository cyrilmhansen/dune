# Pass 38 — acquisition dispatch and indirect reentry

Baseline: `280f491cc0c56af8b953944e95b7673263d434c0`. Archaeology only: no native operation, new PL/I fixture, compiler capture or CPU/Runner/CP/M change.

## Natural scope and compact proof

Fresh corrected ordinary windows give MINIMAL/FIZZBUZ/PICTURE counts **0/3/0** for each of +506E, +500F and +4F54. +506E callers are +5F3A; +500F callers +53BD; +4F54 callers +5012. Duplicate states remain independent. Across the required gates, spine and useful independent small operations, **252 windows** are mechanically checked.

`work-packet.json` retains one decoded supported CFG, three root route layouts/child sequences, three interned stack patterns and nine root value-delta cases. Complete children are contract ID/hash references; partial child I/O is separate. Its **27,946 bytes** meet the 32 KiB target. Ignored `_build/host-compiler-pass-38/full-proof.json` is **36,424,118 bytes** (1303.375 times the model view), with each factual instruction interned once and overlapping envelopes represented by references. It is rederivable from the unchanged captures. This task packet does not alter Procedure Evidence Packet V0.2. No full-RAM shadow or native compatibility planner is claimed by this archaeology pass.

## +506E → selected dispatch → +500F

At the demonstrated domain, eight frame bytes are established by three PUSH H operations and two PUSH/INX-SP one-byte saves. F=entry_SP-8: F0=input C, F1=input E, F2/F3=fresh word[A635], and F4..F7=inherited HL. Complete +81F1(C1) runs after pointer capture. Fresh F1 is compared with32 then20; the natural E=14 passes the represented range checks.

**The jump-table index is fresh saved E, not input C.** MOV C,M reads F1, MVI B,0 zero-extends it, and two DAD B operations select little-endian word[789F+2*E]. All three natural slots are78C7, containing75BB (PLI1+53BB). PCHL transfers to that block without creating another CALL frame. There +500F(C CF) precedes +4F2A. Other dispatcher slots/routes remain RAW and unsupported.

Pass33's +500F law is reused: its one private byte is read again after +2308. The wrapper's **entry C is15**, then +2308 itself sets C0 before +22CB; no assumed-zero entry is used. Fresh A630 is published atA62E before that classifier call. Actual classifier2 plus fresh savedCF wraps toD1, passed to native-known +2511. +4CD4 follows. Only then is literal1 written atA932. Actual +500F returned A is80 with +4CD4's flags; it is not the published1.

+4F2A returns0 in these cases. The dispatcher subsequently rereads F1 for its final comparison, restores the saved pointer toA635 low/high, and **freshly reads A932**. There is no intervening A932 writer. Four POP H restore inherited entry HL. BC comes from +4F2A; DE is **F+3**, the frame high-byte carrier address left by XCHG, not the saved pointer. NZPA/AC come from CMP20,savedE; CY comes from the later DAD SP. A=1 is a fresh publication read, independent of child-return values. All return fields and CALL-word ancestry are checked.

## Exact cause of the two indirect reentries

+4F54 calls +4CC2, rotates its actual result, calls +6619, then independently calls +4CE1, rotates that result, calls +6619 a second time, and finally calls +3304. The two selector-match gates request28 and2C via existing partial +01AF. Each match delegates acquisition to +784E **before** returning literal1. The actual next-selector writers yield1 after the first acquisition and2 after the second. Returned1 denotes the earlier match, not the acquired selector or success of an abstract service.

Each +6619 invocation follows the required clear-repeat path:

`6619 →65F9 →654E →64F2 →6477 →640D →6314 →625D →6223`

The first edge is +4F5B or +4F65; the final actual CALL is +6273. +654E's two inherited words and +6477/+640D/+6314's reserved one-byte stack slots remain real historical storage. Fresh A934.bit0 is clear. Complete +57B7 predicates at bases7969/7960/7957/7950 terminate by their actual sampled zero bytes and return clear masks; no precomputed skip schedule is substituted. +625D's independent requested28 probe mismatches, permitting CALL +6223; A934 is reset only after its return. The independent requestedF9 probe then mismatches.

The first reentry observes selector1: existing +020E returnsFF and +6223 takes Route A (`01E8/256C`). The second observes selector2: +020E returns00 and +6223 takes Route B (`5929/2511`). Their corrected identities are cross-checked with Pass32, and Pass33's ancestry is reused. The first entire reentry returns before the second begins. This is **indirect reentry**, not a direct recursive CALL in +500F/+506E/+4F54. Each +4F54 retains +3304's BC/DE/HL/flags while replacing only A with literal1; natural +3304's direct returned A is0F and its Z flag remains set after the literal.

Three independent +654E loop invocations are observed elsewhere in FIZZBUZ. They are outside the required six clear-repeat invocations and remain unpromoted/delegated; they are not described as unobserved.

## Small operations closed together

- **+23B9:** publish E atA651 before C atA650; compare fresh E against fresh C. Reload the selected byte and return unsigned max(C,E), retaining **CMP(E,C)** flags. Both branches occur in24 independent FIZZBUZ calls. BC/DE preserved; HL=A650; no body stack traffic. Complete at its nonaliasing scope.
- **+2308 / +4C4C:** set C0 internally and delegate respectively to existing +22CB / bounded +240A. No constant-result substitution or duplicated child algorithm.
- **+4CC2 / +4CE1 / +4CD4:** requested28/2C/29 probes, exact RAR incoming-CY/NZPA behavior and branch polarity. Acquisition remains delegated to +01AF/+784E; unobserved alternatives remain RAW.
- **+4F2A:** fresh A628 &14 test, two overlapping paired reads atA62F/A630 andA630/A631, cached maximum toA62E, then fresh `u8(A62D-A630+A62E)` toA62B before +4C4C. Returned state is that child's state. Neighboring bytes are read even where the low-byte arguments select the calculation.
- **+31FB:** fresh AE32→A667; independent control, primary, secondary and mapped-word lookups publish A62A/A62D/A630/A63F..40. Fresh position→Balance_scan; decrement its direct stopping cursor and save it. Four fresh second-position lookups publish A629/A62C/A62F/A63D..3E, then literal1→A634. Nine existing complete primitives are substituted. Every paired A667/A668 read remains separate. Final A/BC/DE derive from the last mapped-word child; HL=A634; NZPA/AC from stopping-cursor DCR, CY from the final mapped-word lookup. **0/10/1** natural calls; complete under inherited nonaliasing/conditional-termination scope.
- **+2705:** fresh A628, CPI16, natural mismatch shared RET; exact flags and preserved BC/DE/HL. **0/19/1** calls. RAW equality call unsupported.
- **+329F:** two independent overlapping pairs select C and DE; +23B9's result→A62B, then unconditional0→A62E. The neighboring extra byte is read before zeroing. Exact comparison flags and child BC/DE are retained; HL=A62E. **0/5/0** calls; complete at its nonaliasing scope.

Stack proof derives CALL words from canonical instruction length/runtime address and every PUSH from the actual register/PSW source, high then low. Final stack patterns retain relative addresses, last writers and value deltas; overwrite chronology hashes point to the single-copy full proof. No residue is copied from an imagined post-state or native oracle.

## Substantial boundaries and parent impact

+3304's local interface is now explicit: +31FB, +30C1, fresh selector comparison, +2705, literal2→A634, another fresh comparison, optional +2C59, independently +2705 again, then +329F. The completed small operations do not make its **+30C1 and +2C59** algorithms known. Their observed read/write ranges, child I/O and chronology digests are retained as delegated interfaces. No tuple of their outputs is used as a replacement law. +3314's alternative remains RAW.

The deferred native-ready queue gains +23B9, +31FB and +329F, plus bounded +2308/+4C4C/+2705. The gates/spine have known local compositions but depend on acquired input and the partial +6223 parent. +500F/+506E, +5E98, +60E5 and +61A4/+620C are **not yet faithfully reproducible/native-ready**. +784E is **not the sole blocker**: +3304 requires +30C1/+2C59, and +6223 retains its existing +256C/+5929 dependencies. These boundaries cannot be hidden by final A=1.

Recommend **Pass39 focused on +3304's +30C1/+2C59 state-transformation subtree**, starting with the earliest +30C1 field producer and retaining +2C59's larger publication transformation as the substantial target. Reuse +31FB/+2705/+329F and all native children; do not allocate migration passes to each small leaf. +784E remains the separate input-service obligation.

## Fidelity and validation

**565 RAW bytes become UNDERSTOOD**, with21 new hypotheses and one +500F refinement. Only +23B9/+31FB/+329F become complete contracts. Other entries retain explicit partial scope; no global parent completeness is promoted. All unexecuted local alternatives remain RAW; independent +654E loop bytes are also deliberately not promoted.

Zero new historical-binary queries were needed: exact instruction/dataflow proof plus all natural cases distinguish these laws. No prior semantic contract correction, pragmatic divergence or fidelity debt is introduced. Compiler/source meanings, capacities, ownership, arbitrary aliases and arbitrary recursive termination remain unclaimed.

The timed regression runner serializes shared Dune build/test work, then uses four workers for immutable captures/prebuilt executables and unique temporary experiment/fixture outputs. A read-only Dune-exec launcher invokes the existing compiled binaries without concurrent builds. Every previous category runs; none is skipped on a prior-pass assumption. Per-category elapsed times, top ten slowest categories, wall time and sum of times are recorded in `validation.json`; detailed logs remain ignored. Repeated parsing of the same three JSON captures across independent regression suites remains an obvious cost; the target checker batches22 entries into one pass per capture. No validation framework or emulator architecture redesign is performed.

Final validation passed all **61 categories**, including **381 Python tests** (19 new, 109 MINIMAL and 27 packet/continuation), the project/native/CP/M suites, V1 and exact image verification. Two aggregate commands used up to four safe workers. Total wall time was **986.676 seconds**, with **3702.549 summed category seconds**, including the affected-suite rerun after refreshing the current MINIMAL dynamic-progress report; frozen historical pass snapshots were retained. All four images reconstruct **94,720 bytes exactly** and `git diff --check` passes. CPU, Runner, CP/M and packet architecture remain unchanged.
