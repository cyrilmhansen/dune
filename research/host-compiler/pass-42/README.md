# Pass 42 — +5929 / +46A7 causal closure

Baseline `5531351f24cb7c34b81afd072b38633a5b6fdfde`; incremental validation against
Pass40 full checkpoint `22c38cf8d83b61e602523c48aacf5147a69835ba`.
Archaeology only: no native implementation or CPU/Runner/CP/M/packet changes.

The required +5929 composition is now faithfully reproducible at every
MINIMAL/FIZZBUZ/PICTURE natural scope. +4651 is no longer opaque: its +4562
prefix-sum child was completed in Pass34, and its other required children already
have complete or sufficient bounded contracts. Required +4693/+4468 paths reuse
existing constructor proofs; no allocator or general +8 traversal scope is added.

| Corrected calls | MINIMAL | FIZZBUZ | PICTURE | Caller |
|---|---:|---:|---:|---|
| +5929 | 1 | 11 | 1 | +6240 |
| +46A7 | 1 | 11 | 1 | +5937 |
| +4651 | 1 | 11 | 1 | +46AF |
| +4693 | 1 | 8 | 1 | +46BD |
| +4468, globally observed | 2 | 11 | 1 | +46A3 or +4756 |
| +4468 required beneath +4693 | 1 | 8 | 1 | +46A3 |

These are freshly reconstructed CALL/return windows. Duplicate states remain
independent cases. All +46A7/+4651/+4693 calls are beneath the required +5929
parents; four independent +4468 calls provide discrimination without widening the
required parent scope. [route-distribution.json](route-distribution.json) retains
source-specific routes and actual callers.

## +4651: prefix hash, pointer selection and reuse gate

Extent `[4651,4693)`, 66 bytes, with **59 explained bytes**. Bounds are stable;
control flow and global contract remain partial. Seven unexecuted bytes at+4680
and+468C..+4691 remain RAW. Required paths are fully explained.

Save input C atA90F. Complete +4562 reads the paired width20C5/first-prefix20C6
carrier, calls complete +452B and publishes the descending prefix sum modulo128
atA760. Complete +422F freshly reads that index, selects word[A761+2*index] and
publishes working pointer A863 low/high.

At each iteration complete +4275 freshly compares working pointer against
reference A8AB. Returned A.bit0, consumed by RAR, means pointer>=reference;
its CY still represents the opposite unsigned borrow. If the bit is set,
complete +428E freshly reads the successor word atpointer+8, publishes A863 and
repeats. Only the historical comparison terminates this walk. Natural evidence
has 14 comparisons: one set-bit step and 13 clear-bit exits.

Fresh +4281 tests the resulting pointer. A zero pointer returns through +4692:
A00, HL0, DE=A864, BC from the prior comparator, S0 Z1 AC1 P1 CY0. Nine windows
select a zero slot directly; MINIMAL reaches zero after one +8 step.

For a nonzero pointer, freshly read the paired width/source carrier; BC=20C6 and
E=width feed existing bounded +4584. All three required calls take its positive,
equal-length, exact-payload-match route. That child compares bytes in descending
order and preserves the selected pointer. +4281 independently rechecks nullness;
complete +419F then freshly reads pointer+2. CMP against fresh saved A90F selects
the witnessed tag-equality return. Final A is the tag (02 in these three cases),
BC=10, DE=A864, HL=A90F and flagsCMP(tag,saved). No constant tag substitution is
used. Payload mismatches, retry/floor alternatives and post-match null return are
not generalized. Own data publication is onlyA90F; all child effects stay distinct.

## +46A7: independent null mask and construction

Extent `[46A7,46C1)`, **26 bytes**, all explained. Status is stable/complete/partial:
the local CFG is complete, but inherited child alternatives remain globally partial.

Save C atA911, genuinely read A911/A912 and pass only the low byte to +4651.
Then call +4281 independently. Its mask, rather than +4651's returned A, controls
RAR/JC. A nonzero pointer skips construction: three FIZZBUZ calls return AFF with
S1 Z0 AC0 P1 CY1, DE=A864, HL=current pointer and BC inherited from selection.

A zero pointer causes a **fresh** paired A911/A912 reread. Low C feeds +4693.
Its constructor returns the actual machine state: nine empty-slot insertions
(eight FIZZBUZ, one PICTURE) and one MINIMAL nonempty terminal-link insertion.
Both return A00, but empty insertion retains null-mask AC1 and nonempty insertion
has final ORA AC0. These flag channels must remain separate.

## Existing +4693 / +4468 scope and software continuation

+4693 saves tag atA910, pushes source pointer20C6 as a separate caller argument,
reads width20C5/20C6, and independently rereads A910/A911 for the tag carrier.
Only width low C and tag low E have the established constructor roles; neighboring
high bytes are genuine reads. No source pointer is inferred from an equal register.

+4468 consumes the original hardware continuation and **one two-byte source
argument**. Its +4474 PUSH D copies the continuation to constructor entrySP+2.
RET leaves SP=constructor entrySP+4 and PC=actual +46A3 CALL continuation, runtime
68A6. This restores wrapper SP before its own RET, which leaves wrapper entrySP+2.
The original argument bytes, copied continuation and temporary destination-pointer
PUSH words remain separate. Source-derived last writers include consumed positive
stack offsets; no residue is copied from historical post-memory.

Existing +4394 guard-success arithmetic selects p=old_top-9-count modulo65536,
updates top=p-1 and initializes size/header bytes. The constructor publishes tag,
zeros fields in historical order, and copies the source bytes descending into
p+10+index. Complete +422F/+4281 then select the current slot. The existing empty
arm rereads the index and publishes p to that slot; the existing nonempty arm
reads successor words through complete +83A0, tests the full word via ORA, follows
+428E as needed, and writes p at the zero terminal successor. Finally A863=p.
All ten required constructors fit these prior bounded laws. Four independent
nonempty constructor calls also validate them. No allocator failure, floor,
arbitrary chain termination or ownership meaning is inferred.

## Exact +5929 compatibility and upward impact

Every parent follows:

`+57B7 -> RAR/JNC -> fresh20C3/20C4 -> +46A7 -> fresh publications -> +239A -> +2511 -> +784E -> return`.

The found result is independently tested. After +46A7, +5929 freshly rereads20C3;
**gate A00/FF is not the selector02/05**. Fresh A863 is copied into A63B and A635
as separate low/high publications; fresh selector/width and zero extra populate
A628/A62B/A62E. Independent pointer rereads precede pointer+4/+5 publications.
Fresh +239A is followed by wrapping INR A/MOV C,A before bounded native +2511.
The final +784E input, output and return ancestry match all13 exact Pass41
acquisition cases, then the parent delegates its data registers and flags.

At the required terminating scopes, +46A7/+4651 and +5929 are reproducible and
native-ready. +6223 Route B has no remaining required causal blocker. The
transitive +5E98, +60E5 and +61A4/+620C composition chain is now closed at its
previously demonstrated scopes, including indirect reentry. This is bounded
readiness, not global completeness or arbitrary termination. Unexecuted +5929
selectors3/4/7/8/9 and not-found alternatives remain outside the claim.

Pass43 should assess and compose/migrate coherent parent units, account for the
ordinary reentry ancestry and private/software frames, and run the scheduled full
checkpoint. Do not spend another pass migrating individual tiny leaves. The
[deferred queue](boundary-assessment.json) names the now-ready operations.

## Evidence, scope and validation

The model-facing [work packet](work-packet.json) is **30,339 bytes**. It interns
CFG, route/write layouts, child sequences and stack patterns; established contracts
are referenced by coordinate/hash. Full rederivable proof is 17,337,416 bytes under
ignored `_build/host-compiler-pass-42/full-proof.json`. No raw traces or RAM dumps
are committed. Natural classification tests cover all63 target windows, including
independent constructors. **Zero historical-binary queries** were needed.

There are two new ProcedureHypotheses and **85 RAW -> UNDERSTOOD bytes**.
+5929 is refined only at the required bounded scope; its global classification
remains provisional/partial/partial. Existing +4693/+4468, pointer helpers and
Pass34 leaf contracts are unchanged. Shared numeric state and nonaliasing scopes
remain explicit; no table capacities or language-level interpretation are added.

Incremental categories and measured wall time are in [validation.json](validation.json):
new42, Pass32 ancestry, Pass34 composition, Pass13 constructor/continuation,
Pass41 acquisition, Pass33 upward ancestry, V1, cheap Dune, exact reconstruction
and diff checking. Unrelated suites and full epoch-aware Pass16/39/40 regressions
remain deferred to Pass43. Historical images reconstruct exactly **94,720 bytes**.
No historical correction, pragmatic divergence or fidelity debt is introduced.
