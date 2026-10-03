# MINIMAL decompilation pass 10

Task `MINIMAL_DECOMPILATION_PASS_10`; baseline `83f3f21`. This pass recovers the
executed traversal/buffer, resident word-processing and literal-result helpers,
then substitutes their scoped operations upward. No compiler capture, FIZZBUZ
work, new fixture or packet infrastructure change was made.

## Structural reconnaissance and selective packets

Corrected CALL entries, original hardware slots/returns, local branches, stack
behavior and independently callable neighbors support the hypotheses below.
No dynamic-context min/max or RoutineCandidate extent supplied ownership.
[structural.json](structural.json) retains callers, counts, exact return steps,
candidate extents and incoming-transfer checks. All seven executed targets have
ordinary original-slot returns, zero reserved frame bytes and no recursion.

| Target | Extent | Calls | Own coordinates / occurrences | Classification |
|---|---|---:|---:|---|
| PLI1+452B | [452B,4562) | 6 | 27 / 726 | PACKET CANDIDATE |
| PLI1+422F | [422F,4241) | 7 | 11 / 77 | SMALL / DIRECT |
| PLI1+4275 | [4275,4281) | 6 | 6 / 36 | SMALL / DIRECT |
| PLI1+428E | [428E,429D) | 6 | 9 / 54 | SMALL / DIRECT |
| PLI1+4584 | [4584,45F0) | 4 | 47 / 804 | PACKET CANDIDATE |
| PLI.COM+1207 | [1207,1229) | 2 | 18 / 36 | PACKET CANDIDATE |
| PLI1+22CB | [22CB,2308) | 2 | 25 / 50 | SMALL / DIRECT |
| Requested PLI1+84BB | no supported extent | 0 | 0 / 0 | STRUCTURE ONLY |

V0.2 packets were generated for the complex procedures after structural seeding;
Markdown preceded selected JSON queries. +46ED/+4738/+666E/+2355/+28AA packets
were regenerated after substitution. All generated packet JSON/Markdown remains
ignored under `_build/minimal-pass-10/packet`. Small helpers were analyzed directly.

### Correct the +84BB anchor before interpreting its zero result

Pass-9 prose and the requested anchor called the +66FA dependency “+84BB.” The
retained exact coordinate was already different:

```text
PLI1+6704: CALL A4BBH
verified PLI1 runtime load base: 2200H
A4BBH - 2200H = file offset 82BBH
target_origin: PLI1.OVL+82BB
callee RET: +82C5; caller resumes +6707
```

There is no MINIMAL CALL or instruction at file coordinate +84BB. It receives
no ProcedureHypothesis, bounds, contract or byte promotion. The **existing
complete +82BB contract** is reused; it is not decompiled again. It reads the
first word through HL into BC, adds the low word byte through DE with ADD C,
then the high byte through DE+1 with ADC B, returning their sum in HL.
Observed zero is thus justified by the actual addition operation, not by equality
of zero-valued words, an inferred subtraction or a same-address ownership guess.
The cached-word role and +66FA/+666E caller descriptions now cite +82BB explicitly.

## Cluster A: buffer sum, pointer selection and comparisons

+452B uses **BC as source pointer, E as byte count; D is ignored**. It stores
those at A901/2 and A903, clears A760, then decrements remaining before reading
source[remaining]. The sum wraps as an 8-bit byte; final ANI7F republishes and
returns its low seven bits. At nonaliasing buffer/scratch/return-stack scope:

```text
sum=0; remaining=E
while remaining>0:
    remaining--; sum=u8(sum+byte[u16(source+remaining)])
A=byte[A760]=sum&7F
```

Six count-seven calls read descending ranges FBF1..FBF7, 20C6..20CC or
A948..A94E and return07. Only A760/A901..A903 are written; the demonstrated
A947/A948 buffer state is not modified. DE is preserved; HL=A903; BC=0 after
nonempty traversal, otherwise unchanged input BC. CY=0 and NZPA/AC come from
ANI7F, not the byte additions. Its bounds/CFG/contract are stable/complete/complete.

+422F zero-extends byte[A760], reads word[A761+2*index] and publishes it to
A863. A761 is the existing `link_heads` storage from the initializer, now with
the sum-indexed read relationship recorded; it is not A8AB. Return HL=selected
pointer, DE=selected high-byte address, BC=A761; A/NZPA preserved, CY=0 from the
fixed-base address addition. Only A863/4 are written. No new capacity or ownership
claim is made.

+4275 supplies BC=&A8AB and DE=&A863 to complete resident +1A33:

```text
difference=u16(word[A863]-word[A8AB]); CY=(working<reference)
SBB A -> FF if borrow, else00
CMA   -> 00 if borrow, elseFF; flags unchanged
```

Returned A=FF iff working pointer>=reference, while returned CY means the
opposite inequality. Z/S/P still describe self-SBB **before CMA**; in particular,
returned FF can have Z=1. HL=difference, BC=reference word, DE=A864. Only the
nested CALL stack is written. The caller's RAR/JNC exits the loop iff p<reference.

+428E reads old p=word[A863], then word[u16(p+8)], and publishes that successor
word at A863. Return HL=new pointer, DE=u16(p+9), BC=8; A/NZPA preserved; CY is
the address overflow from p+8, not a property of the loaded pointer. It has no
null guard. The +8 storage relation is established without inferring list/tree
ownership or guaranteed termination. Both +422F and +428E are complete at their
declared nonaliasing/readable-slot scopes.

+4584 saves source BC and low count E at A905/6/7. Complete resident +1A33
computes record_top-working_pointer; JNC +4595 returns on p<=top. Its observed
p>top path requires u8(byte[p]-10)==count, then compares source[k] with p+10+k
for k=count-1 down to0. All four count-seven invocations have header17 and equal
payloads. They return at +45DD with pointer unchanged, A=0, BC=10, DE=source,
HL=p+10 and flags from final CPI remaining,0. This A is not a normalized match
predicate consumed by +46ED; the caller subsequently tests A863 through +4281.
Only A905..A908 and transient CALL/PUSH stack are written on the matching path.

**STATIC / UNOBSERVED:** byte mismatch clears remaining at +45E1; length
inequality or zero count reaches +45E9 CALL +428E and retries at +458C;
the p<=top exit at +45EF does not itself force A863 to zero. Zero-length data
does not vacuously return a match through +45DD. These 12 bytes remain RAW;
the procedure remains provisional/partial/partial, UNDERSTOOD only at its
positive-count matching scope. Arbitrary successor-chain termination and wider
alias conditions remain unproved.

## +46ED and +4738 refinement

+46ED now composes a coherent scoped operation:

1. Sum the A948 buffer using low byte[A947]; select its A761 word slot into A863.
2. While pointer>=word[A8AB], follow its +8 word. +4275's returned A and the
   caller RAR establish that inequality; helper CY is not tested directly.
3. Return if A863 is zero. Otherwise call +4584 at its declared payload scope.
4. Re-test pointer-null, compare byte[p+2] with saved request C at A915, and
   advance through +8 on a field mismatch.

Both recorded C=28 invocations produce the same ordered pointer chain through
distinct calls/states: sum7 selects FBE1; reference=FBE1; first advance gives
FBC6<reference. Seven payload bytes match, but field05 differs from28. The next
+8 word is zero, causing the final null return. Equality/post-search-null early
RET bytes +4730/+4723 remain RAW and explicitly STATIC / UNOBSERVED.
+46ED's 73 represented bytes become UNDERSTOOD at partial scope; its completeness
stays provisional/partial/partial. No unconditional search/termination or storage
ownership theorem is substituted.

+4738 now knows what +46ED supplies before its +4281 test: the demonstrated
lookup returns null because the payload matches but the field differs. Its normal
constructor path therefore runs. The existing +4468 software-cleanup proof is
unchanged: one source word, two consumed bytes, resume +4759. Then it retains
three distinct values/channels: saved old word, old+count at h+2, saved old at
new p+6. Observed old0/count7 gives word[FBE3]=7 and word[FBBB]=0. Its 85 bytes
become UNDERSTOOD, with stable/complete/partial completeness. +4468 remains
STRUCTURED/partial; only the newly complete +422F/+428E effects and its blocker
description were substituted. Opaque +83A0, allocator failure and its RAW arm
remain explicit; no software boundary was decompiled again.

## Cluster B: field/cache addition and resident bit processing

+66FA is now complete at nonaliasing operand/return-stack scope:

```text
p=word[A863]
complete82BB(HL=p+6, DE=&A9D6)
HL=u16(word[p+6]+word[A9D6])
```

Return BC=field word, DE=A9D7, A=high sum; CY is full-word overflow and NZPA
describe the high ADC, not full-word zero. Only nested CALL stack is written.
Its 14 bytes become UNDERSTOOD, stable/complete/complete.

Resident +1207 independently accepts BC as a word, caches low/high at20BD/BE,
and invokes partial +119E in this exact order:

| Writer call | C | E |
|---|---|---:|
| +1211 | 80 | 2 |
| +121B | reloaded cache low byte | 8 |
| +1225 | reloaded cache high byte | 8 |

At the existing writer/cache-preservation success scope this requests prefix
bits10, then low byte MSB-first, then high byte MSB-first: 18 bit operations.
Both BC=0 calls have different callers (PLI1 and PLI2) and output cursor states;
equal zero bytes alone do not establish source identity. Exact MOV A,L/MOV A,H
and ordered LHLD reads at20BD/BE do, and are checked separately.
Own cache publication differs from child writes to20B6/7/8, REL buffer1D0A and
indices1D8A/B. Return A=0/HL=20B8, with flags from the final zero-remaining writer
comparison; remaining registers are writer-derived (observed BC1D0A/E08 and
incoming D high retained). Its 34 bytes become UNDERSTOOD, stable/complete/partial.
Resident +1140/+119E contracts are reused without broadening their flush/error
scope. No PLI1-specific meaning is assigned to the resident word interface.

+666E's demonstrated selector09 pipeline is now explicit: cache input BC/DE,
read field+3 &1F, request seven setup bits through119E(C96,E7), add field word
p+6 to cached DE through +66FA/+82BB, pass that sum to resident +1207, then
process seven payload bytes through +66C6 (a zero bit and eight byte bits each).
The independent observed writer-input check yields **7+18+7*9=88 ordered bits**.
Operand fields, cached DE, resident word cache, payload and REL output storage
remain separate. +28AA ignores returned A=6 and reloads preserved A863 at this
normal nonaliasing/no-flush scope. +666E's 54 represented bytes become UNDERSTOOD,
remaining provisional/partial/partial; selector11/other selectors and resident
flush/error paths are still excluded.

## Cluster C: +22CB, +230E and +2355

+22CB caches input index at A64B and rereads byte[A628+index] for comparisons
15,16,19. Both recorded index0/byte05 calls return default literal02. BC=A628,
HL=selected slot, DE preserved; only A64B is written. Flags still describe
CPI19 on05: CY1/Z0/S1/P0. They do not describe returned02.
**STATIC / UNOBSERVED:** literal15 returns02 with different comparison flags,
literal16 returns00, literal19 returns01. Their nine bytes stay RAW. The represented
52 bytes become UNDERSTOOD, provisional/partial/partial.

+230E's two increments therefore transform the literal result byte02->03->04;
CY1 survives, while NZPA come from the second INR. This is arithmetic on a selected
return byte, not Boolean normalization. Source-language data/status meanings
remain unknown. +2355's correlated results remain (index0/byte40 ->05),
(index0/byte05 ->04 twice), (index2/byte28 ->01 twice). Its literal31/2A alternatives
and +230E's 24/25 zero-result arm remain unobserved and are not newly substituted.
Both existing hypotheses stay UNDERSTOOD at partial scope.

## +28AA promotion and branch audit

Only the existing operational map's helper regions were refined. The normal
operation now has explicit sum-indexed pointer selection, payload and request-field
matching, constructor/word repair, field+cached-word addition, scoped bit processing
and distinct mapped publications. This is substantially stronger than assigning
names to opaque CALLs. The **684 represented bytes become UNDERSTOOD at partial
scope**. Bounds/CFG/contract remain **provisional/partial/partial**; all 253
enclosing RAW bytes and single-outcome branches are unchanged. No full-procedure
algorithm, source-language interpretation or tree ownership is claimed.

The first saved-PSW +2185/+6708 predicate and both software-child boundaries remain
as proved in V0.2. Original outer RET +2C52 remains caller-owned. The later pipeline
reloads A863 rather than using +666E's A, then publishes the pointer through its
selected word slot/mapped word table and distinct mapped byte/control/auxiliary
tables. Existing publications02/14 through +2355 retain their actual scopes.

| Branch/value | Producer | Final representation/flag and polarity |
|---|---|---|
| +452B +453E JNC | A=0; CMP remaining | CY=(remaining>0); taken iff remaining==0 |
| +4275 returned A | 1A33 p-reference; SBB A; CMA | A=FF iff p>=reference; CY still p<reference; NZPA self-SBB before CMA |
| +46ED +4702 JNC | returned A; RAR | final CY=A.bit0; taken iff p<reference, despite original helper CY=1 |
| +4584 +4595 JNC | 1A33 top-p | tested CY=unsigned borrow; taken iff p<=top |
| +4584 +45A4 JNZ | DCR twice/SUI8 then CMP count | tested Z; taken iff wrapped header-10 differs from count |
| +4584 +45B2 JZ | CPI remaining,0 | taken iff remaining==0; advance arm unobserved |
| +4584 +45D2 JNZ | source byte CMP payload byte | taken iff unequal; mismatch arm unobserved |
| +4584 +45DA JNZ | CPI remaining,0 | taken iff remaining!=0 |
| +22CB JNZ at22DB/22ED/22FF | selected byte CPI15/16/19 | taken iff byte differs from corresponding literal |
| +230E returned A/flags | literal02; INR twice | A04, CY1 unchanged; NZPA secondINR; no Boolean interpretation |
| +82BB returned flags | low ADD C, high ADC B | CY=word overflow; NZPA high byte, not full-word zero |

Packet-supported dependency chains supply branch source/transform/flag identities;
known complete callee contracts supply the word operations conservatively. Partial
paths remain declared rather than being inferred from equal states.

## Diminishing-returns audit and Pass-11 choice

After this pass PLI1 still has **88 unresolved CALL entries** and **6,396 RAW
instruction occurrences**. An additional bounded structural audit of eight
ordinary-return entries yields the following local footprints, excluding every
matched child window. These are not new procedure extents/contracts or promotions.

| Executed opaque entry | Calls | Own coordinates | Own occurrences |
|---|---:|---:|---:|
| +01AF | 34 | 11 | 281 |
| +8048 | 22 | 43 | 570 |
| +7EC0 | 18 | 12 | 205 |
| +7E5F | 16 | 45 | 720 |
| +7A93 | 13 | 12 | 156 |
| +80B7 | 10 | 9 | 90 |
| +4227 | 8 | 5 | 40 |
| +2511 | 8 | 15 | 120 |
| Total selected audit | | | **2,182** |

[remaining-helper-audit.json](remaining-helper-audit.json) keeps exact CALL-based
isolation and direct callee inventories, not old context occurrence estimates.

1. **Executed opaque helpers recoverable from MINIMAL:** those eight entries alone
   account for substantial repeated local work. +7E5F's four mapped setters are
   already complete; +7A93 is a leaf; +8048 composes known mapped helpers plus
   remaining ordinary wrappers. +83A0 also has six executed ordinary calls and
   still blocks the constructor's link-word operation. These are existing-code
   opportunities before introducing inputs.
2. **Structured larger bodies with incomplete semantics:** +4468 remains
   STRUCTURED (173/195 represented bytes) with opaque +83A0 and a RAW arm.
   +28AA/+784E/+7C1B/+7D53 are UNDERSTOOD only at scoped partial contracts; their
   enclosing hypotheses must not be treated as semantically complete.
3. **Unobserved outcomes:** +28AA's alternate guards, +4584 mismatch/length/floor/
   zero-count paths, allocator failure, non-30 +429D selectors, +22CB literals,
   recursive +7C1B alternatives and resident output flush/error cases have no new
   dynamic outcome in MINIMAL. Static analysis can describe some operations but
   cannot manufacture those states or increase coverage.
4. **Producer provenance:** earlier composition of pointer-slot/reference values,
   map/table contents, initial headers and output consumers; alias conditions
   beyond the captured scopes; no global ownership or termination theorem.
5. **Genuine new-input/construct questions:** which constructs select field11
   rather than09, produce nonzero +1207 words, choose literal alternatives or
   trigger allocator/output error paths cannot be distinguished by this capture.
   No fixture is designed here. Low-level low/high source order itself is already
   mechanically justified, even with zero-valued words.

Recommend **A: one more MINIMAL helper pass**, prioritizing +7E5F/+7A93 and
+83A0, then their +8048/+7EC0 composition. The 2,182 audited local occurrences
and remaining constructor blocker satisfy the “substantial reusable executed
opacity” criterion. Alternate-path coverage is approaching diminishing returns,
but C/D are premature while those demonstrated operations remain unexamined.

## Progress, packets and validation

| Executed status | Before | After |
|---|---:|---:|
| RAW | 14,306 | 14,024 |
| DECODED | 304 | 304 |
| STRUCTURED | 2,348 | 1,438 |
| UNDERSTOOD | 4,054 | 5,246 |

RAW->STRUCTURED **0**; RAW->UNDERSTOOD **282**; STRUCTURED->UNDERSTOOD **910**.
UNDERSTOOD CALL entries **87->99**; STRUCTURED 14->9; unresolved 290->283.
The 391 CALL/RST and eleven PCHL continuation entries remain separate inventories.
Dynamic UNDERSTOOD **47.2629%->47.7827%** (207,956->210,243 occurrences).
PLI1 **78.7522%->84.0023%** (33,765->36,016); PLI.COM 47.8737%, PLI0 40.8068%,
PLI2 22.3957%. [progress.json](progress.json) and [dynamic-progress.json](dynamic-progress.json)
retain exact counts; [before.json](before.json) preserves the starting snapshot.


| Packet | JSON bytes | Markdown bytes |
|---|---:|---:|
| PLI1.OVL+452B | 820,046 | 6,513 |
| PLI1.OVL+4584 | 959,798 | 11,746 |
| PLI.COM+1207 | 283,412 | 6,840 |
| PLI1.OVL+46ED | 423,786 | 12,454 |
| PLI1.OVL+4738 | 325,922 | 8,890 |
| PLI1.OVL+666E | 476,987 | 8,956 |
| PLI1.OVL+2355 | 264,068 | 8,548 |
| PLI1.OVL+28AA | 2,192,713 | 36,973 |

Packet sizes and single-sample times are in [packet-sizes.json](packet-sizes.json).
Artifacts are not committed. All packets use the established zero-byte frame and
empty class-slot profile; no extractor generalization was required.

Validation passes: project tests; all MINIMAL baseline/pass-1–10 tests (93);
V0.2 packet tests (23, including 55 continuation corrupt/unsupported variants);
V1 tests (9); verifier tests (11); dynamic-progress consistency; `git diff --check`.
Eight new tests check descending sums, pointer-slot/+8 relationships, complemented
borrow versus returned flags, payload address/order and top-p operand order,
actual82BB identity and addition, low/high source identity, 18/88 ordered writer
bits, literal-result arithmetic, scopes, RAW gaps and original continuation slots.
Historical pass8/9 STRUCTURED assertions now use their immutable snapshots;
live completeness/progress checks remain. Precise adjacent-byte role comments
were retained when substituting caller contracts.

The verifier reconstructs **all 94,720 historical bytes exactly**, checking section
and full-image hashes, partitions, encodings and runtime mappings. Every former
stable label survives; operand-internal former RAW labels remain coordinate-only
EQUs. No unexecuted byte is promoted. Unrelated untracked files remain untouched.

```sh
python3 tools/annotated-assembly/test_minimal_pass_10.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_procedure_evidence_packet.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_decompilation_annotations.py -v
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
git diff --check
```
