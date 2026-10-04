# MINIMAL decompilation pass 12

Task `MINIMAL_DECOMPILATION_PASS_12`, baseline `f5f0f5c`. This is a focused
repeated-helper pass. No compiler capture, new fixture, FIZZBUZ execution or
Procedure Evidence Packet infrastructure change occurred.

## Structure and evidence interface

[structural.json](structural.json) records exact CALL callers/counts, local
coordinate/occurrence counts, candidate bounds, original-slot returns, branches
and unresolved paths. Corrected return windows exclude nested calls; no context
count, RoutineCandidate or context min/max supplied ownership. All entries have
ordinary outer hardware returns, no reserved frame and no observed recursion.
PUSH/POP PSW and temporary pointer saves restore SP before RET. Distinct +8380,
+8386 and +8396 identities remain; neither proximity nor equal values establishes
shared code. No selected target remained STRUCTURE ONLY.

| Entry | Calls | Own coordinates / occurrences | Classification | Completeness (bounds / CFG / contract) |
|---|---:|---:|---|---|
| +57B7 | 6 | 26 / 502 | SMALL / DIRECT | stable / complete / complete |
| +41AF | 5 | 6 / 30 | SMALL / DIRECT | stable / complete / complete |
| +421F | 6 | 5 / 30 | SMALL / DIRECT | stable / complete / complete |
| +47E2 | 2 | 8 / 16 | SMALL / DIRECT | provisional / partial / partial |
| +4890 | 3 | 70 / 136 | PACKET CANDIDATE | provisional / partial / partial |
| +4802 | 2 | 71 / 166 | PACKET CANDIDATE | provisional / partial / partial |
| +8386 | 3 | 14 / 105 | SMALL / DIRECT | stable / complete / complete |
| +2221 | 3 | 25 / 75 | SMALL / DIRECT | provisional / partial / partial |
| +020E | 5 | 13 / 65 | SMALL / DIRECT | stable / complete / complete |
| +13E3 | 2 | 20 / 40 | SMALL / DIRECT | stable / complete / complete |
| +14C8 | 6 | 6 / 36 | SMALL / DIRECT composition | stable / complete / complete at inherited +7B7A scope |
| +8380 | 3 | 4 / 33 | SMALL / DIRECT | stable / complete / complete |
| +8268 | 5 | 5 / 25 | SMALL / DIRECT | stable / complete / complete |

Structural seeds preceded semantic interpretation. V0.2 packets for +4890 and
+4802 were read Markdown-first; selected JSON states/accesses supplied detailed
questions. Both zero-frame packets isolate ordinary nested callees. No new
continuation form appeared. Generated artifacts remain ignored under
`_build/minimal-pass-12/packet`; final JSON / Markdown sizes are recorded below.

| Packet | JSON bytes | Markdown bytes |
|---|---:|---:|
| PLI1+4890 | 337,339 | 12,000 |
| PLI1+4802 | 428,018 | 13,542 |

The dependency chains expose saved PSW masks, helper output boundaries and final
ANA/RAR tests. +4802's ADI carry producer remains unsupported by the compact
chain; exact local instruction/state inspection resolves it. This isolated
arithmetic limitation does not justify V0.3. Class entry C is merely a grouping
key; individual chronological member records, not independent value sets,
justify these contracts.

## +57B7 scan

OBSERVED: six distinct callers +201F/+6325/+592C/+6414/+647E/+6556, one each;
ordinary returns at +57DB (five) and +57E8 (one). DEDUCED operation:

```text
word[A936] = inputBC                    // saved base
byte[A935] = FF                         // wrapping index
repeat:
    i = u8(byte[A935] + 1); byte[A935] = i
    BC = i; HL = u16(word[A936] + i)
    sample = byte[HL]; byte[A938] = sample
    if sample == 0: A = 0; RET
    HL = A938
    if byte[20C3] == sample: A = 1; RET
```

The six paths visit 4/4/7/3/3/9 bytes, stopping at indices 3/3/6/2/2/8.
This explains all 502 local occurrences. Zero is tested before selector equality;
selector zero cannot produce the match return. DE is preserved. Both returns
have CY0/Z1 from their actual last comparison, despite different returned A.
HL is the sample address on zero and A938 on match. Scratch base/index/sample
publications are distinct; the source is read-only. No accumulating sum occurs.
If none of the cyclic 256 addressed bytes is zero or a matching nonzero selector,
the scan can repeat indefinitely. Completeness describes this operation, not an
arbitrary termination theorem or source-language meaning.

## Readback leaves and +4890

+41AF reads `byte[word[A863]+3]&07`, returns BC3/HL=field address, preserves DE.
+421F reads `byte[word[A863]+1]&E0`, preserves BC/DE. Both return arbitrary masked
bytes with ANA flags/CY0 and no writes. They are independent complete leaves.
+47E2 increments A8EB modulo256, returns C=new index/A1E. CMP/JNC +47ED selects
RET iff new index<=1E. MINIMAL observes 0->1 and 1->2. Six higher-index bytes
remain RAW; their algorithm is not supplied by the normal contract.

+4890 composes those leaves with complete +4227/+452B:

```text
p = word[A861]; word[A863] = p
word[A861] = u16(p + byte[p])
// demonstrated scope: A91F==0, (byte[p+3]&07)!=3
high = byte[p+1]&E0; count = byte[p+1]&1F
if high==0 && count>0:
    j = complete452B(BC=p+10, E=count)    // descending sum, u8 then &7F
    slot = A761 + 2*j
    word[p+8] = word[slot]               // actual local MOV writers
    word[slot] = p                      // separate publication
RET
```

The correlated paths are `(p=FBE1,size6,high20,count0,skip)`,
`(p=FBE7,size17,high0,count7,publish j7)` and
`(p=FBF8,size6,high20,count2,skip)`. The action writes FBEF/FBF0=old slot word0,
then A76F/A770=FBE7. A861 already holds the advanced cursor while A863 still
holds p; equal-looking pointer state must not merge them. Action return:
A=j, BC=A761, DE=p, HL=slot+1; NZPA from +452B's final ANI, CY0.
Skip: A0/BC0, DE=size, HL=p+1, CY0/NZPA from zero ANA.

**STATIC / UNOBSERVED:** the field3 equality region +48B3..+48BE and mode-nonzero
region +48C7..+48D2 are excluded. Their bytes remain RAW. No allocation,
container ownership or global table capacity is inferred.

## +4802 parent composition

```text
byte[A91F] = 0
if word[A861] >= word[1C32]: unobserved_exit_4813()
saved = word[A861]; word[A8E9] = saved
partial4890(); word[word[A863]+4] = 0
while byte[A8EB] < (byte[word[A863]+1]&1F):
    partial47E2()
    word[A8AB+2*byte[A8EB]] = 0
i = byte[A8EB]
word[A8AB+2*i] = saved
word[A86D+2*i] = saved                  // distinct parallel channel
repeat:
    p = word[A861]; word[A863] = p
    below = p < word[1C32]             // +83A3 full-word borrow
    high = complete421F()
    if !(below && high!=20): RET
    partial4890()
```

Complete resident +1A33 establishes the initial cursor-minus-floor borrow; +83A3
independently supplies the later full-word subtraction. Their high-byte Z flags
are not full-word equality predicates. +4227 supplies the low-five-bit count,
+421F the high-bit mask, +47E2 the index advance. Neither word subtraction nor
field mask is merged merely because an observed value is zero.

One invocation starts FBE1/index0: +4890 advances to FBE7, initial count0 needs
no growth; publishes FBE1 independently at A8AB and A86D. Its continuation calls
+4890 once more on FBE7, then stops at FBF8/high20 while still below floor FBFD.
The other starts FBF8/index0: +4890 advances to FBFE, count2 grows index twice,
zeroing A8AD/AE and A8AF/B0; saved FBF8 is published at A8AF/B0 and A871/72.
It stops with cursor FBFE>=floor FBFD, despite high60. These correlated stopping
reasons must remain distinct. Both return A0/CY0/Z1 from the combined false mask;
HL=terminal cursor+1, DE=1C33, B=C=saved borrow mask. No helper returns an
assumed success Boolean here.

**STATIC / UNOBSERVED:** +4813 nonborrow RET remains RAW. +4890 special arms and
+47E2 higher-index scope remain inherited blockers. Nonaliasing selected memory
and progression/termination assumptions remain explicit; zero/wrapping sizes
can stall or cycle an arbitrary traversal. +4802 and +4890 become UNDERSTOOD for
their represented scoped operation, retaining provisional/partial/partial.

## Word shifts and secondary leaves

+8386 is called only at +14DF (three calls). It reads word[inputHL] into DE and
XCHG sets HL=value/DE=inputHL+1. ORA high clears carry; RAR high then low performs
logical word right shift. DCR C/JNZ repeats; initial C0 means 256 iterations.
Return HL=word>>n, A=L, C0, B preserved, CY=last discarded bit; NZPA from final
DCR, not from the shifted word. The observed counts 3/6/1 transform 0000/0210/0250
into 0000/0008/0128. No data writes occur. +8380 independently doubles input HL
n times modulo65536; it preserves A/B/DE and returns last DAD carry/final DCR
flags. Neither entry shares its physical body with nearby +8396/+83A0.

Additional small repeated operations:

- +020E: maskFF iff first selector20C3==1 or second selector>=81; otherwise00.
  Two successive SUI 1 operations use the *second* borrow after wrapping. PSW
  carries the first mask into B/C; final ORA defines flags, CY0. HL/DE preserved.
- +2221: cache index A649; nonspecial selected A628 byte yields FF iff6<=v<=9
  through SUI 6/SUI 4/SBB. Observed values5/0/5 return00. **STATIC / UNOBSERVED:**
  literal24/25 arms remain RAW and excluded.
- +13E3: cache input C at A607, replace byte[A5FE+indexA606]. Below7, increment
  index and write FF at the next slot; index>=7 skips those operations. The skip
  outcome is **STATIC / UNOBSERVED**, with all its instruction bytes already
  represented. No source-array capacity claim follows from the literal7.
- +14C8: pass u8(A610-1) to established complete +7B7A at its table/termination
  scope; publish returned stop position to A60F and forward child flags.
- +8268: cache C at AE79, publish it to AA1A, return A=C/HL=AE79; BC/DE/flags
  preserved. The arbitrary byte is not normalized into a Boolean.

## Caller propagation and data roles

New +4890 and +4802 pseudocode/comments/contracts directly substitute every
selected leaf and composition at its actual scope. No other pre-existing
cataloged hypothesis calls these selected entries. The other callers are still
RAW; [caller-refinements.json](caller-refinements.json) projects the new contract
to each recorded CALL/RET with correlated register inputs/outputs and scope,
without inventing unread continuation behavior or promoting its caller.
In particular +57B7's six callers and +8386's +14DF now have explicit reusable
results; +14C8 removes the scanner opacity in RAW +1421 and +8268 identifies the
gate write in RAW +140D/+1C07. Their whole bodies remain future work.

Roles retain numeric addresses: A935 index/A936 saved base/A938 sampled byte;
A861 readback cursor (distinct scoped use from reset input), A91F mode,
A86D indexed parallel word publications, A649 selected-mask index,
A606/A607 indexed byte cursor/input and A5FE addressed-byte base, AE79 gate input.
Established A8EB index and A8AB word slots now include demonstrated indices0/1/2;
no capacity is inferred. A761 sum-selected slots, A8AB slots, A86D slots, p+8
successor, p+4 zero field and PSW/return carriers remain distinct.

## Final branch / flag audit

| Coordinate / producer | Final tested flag and branch polarity |
|---|---|
| +57D6: CPI00(sample) | JNZ iff sample!=0 |
| +57E3: selector CMP sample | JNZ iff unequal; match returns1 without changing flags |
| +47ED: A1E CMP newindex | JNC iff newindex<=1E unsigned |
| +48A8/+48B0/+48C4: CPI0(mode), CPI3(field), CPI0(mode) | JNZ iff mode!=0 / field!=3; JZ iff mode==0 |
| +48E8: SUI0/SUI 1/SBB mask(high==0), saved PSW; 0-SUBcount/SBB mask(count>0); POP B/copy/ANA/RAR | CY=original combined mask bit0; JNC iff !(high==0 && count>0) |
| +4810: resident +1A33 word cursor-floor | JC iff cursor<floor, full-word borrow |
| +4832: index CMP low5count | JNC iff index>=count unsigned |
| +4886: +83A3/SBB (saved cursor<floor mask), +421F/SUI 20/ADI FF/SBB(high!=20 mask), POP B/copy/ANA/RAR | CY=combined mask bit0; JNC iff !(cursor<floor && high!=20); ADI replaces SUI carry |
| +8392/+8382: DCR C | JNZ iff decremented C!=0; CY preserved from last RAR/DAD |
| +2231/+2243: indexed-byte CPI24/CPI25 | JNZ iff corresponding inequality |
| +2257: SUI 6/SUI 4/SBB A | FF iff u8(v-6)<4, i.e.6..9; CY1 for that range, else0 |
| +0215/+021C..+0220: SUI 1/SUI 1/SBB; SUI 81/SBB/CMA; ORA saved mask | firstFF iff v==1; secondFF iff v>=81; final ORA CY0/Z iff combined mask zero |
| +13F9: index CPI7 | JNC iff index>=7; below7 falls through |

No observed byte equality alone establishes a Boolean. SBB supplies explicit
00/FF masks; field reads and scan samples remain arbitrary bytes. Returned A,
full-word borrow, high-byte flags and later logical flags are separate channels.

## Final category-1 audit and MINIMAL stop test

[category1-audit.json](category1-audit.json) contains every remaining RAW PLI1
CALL entry. Each invocation has a corrected original-slot return, nested child
windows are excluded, and own step identities across selected entries are
disjoint. Unresolved return entries: **zero**. Counts do not use context totals.

| Measure | Pass 11 | Pass 12 |
|---|---:|---:|
| RAW PLI1 CALL entries | 75 | 62 |
| Their local occurrences | 3,517 | 2,258 |
| Entries called more than once | 31 | 18 |
| Local occurrences in those repeated entries | 1,731 | 472 |

The thirteen selected entries account for exactly 1,259 local occurrences.
PLI1's remaining RAW dynamic total is 2,291; the other 33 are outside these CALL
projections and receive no inferred owner. Largest remaining entries:

| Entry | Calls | Own coordinates / occurrences | Immediate opaque callees | Partial callees |
|---|---:|---:|---|---|
| +7ED7 | 1 | 58 / 699 | none | none |
| +1421 | 1 | 76 / 193 | +7ED7 | none |
| +0A32 | 1 | 89 / 121 | +02E9, resident18DB, +02F0, +0146, +45F0, +0266 | +01AF, +80B7, +784E |
| +4986 | 2 | 47 / 100 | none; complete4929/83A0 | none |
| +0C75 | 1 | 57 / 78 | +013D, +45F0, +0261, +0C1B, +0146 | +784E, +01AF, +80B7 |
| +14E4 | 3 | 21 / 63 | +14D4, +834F | none |
| +02F0 | 1 | 62 / 62 | +80CA, +02E9, resident18DB, +2006, +01D8 | +01AF |
| +80EF | 4 | 14 / 56 | none | +80B7, resident0EF6 |
| +0D6E | 2 | 19 / 38 | +7FF3 | +2511 |

The full audit separately lists every direct callee and its catalog scope.
Other repeated work is +140D/+7FF3 (27 each), +14D4/+8167/+834F (24 each),
+4562 (15), +45F0 (14), +80B1 (12), and eight adapters/leaves with at most nine
occurrences each. +14D4 now calls complete +8386; +140D's gate writer is known.
+4986 remains a recoverable two-call composition of complete helpers; it has
real residual value and is not claimed understood or trivial. But no cataloged
PLI1 parent remains blocked by a *missing observed direct* callee contract.
The remaining repeated cluster is small, largely composition/adaptation and
inherited partial scopes, rather than the high-leverage opaque primitives that
justified passes10–12. Another general repeated-helper pass has diminishing value.

Remaining information categories:

1. **Executed RAW operations:** 62 entries/2,258 local occurrences above; only
   472 are in repeated entries. Single-call +7ED7 now dominates at699; +1421 and
   +0A32 contribute193/121. None was semantically decompiled in this ticket.
2. **Cataloged partial operations:** +4890 mode/field alternatives, +4802 initial
   exit and +47E2 higher index; constructor/allocator, mapped processor recursion
   and resident emission scopes. Missing *executed* direct PLI1 helper contracts
   no longer dominate existing cataloged parents. RAW callers remain category1.
3. **Unobserved states/branches:** +24BC field11 vs09/mode alternatives, +784E
   descriptor/rewrite arms, +2355/+230E literal selectors, +7E5F threshold,
   +8048 gate-set arm, +4468 empty bucket, +4394 failure/floor, resident nonzero
   word output/flush/error. Current MINIMAL cannot supply those outcomes.
4. **Provenance/alias/termination:** initial table/cursor producers, selected
   buffer/word/stack aliases, wrapping scans and recursive depth/cycles. More
   annotation of the same outcomes cannot establish general invariants.
5. **Different source/state requirements:** recursive mapped1E/21 and alternate
   predecessor paths, empty bucket, literal alternatives and nonzero output.
   New inputs should supply independent observed outcomes before completeness
   can be strengthened.

**Recommendation: stop the focused MINIMAL helper series here. Pass 13 should
begin FIZZBUZ-minus-MINIMAL (D).** This does not assert MINIMAL is fully understood;
+7ED7/+4986 and the RAW orchestration bodies remain valid future bounded work.
The decisive reduction is reusable unresolved work, not a percentage threshold.

[next-input-audit.json](next-input-audit.json) compares *existing* coverage-delta
coordinates with accumulated supported extents; no new FIZZBUZ execution or
semantic analysis took place. The known delta has 4,771 coordinates, including
2,675 PLI1 coordinates/5,339 new fetched bytes. It adds 65 coordinates inside
+7C1B's known envelope and 13 inside +4468's empty-bucket region. These are a
coherent recursive/mapped/construction expansion with mature surrounding helper
contracts. Coordinate overlap alone does not prove invocation ownership or
concrete branch states. The future run must join actual boundary/state evidence.

Matched microfixtures would be better for one isolated literal, field11,
nonzero word or allocator failure question. The old FIZZBUZ delta adds no new
coordinates inside +24BC/+784E/+2355/+230E/+4802/+4890/+7E5F/+8048/+1207/
resident0EF6; same-coordinate value differences remain possible and are not
predicted. For the next broad experiment, its naturally demonstrated recursive
and empty-bucket code delta is preferable to designing fixtures now. Microfixture
planning should follow that delta analysis for unresolved single-state questions.

First exact questions for the next input (planning only):

| Procedure / branch | Missing observed state | Existing evidence | Desired discriminating outcome |
|---|---|---|---|
| +7C1B +7C56..+7CB6 alternative | mapped byte1E/21, correlated attributes/auxiliary inputs and child calls | complete mapped primitives; MINIMAL normal scope;57 delta coordinates in this region | proven invocation boundaries and ordered recursive/helper outputs, replacing the RAW alternative with a scoped operation |
| +7C1B +7CD0..+7CDB | mapped17 path with predecessor !=0A | MINIMAL predecessor0A case;8 delta coordinates here | concrete predecessor/result/publication relation for the unequal path |
| +4468 +44E7..+44FC | selected A761 head word zero | proven N2 software cleanup and normal nonempty +8 traversal;13 delta coordinates here | actual slot writer/word value, created pointer and software RET relation on empty-bucket path, distinguished from last+8 publication |

No source fixture or new execution was designed or run.

## Progress and validation

Only dynamically observed instruction bytes were promoted: **514 RAW ->
UNDERSTOOD**, **0 RAW -> STRUCTURED**. All other status transitions are identity.
No unexecuted RAW byte was promoted. Executed statuses now RAW 12,993,
DECODED 304, STRUCTURED 1,265, UNDERSTOOD 6,450 (total 21,012). Whole-image status
counts remain independent of dynamic counts and procedure completeness.

| Measure | Before | After |
|---|---:|---:|
| Executed UNDERSTOOD bytes | 5,936 | 6,450 |
| UNDERSTOOD CALL/RST entries | 113 | 126 |
| STRUCTURED / unresolved CALL/RST entries | 8 / 270 | 8 / 257 |
| Dynamic UNDERSTOOD overall | 48.5348% | 48.8209% |
| Dynamic UNDERSTOOD PLI1 | 91.7201% | 94.6566% |
| Dynamic UNDERSTOOD PLI.COM | 47.8737% | 47.8737% |
| Dynamic UNDERSTOOD PLI0 | 40.8068% | 40.8068% |
| Dynamic UNDERSTOOD PLI2 | 22.3957% | 22.3957% |

Counts are 214,811/439,998 understood historical instruction occurrences;
PLI1 40,584/42,875. Capture hashes, coordinates, counts, transfers, software
continuation proofs and cross-run presence are unchanged. Stable labels retained;
operand-interior labels become verified coordinate-only EQUs where necessary.
See [progress.json](progress.json) and [dynamic-progress.json](dynamic-progress.json).

Validation: project `dune runtest`; baseline/pass1–12 tests (109 total);
V0.2 packet tests (23, including 55 continuation-corruption variants);
V1 annotation tests (9); annotated-byte verifier tests (11); fresh remaining
RAW-entry isolation and dynamic-progress consistency; `git diff --check`.
Independent historical images reconstruct **all 94,720 bytes exactly**, with every
section/full-image hash and source/runtime mapping verified. Eight new tests
check address equations, masks, actual word writers, flag polarity, shift counts,
stack-return identity, correlated paths and the full remaining-entry audit.
