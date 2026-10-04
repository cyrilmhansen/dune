# FIZZBUZ differential pass 13

Task `FIZZBUZ_DIFFERENTIAL_PASS_13`; baseline
`217228d7d722af74048d6f1c2d922aee0251b993`. This pass explains only
PLI1+7C56..+7CB6, +7CD0..+7CDB and +44E7..+44FC. Those are 57/8/13
FIZZBUZ-minus-MINIMAL instruction coordinates: **78 coordinates, 131 bytes**.
No generic helper pass, unrelated byte promotion, custom fixture, new compiler
capture or packet/CPU/trace infrastructure change occurred.

## Capture and structural observations

The existing ignored capture `_build/evidence-packet-cross-run/fizzbuz-capture`
was reused. Identity:
`FIZZBUZ:a7a657b3c9c758be44a16c4c76a2986744f01de34d773d2b9597d4758eff0f49`.
PASS1/PASS2/END COMPILATION success and the 768-byte REL were rechecked;
SHA-256 `68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`.
Its 1,145,517 instruction witnesses, corrected ordinary/software events and
canonical bytes/runtime/count chronology are validated by unchanged V0.2.

[structural.json](structural.json) derives exact CALLs, caller counts, original
hardware returns or existing POP-D software proofs. Nested windows are excluded;
no context count, coordinate min/max, RoutineCandidate or value equality supplies
ownership. [before.json](before.json) retains the original contracts/metadata.

| Entry | FIZZBUZ calls | Own coordinates / occurrences | Observed bytes in FIZZBUZ | Accumulated byte union |
|---|---:|---:|---:|---:|
| +7C1B | 96 | 186 / 6,180 | 312 | 203 -> 312 |
| +4468 | 11 | 104 / 1,607 | 189 | 173 -> 195 |
| +4738 | 3 | 47 / 141 | 85 | 85 -> 85 |
| +4693 (necessary parent only) | 8 | 10 / 80 | 20 | 20 -> 20 |

The +4468 union retains six MINIMAL-only bytes; 189 FIZZBUZ bytes never replace
or add arithmetically to the prior 173. Seed instruction records preserve existing
MINIMAL counts and add separate FIZZBUZ facts. The original MINIMAL invocation
counts 16/2/1 remain for +7C1B/+4468/+4738. Caller observations added:

- +7C1B: +7C5D 1, +7C71 1, +7CE3 17, +7D2D 42, +7D9D 35. The first four are
  **61 recursive calls**; 35 are external. MINIMAL's seven children remain
  separately identified. Return sites +7CB6/+7CDB join the existing three sites.
- +4468: +46A3 eight, +4756 three; all 11 software RETs are +452A with N2.
- +4738: +2B3F three, original hardware-slot RET +478C.
- +4693: +46BD eight, original hardware-slot RET +46A6.

**Counterevidence to the proposed +4738 envelope:** none of its three children
executes +44E7. All eight empty-slot children are called at +46A3, inside the
already-cataloged ordinary +4693 wrapper. Its metadata and packet were therefore
necessary to isolate the requested path. No new procedure or +4693 semantic
subproject was introduced; its orchestration remains delegated at partial scope.

## Packet evidence interface

After structural metadata was established, +7C1B was generated with
`--run FIZZBUZ --frame-bytes 5 --class-slots 0 3`. Ordinary +4738/+4693 parent
packets use zero frames. Markdown was read first, then selected JSON queries.
Independent MINIMAL accumulated contracts are substituted only at their declared
scopes; the two runs are never merged into a new packet representation.
Generated JSON/Markdown stay ignored under `_build/fizzbuz-pass-13/packets`.
Final sizes/counts are in [packets.json](packets.json).

| Packet | JSON bytes | Markdown bytes | Invocations / classes / blocks |
|---|---:|---:|---|
| +7C1B | 16,369,179 | 43,897 | 96 / 64 / 28 |
| +4738 | 671,121 | 10,019 | 3 / 1 / 6 |
| +4693 | 592,324 | 7,008 | 8 / 2 / 2 |

+7C1B class discriminators include inherited PUSH-H bytes; the first-written F+3
is not the later semantic mapped-byte assignment at +7C2C. The special member's
first-written F+3 is CB, while its mapped byte is 1E. Every member's chronology
remains independent. Supported V0.2 dependency chains supplied exact equality,
max/clamp comparison and predecessor predicates; no infrastructure change was
needed.

The parent packets retain full software proof prefixes and subtree access lists,
but do not expose every child-local branch state. For +4468, the already
structurally isolated child records supplied narrowly selected flag/instruction
states. Their memory effects were matched by actual step/address/value to the
ordinary parent packet. This is an explicitly bounded child projection, with the
existing proof as authority, not a software-outer packet or context fallback.

## +7C56..+7CB6: two ordered children and byte result publication

[7C1B-correlations.json](7C1B-correlations.json) retains the correlated members.
Exactly one invocation reaches this special arm: CALL step **618240**, caller
+7D2D, C=5, entry HL=FFCB, DE=FB00, F=FFC4. Mapped byte1E is read via +7A4D and
written to F+3. No mapped21 invocation exists in this capture or MINIMAL.

The equality sequences each use SUI literal/SUI1/SBB A: the second borrow yields
FF exactly on equality, despite wrapping the first subtraction. PUSH PSW/POP B
carries the first mask into B/C. ORA combines masks and clears carry; RAR places
the original OR bit0 into CY. JNC +7C53 is taken iff neither mapped equality
holds. The observed1E maskFF therefore selects fallthrough, not a false predicate.

Exact direct call order (initial mapping included):

| Callsite / target | Input C | Returned A | Relevant return flags |
|---|---:|---:|---|
| +7C25 / +7A4D | 5 | 1E | mapping preserves NZPA; CY0 |
| +7C5D / recursive +7C1B | 4 | 1 | Z1/S0/P1/AC1/CY0 |
| +7C6C / complete +7B7A | 4 | 3 | Z1/S0/P1/AC1/CY0 |
| +7C71 / recursive +7C1B | 2 | 15 | Z0/S1/P0/AC0/CY0 |
| +7CAB / complete +7B2E | 5, E=15 | 15 | retains parent clamp NZPA; CY0 |

The original F+0 remains5. The first child A1 is saved at F+2. +7B7A returns
stopping position3, which is decremented to2 for the second child; that child's
A15 is saved at F+4. F+1 retains inherited entry L=CB on this arm and is not a
loop counter. F+4's special role differs from default cached auxiliary data.

```text
F2 = recurse(u8(original_position-1))
stop = complete7B7A(u8(original_position-1))
F4 = recurse(u8(stop-1))
if F2 < F4: F2 = F4
F2 = u8(F2+1)
if F2 > 0F: F2 = 0F
complete7B2E(C=original_position, E=F2)
return F2
```

Thus the operational expression is
`min_u8(0F, u8(max_u8(child1,child2)+1))`. Max FF would wrap to00 before the
clamp; this is not a nonwrapping integer saturation claim.

At +7C82, CMP first-second sets CY1 for1<15; JNC +7C83 is not taken and the
second value replaces F+2. INR +7C94 writes16. MVI A0F/CMP F+2 sets CY1;
JNC +7C98 is not taken, and +7C9F writes constant0F to F+2. This constant
**replaces** the increment result and is the final publication's producer.
Its equality with the second child's byte does not establish direct provenance.
+7CAB's setter rereads position_map[5]=5 and writes **AD0D=15**, separately from
its AE43/AE44 caches. Recursive child publications remain separate channels.

Return: A15, BC0005, DE000F, HL0F1E. Final POPs reconstruct HL from F+3/F+4;
entry HL is not preserved. NZPA come from CMP0F-16 (Z0/S1/P1/AC1), while the
last frame DAD sets CY0. Returned A15 and the second child's flags do not determine
these final flags.

**DEDUCED:** mapped1E and21 dispatch to exactly the same body, with no subsequent
mapped-byte selection; final HL.low still contains the original mapped byte.
**STATIC / UNOBSERVED:** mapped21, first>=second JNC outcome and incremented
result<=0F JNC outcome. Different positions/table states may produce different
child values; there is no observed21 comparison or higher-level operator meaning.

## +7CD0..+7CDB: read current auxiliary, skip child publication

Six invocation steps reach the fallback:
**376381, 406180, 475962, 542692, 608347, 619581**.
Their original positions are **2,1,1,1,1,2**; every mapped byte is 17 and every
predecessor mapping is05. The last is the special arm's second child.

At +7CCB, CPI0A compares the predecessor's returned byte05; JZ +7CCD is not
taken. +7CD4 loads **original F+0**, then +7CD5 calls complete +7AA9 there.
Direct order is +7A4D(original), +7A4D(original-1), +7AA9(original). No recursive
call and no +7B2E publication occur. Auxiliary reads are AD0A/AD0C/AD0F/AD0C/
AD0F/AD0F respectively, each returning15. The getter writes only its AE3A
position cache. The original-position auxiliary channel is **read**, not replaced
by another write; F+2/F+4 have no semantic assignments on this path.

Return A15, BC=fresh mapped index, DE=entry DE, HL=(entry H<<8)|17. NZPA retain
CPI05-0A (Z0/S1/P0/AC0); CY0 comes from the getter's address DAD. These flags
remain separate from returned auxiliary data. Frame POPs retain the inherited
F+4 high byte. **DEDUCED**, under the established nonaliasing getter scope, any
other predecessor!=0A takes this same read-only instruction sequence; only05
has a concrete accumulated observation.

## +44E7..+44FC: direct word-slot publication and unchanged cleanup

[4468-correlations.json](4468-correlations.json) includes all 11 selected
constructor children, their ordinary parent, argument read, branch state,
software relation and actual publication writers. The eight empty-slot members:

| Child CALL step | Count C / tag E | Sum index j | Selected slot | Published p=word[1C36]+1 |
|---:|---|---:|---|---|
| 357427 | 1 / 02 | 49 | A7C3 | FBB4 |
| 364891 | 2 / 02 | 102 | A82D | FBA8 |
| 396824 | 1 / 02 | 48 | A7C1 | FB9D |
| 430788 | 8 / 05 | 14 | A77D | FB8B |
| 461318 | 1 / 02 | 51 | A7C7 | FB6E |
| 499818 | 4 / 05 | 67 | A7E7 | FB60 |
| 528116 | 1 / 02 | 53 | A7CB | FB47 |
| 566468 | 4 / 05 | 75 | A7F7 | FB39 |

All are called at +46A3 through +4693 and consume caller source word20C6,
actually written by the parent's +469A PUSH B. The argument carrier's read is
before its overwrite by the copied continuation; it is not a writable result
slot. No custom source input was needed.

Complete +422F reads the selected slot at +4239/+423B: both bytes are zero in
each member, and A863 becomes0. +4281 returns A00. RAR +44E3 puts its bit0 in
CY0; JC **+44E4** is not taken. Returned helper carry is not the tested source:
RAR always replaces CY with returned A.bit0.

```text
p = word[1C36]+1
PUSH temporary p
j = byte[A760]                         // fetched adjacent high byte discarded
slot = A761+2*j
BC = POP temporary p
word[slot] = BC                        // own MOV +44F7 low, +44F9 high
JMP +4523
p = word[1C36]+1; word[A863] = p
RET copied continuation
```

Every write in the selected arm is accounted for: +44EB's temporary stack pair,
+44F7/+44F9's direct slot pair, then the common +4527 A863/A864 publication.
No +83A0/+428E traversal or last-pointer+8 publication happens on this arm.
The prelude's previously understood header/payload writes are distinct and
retain their normal positive-count/allocator-success scope.

The temporary PUSH at +44EB writes the **old child CALL slot E**; the copied
continuation remains at **E+2**. These are different writer/consumer channels.
For every member, `software_continuation.prove()` verifies:

```text
S = pre-child-CALL SP; E = S-2
CALL writes original return at E; POP D consumes that exact original word
POP B consumes caller word at E+2; DE keeps original return PC
PUSH D writes copied continuation at E+2
RET +452A reads exactly that copied word; final SP=S+2
```

The empty branch resumes +46A6, then the ordinary parent RET consumes its own
original hardware slot. The three +4738 children separately prove identical
N2 mechanics and resume +4759; they are all nonempty. All eleven child windows
are excluded from parent-local execution. No software-outer packet is attempted.

Empty return: A0, BC=p, DE=A864, HL=p. NZPA retain +4281's null-mask flags
(Z1/S0/P1/AC1); CY0 follows the final slot-address DAD. This is different from
the nonempty path's final successor-zero ORA flags, despite identical A0.
Copied-return equality alone is insufficient: the new corruption check changes
writer identity while preserving bytes/target and is rejected.

## Annotation changes, preserved scopes and remaining questions

The two procedure contracts now contain coherent operational pseudocode for all
three selected alternatives; the prior mapped0A, default, mapped17/child,
header/copy and nonempty-chain MINIMAL operations remain intact. Near-code
comments and block pseudocode identify the actual producer/flag/publication.
All machine bytes/encodings and stable coordinate labels remain authoritative.
Operand-interior labels remain verified coordinate-only EQUs.

+7C1B grows 203 -> 312 represented UNDERSTOOD bytes; +4468 grows 173 -> 195.
**131 RAW -> UNDERSTOOD; zero RAW -> STRUCTURED; no unrelated byte changes.**
These additions fill their final represented holes and establish all local
instruction groups, branch targets, direct callees and ordinary/software return
sites. Extent endpoints retain their existing entry/terminal/independent-neighbor
support. Bounds become **stable**, local control flow **complete**, and contract
remains **partial** for both. This is a closure of the represented local graph,
not complete procedure semantics or a proof of original source ownership.
+4738/+4693 retain stable/complete/partial and their prior bytes/operations.
No data role or new procedure is introduced.

Closed questions: observed special mapped1E order/data/flags, predecessor05
read-only fallback, empty-slot direct publication, and N2 continuation ownership
on that alternative. Still unresolved: mapped21 and opposite max/clamp outcomes,
allocator failure/floor, recursive/reverse-scan termination for arbitrary tables,
full alias preconditions and earlier table/cursor producers. **STATIC / UNOBSERVED**
alternatives are named without promoting any unexecuted RAW bytes.

MINIMAL's captured instruction/status rows, coverage and dynamic-progress files
remain byte-identical. Its executed UNDERSTOOD count 6,450, CALL entries 126,
overall 48.8209% and PLI1 94.6566% do not change. The MINIMAL inventory updates only
the two live completeness links; capture/cross-run counts are unchanged.

## Validation and next experiment

Eight new tests check exact selected-run metadata and REL, per-invocation mapped
states, call order/results/publications, immediate branch flag producers,
read-only auxiliary fallback, ordinary-parent isolation, all eleven N2 ancestry
relations, direct slot writes, writer-identity corruption, accumulated byte union
and unchanged MINIMAL progress. Existing packet corruption checks remain intact.
The old MINIMAL test requiring +44E7 to stay RAW forever now distinguishes its
FIZZBUZ-only observation; the two prior completeness assertions reflect the
new local-graph closure. A synthetic missing-FIZZBUZ-count fixture explicitly
removes that field in memory, so another run's metadata cannot satisfy it.

Project tests, all 109 MINIMAL tests, the 27-test packet/continuation suite,
V1 annotation tests, verifier tests and the full historical-byte verifier pass,
along with `git diff --check`. **All 94,720 historical bytes reconstruct EXACTLY.**
Generated captures/packets remain ignored and unrelated untracked files untouched.

Another **bounded natural FIZZBUZ differential pass** is justified, beginning
with +7D53's composition of this expanded +7C1B contract and its already-known
mapped/auxiliary/emission channels. This pass explains 78 of the known 4,771 new
coordinates; it does not exhaust the natural delta. That next work should first
establish its FIZZBUZ structure/catalog facts and remain selective. Matched
microfixtures are the appropriate discriminator specifically for mapped21,
first>=second, unclamped<=0F and allocator-failure states absent from both runs;
they were neither designed nor run here. No improved decompilation stability is
claimed from this single differential session.
