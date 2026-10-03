# MINIMAL decompilation pass 11

Task `MINIMAL_DECOMPILATION_PASS_11`; baseline `2d5b508`. All priority and
secondary targets were investigated, including +240A's immediate +23A0/+23D2
dependencies. No compiler capture, FIZZBUZ work, fixture design or packet
infrastructure change occurred.

## Structure and packet discipline

Exact CALL entries, corrected original-slot returns, local branches and independent
neighboring entries support these hypotheses. No context min/max or RoutineCandidate
extent supplied ownership. [structural.json](structural.json) retains the details.
All targets were structurally supported; none remained STRUCTURE ONLY.

| Entry | Calls | Own coordinates / occurrences | Classification |
|---|---:|---:|---|
| +83A0 | 6 | 11 / 66 | SMALL / DIRECT |
| +83A3 | 3 | 9 / 27 | SMALL / DIRECT; independent shared entry |
| +7E5F | 16 | 45 / 720 | PACKET CANDIDATE |
| +7A93 | 13 | 12 / 156 | SMALL / DIRECT |
| +8048 | 22 | 43 / 570 | PACKET CANDIDATE |
| +7EC0 | 18 | 12 / 205 | SMALL / DIRECT |
| +80B7 | 10 | 9 / 90 | SMALL / DIRECT composition |
| +2511 | 8 | 15 / 120 | SMALL / DIRECT; one private byte |
| +240A | 8 | 59 / 325 | PACKET CANDIDATE |
| +23A0 | 3 | 10 / 30 | SMALL / DIRECT |
| +23D2 | 8 | 27 / 216 | SMALL / DIRECT composition |
| +01AF | 34 | 11 / 281 | SMALL / DIRECT adapter |
| +4227 | 8 | 5 / 40 | SMALL / DIRECT |

V0.2 packets for +7E5F/+8048/+240A followed structural seeding and were read
Markdown-first. +4738 was regenerated after constructor substitution. Artifacts
remain ignored under `_build/minimal-pass-11`. Shared +83A0/+83A3 were analyzed
directly, avoiding the ordinary packet's global-coordinate-count restriction.
Existing pass-8 gathering and unchanged `software_continuation.prove()` supplied
the two +4468 outer software-return records; no second recognizer was introduced.

## +83A0/+83A3 and constructor callers

+83A0 zero-extends A into DE, then enters +83A3's physical tail. Direct +83A3
accepts full DE. Both read word[inputHL], perform low SUB/high SBB and return:
HL=u16(minuend-word[inputHL]), DE=inputHL+1, A=high difference, BC preserved.
CY is unsigned borrow; NZPA/AC describe high SBB, not full-word zero. No memory
writes occur. Separate counts/inputs/headers remain; shared comments/block meaning
agree physically. Both contracts are stable/complete/complete.

In +4468, +4506 supplies A=0 and HL=current_pointer+8. The result is a negated
successor word, not a pointer update. +4509 ORA L combines high A and low L,
clears carry and establishes full-word Z; +450A JZ is taken iff successor==0.
Otherwise +428E follows the successor and repeats. At terminal zero, +4513..+4522
recomputes newp=word[1C36]+1, temporarily pushes newp, and its own MOV M,C/MOV M,B
publish word[last_pointer+8]=newp. +83A0 itself is read-only. A863 becomes newp.
NZPA retain the last zero-word ORA; CY follows the later address DAD.

The proven two-byte software cleanup, caller source word, allocator-normal
header/tag/zero fields, descending source copy, selected word slot and +8 chain
operation remain distinct. Two count7/source20C6-or-A948/tag05-or-28 invocations
perform one/two successor checks. Its 173 represented bytes become UNDERSTOOD
at partial scope; 22 empty-bucket bytes and allocator failure remain unobserved.
Bounds/CFG/contract remain provisional/partial/partial; cycles, aliases and global
allocation/list/tree ownership are not generalized. +4738/+4693 inherit that
normal operation; saved old, updated h+2 and newp+6 channels remain separate.
+28AA's blocker description is refined without changing completeness.

## Mapped publication and orchestration

+7E5F saves input C at AE54 and DE at AE55/56. CMP94-end/JNC +7E6D takes normal
operation iff end[AE35]<=94 (all 16 calls). At position pos with oldslot j=AE33:

```text
byte[AA1F+pos]=j
byte[AE33]=byte[AAB4+j]       // displaced byte read before overwrite
7AD5(pos,inputC)              // mapped byte AAB4+j
7AF0(pos,inputDE)             // mapped word AB49+2*j
7B2E(pos,0)                  // primary auxiliary AD08+j
7B49(pos,0)                  // second auxiliary AD9D+j
byte[AE32]=pos; byte[AE35]++
```

AE33 is replaced, not incremented. AC73 is not initialized here. Every member's
input byte/word, position, oldslot, displaced byte and ordered publications remain
correlated in JSON. Return A=oldpos, BC=slot, DE=inputword.high<<8, HL=AE35;
CY0 and NZPA/AC from final INR. **STATIC / UNOBSERVED:** +7E70 CALL runtime9C46
targets +7A46 for end>94 before fresh-end continuation. Its three bytes remain
RAW; no capacity/flush algorithm is inferred. Contract remains partial at normal
nonaliasing setter scope, with provisional bounds/partial CFG.

+7A93 is complete: save C at AE39, j=byte[AA1F+C], return byte[AC73+j], BC=j,
HL=AC73+j, DE/NZPA preserved, CY0. Only AE39 is written; adjacent AE3A is fetched
then discarded. It reads mapped control bytes, distinct from fixed attributes1B4B.

+8048 caches C at AE6A. CMP DD-C/JNC +8052 selects these correlated paths:

- C<=DD (12): +7E5F(C,word0); use fresh lastpos AE32. Independently read
  predecessor u8(lastpos-1) control through +7A93 and copy through +7B13, primary
  auxiliary through +7AA9/+7B2E, second auxiliary through +7ABF/+7B49. Wrapped
  predecessor FF at position0 is actual machine behavior. Coincident values or
  indices do not merge channels. Returned A is last auxiliary data; NZPA/AC come
  from the third predecessor DCR and survive the last getter/setter, CY0.
- C>DD/gate AA1A.bit0 clear (10): RAR/JNC +8059 selects +7D53 at its accumulated
  partial scope, then reloads saved C and emits through +0EF6's success scope.
  It ignores +7D53 A and consumes its global effects; final results are emitter-derived.

**STATIC / UNOBSERVED:** high/gate-set +805C..+8068 invokes +7E5F(C,0), then
jumps +8073/RET, bypassing +7D53/direct emission/predecessor copying. Those 13
bytes remain RAW. Its 92 represented bytes become UNDERSTOOD, still
provisional/partial/partial, with all child scopes and alias restrictions retained.

+7EC0 saves C at AE57 and directly reads fixed byte[1B4B+C], without position_map.
RLC/RAR restores original A but places original bit7 in CY. JNC +7ED0 skips
+7D53 iff bit7clear (11 calls); seven invoke partial +7D53 and forward its outputs.
Skip returns arbitrary table data, not a Boolean mask. Bounds/CFG stable/complete;
contract partial through +7D53.

## Secondary compositions and leaves

+80B7 caches C at AE6B, invokes +8048 then rereads the saved input for +7EC0.
Ten ordinary calls forward final +7EC0 outputs within child scopes.
+2511 sequences +8048(savedC), +240A(index0), +7EC0(savedC) using one private
byte: MOV B,C/PUSH B/INX SP leaves byte[F]=C, F=entrySP-1. It revisits that byte
twice, discards it, then RET consumes original hardware word at F+1. This is not
caller-argument consumption or a new software-return family. Eight calls preserve
writer/read chronology. Both adapters become UNDERSTOOD, stable/complete/partial.

+240A's necessary immediate helpers are now explicit:

- +23A0 compares cached C with E; JNC selects returned E iff C>=E (three calls),
  retaining CMP flags, BC/DE. **STATIC / UNOBSERVED:** C<E returns C; four bytes
  remain RAW. This supports unsigned minimum, not Boolean normalization.
- Complete +23D2 independently publishes indexed A628/A62B/A62E bytes through
  +7B13/+7B2E/+7B49 at fresh AE32 positions: distinct AC73/AD08/AD9D channels.
- +240A: three selected15 calls clamp the A62B value through +23A0 using low
  limiter A642, then observe extra A62E byte0. Five other calls differ from15/16/19.
  Common tail publishes word[A63B+2*index] through +7AF0, then +23D2's three bytes.
  Selector16/19, 15/nonzero-extra and lower-C clamp alternatives remain RAW/partial.

+01AF caches requested C at A5AF and compares selector20C3. JNZ +01BA mismatch
returns00 with CMP flags and no acquisition (25). Equality invokes partial +784E,
then returns01 without recomputing child flags (nine). Returned1 describes entry
equality, not acquisition success or post-call selector. +784E's own annotations
and contract remain unchanged. +4227 is complete: byte[word[A863]+1]&1F,
BC/DE preserved, HL=field address, CY0/NZPA from AND; no memory writes.

## Boolean/flag audit

| Branch/result | Actual producer | Flag/representation and polarity |
|---|---|---|
| +83A0/+83A3 | low SUB/high SBB | word difference, A=high, CY=borrow; high-byte Z is not full-word Z |
| +4468 +450A JZ | A0-successorword; ORA L | full-word Z; taken iff successor0; ORA clears helper carry |
| +7E5F +7E6D JNC | A94 CMP end | CY=(94<end); taken iff end<=94 |
| +8048 +8052 JNC | A=DD; CMP savedC | taken iff C<=DD unsigned |
| +8048 +8059 JNC | gate-byte RAR | CY=originalbit0; taken iff clear |
| +7EC0 +7ED0 JNC | attribute RLC/RAR | A restored; CY=originalbit7; taken iff clear |
| +01AF +01BA JNZ | selector CMP request | taken iff inequality; returned01/00 does not determine flags |
| +23A0 +23AD JNC | cached C CMP E | taken iff C>=E; flags separate from returned E |
| +240A +241A/+2464/+24AC JNZ | selectedbyte CPI15/16/19 | corresponding inequality |
| +240A +2444 JZ | extra-byte CPI00 | taken iff extra0 |

Supported packet dependency chains supplied tested source/transform/flag identities.
Unsupported scalar arithmetic was audited locally; no repeated ownership/joining
blocker required V0.2 extension. Unobserved descriptions remain STATIC / UNOBSERVED.

## Fresh exact MINIMAL information audit and stop decision

[category1-audit.json](category1-audit.json) lists **all 75 remaining RAW PLI1
CALL entries**, each with full recorded ordinary-return count, own coordinates,
own occurrences, immediate opaque/missing callees and separately partial callees.
Every window is extracted from corrected events; nested ordinary/known software
children are excluded, original slots checked, and local step identities disjoint.
No context count/min-max ownership estimate substitutes for missing proof. All 75
were isolatable; unresolved-return list is empty.

Exact category1 work: **3,517 local occurrences**; **1,731** belong to **31 entries
called more than once**. PLI1 has 3,550 RAW occurrences overall; other 33 lie outside
these CALL projections and are not assigned ownership. Largest examples:

| Entry | Calls | Own coordinates / occurrences | Immediate opaque callees |
|---|---:|---:|---|
| +7ED7 | 1 | 58 / 699 | none |
| +57B7 | 6 | 26 / 502 | none |
| +1421 | 1 | 76 / 193 | +14C8,+7ED7 |
| +4802 | 2 | 71 / 166 | +4890,+421F,+47E2 |
| +4890 | 3 | 70 / 136 | +41AF,+421F |
| +0A32 | 1 | 89 / 121 | +02E9,resident18DB,+020E,+02F0,+0146,+45F0,+0266 |
| +8386 | 3 | 14 / 105 | none |
| +4986 | 2 | 47 / 100 | none; known4929/83A0 |

Remaining categories are kept separate:

1. Executed RAW local operations: the full75-entry table, especially repeated
   +57B7 and construction/readback +4802/+4890/+41AF/+421F. One-call +7ED7's699
   occurrences are excluded from repeated-entry work.
2. Cataloged partial bodies blocked by executed opaque callees: no cataloged
   PLI1 hypothesis now has a missing observed direct-callee contract. Inherited
   partial resident/recursive scopes remain limited; missing callees in RAW
   callers stay in category1 rather than being hidden inside understood parents.
3. Unobserved branches: constructor empty-bucket/allocator failure, higher-end
   +7E5F call, high/gate-set +8048, selected-state/clamp alternatives, +784E rewrite/
   descriptor alternatives, +7C1B recursion and output flush/error paths. Static
   code can describe some operations but cannot supply new dynamic states.
4. General provenance/alias/termination: initial maps/pointer fields, broad storage
   meanings, arbitrary successor/recursive cycles, aliases beyond scoped selected
   addresses and output consumers; no ownership/type theorem from equal values.
5. Different-source questions: field11 versus09, nonzero resident word output,
   literal alternatives and missing allocator/recursive states need discriminating
   input eventually. They are separate from unread executed helpers; no fixture
   was designed here.

**MINIMAL should not stop here. Recommend A: a smaller further helper pass**, on
+57B7, the +4802/+4890 readback cluster and +8386. This follows 1,731 repeated
occurrences including a six-call502-occurrence leaf, not residual RAW byte count
or dynamic percentage. Once that reusable work is contracted, C is best for one
exact missing branch/state; D is best for a coherent broad source-construct delta.
The present audit does not meet the stop condition.

## Progress, artifacts and validation

| Executed status | Before | After |
|---|---:|---:|
| RAW | 14,024 | 13,507 |
| DECODED | 304 | 304 |
| STRUCTURED | 1,438 | 1,265 |
| UNDERSTOOD | 5,246 | 5,936 |

RAW->STRUCTURED0; RAW->UNDERSTOOD **517**; STRUCTURED->UNDERSTOOD **173**.
UNDERSTOOD CALL entries **99->113**; STRUCTURED9->8; unresolved283->270.
391 CALL/RST and eleven PCHL continuation entries remain separate inventories.
Dynamic UNDERSTOOD **47.7827%->48.5348%** (210,243->213,552 occurrences).
PLI1 **84.0023%->91.7201%** (36,016->39,325); other images unchanged:
PLI.COM 47.8737%, PLI0 40.8068%, PLI2 22.3957%. Exact snapshots:
[progress.json](progress.json), [dynamic-progress.json](dynamic-progress.json),
[before.json](before.json). Measurements: [packet-sizes.json](packet-sizes.json).


| Packet | JSON bytes | Markdown bytes |
|---|---:|---:|
| PLI1.OVL+7E5F | 1,199,749 | 12,067 |
| PLI1.OVL+8048 | 1,463,563 | 16,110 |
| PLI1.OVL+240A | 567,353 | 9,802 |
| PLI1.OVL+4738 | 328,114 | 9,285 |

Generated packet JSON/Markdown remains ignored; times are single samples, not a controlled benchmark.

Eight new tests check shared-entry subtraction, constructor zero/link writer,
all 16 publication tuples,22 threshold paths and predecessor channels, attribute
rotations, private frames/selector adapter, clamp/state composition and the entire
75-entry audit. All project tests, MINIMAL baseline/pass1-11 tests (101), V0.2
packet tests (23, including 55 continuation corruption/unsupported variants), V1
tests (9), verifier tests (11), dynamic consistency and `git diff --check` pass.
The pass2 neighbor test now protects distinct +8396/+83A0/+83A3 identities rather
than permanently freezing an independently investigated neighbor RAW.

The verifier reconstructs **all 94,720 bytes exactly**, checking section/full hashes,
original encodings, partitions, runtime mappings and stable labels. No unexecuted
byte was promoted; original operand-internal labels remain coordinate-only EQUs.
Unrelated untracked files remain untouched; task temporary directories are cleaned.

```sh
python3 tools/annotated-assembly/test_minimal_pass_11.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_procedure_evidence_packet.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_decompilation_annotations.py -v
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
git diff --check
```
