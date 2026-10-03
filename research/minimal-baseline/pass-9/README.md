# MINIMAL decompilation pass 9

Task `MINIMAL_DECOMPILATION_PASS_9`, baseline `abf41e8`. This pass uses the
unchanged V0.2 extractor for +28AA and its complex helpers. It does not run a new
compiler capture, start FIZZBUZ, introduce fixtures or extend packet code.
Historical image+offset identity remains authoritative.

## Evidence workflow and operational map

A fresh +28AA packet was generated with an explicit zero-byte frame and no
class discriminator slots. Its Markdown was read before selected JSON queries.
The first packet was 2,072,161 JSON bytes / 36,440 Markdown bytes. After the
accumulated annotations were refined, regeneration produced **2,183,364 JSON
bytes / 36,283 Markdown bytes**. Generated packets and scratch projections stay
ignored under `_build/minimal-pass-9/packet` and `_build/minimal-pass-9`.

The operational partition preceded semantic interpretation:

| Local coordinates | Operation/navigation region |
|---|---|
| +28AA..+2949 | Entry gate, selected-byte guard cascade, selected pointer |
| +294A..+2987 | +2185 predicate and first four-word argument construction |
| +2988..+29B2 | Caller-owned saved PSW recovery and combined predicate |
| +29B3..+2A8A | Selected-byte comparisons and demonstrated byte mutation |
| +2A8B..+2AB6 | Second four-word argument construction and +6708 call |
| +2AB7..+2B16 | Caller-owned continuation and compound gate |
| +2B17..+2B41 | +46ED state/buffer traversal, pointer test, +4738 wrapper |
| +2B42..+2B7D | Three field publications and +666E processing |
| +2B7E..+2BAD | Pointer publication, reverse scan, cached position test |
| +2BAE..+2C51 | Position-selected word/byte publications and result arithmetic |
| +2C52 | Original outer hardware RET |

These ranges include explicit RAW holes; they are navigation groups, not newly
decoded blocks or independently established procedures. The 351 local
instructions/occurrences, 684 represented bytes and 19 CALL sites are unchanged.
[operational-map.json](operational-map.json) links the groups to packet blocks.

For each new helper, corrected CALL/return witnesses established entry, return
slot, local branch/callee coordinates and stack behavior before semantic work.
The transfer inventory confirms no observed alternate CALL/jump/PCHL entry in
the selected envelopes. Return edges into continuation coordinates were not
mistaken for alternate entries. Bounds were supported by entry/branches/terminal
RET and separately callable neighbors, never context min/max or RoutineCandidate
ownership. [structural.json](structural.json) retains the checks and counts.

| Helper | Classification | Calls | Own coordinates / occurrences | Represented bytes |
|---|---|---:|---:|---:|
| +2185 | SMALL / DIRECT | 1 | 16 / 16 | 34 |
| +213C, immediate dependency | SMALL / DIRECT | 2 | 22 / 44 | 55 |
| +46ED | PACKET CANDIDATE | 2 | 31 / 74 | 73 |
| +4738, existing wrapper | PACKET CANDIDATE | 1 | 47 / 47 | 85 |
| +666E | PACKET CANDIDATE | 1 | 26 / 26 | 54 |
| +66FA, immediate dependency | SMALL / DIRECT | 1 | 6 / 6 | 14 |
| +66C6, immediate dependency | PACKET CANDIDATE | 1 | 23 / 130 | 52 |
| +7AF0 | SMALL / DIRECT | 26 | 23 / 598 | 35 |
| +7B13 | SMALL / DIRECT | 22 | 15 / 330 | 27 |
| +7B49 | SMALL / DIRECT | 38 | 15 / 570 | 27 |
| +2355 | PACKET CANDIDATE | 5 | 30 / 124 | 62 |
| +21AD, immediate dependency | SMALL / DIRECT | 6 | 23 / 116 | 39 |
| +230E, immediate dependency | SMALL / DIRECT | 4 | 35 / 124 | 61 |

No selected helper remained STRUCTURE ONLY: each supports at least a useful
scoped operation. This classification does not imply a complete contract.
+46ED/+666E/+66FA remain STRUCTURED with explicit opaque dependencies. The three
mapped setters have stable/complete/complete contracts. Other newly UNDERSTOOD
helpers retain partial contracts and unexecuted or delegated scope restrictions.
+4738 remains STRUCTURED, stable/complete/partial.

## Scoped helper contracts

+213C compares its saved C against 0B,0C,0D,02,03,04, in order. The observed
C=40 and C=28 invocations fail every comparison and return A=00 with flags still from
CPI 04; B/C/DE remain unchanged. **STATIC / UNOBSERVED:** each equality exit
returns 01 with MVI/RET. These exits remain RAW. There is no uniform FF/00 mask.

+2185 saves C at A646, tests its high nibble against 10, then calls +213C on
the witnessed nonmatching path. With +213C.A.bit0 clear, it reloads C and uses
SUI 31 / SUI 01 / SBB A: the final mask is FF iff saved C==31, otherwise 00.
Observed C=28 returns 00 with final self-SBB flags, BC unchanged and DE preserved.
**STATIC / UNOBSERVED:** the nibble-10 and helper-bit-set exits return 01.
The procedure's true representations can therefore differ by path; bit0 is the
tested relation. Its completeness remains provisional/partial/partial.

+21AD saves a byte at A647. ADI FF after wrapped C-30 sets carry iff that
wrapped difference is nonzero; self-SBB produces the first mask. CMA of the
31-C borrow mask produces FF iff C<=31. The AND is true iff C!=30 AND C<=31;
RAR/JNC delegates to +213C when false. The local true arm returns 01. This is
the operational unsigned relation, not an invented source-language category.
The ADI carry ancestry was audited locally because this small direct helper
does not need a packet; no extractor extension was made.

+2355 saves an index, invokes +21AD on byte[A628+index], and returns 05 on its
clear-bit result. Otherwise it checks the selected byte against 31 and 2A,
then delegates +230E. **STATIC / UNOBSERVED:** those two literal arms return
06/07. +230E returns 01 for observed selected byte 28; its selected-byte-05
path invokes opaque +22CB and increments the result twice (observed 02->03->04).
Its 24/25 zero-result
arm remains **STATIC / UNOBSERVED**. The two +28AA calls both select byte 28
and return 01, enabling caller publications 02 and 14 without a general claim
about the unresolved +22CB algorithm.

+46ED is independently callable from +2B26 and +4740. It saves comparison C
at A915, passes BC=A948 and DE=word[A947] to opaque +452B, then calls opaque
+422F. It advances through opaque +428E while opaque +4275.A.bit0 is set.
The later loop uses complete +4281 to test A863 for null, invokes opaque +4584
on the same buffer interface, and compares saved C with byte[p+2]. Mismatches
call +428E and repeat. Both correlated C=28 paths reject field 05 and end with
A863=0. The five child algorithms remain explicit; no list ownership, search
success guarantee or arbitrary termination claim is made.

+4738 calls that independent +46ED operation and uses +4281's nonzero-pointer
predicate. At the observed null result it supplies source A948, count byte[A947]
and saved tag C to partial +4468. V0.2 isolates the two-byte software cleanup
and resumes at +4759. It saves old=word[h+2], where h=word[A8AB], adds count
through complete resident +1A1D, then publishes the saved old word to new p+6,
with p=word[1C36]+1. Observed h=FBE1, old=0, count=7, p=FBB5: word[FBE3]=7 and
word[FBBB]=0 are distinct publications. +46ED and +4468 scopes still block a
complete wrapper contract.

+666E is stateful orchestration: cache BC at A9D4/5 and DE at A9D6/7; set
A863 from cached BC; read p+3 via complete +41A6 and cache its low five bits at
A9D8. Observed field 29 selects 09. It calls partial resident +119E(C=96,E=7),
then +66FA, passes returned HL in BC to opaque resident +1207, and invokes
+66C6. +66FA prepares HL=p+6 and DE=&A9D6 for opaque +84BB; no arithmetic
meaning is inferred from its observed zero return. +66C6 processes seven buffer
bytes in order, calling partial resident +1140(C=0) and +119E(C=buffer[i],E=8)
per iteration. It rereads count A947 before each unsigned count-minus-one/index
test. The final index is 7, A=6, and flags come from CMP 6-7. Count-zero/wrap
and +666E's alternative field-selector paths remain unobserved. +28AA ignores
+666E's returned A and reloads global A863, observed still FBB5.

The mapped setters are unconditional mutations at nonaliasing scratch/table/stack
scope, even if the written byte equals its previous value:

| Helper | Selection and publication | Supported return |
|---|---|---|
| +7AF0 | j=byte[AA1F+C]; word[AB49+2*j]=input DE | A/DE/NZPA preserved; BC=j; HL=AB4A+2*j; CY=0 |
| +7B13 | j=byte[AA1F+C]; byte[AC73+j]=input E | DE/NZPA preserved; A=E; BC=j; HL=AC73+j; CY=0 |
| +7B49 | j=byte[AA1F+C]; byte[AD9D+j]=input E | DE/NZPA preserved; A=E; BC=j; HL=AD9D+j; CY=0 |

AC73 gains a scoped mapped-control-byte role; it is distinct from the fixed
packed-attribute lookup at 1B4B, mapped bytes AAB4, mapped words AB49, primary
auxiliary bytes AD08 and second auxiliary bytes AD9D. New scratch roles retain
numeric addresses and scope. No table capacity, source type or compiler object
meaning is inferred.

## +28AA data flow, calls and polarity

All 19 immediate callsites now cite existing contracts. COMPLETE ordinary calls:
resident +1A40 at +2B2E; +7B7A at +2B95; +7AF0 at +2BB6; +7B13 at +2BC7/+2C1C;
+7B2E at +2BD8/+2C2D; +7B49 at +2BE9/+2C3E; +7AD5 at +2C07/+2C4F.
PARTIAL ordinary calls: +2185 at +2953; +46ED at +2B26; +4738 at +2B3F;
+666E at +2B7B; +2355 at +2BF8/+2C45. PARTIAL SOFTWARE-CLEANUP calls:
+6708 at +2985/+2AB4. None of those partial scopes becomes a universal contract
merely because this invocation has a concrete result.

The first producer/carrier chain is explicit:

```text
+2185(C=28).A=00 -> +2956 PUSH PSW at FFCE/FFCF
    four arguments: source FBD0, selector FB00, cursor FBC6, extra 002B
    +2985 CALL +6708 -> copied continuation FFCC -> software RET
+2988 POP B: B=saved A=00; C=packed flags=56
+2989 MOV C,B -> +298A ANA C: returned FF AND saved 00 = 00
+298B RAR: CY=0 -> +298C JNC taken
```

Writer ancestry, not equal endpoint values, establishes that saved PSW: every
intervening parent/child guest write is checked against its two addresses, and
the established observed copier arm has no child calls/host effects. Its four
consumed words and copied continuation are disjoint from the saved PSW.
The second call uses selector word C602 (only low 02 consumed), has no saved
predicate, copies its continuation to FFCE and resumes at +2AB7.

These parent branch polarities are mechanically supported by the packet's
dependency chains and confirmed against its concrete outcomes:

| Branch | Producer chain and final flag | Taken iff | Observed |
|---|---|---|---|
| +28C1/+28E5/+2909 | selected byte minus literal, SUI1, SBB A, RAR -> CY | byte differs from 0B/0C/0D respectively | taken each |
| +2926 | A=0A; CMP selected byte -> CY | selected byte <=0A unsigned | taken |
| +293F | retained 0D equality mask; RAR -> CY | mask.bit0 clear | taken |
| +298C | copy A AND saved predicate A; RAR -> CY | either original A.bit0 clear | taken |
| +29D7 | 02/03 equality masks OR; RAR -> CY | selected byte neither 02 nor03 | taken |
| +29F4/+2A30 | CPI04/CPI05 -> Z | selected byte differs from04/05 | taken/fallthrough |
| +2A48 | base-byte28/2A equality masks OR; RAR -> CY | base byte neither28 nor2A | fallthrough |
| +2AB8 | copy-return A; RAR -> CY | returned A.bit0 set | taken |
| +2AE7 | selected-byte15/25/24 masks OR, AND saved incoming C; RAR -> CY | compound.bit0 clear | taken |
| +2B32 | zero-subtrahend +1A40 load; ORA L -> Z | word[A863] nonzero | fallthrough |
| +2BA0 | CPI index,01 -> Z | index!=1 | taken |
| +2BF1 | CPI saved byte,00 -> Z | A661!=0 | fallthrough |

Additional helper audits are explicit in their block pseudocode: +2190 JNZ
tests masked nibble inequality; +219E JNC tests +213C.A.bit0 clear; +21C6 JNC
tests the complemented conjunction described above. +4702/+470F JNC test
helper A.bit0 clear, +4720 JC tests A.bit0 set and +472D JNZ tests byte inequality.
+4747 JC returns iff the current pointer is nonzero. +668B JNZ tests masked
field!=09. +66CB JZ tests initial count==0; +66DB JC tests wrapped count-minus-one
< index; +66F6 JNZ tests incremented index!=0. +2367 JC tests +21AD.A.bit0 set;
+2379/+238B JNZ test selected-byte inequality. +232C JNC tests neither24 nor25;
+233E JNZ tests byte!=28. Helper carry is not substituted for returned A.bit0.

The resulting coherent observed path includes a selected-byte mutation 05->28,
two scoped copier invocations, null-pointer selection, wrapper construction,
field writes and position-selected publications. There are still material opaque
islands, so +28AA remains **STRUCTURED**, with **provisional/partial/partial**
completeness and all 253 enclosing RAW bytes unchanged. Every substantially
interpreted local region has near-code block pseudocode; its procedure pseudocode
retains explicit partial helpers instead of inventing one high-level algorithm.

Observed publication channels remain separate:

- Parent state: A62A=28, A660=1, A661=2, A662=2B, and selected pointer word A63F=FBB5.
- Parent indirect fields: FBB8/9/A=29/7/0.
- Wrapper repairs: word[FBE3]=7 and word[FBBB]=0.
- Mapped word: word[AB4D]=FBB5.
- Mapped control bytes: AC75/AC73=28; primary auxiliary AD0A/AD08=7;
  second auxiliary AD9F/AD9D=0; mapped bytes AAB6=02 and AAB4=14.
- Copier buffer/count/control mutations and resident child effects keep their
  callee scopes. They are not merged with parent stores or mapped-table writes.

## Secondary refinement

+4B69 was not decompiled again. All three +4394 calls in this capture take the
successful p>=AE7A guard; the only +429D invocation has selector30. Therefore
neither failure nor non-30 dispatch gains dynamic scope. **STATIC / UNOBSERVED:**
exact bytes +43B8..+43BD prepare BC=637A and CALL runtime05F2, opaque
PLI.COM+04F2. Its return/diagnostic/recovery behavior is unresolved. The RAW bytes
remain RAW and no error-path contract is substituted into +43D5 or +4B69.
Their existing normal scope remains intact; +4B69 stays UNDERSTOOD with
provisional/partial/partial completeness. The exact blockers are now recorded
in those hypotheses.

## V0.2 assessment and remaining gaps

Continuation-aware ownership materially reduced manual reconstruction: both
+6708 calls and +4738's +4468 call behave as ordinary pre-call/post-return
evidence boundaries once their distinct return convention is inspected. No
parent/callee ownership ambiguity remains on the recorded paths. Consumed words,
copied continuation and parent saved PSW have exact separate addresses and
coordinates in JSON; the compact Markdown describes cleanup without a proof dump.

The full saved-PSW producer chain still required one selected writer/access query:
conservative partial-contract preservation stops the automatic definition at the
copier boundary, leaving an observed saved-byte leaf. That local gap could be
resolved safely from packet accesses and the established copier scope. Partial
scope/preservation recognition and some ADI carry dependencies remain limited.
Neither is a repeated impossible blocker here; **no V0.3 change is justified**.
This is one semantic use of V0.2, not an independent stability experiment.

| Gap | Classification / best next route |
|---|---|
| +46ED's +452B/+422F/+4275/+428E/+4584 | Missing helper algorithms; existing helper decompilation first |
| +66FA's +84BB and resident +1207 | Missing helper algorithms; establish their operations before broader +666E interpretation |
| +2355/+230E selected-byte05 fallback +22CB | Missing helper; observed contract recovery first |
| +6708/+4468 and resident +1140/+119E | Partial helper contracts; preserve declared scopes, investigate missing existing paths first |
| +28AA's 253 RAW bytes and single-outcome guards | Unobserved paths; bounded static analysis may help, but MINIMAL cannot supply new dynamic outcomes |
| Allocator failure and non-30 selectors | Unobserved/partial paths; static continuation/error-helper work first, genuinely different inputs eventually needed |
| Table/state producers, selected pointer aliases, arbitrary traversal termination | Unknown producer / alias-precondition / general provenance; not resolved by equal concrete values |

MINIMAL is approaching diminishing returns for alternate-path coverage, while
reusable executed helpers still offer a simpler route than fixtures. Recommend
**A: another MINIMAL helper pass**, focused on the +46ED traversal/buffer cluster,
+84BB and resident +1207, followed by +22CB where it removes a specific gap.
Those contracts can strengthen +28AA without new source constructs. Do not start
FIZZBUZ or matched microfixtures merely to increase dynamic percentages.

## Progress, packet measurements and validation

| Executed byte status | Before | After |
|---|---:|---:|
| RAW | 14,839 | 14,306 |
| DECODED | 304 | 304 |
| STRUCTURED | 2,207 | 2,348 |
| UNDERSTOOD | 3,662 | 4,054 |

RAW->STRUCTURED: **141 bytes**; RAW->UNDERSTOOD: **392 bytes**. UNDERSTOOD CALL
entries: **78->87**; STRUCTURED entries: 11->14; unresolved: 302->290. The 391
CALL/RST entries and eleven PCHL continuation entries remain separate inventories.
Dynamic UNDERSTOOD: **46.7966%->47.2629%** (205,904->207,956 occurrences).
PLI1: **73.9662%->78.7522%** (31,713->33,765). Other images are unchanged:
PLI.COM 47.8602%, PLI0 40.8068%, PLI2 22.3957%.
[progress.json](progress.json), [dynamic-progress.json](dynamic-progress.json)
and [before.json](before.json) retain the exact comparison.

| Packet | JSON bytes | Markdown bytes |
|---|---:|---:|
| +28AA | 2,183,364 | 36,283 |
| +46ED | 318,298 | 13,044 |
| +4738 | 318,195 | 8,463 |
| +666E | 412,239 | 8,867 |
| +2355 | 263,359 | 8,295 |
| +66C6 | 491,871 | 7,261 |

Single generation samples were 6.461–6.830 seconds alongside validation; these
are not controlled benchmarks. [packet-sizes.json](packet-sizes.json) records
measurements; generated packet JSON/Markdown is not committed.

Validation: project tests, all MINIMAL baseline/pass-1–9 tests (85), all V0.2
packet tests (23, including 55 continuation corrupt/unsupported variants), V1
tests (9), verifier tests (11), dynamic-progress consistency and `git diff --check`
pass. Seven new pass-9 tests independently check mapped addresses/values/flags,
predicate masks, saved-PSW writer ancestry, software boundaries, wrapper repairs,
ordered processing calls, distinct publication channels and partial scope.
The baseline's live totals were updated; pass-8's immutable progress assertions
now read its historical snapshot while still checking live consistency.

The historical verifier reconstructed all **94,720 bytes exactly**, checking
section/full-image hashes, partitions and runtime mapping. No unexecuted byte was
promoted; existing stable labels survive, with operand-internal former RAW labels
retained as coordinate-only EQUs. Unrelated untracked files remain untouched.

Reproduce:

```sh
python3 tools/annotated-assembly/procedure_evidence_packet.py \
  --images /path/to/DISK1 --entry PLI1.OVL+28AA --frame-bytes 0 --class-slots \
  --output _build/minimal-pass-9/packet
python3 tools/annotated-assembly/test_minimal_pass_9.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_procedure_evidence_packet.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_pass_8.py -v
python3 tools/annotated-assembly/test_decompilation_annotations.py -v
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
git diff --check
```
