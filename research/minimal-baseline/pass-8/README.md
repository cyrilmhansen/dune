# MINIMAL decompilation pass 8

Task `MINIMAL_DECOMPILATION_PASS_8`; baseline `5b5249c`. The original CALL word,
argument consumption, copied continuation and software RET were re-established
for every observed +4468/+6708/+43D5 invocation before interpretation. No compiler
run, new fixture, FIZZBUZ analysis or Procedure Evidence Packet change occurred.
All 94,720 historical bytes remain exact.

## Evidence and continuation ownership

Corrected indexed witnesses select exact CALL entries and close them only at a
proved hardware or copied-continuation return. Ordinary child returns isolate
descendants. Software children require original CALL slot→POP D, explicit
DE-preserving operations, PUSH D, latest byte-writer identities and the actual
RET reads. Return-address equality alone does not select a child boundary.
The task-local join is in `check_minimal_pass_8.py`; it is not packet discovery
or a new frame/ownership/provenance architecture.

Let pre-CALL SP be **S**, entry SP **E=S−2**, and consumed caller bytes **N**:

```text
CALL writes return PC at E
POP D reads exactly that original low/high word; SP=S
N/2 POP B instructions read caller words S,S+2,...,S+N-2; SP=S+N
PUSH D writes copied return PC at S+N-2=E+N
body temporary saves/CALLs run below the relocated continuation
software RET reads that writer's bytes and resumes original CALL+3
final SP=S+N=E+N+2
```

No temporary push/pop is intermixed with argument consumption in these three
observed prologues. The body may later save temporaries: +43D5 uses PUSH H/XTHL/
POP H below its copied continuation; +4468 uses temporary pointer/link saves.
+6708's observed copy/padding arm has no body calls or temporary pushes.
[continuations.json](continuations.json) retains every actual instance, prefix,
writer/slot/consumer relation and algebra; [regions.json](regions.json) retains
caller argument producers and consumption order.

| Procedure | Original word POP | Caller bytes | Copied register / PUSH | Relocation from E | Final SP | Argument interpretation at observed scope | Nested calls |
|---|---|---:|---|---:|---|---|---|
| +4468 | +446F POP D | 2 | DE / +4474 | +2 | S+2 | one full source-pointer word | +4394/+422F/+4281/+83A0/+428E |
| +6708 | +670F POP D | 8 | DE / +671F | +8 | S+8 | full word0, low word1, full word2, low word3 | none on witnessed arm |
| +43D5 | +43DC POP D | 2 | DE / +43DF | +2 | S+2 | one word's low byte; high ignored | +4394/+429D/+1A1D |

Software RETs are +452A, +67BA and +4467 respectively. Decision **A**: these
observations support one mechanically reusable cleanup relation parameterized
by N. Their argument layouts, register inputs, memory operations and completeness
are materially different; none was inferred from the control example's semantics.
+4468's contract/status remain the established calibration, including partial
linked-tail/helper paths. Only its prefix ancestry sample and explicit cleanup
metadata were strengthened.

### All observed stack instances

| Entry / callsite | Call step | S | Original slot | Copied slot | Final SP | Caller words in ascending-address/pop order |
|---|---:|---:|---:|---:|---:|---|
| +4468 / +46A3 | 257266 | FFB7 | FFB5 | FFB7 | FFB9 | FFB7=20C6 |
| +4468 / +4756 | 264679 | FFCC | FFCA | FFCC | FFCE | FFCC=A948 |
| +6708 / +2985 | 259545 | FFC6 | FFC4 | FFCC | FFCE | FFC6=FBD0, FFC8=FB00, FFCA=FBC6, FFCC=002B |
| +6708 / +2AB4 | 263336 | FFC8 | FFC6 | FFCE | FFD0 | FFC8=FBD0, FFCA=C602, FFCC=FBC6, FFCE=002B |
| +43D5 / +4BBA | 218051 | FFF8 | FFF6 | FFF8 | FFFA | FFF8=A730 |

The highest consumed carrier word is overwritten by the copied continuation.
These are input carriers, not writable result slots. The actual result channels
are buffer/global/indirect writes and returned registers. Source pointers are
read, not caller-stack output locations. All carrier writes after entry were
checked; only the continuation PUSH writes into those consumed slots.

## +6708 arguments and scoped operation

The caller PUSH order is reversed by the callee's ascending-address POP order:

| POP | Role / cache | First producer / value | Second producer / value |
|---|---|---|---|
| +6710 | full source pointer → A9DE/DF | +2973 PUSH H / FBD0 | +2AA8 PUSH H / FBD0 |
| +6715 | low selector → A9DD; high ignored | +296B PUSH B / FB00 | +2AA0 PUSH H / C602 |
| +6718 | full initial cursor → A9DB/DC, then A863 | +2968 PUSH B / FBC6 | +2A9C PUSH B / FBC6 |
| +671D | low cached byte → A9DA; high ignored | +295A PUSH H / 002B | +2A8E PUSH H / 002B |

Input C=7 is the saved source-byte count A9E0; E=5 is saved atA9E1 and compared
with05. Word1's high FB/C6 is carried by caller instructions but never used by
the callee; word3's high00 is also discarded. Full words0/2 are cached without
truncation. Word2 initializes working pointerA863 before buffer writes; its later
cache corruption does not change that already-published word.

Observed code gates `(byte[A628+selector]&28)==28`, E==05 and the mask22 prefix
arm being false. It clears destination countA9E2 and source offsetA9E3, then:

```text
loop:
    selector = byte[A9DD]                 // freshly read, not immutable argument
    limit = byte[A62B + selector]
    if unsigned(byte[A9E3]) >= limit: break
    if byte[A9E3] < byte[A9E0]:
        byte[A9E4] = byte[word[A9DE] + byte[A9E3]]
    else:
        byte[A9E4] = 20
    byte[A948 + byte[A9E2]] = byte[A9E4]
    byte[A9E2]++
    byte[A9E3]++
byte[A947] = byte[A9E2]
A = FF iff byte[A9E3] >= byte[A9E0], else 00
RET copied continuation
```

Do not replace this with fixed-length memcpy/padding: writes may alias saved
controls, and each stopping predicate reloads its selector and limit.

| Member | Initial selector / limit | Source / padding writes | Alias effect | Final count / limit | Return A / CY / Z |
|---|---|---|---|---|---|
| +2985 | 0 / FE (254) | 7 / 143 | output offsets146..149 write20 to A9DA/DB/DC/DD; selector becomes20 | 150 / byte[A64B]=00 | FF / 0 / 1 |
| +2AB4 | 2 / 7 | 7 / 0 | none of those controls overwritten | 7 / 7 | FF / 0 / 1 |

The first member's word2 cache becomes2020 and cached word3 low byte becomes20;
these cannot be called preserved arguments. Its source pointer/count remain
unchanged on the demonstrated span. The output intervalA948..A9DD is observed,
not an inferred buffer capacity or a compiler-level diagnosis. The second call
re-caches arguments and overwrites only seven buffer bytes; it does not clear
the old padding beyond them.

Final SUB count sets CY iff offset<count; SBB A yields FF for borrow,00 otherwise;
CMA complements A **without recomputing flags**. Thus returned A.bit0 is the
inverse of returned CY, and both witnessed FF returns retain Z=1 from self-SBB.
HL=A9E0, BC=A62B and DE=6 on both observed exits; register results are not assumed
for excluded modes/aliases.

+6708 is UNDERSTOOD only at these correlated path scopes: 166 bytes /87 own
coordinates /3,976 own occurrences. The provisional observed-path envelope is
`[6708,67BB)`. The known gate-failure target **+67BE escapes it**, and full bounds
are unresolved rather than truncating unseen callee operations into the caller.
Other E/mask22 paths remain RAW. Arbitrary overlapping-state termination is not
proved. No PL/I parameter types or meanings of the cached byte/cursor were added.

## +43D5 and the +4B69 caller

+4BB5 PUSH B supplies A730: +43DD POP B caches **only 30H** atA8F7; A7 is ignored.
This is not a pointer argument. Input C=2/E=0 go toA8F8/F9 and later fields+4/+5.

At the existing +4394 normal floor scope, C=0 reserves a ten-byte headered block
p=old_top−9, sets top=p−1, header bytes 10/0 and working pointerA863=p. +43D5 writes
p+2=30, p+3=4C, p+4=2, p+5=0. The immediate +429D dispatch was recovered only for
selector30: complete field getters +419F/+41A6 read pointer+2/+3; +429D caches
those bytes and field+4 atA8F3/4/5, fails15/16/19 and masked24/28 tests, then
returns A=2 with flags still from CPI30. No source-language selector meaning is
assigned. Other dispatch arms remain partial/RAW, including an escaping target.

Let `slot=A8AB+2*byte[A8EB]`, `h=word[slot]`, `old=word[h+2]`. Then +43D5:

1. Copies h to newblock word[p+8], using PUSH H/XTHL/POP H below the continuation.
2. Rereads slot, sets A863=h and saves old atA8FB/FC.
3. Adds the returned delta2 to word[h+2] via complete resident +1A1D; publishes
   low/high back to that same word.
4. Restores p=word[record_top]+1 atA863 and writes saved old to word[p+6].

It does not write the head slot itself at this scope. Return A is high updated
oldword, BC=6, DE=saved oldword, HL=p+7; NZPA retain +1A1D's high ADC, CY follows
final address DAD. The complete local graph has89 coordinates/147 bytes, but
contract remains **partial** through allocator failure and selector alternatives.
Bounds are stable `[43D5,4468)`; original CALL-word/argument consumption is explicit.
The calibration +4468 is the separately called adjacent entry, not a shared tail.

+4B69 now has a normal outer ProcedureHypothesis `[4B69,4BD5)`:

- Save q=record_top+1 atA861. Complete +1A2C computes **DE−HL=q−AE7A**; +4B77 JNC
  selects the normal path iff q>=AE7A. Three guard-failure bytes remain RAW.
- Set A8EB=0 and copy q toA8E9/A8AB/A86D. Clear A92B and write exactly128 zero
  words atA761..A860, low/high order. The unsigned7F guard exits at index 128,
  after128 JNZ backedges. These words are zeroed, not initialized to q.
- Push the byte30 carrier word, pass C2/E0 to +43D5, and consume no further
  caller cleanup: the software child returns SP to the outer entry value.
- Save newp atA86B, reload unchanged head h fromA8AB intoA863, and decrement
  word[h+2] twice through BC. This undoes the scoped delta2 while leaving the
  newblock and its saved original word as distinct publications.

Observed q=h=FBE1, newp=FBD7, original oldword0→temporary2→restored0. Newblock
word+6 is0 and word+8 isFBE1. Outer RET+4BD4 consumes its unchanged CALL slot;
A/DE/flags inherit the child, BC=restored oldword and HL=h+3. The 105 represented
bytes /52 coordinates /2,088 own occurrences are UNDERSTOOD at declared normal
scope. Bounds/CFG/contract remain **provisional/partial/partial** for the RAW
floor path and inherited helper scopes.

## +28AA: precise ownership and bounded refinement

The normal outer hypothesis remains `[28AA,2C53)`, 351 own coordinates and
occurrences /684 represented bytes; nineteen local CALL sites. Callee +6708's
3,976 occurrences are not +28AA body simply because its original frame was popped.
Its prologue, argument caches, loop, copied continuation and software RET remain
inside the proved child invocation window.

Both callsites form source pointer `word[A863]+10` and source count
`byte[word[A863]]−0A` (17−10=7 observed), and push the selected cursor word from
`A63B+2*byte[A634]`. The first selector word FB00 deliberately uses low0 while
retaining a prior B=FB; the second C602 comes from LHLD A634 and uses only low2.
The word atA662 supplies low cached byte2B, with its neighboring high byte unused.
Incoming E is5 at both calls.

A saved PSW from opaque +2185 is **not** one of the four arguments. +6708's
cleanup restores SP to that earlier saved word. +2988 POP B reads its original
PUSH PSW bytes; MOV C,B/ANA C/RAR/+298C JNC tests:

```text
branch taken iff NOT(6708.returned_A.bit0 AND saved_2185_A.bit0)
observed: FF AND 00 = 00; CY=0; JNC taken
```

The second call has no such saved predicate. +2AB7 RAR/+2AB8 JC tests returned
A.bit0 directly: FF gives CY=1 and JC taken; helper CY=0 is not the predicate.
The ensuing +2ABF code is caller-owned. No fifth argument or shared callee tail
is invented from those subsequent stack accesses.

+28AA is now **STRUCTURED**, with provisional/partial/partial completeness.
Only the two argument/callee/continuation/polarity regions were semantically
refined; the remaining body keeps explicit unreviewed/delegated operations. Its
old context count4,315 is not an importance or ownership measure. Highest-leverage
remaining candidates are the opaque +2185 guard producer, +46ED/+4738 state/copy
operations, +666E, and mapped helpers +7AF0/+7B13/+7B49/+2355. Existing +7B7A,
+7B2E and +7AD5 contracts remain usable only at their actual scopes.

## ABI support and evidence gaps

The proven relation can truthfully contain:

```text
call_step, original_return_slot, original_return_pop_step,
continuation_register, continuation_writer_step, relocated_return_slot,
consumed_caller_bytes, software_ret_step, final_SP_minus_preCALL
```

That small generalization is **justified** for this observed family, with strict
POP/source-register/PUSH/last-writer/RET checks and no same-value-only joins.
**Packet support is not implemented here**: safe direct analysis completed the
scoped +4B69 operation and bounded +28AA refinement without forcing the ordinary
extractor. A separate infrastructure ticket can add nested software-return proof
presentation/isolation while retaining ordinary outer-frame restrictions. Seeding
an entry does not solve return ownership; no general SSA/provenance/ABI engine
is proposed.

The historical-byte verifier's existing software sample check was narrowly
parameterized from two bytes to a proven positive even count, with new counts
requiring actual prefix ancestry. The existing +4468 proof was strengthened with
that prefix. This is annotation validation, not a packet/frame-profile extension;
legacy verifier error behavior and corruption checks remain intact.

Remaining blockers:

- +6708: **unobserved path / unresolved bounds** at +67BE, other E/mask22 paths;
  **alias/precondition / termination concern** for arbitrary self-overlap;
  **unknown producer/general provenance** of lookup bytes and excluded cursor roles.
- +43D5: **partial helper contract** +4394 failure and +429D other selectors;
  **alias/precondition** of head/newblock/scratch/stack; wider ownership unspecified.
- +4B69: **unobserved path** three floor-failure bytes and **partial helper contract**
  allocator behavior near the floor. Its current normal loop/setup operation is
  clear; no additional packet is required to preserve observed ownership.
- +28AA: **missing helper** guard/state/mapped operations listed above, 253 RAW
  enclosing bytes, **unknown producer/general provenance** of wider tables/state.
  Larger semantic work would benefit from **continuation-aware packet support**.

Pass-9 recommendation is separate: **+4B69: A, finish existing partial allocator/
failure-path evidence before fixtures**; **+28AA: C, a small continuation-aware
packet infrastructure ticket before broad body reasoning, then B/A as helper
contracts permit**. No new fixture or FIZZBUZ step is currently the simpler route.

## Small operand-order erratum

The existing +1A2C contract/instructions explicitly compute E−L then D−H−borrow,
thus **DE−HL**. The pass7 +7BBF description had transcribed new_top−old_top;
its saved DE is old_top, so wording now says old_top−new_top. For masks0/8000 the
modulo16-bit differences and all zero/equality decisions are identical in both
orders, and the following ORA clears carry. No count, publication, polarity,
completeness or byte status changes. [caller-refinements.json](caller-refinements.json)
records the exact correction; no unrelated arithmetic helper was re-decompiled.

## Roles, progress and exactness

New scoped globals name +6708 source pointer/count, selector, cursor/extra caches,
written/source offsets, padding-byte cache and flag/limit tables; the observed
cache-overwrite aliases remain explicit. +43D5 roles name low-word argument,
C/E caches, delta, saved oldword and selected head-table/index. Stack words remain
E-relative argument roles in forensic records, not global parameter declarations.
Existing buffer/count roles A948/A947 and A863's construction/link aliases retain
numeric addresses and procedure-specific scopes. No table capacities or PL/I types
were inferred. Immediate field getters have complete operational contracts;
+429D is qualified to selector30 with other dispatch still RAW.

| Executed bytes | Before | After | Delta |
|---|---:|---:|---:|
| RAW | 16,035 | 14,839 | −1,196 |
| DECODED | 304 | 304 | 0 |
| STRUCTURED | 1,523 | 2,207 | +684 |
| UNDERSTOOD | 3,150 | 3,662 | +512 |

RAW→STRUCTURED684, RAW→UNDERSTOOD512. No unexecuted RAW byte is promoted and
no executed coordinate is newly captured. Whole images:88,506 RAW /304 DECODED /
2,238 STRUCTURED /3,672 UNDERSTOOD, sum 94,720. All prior labels survive; all
section/full-image hashes and file/runtime coordinate checks round-trip exactly.

| CALL entries | Before | After |
|---|---:|---:|
| UNDERSTOOD | 72 | 78 |
| STRUCTURED | 10 | 11 |
| DECODED | 3 | 3 |
| RAW | 306 | 299 |

Classification unresolved309→302 includes three DECODED entries. The391
CALL/RST coordinates and eleven separate PCHL entries are unchanged. +4468
remains STRUCTURED; +7BBF's erratum earns no promotion.

| Dynamic image | Occurrences | RAW after | STRUCTURED after | UNDERSTOOD after | UNDERSTOOD before→after |
|---|---:|---:|---:|---:|---:|
| PLI.COM | 266,524 | 33,267 | 43,210 | 127,559 | 47.8602%→47.8602% |
| PLI0.OVL | 94,418 | 44,567 | 11,322 | 38,529 | 40.8068%→40.8068% |
| PLI1.OVL | 42,875 | 10,301 | 861 | 31,713 | 59.4962%→73.9662% |
| PLI2.OVL | 36,181 | 23,127 | 3,649 | 8,103 | 22.3957%→22.3957% |
| Total | 439,998 | 111,262 | 59,042 | 205,904 | 45.3866%→46.7966% |

DECODED occurrences remain 63,790. Newly understood own occurrences are 6,204;
+28AA's351 become STRUCTURED. Parent/callee windows are not double-counted.
[before.json](before.json), [progress.json](progress.json),
[dynamic-progress.json](dynamic-progress.json), [regions.json](regions.json) and
[structural.json](structural.json) retain pass snapshots. Live root artifacts
follow current statuses; old pass7 assertions retain its historical classifications.

## Validation

```sh
python3 tools/annotated-assembly/check_minimal_pass_8.py \
  --output _build/minimal-pass-8/checked.json
python3 tools/annotated-assembly/test_minimal_pass_8.py -v
python3 tools/annotated-assembly/test_procedure_evidence_packet.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_baseline.py --images /path/to/DISK1 -v
# Run test_minimal_pass_1.py through test_minimal_pass_7.py with --images.
python3 tools/annotated-assembly/test_decompilation_annotations.py -v
python3 tools/annotated-assembly/test_verify.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1 --write-progress
python3 tools/annotated-assembly/minimal_dynamic_progress.py
python3 tools/annotated-assembly/decompilation_annotations.py
dune runtest --force
git diff --check
```

Eight new tests check all twelve selected invocations, every original/copy/RET
relation, actual argument producers/order/unused high bytes, equal-valued wrong
slots and DE-clobber rejection, correlated self-overlap/fresh limits, returned A
versus flags, short-block/old-word/parent restoration, caller-owned saved PSW,
partial scopes and dynamic consistency. Existing verifier latest-writer error
checks still pass. Pass2's obsolete permanent-RAW assertion for +43D5 now checks
its independent identity adjacent to +4394 instead of preventing later work.
All project tests (976,272 ALU cases), packet/MINIMAL pass tests, V1, continuation
and exact historical-byte checks passed. All 94,720 bytes are exact. Scratch
queries remain ignored under project `_build`; no generated packet is committed,
no task /tmp directories remain, and unrelated untracked files are untouched.
