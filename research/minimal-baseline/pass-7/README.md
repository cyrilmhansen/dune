# MINIMAL decompilation pass 7

Task `MINIMAL_DECOMPILATION_PASS_7`; baseline `8dfba28`. Both selected helper
clusters now have useful low-level contracts, and established effects propagate
through +7BBF → +7C1B → +7D53. No compiler run, FIZZBUZ work, new fixture,
packet infrastructure change or broad static disassembly was performed.
All 94,720 historical bytes and prior numeric labels remain exact.

## Structural selection and evidence interfaces

Actual CALL coordinates, corrected hardware returns, local transfers and exact
image bytes established the seven helper envelopes before interpretation. All
148 helper calls consume their original hardware CALL slot and return with
SP=entrySP+2. All seven reserve no local frame; only the two emission wrappers
have nested CALLs. There is no observed recursion or alternate external entry
inside these envelopes. [structural.json](structural.json) preserves callers,
returns, branches, stack deltas, counts and incoming-transfer audits.

| Entry | Extent, exclusive end | Calls / sites | Own coordinates / occurrences | Classification |
|---|---|---:|---:|---|
| PLI1+7A79 | `[7A79,7A93)` | 11 / 3 | 16 / 176 | SMALL / DIRECT |
| PLI1+82E1 | `[82E1,82EA)` | 36 / 1 | 9 / 324 | SMALL / DIRECT |
| PLI1+82BB | `[82BB,82C6)` | 37 / 2 | 11 / 407 | SMALL / DIRECT |
| PLI1+82C9 | `[82C9,82D0)` | 36 / 1 | 7 / 252 | SMALL / DIRECT |
| PLI1+7ABF | `[7ABF,7AD5)` | 14 / 3 | 12 / 168 | SMALL / DIRECT |
| PLI1+7E46 | `[7E46,7E56)` | 7 / 1 | 8 / 56 | SMALL / DIRECT |
| PLI1+7E56 | `[7E56,7E5F)` | 7 / 1 | 5 / 35 | SMALL / DIRECT |

Minimal structural V1 hypotheses preceded semantic interpretation. None was
forced through the packet extractor merely because it was a selected target.
All 100 helper bytes are represented by dynamically executed instructions.
Exact terminal RETs support their stable bounds; no context min/max or
RoutineCandidate ownership supplied an extent.

The complex, already cataloged parents +7BBF, +7C1B and +7D53 used V0.1 packets
as their joined semantic interface. Markdown was read first, then selected JSON
state/access/call subsets. Known frame options were zero bytes/empty class slots
for +7BBF/+7D53 and five bytes/class slots0,3 for +7C1B. No broad witness or
context mining replaced that interface for parent semantics. Small helpers used
direct corrected witnesses and exact instruction equations.

Final regenerated artifacts remain ignored at `_build/minimal-pass-7/packets`:

| Packet | Invocations / classes / blocks | JSON bytes | Markdown bytes |
|---|---:|---:|---:|
| PLI1.OVL+7BBF | 3 / 3 / 10 | 1,904,616 | 11,353 |
| PLI1.OVL+7C1B | 16 / 12 / 19 | 2,285,913 | 20,137 |
| PLI1.OVL+7D53 | 21 / 12 / 33 | 2,894,121 | 26,413 |

The 188 checked invocations include the 148 helpers, three +7BBF invocations,
sixteen +7C1B invocations and twenty-one +7D53 invocations. Own instructions are
isolated from descendants; inclusive callee footprints are not summed as
exclusive cost or procedure ownership.

## Cluster A contracts

+7A79 saves input position C atAE38. It reads a byte index
`j=byte[AA1F+C]`, then the little-endian word at `AB49+2*j`. Return HL is the
word, BC=j, DE is the selected high-byte address, and A/NZPA are preserved.
CY=0 comes from address addition. LHLD also reads the neighboring AE39 byte,
which MVI H,0 discards. Only AE38 is written; no word-table capacity is inferred.

+82E1 takes HL=word pointer and DE=mask. XCHG places the pointer in DE and mask
in HL; low and high bytes are read and ANDed separately. Return HL is
`word[inputHL]&inputDE`, DE=inputHL+1, A=high result, BC preserved. CY=0 and NZPA
come from the high ANA, so Z describes the high byte rather than the whole word.
There are no body memory writes.

+82BB reads the first word through input HL into BC before changing L/H. It
then reads the second word through input DE, performs ADD low / ADC high, and
returns their wrapping sum in HL. BC is the first word, DE is the second pointer
plus one, A is high sum, CY is word overflow, and NZPA describe the high ADC.
No incoming-carry dependence or body writes. Thirty-six calls read the **same
pointer twice**; the extra call from +6704 has distinct pointers whose observed
word values happen both to be zero. Equal values do not establish aliasing.

+82C9 takes register words DE and HL and returns `DE & HL` in HL, A=high result.
BC and DE are preserved, CY=0, NZPA come from high ANA. No data-memory access
beyond the RET word and no body writes. None of these helpers returns a general
Boolean in CY or Z for the full word.

Each Cluster A contract was substituted into +7BBF's local blocks as it became
available. [caller-refinements.json](caller-refinements.json) records the four
staged substitutions from the baseline plus the final parent refinements.

## +7BBF: complete bounded operation at declared scope

Save position atAE4B, set counterAE4C=15, and load the mapped word intoAE4D/4E.
Each iteration executes these operations in order:

```text
positive = (counter != 0)           // FF/00 mask saved through PSW
old_top = word[AE4D] & 8000
new_word = u16(word[AE4D] + word[AE4D])
word[AE4D] = new_word               // low byte then high byte
new_top = new_word & 8000
if !(positive && new_top == old_top): break
counter--
```

+82E1 returns DE=AE4E; copying/decrementing establishes **both** +82BB input
pointers as AE4D. Its reads therefore double the same word. XCHG/DCX proves the
subsequent indirect publication destination is AE4D/4E. +82C9 computes the new
top mask from doubled DE. POP D restores the saved old top mask; existing
complete +1A2C subtracts new_top-old_top. These are word transformations and
address equations, not packed-object/source-language semantics.

The loop tests the counter **after shifting**. At nonaliasing scratch/table/stack
scope it performs at most sixteen shifts and returns `counter=16-shift_count`.
The counter-zero outcome still performs the sixteenth shift. This outcome was
not observed; all its instructions are represented, and the complete helper
contracts plus bounded counter arithmetic justify the operation without
promoting unexecuted bytes. The independent 65,536-word arithmetic check finds
the same stopping point from the original sequence of adjacent bits.

| Input position | Initial word | Shifts | Final word | Counter / returned A | Auxiliary destination |
|---:|---:|---:|---:|---:|---:|
| 4 | 0001 | 15 | 8000 | 1 | AD09 |
| 2 | 0252 | 6 | 9480 | 10 | AD0D |
| 0 | 0001 | 15 | 8000 | 1 | AD0B |

After the loop +7B2E writes the counter to `AD08+fresh position_map[saved position]`.
This auxiliary publication is separate from the shifted scratch word. Return
A=counter, BC=fresh map index, HL=auxiliary address. LHLD AE4C reads counter plus
neighboring shifted-word **low byte**, so preserved DE is
`counter+256*final_word.low`, not the full shifted word. CY=0; NZPA retain final
mask ANA: Z=1/S=0/P=1 while auxiliary carry depends on its operands. Returned A
is data even though the zero flag is set.

All four opaque algorithms are removed. +7BBF changes STRUCTURED→UNDERSTOOD
and **stable/complete/partial→stable/complete/complete** at its explicit
nonaliasing scratch/table/stack scope. Input producers, wider alias relationships
and source meanings remain general provenance questions rather than local
algorithm blockers. No capacity or global table disjointness is asserted.

+7C1B's mapped0A arm now returns this established counter and publishes it to
the auxiliary mapped slot. Its default cached-auxiliary return, ordered children,
and mapped17 child-result publication remain distinct. There are still seven
recursive children; no recursion ownership or global termination theorem is
inferred. +7C1B retains 203 UNDERSTOOD bytes and
**provisional/partial/partial** completeness because its RAW alternatives and
recursive/skip preconditions remain unresolved.

## Cluster B and +7D53

+7ABF saves C atAE3B, reads `j=byte[AA1F+C]`, then returns `byte[AD9D+j]`.
BC=j, HL=AD9D+j, DE/NZPA preserved, CY=0 from address addition. Returned A does
not recompute flags. This is a **second auxiliary byte table**, distinct from
primary auxiliary AD08, mapped bytes AAB4, mapped words AB49 and packed
attributes1B4B. Only scratchAE3B is written at declared nonaliasing scope.

+7E46 ignores incoming C as a position argument: it freshly reads cursorAE4F
(and neighboring cacheAE50), passes the low cursor byte to +7A79, and publishes
the returned word low/high atAE52/53 **before** passing its low byte as C to
resident +0EF6. Return registers/flags are the emitter's state, not an independent
word result. Own nonstack writes are only AE52/53; mapping scratch and emitter
buffer/index/scratch effects remain separate callee channels.

+7E56 freshly reads both cached word bytes atAE52/53 even though the low byte
is unused, passes high byte H as C to +0EF6, and returns emitter state. It does
not reuse the earlier +7E46 register result or write the word cache itself.
Both wrappers have stable bounds/complete local CFG but **partial contracts**
through the existing +0EF6 success/error/flush scope. The emitter was not
reopened, and observed state preservation is not made a universal helper claim.

+7D53 now has a coherent scoped operation without direct opaque helper
placeholders:

- Empty/gate returns precede work. The seven work paths reverse-scan a wrapping
  cursor, call partial +7C1B, then the independent +7B7A attribute-balance scan,
  and predecrement the returned stopping cursor again in the outer loop.
- Forward traversal maps current position and emits its mapped byte. Fresh cache
  feeds +7B64's packed attribute bits3..5; observed attributes are 2/3/4.
- Attribute2 publishes a selected mapped word atAE52/53 and emits low byte then
  freshly read high byte through +7E46/+7E56. Attribute3 emits the second
  auxiliary byte atAD9D+j, then primary auxiliary atAD08+j. Attribute4 emits
  primary auxiliary only. Unobserved attribute alternatives remain excluded.
- +7BA2 writes **previous AE33** to the mapped-byte slot, then separately
  replaces AE33 with a freshly read position-map index. Cursor increments and
  loop/end predicates retain their exact original polarity.
- Work completion publishes `endAE35=fresh beginAE34`; the word cache, byte
  caches, auxiliary reverse writes, mapped recycling and emission are separate.

The sixteen forward iterations have five emission channels:

| Channel | Calls |
|---|---:|
| Mapped byte | 16 |
| Primary auxiliary byte | 9 |
| Second auxiliary byte | 1 |
| Mapped word low byte | 7 |
| Fresh mapped word high byte | 7 |
| Total | 40 |

Twenty-six are parent-direct +0EF6 calls, fourteen are calls inside the wrappers.
They must not be mistaken for forty parent-local CALL instructions. Helper return
A/flags and actual emitted C bytes are checked separately; correlated member
chronologies remain in [regions.json](regions.json) and the ignored packet.

No selected Cluster B helper directly writes the position map, mapped-byte table,
primary auxiliary table or cursor. +7ABF writes its position scratch; +7E46 writes
the word cache; +7E56 only reads it. Emitter effects remain scoped. +7BBF/+7C1B
auxiliary publications can affect later +7AA9 reads, as already demonstrated in
pass6; +7BA2's mapped-table mutation is a different channel. Possible wider table/
scratch overlaps remain alias questions rather than source-language array claims.

+7D53 changes its 237 represented bytes STRUCTURED→UNDERSTOOD **at partial scope**.
Bounds/CFG/contract stay **provisional/partial/partial**: six RAW bytes,
recursive +7C1B paths, +0EF6 error/flush scope, shortcuts, mapped>=F7, unobserved
attribute alternatives and cursor wrap still prevent completeness.

## Durable roles

New roles retain numeric addresses and image identity:

- `mapped_word_position@AE38`: saved position for the word lookup.
- `mapped_word_table@AB49`: selected little-endian words; capacity unknown.
- `second_auxiliary_position@AE3B`: saved position for the second byte lookup.
- `second_auxiliary_byte_table@AD9D`: second mapped auxiliary byte source; capacity unknown.
- `mapped_emit_word@AE52` (two bytes): cache published before low-byte emission and freshly read for high-byte emission.

Existing `packed_loop_counter@AE4C` now records `16-total_shifts`, and
`packed_loop_word@AE4D` records the loaded then shifted word. Position map,
mapped byte/word tables, primary/second auxiliary tables, packed attributes,
cursor/byte caches and emission buffers remain separate scoped roles. No
source-language type, global ownership or full-array disjointness is inferred.

## Polarity / representation audit

The new helpers have no internal conditional branches. Their relevant flags
are explicit: word lookup / byte lookup preserve NZPA and clear CY through
address addition; word ANDs set flags from high-byte ANA; word addition sets
flags from high-byte ADC, with full-word overflow only in CY; emission wrappers
inherit emitter flags. None is interpreted as a Boolean helper by its returned
A or coincident observed flag value.

+7BBF's nontrivial +7C02 producer chain is:

```text
0 SUB counter -> SBB A -> FF/00(counter != 0) -> PUSH PSW
new_top - old_top -> ORA L -> SUI 1 -> SBB A -> FF/00(word difference == 0)
POP B -> MOV C,B -> ANA C -> RAR -> CY -> JNC
```

Final CY is original combined A.bit0. **JNC is taken iff counter==0 OR top bit
changed**; true combined FF produces CY=1 and repeats. Counts are 3 taken /33
fallthrough, correlated with the three actual members. The word subtraction's
carry is replaced by logical/arithmetic operations; it is not the branch test.
V0.1 exposes NOT(AND), transformations and outcomes. Its saved-counter ancestry
still ends at a stack-byte leaf across the callee preservation presentation;
exact saved-byte/pure-helper scope is audited locally. No parser/SSA expansion
or equal-value-based preservation was introduced.

Parent +7C1B/+7D53 polarity summaries retain the same equality, bit tests,
unsigned comparisons and byte-wrap conditions already reviewed. Their supported
V0.1 chains and all concrete outcomes are rechecked; new data-helper results are
substituted before existing CPI predicates, not renamed into semantic Booleans.

## Secondary large-context structural reconnaissance

Only after both clusters were established, corrected witnesses were selected
at the two actual CALL entries. Their **outer** hardware returns preserve the
original slots; the ordinary extractor fails on nested software returns.
Task-local structural audits prove original CALL slot→POP D, unchanged DE
through the observed BC/H operations, PUSH D of the copied word to a relocated
slot, and the corrected software RET consuming those bytes. A same-valued word
alone is not accepted as a continuation link. No packet/profile code changed.

| Anchor | Caller / calls | Provisional envelope | Own coordinates / occurrences / bytes | Classification |
|---|---|---|---|---|
| PLI1+28AA | +2C55 / 1 | `[28AA,2C53)` | 351 / 351 / 684 | STRUCTURE ONLY |
| PLI1+4B69 | +0108 / 1 | `[4B69,4BD5)` | 52 / 2,088 / 105 | STRUCTURE ONLY |

+28AA has nineteen direct CALL occurrences at nineteen sites, seventeen local
jump sites, and no repeated own instruction on its witnessed path. Two calls to
+6708, at +2985/+2AB4, consume four caller words each; their copied continuation
moves eight bytes above the original hardware slot. Other immediate callees are
listed numerically in [large-structural.json](large-structural.json), including
known +7B7A/+7B2E/+7AD5 and still-unreviewed operations. The outer RET is+2C52.
Its inclusive subtree has10,107 occurrences; that is not its own footprint.

+4B69 has two local CALL sites: complete resident +1A2C and still-opaque +43D5.
There are three local jump sites; the +4B99 guard repeats128 times then exits,
with 128 backedges. +4BBA's +43D5 call consumes one caller word, moving its copied
continuation two bytes above the original slot. The outer RET is+4BD4; inclusive
subtree 2,289 occurrences. Neither parent reserves a local frame on observed
paths; SP movement consists of transient saves/caller-word pushes/CALLs/returns.
There are no observed alternate external entries, escaping local jump targets,
shared tails or direct recursion inside the candidate envelopes.

All facts and compact continuation/hardware samples are in the structural report.
The documentary hypotheses remain **provisional/partial/partial**. They are not
cataloged, semantically decompiled or promoted: their bytes remain RAW. The
bounded packet profile rejects software argument-consuming nested returns,
regardless of whether an entry/frame seed exists; this is not a seed-mode issue.
Future packet use needs a justified bounded continuation join after the relevant
callee conventions/contracts are reviewed.

The old exploratory RAW-context counts 4,315/2,171 therefore do not describe
exclusive procedure cost. Corrected own footprints are 351/2,088; together 2,439
occurrences, about 14.47% of remaining PLI1 RAW execution. They do not establish
that large procedure bodies dominate that remaining surface. In particular,
+28AA's earlier apparent weight largely lay in delegated/continuation contexts.

## Remaining gaps and Pass-8 choice

- +7BBF: **alias/precondition** and **general provenance** outside its complete
  local scope; counter-zero exit is an **unobserved outcome** over already
  represented instructions, not missing local code or a fixture blocker.
- +7C1B: **unobserved paths** mapped1E/21 and17/non0A predecessor; **termination
  concern** recursion / wrapping skip scans; **alias/precondition** and table
  **unknown producer/general provenance**. No selected packed helper remains opaque.
- +7D53 / +7E46 / +7E56: **partial helper contract** +0EF6 and recursive +7C1B,
  **unobserved paths** shortcuts/high mapped/attribute alternatives/cursor wrap;
  six RAW bytes remain. No broad emitter reanalysis was necessary.
- Packet: **unsupported dependency / preservation presentation** for some word
  operations and saved-stack ancestry; paired states and scopes remain usable,
  so local audits suffice and infrastructure stays unchanged.
- Large anchors: **unusual stack/continuation** and **missing helpers** +6708/
  +43D5 first; other +28AA callees are unreviewed. RAW alternatives and general
  producer/alias information also remain. No new fixture is yet the simpler route.

Recommendation **B: another reusable-helper / continuation pass**, prioritizing
+6708 and +43D5, then revisiting +4B69 and +28AA. Their concrete stack-consumption
conventions must be integrated before forcing these larger bodies through the
ordinary packet profile. +4B69 remains a substantial own-loop target, but the
corrected +28AA footprint does not support the earlier dynamic-cost assumption.
No global dominance/ownership claim is inferred from context rankings. Matched
microfixtures and FIZZBUZ-minus-MINIMAL remain premature for these blockers.

## Progress, exactness and validation

| Executed bytes | Before | After | Delta |
|---|---:|---:|---:|
| RAW | 16,135 | 16,035 | -100 |
| DECODED | 304 | 304 | 0 |
| STRUCTURED | 1,852 | 1,523 | -329 |
| UNDERSTOOD | 2,721 | 3,150 | +429 |

RAW→UNDERSTOOD100; STRUCTURED→UNDERSTOOD329; RAW→STRUCTURED0. No newly fetched
byte or unexecuted RAW byte is promoted. Whole-image totals are 89,702 RAW /
304 DECODED /1,554 STRUCTURED /3,160 UNDERSTOOD, totaling 94,720. Only PLI1 source
annotations/statuses change. All prior labels survive; two operand-interior
numeric-only EQUs retain +7AC0/+7AD0 coordinates without asserting entries.

| CALL entry status | Before | After |
|---|---:|---:|
| UNDERSTOOD | 63 | 72 |
| STRUCTURED | 12 | 10 |
| DECODED | 3 | 3 |
| RAW | 313 | 306 |

Classification unresolved316→309 includes the three DECODED entries. The391
CALL/RST targets and eleven separate PCHL entries remain unchanged.

| Dynamic image | Occurrences | RAW after | STRUCTURED after | UNDERSTOOD after | UNDERSTOOD before→after |
|---|---:|---:|---:|---:|---:|
| PLI.COM | 266,524 | 33,267 | 43,210 | 127,559 | 47.8602%→47.8602% |
| PLI0.OVL | 94,418 | 44,567 | 11,322 | 38,529 | 40.8068%→40.8068% |
| PLI1.OVL | 42,875 | 16,856 | 510 | 25,509 | 50.5819%→59.4962% |
| PLI2.OVL | 36,181 | 23,127 | 3,649 | 8,103 | 22.3957%→22.3957% |
| Total | 439,998 | 117,817 | 58,691 | 199,700 | 44.5179%→45.3866% |

DECODED occurrences remain 63,790. Independent own-coordinate promotions sum
1,418 RAW→UNDERSTOOD plus2,404 STRUCTURED→UNDERSTOOD occurrences. Full run441,855
includes 1,857 modeled instructions outside historical images, giving 45.195822%
UNDERSTOOD on that denominator. PLI1 RAW is 39.3143% of its historical occurrences.
[before.json](before.json), [progress.json](progress.json),
[dynamic-progress.json](dynamic-progress.json) and [regions.json](regions.json)
retain immutable pass snapshots and full correlated member summaries. Live root
artifacts follow current annotation statuses. Old pass5/pass6 assertions retain
historical statuses through their snapshots/transition ledgers while independently
checking live dynamic consistency; they do not freeze callers against later work.

```sh
python3 tools/annotated-assembly/check_minimal_pass_7.py \
  --images /path/to/DISK1 --output _build/minimal-pass-7/checked.json
python3 tools/annotated-assembly/test_minimal_pass_7.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_procedure_evidence_packet.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_baseline.py --images /path/to/DISK1 -v
# Run test_minimal_pass_1.py through test_minimal_pass_6.py with --images.
python3 tools/annotated-assembly/test_decompilation_annotations.py -v
python3 tools/annotated-assembly/test_verify.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1 --write-progress
python3 tools/annotated-assembly/minimal_dynamic_progress.py
python3 tools/annotated-assembly/decompilation_annotations.py
dune runtest --force
git diff --check
```

Eight new tests cover 188 correlated calls, exact word load/AND/add behavior and
high-byte flags, same-pointer doubling versus equal-valued distinct pointers,
loop polarity and indirect publications, all 65,536-word stopping arithmetic,
five separate emission channels, partial scopes, software-copy ancestry samples
and live progress. Corrupted carry/publication/continuation source facts are
rejected. Project tests (976,272 ALU cases), all packet/MINIMAL pass tests, V1,
historical-byte verification and dynamic consistency passed. All 94,720 bytes
round-trip exactly. V0.1 remains useful on the ordinary bounded parents; this
pass does not establish improved independent decompilation stability.
Task scratch and generated packets stay ignored under project `_build`; no task
/tmp directories remain, and unrelated untracked files are untouched.
