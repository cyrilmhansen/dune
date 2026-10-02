# MINIMAL decompilation pass 6

Task `MINIMAL_DECOMPILATION_PASS_6`; baseline `adfe3db`. This pass resolves
selected low-level helper operations blocking +784E and +7D53. No compiler run,
FIZZBUZ work, new fixture, packet infrastructure change or broad static sweep
was made. Exact images and corrected original-slot hardware returns remain the
structural authority.

## Structural reconnaissance and classification

Actual CALL entries were selected before interpretation. Corrected returns
separate each invocation's own instructions from descendants, including recursive
children. All 863 selected invocations have original-slot ordinary hardware
returns; all 480 own coordinates / 18,313 occurrences agree with existing
MINIMAL observations. No dynamic-context or RoutineCandidate extent supplied a
procedure boundary. [structural.json](structural.json) retains callers, returns,
branches, direct callees, SP deltas and exact candidate envelopes.

| Primary entry | Candidate extent, exclusive end | Calls / caller sites | Coordinates / occurrences | Classification |
|---|---|---:|---:|---|
| PLI.COM+1376 | `[1376,15DA)` | 38 / 2 | 142 / 6,622 | PACKET CANDIDATE |
| PLI1+7C1B | `[7C1B,7D53)` | 16 / 3 (including recursion) | 121 / 999 | PACKET CANDIDATE |
| PLI1+7B7A | `[7B7A,7BA2)` | 21 / 4 | 20 / 679 | PACKET CANDIDATE |
| PLI1+7B64 | `[7B64,7B7A)` | 16 / 1 | 13 / 208 | SMALL / DIRECT |
| PLI1+7BA2 | `[7BA2,7BBF)` | 16 / 1 | 14 / 224 | SMALL / DIRECT |

There are no observed alternate external CALL/JMP entries or shared tails in
these envelopes. +7C1B has nine external invocations plus seven children at its
two internal recursive callsites. Its five-byte frame is supported by two PUSH H,
MOV B,C/PUSH B/INX SP and matching releases. The other targets reserve no locals;
temporary saves and CALL words are below entry SP. No target remained STRUCTURE
ONLY, but RAW alternatives keep the complex envelopes provisional.

Immediate helpers were followed only to explain the selected operations:

| Entry | Why followed | Represented / envelope bytes | Status; bounds / CFG / contract |
|---|---|---:|---|
| PLI.COM+0817 | +1376 / +12D9 numeric byte transform | 23 / 23 | UNDERSTOOD; stable / complete / complete |
| PLI.COM+12D9 | +1376 reader adapter | 8 / 8 | UNDERSTOOD; stable / complete / partial |
| PLI.COM+15DA | +1376 / +15F9 byte interval predicate | 9 / 9 | UNDERSTOOD; stable / complete / complete |
| PLI.COM+15E3 | +1376 / +15F9 range/equality predicate | 22 / 22 | UNDERSTOOD; stable / complete / complete |
| PLI.COM+15F9 | +1376 continuation predicate | 26 / 29 | UNDERSTOOD; provisional / partial / partial |
| PLI.COM+1627 | +1376 prefix/count/accumulator writes | 42 / 71 | UNDERSTOOD; provisional / partial / partial |
| PLI1+7A63 | +7C1B / +7B7A low3 attribute reader | 22 / 22 | UNDERSTOOD; stable / complete / complete |
| PLI1+7AA9 | +7C1B cached auxiliary value | 22 / 22 | UNDERSTOOD; stable / complete / complete |
| PLI1+7AD5 | +7BA2 mapped-table writer | 27 / 27 | UNDERSTOOD; stable / complete / complete |
| PLI1+7B2E | +7C1B / +7BBF auxiliary writer | 27 / 27 | UNDERSTOOD; stable / complete / complete |
| PLI1+7BBF | +7C1B mapped0A operation | 92 / 92 | STRUCTURED; stable / complete / partial |

+7BBF is an additional PACKET CANDIDATE; the other immediate helpers are
SMALL / DIRECT. Its own graph is fully represented, but opaque packed-word
callees still prevent a complete algorithm. +1376 (328/612) and +7C1B (203/312)
are UNDERSTOOD only at explicitly partial scopes. The three other primary
helpers have stable/complete/complete contracts at their declared alias and
termination preconditions. UNDERSTOOD does not complete the enclosing RAW paths.

Minimal structural V1 seeds preceded semantic interpretation. Four packets were
generated under ignored `_build/minimal-pass-6/packets`, with `--frame-bytes 0
--class-slots` except +7C1B (`--frame-bytes 5 --class-slots 0 3`). Markdown was read
before selected JSON state/access queries. Complex semantic work used those
joined packets and exact instructions, rather than broad witness/context mining.
The final packets were regenerated with the new accumulated knowledge.

| Packet | Invocations / classes / blocks | JSON bytes | Markdown bytes |
|---|---:|---:|---:|
| PLI.COM+1376 | 38 / 35 / 46 | 12,368,350 | 47,132 |
| PLI1.OVL+7C1B | 16 / 12 / 19 | 2,075,276 | 20,073 |
| PLI1.OVL+7B7A | 21 / 15 / 5 | 1,111,849 | 9,515 |
| PLI1.OVL+7BBF | 3 / 3 / 10 | 1,831,834 | 11,463 |

First-written discriminator F+3 in +7C1B includes the inherited low byte pushed
by the prologue before the mapped-byte assignment. It is not an entry snapshot
or a semantic mapped-byte class. Full correlated members remain authoritative.

## +1376: prefix acquisition and retained following byte

At all 38 observed entries, EOF[2012].bit0 and reuse[20C4].bit0 are clear.
Clear 2088/2087, modulo16 accumulator[1C58], width[20C5] and selector[20C3].
While selector is zero, context[20C1] equal00 or20 causes +12D9 to read and
replace context. That adapter calls the existing partial counted reader +12AE,
then +0817: save C at 208F and return `C>5F ? C&5F : C`.

Otherwise +15E3 tests context41..5A or3F using true bytes01/FF. Set bit0 selects
selector1. +15DA returnsFF for context30..39; its true dispatch arm is RAW.
Observed false then selects5 for context27 (clearing context), or0A otherwise.
No lexical or source-language names are assigned to these numeric cases.

In the acquisition loop, nonzero context is appended **before** reading another
byte: partial +1627 writes `20C6+width`, increments width and updates
`(old_accumulator+context)&0F`. Its width>127 overflow arm remains RAW. Save old
context at 20C2, read through +12AE into20C1, and apply +0817 unless selector5.
The emitted prefix and the retained following context are separate publications.

- Selector1 repeats while +15F9's returned A.bit0 is set. Clear bit selects a
  word at `1C38+2*accumulator`, copies it to1C59, subtracts0 through existing
  complete +1A40, and tests full-word zero with ORA L/JZ. All18 selected words
  are zero, returning A=0/HL=0 while selector remains1.
- Selector0A's saved previous-byte2E AND new-byte30..39 predicate is false on
  all 18 paths. It returns after one appended byte, A=0A and flags from CPI05.
- Selector5 skips the conditional mask during accumulation. Seven prefix bytes
  are appended; context27 causes one additional masked read via +12D9. The
  observed extra byte is neither42 nor27, and returns as A from +15AB. Other
  1A/5E/42/27 alternatives remain RAW.

The two ordered 19-call streams, from PLI0+42D4 and PLI1+784E, produce identical
correlated `(entry context, selector, width, prefix, following context, returned
A)` tuples despite differing incoming registers. Each has 9 selector1,9 selector0A,
and1 selector5. There are 128 appends,130 direct reader calls and28 adapter reads,
including two extra reads. Prefix widths are 1..9; no whole buffer capacity/type
is inferred. Acquisition inputs are durable reader/context state, not incoming C.
Incoming registers can still influence preserved/delegated return state.

There is no direct BDOS call. Eight recorded reader refills occur in these
subtrees (six under +12D9, two under direct +12AE). Existing partial +0D40
buffer-building contracts explain those guest operations. The packet does not
join host effects: a narrow supplemental query selected only indexed host/file
events in packet invocation spans, with no indexed file events or selected host
events found. [host-effects.json](host-effects.json) records that limited finding;
it is not a general no-host-effects contract or a new provenance engine.

New resident roles name context/previous/selector/reuse/count/prefix, modulo16
accumulator, sixteen selected word slots, selected word, reset word and mask
scratch, retaining addresses and image identity. Existing PLI1 prefix/context
roles now reference their scoped resident producer.

+784E's prelude, contract, local block and comments substitute this acquisition.
Its triple guard, pattern scan, result channels and RAW alternatives remain
unchanged. Completeness stays provisional/partial/partial; no caller bytes are
promoted by this substitution.

## Mapped helpers and +7D53

The following operations share concrete address equations, without asserting
full table capacities or disjoint source-language arrays:

```text
j = byte[AA1F + unsigned(position)]
mapped = byte[AAB4 + j]                 // existing +7A4D
auxiliary = byte[AD08 + j]              // newly complete +7AA9
low_attribute = byte[1B4B + mapped] & 7 // newly complete +7A63
high_attribute = (byte[1B4B + C] >> 3) & 7 // +7B64, C is mapped byte
```

+7B64 writes scratchAE47=C and only reads the packed attribute byte. ANI FC,
three RAR and ANI07 implement bits 3..5 extraction exactly: the first two outgoing
carry bits are zero, so the third RAR has incomingCY=0. Final CY=0/NZPA describe
ANI07. DE is preserved; BC=1B4B and HL=1B4B+C. This is deterministic given input C
and the consulted byte, with a scratch side effect rather than a pure operation.

+7B7A independently sets cursorAE48=C and balanceAE49=1. Each iteration reads
low3 mapped attributes via +7A63, sets `balance=u8(balance+attribute-1)` and
exits precisely at zero; otherwise cursor decrements with wrap. Return A is the
stopping cursor, BC=0, HL=AE49, DE preserved, flags from CMP0,0. Twenty-one
invocations perform44 attribute reads and23 cursor decrements. No arbitrary
termination theorem follows: wrapping cursors/balances can revisit positions.

+7C1B's frame is:

| Slot | Demonstrated assignment/use |
|---|---|
| F+0 | input position, later default decrement/skip cursor |
| F+1 | low3 attribute countdown on default path |
| F+2 | recursive returned A; publication source on mapped17, unused default return |
| F+3 | mapped byte, overwriting inherited pushed L |
| F+4 | initially inherited H; default initial auxiliary byte cached across children |

Mapped0A calls partial +7BBF and returns its A. Mapped17, when preceding mapped
byte is0A (two observations), recurses once at `u8(original_position-1)`, writes
child A via +7B2E to `AD08+position_map[original_position]`, and returns saved
child A. The original position is retained on this arm.

On eleven default calls, cache auxiliary byte inF+4 and low3 attribute count in
F+1. While count is positive: decrementF+0, recurse at that position, save childA
inF+2, run +7B7A at the same decremented position, replaceF+0 with its stopping
cursor, decrementF+1. Default child count equals the initial attribute count at
nonaliasing frame scope; there are five such calls, plus two mapped17 children.
One invocation's ordered children receive positions2 then1 and return10 then1,
while the parent returns cached auxiliary0. No tree ownership is inferred.
Final POP H combines F+3/F+4 into HL; entry HL is not preserved. Default flags
come from final CMP0,0; frame DAD leaves CY0. Other return flags inherit helper
scope. Mapped1E/21 and mapped17/predecessor-not0A paths remain RAW.

+7BBF records three loops with counters 15 initialized, ending 1/10/1 after15/6/15
comparisons. Its saved nonzero-counter mask and word-equality mask control
repetition. Opaque +7A79/+82E1/+82BB/+82C9 produce/manipulate words; +1A2C supplies
the known subtraction; indirect low/high writes and final auxiliary publication
are explicit. Recorded saved-byte survival is not promoted into those helpers'
general preservation contracts. This remains partial STRUCTURED orchestration.

+7AD5 saves C/E atAE3C/3D and unconditionally writes E to `AAB4+position_map[C]`.
+7B2E similarly saves C/E atAE43/44 and writes `AD08+position_map[C]`. Both preserve
DE/NZPA and return A=E, BC=map index, HL=destination, CY0 at nonaliasing scope.
The mapped writer's destination must not alias accessed position-map bytes;
table roles imply no whole-array disjointness.

+7BA2 saves position atAE4A, reads wordAE33 (D also receives neighboring begin
byteAE34), and passes E=**previous AE33** to +7AD5. After that publication it
**rereads** `AA1F+saved_position` and writes the returned index intoAE33. Return
A is this fresh map byte; BC=AA1F, HL=map address, DE=previous wordAE33;
NZPA preserved/CY0. All16 writes are unconditional, at selected slotsAAB4..AABA
in this capture. Old value and new cached index sometimes differ, so the two
channels cannot be merged. AE33's initializer-counter role is refined to retain
its later cached-index/publication role; no allocation meaning is assigned.

+7D53 substitutes all these operations, including +7AA9 followed incidentally to
recover +7C1B. Its reverse scan now distinguishes partial recursive processing,
independent balance scan, and the outer subsequent predecrement. Its forward
branch data comes from packed bits 3..5. Secondary emission comes from the
auxiliary table. [table-flow.json](table-flow.json) records two same-address
auxiliary write→read links inside parent invocation251128: +7B2E writesAD0C/AD08
before later +7AA9 reads. +7BA2's mapped-table writes are a separate channel that
can affect later mapping; no unrecorded cross-invocation producer is invented.
The parent remains STRUCTURED and provisional/partial/partial because
+7ABF/+7E46/+7E56, partial recursive/packed operations and RAW alternatives remain.

## Polarity and completeness audit

| Branch | Producer / tested flag | Branch taken iff; observed taken / fallthrough |
|---|---|---|
| COM+1382 / +1395 | load byte→RAR; CY=original bit0 | EOF / reuse bit0 clear;38/0 each |
| COM+13C2 | equality00/20 FF/00 masks→PSW/POP/register copy→OR→RAR; CY | context neither00 nor20;38/26 |
| COM+13D2 / +13E1 | helper returned A→RAR; CY | helper A.bit0 clear;20/18 and20/0 |
| COM+144A | previous==2E mask saved across partial helper, AND returned range mask→RAR; CY | restored original predicates not both true;18/0; saved-mask ancestry stops conservatively in packet |
| COM+145F | +15F9.A→CMA→RAR; CY=original inverted bit0 | ORIGINAL returned A.bit0 set;78/18; returned helper CY is not tested |
| COM+147C | +1A40.A=high word; ORA L; Z | full selected word zero;18/0 |
| COM+0821 | CMP5F,savedC; CY unsigned borrow | unsigned inputC<=5F;46/100 |
| COM+15EA | wrapped(context-41) CMP1A; CY | wrapped difference>=1A;38/96 |
| COM+15FD / +1607 | helper returned A→RAR; CY | returned bit0 clear;18/78 and18/0 |
| COM+162D | CMP7F,width; CY | width>127;0/128; overflow path RAW |
| PLI1+7C2F | mappedA CPI0A; Z | mapped byte!=0A;13/3 |
| PLI1+7C53 | equality1E/21 FF/00 masks→PSW/POP/copy→OR→RAR; CY | neither equality true;13/0 |
| PLI1+7CBE / +7CCD | CPI17 / preceding mappedA CPI0A; Z | mapped!=17 (11/2) / preceding mapped==0A (2/0) |
| PLI1+7D22 | CMP0,F1; CY | count==0;11/5 |
| PLI1+7B94 | ADD attribute+balance→DCR→C; CMP0,C; CY | updated balance==0;21/23; ADD carry replaced by CMP |
| PLI1+7C02 | word subtraction→ORA L→SUI1→SBB A, AND restored mask→RAR; CY | saved mask.bit0 clear OR word difference nonzero;3/33; opaque saved-mask preservation observed only |

Remaining CPI/JZ/JNZ branches in +1376 test equality/inequality of the explicitly
loaded selector/context bytes. Block comments and the packet retain exact
coordinates, outcomes and operational conditions. Predicate audits use supported
V0.1 dependency chains; opaque-call saved-byte gaps are checked locally from
concrete accesses, not converted into helper preservation contracts. No ADI
ancestry limitation required infrastructure changes in this pass.

The three RAW bytes +160A..+160C inside +15F9 statically encode MVI A,01 / RET.
Their description is explicitly **STATIC / UNOBSERVED**; they are not promoted
and do not complete the dynamic contract. No other new RAW decoding was required.

## Evidence gaps and next strategy

- +1376: **partial helper scope** +12AE/+0D40 refill and +1627 overflow; **unobserved
  branches** EOF/reuse, selectors2/3/4, nonzero word probe, special selector5
  alternatives; **general provenance need** earlier reader/context/table producers.
- +7C1B: **missing helper algorithms** inside partial +7BBF; **unobserved branches**
  mapped1E/21 and17/non0A predecessor; **missing alias/precondition** for arbitrary
  frames/table state; **arbitrary termination concern** recursive/wrapping scans.
- +7B7A: local operation complete at scope; **arbitrary termination concern**
  wrapping balance/cursor; **general provenance need** packed attribute producers.
- +7B64: operation complete at scope; **general provenance need** attribute-table
  contents/producers and broader capacity. Its scratch write is established.
- +7BA2/+7AD5: operation complete at nonaliasing scope; **missing alias/precondition**
  outside it; **general provenance need** initial AE33 and position-map producers.
- +7BBF: **missing helper algorithms** +7A79/+82E1/+82BB/+82C9, **partial helper
  scope** observed saved stack words; resolve these before considering fixtures.
- +7D53: **missing helper algorithms** +7ABF/+7E46/+7E56, inherited partial +7C1B,
  **partial helper scope** emitter error/flush, **unobserved branches** shortcuts,
  high mapped/attribute dispatch and cursor wrap. No unusual continuation blocker
  was found. No question yet warrants a new discriminating fixture.

Recommendation **A: another MINIMAL helper pass**, beginning with remaining
+7D53 and packed-word helpers, followed by structural reconnaissance of remaining
larger PLI1 anchors. The remaining PLI1 RAW surface is18,274/42,875 occurrences
(42.62%). It is **not dominated by the small selected helper set alone**: existing
inventory context-coordinate navigation ranks larger +28AA/+4B69 contexts ahead
of these remaining helpers (4,315/2,171 RAW occurrences on their listed coordinate
sets). These navigation counts are not procedure ownership/bounds/contracts.
Reusable helpers still offer cross-procedure leverage, but context rankings do
not justify claiming that a few helper contracts will close all PLI1 gaps.
Microfixtures and FIZZBUZ-minus-MINIMAL remain premature for this pass's blockers.

## Progress and historical exactness

| Executed byte status | Before | After | Delta |
|---|---:|---:|---:|
| RAW | 17,077 | 16,135 | -942 |
| DECODED | 304 | 304 | 0 |
| STRUCTURED | 1,760 | 1,852 | +92 |
| UNDERSTOOD | 1,871 | 2,721 | +850 |

All942 promoted bytes were already dynamically fetched: RAW→UNDERSTOOD850 and
RAW→STRUCTURED92. No unexecuted RAW byte is promoted. Whole-image totals are
89,802 RAW /304 DECODED /1,883 STRUCTURED /2,731 UNDERSTOOD, sum 94,720.
All prior numeric labels and image hashes remain exact; new operand-interior
coordinate-only labels assert no additional entry.

| CALL entries | Before | After |
|---|---:|---:|
| UNDERSTOOD | 48 | 63 |
| STRUCTURED | 11 | 12 |
| DECODED | 3 | 3 |
| RAW | 329 | 313 |

The391 callable coordinates and eleven separate PCHL entries are unchanged.
Classification unresolved332→316 includes the three DECODED entries.

| Dynamic image | Total | RAW after | STRUCTURED after | UNDERSTOOD after | UNDERSTOOD before→after |
|---|---:|---:|---:|---:|---:|
| PLI.COM | 266,524 | 33,267 | 43,210 | 127,559 | 43.0832%→47.8602% |
| PLI0.OVL | 94,418 | 44,567 | 11,322 | 38,529 | 40.8068%→40.8068% |
| PLI1.OVL | 42,875 | 18,274 | 2,914 | 21,687 | 40.5038%→50.5819% |
| PLI2.OVL | 36,181 | 23,127 | 3,649 | 8,103 | 22.3957%→22.3957% |
| Total | 439,998 | 119,235 | 61,095 | 195,878 | 40.6422%→44.5179% |

DECODED occurrences remain 63,790. Parent-local promotions independently sum
17,053 UNDERSTOOD plus1,260 STRUCTURED occurrences. Full run441,855 includes 1,857
modeled instructions outside historical images; its UNDERSTOOD percentage is
44.330833%. [before.json](before.json), [progress.json](progress.json),
[dynamic-progress.json](dynamic-progress.json) and [regions.json](regions.json)
retain pass snapshots and correlated checked members. Live parent artifacts follow
current annotations; older pass5 dynamic assertions use its historical snapshot
while independently checking current consistency.

## Packet assessment and validation

V0.1 remained usable without extension. +1376's complement/rotation branch,
+7C1B's saved equality OR and countdown, and +7B7A's final CMP balance test were
available mechanically. Recursive child order, five-byte frame accesses and
helper output boundaries stayed correlated. Exact table address equations,
packed-bit transform, alias scope and conditional termination still require
local reasoning. Opaque +7BBF calls conservatively stop saved-mask/word ancestry;
concrete stack survival was audited without inventing a general contract.
Host effects remain outside the packet; a narrowly selected supplementary query
was documented. No seed mode or infrastructure change is justified by this pass.
Selective packets should precede future difficult compatible MINIMAL targets;
small straight-line helpers still benefit from direct checks. This run does not
establish improved independent decompilation stability.

```sh
python3 tools/annotated-assembly/check_minimal_pass_6.py \
  --images /path/to/DISK1 --output _build/minimal-pass-6/checked.json
python3 tools/annotated-assembly/test_minimal_pass_6.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_procedure_evidence_packet.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_baseline.py --images /path/to/DISK1 -v
# Run each test_minimal_pass_1.py through test_minimal_pass_5.py with --images.
python3 tools/annotated-assembly/test_decompilation_annotations.py -v
python3 tools/annotated-assembly/test_verify.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1 --write-progress
python3 tools/annotated-assembly/minimal_dynamic_progress.py
python3 tools/annotated-assembly/decompilation_annotations.py
dune runtest --force
git diff --check
```

Eight new tests exercise863 concrete invocations, the two correlated acquisition
streams, supported dependency polarities, recursive order/count/results, exhaustive
packed-bit arithmetic, distinct old-slot/new-cache channels, observed auxiliary
write→read links, partial scopes and progress. Corrupted transform/publication
values are rejected. All project (including976,272 ALU cases), existing packet,
baseline/pass, V1 and verifier checks passed; all 94,720 historical bytes round-trip
exactly. Packet JSON/Markdown and scratch queries remain ignored under project
`_build`, not committed. Unrelated untracked files are untouched; no task-created
/tmp directories remain.
