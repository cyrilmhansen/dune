# MINIMAL decompilation pass 5

Task `MINIMAL_DECOMPILATION_PASS_5`; baseline `6983d77`. No new compiler capture,
FIZZBUZ work, seed-packet mode or generic decompiler was introduced. Exact image
bytes and corrected hardware-return witnesses are the structural authority.

## Structural reconnaissance and selective packet use

Each target was first selected by its actual CALL coordinate. Corrected return
events isolate its own instructions from descendants; every original hardware
slot, return target and SP relationship was checked. All five have zero-byte
reserved local frames. PUSH/POP saves and nested CALL words use space below entry
SP. None recurses or has observed software continuation behavior.

| Entry | Candidate envelope, end exclusive | Calls / sites | Own coordinates / occurrences | Classification |
|---|---|---:|---:|---|
| PLI0+1E0B | `[1E0B,1E2D)` | 87 / 7 | 21 / 1,827 | SMALL / DIRECT |
| PLI1+784E | `[784E,7A15)` | 19 / 8 | 139 / 8,437 | PACKET CANDIDATE; principal experiment |
| PLI1+4929 | `[4929,4986)` | 2 / 1 | 51 / 5,425 | PACKET CANDIDATE |
| PLI1+8273 | `[8273,82AC)` | 1 / 1 | 27 / 2,103 | SMALL / DIRECT |
| PLI1+7D53 | `[7D53,7E46)` | 21 / 4 | 99 / 1,144 | PACKET CANDIDATE |

No target remained STRUCTURE ONLY: all support a bounded ordinary-return
hypothesis. There are no other observed CALL targets or outside JMP/PCHL entries
inside the envelopes. Packet source counters independently agree with the
per-invocation coordinate counts, rather than assigning dynamic-context ownership.
Small-target boundaries follow their terminal RET and coherent entry/branch
sequence. +7D53's terminal RET precedes its separately called +7E46 helper.
+784E retains provisional bounds because its unexecuted special-handling arms
remain RAW. None of these extents was adopted from RoutineCandidate or context
min/max ownership.

[structural.json](structural.json) records callers, branches, direct callees,
return sites, SP deltas, candidate envelopes and classification. Direct callers
and matched samples are also retained in the standard image evidence seeds.

Before semantic interpretation, minimal V1 structural hypotheses and exactly
observed STRUCTURED instructions were authored. Their initial contracts explicitly
said behavior was not understood. They supplied the bounded catalog/frame inputs
required by V0.1. Packets were then generated with `--frame-bytes 0 --class-slots`.
The compact rendering was read first, followed by selected JSON state/access
queries; semantic work did not return to broad witness/canonical/context mining.
The reviewed packets were regenerated afterward with the new accumulated knowledge.

Current ignored artifacts are `_build/minimal-pass-5/packets/PLI1+ENTRY.json/.md`:

| Packet | Invocations / classes / blocks | JSON bytes | Markdown bytes |
|---|---:|---:|---:|
| +784E | 19 / 18 / 24 | 10,117,229 | 28,194 |
| +4929 | 2 / 2 / 8 | 6,989,747 | 8,344 |
| +7D53 | 21 / 12 / 33 | 2,524,278 | 32,735 |

Generated packet JSON/Markdown is not committed. The summaries in
[regions.json](regions.json) preserve individual invocation facts and paths;
they are not cross products of independent values or copies of entire traces.
All 130 invocations and 18,936 parent-local occurrences have contract checks.

## Recovered contracts and qualified understanding

| Procedure | Status of represented bytes | Represented bytes | Bounds / CFG / contract |
|---|---|---:|---|
| PLI0+1E0B | UNDERSTOOD | 34 / 34 | stable / complete / complete |
| PLI1+8273 | UNDERSTOOD | 57 / 57 | stable / complete / complete |
| PLI1+4929 | UNDERSTOOD | 93 / 93 | stable / complete / complete |
| PLI1+784E | UNDERSTOOD at declared partial scope | 268 / 455 | provisional / partial / partial |
| PLI1+7D53 | STRUCTURED, useful partial orchestration | 237 / 243 | provisional / partial / partial |
| PLI0+24BC, refined | unchanged STRUCTURED | unchanged 661 / 991 | provisional / partial / partial |

UNDERSTOOD does not imply complete enclosing procedures. +784E's opaque prelude
and RAW alternatives are explicit scope restrictions. +7D53 stays STRUCTURED
because its numerous missing helper algorithms still dominate its operation.
No PL/I-level token, keyword, node type, tree or ownership meaning was invented.

### PLI0 +1E0B and its +24BC caller

Write `byte[word[69C5]]=byte[69C7]`: the count comes from **extent_count**, not
incoming C (several observations distinguish them). Resident +1A1C computes
`next=u16(word[69C3]+unsigned(count))`. Save next on the stack, address the word
at `6A0D+2*byte[6A4C]`, publish next low/high there, then publish it low/high to
staging_cursor[69C3]. The source word is the staging cursor, not necessarily the
working base. The neighboring high byte fetched by LHLD6A4C is discarded.

Return BC=next, DE=selected table high-byte address, HL=69C4 and A=high(next).
CY=0 comes from table-address DAD B; NZPA retain the addition helper's high ADC.
The working base, count and index are unchanged under the stated nonaliasing
scope. No allocation or table-capacity meaning is inferred.

This closes one +24BC opacity: its copied working record receives the count
header, and the selected boundary/staging end are published. Local +2560
pseudocode, comments, procedure contract and limitations now substitute that
operation before still-opaque +22B3. Count/base are not assumed consumed; F+16
and result-slot publications remain separate. The previously corrected polarity
and recursion descriptions remain intact. [caller-refinements.json](caller-refinements.json)
records before/after and zero caller byte promotions.

### PLI1 +8273

Initialize exactly **149** bytes at AAB4..AB48 with values 1..149 using AE33 as a
byte counter. CMP94H/JC ends at index 95H; the index-wrap alternative cannot run
under stable nonaliasing controls. Zero AA1A/AA1B/AA1C and AE35/AE34/AE33 in the
observed order. DE is preserved; A=0, BC=AAB4, HL=AA1C, and flags still describe
94H-95H rather than returned A.

The existing mapped_byte_table role is reused without inventing its whole-table
capacity. The position map at AA1F and bytes beyond AB48 are not initialized.
New scoped roles name the initialization counter, work gate, adjacent reset
controls, and byte begin/end controls later read by +7D53.

### PLI1 +4929

Save unsigned input BC at A920; visit 128 word slots at A761+2*i. Copy each
head into A863; +1A33 computes head-limit. A borrow selects the next slot.
Otherwise follow `word[u16(old_head+8)]`, update the scratch head, **re-read the
same old_head+8/+9 bytes**, and publish that successor to the current table slot.
XCHG/DCX retains the old link address; it does not select the previous slot.
Then compare again. The two invocations visit 256 slots and perform257
comparisons, with one link replacement in the second invocation.

Return A=7F, BC=saved input limit, DE=A864, HL=A922; flags describe7F-80.
The local graph/operation is complete at nonaliasing scope, but arbitrary cyclic
or nondecreasing links need not terminate. New link_limit/link_cursor/index/head
roles assert arithmetic/storage roles, not heap or tree ownership.

### PLI1 +784E: principal packet experiment

Call opaque resident +1376 once, then operate on its resulting fields. The
first guard combines FF/00 equality masks for selector[20C3]==0A,
input_first[20C6]==2F and context[20C1]==2A. All three reads occur. V0.1 exposes
the saved-PSW/copy/AND/RAR chain: JNC skips RAW handling when the combined
predicate is false (nineteen observations).

A second mask uses SUI k / ADI FF / SBB A. Adding FF carries exactly when the
wrapped difference is nonzero; the mask therefore means **inequality**. After
AND/RAR, +78B8 JNC enters handling iff selector is 0A or 01. This was independently
checked from packet states and all 256 byte values, because V0.1 currently stops
carry ancestry through ADI. One selector 5 path instead returns A=7F/CY=1 without
publishing a new selector.

Nine selector 0A paths copy the first input byte to 20C3, fail all seven literal
comparisons21/5C/2A/2D/3C/3E/5E and return. Their flags describe final CPI5E.
Rewrite alternatives stay RAW.

Nine selector 01 paths have width<=13. A word table at 9A32+2*width selects a
cursor[AA16], whose first byte supplies a remaining descriptor count[AA18].
Before each descriptor, decrement remaining and set reverse index[AA19]=width.
The packet exposes the second saved-Boolean chain: continue precisely when
`j!=0 AND input[20C6+u8(j-1)]==descriptor[cursor+j]`.
**Both reads happen even at j=0**: seven matching invocations also read 21C5
and the descriptor header before the saved zero guard suppresses equality.
Do not reconstruct this as a short-circuit read.

Every descriptor comparison advances the pointer by width+1 via +1A1C and
publishes it at AA16 **before** testing whether j reached zero. Seven matches
publish the byte at the advanced pointer to 20C3; A is that byte, BC=0, HL=DE=
advanced pointer, and Z=1/CY=0 still describe CPI j,0. Two exhausted scans store
selector1 while returning A=0. There are 117 advances and 52 positive equal-byte
index decrements. Per-invocation path records retain the differing widths,
advance counts, outputs and callers.

New roles name the selector/context/width/input byte area, the 14 accessed pointer
words, and scan pointer/count/index. No descriptor ownership or compiler meaning
is assigned. +1376 remains the principal opaque helper. Triple-true handling,
rewrite arms and the width>13 RET (STATIC / UNOBSERVED) remain RAW.

### PLI1 +7D53

Twelve empty-range calls return immediately; two gate-bit-set calls return after
RAR. Seven work paths reverse-scan a byte cursor, stopping at `u8(begin-1)`;
thus begin 0 can produce cursor FF without a signed/sentinel interpretation.
The complete +7A4D mapping contract supplies current table bytes. Missing
+7C1B/+7B7A contracts prevent interpretation of reverse helper processing.

Forward traversal checks `unsigned(u8(end-1))<cursor`, maps and emits each
current byte through resident +0EF6 at its partial success scope, and dispatches
fresh cached helper results around 3/2/6/5 comparisons. There are 16 forward
iterations and 26 emission C-byte arguments. Cache stores, additional emission
arguments and the final end=begin publication remain distinct. Cursor/bounds/
cache values are reloaded around opaque calls; no general preservation is inferred
from their observed equality. +7BA2's observed table writes can affect later
mapping calls but are not promoted into a general helper algorithm.

The eight missing PLI1 helpers, resident emitter error path, shortcut/mapping/
transformed-byte alternatives and six RAW bytes block a full contract. The local
operation is represented honestly as partial STRUCTURED orchestration.

## Evidence gaps and next work

- +1E0B: operation complete at scope; table capacity/source meaning remains a
  missing data-role/ownership question, not a local opcode blocker.
- +8273: complete local initializer; other table writers/whole capacity need
  helper decompilation/general provenance before broader meaning.
- +4929: complete local loop; arbitrary link termination is conditional, and
  ownership/producers need general provenance. No new fixture is needed to
  describe the observed operation.
- +784E: **opaque helper +1376** first; RAW triple/literal/width arms are
  unobserved branches. ADI carry ancestry is an unresolved producer in V0.1,
  resolved manually at this coordinate from packet backing. Earlier input/
  descriptor producers and alias scope need general provenance. Matched
  discriminating fixtures should follow helper analysis if still necessary.
- +7D53: **opaque helpers** +7C1B/+7B7A/+7B64/+7AA9/+7ABF/+7BA2/+7E46/+7E56,
  **partial helper path** +0EF6 error/flush, and **unobserved branches** shortcut,
  bytes>=F7, transformed>=5/equal6 and cursor wrap. No unusual continuation was
  found. Decompile existing helpers before designing fresh fixtures.

## Progress and exactness

The unchanged capture has 10,378 canonical coordinates and 21,012 fetched bytes.
Only annotations/status metadata changed. All old labels are preserved; two new
PLI0 and24 new PLI1 numeric-only labels retain coordinates inside newly
represented operands. All 94,720 historical bytes and image hashes round-trip.

| Executed bytes | Before | After | Delta |
|---|---:|---:|---:|
| RAW | 17,766 | 17,077 | -689 |
| DECODED | 304 | 304 | 0 |
| STRUCTURED | 1,523 | 1,760 | +237 |
| UNDERSTOOD | 1,419 | 1,871 | +452 |

Net baseline RAW→STRUCTURED is237 and RAW→UNDERSTOOD is452. Initial structural
seeding was not counted as separate semantic progress. Whole-image totals are
90,744 RAW / 304 DECODED / 1,791 STRUCTURED / 1,881 UNDERSTOOD. Unexecuted previously
promoted bytes retain their status; no new unexecuted byte is promoted.

| CALL entries | Before | After |
|---|---:|---:|
| UNDERSTOOD | 44 | 48 |
| STRUCTURED | 10 | 11 |
| DECODED | 3 | 3 |
| RAW | 334 | 329 |

Classification unresolved is 337→332; the 391 CALL/RST targets and eleven separate
PCHL continuation entries are unchanged. Bounds/control/contract completeness
remains independent of status.

| Dynamic image | Occurrences | RAW after | STRUCTURED after | UNDERSTOOD after | UNDERSTOOD before → after |
|---|---:|---:|---:|---:|---:|
| PLI.COM | 266,524 | 45,999 | 43,210 | 114,827 | 43.0832% → 43.0832% |
| PLI0.OVL | 94,418 | 44,567 | 11,322 | 38,529 | 38.8718% → 40.8068% |
| PLI1.OVL | 42,875 | 23,855 | 1,654 | 17,366 | 3.2676% → 40.5038% |
| PLI2.OVL | 36,181 | 23,127 | 3,649 | 8,103 | 22.3957% → 22.3957% |
| Total | 439,998 | 137,548 | 59,835 | 178,825 | 36.5986% → 40.6422% |

DECODED occurrences remain 63,790 (PLI.COM 62,488; PLI2 1,302). Full run 441,855
includes 1,857 modeled instructions outside historical images; using that full
denominator gives 40.4714% UNDERSTOOD. Parent-local promotion counts independently
sum 17,792 UNDERSTOOD and 1,144 STRUCTURED occurrences, matching the status delta.

[before.json](before.json), [progress.json](progress.json) and
[dynamic-progress.json](dynamic-progress.json) retain immutable pass snapshots;
parent coverage/inventory/instruction annotation-status/dynamic artifacts follow
current annotations. Historical pass tests retain their original snapshots;
pass4's old next-target queue is tested against pass4's region set, not the live
catalog after pass5.

## Packet workflow assessment and strategy

V0.1 materially reduced mechanical joining for +784E: saved predicates,
producer coordinates, branch outcomes/classes, call boundaries and full member
states were together. No cross-file reconstruction of the supported triple guard
or reverse-comparison polarity was needed. Selected queries still exposed the
zero-index reads, advanced-pointer publication and differing return-register/
stored-result channels. +4929's complete subtraction contract was adjacent to
its callsite; +7D53 made the many missing/partial callee scopes visible.

Limitations are concrete: ADI carry→SBB ancestry is unsupported; word DAD
address relations still require instruction/state reasoning; initial structural
seeds without named roles have weak pointer/publication navigation (unlabeled
STA effects remain in full step accesses). Opaque-effect rendering can list
large callee-subtree/stack address sets. These are experimental extractor limits,
not reasons to infer missing semantics or broaden this pass.

A separate seed mode is **not yet justified by a blocking need**: all three
structural hypotheses worked with explicit zero-frame/empty-slot options and no
extractor changes. Structural seeding has authoring cost, but a seed mode alone
would not supply bounds authority or missing roles. No seed mode was implemented.
One run does not demonstrate improved decompilation stability.

Recommendation **A: continue MINIMAL**, especially resident +1376 and +7D53's
opaque PLI1 helpers. PLI1 still has 23,855/42,875=55.64% RAW dynamic execution;
the structural/contract gaps are substantial despite the gain. Existing helper
work should precede matched microfixtures, and FIZZBUZ-minus-MINIMAL remains
premature. Dynamic percentage alone was not used to force promotions.

## Validation / reproduce

```sh
python3 tools/annotated-assembly/check_minimal_pass_5.py \
  --images /home/john/pli/cpm/pli80/DISK1 \
  --output _build/minimal-pass-5/rechecked.json
python3 tools/annotated-assembly/test_minimal_pass_5.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_procedure_evidence_packet.py --images /path/to/DISK1 -v
dune runtest --force
python3 tools/annotated-assembly/test_minimal_baseline.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_pass_1.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_pass_2.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_pass_3.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_pass_4.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_decompilation_annotations.py -v
python3 tools/annotated-assembly/test_verify.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
python3 tools/annotated-assembly/minimal_dynamic_progress.py
git diff --check
```

Eight new tests cover all 130 invocations, global-count/header publications,
exact 149-byte initialization, retained old link addresses, primary masks/results/
zero-index reads, packet dependencies, qualified emission traversal and progress.
Corrupt writes/link addresses are rejected. Project tests (976,272 ALU cases),
all 91 Python annotation/baseline/pass/packet tests, V1 conventions, exact image/
section/partition/coordinate checks, dynamic consistency and diff checks passed.
Task scratch and packet artifacts remain ignored in the project `_build` tree;
no task-created /tmp files remain.
