# MINIMAL decompilation pass 3

Starting commit: `68c0f79`. This pass follows Annotated Decompilation Conventions
V1 and reuses the corrected existing MINIMAL witnesses. No new capture,
FIZZBUZ investigation, static sweep, visualization or procedure ownership model
was introduced. Cross-run presence below comes only from the existing inventory.

## OBSERVED: static executed-byte and callable progress

MINIMAL still executes **10,378 canonical coordinates / 21,012 image bytes**.
All **94,720 historical bytes** remain exact, with unchanged full-image hashes.

| Executed status | Before | After | Change |
|---|---:|---:|---:|
| RAW | 18,991 | 18,018 | −973 |
| DECODED | 304 | 304 | 0 |
| STRUCTURED | 862 | 1,523 | +661 |
| UNDERSTOOD | 855 | 1,167 | +312 |

| Image | Executed RAW | DECODED | STRUCTURED | UNDERSTOOD |
|---|---:|---:|---:|---:|
| PLI.COM | 2,466 | 142 | 65 | 648 |
| PLI0.OVL | 3,654 | 0 | 661 | 42 |
| PLI1.OVL | 6,788 | 0 | 258 | 102 |
| PLI2.OVL | 5,110 | 162 | 539 | 375 |

UNDERSTOOD bytes are now **5.55% of executed bytes** (was 4.07%). These are
useful low-level contracts at their stated scope, not fully recovered original
source procedures. There remain **391 CALL/RST targets**: **36 UNDERSTOOD,
10 STRUCTURED, 345 unresolved**, versus 30/9/352 before. Eleven separate PCHL
continuation entries remain unresolved; total callable coordinates remain 402.
No RST is executed. Whole-image status is 91,685 RAW / 304 DECODED / 1,554
STRUCTURED / 1,177 UNDERSTOOD; the ten unexecuted UNDERSTOOD bytes and 31
unexecuted STRUCTURED bytes are unchanged.

## OBSERVED: dynamic understanding metric

This is a new independent measurement: sum the execution counts of canonical
instruction coordinates under each **current annotation status**, rather than
counting each fetched byte once. All bytes of an instruction must have the same
status; a split is rejected. Image hashes and runtime/file mapping are checked.

| Image | Instruction occurrences | RAW | DECODED | STRUCTURED | UNDERSTOOD | Dynamic UNDERSTOOD |
|---|---:|---:|---:|---:|---:|---:|
| PLI.COM | 266,524 | 51,087 | 62,488 | 43,210 | 109,739 | 41.1742% |
| PLI0.OVL | 94,418 | 75,618 | 0 | 11,322 | 7,478 | 7.9201% |
| PLI1.OVL | 42,875 | 42,140 | 0 | 510 | 225 | 0.5248% |
| PLI2.OVL | 36,181 | 23,127 | 1,302 | 3,649 | 8,103 | 22.3957% |
| Total | **439,998** | **191,972** | **63,790** | **58,691** | **125,545** | **28.5331%** |

Before this pass: 208,017 RAW / 63,790 DECODED / 47,369 STRUCTURED / 120,822
UNDERSTOOD occurrences, or **27.4597% dynamically UNDERSTOOD**. This pass adds
4,723 UNDERSTOOD occurrences and 11,322 STRUCTURED occurrences. Nested calls
are classified at their own coordinates, not given their parent's status.

The full run has 441,855 instruction occurrences. Its 1,857 modeled BDOS RETs
at 0005H have no historical-image coordinate and are explicitly outside this
metric. Using the full-run denominator instead gives 28.4132% UNDERSTOOD.
[dynamic-progress.json](dynamic-progress.json) contains reproducible per-image
values; [progress.json](progress.json) retains both snapshots. Static coverage,
dynamic execution, byte status and procedure completeness are separate dimensions.

## ProcedureHypotheses and independent completeness

The five anchors were reviewed in priority order. The PLI2+09BA contract needed
two immediate helpers, +04D3 and +061B: **seven distinct callable regions** in
total. No anchor was merged with an adjacent entry. Bounds below are hypotheses
with exclusive ends; they follow entry/prologue, concrete local branches and
terminal RET sequences, not stack-context min/max extents. Only instructions
already fetched by MINIMAL were promoted. Unexercised holes remain RAW.

| Entry | Hypothesized envelope | Checked CALLs | Status | New bytes | Bounds / CFG / contract |
|---|---|---:|---|---:|---|
| PLI.COM+0AF5 | `[0AF5,0B2A)` | 199 | UNDERSTOOD | 34 | provisional / partial / partial |
| PLI2+09BA | `[09BA,0AFB)` | 9 | UNDERSTOOD | 196 | provisional / partial / partial |
| PLI2+04BF | `[04BF,04D3)` | 32 | UNDERSTOOD | 20 | stable / complete / complete |
| PLI1+4281 | `[4281,428E)` | 11 | UNDERSTOOD | 13 | stable / complete / complete |
| PLI0+24BC | `[24BC,289B)` | 85 | STRUCTURED | 661 | provisional / partial / partial |
| PLI2+04D3 | `[04D3,04E9)` | 39 | UNDERSTOOD | 22 | stable / complete / complete |
| PLI2+061B | `[061B,0636)` | 32 | UNDERSTOOD | 27 | stable / complete / complete |

All **407 invocations** preserve their original hardware return slots and targets.
No software-continuation relation was assigned to them. Detailed return proofs,
representative own-invocation windows, branches, direct calls and contracts are
in [regions.json](regions.json). Local projections exclude child instructions,
including recursion, using corrected matched hardware-frame return events.
No RST/PCHL entry, alternate callable entry or shared tail was observed inside
these seven envelopes. Internal loop branches are not additional procedures.
All seven entries are also CALL targets in the existing FIZZBUZ/FACTOR/OPTIMIST
inventory; this is presence evidence, not validation of those runs' contracts.

### DEDUCED: resident +0AF5

With byte[2008]=0, call the established +09CB filter, cache A at 209A, compare
with 1A, and return cached A. EOF assigns byte[2012]=1; it does not OR a bit into
the prior value. Flags remain from the EOF comparison. BC/DE and non-EOF HL
follow the filter; EOF sets HL=2012. Its own data stores are 209A and conditional
2012; nested effects remain delegated. OBSERVED: 195 non-EOF bytes and four EOFs,
all 199 original slots returning +0B29. The nonzero-2008 alternate source remains
RAW. HYPOTHESIS: byte-source selection wrapper, not complete source management.

### DEDUCED: PLI2 +09BA and immediate mapped-table helpers

Start at the backward span cursor +0992(byte[AAAE]); save it at AAAD/AC4F.
For each forward position until byte(AAAE+1), obtain weight via +04A9 and kind
via +04BF. Under witnessed kind0/mode202B=0, initialize accumulator from +04D3.
For each remaining weight, walk a backward child span and form the byte-modular
candidate `(value04D3(child)+remaining−1)&FF`. Keep the unsigned maximum, move
child cursor to span-start−1, decrement remaining. Publish through +061B and
increment forward cursor. OBSERVED: sixteen outer iterations (weights 0×10,
1×5, 2×1), seven child iterations, and both max outcomes (retain four/update
three). The repeat flag is set then consumed once on these paths.

Kind1/3/4, mode bit0=1 and extra-pass branches remain RAW; general semantics and
termination are unresolved. UNDERSTOOD applies to the represented scoped fold,
with partial bounds/CFG/contract explicitly visible. HYPOTHESIS: mapped-byte
attribute propagation across spans; no PL/I category or source-level type.
The final LHLD AC3F/XCHG also loads adjacent candidate byte AC40 into D:
caller D is **not preserved**, even though the table helpers preserve DE.
The candidate high byte can be stale when the current position has weight zero.

+04BF is a distinct wrapper: save C at ABFB, call +047D, then use its class byte
as the index into the table at 2274. Return A=that table byte, BC=class,
HL=2274+class; DE/NZPA preserved, CY=0. All 32 observed kind results are zero.

+04D3 reads `j=byte[AAB0+C]`, then byte[A732+j], saving C at ABFC. +061B saves
C/E at AC0E/AC0F and writes E to the **same mapped address**. Each returns
BC=j, HL=A732+j, DE/NZPA preserved and CY=0. The table at A732 is demonstrably
mutable, not an immutable classification table. All table/scratch alias cases
are outside the declared contract; source-level meaning remains hypothetical.

### DEDUCED: PLI1 +4281

Load current_record word[A863] through the established +1A40 word-minus-zero
primitive. OR high/low bytes, ADI FF, then SBB A produces A=FF/CY=1 for a nonzero
pointer or A=00/CY=0 for zero. HL retains the pointer, DE=A864 and BC is
preserved. No dynamic record dereference, data write, caller argument or return
rewrite occurs. OBSERVED: six true and five false results from six caller sites.
HYPOTHESIS: record-presence predicate; nonzero does not establish validity.

### DEDUCED structure: PLI0 +24BC

Let S be entry SP. The prologue subtracts 17, pushes duplicated C, then increments
SP to establish **F=S−18**, with local_mode at F+0. This is not a software return.
Words occupy F+1/+3/+5/+7/+12/+14/+16; F+9/+10/+11 hold tag/masked flags/count.
The original return word stays at F+18. Save tested_pointer[6A82] at F+14,
clear record[p+3] bit7, snapshot tag/payload fields, and zero output result.

Tags 41/40 control recursive children at +27B4/+2808/+2819 with C=mode&1 or 4,
using saved pointers and a count loop. There are twenty recursive children, not
alternate procedures. Mode1 additionally performs a seventeen-byte copy and
word repairs through pointer[6A88]. A temporary PSW across +2790 sits below F;
all other direct CALLs use F. Publish word[F+16] to 6A8E, set SP=F+18 and RET
through the original slot at +289A. OBSERVED modes: 0×80, 4×4, 1×1.
Stack-relative operands account for temporary PUSHes: the final copy-back's
SP+14 accesses saved word F+12 while SP=F−2, not saved pointer F+14. The
opaque +21AB receives word values from F+16/F+1, rather than their addresses.

The operation remains STRUCTURED: several helper effects, tag70/error/repair
arms and record semantics remain unresolved. No recursive tree or ownership
contract is claimed. Its pseudocode names the demonstrated local effects and
marks delegated operations instead of disguising them as semantic calls.

## Durable roles, interpretation review and exactness

New scoped roles include source_selector[2008]/cached_source_byte[209A],
class_kind_table[2274], mapped_value_table[A732], span_start/end[AAAD/AAAE],
fold cursor/remaining/accumulator scratch, store index/value[AC0E/AC0F], and
PLI0 working_record_pointer[69C5], result_slot_pointer[6A88] and
output_record_word[6A8E]. Every name retains raw addresses and image hashes in
the role catalog. Constructor current_record[A863] now connects to the explicit
nonzero predicate; this does not establish a PL/I type or tag interpretation.

**No prior durable boundary or contract was invalidated.** V1 makes two tempting
interpretations explicitly unsupported: +4281 checks only nonzero, and +24BC's
recursive stack contexts are conventional hardware frames rather than the
software continuations seen in other overlay regions. Existing +0D40/+09CB and
lookup/walk contracts compose without being widened beyond their declared scope.

All prior **6,909 coordinate labels** remain present. Twenty-four labels that
formerly started RAW rows now lie inside instruction operands; numeric
coordinate-only EQU declarations retain their identity without emitting bytes
or asserting instruction entry. The normal verifier accepts only manifest-listed
stable-coordinate EQU symbols and verifies their runtime mapping. New instruction
labels are added; semantic aliases never replace stable coordinates.

All modified section hashes, whole-image hashes/equality, manifest partitions
and runtime mappings pass. Only RAW instruction bytes are promoted: no opcode
alias is normalized, no unexecuted path decoded, and no table rewritten.

## Next MINIMAL targets and remaining RAW execution

Important high-frequency code remains RAW: **18,018 executed bytes** and
**191,972 occurrences (43.63%)**. PLI1 alone has 42,140 RAW occurrences out of
42,875. RAW is an annotation status, not a code/data/dead-code conclusion.
The following queue uses inventory facts only; bodies were not investigated:

- **PLI.COM+0390:** 424 calls/five sites; console-byte wrapper composing +0380.
- **PLI0+240B:** 152 calls/six sites; common bit-test consumer in recursive paths.
- **PLI0+23DF:** 85 calls/one site; a pointer-state transition in every +24BC call.
- **PLI0+1A8C:** 87 calls/five sites; shared helper needed for the copy/setup path.
- **PLI1+7A4D:** 98 calls/five sites; common small primitive and calling-convention anchor.

The eleven PCHL handlers and partial +1FB5/+1DFF/+24BC operations also remain
important unresolved structure. No FIZZBUZ decompilation begins in this pass.

## Reproduce and validate

The capture and ignored analysis remain under `_build/minimal-baseline/` and
`_build/minimal-pass-3/`. Durable provenance hashes identify the existing witness
index, canonical report and run summary. Representative windows are projections;
they cannot replace the complete chronology for arbitrary new analysis.

```sh
python3 tools/annotated-assembly/check_minimal_pass_3.py \
  --capture _build/minimal-baseline/capture --output _build/minimal-pass-3/rechecked.json
python3 tools/annotated-assembly/minimal_dynamic_progress.py
dune runtest --force
python3 tools/annotated-assembly/test_minimal_pass_3.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_decompilation_annotations.py -v
python3 tools/annotated-assembly/test_minimal_pass_2.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_pass_1.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_baseline.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_verify.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
git diff --check
```

Validation passed: project suite (including 976,272 ALU cases), all 55 annotated
assembly/baseline/pass tests, the full verifier, V1 validation and diff checks.
