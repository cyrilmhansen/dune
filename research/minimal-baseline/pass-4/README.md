# MINIMAL decompilation pass 4

Starting commit: `7138604`. Existing corrected MINIMAL witnesses and historical
bytes are the primary evidence. Five requested anchors and three immediate
storage/arithmetic helpers were reconstructed under V1. No new capture,
FIZZBUZ decompilation, generic decompiler or ownership model was introduced.

## OBSERVED: progress and exactness

Coverage remains **10,378 canonical coordinates / 21,012 executed image bytes**.
All **94,720 original bytes** round-trip exactly, with unchanged image hashes.

| Executed status | Before | After | Change |
|---|---:|---:|---:|
| RAW | 18,018 | 17,766 | −252 |
| DECODED | 304 | 304 | 0 |
| STRUCTURED | 1,523 | 1,523 | 0 |
| UNDERSTOOD | 1,167 | 1,419 | +252 |

| Image | Executed RAW | DECODED | STRUCTURED | UNDERSTOOD |
|---|---:|---:|---:|---:|
| PLI.COM | 2,440 | 142 | 65 | 674 |
| PLI0.OVL | 3,450 | 0 | 661 | 246 |
| PLI1.OVL | 6,766 | 0 | 258 | 124 |
| PLI2.OVL | 5,110 | 162 | 539 | 375 |

There remain **391 observed CALL/RST targets** (no RST executes): **44 UNDERSTOOD,
10 STRUCTURED, 337 unresolved**, versus 36/10/345 before. Eleven separate PCHL
continuation entries remain unresolved. All eight new entries are UNDERSTOOD at
their declared scope; procedure completeness remains independent of byte status.
Only already executed RAW instructions were promoted. RAW→STRUCTURED is zero;
the parent +24BC retains all 661 previously STRUCTURED bytes.

Whole-image totals are **91,433 RAW / 304 DECODED / 1,554 STRUCTURED / 1,429
UNDERSTOOD**. Ten unexecuted UNDERSTOOD and 31 unexecuted STRUCTURED bytes retain
their prior status. All prior stable coordinate labels, including operand-interior
coordinate-only EQUs, are retained and their mappings checked.

## OBSERVED: dynamic execution

Count each instruction occurrence at its canonical image+offset under current
annotation status. Nested calls retain their own statuses. All fetched bytes of
an instruction must have one status. The denominator excludes 1,857 modeled
BDOS RETs without historical-image coordinates (full run: 441,855 instructions).

| Image | Occurrences | RAW | DECODED | STRUCTURED | UNDERSTOOD | UNDERSTOOD before → after |
|---|---:|---:|---:|---:|---:|---:|
| PLI.COM | 266,524 | 45,999 | 62,488 | 43,210 | 114,827 | 41.1742% → 43.0832% |
| PLI0.OVL | 94,418 | 46,394 | 0 | 11,322 | 36,702 | 7.9201% → 38.8718% |
| PLI1.OVL | 42,875 | 40,964 | 0 | 510 | 1,401 | 0.5248% → 3.2676% |
| PLI2.OVL | 36,181 | 23,127 | 1,302 | 3,649 | 8,103 | 22.3957% → 22.3957% |
| Total | **439,998** | **156,484** | **63,790** | **58,691** | **161,033** | **28.5331% → 36.5986%** |

The eight hypotheses account for **35,488 newly UNDERSTOOD occurrences**. Their
own-invocation counts independently match this delta. Static executed-byte
UNDERSTOOD coverage is **6.75%**; dynamic coverage is a separate measurement,
not proof of complete procedures or exhaustive paths. With the full-run
denominator, UNDERSTOOD is 36.4448%.

[progress.json](progress.json) retains before/after snapshots and label/provenance
audits; [dynamic-progress.json](dynamic-progress.json) is this pass's immutable
snapshot. The [parent dynamic artifact](../dynamic-progress.json) follows current
annotations, allowing historical pass tests to retain their original metrics.

## DEDUCED: hypotheses and contracts

Bounds below are exclusive-end hypotheses derived from actual entries, local
branches/prologues and RETs. They are not RoutineCandidate/context min/max bounds.
All **1,308 invocations** preserve their original hardware slots, bytes and return
targets. No secondary CALL/RST/PCHL entry or shared tail was observed inside the
eight new envelopes. Internal loop destinations are not new procedure identities.

| Stable entry | Envelope | CALLs | Promoted bytes | Bounds / CFG / contract |
|---|---|---:|---:|---|
| PLI0+240B | `[240B,242B)` | 152 | 29 | provisional / partial / partial |
| PLI0+23DF | `[23DF,240B)` | 85 | 44 | stable / complete / complete |
| PLI0+1A8C | `[1A8C,1AA6)` | 87 | 26 | stable / complete / partial |
| PLI1+7A4D | `[7A4D,7A63)` | 98 | 22 | stable / complete / complete |
| PLI.COM+0390 | `[0390,03E9)` | 424 | 26 | provisional / partial / partial |
| PLI0+1A47 | `[1A47,1A7D)` | 90 | 54 | stable / complete / complete |
| PLI0+1A14 | `[1A14,1A47)` | 152 | 42 | provisional / partial / partial |
| PLI0+4662 | `[4662,466B)` | 220 | 9 | stable / complete / complete |
| PLI0+24BC, refined | `[24BC,289B)` | 85 (pass-3 evidence reused) | 0 | provisional / partial / partial |

Detailed callers/counts, representative registers/flags/memory, direct calls,
branch outcomes and original-slot proofs are in [regions.json](regions.json).
Existing cross-run CALL presence is retained without validating or decompiling
those runs. Complete local operation does not establish compiler-level meaning.

### PLI0 +240B and +23DF

+240B saves input C at 6A96 and invokes the established +23C3 bound/tag predicate.
On observed guard-false, return A=FF/CY=1 exactly when `(byte[p+3]&7)==C`, else
A=0/CY=0. SUB C followed by SUI 1 tests the wrapped difference for zero:
**equality, not ordering**. BC=3, DE=6A83, HL=6A96; NZPA follow final self-SBB.
OBSERVED: sixteen true and 136 false; requests 1/3/4/5/6/7. Guard-true bytes remain
RAW, so the contract/CFG/bounds are partial.

+23DF saves C at 6A95. Loop: if +23C3 is true, complement/rotate its Boolean and
return; otherwise advance tested_pointer[6A82] by byte[old pointer], then compare
`byte[advanced pointer+1]&E0` with C. Match returns; mismatch repeats the guard.
OBSERVED: 85 advances, 84 matches and one mismatch/guard exit, all C=0. Both RETs
return A=0/CY=0 in MINIMAL, but matched RET +2406 has Z=1 while guard RET +240A
preserves true-guard NZPA with Z=0. Zero lengths/nonmatching data need not terminate;
nonzero requests and longer walks remain unobserved, not unrepresented local CFG.

### PLI0 +1A8C and necessary storage helpers

+1A47 selects `T=word[6A0D+2*byte[6A4C]]`, saving it at 6A56. While
staging_cursor[69C3]>T, decrement source cursor, read that byte, write at current
record_top[1C36], then decrement destination cursor. Recheck unsigned difference
through existing resident +1A33. OBSERVED: 87 zero-copy calls and three tails of
6/29/1094 bytes, totaling **1,129 bytes**; 1,219 comparisons. All stop at equality.
Return BC=final source, DE=6A57, HL=T−source, A=high difference, CY=0; other flags
describe high-byte subtraction. It is an ordered copy, not an inferred memmove,
original allocator or source-language ownership operation.

+1A8C saves C at 6A58, calls +1A47, sets working_record_pointer[69C5] to the
post-copy staging_cursor, and clears extent_count[69C7]. Reload C and call +1A14.
The initializer itself does not advance staging_cursor or emit record headers.
All 87 MINIMAL initializer calls take the zero-copy path; requested extents are
6×5, 8×81 and 17×1. Its operation remains partial because reservation failures
are unresolved.

+1A14 saves request C at 6A55 and checks `255−old_count>=C`. On witnessed success,
store new count **before** the address guard. Resident +1A1C computes the wrapped
working-window end; +4662 computes end−word[1C36]. CY=1 (end<top) selects RET.
BC is preserved, DE=1C37, A=high difference, HL=difference. Capacity/top error
branches remain RAW. Two concrete reads from the already established resident
addition and two from the subtraction leaf independently check the address
formula for every selected +1A14 invocation.

+4662 is separate: given DE=value and HL=word pointer, return HL=value−word[p],
DE=p+1, A=high result and full unsigned borrow in CY; BC unchanged. Other flags
describe high-byte SBB, not full-word zero/sign. No data stores or unusual stack
convention. OBSERVED: 219 borrow and one no-borrow across 220 calls.

### Integration into +24BC

[caller-refinements.json](caller-refinements.json) records the precise before/
after contract and block updates. The source's +2535 block now initializes a
counted working window before its seventeen-byte copy; +264A/+265B/+2775/+27E6
explain field equality tests 5/6/7/3; +2688 explains length-scanning to masked tag
zero or guard. The only +24BC initializer invocation uses request17 and copies
no staged tail before the caller's own seventeen-byte copy.

Three opaque calls are removed from its pseudocode and replaced locally with
demonstrated operations. **+24BC stays STRUCTURED/partial in all three dimensions.**
Helpers +1E0B/+21AB/+2290/+22B3/+242B/+247C/+249A and unprocessed parent arms still
block a complete contract. The F=entry_SP−18 frame, recursion and ordinary RET
interpretation remain intact. No previous established boundary/contract is
invalidated; the refinement supplies missing effects rather than widening scope.

New roles connect staging_cursor[69C3], extent_count[69C7], boundary selection
[6A0D/6A4C/6A56] and saved requests[6A55/6A58/6A95/6A96] with the existing
working_record_pointer[69C5] and record_top[1C36]. No new helper directly consumes
result_slot_pointer[6A88] or output_record_word[6A8E]; their remaining relationship
stays limited to the prior concrete pointer-copy/publish observations.

### PLI1 +7A4D

Save unsigned C at AE36; LHLD also reads AE37, then discards its high byte.
Map `j=byte[AA1F+C]`; return `A=byte[AAB4+j]`, BC=j, HL=AAB4+j. DE/NZPA are
preserved and CY=0. There are no calls, internal branches, arguments or rewritten
return slots. OBSERVED: 98 calls/five sites, positions 0..6/FE/FF and sixteen
returned byte values. High indices are unsigned positions, not inferred sentinels.

This establishes reusable position_map[AA1F], mapped_byte_table[AAB4] and
mapped_lookup_index[AE36] roles. It resembles the known PLI2 mapping shape but
has distinct identity/tables; they are not merged. Callers use A as data: +7A6E
indexes another table, +7C2D/+7CCB compare 0A, +7D94/+7DD2 compare F7, and +7DC8
caches A before a resident emission call. Caller comparisons establish flags;
the leaf's preserved NZPA do not describe its return byte. These are continuation
observations only; caller bodies are not decompiled here. No PL/I token/type name.

### Resident +0390

A distinct routing wrapper around +0380: save C at 206B, test low bits of route
flags202A/201E, then on witnessed zero bits reload unchanged C and call +0380.
Return its registers/flags, not the emitted byte (all MINIMAL returns A=AA).
OBSERVED: 424 plain-output calls, 56 byte arguments and one +0380 invocation each.
Nonzero route arms remain RAW; their device/filtering meaning is unresolved.
New scoped cache/flag roles retain numeric addresses. +0380 remains separate.

## Next MINIMAL pass

**Another MINIMAL pass is justified; the remaining surface is not marginal.**
PLI1 still has **40,964/42,875 = 95.5429% RAW dynamic execution**. Overall RAW is
156,484/439,998 = 35.5647%, and 17,766 executed bytes remain RAW. Continue MINIMAL
before FIZZBUZ-minus-MINIMAL; that delta was not investigated in this ticket.

| Next anchor | Calls / sites | Why |
|---|---:|---|
| PLI0+1E0B | 87 / 7 | Connect counted window to +24BC downstream effects. |
| PLI1+784E | 19 / 8 | Shared central operation; 139 RAW context coordinates. |
| PLI1+4929 | 2 / 1 | Heavily repeated RAW loop context. |
| PLI1+8273 | 1 / 1 | Repeated RAW context with no direct nested calls. |
| PLI1+7D53 | 21 / 4 | Connect new mapped-byte access to larger operations. |

Existing context-associated coordinate counts suggest 8,437 / 5,425 / 2,103 /
1,144 RAW global occurrences for those four PLI1 anchors. They are **priority
evidence only**, not authoritative procedure membership, exclusive invocation
costs or additive savings. No next-target bodies were investigated.

## Reproduce and validate

Existing capture and task analysis stay under ignored `_build/minimal-baseline/`
and `_build/minimal-pass-4/`. Retained projections are not full replay traces;
the report reuses pass-3 witness/canonical/run-summary provenance hashes.

```sh
python3 tools/annotated-assembly/check_minimal_pass_4.py \
  --capture _build/minimal-baseline/capture --output _build/minimal-pass-4/rechecked.json
python3 tools/annotated-assembly/minimal_dynamic_progress.py
dune runtest --force
python3 tools/annotated-assembly/test_minimal_pass_4.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_pass_3.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_pass_2.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_pass_1.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_baseline.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_decompilation_annotations.py -v
python3 tools/annotated-assembly/test_verify.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
git diff --check
```

Validation passed: project suite (976,272 ALU cases), all 66 annotation/baseline/
pass tests, V1 validation, dynamic consistency, complete image/section hashes,
byte equality, partition/mapping checks and `git diff --check`.
