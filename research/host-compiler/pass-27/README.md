# Pass27 — bounded native PLI1+7E5F

Baseline: `f3e17523f52167c251e3a89182df7f09eab24b92`.

`Pli80_host.Range_publication` composes the four existing publication algorithms
on shared byte-addressed State. Its supported predicate is unsigned end<=94 plus
valid byte/word arguments and the inherited child/cache/code/stack nonalias
scopes. Semantics depend only on current memory and inputs. The source-bound
snapshot oracles belong solely to the differential harness.

Input DE is saved high at AE56, low at AE55, then C at AE54, exactly as the
historical instructions do. A fresh end comparison rejects end>94. The operation
publishes old AE33 into position_map[end], reads the displaced mapped byte through
old AE33 and replaces AE33. It independently rereads the endpoint before each
child: mapped byte publication, mapped word publication, primary zero publication,
secondary zero publication. It finally reads end afresh, publishes it to AE32,
and increments AE35. Child algorithms are reused, not duplicated.

The bridge validates canonical CALL ancestry and immutable root/helper encodings,
prepares a private RAM transition and records the full chronological write journal.
A late child alias failure cannot mutate live memory. Wrong entry/image/code,
invalid CALL/continuation, unsupported end, inherited child alias, malformed input,
extra/omitted invocation and source-proof failures are covered by tests.

## Natural proof set

Every duplicate invocation is retained. Historical executions were rerun to
capture exact private entry/post RAM; tests independently reconstruct all corrected
ordinary root/child returns from the existing event-witness captures.

| Source | Roots/shadows/single transitions | Observed end range | Callers and counts |
|---|---:|---|---|
| MINIMAL | 16 | 0..6 | 807D:12; 80E8:1; 7FFF:3 |
| FIZZBUZ | 107 | 0..8 | 807D:78; 80E8:8; 7FFF:21 |
| PICTURE | 22 | 0..3 | 807D:16; 80E8:2; 7FFF:4 |

All **145** shadows match every register/flag, SP/actual continuation, all
**65,536 bytes**, ordered logical writes and the complete CALL/PUSH write journal.
Tests additionally cover all 149 supported endpoints with all 32 entry flag
combinations. This validates the bounded operation, not general compiler semantics.

## ABI and stack

At return A is the fresh old end, BC is the secondary publisher's fresh index,
DE retains the saved input word high byte with E=0, and HL=AE35. Final NZPA/AC
come from INR end; CY remains the final child's DAD carry, zero in the declared
address scope. RET consumes the original CALL word; SP=S+2.

Child CALLs repeatedly overwrite S-2/S-1. The last is +7EB2, publishing
continuation A0B5. The +7AF0 PUSH at +7B09 leaves its selected destination low/high
at S-4/S-3, consumed but not erased by POP. Every residue value is independently
derived from code and native child results; no post-oracle byte is copied.
`stack-compatibility.json` and per-case journals retain writer/depth/overwrite
ancestry.

## Hybrid hierarchy

Each root is **one** Runner transition. Its four native publication children
execute internally. A minimal optional exclusion-window parameter reuses the
existing cumulative dispatcher hierarchy; no Runner/CPU/CPM change is required.

Cumulative vector order:
`7E5F,7D53,7C1B,7BBF,7B7A,7BA2,7AD5,7B64,7ABF,0EF6,7A79,7E46,7E56,7AF0,7B49`.

| Source | Residual Runner transitions | Host BDOS services |
|---|---|---:|
| MINIMAL | 16,21,0,0,7,0,2,0,13,88,1,0,0,10,22 | 2 |
| FIZZBUZ | 107,77,0,0,58,5,33,7,106,131,28,0,0,102,197 | 6 |
| PICTURE | 22,23,0,0,8,0,6,3,19,72,3,0,0,19,39 | 2 |

Each of the four logical children has 16/107/22 internal uses, respectively.
No enabled historical body executes; canonical image identity prevents overlay
PC collisions. All six standalone/cumulative compiler runs preserve INT/REL
record ordering, factual file-event order and complete filesystem identity.
PASS1/PASS2 report no errors, END COMPILATION is observed, and all terminate at
warm boot. Exact REL goldens:

| Source | Bytes | SHA256 |
|---|---:|---|
| MINIMAL | 256 | 7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119 |
| FIZZBUZ | 768 | 68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203 |
| PICTURE | 256 | c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1 |

## Validation and next boundary

```
RUNES_HOST_IMAGES=/path/to/DISK1 dune exec test/native_range_publication.exe
python3 tools/annotated-assembly/test_native_7e5f_pass_27.py --images /path/to/DISK1 -v
dune exec pli80-native-range-publication -- --toolchain /path/to/DISK1 --output-dir _build/new-pass27-results
```

Validation totals and exact 94,720-byte reconstruction are in `validation.json`.
No historical annotation, completeness field, error arm or +7A46 semantics changed.
There is no divergence or fidelity debt. Reports contain compact metadata and
hashes; snapshots remain in process and generated evidence stays ignored.

Recommend **B** for Pass28: introduce reusable control read/publication primitives
inside a bounded +8048 composition pass, rather than another isolated helper
migration. Keep AC73 distinct from auxiliary/packed tables and preserve the three
independent predecessor-copy channels. Reject high-input gate-set +805C..+8068
on private state. Preserve all child scope restrictions and stage the high-path
+7D53/emission/services as one transaction. See `next-boundary-assessment.json`.
Neither +8048 nor the unobserved +7E70 arm is implemented in Pass27.
