# Pass 39 — cached state transformation and acquisition boundary

Baseline/full-regression checkpoint: `fe6e25bdae01f787731cb45e1bef17296d7d3b2e`. Archaeology only; no native implementation, new fixture, runtime change or schema change. Established contracts are reused unchanged. The validation tier is **incremental**; a full checkpoint is due by Pass40 or before migration of the +5E98 family.

## Natural scope

Fresh corrected ordinary CALL/return windows give MINIMAL/FIZZBUZ/PICTURE:

| Operation | Calls | Actual callers |
|---|---|---|
| +30C1 | 0 / 8 / 0 | +3307:5; +3481:3 |
| +2C59 | 0 / 10 / 1 | FIZZBUZ +2DC3:3, +3329:4, +34A3:3; PICTURE +2DC3:1 |
| +2FC2 | 0 / 8 / 0 | +31A4 |
| +21D4 | 0 / 13 / 1 | +22C0 and independent +2259 |
| +25D6 | 0 / 7 / 0 | +2FF7 |
| +834F | 3 / 21 / 3 | +1507 and +2B0C |

The batched packet also retains +2221 (3/28/3), +22C0 (0/8/0), +2C53 (1/17/2) and substantial +28AA (1/19/3). **160 independent windows**, including duplicate values, are checked. Complete/bounded +31FB/+2705/+329F/+23B9 and previously established/native children are substituted, not rediscovered.

The model-facing packet is **24,363 bytes**, with one CFG per operation, two root route classes, nineteen root value-delta cases and four interned stack patterns. The ignored, rederivable proof is **22,665,037 bytes**; factual instructions are interned once. `efficiency.json` records its hash, generation time and 930.306× ratio. No full-memory native shadow is claimed.

## +30C1 and +2FC2: bounded operational law

+30C1's hypothesized extent is [30C1,31A8), with **190/231 represented bytes**. Call +22C0 first. Six independent fresh equality-mask reads test A629/A62A against19/04/0D through SUI/SUI/self-SBB, PSW carriers and OR. All natural calls skip the unobserved19 publication. Another fresh OR sequence combines equality15 with two independent +2221 indexed-range masks (C1, C2). All eight publish literal15 to A628.

Fresh primary A62C is cached at A665; independent extra A62F is cached at A666. A fresh selector/membership conjunction uses +213C(A629), preserving its actual bit result separately from flags. The demonstrated clear conjunction skips the RAW conversion arm. Fresh cache rereads publish A62B and A62E, then call +2FC2. There is no local traversal loop; this route is a finite guard/composition graph.

+2FC2 [2FC2,30C1) has **167/255 represented bytes**. It first caches fresh A62D→A663 and A630→A664. The fresh base mask11 and second-selector equality16/+213C bit decide whether to transform the primary cache through +25D6. **Seven calls transform; one skips**. Actual cache inputs2 and1 yield7 and4; the independent skipped input5 remains5. True conversion then freshly tests the second cache against zero; the nonzero arm remains RAW.

At the supported selector15 route, clear A62E. Fresh primary-minus-extra wraps and publishes A62B. Independently, transformed cache-minus-secondary cache wraps and publishes A663. Two separate paired-input +23B9 calls select the extra maximum, then the primary maximum. Add freshly reread extra modulo256 before publishing primary. Fresh paired primary and limiter then feed +23A0; publish its direct result and return its exact ABI/flags. No simplified saturation formula or constant15 return law substitutes these operations.

All eight direct returns happen to have A=0F, HL=A64F, DE=350F and final comparison flags S0/Z1/AC1/P1/CY0. **B differs** in the independent no-conversion case; BC is inherited through the actual children. D=35 is the genuinely read A643 neighboring limiter byte, not a guessed zero-extension. Exact per-call state is retained in the compact packet.

These two operations are reproducible at their demonstrated state-predicate scope. Their unexecuted transformation alternatives remain RAW and do not block a bounded implementation of the demonstrated routes.

## Small mechanical leaves closed in this pass

- **+21D4 [21D4,21E9):** independently form zero-equality masks from fresh A632 and A633; save the first PSW, then AND the two masks. A=FF iff both bytes are zero. B=C=first mask; DE/HL preserved. Final ANA flags remain independent outputs. Only the derived PSW residue is written below the entry SP.
- **+25D6 [25D6,25EC):** publish C at A65C, read both A65C/A65D, pass only low C to existing +23A0 with E10 while retaining D. Use the minimum as a fresh direct index into byte[42DC+j]. Returned A is that byte, BC=j, HL=42DC+j, DE=entryD:10; NZPA/AC are the minimum's comparison flags, CY is the final DAD result. The observed 1→4 and 2→7 values are reads, not a fitted equation.
- **+834F [834F,8357):** low byte at DE OR L; increment DE modulo65536; high byte at updated DE OR H. Return A=high OR, updated HL/DE, preserved BC, and high-ORA flags. Exact B5/B4 encodings distinguish OR from addition; no data writes or body CALL/PUSH.
- **+22C0:** compose +21D4 then the actual RAR. Natural FF with incoming CY0 rotates to7F/CY1 and reaches the shared RET. The unobserved clear-bit literal arm remains RAW.
- **+2C53:** C1→+28AA then return the actual child state. No new acquisition semantics are invented in this wrapper.

The first three leaves have stable bounds/complete local graphs/complete low-level contracts at declared noninterference scope. The wrappers and larger parents retain partial contracts.

## +2C59 and the required substantial boundary

+2C59 [2C59,2DC3) has **290/362 represented bytes**. Acquisition through +2C53 occurs **before** paired A634/A635 and selected A628+index reads. +21AD then supplies the actual rotated predicate. All eleven local paths observe index2, selected15 and base15, taking the represented guard-skip route. Fresh selected/base masks preserve PUSH PSW/POP B, ANA/ORA/RAR chronology; no local nonstack publication occurs. This does **not** mean the acquisition child leaves memory untouched.

The final fresh base comparison with16 sets S1/Z0/AC0/P1/CY1. A=fresh base15, BC=A628, HL=A62A, DE remains the acquisition/classifier channel. Acquisition returns0A or17 in these windows, independently of the parent's returned15. No tuple or snapshot selects semantics.

Pass38's five +3304 windows are linked by exact child CALL steps and returned states. Four require +2C59; their +28AA entry selects **02**, then changes that selected field to15 and publishes its pointer/control/auxiliary state before +2C59 rereads it. The second +2705 and final +329F run afterward, independently, with the freshly transformed fields. One +3304 call skips +2C59 because its second field already equals the base; this distinction is retained.

The existing +28AA contract established the selector05 copy/construction route. It cannot stand in for the required **selector02** route. Ten accumulated selector02 windows (including independent callers) call +6708 with E02 and C1 or C2, actually entering **+67BE**, then use existing +8380 and newly established +834F before publication. The observed alternate child contains six direct arithmetic helpers (+8309/+8380/+8396/+83A3 and resident +1A38/+1A43); a representative call spans308 historical instructions. Its existing eight-byte software argument-consumption/continuation proof is reused exactly. The alternate algorithm, returned channels and termination are a substantial boundary, not an already established E05 law. Its instructions remain unpromoted here.

The target packet keeps this dependency's entry/return states, child chronology and writer hashes as an **interface**, not a replacement algorithm. Unrelated selector05/global RAW alternatives need not be completed to reproduce the required selector02 scope.

## Parent impact and next step

+30C1's blocker is closed at the demonstrated scope. +2C59's local graph is explained, but the **whole +30C1/+2C59 requirement is not yet closed**: +3304 still needs +28AA selected02/+6708 alternate67BE. Therefore +3304, +4F54, +500F/+506E and +5E98 remain non-native-ready. Keep +21D4/+25D6/+834F and bounded +22C0/+2FC2/+30C1 in the deferred native-ready queue; do not migrate leaves separately.

Rank the required causal obligations: first +28AA selected02/+6708 alternate67BE, then input acquisition +784E, then +5929's actually used opaque +46A7. +256C's demonstrated local composition is already established and all its children are now native; its global partial status is **not an additional archaeology blocker**. +5929's unexecuted selector alternatives likewise need not be completed, but its required +46A7 and +784E operations do. Add bounded +256C composition to the deferred queue. **+784E is not the sole blocker.** Recommend Pass40 reconstruct the selected02 acquisition/arithmetic/publication subtree as one unit, reusing complete arithmetic children and closing small leaves. Pass40 must also establish the next full-regression checkpoint.

## Fidelity and validation

**712 RAW bytes become UNDERSTOOD**, with eight new ProcedureHypotheses. No established catalog contract is corrected or widened. Fresh paired reads, independent equal-valued sources, wrapping operations, same-valued writes, comparison flags and CALL/PUSH last writers are mechanically checked. Aliases remain restricted by inherited code/carrier/cache/publication/stack scopes; no table capacities, ownership or PL/I types are inferred. Zero new historical-binary queries were needed.

Incremental validation results and elapsed times are in `validation.json`. It lists each executed category and the exact deferred Pass38 checkpoint categories. No trigger for a full wave occurred: no CPU/Runner/CP/M/native change, schema change, established shared-contract correction or unexplained cross-boundary regression. The development test's sole format error was the legacy object-only JSON loader applied to a new list report; the report now uses the normal JSON parser. No archaeology correction, pragmatic divergence or fidelity debt is introduced.

Final incremental validation passed **58 Python tests** (Pass39:19, Pass38:19, V1:9, verifier:11), cheap `dune runtest`, exact reconstruction and diff checking. Two aggregate commands used two read-only workers after serial Dune work. Wall time: **83.058 seconds**; reconstruction: **11.408 seconds**. Category times: Pass39 40.178s, Pass38 48.104s, V1 17.232s, verifier tests 22.818s, Dune 0.599s, diff check 0.030s. The exact **55 deferred checkpoint categories and commands** are listed in `validation.json`, including unrelated MINIMAL/Pass13–15/native experiment suites and packet/continuation. Ordinary Dune content-hash scheduling is retained; no forced rerun of unchanged stanzas is claimed. All four historical images reconstruct **94,720 bytes exactly**; old contracts/evidence seeds and stable labels are preserved.
