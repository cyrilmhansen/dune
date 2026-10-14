# Pass105 — reuse scoped native gateway staging

Baseline HEAD and origin/main both matched `42b37ef23023f92622c28ac05e2a61b867eae8b4`. One existing controller at41B5 still selects k23 → k123 → k33 → k216 → guest. The accepted domain and guest instructions are unchanged.

## Narrow executable change

`Scanned_gateway_dependencies.assess33` and `K216_gateway_transaction.assess` retain the original complete copied preparation and exactly the same explicit scope-exception lists, returning `Some prepared` on success and `None` for the original declines. Their existing boolean eligibility interfaces delegate to these assessments. No historical instruction body, canonical child law or shared transaction interpretation changes.

For new k33/k216 candidates only, `Native_resident_output.controller` retains that already computed operation. Its binding captures full entry registers/flags/PC/SP, all64KiB RAM, filesystem and DMA, original previous hardware CALL/Step and canonical image origin before copied assessment or selection observers. The controller owns one bridge whose historical images are copied at creation. Before reuse it checks the complete binding and re-verifies CALL ancestry. The operation belongs to one applicability attempt: a new attempt clears the previous choice and successful host-program handoff clears it. There is no cross-invocation cache or oracle-based choice.

Original k23/k123 selection and preparation paths remain unchanged, including their original snapshot guard. A `reuse_staging:false` measurement control follows the historical four-domain selector, original snapshot guard and fresh preparation. The normal four-domain mode reuses staging by default; no caller flag is required to enable the optimization.

Reuse does **not** bypass any oracle or commit check. Complete entry/postCPU and RAM oracles, ordered logical/compatibility journal validation, original program validation, final staged preview, filesystem/DMA/service/record expectations and atomic host-program application all remain. Effects are computed from current historical state by the original operation, never copied from oracle outputs. Same-valued writes, frame residue and hardware/software continuations are preserved. Unexpected proof errors still propagate; no blanket exception-to-guest handler was added.

## Repeated native execution timing

Primary measurements use one binary/input/Execution-analysis configuration, seven paired sequential native runs per source, alternating which mode runs first. Oracle acquisition and controller construction are outside execution timing; detailed chronology snapshots, phase diagnosis and negative tests are also outside these timing windows. No other task validation ran concurrently. External machine load remains uncontrolled, so ranges and all individual samples are retained in `performance.json`.

Times are seconds: median [minimum, maximum].

| Source | Pass104-path control | Reuse staging | Actual guest instructions | Native / guest gateway roots |
|---|---:|---:|---:|---:|
| MINIMAL | 0.266728 [0.259382, 0.314836] | 0.266606 [0.261113, 0.286482] | 440,293 | 1 / 10 |
| FIZZBUZ | 0.764900 [0.735851, 0.776618] | 0.762788 [0.750810, 0.788561] | 1,123,194 | 13 / 48 |
| PICTURE | 0.316416 [0.312146, 0.328003] | 0.317341 [0.313715, 0.322703] | 516,314 | 1 / 11 |
| FACTOR | 0.569580 [0.559209, 0.571979] | 0.553907 [0.544134, 0.578437] | 821,952 | 6 / 26 |
| OPTIMIST | 1.840930 [1.832973, 1.869171] | 1.765005 [1.752440, 1.795883] | 2,496,035 | 9 / 106 |

OPTIMIST's median falls75.925ms (about4.1%); every paired OPTIMIST sample improves and the ranges do not overlap. FACTOR's median falls15.673ms (about2.8%), with overlapping ranges and five of seven paired improvements. MINIMAL/FIZZBUZ/PICTURE show no convincing change. This is an improvement in the actual `Native_dispatch.run` execution path, not merely faster oracle acquisition. It is limited to this Execution-analysis environment; it does not establish a universal compiler speedup or remove the whole Pass104 overhead.

As a backstop, the pre-edit Pass104 executable was preserved under ignored_build with its SHA256 and ran the original sequential concrete/Pass87/Pass103/Pass104 campaign three times. `exact-baseline.json` retains those medians/ranges and raw receipt digests; root/final identities and counters agree. That older driver hashes accepted entry RAM during execution, unlike the minimal timing observer in the paired driver. Its absolute difference against the candidate must not be attributed solely to staging. The same-binary paired control is the causal comparison.

## What dominates and what remains

Separate natural-root phase samples, milliseconds:

| Root | Complete copied assessment | Fresh duplicate preparation | Cached handoff | Mandatory final preview | Logical digest |
|---|---:|---:|---:|---:|---:|
| FACTOR k33 | 12.731 | 19.697 | 0.019 | 0.015 | 0.072 |
| OPTIMIST k216 | 70.419 | 65.257 | 0.030 | 0.409 | 0.565 |
| OPTIMIST k33 | 15.032 | 13.264 | 0.034 | 0.018 | 0.084 |

The expensive success path was computed twice. Reuse eliminates the second complete copied transaction, while context checks and the final preview/oracle checks remain. Boundary-view timing also samples exposed RAM/filesystem copies and inclusive nested preview time. Those fields cover assessment, separate fresh preparation and final preview together; they are not disjoint costs to add to execution time. They do not expose every internal copy or local64KiB materialization loop. Internal canonical work, repeated full-state reconstruction and guards remain substantial; the samples do not constitute an allocator profile. Controller/oracle construction timings are separately recorded; runtime oracle validation remains mandatory.

Failed probes sampled by replaying actual naturally declined entry states once, outside runtime timing:

| Source | Declined invocations | Failed k33 ms | Failed k216 ms |
|---|---:|---:|---:|
| MINIMAL | 10 | 13.834 | 10.795 |
| FIZZBUZ | 48 | 48.618 | 47.522 |
| PICTURE | 11 | 11.685 | 10.355 |
| FACTOR | 26 | 27.230 | 27.429 |
| OPTIMIST | 106 | 116.921 | 109.576 |

These rejected-domain costs remain. A simple canonical-index or descriptor prefilter is **not installed**: the existing full probe executes canonical child code/alias guards before rejecting an unrelated index. Each source has an independent naturally declined-entry discriminant where corrupt resident+1272 code must propagate `acquisition family bridge: resident code changed 1272`. Both original and candidate retain that exact failure. Early index rejection would silently hide it. A safe future optimization must preserve/share the ordered validated prefix and its full guard/error semantics; duplicating guard lists or refactoring canonical execution is outside this narrow change. This is the precise remaining FIZZBUZ/PICTURE/MINIMAL boundary.

## Fidelity and failure evidence

Five fresh concrete references acquire the original Pass104 oracles. Detailed old/new native executions compare the complete accepted **and declined** entry chronology: route, CPU/flags, full RAM, filesystem and DMA. Every accepted root keeps identical input/output vectors, entry/postRAM, ordered-write digest/count and actual frame ownership. All roots exactly match published Pass104 evidence, so every absorbed nested root remains absorbed by the same parent. Counts remain25 k23,2 k123,2 k33,1 k216,201 guest declines; one chronological stream and30 total live transitions. Existing dispatcher8/8 proof coverage is not eight native roots.

All repeated executions verify root oracles and complete ordered programs, full final RAM, exact REL/INT, filesystem, file/record order, console/compiler messages, termination/warm boot and guest/native service behavior. Final CPU equality follows exact root post-state plus deterministic identical guest intervals/suffix; no final-CPU API was added. Historical direct/inherited read laws are unchanged. The copied staged program is also compared directly with a fresh operation's CPU, full journal, logical writes and every ordered host effect.

Focused new negatives cover changed full entryRAM after selection, PC/SP/flags, filesystem/DMA, image/CALL ancestry, malformed hardware continuation, descriptor/predicate restrictions, repeated assessment, accepted late-child errors, failed staged preview and same-boundary recovery. Missing/incorrect/reordered oracles fail without live RAM/filesystem/DMA mutation. Existing Pass87/103/104 tests preserve their installed late preparation, post-state/RAM/journal failure and fresh-controller recovery checks; the original partial-controller fixture retains same-controller transient retry semantics. A new scope attempt always reassesses, rather than trusting a stale preparation.

## Validation and preservation

Focused pass105/pass104/pass103/pass87/pass93/pass102 plus mandatory build/project/diff-check/validation-runner-tests: **10/10 passed**,36 Python executions, four workers,70.315s wall/199.770s summed. The actual receipt is preserved byte-for-byte. Pass93/102 are included because their eligibility wrappers changed; their instruction laws did not. The category uses three repeated pairs without a timing assertion, so normal runtime variation cannot invalidate historical fidelity. Published performance claims use the separate seven-pair run.


All five REL/INT goldens remain exact; FACTOR REL is `9a42e8341a013243036040c8db0e56939c699c7fbbfb20878f7ba5af8d6b470d`. Reconstruction remains94,720 bytes: all current images match recorded hashes, annotated reconstruction sources have the unchanged Git tree, and the existing fresh Pass103 verifier receipt remains valid for identical inputs. No annotations changed and no V1 regeneration was required. Knowledge promotions and new native domains/coordinates:0.

Generic Native_dispatch, Runner, CPU8080, CP/M/BDOS, bridge instruction semantics, historical transaction bodies, installed applicability domains and oracle ordering remain unchanged. Older Pass87 test-generated report rewrites were restored byte-for-byte from pre-validation copies; all earlier evidence/certificates and Pass79 failures remain preserved. Protected user files and unrelated changes are untouched. No task-owned/tmp directories, FULL execution/scheduling/waiting or certification changes. Pass74 remains the last certified FULL epoch3 and does not certify this descendant.
