# Validation scalability, Phase 1

Baseline: `b192213594cd499953cedf42f08fdad3c833e52d` (Finalize Pass62 full checkpoint documentation).

Historical proof, active regression and FULL epochs are separate concepts. Every historical test and receipt is preserved. ACTIVE/INCREMENTAL regression does not certify every archived historical proof. Pass62 remains the last certified FULL epoch; ancestry alone does not certify arbitrary future code.

## Commands

From the repository root:

```sh
# Routine regression; add only explicitly affected historical categories.
python3 tools/annotated-assembly/run_host_compiler_regressions.py --profile active --images /home/john/pli/cpm/pli80/DISK1 --output _build/validation-active --workers 4
python3 tools/annotated-assembly/run_host_compiler_regressions.py --profile active --extra-categories pass53,pass62 --images /home/john/pli/cpm/pli80/DISK1 --output _build/validation-targeted --workers 4

# Exhaustive certification, when due (not executed for this infrastructure task).
python3 tools/annotated-assembly/run_host_compiler_regressions.py --profile historical-full --images /home/john/pli/cpm/pli80/DISK1 --output _build/validation-full --workers 4

# Selection only, without executing tests or requiring image/output paths.
python3 tools/annotated-assembly/run_host_compiler_regressions.py --profile historical-full --list-categories
python3 tools/annotated-assembly/run_host_compiler_regressions.py --profile active --extra-categories pass53,pass62 --list-categories
```

Plain invocation retains exhaustive behavior. Existing `--categories` retains its legacy subset selection with mandatory build/project stages. It cannot be combined with a profile; active additions use `--extra-categories`. Unknown names fail before execution; duplicates are harmless.

## Active core

The inspectable source of membership is `../validation-policy.json`. Archived expensive pass suites are excluded by default. Historical leaf queries remain included because their Pass62 measured time was only 3.611 seconds.

- `V1`
- `acquisition-parent-unit`
- `attribute-unit`
- `balance-unit`
- `baseline`
- `build`
- `classifier-unit`
- `control-unit`
- `diff-check`
- `dynamic-progress`
- `emitter-unit`
- `gate-unit`
- `historical-leaf-queries`
- `input-unit`
- `mapped-unit`
- `native-emitter-unit`
- `native-unit`
- `packet-continuation`
- `project`
- `publication-unit`
- `range-publication-unit`
- `range-unit`
- `recursive-unit`
- `roundtrip`
- `roundtrip-tests`
- `validation-runner-tests`
- `word-emitter-unit`

Build/project run serially. Later categories use the existing read-only Dune launcher, at most four workers and unchanged category commands. Pass62 timings only influence start order; missing hints fall back safely and never skip tests.

## Progress and receipts

Whole START/DONE lines are locked and immediately flushed, including serial stages. DONE gives category, completed/total, OK/FAILED and seconds; failures retain useful log tails. A heartbeat appears about 45 seconds after the last completion or heartbeat, with one-second timer resolution. It lists only jobs actually running, excluding queued futures. Per-category logs remain available.

Receipts preserve existing fields and add profile, validation tier, selected/extra categories, worker/count/test metrics and the last certified epoch reference. Active receipts are explicitly ACTIVE/INCREMENTAL; legacy subsets are INCREMENTAL. Only historical-full is labeled FULL, with `all_passed` recording whether execution succeeded.

## Historical preservation and epoch policy

`category-set-proof.json` proves all 92 categories in the successful Pass62 receipt are still selectable. Historical-full has 93 categories: the 92 preserved categories plus the cheap validation-runner self-test. No historical test, proof or evidence was deleted or rewritten. This is a selection-set proof; the exhaustive suite was not rerun.

Pass62 epoch 0 recorded 643 distinct Python tests, 39 Dune stanzas, four workers, 2932.110 wall seconds, 10788.750 summed category seconds, zero reruns and 94720 exact historical bytes. Implementation, receipt and documentation commit identities are recorded in `../validation-policy.json`.

A new FULL epoch is required for changes to CPU, CP/M/BDOS, Runner, shared journals, common native transactions, interpretation-affecting capture/proof schemas or material reconstruction mechanisms; modifications to known certificate dependencies without narrower proof; major refactor/release milestones; or periodic certification. Plan the next ordinary epoch no later than approximately Pass67, earlier if a trigger fires. This is policy, not a hard-coded semantic constraint. Phase 1 implements no automatic dependency-hash certificate system.

## Pass63 handoff

Assess +829C only in the future semantic pass. Preserve exhaustive Pass63-local shadows/discriminants, run the active core with explicitly selected direct historical dependencies, run standalone/cumulative hybrids, and verify exact goldens/reconstruction. Select dependencies from actual Pass63 evidence. Do not run historical-full unless a trigger fires or periodic certification is due. This infrastructure task performs no new archaeology.

## Validation and change scope

Files changed: the regression runner; its focused self-tests; validation policy; and this report, category-set proof and active receipt. No compiler/native, CPU8080, CP/M, Runner execution or historical-contract semantics changed. No historical pass driver needed adjustment. User-owned `scripts/view-optimist.sh` remains untouched and untracked. Transient outputs remain under ignored `_build`; no task directory was created under `/tmp`.

The single real active execution against `/home/john/pli/cpm/pli80/DISK1` passed initially: **27 categories, 73 Python tests, 39 Dune stanzas, four workers, 123.152 wall seconds and 247.172 summed category seconds**, zero reruns. The 17 focused infrastructure tests also passed, and Python syntax compilation and diff checks passed. Exact reconstruction verified **94720 bytes**; V1, roundtrip tests, packet/continuation integrity and dynamic progress all passed.

Compared with Pass62 FULL at 2932.110 seconds, active took 2m03s instead of 48m52s: **23.81× shorter**, a **95.80% wall-time reduction**. The workloads intentionally differ; this is not an equivalent certification claim. Dune reused its existing build/test cache as usual. No historical-full execution occurred. `active-results.json` preserves the actual receipt and `summary.json` records measurements. Exhaustive journals/logs remain under ignored `_build/validation-scalability/active`.

Observed progress included `[HEARTBEAT  26/27] active=packet-continuation:01m36s` after all other categories completed, demonstrating that completed and queued jobs do not appear as running.
