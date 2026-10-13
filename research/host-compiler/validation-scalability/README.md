# Validation scalability, Phase 1

Baseline: `b192213594cd499953cedf42f08fdad3c833e52d` (Finalize Pass62 full checkpoint documentation).

Historical proof, active regression and FULL epochs are separate concepts. Every historical test and receipt is preserved. ACTIVE/INCREMENTAL regression does not certify every archived historical proof. Pass74 is now certified FULL epoch3 after a documented harness-only rerun; Pass72, Pass67 and Pass62 remain preserved historical predecessors. The original Pass74 FULL ran all105 categories, passed102 and failed three historical assertions. Its original receipt and the successful five-category targeted rerun receipt remain separate in the [Pass74 composite certificate](../pass-74/validation-full.json). Ancestry alone does not certify arbitrary future code.

## Commands

From the repository root:

```sh
# Routine regression; add only explicitly affected historical categories.
python3 tools/annotated-assembly/run_host_compiler_regressions.py --profile active --images /home/john/pli/cpm/pli80/DISK1 --output _build/validation-active --workers 4
python3 tools/annotated-assembly/run_host_compiler_regressions.py --profile active --extra-categories pass53,pass62 --images /home/john/pli/cpm/pli80/DISK1 --output _build/validation-targeted --workers 4

# FULL requires an explicit certification decision or user request. Run it only
# from a detached, SHA-pinned worktree as described below; never inline here.

# Selection only, without executing tests or requiring image/output paths.
python3 tools/annotated-assembly/run_host_compiler_regressions.py --profile historical-full --list-categories
python3 tools/annotated-assembly/run_host_compiler_regressions.py --profile active --extra-categories pass53,pass62 --list-categories
```

Plain invocation retains exhaustive behavior. Existing `--categories` retains its legacy subset selection with mandatory build/project stages. It cannot be combined with a profile; active additions use `--extra-categories`. Unknown names fail before execution; duplicates are harmless.

## Explicit FULL certification in a detached worktree

FULL is **not periodic** and is never a blocking validation step for the semantic-development agent. A maintainer explicitly selects a certification milestone (or a user requests FULL), resolves the candidate to an immutable commit SHA, and launches a separate job. Routine ACTIVE/INCREMENTAL and explicit scoped categories remain unchanged. Substantive shared changes can prompt an explicit certification decision but cannot automatically start FULL.

From the main repository worktree, using Bash:

```bash
# Choose the candidate explicitly; resolve it to a SHA before work resumes.
FULL_SHA="$(git rev-parse --verify HEAD^{commit})"
FULL_WT="$HOME/runes-full-${FULL_SHA:0:12}"
git worktree add --detach "$FULL_WT" "$FULL_SHA"
test "$(git -C "$FULL_WT" rev-parse HEAD)" = "$FULL_SHA"
mkdir -p "$FULL_WT/_build/certification"

# Launch asynchronously. Do not wait; resume semantic work in the main worktree.
(
  cd "$FULL_WT" || exit 1
  nohup python3 tools/annotated-assembly/run_host_compiler_regressions.py \
    --profile historical-full \
    --images /home/john/pli/cpm/pli80/DISK1 \
    --output _build/certification/full-validation \
    --workers 4 \
    > _build/certification/console.log 2>&1 < /dev/null &
  echo "Detached FULL PID: $!; candidate SHA: $FULL_SHA"
)
```

Use a **new dedicated worktree and its own `_build` for every FULL run**. Do not reuse a build/cache/capture directory from the development checkout or another FULL job. The image directory is an input; keep it immutable during the run. Detached worktree isolation prevents interference *between* the development workflow and FULL, but not races between categories *inside the same FULL* when old test drivers share paths. Such failures must be repaired or rerun with documented evidence separately; never silently mark failed categories as passed.

After the detached job finishes, the certifier independently reviews its original receipt, category coverage, exact reconstruction, applicable executable identities and any documented targeted reruns. Retain original failed receipts unchanged. A separate certification commit may advance `current_full_epoch` **only for the exact tested commit SHA**; it does not certify newer semantic commits. The semantic agent must keep progressing without polling for or waiting on the FULL job. No additional orchestration or monitoring service is required.

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

Build/project run serially. Later categories use the existing read-only Dune launcher, at most four workers and unchanged category commands. Certified receipt timings only influence start order; missing hints fall back safely and never skip tests.

## Progress and receipts

Whole START/DONE lines are locked and immediately flushed, including serial stages. DONE gives category, completed/total, OK/FAILED and seconds; failures retain useful log tails. A heartbeat appears about 45 seconds after the last completion or heartbeat, with one-second timer resolution. It lists only jobs actually running, excluding queued futures. Per-category logs remain available.

Receipts preserve existing fields and add profile, validation tier, selected/extra categories, worker/count/test metrics and the last certified epoch reference. Active receipts are explicitly ACTIVE/INCREMENTAL; legacy subsets are INCREMENTAL. Only historical-full is labeled FULL, with `all_passed` recording whether execution succeeded.

## Historical preservation and epoch policy

`category-set-proof.json` proves all 92 categories in the successful Pass62 receipt are still selectable. At the Phase 1 infrastructure baseline, historical-full had 93 categories: the 92 preserved categories plus the cheap validation-runner self-test. No historical test, proof or evidence was deleted or rewritten. That was a selection-set proof; the exhaustive suite was not rerun during the Phase 1 infrastructure task.

Pass62 epoch 0 recorded 643 distinct Python tests, 39 Dune stanzas, four workers, 2932.110 wall seconds, 10788.750 summed category seconds, zero reruns and 94720 exact historical bytes. Implementation, receipt and documentation commit identities are recorded in `../validation-policy.json`.

The earlier five-semantic-pass cadence was removed. FULL now occurs **only** at an explicitly authorized certification milestone or on user request, always in a detached SHA-pinned worktree. CPU, CP/M/BDOS, Runner, shared journal/native transaction, proof/capture-interpretation, exact-reconstruction and known-certificate-dependency changes are reasons to consider an explicit certification decision, **not automatic launch conditions**. Pass74 remains the last certified FULL epoch until another candidate has a reviewed, passing certificate. The four-worker runner ceiling is unchanged. No dependency-hash invalidation system is implemented.

## Original Pass63 handoff (historical)

The following paragraph describes the original Pass63-era instructions, including superseded FULL triggers; it is retained as history, not as current scheduling policy.

Assess +829C only in the future semantic pass. Preserve exhaustive Pass63-local shadows/discriminants, run the active core with explicitly selected direct historical dependencies, run standalone/cumulative hybrids, and verify exact goldens/reconstruction. Select dependencies from actual Pass63 evidence. Do not run historical-full unless a trigger fires or periodic certification is due. This infrastructure task performs no new archaeology.

## Validation and change scope

Files changed: the regression runner; its focused self-tests; validation policy; and this report, category-set proof and active receipt. No compiler/native, CPU8080, CP/M, Runner execution or historical-contract semantics changed. No historical pass driver needed adjustment. User-owned `scripts/view-optimist.sh` remains untouched and untracked. Transient outputs remain under ignored `_build`; no task directory was created under `/tmp`.

The single real active execution against `/home/john/pli/cpm/pli80/DISK1` passed initially: **27 categories, 73 Python tests, 39 Dune stanzas, four workers, 123.152 wall seconds and 247.172 summed category seconds**, zero reruns. The 17 focused infrastructure tests also passed, and Python syntax compilation and diff checks passed. Exact reconstruction verified **94720 bytes**; V1, roundtrip tests, packet/continuation integrity and dynamic progress all passed.

Compared with Pass62 FULL at 2932.110 seconds, active took 2m03s instead of 48m52s: **23.81× shorter**, a **95.80% wall-time reduction**. The workloads intentionally differ; this is not an equivalent certification claim. Dune reused its existing build/test cache as usual. No historical-full execution occurred during that infrastructure task. Pass67 was subsequently certified from the external 98-category FULL and complete targeted rerun, with both receipts preserved. `active-results.json` preserves the actual receipt and `summary.json` records measurements. Exhaustive journals/logs remain under ignored `_build/validation-scalability/active`.

Observed progress included `[HEARTBEAT  26/27] active=packet-continuation:01m36s` after all other categories completed, demonstrating that completed and queued jobs do not appear as running.
