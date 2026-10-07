# Pass44: bounded reentrant native +6223

The canonical `Pli80_host.Reentrant_acquisition` now composes both demonstrated
routes. Route B reuses native `Acquisition_parent` (+5929), a fresh canonical
classifier, ADI13 and +2511. Route A composes +620C/+61A4 and the five-byte +60E5
frame through `Acquisition_family`, preserving +5E98 field15 cleanup and field80
acquisition/reentry. The same +6223 operation handles recursive +625D calls.
No child is an independent Runner transition inside an outer root.

All 21 logical invocations match independently: MINIMAL1, FIZZBUZ18, PICTURE2.
The 15 outer roots are1/12/2. Six FIZZBUZ internal reentries have maximum observed
depth2. Logical routes are B13, A-processing5, A-early3; outer routes are B10,
A-processing2, A-early3. Successful recursive checkpoints additionally compare
actual host-composed entry/return RAM, registers/flags, journals/depth, DMA,
filesystem and services with the independent logical shadows.

Seven field15 and three field80 +60E5/+5E98 pairs match at both boundaries.
Field80 preserves the two distinct +6619..+625D reentries, +3304's state
transformation, selector02 +28AA, +6708 E02 decimal algorithm and N=8 software
continuation. +500F returns the actual +4CD4 result separately from its literal1
publication at A932; +506E freshly rereads that publication. No artificial
recursion/iteration guard, fixture dispatch or oracle-derived result is used.

The first genuinely missing causal contract was the resident +1376 digit-selected
route beneath the second +4F54 acquisition. The user authorized its narrow
extension. Three natural contexts31/33/35 are hexadecimal bytes at20C1 (ASCII
'1'/'3'/'5'), not selectors. Prefixes31,35 /33 /35, widths2/1/1 and modulo16
accumulators6/3/5 retain following29. Independent resident shadows and corrected
witness rederivation prove the exact selector02, counted reads, prefix writes,
CMA/RAR termination and A7F return with independent flags. Zero oracle queries.
39 reached RAW resident bytes are newly represented. Global +1376 remains
provisional/partial/partial. This extends Pass41; it does not correct its facts.
All16 Pass41 tests remain valid with explicitly preserved catalog epochs.
See [numeric-contract.md](numeric-contract.md).

The compatibility planner derives hardware CALL/PUSH/private-frame writers from
immutable bytes and current staged values. It preserves constructor N=2 and
numeric N=8 as separate software protocols; N=8 copies the original continuation
to entrySP+8 and returns at entrySP+10 while preserving the caller PSW. Final
stack bytes are compared with historical last writers; none come from oracle
post-RAM. The existing generic copied RAM/process/filesystem transaction stages
all nested host programs and real CP/M services. CPU, Runner and CP/M are unchanged.

Standalone +6223 and cumulative hybrids match all INT/REL record sequences,
file events, final filesystem and markers/warm boot. Cumulative actual guest
instructions are425324 /1005906 /496062, compared with Pass43's425454 /1029607 /
498198: savings130 /23701 /2136. Host transitions change126->125 /586->445 /
159->148. Native BDOS26/21 totals remain1/1,3/3,1/1; DMA/FCB/record behavior comes
from the existing runtime. No synthetic guest Steps or t-states are generated.

Unsupported gates/selectors, global RAW alternatives, numeric decimal/exponent,
refill/EOF/reuse, arbitrary aliases and unproved termination stay fail-closed.
Preparation negatives and corrupted proof tests leave live RAM/DMA/filesystem
unchanged. Archeological scope extension: yes; historical correction: none;
pragmatic divergence: none; fidelity debt: none.

Compact durable reports include logical/outer cases, interned stack patterns,
operation trees, hierarchy, services and fidelity. Full journals and snapshots
remain ignored under `_build/host-compiler-pass-44`. The model-facing packet is
under32KiB. The required full checkpoint replaces the initial incremental plan
because +1376's supported contract was extended. See [validation.json](validation.json).
The unrelated `scripts/view-optimist.sh` remains untouched.

Pass45 should assess a bounded external +6619 wrapper-chain composition around
native +6223, rather than independently migrating the now-internal acquisition
family. Fresh external-route proof remains required; unobserved search/selector
arms must stay explicit. See [boundary-assessment.json](boundary-assessment.json).

Full checkpoint:73 categories,477 Python tests,37 Dune test stanzas, four workers,
810.041 seconds. One19-test Pass42 rerun passed after its catalog-epoch assertion
was pinned to the preserved pre-extension contract. All other categories passed
on the first checkpoint run; reconstruction remains exactly94,720 bytes.
