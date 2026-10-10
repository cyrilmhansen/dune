# Pass61 — three true parents of canonical +73D0

Baseline `d19ce2f2012109802f968630b4cec45716b6a807` is published Pass60. Pass59 remains the current FULL checkpoint. This pass is INCREMENTAL; no CPU/Runner/CPM or shared-schema trigger occurred.

## Selected operations and natural topology

The selected real entries are PLI2.OVL+742A `[742A,7434)` (10 bytes), +8258 `[8258,829C)` (68 bytes) and +82B5 `[82B5,82DD)` (40 bytes). +825E/+82BA are internal CALL sites, not roots. Corrected logical/external counts are respectively 3/14/3, 1/11/1 and 1/1/1 across MINIMAL/FIZZBUZ/PICTURE; all 36 primary calls are external before this pass. Natural returns are +7433/+829B/+82DC. No overlapping natural entry was found. Callers and entry register distributions are retained in inventory-summary.json. FACTOR adds 9/3/1 independently shadowed parent calls. Prior FACTOR/OPTIMIST catalog coverage totals are preserved.

These are three distinct operations sharing canonical primitives, rather than one parameterized law. +742A resets carriers, publishes FFFF, and returns a fresh position. +8258 captures an input word and output position for field emission. +82B5 initializes/reset several carriers and emits a fixed zero field. Shared +73D0 and +7423 do not make their input/state/output laws isomorphic.

## Exact laws and newly reconstructed helpers

+7423 `[7423,742A)` (7 bytes) sets HL=FFFF and SHLD writes low FF then high FF at ADA6/ADA7. Flags and other registers are preserved. Natural primary counts 5/26/5, FACTOR 13; all callers lie in the three selected parents. Its local bounds/CFG/contract are complete. +79A2 `[79A2,79AE)` (12 bytes) writes zero to AE04, then AE05, then AE06; final HL=AE06, flags and other registers preserved. Primary counts 1/1/1, FACTOR 1. The following independent +79AF is excluded. Its local bounds/CFG/contract are complete.

+742A calls canonical +73D0, calls canonical +7423, then freshly LHLD1C2C and returns. Registers/flags come from actual child state, except HL receives the fresh position. Bounds stable, local CFG complete, contract partial over child/alias scope.

+82B5 publishes ADAA=1, invokes canonical +73D0 to clear ADAA/ADAB[0..7], writes the word ADA8/9=0, supplies BC=0 to canonical +7434, invokes +7423, zeros ADC9 then ADCA then AE6A, and invokes +79A2. It preserves ordered same-valued publications. Final HL=AE06; flags and other registers are actual adapter results. Complete natural child sequence: +73D0, +7434, +7423, +79A2. Bounds stable, local CFG complete, contract partial over canonical output/alias scope.

+8258 saves B atAE67 before C atAE66. After canonical +73D0, fresh 1C2C is captured with low/high SHLD toAE68/69. An independent paired input reread is incremented modulo 65536 and supplied as BC to +7434. Fresh 201D RAR tests bit0; all 13 primary and three FACTOR calls take the clear branch. Another paired AE68 read supplies captured position to +7630; another independent read supplies it to +7434. +7630 increments position twice, while the final +7434 republishes the captured position. +7423 publishes FFFF before RET. Complete natural chronology: +73D0, +7434, +7630, +7434, +7423. No required natural child remains opaque. Bounds stable; local CFG and contract partial because the 17-byte arm `[8277,8288)` is STATIC/UNOBSERVED and RAW. Exact static CALLs there are +745A, resident +03F4 with literal BC94E5, and resident +0466 after a fresh saved-position read. This listing/output alternative rejects staging; it is not fabricated as natural coverage or promoted.

## Independent proofs and stack

Every primary parent, +7423/+79A2 component and useful canonical +73D0/+7434/+7630 call independently matches registers, flags, SP/PC, ordered logical writes, all 65536 RAM bytes, stack last writers, child CALL chronology, DMA, filesystem and record/service chronology. Canonical +119E/+1140 children inside selected windows have separate shadows: 15/125/15 serializer and94/784/94 writer calls. Exhaustive natural per-call journals and intermediate local/child checkpoints stay under ignored `_build/host-compiler-pass-61`. Their hashes are durable in shadow-summary.json.

Two targeted +8258 discriminants per primary call use BC=FFFF (input increment wraps to0) and BC=7F2A with captured position 1234. The existing concrete CPU independently executes original instructions and children; full registers/flags/RAM/ordered writes and stack writers match. No synthetic BDOS services occur. These 26 cases prove state-driven arithmetic and distinct saved-word/position carriers without source/caller dispatch. They do not cover or promote the listing arm. Rejection checks include201D-set, code/caller/continuation corruption, stack aliases, writer scope and new publication/sentinel aliases; copied staging rejects before live mutation.

There is no private frame. Original CALL word remains at entrySP. Each local CALL writes resume high atSP-1 then low atSP-2; children may leave deeper historical residue. RET reads original low/high and gives SP=entrySP+2 and original continuation. Canonical descendants preserve their actual hardware/PUSH/POP frames. Per-call last-writer journals prove surviving stack bytes; no new software continuation mechanism is introduced.

## Hierarchy, hybrids and actual leverage

| Source | Pass60 → Pass61 guest | Removed | Host before → after | Outer roots |
|---|---:|---:|---:|---:|
|MINIMAL|300335 → 300032|303|98 → 99|5|
|FIZZBUZ|568781 → 567517|1264|255 → 247|26|
|PICTURE|346881 → 346578|303|88 → 89|5|

Each +8258 replaces two +7434 roots and one +7630 root: host delta -2 percall. +82B5 replaces one +7434 root: delta0. +742A adds one boundary percall because canonical +73D0 was not globally intercepted. Total host deltas +1/-8/+1 are measured, not inclusive-window estimates. Absorbed +7434 totals3/23/3 and +7630 totals1/11/1. Internal primitive calls include +73D0 (5/26/5), +7423 (5/26/5), +79A2 (1/1/1), and exact adapter descendants. Suppression uses corrected outer windows only. All external +73D0 calls disappear:0/0/0. +119E remains36/36/43; no global serializer interceptor was introduced.

Standalone and cumulative hybrids pass exact REL goldens, full REL/INT record chronology, filesystem, console, PASS1/PASS2/END, BDOS ordering/counts and warm boot. Hashes: MINIMAL 7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119; FIZZBUZ 68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203; PICTURE c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1. Machine-readable hybrid summaries include complete record hashes.

## Archaeology, extraction and next boundary

Promotions: RAW→UNDERSTOOD 120; DECODED→UNDERSTOOD 0; STRUCTURED→UNDERSTOOD 0. All 120 promoted bytes are naturally OBSERVED; no STATIC/UNOBSERVED bytes promoted. +8258 represents 51 of 68 bytes. Existing canonical children are unchanged. Exact reconstruction remains 94720 bytes. Oracle queries 0. No historical correction or pragmatic divergence. The draft INX increment was explicitly wrapped before the synthetic proof; this is an implementation correction. Fidelity debt remains the unobserved listing arm and inherited unsupported writer/error/wrap/alias states, all fail closed.

Semantic-extraction.json documents distinct state reset/publication/captured-position operations separately from scratch addresses, paired reads, bit gate and stack/flag machinery. No faithful-code refactor or MIR/API design occurred.

One-level ancestry shows +742A in compiler dispatch +1FB5 or +259B; +8258 in +1FB5. Startup +82B5 is called at +0457 without a matched enclosing ordinary procedure. These introduce separate compiler semantics, so no widening. Residual +7314 callers +7352/+7361 both belong to real +7338, with3/11/4 calls; rank this next against distinct +829C field-generation and +82DD lifecycle parents. Serializer callsites +82A6 belong to +829C; +82E1/+82F0 belong to +82DD. They remain separate and unabsorbed. Pass62 is the next ordinary FULL checkpoint after semantic closure.

Packet: 25868 bytes. The deterministic driver automates fresh entries/call discovery, component/root proofs, route and checkpoint grouping, hierarchy, hybrids, cross-evidence, residual maps, contracts, report generation and incremental validation. Interactive call count is not instrumented. validation.json records category/test/stanza/worker/timing/rerun results. scripts/view-optimist.sh is untouched.
