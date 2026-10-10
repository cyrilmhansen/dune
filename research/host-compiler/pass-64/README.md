# Pass64 — representation trailer and console word output

Baseline: `2cf8fa26f42c51eea1755438f11a4e110e9821d4`, verified against published origin/main. **Pass62 remains the last certified FULL epoch.** Historical-full was not executed and no FULL trigger fired. CPU8080, CP/M, Runner and shared journal/capture interpretation are unchanged.

## Bounds and natural evidence

PLI2.OVL+82DD has stable extent **[82DD,8340), 99 bytes**, ordinary RET at833F and no overlapping natural entry. MINIMAL, FIZZBUZ and PICTURE each have one logical and one corrected external root, called at046E inside true parent0457. FACTOR and OPTIMIST each add one independently shadowed natural root. Full entry/return state, ordered reads/writes and values are in [natural-provenance.json](natural-provenance.json) and [cross-evidence.json](cross-evidence.json).

The natural direct sequence is119E,11E5,119E,11E5,124B,05FF,0466,05FF,0466,05FF,0466. AE6A bit0 is set in every primary root. The alternate tag00 arm is synthetic-only evidence.

## Exact operation

Literal C=9A,E=7 invokes canonical119E and emits bits7..1 MSB-first: **1001101**. Fresh1C2C low/high becomesBC for canonical11E5 (tag40,low8,high8). Literal9C,E7 emits **1001110**. FreshAE6A RAR setsCY to oldbit0 and preservesNZPA. WithBC=0, bit0 set selects11E5/tag40 and clear selects11C3/tag00. Equal zero words retain distinct representations.

124B reads2029 and1D05 bit0 gates. The accepted active-output route repeatedly rereads1D8B and calls1140(C=0) until byte-aligned, then119E(C=9E,E=7) emits **1001111**. It aligns and adds a trailer; it does not close a file. The suppressed2029 earlyRET at1252 remainsRAW and outside accepted staging scope. Later independent1272 still owns file close.

Three05FF calls receive literalBC pointers94EB,94FA,9507. Each prints CR/LF followed by a fresh dollar-terminated string. Three0466 calls print four hexadecimal characters from **fresh1C2C**, **structure payload**, and **fresh1C2E**, respectively. The final source corrects the provisional task decode's1C2C wording; historical behavior is unchanged.

The structure acquisition independently executes LHLDACA3, SHLDAC9F low then high, freshLHLDAC9F, twoINXH, low byte[p+2] toC, oneINXH and high byte[p+3] toB. Same-valued pointer writes and independent rereads remain visible. The Pass63 parent operation is not substituted here. Accepted targets are nonwrapping and exclude code/output/carrier/stack/sentinel aliases.

## Resident dependency contracts

| Entry | Extent | Bounded law |
|---|---|---|
|124B|[124B,1272)|Active output: zero padding to byte alignment, then7-bit9E trailer; no close.|
|05FF|[05FF,0611)|Save B2080 then C207F;05F8;fresh paired pointer ->03F4.|
|05F8|[05F8,05FF)|Canonical05B2 zero-key poll, then03E9.|
|0466|[0466,047D)|Save B2073 then C2072; independent high/low reads ->044B.|
|044B|[044B,0466)|Save C2071;fresh ANI F8/RARx4 high nibble and fresh ANI0F low nibble ->0421.|
|0421|[0421,044B)|Save C2070; compare9; ADI30 or ADI41/SUI0A; publish/reload character ->0390.|
|03F4|[03F4,0421)|Save pointer206D/E; index206C=0; fresh indexed reads,206F publication,dollar comparison,0390,INR index.|
|03E9|[03E9,03F4)|Ordered C0D then C0A calls to0390.|
|0390|[0390,03E9)|Save206B; fresh202A/201E bit0 clear; paired low carrier ->0380. Other arms remainRAW.|
|0380|[0380,0390)|Save206A; fresh paired low byte zeroextended intoDE; C2 ->canonical19BB/BDOS2.|

The new reusable console laws live in `resident_console.ml`. Canonical serializer, bit writer, poll and signature/service gate algorithms are reused. Existing CP/M A/B->L/H return aliasing is preserved. Strings require a nonwrapping dollar terminator within256 bytes and exclude scratch/output/FCB/stack aliases. Listing, redirected output, key-present poll and writer errors remain unsupported. No independent large subsystem was required by the natural operation.

## Proof and transaction

Each primary root independently compares every register and flag, SP/PC, ordered writes, full65536RAM, stack last writers, childCALL chronology, DMA/filesystem and record/service chronology. Per-source resident shadows include124B1,05FF3,0466 3,05F8 3,03E9 3,03F4 3,0390 56,0380 56,044B6 and0421 12, plus independent119E/1140/tag-family correlations. Global caller counts are separately retained in [inventory-summary.json](inventory-summary.json); natural calls outside the selected root are not silently intercepted.

**42 synthetic original-CPU executions**, 14 classes per primary state, distinguishAE6A clear/set/high-only, staleAC9F, independent payload bytes and pointer bytes, irrelevant neighbors, page crossing, maximum nonstack target ending exactly at the protected stack region, independent1C2C/1C2E values, referenced string data and a record-boundary flush. Independent concrete BDOS execution checks console text, service order, record bytes, DMA and filesystem as well as complete RAM/register/flag/stack-write equality. Synthetic-only evidence remains DEDUCED STATIC UNOBSERVED.

Corrupt code/child code, CALL/continuation, unsafe stack, pointer/scratch/output/sentinel aliases, output/listing/file gates and wrapping targets reject before live mutation. The whole RAM/process/filesystem/event transaction is staged before acceptance; a later unsupported child cannot leave earlier emissions live.

No private frame exists. Outer CALL046E writes continuation2671 at entrySP (naturalFFFA). Child CALL words and deeper PSW/signature/service frames retain actual historical writers. Final CALL833C writesA53F belowSP. FinalRET consumes the unchanged outer word, with SP=entrySP+2. Intermediate instruction checkpoints and exhaustive journals remain under ignored `_build/host-compiler-pass-64`, with hashes in [shadow-summary.json](shadow-summary.json).

## Hierarchy and measured effects

| Source | Pass63 → Pass64 guest | Removed | Host before → after |
|---|---:|---:|---:|
|MINIMAL|299516 → 294735|4781|102 → 101|
|FIZZBUZ|566481 → 561768|4713|258 → 257|
|PICTURE|345997 → 341214|4783|93 → 92|

Each new82DD root absorbs two previously external11E5 roots: host delta **-1/-1/-1**. No new resident leaf Runner roots are enabled. Suppression applies only inside exact corrected parent windows. Remaining external119E is **32/32/39**,11E5 is1/1/1,11C3 is zero,124B is zero,05FF is3/3/3 and0466 is zero. See [topology-summary.json](topology-summary.json). Ranking windows are not savings.

Standalone and cumulative hybrids preserve REL/INT record chronology, filesystem, console, compiler milestones, BDOS order/counts and warm boot. Exact REL goldens:

- MINIMAL:7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119
- FIZZBUZ:68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203
- PICTURE:c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1

## Knowledge and future boundary

RAW→UNDERSTOOD **310**:211resident and99parent. DECODED→UNDERSTOOD0; STRUCTURED→UNDERSTOOD0. **304 naturally OBSERVED bytes;6 DEDUCED STATIC UNOBSERVED bytes** in the alternate zero-word arm. Root bounds are stable, local CFG complete, contract partial over explicit domains. Resident0390 remains locally partial and124B1252 remainsRAW. Existing child contracts are unchanged. FACTOR/OPTIMIST catalog totals are preserved. Exact reconstruction: **94720 bytes**. New historical oracle queries: **0**.

[semantic-extraction.json](semantic-extraction.json) separates representation trailer and three-word display from scratch, pointer, nibble, flag and stack mechanisms. Stronger compiler lifecycle/statistics meaning remains HYPOTHESIS. No MIR/API design or faithful-code refactor. Fidelity debt is unsupported listing/key/error/alias/wrapping scope and unproved higher meaning. Development fixes corrected the local BDOS2 resume prediction and initialized independent synthetic DMA correctly; runtime semantics did not change.

Recommend **7ED6 for Pass65 assessment** before large18B3 traversal. Immediate parent0457 introduces a broader compiler phase and is deferred.82DD remains separate from829C. [next-boundary-ranking.json](next-boundary-ranking.json) records post-pass topology and ranking evidence.

## Validation

ACTIVE core plus explicit extras **pass64,pass52,pass63**. Pass52 covers canonical119E/1140/tag-family and successful flush contracts. Pass63 directly regresses the shared bridge/native proof code extended here and the independently established pointer-publication mechanism; its parent algorithm is not called. Pass64 is registered for future historical-full, not permanent active core.

The95-category historical-full selection preserves every92Pass62 category plusvalidation-runner-tests,pass63,pass64. This is a selection-set proof only. Pass62 remains last certified FULL; next ordinary FULL remains approximatelyPass67 unless a real trigger fires.

```sh
python3 tools/annotated-assembly/run_output_lifecycle_pass_64.py validate
```

[validation.json](validation.json) records ACTIVE/INCREMENTAL categories, extras, workers, tests, timings and reruns after execution. Reports, catalog, progress and packet are finalized before aggregate validation. Packet: **27220 bytes**. Driver phases: discovery, inventory, contracts, components, prove, cross, topology, reports and active validation.

User-owned `scripts/view-optimist.sh` and unrelated untracked files are untouched. No task temporary directory was created under `/tmp`; temporary proof directories under ignored `_build` clean up on exit.
