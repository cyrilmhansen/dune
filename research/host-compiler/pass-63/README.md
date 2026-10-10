# Pass63 — structure-derived representation emission

Baseline: `692a4da420409e14970e94754067a33532f41adc`, verified as the published scalability commit. Pass62 remains the last certified FULL epoch (92 historical categories,643 Python tests,39 Dune stanzas,2932.110 wall seconds,zero reruns,94720 bytes). This is a bounded local semantic extension; no FULL trigger fired and historical-full was not executed.

## Bounds and natural evidence

PLI2.OVL+829C has exact extent **[829C,82B5),25 bytes**, ordinary RET at +82B4. All25 bytes are naturally OBSERVED; no overlap/alternate entry occurs in the corrected windows. Primary logical/external roots are **1/1/1**, all called at +19A7 inside true parent +18B3, continuation runtime3BAA. FACTOR and OPTIMIST each add one independently shadowed natural root. Full entry/return states, ordered reads/writes and pointer/payload values are in [natural-provenance.json](natural-provenance.json) and [cross-evidence.json](cross-evidence.json).

Primary pointers are FBE1/FBC9/FBAF; low/high payloads are 07/00,12/00,0B/00. Equal high bytes are not treated as provenance proof.

## Exact law

LHLD ACA3 reads ACA3 then ACA4 into L/H. SHLD AC9F publishes low then high, including same-valued writes. This is a **direct pointer-word copy**, not a dereference through ACA3. E=7,C=94H invokes canonical resident119E at +82A6. Seven MSB-first RLC/append steps emit bits7..1 of94H: **1001010**; bit0 is not emitted.

After the header child returns, LHLD AC9F freshly reads AC9F then ACA0. Two INX H instructions advance modulo65536 to pointer+2, MOV C,M acquires the low payload byte, another INX H advances to pointer+3, and MOV B,M acquires the high byte. Canonical resident11C3 at +82B1 receives that BC word and emits tag00,low8,high8. The total representation is25 bits. Pointer+0/+1 are not read. No source-language or LINK-80 item name is established.

The local instructions preserve flags. Header/writer/serializer children replace flags according to their certified contracts; INX does not expose DAD carry. Final A=0,HL=20B8,E=8 and NZPA/CY come from the final counted-bit child; BC/DE are the actual child channels, not restored entry registers. RET preserves them.

## Proof and supported scope

All three primary roots and both cross-source roots independently compare all registers/flags/SP/PC,ordered writes,full65536RAM,stack last writers,child chronology,DMA/filesystem and record/service state. Each primary has four independent119E component shadows (one header plus three word segments) and one11C3 shadow. Naturally executed bit-writer subtrees are covered transitively and Pass52 supplies independent writer/flush regressions. No established child algorithm was duplicated or globally intercepted.

Twenty-seven synthetic cases run original concrete CPU instructions independently with full state/RAM/write/stack comparisons: distinct low/high bytes; independently varied stale AC9F carrier; low-only and high-only changes; irrelevant neighbor changes; independently changed pointer low/high; page crossing; FFFC nonwrapping target. Three more cases start at output byte127/bit7 and independently verify25-bit packing and exact flushed record bytes. Synthetic state variants are DEDUCED/STATIC/UNOBSERVED; they add no new instruction bytes or natural coverage. Incoming AC9F=1234 differs from the source and is overwritten before its post-header reread. Unsupported FFFD/FFFF wrapping,code/child-code,continuation,stack,source/publication/output/sentinel aliases reject during staging. Copying/preview never mutates live RAM/DMA/filesystem/events before full acceptance.

## Stack and child correlation

No private frame exists. Original CALL from19A7 writes continuation3BAA at entrySP (naturalFFF6), high then low. Header CALL82A6 writes A4A9 below SP; payload CALL82B1 later overwrites those slots with A4B4. Canonical11C3/119E/1140 CALL and PSW/service frames remain historical. Last-writer journals compare every surviving stack byte; final RET returns to3BAA with SP=entrySP+2. Original continuation bytes remain untouched. Per-instruction natural checkpoints and synthetic CPU checkpoints remain under ignored `_build/host-compiler-pass-63`.

## Hierarchy and measured whole-run effects

|Source|Pass62 → Pass63 guest|Removed|Host before → after|
|---|---:|---:|---:|
|MINIMAL|299837 → 299516|321|102 → 102|
|FIZZBUZ|566802 → 566481|321|258 → 258|
|PICTURE|346318 → 345997|321|93 → 93|

Each accepted outer root replaces exactly one formerly external11C3 root: net host delta0 in every source. Each internalizes one direct119E,three tagged-word119E and25 bit-writer calls. Remaining external119E is **35/35/42**, with the82A6 caller class gone. Remaining external resident-family classes and other generation calls are retained in [topology-summary.json](topology-summary.json); suppression is confined to corrected root windows. Ranking sums are not used as savings.

Standalone and cumulative hybrids preserve exact REL hashes,complete REL/INT record chronology,filesystem,console,PASS1/PASS2/END,BDOS order/counts and warm boot:

- MINIMAL:7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119
- FIZZBUZ:68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203
- PICTURE:c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1

## Archaeology and future boundary

RAW→UNDERSTOOD25;DECODED→UNDERSTOOD0;STRUCTURED→UNDERSTOOD0. Naturally OBSERVED25,static-only instruction bytes0. Bounds stable,local CFG complete,general contract partial over explicit nonwrapping/nonalias child scope. Prior FACTOR/OPTIMIST catalog totals are preserved. Historical reconstruction remains94720 exact bytes. Oracle queries0. No historical correction,implementation correction,pragmatic divergence or shared/runtime schema change; fidelity debt is bounded alias/wrapping scope and unproved higher compiler meaning.

[semantic-extraction.json](semantic-extraction.json) separates observed pointer-derived representation emission from scratch/LHLD/INX/register/stack mechanisms. The possible modern name remains HYPOTHESIS. No MIR API or faithful-code refactor.

[next-boundary-ranking.json](next-boundary-ranking.json) compares82DD,7ED6 and discovered ancestor18B3 using post-Pass63 hierarchy. **Recommend82DD for Pass64 assessment**: coherent but separate lifecycle/finalization output.7ED6 is a broader generation policy;18B3 has extensive independent structure/traversal children and is deferred. No upward widening occurs.

## Validation workflow

Pass63-local proofs are exhaustive for supported natural/synthetic scope. ACTIVE core plus explicit extras **pass63,pass52** is the final aggregate. Pass52 is directly justified by119E/11C3/1140 contracts and successful flush scope; no unrelated archived category is selected. Pass63 is registered for future historical-full but is not part of permanent active core. All92 Pass62 categories,infrastructure self-test andPass63 remain selectable; this is a category-set proof,not an executed FULL checkpoint.

```sh
python3 tools/annotated-assembly/run_structure_field_generation_pass_63.py validate
```

This invokes active with explicit extras and writes [validation.json](validation.json), always ACTIVE/INCREMENTAL with last certified FULL epochPass62. Actual aggregate category/test/time metrics are recorded there after execution. Reports/catalog/progress/packet are finalized before launch. The ordinary next FULL target remains approximatelyPass67 unless a real trigger fires.

Packet:18989 bytes. Driver phases:discovery/inventory,contracts,components/prove,cross,topology,ranking,reports,focused checks,active validation. No interactive call counter is instrumented. User-owned `scripts/view-optimist.sh` and unrelated untracked files are untouched. No task temporary directory under `/tmp`; transient proof directories under `_build` are cleaned.
