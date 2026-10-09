# Pass57 — saved-selector pending-generation policy

Baseline `7bd9ca0a11984e7f618293bb2ab4f2c0d4b79314` is published Pass56/FULL checkpoint. Pass57 is incremental.

Discovery establishes naturally called +7AC4 [7AC4,7AD4),+7AD4 [7AD4,7AE4),+7AE4 [7AE4,7B02). +7AD0 is the CALL79E2 inside7AC4,not an observed entry. +7ABE is an LXI/internal reset block in7AA3,not an observed entry. This corrects search-anchor terminology,not historical behavior. Full execution-owned CFGs/journals are ignored under `_build/host-compiler-pass-57`.

Selected7AE4 has2/21/1 logical and external calls. Save C atAE0A;fresh paired reload includingAE0B andtransfer low before7AC4;independent reread before7AD4;fresh LDA/CPI5 before optional7A17. 7AC4 independently publishesAE08 thenCPI7 andequal79E2;7AD4 publishesAE09 thenCPI4 andequal7A17. Selector distribution and actual child checkpoints are in packet. No caller/source dispatch.

All natural79E2 calls remainAE05=0;no nonzero extension needed. FreshAE04-zero7A17 unchanged. Three FIZZBUZ AE04=1 cases fresh-reread/compare1,call79B6(E4,C C5) then7903,independently readAE05 andcompare2;non2 path publishesAE04=0,then fresh wrappingDCR AE06. DCR produces NZPA;CY survivesCPI2. Parent may overwrite those flags with laterCPI5 on selector4. AE04 andAE05 are independent gates;no speculative global state-machine/item semantics.

7903 savesE/C atAE01/AE00,derives equality6 mask atADCA,freshCPI C1,conditionally rereads maskRAR. C1 with clear mask calls73A7;then independent savedC/E reloads feedcanonical75CE. C1/E6 alternative unsupported. All6 natural cross-cases proved,including3C1/E2 outside selected roots. 73A7 saves indexADC3,compares6,supportednon6 route calls7397 with fresh low index,then fresh LDA/INR andcalls7397 again. 7397 savesADC2,pairedreadsADC2/ADC3,discardsH,addsADAB,publishes0 atactualindexed carrier. Index<8 scope;index6 early73A7 RET remainsRAW/unaccepted.

New/extended contracts:7397,73A7,7903,79B6,7A17,7AC4,7AD4,7AE4. Natural component counts and proofs in shadow-summary.json. Root and independent components compare allregs/flags/SP/PC,orderedwrites,full64KiBRAM,derivedstacklastwriters,childCALLchronology,DMA/FS,record/servicechronology. Original CALL words survive;no private frame invented. Synthetic gates,selectors,wrappingcounter,recordboundary,code/continuation/aliases checked in copiedstaging. Unsupported routes reject without live mutation.

7B99 adds independent indexedADAB/ADB3 transfer through793C;7E05 adds broaderAE36/37,ADAA/202B gates and7314transform. Both deferred rather than constructing an artificial ancestor. 7AA3 separate reset/transfer policy remains guest;its7903 calls provide anti-overfitting evidence.

|Source|Pass56 guest|Pass57 guest|Removed|Host pre → post|Roots|
|---|---:|---:|---:|---:|---:|
|MINIMAL|300501|300443|58|100 → 102|2|
|FIZZBUZ|571416|570705|711|269 → 287|21|
|PICTURE|346964|346935|29|89 → 90|1|

Actual savings798,net host+21:24 parent roots replace3 formerlyexternal75CE roots. This explicitly modest tradeoff closes a pending-state law without globally intercepting helpers/serializers or claiming a higher unproved generation transaction. All contained lower operations internal;same operations elsewhere remain enabled. +79E2 remaining0/0/0;7A17 remaining1/10/3;73D0 remaining5/26/5;7AE4 remaining0/0/0;external119E unchanged36/36/43. Caller distribution in topology-summary.json.

Standalone andcumulative hybrids preserve exactRELgoldens,REL/INTchronology,FS,console,PASS1/PASS2/END,BDOS ordering/counts andwarmboot. Promotions {'RAW': 197};DECODED/STRUCTURED0. Exact historical image94720bytes. Zero oraclequeries. Scopeextension;historicalcorrection/divergence/fidelitydebt:none. Development implementation corrections separated in fidelity.json. Historical FACTOR/OPTIMIST catalog totals retained.

Packet17823bytes. Driver automates entrydiscovery,correctedwindows,CFG/caller/routegroups,component/root/hybridproof,transition/residualmaps,contract/compactreport generation andincremental aggregate. Interactive callcount notinstrumented. Semantic-extraction.json documents only this selected parent's possible clean operation and historical mechanisms;no refactor/MIR design.

Next assess7B99/793C indexedcarriertransfer/emission;broader7E05 remainsseparate. scripts/view-optimist.sh untouched. Validation receipt records final aggregate outcome.
