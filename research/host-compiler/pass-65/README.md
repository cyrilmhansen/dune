# Pass65 — bounded paired-relation generation policy

Verified published baseline: `ba434b6565e25390d62c0e18dbe3882b29cff508`. **Pass62 remains the last certified FULL epoch.** Historical-full was not executed; no FULL trigger fired. CPU8080, CP/M, Runner and existing capture/journal interpretation are unchanged.

## Bounds, coverage and independent helpers

The root is **PLI2.OVL+7ED6 [7ED6,8072), 412 bytes**. Early returns and final RET at8071 belong to this local CFG. The following8072 is a separate natural procedure. No overlapping externally called entry was found inside the root. [CFG](cfg.json) retains every decoded instruction and its evidence class; [inventory](inventory-summary.json) retains actual callers and complete child sequences.

Primary logical/external counts are **MINIMAL3, FIZZBUZ11, PICTURE4**, all called at808D. Seventeen primary roots returnA0 at7EF1 because freshADAA.bit0 is clear. One PICTURE root passes the gates and completes a failed indexed search:16 independent7365 calls, indices0..7 with6 skipped, then index8 terminates. FACTOR adds5 and OPTIMIST14 independently shadowed natural roots, all on the early route. Neither cross source is a semantic selector.

New reusable helper bounds are **7D47[7D47,7D85), 7D85[7D85,7DC3), 8398[8398,83A2), 83B4[83B4,83BA), 83D2[83D2,83DC)**. Their150 bytes are separate from the412 root-own bytes. Global natural shift/OR helper counts are9/34/12 each;7D47 has one independent FIZZBUZ call. These cross-caller executions are independently shadowed.7D85 has one natural cross-corpus call in each of FACTOR/OPTIMIST, independently traced and shadowed.83D2 has no natural calls; its accepted routes are synthetic-only.

## Exact state-driven law

Entry saves **D→AE3C, E→AE3B, C→AE3A**, in that order. Each later paired LHLD remains independent. Fresh202B RAR: bit0set returnsA0. Otherwise freshADAA RAR: bit0clear returnsA0. Otherwise freshsavedC CPI6: equal returnsA0. Producing flags and preceding saves remain visible. EntryC0..7 is bounded; active nonreserved paths requireC0..5 so adjacent indices remain supported.

The active path independently forms ADAB[C] and ADAB[C+1]. PUSH H/POP H carries the first address; ANA/RAR tests conjoined activity bit0. If both are active, ADB3[C] becomes the high byte through83B4 shift8; freshADB3[C+1] is ORed into the low byte through8398. SHLD publishes the resulting word atAE3E/F. Canonical resident word differences and83D2 subtraction of3 test forward or reverse unsigned distances0..2. Equality returnsA1. Otherwise7D47/7D85 emits through canonical75CE and increments/decrements the adjacent relation bytes; the parent independently rereads/increments/decrements AE3E until equality. At most two adjustments follow from the distance predicate; no observed iteration count selects behavior. A farther value falls through to the following policy.

The fallback publishes savedD atAE40 and savedE atAE41.7365 at7FBA tests(C,D); its returned bit0 throughRAR selects7E05(C+1,E), thenA1. Otherwise7365 at7FD9 independently tests(C+1,E); a match selects7E05(C,D), thenA1. Equal values retain separate read provenance.

Neither match initializesAE42/43 toFF and AE3D to0. FreshA7 CMP index scans0..7 and explicitly skips6.7365 at8015 tests(index,D) and publishes AE42 on success.7365 at802B independently tests(index,E), publishing AE43 only when index differs from savedC. Candidates persist across iterations. Fresh candidate OR/RLC/RAR tests oldbit7: both valid invoke793C(C,first) and then793C(u8(C+1),second), returningA1. Failed candidates INR the fresh index before the backedge. Index8 returnsA0 with the actual final CMP flags, includingS/CYset.

7D47/7D85 preserve saved selectors, literal3/0B emission, low-byte update before carry/borrow into the preceding byte, and their reserved6 arms.8398 preserves exact E/D/A/L/H transfers and OR flags;83B4 preserves each DAD carry and DCR flags;83D2 preserves SUB/SBB channels and borrow. [Contracts](contract-laws-PLI2.OVL.json) retain the complete bounded instruction laws. Canonical7365,7E05,793C,75CE and resident arithmetic operations are composed internally; no guest instruction execution occurs in the host algorithm.

## Proof, stack and transaction

[Shadow summary](shadow-summary.json) records all primary/cross natural roots and independent helper proofs. **558 original-CPU synthetic proofs** cover each gate, D/E differences, first/second matches, paired equality/±1/±2/far values, search matches0/5/7, index6 skip, destination exclusion, equal values, high gate bits and changed incoming carry. Separate helper cases cover shift/OR/subtraction, word carry/borrow, forward/reverse wrapping and reserved6 arms. Full instruction/loop checkpoints stay under ignored_build; durable reports contain hashes.

Every supported root compares all registers/flags/SP/PC, ordered writes, complete65536-byte RAM, stack last writers, child CALL chronology, DMA/filesystem and record/service state. Natural and synthetic evidence remain separate. Outer808D CALL stores continuationA290. PUSH/POP H carriers and each nested CALL retain historical residue; RET consumes the unchanged original word withSP=entrySP+2. The83B4 entry is independently CALLed; its preceding83B0 prefix remains STATIC/unmigrated, with no natural calls. Its backedge is a local loop, not a second invocation; its new-entry shadow explicitly distinguishes that loop.

Code, child code, CALL/continuation, sentinel/table/scratch/stack aliases and unsupported child domains reject before live mutation. Copied staging validates the entire route, including later children and output state. Negative proofs include activeC7 rejection after the entry saves and a later position-wrap child rejection after staged preparation/output. No partial publication followed by guest fallback is permitted.

## Hierarchy and economics

| Source | Guest before → after | Removed | Host before → after |
|---|---:|---:|---:|
|MINIMAL|294735 → 294693|42|101 → 104|
|FIZZBUZ|561768 → 561614|154|257 → 268|
|PICTURE|341214 → 340593|621|92 → 96|

[Topology](topology-summary.json) records absorption and remaining7365/7ED6/7338/75CE/7619/7A17/8072/119E. Natural roots contain no already-enabled lower Runner root. Thus this policy adds one boundary per invocation; its modest guest reduction is reported alongside that cost. No global7365 or serializer interceptor is added. Standalone and cumulative hybrids preserve exact REL goldens, complete REL/INT record chronology, filesystem, console, BDOS order/counts, compiler milestones and warm boot. Goldens are retained in both hybrid receipts.

Knowledge gain is **562 RAW→UNDERSTOOD; DECODED0; STRUCTURED0**. [Knowledge summary](knowledge-summary.json) separates root/helper bytes and naturally OBSERVED bytes from DEDUCED STATIC UNOBSERVED bytes. All local CFG bytes are accounted for, but the general contract remains partial over explicit index, child mode/error, output/position and alias domains. No higher PL/I meaning is claimed. [Semantic extraction](semantic-extraction.json) separates relation search/adjustment from scratch, paired reads, arithmetic flags and stack mechanisms; the proposed compiler-level meaning remains HYPOTHESIS. No MIR/API design or faithful-code refactor.

## Validation and next boundary

ACTIVE core plus explicit extras **pass65, pass59, pass58, pass60, pass54**. Pass59 directly proves7365; Pass58 proves793C; Pass60 proves7E05; Pass54 proves75CE used directly by the new adjustment helpers. Pass52/63/64 are not accumulated merely because they were previous extras. [Validation receipt](validation.json) records categories, tests, workers, wall/summed seconds and reruns. Previous ACTIVE walls: Pass63 423.418s and Pass64 503.528s.

Historical-full selection preserves all92 Pass62 categories plus validation-runner-tests and pass63/64/65 (**96 selected**). This is a selection-set proof only. Exact reconstruction remains **94720 bytes**. New oracle queries: **0**. Packet: **26116 bytes**. Driver phases cover discovery, inventory, contracts, components, cross-evidence, topology, reports and ACTIVE validation.

Immediate parent8072 has separate policy around7338,75CE,7619 and sometimes7A17; its complete natural child sequences are retained in the inventory. Recommend its assessment forPass66 before the large independent18B3 traversal.8072 is not migrated here; transition savings alone do not justify climbing. Pass62 remains lastFULL, with ordinary nextFULL approximatelyPass67.

There is no historical behavior correction or pragmatic divergence. Development corrected a reversed scan-termination branch through independent CPU comparison and removed inapplicable inherited corruption tests that changed no effects on an early-return path. Fidelity debt is bounded child/error/alias scope, synthetic-only alternate coverage and unproved higher meaning. User-owned scripts/view-optimist.sh is untouched. Proof artifacts and aggregate temporary directories are under ignored _build and clean up on exit. The focused V1 test used its existing automatically cleaned temporary-directory mechanism.
