# Pass60 — indexed carrier generation

Baseline `a3ca60c886833e1bdae92e1334504c9acd5fabd8` is published Pass59 and the current FULL checkpoint. Pass60 uses incremental validation.

## Scope and natural evidence

The selected root is PLI2.OVL+7E05, `[7E05,7ED6)`, 209 bytes. Natural logical and external counts are 2 MINIMAL, 11 FIZZBUZ and 1 PICTURE; FACTOR adds two independently shadowed cross-cases. All use C=7. E distributions and callers are retained in inventory-summary.json. All freshly read ADAA=0 and 202B=0 after canonical +7AE4, entering publication without searching. The direct child sequence is +7AE4, +7314, +75CE, +75A7. No naturally called overlapping entry was found.

AE37 receives E before AE36 receives C. Paired rereads preserve adjacent high-byte channels. Entry high registers and flags remain actual channels until historical instructions overwrite them.

## Gate, reuse and search law

Fresh C undergoes SUI6, ADIFF, SBB A: the mask is FF exactly when C differs from 6. ANA fresh ADAA, PUSH PSW, fresh complemented 202B, POP B/MOV C,B, ANA C and RAR give CY = (C != 6) AND ADAA.bit0 AND NOT 202B.bit0. The implementation retains arithmetic flags and the actual stack mask carrier.

An enabled gate checks ADAB[C].bit0. An active carrier reads ADB3[C] into AE38 and compares it with fresh E. Equality returns at +7E4C; modulo +1/-1 invokes +7DC3/+7DE4 and returns. These compact 33-byte helpers save C, reread a paired word into DE and emit through canonical +75CE with C=4/5. Fresh C=6 returns; otherwise a fresh indexed ADB3 byte is incremented/decremented. Both helpers have zero primary/FACTOR natural calls and remain DEDUCED / STATIC / UNOBSERVED.

Search initializes AE39=0 and visits indices 0 through 7 in order. It tests activity first, excludes index6 next, then compares fresh ADB3[index] with fresh E. A match calls canonical +793C with saved destination C and matched index E, then returns. A failed candidate publishes the index increment; index8 enters publication. There is no table snapshot or fixture iteration count. All natural search counts are zero. Synthetic matches at 0/5/7, index6 exclusion and no-match searches retain explicit static classification.

Publication independently rereads saved C and E for canonical +7314, which publishes ADAA=1, ADAB[C]=1 and ADB3[C]=E. Another paired C read supplies DE to +75CE with literal C=6; a separate paired E read supplies C to +75A7. Same-valued writes, paired adjacent reads, child states and stack residue are preserved.

## Proof and measured leverage

All 14 primary roots and the two FACTOR roots independently match registers, flags, SP/PC, ordered writes, all 65536 RAM bytes, stack last writers, child CALL chronology, DMA, filesystem and record/service chronology. Useful canonical child calls have separate shadows. Fourteen synthetic discriminants per primary root execute the historical instructions and children independently, comparing full state and ordered writes including stack traffic. They cover disabled/global gates, C6, equality, ±1 with wraparound, matches at 0/5/7, index6 exclusion and no match. Per-instruction and loop checkpoints are retained under ignored `_build/host-compiler-pass-60`; synthetic CALL/RET witnesses establish helper ancestry without fabricating natural coverage. Synthetic comparisons avoid BDOS; natural shadows and hybrids prove external chronology.

| Source | Pass59 → Pass60 guest | Removed | Host before → after | Roots |
|---|---:|---:|---:|---:|
|MINIMAL|300443 → 300335|108|102 → 98|2|
|FIZZBUZ|569375 → 568781|594|277 → 255|11|
|PICTURE|346935 → 346881|54|90 → 88|1|

Each outer root replaces three existing boundaries: +7AE4, +75CE and +75A7. Canonical +7314 was already an internal operation, not an independently enabled Runner root. Absorption and the residual map are in hierarchy-summary.json. Remaining external +7AE4 is 0/0/0; +119E remains 36/36/43. Standalone and cumulative hybrids preserve exact REL goldens, complete REL/INT record chronology, filesystem, console, milestones, BDOS order/counts and warm boot.

## Archaeology and limits

Promotions: {'RAW': 275}; DECODED and STRUCTURED promotions are zero. Of the 275 represented bytes, 65 are naturally OBSERVED and 210 are DEDUCED / STATIC / UNOBSERVED. Bounds are stable, local CFG complete, contract partial over bounded indices and current child/output/alias scopes. C outside0..7, unsupported pending states, nonclear 201D, position wrap, writer errors and code/stack/sentinel aliases reject copied staging before live mutation. There are no CPU/Runner/CPM or shared proof-schema changes.

Historical FACTOR/OPTIMIST catalog totals are preserved. Oracle queries: zero; targeted synthetic comparisons use the existing concrete CPU. Exact reconstruction is 94720 bytes. No historical correction, pragmatic divergence or fidelity debt is recorded. The development AE38 STA draft was corrected to a byte write before alternate-route proof. Final review corrected inherited generic proof route labels; the full Pass60 category was rerun without changing execution semantics. Semantic extraction distinguishes possible carrier relation behavior from scratch addresses, mask arithmetic, PSW transport, explicit scans and CALL residue; no MIR API or faithful-code refactor was introduced.

## Boundary and validation

Corrected immediate ancestors are +1FB5 for callsites +3E71/+33E9 and +6704 for +6722. The former is compiler dispatch with stack-local saves/PCHL; the latter also invokes +665B and +059E. These add separate compiler policy, so +7E05 remains the root. Recommended Pass61: discover the real parents of residual +73D0 callers +742A/+825E/+82BA; retain +82A6/+82E1/+82F0 output lifecycles as distinct candidates.

Packet: 19571 bytes. The deterministic driver automates extraction, route grouping, helper discovery, proof batches, synthetic checkpoints, hierarchy, hybrids, residual maps, annotation inputs, semantic extraction, reporting and incremental validation. Interactive call count is not instrumented. validation.json holds the final category/test/stanza/worker/timing receipt. No FULL checkpoint trigger occurred. scripts/view-optimist.sh is untouched.
