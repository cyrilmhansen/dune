# Pass56 — saved-tag/pointer generation transaction

Baseline `315142f4a4dbfaae933f2bbdaeb6ac66048d65d1` is published Pass55. Previous FULL checkpoint is Pass53. Pass56 schedules one FULL checkpoint after all source/catalog/report/progress edits.

Logical +8225/+8248 calls are 7/25/7. Every +8225 is the unique child of one +8248; no independent +8225 call in the primary corpus. +8248 is selected: save BC high then low at AE65/AE64, independently reload it, XCHG to DE, supply literal C4, call canonical +8225. C4's LINK-80 meaning remains unproved.

+8225 [8225,8248) saves D/E/C at AE63/AE62/AE61, invokes canonical +79E2,+7A17,+73D0, independently paired-reads AE61 to C with literal E9 for canonical +756D, then independently reloads AE62/63 to BC for canonical +7701. Original tag/pointer cannot remain in entry registers because preparation and emission clobber them. Exact visible scratch lifetime and flag/register dependency graph are in the packet; preparation children do not mutate saved carriers. This bounded preparation/reset/tag/pointed-field operation is one transaction, without asserting a speculative source-language item name.

+79E2: 9/40/8 natural calls, all fresh AE05=0; CPI0 flags and A0 returned, other registers preserved. Only 9 entry/early-return bytes reconstructed; nonzero arm remains RAW. Envelope [79E2,7A17) provisional, CFG/contract partial.

+7A17: 8/41/10 natural calls. 8/38/10 fresh AE04=0 cases independently proved; CPI0 flags and A0 returned. Three additional FIZZBUZ calls take AE04=1 and invoke +79B6 → +7903, outside every selected root. Their inventory is retained as explicit counter-scope evidence, not silently accepted. Only 9 clear-route bytes promoted; [7A17,7A4E) envelope provisional, CFG/contract partial.

+73D0 [73D0,73FE): 12/51/12 natural calls, independently proved across all callers. Fresh ADAA;RAR;bit0-clear returns rotated A with original NZPA. Bit0-set publishes ADAA=0 and ADC4=0; fresh index comparison against literal7, independent paired-read/zeroextension, publication at ADAB+index, fresh increment/JNZ; final index8, A7, BC=ADAB, HL=ADC4, flags from final CMP. Both routes and all local bytes accounted for: bounds stable, CFG/low-level contract complete. No host array shortcut or fixture loop count.

+8225 and +8248 have stable bounds and complete local CFG; contracts partial at inherited successful-output/clear-mode/nonzero-position/nonalias scope. Nonzero preparation routes, writer errors, wrap and arbitrary aliases reject copied staging before live mutation. No nested Runner, snapshot dispatch or final-state copying.

Every logical parent and accepted outer root matches registers/flags/SP/PC, ordered logical writes, all 64KiB RAM, final stack writers, child chronology, DMA/filesystem, service boundary state and full record chronology. Canonical +756D and +7701 are independently correlated, including the entire pointed-field loop/serializer subtree. FACTOR11 calls per parent independently exact; historical OPTIMIST46 preserved, with no cheap current source/trace. Component counts and hashes are in shadow-summary.json. Synthetic C2/C3/C4, ADAA bit/upper-bit/carry variants, record-boundary and alias/rejection discriminants pass.

Original hardware CALL words survive. No private frame invented. Each preparation/756D/7701 child CALL word, writer PSW/service frame and final RET last writer is derived. Saved carriers remain visible even when same-valued. Ordinary hardware stack and lower continuation mechanisms remain unchanged.

|Source|Pass55 guest|Pass56 guest|Removed|Host pre → post|Roots|
|---|---:|---:|---:|---:|---:|
|MINIMAL|301190|300501|689|107 → 100|7|
|FIZZBUZ|574055|571416|2639|294 → 269|25|
|PICTURE|347549|346964|585|96 → 89|7|

Each +8248 replaces one +7701 and one +756D boundary; net -7/-25/-7. Other native calls remain enabled outside exact corrected windows. Remaining +7701/+8225/+8248 guest invocations outside selected roots are zero. Remaining +119E is36/36/43, unchanged: this parent composes already-native output rather than globally intercepting a leaf. Residual preparation calls/callers are explicitly recorded for the next semantic decision.

+8225-only, +8248-only and cumulative hybrids preserve the exact REL goldens, REL/INT record sequence, filesystem, console, PASS1/PASS2/END, BDOS order/counts and warm boot. Actual whole-run counter differences alone establish savings.

Promotions from baseline manifest: {'RAW': 64, 'STRUCTURED': 51}. Existing parent STRUCTURED bytes are separately counted; no RAW inflation. Historical reconstruction94720 exact bytes. Zero oracle queries. Bounded scope extension; historical correction, pragmatic divergence and fidelity debt:none. Development corrections recorded separately in fidelity.json. Packet 26041 bytes, full journals under ignored `_build/host-compiler-pass-56`; interactive orchestration count not instrumented.

Driver automates natural/child/cross-caller inventory, valid CFG extraction, root correlation and transition accounting, scoped component batches, child checkpoint/cache proof, root/hybrid proof, FACTOR cross-evidence, byte-preserving annotations and historical total preservation, compact reporting and full-checkpoint dispatch. Metadata and reports final before aggregate; validation.json records initial outcome and any affected-category reruns. scripts/view-optimist.sh untouched.

Recommend Pass57 assess pending-generation families around +7AD0/+7ABE, keeping broader structure/generation and independent PLI0 emission lifetimes distinct.
