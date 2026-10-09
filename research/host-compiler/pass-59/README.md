# Pass59 — carrier clear and field emission

Baseline `3cd5b72edd2a5bf7456b3370c10f8de6705e16fe` is published Pass58. Previous FULL checkpoint: Pass56. This pass schedules one final FULL checkpoint after semantic completion.

## Scope and evidence

+7B1B has exact hypothesized envelope `[7B1B,7B79)`, RET +7B78. Natural primary counts are 0/10/0, all FIZZBUZ; callers +31E7 ×1, +36FA/+3701/+420C ×3 each. C/E distribution: B0/07 ×1, 80/07 ×3, 98/07 ×3, B0/05 ×3. FACTOR contributes one independently shadowed B0/06 case. An existing OPTIMIST emission journal contains three distinct parent ancestors, without a full parent ABI/proof; no C/E or complete count is inferred from it. Neither primary nor FACTOR cases uses A8 or B8.

## Faithful law

Save E at AE0D, then C at AE0C. Independently fresh C and E reads feed `SUI literal; SUI 1; SBB A`: the masks are FF exactly for equality with A8 and 7 respectively, otherwise zero. First-mask PUSH PSW writes A high then packed flags low below entry SP. POP B transports that mask without restoring flags; MOV C,B, ANA C and RAR produce the conjunction in CY. Natural cases have CY=0 and continue at +7B52.

Fresh saved C is compared with B8. All natural cases call canonical +7397 with literal C=7, clearing ADAB[7]. B8 skips the clear; bounded synthetic cases prove that branch without claiming natural coverage. Tail calls canonical +746F with freshly paired-read C, +74C7 with independently paired-read E, then +7557 with fresh E OR fresh C. Paired E also reads adjacent AE0E. Children do not modify the saved carriers on the natural routes. Entry high halves and flags are actual channels until historical instructions overwrite them.

The special A8/E7 block is 25 bytes of DEDUCED / STATIC / UNOBSERVED evidence. Exact targets are +79E2, +7365 and +7314. Accepted synthetic scope requires AE05=0 for canonical +79E2. +7365 is passed C=7,E=0. Its returned mask undergoes RAR: CY=1 returns early at +7B47; FF with incoming CY=1 remains FF. Otherwise canonical +7314 publishes the carrier and zero value, then enters the tail without +7397. Nonzero AE05 and inherited unsupported states reject staging; no arbitrary pending-generation behavior is invented.

## Required helpers

+7314 `[7314,7338)`: primary natural counts 8/33/9, plus FACTOR 12. Save E/C at ADBC/ADBB, publish ADAA=1, PUSH the ADAA address, fresh C zero extension, POP B and INX B to ADAB, publish ADAB[C]=1. Independently reread C and E and publish ADB3[C]=E. Exact PUSH residue, DAD carry and preserved NZPA are retained.

+7365 `[7365,7397)`: primary counts 0/0/16. Fresh 202B low bit gates a literal-zero return. Otherwise fresh ADAB[C] low bit gates another literal-zero return. The final route compares fresh saved E with fresh ADB3[C] through SUB/SUI/SBB, returning FF for equality and zero otherwise. PICTURE has 12 carrier-clear returns and four comparison returns. The three-byte first-gate return is STATIC / UNOBSERVED and synthetically exercised. Helpers have independent natural full-state shadows and bounded index scope 0..7.

## Proof, hierarchy and leverage

All ten primary roots, the FACTOR root, 50 primary +7314 cases and 16 +7365 cases independently shadow registers, flags, SP/PC, ordered writes, full 64 KiB RAM, stack last writers, child chronology and DMA/filesystem/record/service state. Natural arithmetic/read/write checkpoints remain under ignored `_build/host-compiler-pass-59`. Synthetic A8/E7 early/publication outcomes, A8/E5, B8/E5/E7, record-boundary output and rejected aliases/code/continuation/states pass. No private frame or final RAM copying is introduced.

|Source|Pass58 → Pass59 guest|Removed|Host before → after|Roots|
|---|---:|---:|---:|---:|
|MINIMAL|300443 → 300443|0|102 → 102|0|
|FIZZBUZ|569925 → 569375|550|277 → 277|10|
|PICTURE|346935 → 346935|0|90 → 90|0|

Only exact accepted +7B1B windows absorb lower roots. Standalone/cumulative hybrids preserve exact REL hashes, full REL/INT chronology, filesystem, console, compiler milestones, BDOS order/counts and warm boot. Residual maps and absorption by coordinate are in hierarchy-summary.json. Guest savings come solely from whole-run counters.

Promotions: {'RAW': 180}. +7B1B 94 bytes includes 25 static special bytes; +7314 36 bytes; +7365 50 bytes includes three static first-gate bytes. Bounds stable, local CFG complete, contracts partial over supported state/index/child/alias scopes. Unsupported error, position-wrap, writer and pending routes fail closed in copied transactions. Existing historical FACTOR/OPTIMIST totals are preserved.

Oracle queries: zero. Exact reconstruction: 94720 bytes. No historical correction, pragmatic divergence or fidelity debt. Development implementation/test corrections are recorded separately in fidelity.json. Semantic extraction documents behavior separately from the historical scratch, mask, PSW, carry and CALL mechanisms; no MIR API or refactor.

Packet: 17523 bytes. Driver phases automate inventory, route grouping, valid extents, component/root proofs, checkpoint equations, cross-evidence, hierarchy, hybrids, reports, semantic extraction and full-checkpoint dispatch. Interactive call count is not instrumented. Final validation.json records category/test/stanza/worker counts, timing and any reruns.

+7B99 is a distinct indexed-copy/preparation transaction with different ABI and callers; it remains canonical and separate. +7E05 is not absorbed. Recommended Pass60: assess that broader carrier-generation policy. scripts/view-optimist.sh is untouched.
