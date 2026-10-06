# Pass 36 — bounded +3A76 acquisition subtree

Baseline: `1e7961c1559aebba910831fda14eb7af5b401fb3`. Archaeology only; no CPU, Runner, CP/M, packet or native implementation changes.

The work packet was generated before interpretation from corrected ordinary CALL/return windows and immutable image coordinates. MINIMAL has no +3A76 call; FIZZBUZ has 9 and PICTURE 4, all called at +3C95 and returning at +3C15. Their subtrees contain 4,040 historical instruction occurrences (FIZZBUZ 2,772; PICTURE 1,268). Duplicate states remain independent. The check also validates all naturally available immediate-helper windows: 122 across the target, four dependencies and the already complete +83A3 subtraction helper.

## Bounded operation

+3A76 saves input BC high then low at A744/A743, duplicates the fresh saved pointer into A745 and A863, tests the fresh low3 field and clears A6E2. The observed low3!=2 branch invokes +3963, publishes its actual HL at A723/A724 and restores the working pointer from a fresh cursor read.

Each loop combines two independent channels: +4275's expanded `current>=reference[A8AB]` mask and resident +1A33's unsigned `saved_input>=current` result. PUSH PSW / POP B preserve the first channel while the subtraction, self-SBB and CMA produce the second. ANA/RAR tests their conjunction. The processing route separately saves the pointer-equality mask, invokes bounded +387F, and tests the fresh +3558 field-bit7 mask. Every selected call has bit7 clear, so the RAW processing arm is bypassed. +424F(0) then advances/searches, and a fresh A863 word becomes the next A745 cursor.

All thirteen calls perform one search iteration of this outer loop. Six FIZZBUZ calls reach the search limit and clear the working pointer, exiting below the reference. Three FIZZBUZ and all four PICTURE calls advance beyond the saved input. The search itself can take two size advances; those inner iterations are preserved separately.

The fresh zero A6E2 tail returns A=00 with CMP(00,00) flags: S=0, Z=1, AC=1, P=1, CY=0. Final BC is the last saved +4275 mask duplicated into both bytes (0000 or FFFF), DE=A744 and HL=`u16(saved_input-current)`. HL naturally takes FBF3, FFF3, FFF0 or FFEA; the later +3C8A zero cleanup does not describe this child's algorithm. Original continuation is runtime 5E98, SP=entrySP+2.

## Immediate dependencies

| Operation | Natural M/F/P | Represented bytes | Status after pass |
|---|---:|---:|---|
| +3A76 | 0 / 9 / 4 | 142 / 416 | provisional / partial / partial |
| +3963 | 0 / 9 / 4 | 36 / 275 | provisional / partial / partial |
| +4241 | 0 / 9 / 9 | 14 / 14 | stable / complete / complete |
| +424F | 0 / 9 / 7 | 38 / 38 | stable / complete / complete |
| +429D | 1 / 10 / 5 | 145 / 247 | provisional / partial / partial |
| +83A3 (reused) | 3 / 26 / 17 | established complete helper | unchanged |

+4241 reads a size byte from the first working-pointer carrier, independently rereads the pointer, adds the zero-extended size modulo 65536 and publishes low then high. A/BC/NZPA survive; CY is word overflow. It has no body CALL/PUSH residue.

+424F saves the requested mask at A8F2 and always calls +4241 before testing the next pointer against fresh word[A861] through +83A3. At/above the limit it clears A863/A864 while retaining subtraction A/flags. Otherwise +421F reads the fresh field mask; CMP against fresh A8F2 either repeats or returns. Both unsigned outcomes and the mismatch loop are naturally witnessed. Completeness describes this conditionally terminating algorithm, not a theorem that arbitrary tables terminate.

+3963 establishes a ten-byte inherited frame using four PUSH H and one PUSH B. Its observed field!=70 branch calls +429D and zero-extends returned A into HL. Five POP D restore DE from inherited entry HL. The field70 body remains RAW.

+429D independently caches fields +2/+3/+4. Selector15 uses ANI FC, three RAR and INR, with no final ANI07: result is 1..32 and CY is original primary bit2. Selector30 returns literal2 retaining comparison flags. Observed fallback selectors31/80 return literal0 retaining CMP(selector,42) flags. Other selector and combined-mask arms remain RAW. Its existing hypothesis is extended, not declared complete.

## Memory, flags and compatibility

The checker validates exact canonical bytes, low/high data-writer ordering, immediate flag producers, all CALL/PUSH encodings, inherited frame writes, and per-cell final stack writers and overwrite ancestry. The final root S-2/S-1 writers are +3AB2 PUSH PSW: 87/00 on below-reference exits, 56/FF on above-input exits. Deeper residue is derived from the real child CALL/frame writers; no post-state bytes are used as a substitute algorithm. No new binary-oracle queries were needed.

Code, active return/save slots, scratch carriers and selected pointer/table accesses must not interfere where the composed contracts require nonaliasing. No table capacities, global ownership, source-language meaning or arbitrary termination claim is introduced. RAW initial low3==2 handling, bit7-selected processing, nonzero A6E2 tail, +3963 field70 and unsupported +429D selectors remain explicit.

## Parent impact and next boundary

The demonstrated C=0 +3C8A path is now reproducible/native-ready at the inherited bounded child scopes; its global partial status and positive-input RAW body are unchanged. +3DD9 still needs the partial +239A→+2355 classifier chain. +5E98 additionally needs +4601 cleanup, substantial +506E/+500F acquisition and the +784E resident-input scope, so +61A4/+620C are not yet native-ready.

Pass37 should combine the small +4601 cleanup with the bounded classifier scope needed by +3DD9, closing mechanical leaves together. +506E/+500F has the largest substantial remaining leverage and should retain a separate bounded subtree boundary; +784E carries a distinct resident buffer/refill obligation. This ranking and its observed-window evidence are in boundary-assessment.json.

297 RAW bytes are promoted: +3A76 142, +3963 36, +4241 14, +424F 38 and +429D 67. Four new hypotheses are added and two existing hypotheses refined (+429D and the +3C8A child-scope reference). The first work packet is 159,994 bytes; model-facing reads were filtered summaries rather than full packet/trace dumps. Validation totals and the exact 94,720-byte reconstruction are recorded in validation.json.
