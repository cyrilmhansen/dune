# Pass 40 — selector02 acquisition and software continuation

Start: `6010894d20941e9e3dfe2706a6cb37224862a6f8`. Archaeology only. This closes the selector02 operation required by +2C59/+3304, while retaining the distinct older selector05/E05 contract. No native implementation, runtime change, source fixture or historical-binary query was introduced.

The validation tier is **full_checkpoint**, closing the incremental Pass39/40 wave based on `fe6e25bdae01f787731cb45e1bef17296d7d3b2e`. Final checkpoint timings, categories and results are retained in `validation.json`.

## Fresh natural inventory

| Coordinate | MINIMAL | FIZZBUZ | PICTURE |
|---|---:|---:|---:|
| +28AA, all corrected ordinary windows | 1 | 19 | 3 |
| +28AA selected02 | 0 | 9 | 1 |
| +6708, corrected software windows | 2 | 15 | 1 |
| +6708 E02 / +67BE | 0 | 9 | 1 |
| +6708 E05, retained separately | 2 | 6 | 0 |
| +8309 | 0 | 12 | 1 |
| +2185 | 1 | 20 | 2 |
| +213C, supporting existing classifier scope | 2 | 26 | 2 |

There are **107 independent windows**; duplicates remain independent. E02 has seven C1 calls and three C2 calls. The resulting words are 0 (three), 1 (one), 15 (three), 3 (one), 5 (one), and 7 (one). These results follow the source bytes and arithmetic, not corpus or snapshot identity. E02's caller is +2985; E05 occurs at +2985/+2AB4. Exact callers and distributions are in `route-distribution.json`.

The committed work packet is **28,082 bytes**, below 32 KiB, with a single decoded graph per operation, 3 route layouts and interned stack patterns. Complete child contracts are referenced by coordinate/hash. Its ignored, rederivable proof is **17,819,928 bytes**, approximately 634.568 times larger. `efficiency.json` records exact sizes/hashes and generation times. No full-memory native shadow is claimed in this archaeology pass.

## Eight-byte software continuation

Let F be +6708 entry SP. +670F POP D consumes the original CALL word at F. Four POP B instructions independently read words at F+2, F+4, F+6 and F+8:

1. Source pointer: full word → A9DE/A9DF, high publication before low.
2. Selector carrier: only low → A9DD; high is read and discarded.
3. Working pointer: full word → A9DB/A9DC, high publication before low.
4. Prefix carrier: only low → A9DA; high is read and discarded.

C and E are first saved at A9E0/A9E1. +671F PUSH D copies the original continuation into F+8/F+9, high then low. Fresh working-pointer rereads publish A863/A864 low then high. Final RET +6CA0 consumes the copied word: PC is the original caller+3, SP=F+10. The parent's separately saved PSW is at F+10/F+11 and survives. High bytes of the selector/prefix carriers are genuinely consumed, even when discarded; their natural variations remain recorded.

Body CALL/PUSH writes occur above the original entry SP as well as below it, overwriting consumed argument slots. The compatibility proof therefore extends through F+9. Every final stack cell is derived from its actual CALL/PUSH register or PSW source and its ordered overwrite ancestry. No post-state residue is copied as an explanation. The existing software-continuation proof is reused without changing packet, Runner or CPU architecture.

## E02 alternate algorithm

Fresh base selector flags choose +67BE. The observed E02 route passes the 24/25, E06/07/08/09, selector19 and E04 tests, then fresh selector15 enters +6BA0. It is an iterative digit-to-word acquisition, distinct from E05 copying and padding.

Clear word A948/A949; set A9E3=1 and offset A9E2=0. Each loop freshly reads the saved count, decrements it modulo256, and compares it against the current offset. Counts 1 and 2 execute one and two digit iterations respectively, followed by the actual unsigned-borrow exit comparison. No arbitrary iteration guard is introduced.

Fresh source-pointer/offset reads select each byte. Separate rereads construct dot, below30, above39 and overflow masks, preserving their PSW carriers and rotate flags. At the demonstrated nondot digit scope, the overflow predicate combines accumulator>0CCC with accumulator==0CCC AND fresh digit>37. +83A3, resident +1A38 and independent byte masks supply those channels. This restricts the supported arithmetic path; unobserved overflow/error branches are not inferred.

+8309 reads the current working word and multiplies it by10 through wrapped doubles: 2w, saved 2w, 4w, 8w, then 8w+2w. Add the freshly reread raw digit byte modulo65536; +8396 subtracts30. Publish A948 low then A949 high **each iteration**, then increment A9E2. Equal source-byte values do not replace their independent reads.

At termination, fresh width A62B+selector drives complete +8380's repeated doubling of word1. Resident +1A43 performs the comparison against the acquired word. The natural width15/word0..15 path borrows; prefix!=2D skips the RAW negation arm. A second fresh width test, CMP07,width, selects two-byte result publication A947=02 followed by literal A=01. Exact final BC=A62B, DE=A949, HL=A947. S1/Z0/AC0/P0/CY1 remain from CMP07,0F; the literal A=01 does not regenerate flags.

The bounded domain consists of the actual route predicates, count1/2, valid nondot digit bytes, clear overflow mask, supported borrowing finish, nonnegative prefix, width>7 and noninterfering code/source/scratch/selected fields/stack. This is not a global contract for all +6708 alternatives or arbitrary termination.

## Selector02 parent composition

+28AA saves input C, freshly reads index and selector, then acquires the indexed pointer word. Fresh prefix/gate state and +2185 precede the four argument PUSHes. The source count comes from the fresh pointer header minus0A; selected02 supplies E, not a guessed type name. After +6708 returns, POP B recovers the separately saved gate PSW; ANA/RAR combines the actual gate byte and child A.

The supported set-bit route independently copies base A628/A62B/A62E into their selected channels. Fresh selector masks and saved input choose A661=0A. Fresh low word-result byte is zero-extended and published to A863/A864. Fresh high result byte is shifted eight times through +8380; +834F OR combines it with the separately published low channel. The assembled word is published low/high to the freshly addressed pointer-table slot.

Fresh AE32 supplies +7B7A; its direct returned cursor is cached at A660. Fresh cursor and word feed +7AF0. Three independent source/position rereads then publish control AC73, primary AD08 and secondary AD9D. A fresh paired A661/A662 supplies mapped0A publication, preserving the genuinely read neighboring high byte in DE. Increment A660; repeat all three independent channels at the new cursor. Finally +2355's actual classification is adjusted by wrapping ADI13, and a fresh cursor feeds +7AD5. Parent returned A=17 is distinct from child A=01, selected15 and the acquired word.

`parent-correlations.json` links all five prior +3304 roots by actual child CALL steps; four require this selector02 acquisition. +2C59's subsequent fresh reads observe selected15, then +3304's second +2705 and final +329F run in their established order. **Required selector02 +28AA, +2C59 and +3304 are reproducible at the demonstrated scope.** No global parent completion or native migration is claimed.

## Small leaves and archaeological changes

**+8309 [8309,8314)** is a new stable/complete/complete 11-byte hypothesis. A/NZPA are preserved; BC=u16(2w), DE=source_high_address, HL=u16(10w). CY is the final wrapped8w+wrapped2w carry, not unwrapped10w overflow. Temporary PUSH/POP leaves the doubled-word residue.

**+2185 [2185,21AD)** now has all three local routes observed and all40 bytes represented: nibble10 literal01, classifier-bit literal01, and equality31 fallback mask. Its bounds/local control flow become stable/complete; contract remains partial because +213C's unobserved equality alternatives remain unsupported. Literal returns preserve their distinct comparison/child flag provenance. The existing +213C bounded comparison-prefix and equal02 law is reused; no new +213C bytes are promoted.

**436 RAW bytes become UNDERSTOOD**. +6708's provisional envelope extends to [6708,6CA1), with RAW holes and partial control flow/contract explicit. +28AA remains provisional/partial/partial. Previously established E05 bytes and evidence survive. There is no correction to a previously established operational law; newly observed paths refine coverage and scope. Unobserved dot, invalid digit, overflow, offset wrap, negative prefix, nonborrow finish, one-byte result and unrelated acquisition/allocator/output paths remain RAW/STATIC/UNOBSERVED.

## Next wave

The required +30C1/+2C59 blocker is closed. Broader global incompleteness of +256C and unrelated +28AA/+6708 alternatives does not block bounded reproduction. Required +5E98-family blockers still include **+784E acquisition** and **+5929→+46A7** in the actual indirect +6223 reentry ancestry; +784E is not the sole blocker.

Recommend **Pass41: accumulated natural +784E acquisition scope**, then the substantial +46A7 obligation under +5929. Keep completed leaves and +3304 in the deferred native-ready queue rather than migrating them individually. Group Pass41/42 archaeology into the next validation wave, with a full checkpoint by Pass43 or earlier for a runtime/schema/shared-contract/native trigger, and before +5E98-family native migration.

## Validation

Focused development checks, including source-address, returned-flag, publication, canonical-byte and copied-continuation corruptions, precede one final full checkpoint. All previously deferred categories plus Pass39/40 are included through the existing Pass38 runner with four isolated read-only workers after serial Dune work. Metadata, annotations and progress are finalized before that run. Exact historical reconstruction remains **94,720 bytes**, all four images. No CPU/Runner/CP/M/native code changes, pragmatic divergence or fidelity debt are introduced. Detailed costs and final totals are in `validation.json`; raw proof stays ignored under `_build`.

Final checkpoint: **63/63 categories**, **417 Python tests**, all **109 MINIMAL tests** and **27 packet/continuation tests** passed. Wall **719.491s**, sum of category times **2831.548s**, four workers, **one checkpoint run and no reruns**. The slowest categories are recorded in `validation.json`; repeated immutable witness parsing remains a cost. Targeted development: **58.075s**. Exact reconstruction and all image hashes passed; annotations/progress were final before the checkpoint. Two aggregate final commands were used. The validation record identifies the tested working-tree candidate by its file hashes; the final commit adds this result record and timing prose. Logs and the rederivable proof remain ignored under `_build`.
