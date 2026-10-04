# Existing-corpus attribute discriminator pass 15

Task `EXISTING_CORPUS_ATTRIBUTE_DISCRIMINATOR_PASS_15`; baseline
`0727eb4837a29be14e8bf6ef57cabde0c7974943`. This is a cross-corpus discriminator
pass, not a FIZZBUZ sweep. Existing **PICTURE.PLI** supplies the desired attr6
state naturally. No PL/I source was synthesized, reduced, fuzzed or changed.

## Static exact initial lookup span

[table-classification.json](table-classification.json) was extracted from the
independent historical **PLI.COM**, verified against its full image hash and the
exact reassembled source. Runtime 1B4B..1C4A corresponds to file offsets
1A4B..1B4A inclusive (load base0100), exactly 256 bytes. Assembly comments did not
supply the values. Each possible mapped byte 00..FF has independently computed:

```text
low_attribute  = initial_byte & 07
high_attribute = (initial_byte >> 3) & 07
```

+7A63's exact MVI A07/ANA M returns low3 after mapping the input position.
+7B64's exact MOV A,M/ANI FC/RAR/RAR/RAR/ANI07 returns bits3..5 for its input
mapped byte; the actual dynamic reads/transformations are checked separately.
These are different fields, not source-language types.

| Initial HIGH attribute | Count | Candidate mapped bytes where relevant |
|---:|---:|---|
| 0 | 33 | full set retained in JSON |
| 1 | 0 | none in initial image |
| 2 | 15 | full set retained in JSON |
| 3 | 50 | full set retained in JSON |
| 4 | 149 | full set retained in JSON |
| 5 | 2 | **5F,67** |
| 6 | 7 | **10,18,75,B0,B3,B4,B8** |
| 7 | 0 | none in initial image |

This is **STATIC exact initial memory**, not an immutability theorem or a claim
that runtime high-attribute1/7 is impossible.

## Cheap corpus screening before detailed selection

[corpus-screen.json](corpus-screen.json) records every canonical image+file-offset
counter, source hash, report locator/hash and exact golden REL validation. All
canonical instruction bytes/runtime coordinates were compared with independent
historical images. Terminal canonical/exceptional step indices also reproduce
the documented guest-step totals. Entry counts below are **instruction execution
counts**, not inferred invocation ownership from contexts.

| Source | Guest steps | REL bytes | REL SHA-256 | +7D53 count | +7E2B / +7E2E counts |
|---|---:|---:|---|---:|---|
| MINIMAL | 441,855 | 256 | 7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119 | 21 | 0 /0 |
| ARITH | 678,165 | 256 | ca98a3a7e1900d65f2b8bf73b8ccdd9e0e49ce7f15768607348740b1b7a8e553 | 32 | 0 /0 |
| FIZZBUZ | 1,145,517 | 768 | 68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203 | 77 | 0 /0 |
| FACTOR | 838,415 | 384 | 9a42e8341a013243036040c8db0e56939c699c7fbbfb20878f7ba5af8d6b470d | 35 | 2 /2 |
| ARRAY | 668,822 | 256 | 875e6d15720691b7b1be7b537a709fb65e99efbcbb06f5761acefcffedbcb269 | 31 | 0 /0 |
| STRUCT | 653,850 | 256 | af95363e5e428b38e0cc536ac6870cd91bc7203c86193a459c2d62e29f69ee3b | 25 | 0 /0 |
| CHAR | 495,103 | 256 | 1caa65bc5823889c3a3983c48b9da1c20ac50eed0edf733ff48e2a566e757b59 | 23 | 0 /0 |
| FIXEDDEC | 673,691 | 384 | b93cddf1e9dd85fa3ef7f8a27740b43da3396c69b10ff03eab248eef2f9e9938 | 27 | 0 /0 |
| PICTURE | 518,213 | 256 | c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1 | 23 | 2 /2 |
| OPTIMIST | 2,535,509 | 1,408 | 5fca1ffe38d11c30d20cfb99a23fe2baf002c569790bda83e09151cf36032b15 | 86 | 1 /1 |

All ten execute +7D53. Positive natural sources are **PICTURE, FACTOR, OPTIMIST**.
Existing MINIMAL/FIZZBUZ/FACTOR/OPTIMIST structural reports were reused. Missing
ARITH/ARRAY/STRUCT/CHAR/FIXEDDEC/PICTURE reports used only execution/summary/structure
mode under ignored `_build/discriminator-pass-15/screen`. No event capture was
made for those six merely to screen coordinates.

PICTURE is the smallest positive execution and a simple six-line repository
example. FACTOR and OPTIMIST take substantially more steps; OPTIMIST's reusable
witnesses do not override the first size criterion. Its old witness index lacks
corrected hardware-return events, which also makes PICTURE's reproducible current
capture preferable. Screening does not assign a dynamic attribute to FACTOR's
positive arm solely from source features or static bytes.

## Selected PICTURE detailed evidence

No reusable PICTURE event-witness capture existed. Exactly one detailed capture
was generated, using the unchanged source and existing machinery:

```sh
dune exec pli80-analyze -- --toolchain /path/to/DISK1 \
  --source examples/pli80/PICTURE.PLI \
  --output-dir _build/discriminator-pass-15/selected-capture \
  --analysis execution --report summary --structure --event-witnesses
```

PASS1/PASS2/END COMPILATION succeed; the 256-byte REL matches the table above.
The detailed canonical report is exactly equal to the cheaper PICTURE screening
report. Capture identity:
`PICTURE:690dbdc67d1a01c466bb359e3c28dcfc2bfb3635455616355c779599b38bcec2`.
It has 518,213 instruction witnesses, 21,848 corrected hardware returns and 16
software returns, zero transfer mismatches. Capture and packet artifacts stay
ignored under `_build/discriminator-pass-15`.

[selected-run-structure.json](selected-run-structure.json) proves **23 ordinary
+7D53 invocations**: 12 equal-range returns,1 gate return,10 work paths. Callers
+8069=10, +7ED3=8, +80EB=2, +816B=3. It has96 own coordinates/1,504 occurrences,
**232 PICTURE bytes**, and **243 accumulated bytes**: the 11-byte attr3 region
still comes from earlier MINIMAL/FIZZBUZ evidence. The union is not a per-run sum.
Only PICTURE observations were added to this procedure's catalog; negative
screened programs and unselected positives were not cataloged.

The existing V0.2 +7D53 packet succeeds unchanged for PICTURE, frame0/empty class
slots. Markdown was read first and selected JSON answered exact questions.
It has23 invocations,15 classes,33 blocks. Final sizes are **3,710,886 JSON bytes / 32,759 Markdown bytes**,
recorded in [packet-size.json](packet-size.json). Pass14's nonhistorical-runtime0005 blocker
remains unchanged for FIZZBUZ; no event was dropped or given a fake historical
origin. Pass7/Pass14 correlation helpers are reused, not reinterpreted.

## Dynamic table writes versus actual read sources

[runtime-table-audit.json](runtime-table-audit.json) streams available MINIMAL,
FIZZBUZ, PICTURE and OPTIMIST witness evidence. It tracks every guest write,
explicit host memory write and BDOS read-record write to the exact address span,
and checks actual +7A63 reads and +7B64 read/transform states against the latest
writer or initial byte. Same-valued writes replace source identity rather than
being treated as preservation. Structural-only sources have **no write-timeline
claim**, and were not given expensive captures for this audit.

| Witness run | Writes within span | Written addresses | +7B64 observed attributes | Modified-address reads |
|---|---:|---|---|---:|
| MINIMAL | 2,498 | 1C2C..1C37 | 2:7,3:1,4:8 | 0 |
| FIZZBUZ | 3,024 | 1C2C..1C37 | 2:42,3:7,4:60 | 0 |
| PICTURE | 2,716 | 1C2C..1C37 | 2:10,4:12,6:3 | 0 |
| OPTIMIST | 4,040 | 1C2C..1C39 | 2:80,3:5,4:134,6:1 | 0 |

These are **all helper reads**, not just +7D53 forward iterations. PICTURE has
one additional attr6 helper call outside the two selected forward iterations;
no unrelated procedure is decompiled here. OPTIMIST's old witnesses support
read/ANA transformation and table-write observations, **not corrected-return
matching**; its matched-return count is explicitly 0. Current selected PICTURE
has 25 actual read/transform/return matches. Full write histories stay ignored;
compact actual read records are in [selected-table-reads.json](selected-table-reads.json).

The span contains mutable runtime state at its tail; it is demonstrably **not
an unchanged 256-byte runtime object** in these runs. Therefore high attr1/7 absence
from the initial image does not prove runtime impossibility. What is supported:
no actual observed helper read uses a previously written address in these four
captures, and no observed read/transform produces high attr1/7. This is neither a
global immutability theorem nor a claim about every possible compiler execution.

## Two attr6 iterations: suppression and distinct word emissions

[selected-iterations.json](selected-iterations.json) and
[selected-correlations.json](selected-correlations.json) retain per-iteration
values, actual table reads/latest writer, branch flags, direct calls, cache writes,
fresh reads, emission channels and mapped recycling. Both belong to ordinary
parent CALL **326116**, caller **+7ED3**, begin0/end3.

| Cursor | Map CALL | Returned mapped | Table read | Actual packed byte | Transform CALL / A | Low / high CALLs |
|---:|---:|---|---|---|---|---|
| 1 | 326960 | 18 | 1B63 | 31 | 326995 /6 | 327037 /327076 |
| 2 | 327138 | B0 | 1BFB | B1 | 327173 /6 | 327215 /327254 |

The packed bytes differ (31/B1), but both produce highattr6 and lowattr1.
Neither selected read address has a prior observed write; the actual recorded
byte, not only the static initial classification, supplies the transformed value.
+7B64's matched return A6 is immediately published to AE50 by +7DDE.

For **each** iteration:

1. Mapped byte18/B0 is emitted first through direct +7DCC.
2. +7AA9 still reads primary auxiliary **0** at AD09/AD0A; +7DFE writes it to AE51.
3. CPI06 at +7E17 compares actual cached6 and produces **Z1**. JZ +7E19 is taken
   to +7E23, skipping +7E1C, +7E1F and **+7E20**. The primary byte is not emitted.
4. CPI05 at +7E26 compares6 and produces **CY0**. JC +7E28 is not taken.
5. +7E2B calls +7E46: fresh cursor/map selects word0 at AB4B/AB4D. Its actual
   SHLD at327057/327235 writes **AE52=0, AE53=0**, then it emits low0.
6. +7E2E calls +7E56: fresh read at327077/327255 independently fetches AE52/53,
   then emits high0. The preceding cache SHLD remains each byte's latest recorded
   writer, even though zero already existed and both values are equal.
7. +7BA2 at327098/327276 reloads cursor1/2, writes previous AE33=0/1 to AAB5/AAB6,
   independently reads AA20/AA21 and publishes fresh map index1/2 to AE33.

Exact observed channel order is **mapped-byte -> mapped-word-low -> mapped-word-high**.
The suppressed primary0 is not one of the two emitted word zeros. Different
addresses, cache writer/read steps, wrapper calls and saved-C emissions establish
those identities; equality alone cannot. Suppression is a numeric branch choice,
not a source-language type or Boolean result.

The wrappers' actual returned registers/flags are emitter-derived and retained
in JSON. +7BA2 receives a newly loaded cursor rather than the emitter's returned
C or A; its existing complete operation preserves relevant NZPA and resets CY
through address addition. The subsequent INR/JNZ controls the loop from the new
cursor value. No data provenance is inferred from returned flags.

For all 22 selected forward iterations, attributes are2:10,4:10,6:2. Attr5 is
unobserved in selected detailed evidence; FACTOR's structural hit is not labeled
attr5 without its own dynamic classification. Attr7/1 remain initially absent
but not globally impossible. Other untouched conditions retain their scopes.

## Semantic update and independent completeness

Only the two actually observed CALL instructions, **+7E2B/+7E2E**, contribute
**six RAW -> UNDERSTOOD bytes**. Exact encodings remain `CD46A0CD56A0`.
Existing MINIMAL/FIZZBUZ counts and understood operations are preserved; new
instruction run records are PICTURE-only. No data-table byte, unrelated procedure
or helper contract is promoted or changed. Stable +7E30's old operand-row label
is retained as a verified coordinate-only EQU; new +7E2E is an actual instruction.

The accumulated local graph now has all 243 bytes represented: the observed
positive path establishes both nested CALL/RET boundaries, rejoins the previously
observed +7BA2 continuation and reaches an original-slot RET. All local branch
and return targets have reviewed instruction groups; shortcuts share the existing
forward entry. Existing entry/terminal/independently called +7E46 neighbor bounds
remain supported. These facts justify **stable bounds / complete local control
flow / partial contract**, independently of the byte-count threshold.

[before.json](before.json), [after.json](after.json) and [progress.json](progress.json)
retain changes. Contract remains partial for attr0/1/5/7, shortcut202B/2011,
mapped>=F7, forward wrap, recursive21/comparison/termination and full alias/provenance
questions, resident error/opaque buffer-host paths. Initial-table absence is not
used to erase runtime1/7 uncertainty. +0EF6 and packet architecture are unchanged.

MINIMAL executed statuses/dynamic percentages remain unchanged because these
six bytes were not fetched there. Only the live +7D53 completeness link in its
inventory updates; byte/instruction/count facts remain identical.

## Validation and next work

Seven focused tests reproduce authoritative/reassembled table bytes, all class
counts/candidates, exact helper encodings/bit relations, ten golden RELs and
canonical coordinates, selected read/write chronology, same-valued-write source
replacement, selected return/cache and attr6 flag/call/channel relations, fresh
word-cache reads, distinct zero emissions, six-byte promotion and scoped graph
closure. All required Pass13/14, 109 MINIMAL, 27 packet/continuation, V1, project and
historical-byte checks pass, plus `git diff --check`. **All 94,720 historical bytes
reconstruct EXACTLY.** Generated structural/witness/packet artifacts are ignored;
unrelated untracked files are untouched.

**No matched PL/I fixture is needed to answer attr6 suppression/pair routing.**
The existing PICTURE example supplies it. If attr5 remains the next question,
first analyze the already-positive FACTOR execution before inventing syntax.
This pass assigns no PL/I syntax-to-mapped-byte meaning, and does not claim that
other missing states are impossible. A later fixture is warranted only after
relevant existing positive evidence has been classified and found insufficient.
