# Pass 30 — accumulated natural +240A archaeology

Baseline: `69af8d37c43f739a4daff5ffe935c94be114af53`.

**Decision A:** the accumulated natural evidence supports a clean bounded +240A
composition for Pass31, together with its +2511 parent. No native implementation,
new source fixture, CPU/Runner/CP/M change or packet change was made here.

## Selected evidence and structural facts

Existing corrected ordinary-return captures were reused independently:

| Run | Capture | +240A | All +23A0 | All +23D2 | +2511 |
|---|---|---:|---:|---:|---:|
| MINIMAL | `_build/minimal-baseline/capture` | 8 | 3 | 8 | 8 |
| FIZZBUZ | `_build/evidence-packet-cross-run/fizzbuz-capture` | 77 | 58 | 77 | 64 |
| PICTURE | `_build/discriminator-pass-15/selected-capture` | 12 | 7 | 13 | 9 |

Exact capture run IDs, canonical caller coordinates/counts, return sites and local
coordinate unions are in [natural-paths.json](natural-paths.json). Counts were
freshly derived from exact CALLs and corrected original-slot returns. Child windows
are isolated; these are not basic-block or context ownership estimates. Every
retained local instruction is checked against the authoritative PLI1 image.
The images retain their manifest SHA-256 identities and total 94,720 bytes.

Input-index counts are MINIMAL `0:8`, FIZZBUZ `0:76, 2:1`, PICTURE `0:11, 2:1`.
All +240A returns are +24F0. Callers are:

| Canonical caller | MINIMAL | FIZZBUZ | PICTURE |
|---|---:|---:|---:|
| PLI1+251E | 8 | 64 | 9 |
| PLI1+5E94 | 0 | 8 | 2 |
| PLI1+2500 | 0 | 1 | 1 |
| PLI1+0F68 | 0 | 1 | 0 |
| PLI1+4C4E | 0 | 3 | 0 |

No new local +240A instruction coordinate is executed: the accumulated union
remains **59 coordinates / 122 represented bytes out of 231**.

## Selector and path correlations — OBSERVED

All byte values in this table are hexadecimal; counts are decimal.

| Selector | MINIMAL | FIZZBUZ | PICTURE |
|---|---:|---:|---:|
| 02 | 0 | 18 | 2 |
| 05 | 2 | 6 | 0 |
| 15 | 3 | 41 | 5 |
| 24 | 0 | 5 | 0 |
| 28 | 1 | 5 | 2 |
| 40 | 2 | 2 | 2 |
| 43 | 0 | 0 | 1 |

Selector15H / extra0 accounts for **3 / 41 / 5** calls. The other route,
selector not15H/16H/19H, accounts for **5 / 36 / 7**. Both index2 calls have
selector28H, primary byte09H and extra00H; they follow the default route.

The selector15H path passes `C=byte[A642]`, `E=byte[A62B+saved index]` to +23A0,
then freshly addresses A62B+saved index and writes returned A there. All 49 such
child calls observe C>=E. Their extra byte at A62E+saved index is zero:
CPI00 at +2442 produces Z=1, and JZ +2444 skips the RAW nonzero-extra arm.
Other selectors take JNZ +241A, JNZ +2464 (CPI16H) and JNZ +24AC (CPI19H).
Per-invocation branch flags and immediate producers are retained, rather than
constructing combinations from unrelated observed values.

**STATIC / UNOBSERVED:** selector16H, selector19H and selector15H with nonzero
extra state. Their RAW intervals `[2447,2455)`, `[2467,24A0)`, `[24AF,24D5)`
are unchanged. No new +240A arm or source-language algorithm was inferred.

## +23A0 — both returns now established

| Run | C>=E | C<E |
|---|---:|---:|
| MINIMAL | 3 | 0 |
| FIZZBUZ | 50 | 8 |
| PICTURE | 6 | 1 |

The new C<E observations belong to +25CA and +25E0, **not** to +240A.
FIZZBUZ +25E0 has five `(C,E)=(01H,10H)` and two `(02H,10H)` cases;
+25CA has `(0FH,36H)` once in each of FIZZBUZ and PICTURE.
Full independent cases, callers and returned registers/flags are retained in
[23a0-cases.json](23a0-cases.json).

**DEDUCED from exact instructions and both observed outcomes:** write E to A64F
first, then C to A64E; reload C, CMP against saved E; JNC selects saved E iff
unsigned C>=E, otherwise reload saved C. Returned A is unsigned min(C,E).
HL remains A64F, BC/DE remain unchanged, and all flags describe **C-E**, independently
of the returned minimum. LDA/RET preserve those flags. There are no body CALL/PUSH
writes; RET consumes the original outer CALL word.

The exact bytes `3A 4E A6 C9` at `[23B0,23B4)` are now dynamically observed as
`LDA A64EH; RET`: **four RAW bytes become UNDERSTOOD**. The complete local graph has
two ordinary returns, no indirect transfer or delegated callee and no remaining
local bytes/arms. At the writable-cache/code/return-stack nonaliasing scope,
+23A0 becomes **stable / complete / complete**, with 24 represented bytes.

An existing pseudocode-order error was corrected: the historical cache order is
E/A64F **before** C/A64E, not the reverse. The exact annotated instructions already
had the correct order; no historical byte or minimum result changed.

## Common +240A publication tail and +23D2

The common tail freshly selects the little-endian pointer word at
`A63B + 2*saved_index`, reads both AE32/AE33 and passes only the low position to
complete +7AF0. Its selected destination is `AB49+2*fresh position_map[position]`;
the setter writes low then high. The pointer selection and publication are separate
channels; equal words do not establish provenance.

Next +240A freshly reloads its saved index and calls +23D2. The latter remains
**stable / complete / complete**, with 56 represented bytes. Its 98 independent
natural calls include PICTURE's one additional direct caller +2591 outside +240A.
The chronological channels are:

| Source read | Fresh position carrier | Child | Publication |
|---|---|---|---|
| A628+index | AE32/AE33 | +7B13 | AC73+fresh map index |
| A62B+index | AE32/AE33 | +7B2E | AD08+fresh map index |
| A62E+index | AE32/AE33 | +7B49 | AD9D+fresh map index |

Each source read, paired position read, actual setter argument, fresh map read and
unconditional destination write is correlated within the same invocation in
[publication-correlations.json](publication-correlations.json). Channels remain
separate even when values match. Return A is the last source byte; BC is its
zero-extended map index, HL its AD9D destination, D is preserved from +23D2 entry,
E is the last byte. NZPA/AC are preserved from +23D2 entry; CY is clear.
+240A delegates its final register/flag state to this last child, apart from its
own SP/continuation. It does not return an independent selector predicate.

In the observed +240A routes, final NZPA/AC retain the last local comparison:
CPI00 on the extra byte for selector15H, or CPI19H on the default selector.
The common pointer address additions and complete setters leave CY clear. All
97 observed returns have A=00H, D=FBH and E=00H; these concrete values do not
define the supported-domain guard or establish a returned Boolean.

## Provenance, aliases and next boundary

The audit tracks **observed** CPU and factual host memory writes and checks read/
write continuity for relevant entry cells. Last-writer records identify exact
addresses/events, not ownership. Both index2 selectors were last written at +27DA,
and their pointer words at +3296. No table capacity, source-language object type,
producer immutability or global alias model is inferred.

The demonstrated composition assumes readable selected indexed sources, pointer
and paired carriers; writable saved-index and helper caches; and nonaliasing among
those sources/caches, selected destinations, accessed map cells, executable code
and original/nested return-stack cells. The audit checks concrete selected
publication destinations against these retained source/cache/map/stack cells and
against one another. A future implementation must retain each child's full
preconditions and chronological fresh reads, not assume equal map values are a
single reusable index. Wider index support requires the same explicit address/
alias conditions, not a guessed table capacity.

+240A remains **provisional / partial / partial**; no RAW arm was inspected to
complete its graph. Its represented accumulated scope gains a clean bounded
contract. There is **no unresolved discriminator within the current 97 natural
cases**. Remaining unsupported selector/provenance/alias states are explicit.

Recommend **Pass31: bounded native +240A and +2511 together**, with complete
+23A0 and +23D2 added as faithful reusable/internal primitives. Select behavior
from actual fresh selector/extra predicates; reject16H/19H and15H/nonzero-extra
before live commit. +2511's other children +8048/+7EC0 are already bounded native;
their restrictions must be inherited without widening. Preserve +2511's one-byte
frame and restore its saved input independently around all three child calls.
No new fixture or broad decompilation is needed for that bounded experiment.

[before.json](before.json), [after.json](after.json) retain exact catalog changes;
[boundary-assessment.json](boundary-assessment.json) records the decision.

## Reproduction and validation

Regenerate independent selected-run facts with:

```sh
python3 tools/annotated-assembly/check_240a_pass_30.py \
  --images /path/to/DISK1 --output-dir _build/host-compiler-pass-30/regenerated
python3 tools/annotated-assembly/test_240a_pass_30.py --images /path/to/DISK1 -v
```

The focused tests regenerate all cases, verify exact caller/catalog counts,
selector/flag polarity, both minimum arms, fresh channel chronology, observed
entry writers, byte/status union and preservation of RAW arms. Corrupted return
flags and publication writes are rejected. No capture or RAM snapshot is committed.
Broad validation results are recorded in [validation.json](validation.json).

Validation completed: **279 Python tests**, including all 109 MINIMAL and 27
packet/continuation tests, plus the project’s 33 Dune test stanzas and native unit
executables. Fresh Pass17–29 shadow/hybrid regressions pass. The frozen Pass16
classification test now reads the recorded pre-Pass30 catalog state for +23A0;
its original reconnaissance claim is preserved rather than rewritten to match
the new complete contract. All 94,720 historical bytes reconstruct EXACTLY;
`git diff --check` passes. MINIMAL dynamic progress is unchanged by the four
FIZZBUZ/PICTURE-only bytes. No pragmatic divergence or fidelity debt was introduced.
