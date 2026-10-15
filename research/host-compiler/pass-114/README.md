# Pass114 — composed PL/I arithmetic through upstream MIR

Baseline: `468d266b0659180aa3c3d965c902055efd583d78`.

**Established:** one manually selected, source-correlated PL/I semantic
composition executes through real upstream MIR interpreter and x86_64 JIT.
For the actual ARITH values a=17, b=25, both produce **c=58**. This is not a
general source-to-native compiler or execution of the historical linked ARITH.

## Source and historical evidence

`examples/pli80/ARITH.PLI` declares a, b and c FIXED on lines 2–4, assigns 17 and
25 on lines 5–6, then contains:

```pli
c = a * 2 + b;
if c > 50 then c = c - 1;
```

`source-correlation.json` records exact source hash, line/column spans and
roles of constants **17,25,2,50,1**. Selection and lowering are manually reviewed;
no new frontend parses these spellings. The function takes semantic a,b after
initialization and returns c after these two statements. PUT and main-procedure
execution are outside the boundary. For extra tests, a,b are supplied semantic
values, not new source-program compilations.

The archived compiler summary and `docs/pli80-experiments.md` establish
**678,165 compiler instructions**, successful passes, END COMPILATION and warm
boot, with a **256-byte REL**. Its fresh SHA256 remains
`ca98a3a7e1900d65f2b8bf73b8ccdd9e0e49ce7f15768607348740b1b7a8e553`.
This proves source-to-REL compilation, not historical runtime arithmetic.
The archived summary is identified by path and digest; it was not rewritten.

## Documentary type and arithmetic contract

The primary basis is the [Digital Research PL/I-80 Language Manual, second
printing December 1980](https://www.bitsavers.org/pdf/digitalResearch/pl1/PL1-80_Language_Manual_Dec80.pdf),
verified local PDF SHA256
`85e09fc830a3520d2e5e24d051cdf74593b393b1851ee982196555e6435b848a`.
`semantic-contract.json` records sections and page coordinates.

- §3.1.1: FIXED defaults to signed FIXED BINARY(15), two-byte storage and range
  -32768..32767. Integer constants in binary-requiring contexts are binary.
- §§7.1.3/7.1.4: multiplication precedes addition; arithmetic relations use
  algebraic ordering after common conversion.
- §7.2.1: binary product precision is `min(15,p+r+1)`; sum/difference precision
  is `min(15,max(p,r)+1)`. Insufficient binary precision loses high bits.
- Chapters 7 and §8.2: assignment sets the target; a true IF executes THEN.
  Out-of-range binary assignment is undefined (§3.1.1).

Each selected arithmetic intermediate has **precision 15**, derived from these
formulas because one operand already has precision 15. This is separate from
the declared variable precision and the wider host implementation. Exact
compiler metadata encodings or the binary precision assigned to each literal
are not inferred: the capped formulas give 15 regardless of the positive
precision of these integral constants. All chosen constants are exactly
representable in the admitted binary context.

### Safe domain

Inputs a,b must be integers in **[-32768,32767]**. Additionally **2*a** and
**2*a+b** must each lie in the same interval. Equivalently, a must be in
[-16384,16383], b in the full interval, and the sum guard must hold. None of
these checks may be omitted, even when an out-of-range product could cancel
against b to produce an in-range sum.

On this domain, product, sum and assignment to c lose no precision. If c>50,
then c-1 is also representable, so the second assignment is exact. MIR i64 is
safe for every admitted calculation and for guard calculations after checking
inputs. It is not a claim that PL/I precision is 64 bits. Overflow, truncation,
undefined assignments and mixed-type/scale conversions remain outside scope.
The documentary edition is not blanket evidence for every v1.4 runtime detail.

## Actual MIR implementation and scalar interface

`tools/mir/pass114/arithmetic.mir` has one function:

```text
mul product, a, 2
add result, product, b
ble done, result, 50
sub result, result, 1
done:
ret result
```

Pinned upstream MIR.md and instruction/interpreter definitions were checked:
mul/add/sub are 64-bit integer operations and **ble is signed less-or-equal,
label first**. Skipping subtraction when c<=50 implements strict `c>50`.
The actual upstream repository remains vnmakarov/mir, MIT, revision
`a8ab7c31cd5f9b23b77d84c60b3d83e62d9d304c`. Both MIR_interp_arr and MIR_gen
execute this reviewed function, JIT optimization level 0. There are no imported
arithmetic helpers. The JIT backend tested is Linux x86_64; other targets are
not claimed.

`arithmetic.mli/ml` provides only an abstract checked input, make and evaluate,
with explicit engine selection and scalar integer output. The narrow C stub
reuses Pass112's synchronous scanning/execution/disposal pattern, but has its
own operation-specific guards. C/OCaml calculate ranges for admission; **MIR
computes the returned arithmetic result**, including the branch and subtraction.
Raw C calls bypassing the OCaml constructor receive the same pre-MIR guards.
No mutable input buffer, compiler global state, callback or persistent JIT
context crosses the boundary. Upstream fatal-error behavior for this isolated
fixed-program experiment remains the inherited limitation.

The existing test build recipe has one additional module-name parameter,
defaulting to the original module. Pass112/113 code, APIs, MOD functions and
published evidence are unchanged. The optional proof builds under isolated
ignored `_build/host-compiler-pass-114/proof`; ordinary Dune remains MIR-free.

## Independent differential validation

`reference.ml` computes doubling as a+a, separately retains product and sum,
uses Int.compare for the decision, and pred for the conditional decrement.
It checks all input, intermediate and final ranges. It does not call MIR, the
C stub or the production guard. Tests independently verify each reference
intermediate and compare the final result with both real execution modes.
The journal's intermediate/decision columns describe the **reference**; MIR
returns a scalar, not an observed internal-variable trace.

`mir-results.json` contains **19 cases per engine**, plus **72 recovery calls**
(36 per engine) after 12 constructor and 24 raw-C rejections. Cases include:

| a | b | Before IF | Final c |
|---:|---:|---:|---:|
| 17 | 25 | 59 | 58 |
| 17 | 16 | 50 | 50 |
| 17 | 17 | 51 | 50 |
| 0 | 0 | 0 | 0 |
| -10 | 25 | 5 | 5 |
| -10 | -25 | -45 | -45 |
| 16383 | 1 | 32767 | 32766 |
| -16384 | 0 | -32768 | -32768 |

Other signed/cancellation and exact boundary cases distinguish signed comparison,
strictness at 50, multiplication-before-addition and conditional decrement.
Inputs outside either operand range, product-only overflow despite cancellation,
and sum overflow are rejected before MIR initialization. Valid calls return 58
after each rejection, in both modes. Immutable inputs and an OCaml-owned
buffer/state canary remain unchanged. This is a small discriminating suite,
not exhaustive arithmetic testing or a benchmark.

## Validation and preservation

```sh
python3 tools/annotated-assembly/run_host_compiler_regressions.py \
  --categories pass114,pass113,pass112,pass107,pass106,diff-check,validation-runner-tests \
  --images /home/john/pli/cpm/pli80/DISK1 \
  --output _build/host-compiler-pass-114/validation --workers 4
```

`validation.json` is the exact actual receipt: **9/9 categories passed, 40 Python
test executions, 16.874s wall, 19.953s summed category time, 4 workers**. Build
and project are mandatory. Existing MOD and MIR demonstrations remain passing.
The only older test edit lets its existing build recipe name the new module;
no new validation framework is introduced.

`preservation.json` records unchanged Git identities for runtime, source,
annotations, earlier research/certificates and MIR operation implementations.
Fresh complete-image hashes against preserved exact reconstruction evidence
still cover **94,720 bytes**. No regeneration or V1 changes were needed.
Archived ARITH and FIZZBUZ REL hashes were freshly checked; all published
goldens remain unchanged. FIZZBUZ SHA256 remains
`68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`.
No new historical compilation, linked program execution or five-program
runtime campaign is claimed. No LINK investigation, MOD extension, FIXED
DECIMAL work, native roots, promotions or FULL run. Pass74 epoch 3 remains
last certified FULL; prior certification/failure evidence is untouched.

## Confidence and next step

**DOCUMENTED:** selected language arithmetic, precision and control rules.
**OBSERVED:** exact source, archived compilation, and actual MIR differential
outputs. **DEDUCED:** the safe source-correlated contract and result58.
**UNPROVED:** historical linked-runtime equivalence, automatic frontend lowering,
general conversions/overflow and instruction-level ARITH metadata causality.

A next small composition could add one independently documented Boolean
combination of arithmetic comparisons, preserving explicit typing and guards.
It should reuse this scalar approach without implying a parser or general
frontend. This pass does not justify treating historical INT/REL serialization
as the MIR boundary.

**RUNES PASS114 — FIRST COMPOSED PL/I ARITHMETIC MIR CONTRACT PROVED**
