# Pass113 — signed FIXED BINARY MOD through upstream MIR

Baseline: `af04987ed6afb4cc7b5d33107279144e474543d9`.

**Established:** documented PL/I MOD for `a` in **[-32768,32767]**, `b` in
**{3,5,15}**, with signed FIXED BINARY(15) operands and result. Actual upstream
MIR interpreter and x86_64 JIT agree with an independent floor-quotient reference.
This is a semantic experiment, not observed linked PL/I-80 v1.4 runtime behavior.

## Arithmetic and real MIR branch

The documentary basis remains the [Digital Research PL/I-80 Language Manual,
second printing December 1980](https://www.bitsavers.org/pdf/digitalResearch/pl1/PL1-80_Language_Manual_Dec80.pdf),
sections 3.1.1 and 12.1.7, identified and verified in Pass112. Its signed
FIXED BINARY(15) range is -32768..32767, with two-byte storage. Precision is
not storage width. For positive b the floor law is `a-b*floor(a/b)`; the
result has the common arithmetic type. Host MIR i64/C int64_t is a wider
implementation choice, not a different PL/I precision.

Upstream [vnmakarov/mir](https://github.com/vnmakarov/mir), MIT, remains pinned at
`a8ab7c31cd5f9b23b77d84c60b3d83e62d9d304c`. The actual pinned MIR.md,
mir.h and mir-interp.c were inspected before implementation: `mod` is signed
64-bit truncation remainder; `bge` is signed 64-bit comparison with the label
first. The documented text example uses `bge fin, iter, N`; the interpreter
implements MIR_BGE with `>=`. The fixed reviewed function is:

```text
mod result, a, b
bge done, result, 0
add result, result, b
done:
ret result
```

This code is in `tools/mir/pass113/mod_signed.mir`. The correction executes
**inside MIR** in both MIR_interp_arr and MIR_gen, optimization level 0.
There is no imported arithmetic helper, OCaml/C result correction or oracle
computation. For nonnegative remainder, including negative exact multiples,
the branch skips the addition. For negative remainder, adding b changes the
truncation result to floor modulo. The result satisfies `0<=result<b`.
The admitted operands, quotient and correction cannot overflow i64.

## Small interface and reuse

`tools/mir/pass113/fixed_binary_mod.mli/ml` supplements the prior positive API
with an abstract checked signed15 numerator, the same closed divisor choices,
and explicit interpreter/JIT selection. Scalar semantic values are the only
inputs; historical scratch, flags, stacks and serialization are absent.

The existing Pass112 C bridge is reused with compile-time lower bound -32768
and a separate `runes_mir_mod_signed` symbol. Its defaults retain the original
positive domain and symbol. Only the signed build selects a different symbol/lower bound and diagnostic
label; positive defaults remain identical; execution, ownership, postcondition checking and disposal are
unchanged. The existing build recipe accepts the small source/output/flag
variation, avoiding a second MIR build or FFI infrastructure. Ordinary Dune
builds still have no MIR dependency. The optional category builds in its own
ignored `_build/host-compiler-pass-113/proof` directory.

Both OCaml and C check inputs. Calls bypassing the abstract constructor are
rejected by C **before MIR_init**. No zero divisor can enter MIR. Contexts remain
synchronous and per-call, with no shared mutable compiler buffers, callbacks,
heap pointers or persistent JIT runtime. Fixed reviewed MIR is the only program
accepted; upstream fatal-error behavior in this isolated proof executable
remains the inherited limitation. No active compiler/native path changes.

## Independent reference and actual results

`reference.ml` does not compute signed remainder followed by correction.
For negative a, it starts q and q*b at zero and descends by one quotient and b
until `q*b<=a`. For nonnegative a it uses repeated subtraction. It computes
`r=a-b*q` and independently verifies `q*b<=a<(q+1)*b` and `0<=r<b`.
The FIZZBUZ predicate reference separately walks ascending multiples.

`mir-results.json` records actual executions:

- **171 distinct arithmetic cases per engine:** all 87 Pass112 positive cases
  plus 84 negative cases, including 16 negative exact multiples and 68 negative
  nonmultiples. Both engines match the reference exactly.
- Near zero, both sides of negative multiples, several quotient boundaries,
  -32768..-32761 and 32760..32767 are covered for every admitted divisor.
- All **45 FIZZBUZ predicates** are retained unchanged. The newly executed
  positive rows equal every published Pass112 row, including quotient/results.
- **14 OCaml constructor rejections** and **28 C-boundary rejections** across
  both execution modes pass. Every rejection is followed by both engines
  successfully evaluating the minimum and maximum numerators with divisor 15.
  The 168 recorded recovery rows plus a final check in each engine total
  **85 additional recovery calls per engine**.
- Input-value checks and an OCaml-owned byte-buffer/state canary remain unchanged.
  No buffer is passed to C or MIR. Unsupported calls include -32769, 32768,
  OCaml integer extremes, zero/negative and other unsupported divisors.

Required results, independently checked in both engines:

| a | b | MOD |
|---:|---:|---:|
| -1 | 15 | 14 |
| -14 | 15 | 1 |
| -15 | 15 | 0 |
| -16 | 15 | 14 |
| -32768 | 15 | 7 |
| -32768 | 3 | 1 |
| -32768 | 5 | 2 |
| 0 | 15 | 0 |
| 32767 | 15 | 7 |

These are selected discriminants, not an exhaustive arithmetic campaign. The
supported contract follows the floor-law argument; empirical validation is the
published finite case set. Tested native generation is Linux x86_64 only.

## Validation and preservation

```sh
python3 tools/annotated-assembly/run_host_compiler_regressions.py \
  --categories pass113,pass112,pass107,pass106,diff-check,validation-runner-tests \
  --images /home/john/pli/cpm/pli80/DISK1 \
  --output _build/host-compiler-pass-113/validation --workers 4
```

`validation.json` preserves the exact actual receipt: **8/8 categories passed,
36 Python test executions, 3.534s wall, 5.738s summed category time, 4 workers**.
Build/project are mandatory; the signed category reuses the existing positive
engine/predicate/image/type checks and adds signed boundaries and preservation.
Pass112's newly produced result JSON equals its published positive result JSON.

`preservation.json` records unchanged runtime, images/annotations, earlier
research and certification policy Git objects. Complete original-image hashes
were freshly checked against preserved exact reconstruction evidence, totaling
**94,720 bytes**, with an unchanged annotated-assembly tree. No regeneration or
annotation/V1 changes were required. The FIZZBUZ REL remains
`68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`;
other published goldens are unchanged. No new five-source campaign is claimed.

Pass112's published evidence is untouched. Its incomplete LINK 1.31 probe was
**not resumed**. No historical runtime equivalence is claimed. No FULL was run,
scheduled or awaited; Pass74 epoch 3 remains the last certified FULL. Earlier
failure/certification records remain untouched. Native roots and knowledge
promotions: **zero**. Proof cases are not installed runtime savings.

## Unsupported boundaries and next step

Zero divisor remains rejected despite its documented special rule. Negative
or other positive divisors, mixed numeric types/conversions, out-of-range
values and general overflow/exception rules remain unsupported. No compiler
metadata, INT/REL or universal v1.4 implementation conclusion follows here.

The next bounded arithmetic extension could independently establish the
zero-divisor branch and its typed return behavior before enabling it. A real
linked historical runtime oracle remains a separate task. Neither is required
to distinguish floor modulo from truncation remainder on the admitted domain.

**RUNES PASS113 — SIGNED FIXED BINARY MOD PROVED**
