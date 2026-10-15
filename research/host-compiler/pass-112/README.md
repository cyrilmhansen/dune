# Pass112 — first bounded PL/I semantic lowering to upstream MIR

Baseline: `6495d609fa046ee51ecc34525da3bfd89b463809`.

**Established:** documented `MOD(a,b)` semantics for signed FIXED BINARY(15),
with `0 <= a <= 32767` and `b` in `{3,5,15}`, execute through real upstream
MIR's interpreter and generated x86_64 code and agree with an independent
mathematical reference. **Historical linked-runtime equivalence remains unproved.**
This is an experimental semantic call boundary outside active compilation paths.

## Contract and evidence

[Digital Research's PL/I-80 Language Manual, second printing December 1980](https://www.bitsavers.org/pdf/digitalResearch/pl1/PL1-80_Language_Manual_Dec80.pdf),
sections 3.1.1 and 12.1.7, supplies the documentary arithmetic basis.
The original local PDF was checked against SHA256
`85e09fc830a3520d2e5e24d051cdf74593b393b1851ee982196555e6435b848a`.
Printed pages 14–15 and 76 correspond to zero-based PDF pages 20–21 and 82.

FIXED alone declares a signed binary integer of precision 15. Its documented
range is -32768..32767 and its storage is two bytes; precision is not storage
width. The documented general law is `a - abs(b)*floor(a/abs(b))` for nonzero b,
with a separate b=0 branch returning a. MOD's result has the common arithmetic
type. On the admitted nonnegative/positive subset this is `a-b*floor(a/b)` and
`0 <= result < b`. All intermediate values here fit safely in signed i64.

Pass111's source-correlated typing and result-consumer proof establishes the
selected FIZZBUZ common FIXED BINARY(15) context. It did not execute arithmetic.
Pass112 uses semantic integer values, without compiler carrier addresses,
attribute tuples, stacks or serialized INT/REL data as inputs. The full language
range is documented; the admitted execution domain is deliberately narrower.

`semantic-contract.json` separates DOCUMENTED rules, DEDUCED equivalence of
signed remainder on this domain, OBSERVED MIR execution, and UNPROVED runtime
compatibility. The manual's contemporary edition does not establish every v1.4
runtime detail. No universal metadata-tag decoding is assumed.

## Implementation

The implementation is in `tools/mir/pass112/`:

- `fixed_binary_mod.mli/ml`: abstract checked nonnegative15 input, closed divisor
  type Three/Five/Fifteen, explicit Interpreter/Jit choice and scalar result.
- `mod_positive.mir`: one fixed function with `mod result, a, b` followed by ret.
- `bridge.c`: synchronous narrow FFI, MIR_scan_string, MIR_interp_arr or MIR_gen,
  and context disposal before returning. No imported C arithmetic helper.
- `reference.ml`: repeated subtraction derives q and r, checking
  `a=q*b+r` and `0<=r<b`. A separate ascending-multiples check derives predicates.
- `demo.ml`: actual differential executions, rejection tests and recovery.

Upstream is [vnmakarov/mir](https://github.com/vnmakarov/mir), MIT, pinned unchanged
at `a8ab7c31cd5f9b23b77d84c60b3d83e62d9d304c`.
Its pinned MIR.md, mir.h, mir-interp.c and mir-gen-x86_64.c were inspected:
`mod` is signed 64-bit remainder, interpreted with `%` and lowered to host
signed division/remainder. Truncation and floor agree on the admitted domain.
C `int64_t`/MIR i64 is a wider host implementation choice, not PL/I precision.
`upstream.json` records source/library digests and the actual Linux x86_64,
OCaml 5.4.0 and GCC environment. Other host targets are not tested here.

OCaml constructors reject unsupported values. A second C guard rejects before
MIR initialization, including test-only calls bypassing the abstract OCaml type.
Thus no zero division, negative input or signed division overflow reaches MIR.
Only scalar values cross the FFI: no OCaml heap pointer, buffer, callback,
filesystem or persistent JIT context. A local byte-buffer/state canary remains
unchanged across accepted and rejected calls. Fixed reviewed MIR is the only
accepted program; upstream fatal-error behavior remains a limitation of this
isolated proof executable, as in Pass106.

Ordinary Dune builds have no MIR dependency. The focused optional test fetches
and builds the exact pin under isolated ignored `_build/host-compiler-pass-112/`.
No historical implementation, native controller or production compilation path
is replaced. Pass106/107 remain independent technology precedents.

## Actual differential results

`mir-results.json` records every result, not expected post-state fixtures:

- 87 distinct arithmetic cases per engine, plus one recovery call per engine.
- Zero, below/equal/above divisor, exact multiples, consecutive quotient
  boundaries and every numerator 32760..32767 for each admitted divisor.
- All i=1..15 with divisors 15, 3 and 5: 45 independently checked predicates.
  True sets are respectively `{15}`, `{3,6,9,12,15}` and `{5,10,15}`.
- All reference, interpreter and JIT results agree exactly; JIT optimization 0.
- 15 OCaml constructor rejections and 30 C-boundary rejections across both modes.
  Calls after rejections recover with MOD(32767,15)=7 in both engines.

The arithmetic reference does not use division/remainder or invoke MIR. Predicate
reference uses ascending multiples. Both engines execute the same reviewed MIR
function. These observations are documentary semantic differential evidence,
not independent Intel 8080 runtime observations. No broad exhaustive arithmetic
campaign or performance claim is made.

## Bounded historical runtime feasibility

The actual distribution contains LINK.COM and PLILIB.IRL. The existing FIZZBUZ
REL matches SHA256
`68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`.
`runtime-oracle.json` records input hashes and two capped attempts through the
existing Runner and memory-backed CP/M filesystem: 500,000 and 10,000,000
instructions. The final attempt printed LINK 1.31's link map and created 4096
bytes of partial in-memory COM output, but reached the cap before returning.
The incomplete output was neither exported nor executed.

`runtime-probe.ml` preserves the final small probe, using existing interfaces;
the initial attempt differed only in cap. Raw receipts remain in ignored
`_build/host-compiler-pass-112/runtime-probe/`. The cap result is not a diagnosis
of a CP/M defect or proof that linking cannot succeed. No linker, library decoder
or runtime subsystem was implemented. **No historical PL/I-80 runtime MOD value
was observed.** The documented arithmetic oracle is sufficient for this bounded
semantic milestone and remains a separate claim.

## Validation and preservation

```
python3 tools/annotated-assembly/run_host_compiler_regressions.py \
  --categories pass112,pass111,pass107,pass106,diff-check,validation-runner-tests \
  --images /home/john/pli/cpm/pli80/DISK1 \
  --output _build/host-compiler-pass-112/validation --workers 4
```

`validation.json` is the unmodified actual receipt: **8/8 categories passed,
36 Python test executions, 16.160s wall, 25.951s summed category time, 4 workers**.
Build and project are mandatory. Pass111 also rechecks source/type evidence;
Pass106/107 remain passing. No FULL execution or scheduling occurred.

`preservation.json` records unchanged Git objects for runtime, images/annotations,
prior evidence and certification policy. All four original image hashes were
freshly checked, totaling **94,720 bytes**, against preserved exact reconstruction
evidence and an unchanged annotated-assembly tree. No reconstruction regeneration
was needed. Fresh selected predecessor checks preserve FIZZBUZ REL; all five
published golden records remain unchanged. A fresh five-program runtime campaign
is not claimed. No annotations, promotions, native roots or installed execution
savings. Pass74 epoch 3 remains the last certified FULL. Pass79 and isolated
Pass105 failure evidence are untouched.

## Exclusions and next step

Negative operands need independently justified floor correction before enabling
them. Zero divisor is deliberately rejected despite the documented special
branch; no host exception substitutes for that rule. Other divisors, decimal or
floating values, scale changes, mixed/general conversions, precision overflow
and exceptional behavior remain excluded. Historical INT/REL compatibility is
not the MIR boundary.

The next small semantic extension is explicit negative-numerator MOD for the
same positive divisors, deriving floor correction and testing negative exact
multiples and boundary values with an independent floor-law reference. A separate
bounded linker investigation could establish a genuine historical runtime oracle;
it is not a prerequisite for this documented positive subset. Neither extension
is implemented here.
