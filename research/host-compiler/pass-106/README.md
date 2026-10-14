# Pass106 — first lowering to upstream MIR

Baseline: `e064fb04149e974bd7380cf6f1e4344797aefb61`.
MIR means [Vladimir Makarov's MIR](https://github.com/vnmakarov/mir), not a new
OCaml intermediate representation. This optional experiment calls the actual
library from OCaml. It is outside every installed compiler/runtime path.

## Upstream choice and embedding

Chosen upstream revision: `a8ab7c31cd5f9b23b77d84c60b3d83e62d9d304c`.
License: MIT, copyright Vladimir Makarov; no fork was needed. See the pinned
[API documentation](https://github.com/vnmakarov/mir/blob/a8ab7c31cd5f9b23b77d84c60b3d83e62d9d304c/MIR.md),
[header](https://github.com/vnmakarov/mir/blob/a8ab7c31cd5f9b23b77d84c60b3d83e62d9d304c/mir.h),
[build instructions](https://github.com/vnmakarov/mir/blob/a8ab7c31cd5f9b23b77d84c60b3d83e62d9d304c/INSTALL.md),
and [license](https://github.com/vnmakarov/mir/blob/a8ab7c31cd5f9b23b77d84c60b3d83e62d9d304c/LICENSE).
The actual pinned headers take precedence over documentation examples; for
example, the error callback declaration has no context argument.

Upstream documents x86_64 Linux/macOS, aarch64 Linux/macOS, and ppc64le, s390x,
riscv64 Linux targets. This experiment was built and tested only on x86_64 Linux,
OCaml 5.4.0 and GCC 16.2.1. It uses `make -j2 libmir.a`, C headers, a C compiler,
GNU make, OCaml's native compiler and system math/dl/pthread libraries. The
upstream archive target also compiles c2mir; we do not invoke that C frontend.
JIT executable-memory permissions and a supported host ABI are required. This is
not a claim that the OCaml stub has been validated on every upstream target.

`tools/mir/pass106/bridge.c` is the entire FFI: one synchronous function with four
OCaml arguments. It copies a 16-byte input into an owned C buffer, initializes a
context, parses fixed reviewed MIR with `MIR_scan_string`, loads/links the module,
and uses either `MIR_interp_arr` or `MIR_gen` and its generated C ABI function.
The JIT uses optimization level 0. The context and generated code are destroyed
before allocating the returned OCaml bytes. No OCaml heap pointer is retained by
MIR, and there are no callbacks, external symbols, persistent contexts, runtime
lock releases or shared mutable handles. Input is never mutated.

The stub validates buffer width and indices before MIR initialization. Upstream
library errors remain process-fatal in this isolated proof executable. Arbitrary
MIR text is not accepted. This is **not** a production binding for untrusted
programs: error containment, resource limits, concurrency and broader target
support need separate design before such use. A full API binding or ctypes
dependency would add no value for this one fixed function.

The focused category fetches the exact revision into its own ignored `_build`
checkout if absent, verifies tracked source integrity and builds there. A cached
checkout at that revision permits offline reruns. Normal `dune build` and
`dune runtest` neither fetch nor link MIR. No source or artifact from the isolated
Pass105 FULL checkout is used or modified.

## Boundary selection

| Candidate | Evidence | Reason for selection/deferment |
|---|---|---|
| Pass58 +7B99 / +793C | Proved indexed carrier transfer and emission | Select its smaller +793C non-6 transfer prefix; emission and +7AE4 preparation remain outside |
| Pass64 +82DD | Proved trailer/word-emission paths | Output cursor, alignment, console, BDOS and opaque representation state make this a larger first boundary |
| Pass66 +8072 | Proved conditional preparation/publication paths | Pending state and branch-specific generation dependencies; language-level relation interpretation is not yet established |

Selected instruction interval: PLI2.OVL `[793C,797E)`, runtime `[9B3C,9B7E)`
with image base 2200h. It stops **before** the emission setup at +797E. This is
not a complete +793C, +7B99 or compiler pass replacement.

### Exact semantic contract

Inputs are two disjoint channels of eight opaque unsigned bytes, a source slot
0..7 excluding 6, and a destination slot 0..7. Both channels and indices are
explicit inputs. Channel A is historically ADAB..ADB2; B is ADB3..ADBA.

1. Read A[source] and publish it to A[destination].
2. Read B[source] and publish it to B[destination].

All other channel bytes remain unchanged. Same-slot and same-valued publications
remain logical effects. The result is 16 state bytes followed by two publication
values in A-then-B order. The destination slot is the explicitly supplied input;
channel identity and publication order are fixed by this operation.

`transfer.mir` is real upstream MIR text, with `p` buffer arguments, `i64` bounded
indices/locals, `u8` loads/stores and an `i64` zero status return. The host ABI
pointer width is MIR's responsibility. No host-endian word serialization occurs:
all transferred payloads are bytes, never sign-extended PL/I values. A separate
two-byte publication buffer makes logical effect order observable as result
data. This does **not** promise that native physical memory stores cannot be
optimized/reordered, or substitute for the historical ordered RAM journal.

The OCaml caller supplies concrete bytes and indices directly to this fixed MIR
function. Its small reference function independently computes the expected
projection; it defines no replacement IR, opcode hierarchy or generic evaluator.

### Evidence classification and exclusions

**OBSERVED:** ten fresh concrete FIZZBUZ prefixes, all called at +7BAE, with
(destination,source) pairs (7,4) four times, (5,7) three, (4,7) three. They execute
29 instructions each, matching Pass58's published inventory. Each has eight
ordered CPU writes and an unchanged entry SP. Full 64 KiB RAM is checked using
an independently computed channel update and explicit test-only residue law.
The original CALL word is verified; no RET or child service occurs in this prefix.

**DEDUCED:** the instruction-derived two-channel law on the explicitly bounded
non-6 indices; 56 synthetic Intel 8080 windows cover every such index pair,
including seven self-copies. MIR interpreter and JIT each cover those pairs with
distinct and same-valued channel patterns (112 synthetic inputs per engine),
plus all ten CPU-derived natural inputs. Twelve FFI negative checks reject bad
width, source 6, and negative/out-of-range indices without changing the input.
Synthetic coverage is not new natural observation or knowledge promotion.

**HYPOTHESIS:** what these channels mean in PL/I terms (variables, allocation,
types or source-language assignments). None of those meanings is asserted.

Source 6's clear-A route, wider indices, emission, pending preparation, output
errors and any source-language interpretation are outside this experiment.
The FFI always owns distinct channel/publication buffers; arbitrary historical
RAM aliasing is not accepted as an implicit parameter.

## Historical effects retained outside this boundary

The independent test adapter accounts for the actual sequence:
AE03=source, AE02=destination, source-A address PUSH bytes, A publication,
source-B address PUSH bytes, B publication. The two PUSH/POP pairs leave their
actual residue below SP. The original hardware continuation remains at SP/SP+1;
this prefix does not consume it. Fresh scratch/pointer reads and register/flag
changes belong to the historical implementation. They are not silently carried
as MIR compiler state. The existing Pass58 full operation and its stronger
machine-level proof are unchanged.

The MIR demonstration compares its **defined projection**, not full CPU state,
flags, services or historical read chronology. The separate CPU proof checks
complete prefix RAM and ordered writes; it is not evidence that the JIT exactly
recreates historical flags or stack. No file/console bytes are emitted here.

## Validation and preservation

Run:

```
python3 tools/annotated-assembly/run_host_compiler_regressions.py \
  --categories pass106,diff-check,validation-runner-tests \
  --images /home/john/pli/cpm/pli80/DISK1 \
  --output _build/host-compiler-pass-106/validation --workers 4
```

`validation.json` preserves the measured receipt. `historical-shadow.json` and
`mir-results.json` preserve the concrete and real-MIR results; `upstream.json`
records the build identity. `implementation-packet.json` binds their digests.
The category checks all four historical image lengths and hashes (total 94,720)
and the unchanged annotated-assembly tree against the prior reconstruction
receipt. No annotations changed, so V1/regeneration is unnecessary.

The fresh FIZZBUZ complete guest run preserves REL SHA256
`68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`.
Other four goldens and all active runtime sources remain unchanged; no claim of
five fresh program runs is made. No native roots or knowledge promotions.
Pass74 epoch 3 remains last certified FULL. No FULL was launched; Pass79 failures
and the isolated, unsuccessful Pass105 FULL evidence are preserved.

## Future integration contract

Recovered PL/I declarations, types, source control flow and verified language
rules belong in the future OCaml frontend. This experiment supplies none of
those missing semantics. Once established, bounded operations can lower directly
to upstream MIR API/instructions, with explicit state/output buffers and defined
widths. MIR handles host execution and host calling conventions.

Historical adapters must retain opaque generation, cache, cursor, record and
service state until a replacement projection has independent differential proof.
They must not hide global writes behind an apparently pure compiler operation.
An eventual REL/INT backend receives explicitly ordered, independently specified
serialization effects. **Upstream MIR is a host interpreter/JIT, not an Intel
8080 backend or historical CP/M REL producer.** Native host code is not the
historical compiled program. Standalone compilation and a future Playground
need separate frontend, diagnostics, isolation and output-backend work.

Smallest next step: express the already proved source-6 clear-A variant as an
explicit supported branch of this same real MIR function, with independent CPU
and MIR differential checks. Beyond that, specify the emission operation's
explicit state and ordered serialization contract before lowering it. Do not
infer that emitted field bytes are an entire REL backend. Production integration
would also require review of MIR error containment and resource ownership.
