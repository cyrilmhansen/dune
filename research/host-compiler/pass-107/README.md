# Pass107 — source-6 conditional transfer through upstream MIR

Baseline: `fadcbaff761792a498632a6f4940145c46b98f73` (Pass106).
Backend remains upstream `vnmakarov/mir`, revision
`a8ab7c31cd5f9b23b77d84c60b3d83e62d9d304c`, MIT license.
The existing fixed MIR function, OCaml caller/reference, C stub and historical
CPU proof driver are extended. There is no second function, custom IR, compiler
framework, native interception or persistent JIT context.

## Contract and actual MIR conditional

Inputs: two disjoint eight-byte unsigned channels A and B, represented by one
owned 16-byte buffer; explicit source and destination indices in 0..7.

| Source | First logical publication | Second logical publication |
|---|---|---|
| Not 6 | A[destination] = A[source] | B[destination] = B[source] |
| 6 | A[destination] = 0 | B[destination] = B[6] |

Other channel bytes remain unchanged. Publications remain A then B, even when
zero or equal to the existing value. Source=destination is supported, including
6: A[6] is cleared while B[6] is retained and published. No PL/I variable, type or
assignment interpretation is asserted for these opaque historical channels.

`tools/mir/pass106/transfer.mir` initializes `first` to zero and uses real MIR
`beq publish_a, source, 6` to skip the A-source load. Both routes then publish A
and execute the existing B transfer. The C stub and independent OCaml reference
now accept source 6. Width and index guards otherwise remain intact. The return
layout remains 16 state bytes plus two ordered publication values and an MIR
status of zero. The C publication buffer starts with nonzero sentinel bytes so
missing zero publications cannot pass merely through an initially zero buffer.

The synchronous ownership model is unchanged: C owns its channel and publication
buffers, no OCaml heap pointer enters MIR, input bytes are never modified, and
the context/generated code are destroyed before allocating the OCaml result.
Only fixed reviewed MIR text is parsed. Interpreter uses `MIR_interp_arr`; JIT
uses `MIR_gen` at optimization level 0 on the tested x86_64 Linux host. The
existing process-fatal MIR error limitation remains explicit in Pass106.
Ordinary Dune builds still neither fetch nor link MIR.

## Historical boundary and independent CPU proof

Pass58 established the source-6 route as **DEDUCED / STATIC / UNOBSERVED**.
The ten Pass106 FIZZBUZ cases contain no source-6 natural invocation. This pass
preserves that distinction; synthetic execution does not make the branch
OBSERVED and no classification or annotation changes.

The stopping boundary remains image `[793C,797E)`, runtime `[9B3C,9B7E)`.
The source-6 route executes fresh AE03/CPI6, declines JNZ +7958, clears
ADAB[destination] at +7953, then jumps at +7955 to the common B-copy code +796B.
It reaches +797E before emission, with no CALL or RET inside this prefix.

Independent Intel 8080 execution checks every destination 0..7 under three
patterns: distinct nonzero source data, all FFh, and all zero. These 24 synthetic
windows include source/destination self-copy and same-valued writes. The
instruction trace confirms the actual JNZ decision and common-copy jump.

| CPU prefix | Instructions | Physical writes | Pointer PUSH/POP pairs |
|---|---:|---:|---:|
| Existing non-6 | 29 | 8 | 2 |
| Source 6 | 24 | 6 | 1 |

The source-6 physical write journal is independently derived as:

1. AE03 = 6.
2. AE02 = destination.
3. ADAB + destination = 0.
4. SP-1 = ADh (common B source-pointer PUSH high byte).
5. SP-2 = B9h (ADB3h + 6, low byte).
6. ADB3 + destination = entry B[6].

SP is unchanged after POP. The synthetic continuation word at SP/SP+1 remains
untouched. Only the B pointer is pushed; the A pointer pair is absent. All
64 KiB of exit RAM is compared against entry RAM plus these independently
computed writes, including repeated/zero values and surviving residue. Exact
historical image bytes are loaded, without invented child outcomes.

All original 56 non-6 synthetic CPU inputs are retained, and all ten natural
FIZZBUZ snapshots are checked against the archived Pass106 natural results.
The CPU adapter computes its projection without MIR or the OCaml reference.
Its 24 source-6 input/expected-output pairs then feed both actual MIR engines.
The OCaml reference supplies a further independent projection check.

Per MIR engine: ten natural CPU-derived inputs, 24 source-6 CPU-derived synthetic
inputs, and 136 directly constructed synthetic inputs (the original 112 plus
24 source-6 cases). The latter overlap the CPU patterns; these are executions,
not a claim of distinct test inputs. Each engine also checks six rejected inputs:
15/17-byte buffers, source -1/8, destination -1/8. Both engines must leave every
input unchanged, for accepted and rejected inputs.

## Validation, evidence and preservation

```
python3 tools/annotated-assembly/run_host_compiler_regressions.py \
  --categories pass107,pass106,diff-check,validation-runner-tests \
  --images /home/john/pli/cpm/pli80/DISK1 \
  --output _build/host-compiler-pass-107/validation --workers 4
```

Both categories use the extended existing test script, with separate task-owned
scratch/build directories under `_build/host-compiler-pass-107`. The upstream pin
is verified independently for each; no writable files are shared. This preserves
Pass106's scratch evidence as well as its published receipts. The selected build
and project checks are mandatory. No unrelated historical campaign is selected.

`validation.json` preserves the actual measured runner receipt. The implementation
packet records artifact digests; `historical-shadow.json` records the ten natural
and 24 source-6 synthetic details and the retained non-6 CPU count; `mir-results.json`
and `upstream.json` record the real interpreter/JIT and build identity.

Fresh FIZZBUZ guest execution preserves REL SHA256
`68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`.
All other historical goldens remain unchanged; no five-source rerun is claimed.
The existing reconstruction evidence, four input-image hashes/lengths and
unchanged annotated-assembly tree establish the preserved 94,720 bytes. No V1
run is required because annotations/classifications are unchanged.

## Remaining fidelity boundary

The MIR result represents channel state and logical publications. It does not
promise physical JIT store chronology or recreate historical flags, registers,
hardware continuation, temporary stack residue or scratch reads/writes. Those
remain in the historical adapter/proof. Emission after +797E and +7AE4 preparation
are outside the contract. Wider indices, arbitrary aliases and unproved language
semantics remain excluded. MIR's JIT produces host code, not historical 8080 REL.

Native roots installed: zero. Knowledge promotions: zero. Active runtime and the
four-domain gateway are unchanged. Pass74 epoch 3 remains last certified FULL;
no FULL was run, scheduled or awaited, and prior failures/evidence are untouched.

Next bounded step: specify explicit output/cursor/cache state and serialization
effects for one already proved emission child before attempting MIR lowering.
Do not infer an entire REL backend from this conditional byte transfer.
