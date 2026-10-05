# Resident INT emitter archaeology — Pass22

Baseline: `d00743be9eddcc955d8ccab0fa3db74f7899c38c`.

This pass establishes resident `PLI.COM+0EF6` as an ordered byte append with a
128-byte sequential-record flush at the witnessed success scope. It adds no
native emitter and changes no Runner, CPU, CP/M, or packet machinery. No custom
source, synthetic filesystem failure, FACTOR investigation, or new event capture
was needed.

## Evidence and replay

The existing corrected captures are:

- MINIMAL: `_build/minimal-baseline/capture`.
- FIZZBUZ: `_build/evidence-packet-cross-run/fizzbuz-capture`.
- PICTURE: `_build/discriminator-pass-15/selected-capture`.

Each exact capture run identity is retained in `buffer-lifecycle.json`. The
read-only `pli80-int-emitter-audit` executable independently reruns these three
existing sources using the historical images, capturing full-memory entry/post
hashes and complete returned state for every emitter invocation. It uses the
existing pre-instruction/resume boundary and never applies a host transition.
Large captures and replay artifacts remain ignored under `_build`.

```sh
dune exec pli80-int-emitter-audit -- \
  --toolchain /path/to/DISK1 --output-dir _build/pass22-fresh-live
python3 tools/annotated-assembly/check_int_emitter_pass_22.py \
  --live _build/pass22-fresh-live/snapshots.json --output _build/pass22-fresh-audit
python3 tools/annotated-assembly/test_int_emitter_pass_22.py --images /path/to/DISK1 -v
```

The output directories must be new. All 640 independent invocations remain in
`emitter-cases.json`; the non-flush/flush files reference individual entry steps.
`bdos-chronology.json` keeps exact producer, consumer, call, host effect, FCB and
return-slot relationships for the five flushes. It retains real nonhistorical
runtime0005 RETs rather than assigning them a historical image origin.

| Source | Emitter calls | Non-flush | Successful flush | Write errors | INT records |
|---|---:|---:|---:|---:|---|
| MINIMAL | 128 | 127 | 1 | 0 | 0 |
| FIZZBUZ | 384 | 381 | 3 | 0 | 0, 1, 2 |
| PICTURE | 128 | 127 | 1 | 0 | 0 |

Entry indices are exactly 00..7F, each appearing 1/3/1 times respectively.
Neighboring `1E0D` is 00 in all 640 cases; its read remains explicit even though
its value is discarded. Every outer return is `PLI.COM+0F2C`, matched against
the original caller CALL word. No additional detailed FACTOR/OPTIMIST capture
was available; their previously accumulated catalog counts remain unchanged.

| Caller | MINIMAL | FIZZBUZ | PICTURE |
|---|---:|---:|---:|
| PLI.COM+10AF | 70 | 93 | 54 |
| PLI1.OVL+7DCC | 16 | 102 | 22 |
| PLI1.OVL+7E11 | 1 | 7 | 0 |
| PLI1.OVL+7E20 | 9 | 60 | 10 |
| PLI1.OVL+7E52 | 7 | 42 | 12 |
| PLI1.OVL+7E5B | 7 | 42 | 12 |
| PLI1.OVL+8070 | 10 | 30 | 10 |
| PLI1.OVL+80FF | 4 | 4 | 4 |
| PLI1.OVL+8107 | 4 | 4 | 4 |

## Non-flush operation

**OBSERVED:** save input C at `20B0`; LHLD reads `1E0C/1E0D`; MVI H,0 discards
the high byte; form `1D8C+i`; read `20B0` freshly and write that destination.
Then reload `1E0C`, increment modulo256, publish the incremented index, and
compare it with 80H. `+0F10 JNZ` returns iff the incremented index is not 80H.
There are no nested calls or host events on these 635 paths.

**DEDUCED:** writing scratch precedes buffer publication, which precedes index
publication. For nonaliasing local states, let `q=u8(i+1)` and `v=u8(q-80H)`:

- A=q; BC=1D8C; DE=entry DE; HL=1D8C+i.
- SP=entry SP+2; PC is the actual caller CALL+3.
- Final CPI80 flags: S=v.bit7, Z=(v=0), P=even_parity(v), CY=(q<80H), AC=1.

The natural record-producing domain is i=00..7F. The exact local non-flush
formula also follows for other disjoint byte-index states, including FF->00;
this is not a claim that such states constitute valid INT-buffer producers.
`test/resident_int_emitter.ml` runs the exact historical bytes over 253
non-flushing, index-pair-nonaliasing values and all 32 entry flag combinations
(8,096 cases). It excludes 7F (flush), 80 (destination aliases index), and 81
(destination aliases the neighboring index byte). No native algorithm is added.

## Successful flush operation

**OBSERVED**, independently correlated for all five invocations:

1. Append the final byte at `1E0B`; publish index80H.
2. `+0F16` invokes DMA wrapper `+02EE` with BC=1D8C. High-first scratch writes
   to `2060/205F`, fresh LHLD/XCHG, and C=26 pass DE=1D8C to the real BDOS entry.
3. Both `+19BB` guards succeed: bytes0005..0007 equal bytes215C..215E
   (`C9 FE FF`), and the pointer read from2155 targets FDFE with byteAA.
   BC/DE are restored before the tail JMP0005. The real runtime0005 RET consumes
   the `+02FA` CALL word, then `+02FD` consumes the `+0F16` wrapper word.
4. Only after DMA setup, `+0F1C` resets `1E0C` to00. It does not clear the buffer.
5. `+0F21` invokes `+0328` with BC=1CA2. The wrapper writes high B to2066,
   low C to2065, freshly reads the pair into DE, sets C=21 and calls `+19BB`.
6. BDOS21 observes DE/FCB=1CA2 and DMA=1D8C. Its sequential file event and
   record-data event consume the current128 buffer bytes. Each byte's latest
   instruction/host writer before that boundary is retained; equal values do
   not substitute for chronological producer identity.
7. The filesystem writes record0 / records0..2 / record0 of the source's INT.
   Actual host FCB writes update extent/record fields and the file-write flag;
   complete36-byte before/after FCB values and every host write remain in JSON.
   In these records EX stays00, RC/CR advance to1,2,3 as applicable, and the first
   write clears S2's80H file-write flag. Same-valued host writes are retained.
8. Host status A=0; runtime0005 RET consumes the `+0334` CALL word; `+0337`
   consumes the `+0F21` wrapper word; CPI00 sets flags; JZ takes `+0F2C`.

At both witnessed BDOS entries A=AA, B is the argument high byte, C is26/21,
DE=1D8C/1CA2, HL=FDFE, and flags S0 Z1 AC1 P1 CY0. Actual post-host state is
A=0, B=0, C unchanged, DE unchanged, HL=0, same flags, same SP/PC before the
real runtime0005 RET. This describes the existing Runes CP/M model's observed
successes; it is not a universal BDOS preservation convention.

The final successful flush state is A=0, BC=0015, DE=1CA2, HL=0000, flags
S0 Z1 AC1 P1 CY0 from CPI00, SP=entry+2, and the original outer continuation.
Every returned register/flag from DMA wrapper `+02EE` is overwritten before the
later emitter result. Its DMA, scratch and stack effects remain real dependencies.

The final below-entry stack residue, with S=emitter entry SP, is:

| Slot | Little-endian value | Exact last writer |
|---|---|---|
| S-2 | 1024 | +0F21 CALL0428 |
| S-4 | 0437 | +0334 CALL1ABB |
| S-6 | 1C15 | +19BB PUSH B |
| S-8 | 1CA2 | +19BC PUSH D |
| S-10 | 1AC6 | +19C3 CALL1B0F |

Earlier DMA-helper continuations1019/03FD are overwritten by these later
writers. The outer word at S is unchanged. Writer/read proofs in JSON establish
identity and last-writer order, not merely matching return-address values.

After each successful flush, all128 physical buffer bytes still equal the
written record, while the index is00. Subsequent appends overwrite individual
slots in increasing index order; an index reset never implies clearing memory.

## Local CFG, wrapper and error boundary

`+0EF6` keeps extent `[0EF6,0F2D)` (55 bytes), with stable bounds, complete local
control flow, and partial contract. Reviewing the unique entry, original outer
RET and represented local branches justifies the first two axes; it does not
require the error outcome to execute. All55 bytes are now represented:
52 successful-path bytes become UNDERSTOOD; the three error-CALL bytes become
DECODED **STATIC / UNOBSERVED**. They are not promoted to UNDERSTOOD.

`+0328` is independently cataloged at `[0328,0338)`: stable/complete/partial.
All16 bytes become UNDERSTOOD at the delegated wrapper scope. Exact ordinary
calls are3/9/3, comprising INT callers `+0F21`1/3/1 and REL callers `+118D`2/6/2.
Its downstream register/flag/file contract remains delegated. The former DB
coordinate label `PLI_0330` is retained as a coordinate-only EQU in the LHLD
operand. The new role2065 is the saved sequential-write argument, not a file name.

**STATIC / UNOBSERVED:** exact bytes at `+0F29` decode as `CALL0FA0H` (resident
file offset `+0EA0`). Local successor is `+0F2C RET` only if that child returns.
The seven-byte `+0EA0` envelope decodes as `LXI B,0298H; CALL05F2H; RET`.
Runtime05F2 maps to file `+04F2`, not an existing cataloged procedure. Its small
static envelope saves BC at2074/75, selects an optional opaque call to runtime0405
using bit0 of1D05, writes2011=1, reloads BC, calls runtime057D, then has a local
RET. Neither it nor +0EA0 executes in the selected captures; downstream callees
were not investigated. No normal-return guarantee or meaning for0298 is claimed.
Their bytes remain RAW. No write-error observation or failure injection is invented.

`+02EE/+19BB/+1A0F` retain their existing contracts and completeness; this pass
adds required-success correlation without broadening their unobserved guard paths.
The tiny annotation renderer change labels the static callee distinctly; packet
schema and behavior are unchanged. The frozen Pass16 audit test now consults
explicit Pass22 before-catalog facts for the later refinement, preserving its
historical report rather than retroactively rewriting it.

## Next boundary and validation

Recommend Pass23 option A: a faithful native +0EF6 experiment at the demonstrated
non-flush/flush-success scope. The prerequisite is a narrow, explicit CP/M service
in the compatibility adapter that retains actual DMA/FCB/filesystem/record effects
and returned state. The native core must keep ordered shared-memory mutation;
its I/O request cannot be an append callback. `boundary-assessment.json` separates
that requirement from +7A79 extraction, later +7E46/+7E56 composition, and deferred
guard/error archaeology. No pragmatic divergence or fidelity debt was introduced.

Golden REL checks are unchanged:

| Source | Bytes | SHA256 |
|---|---:|---|
| MINIMAL | 256 | 7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119 |
| FIZZBUZ | 768 | 68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203 |
| PICTURE | 256 | c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1 |

Fresh replay requires PASS1, PASS2, END COMPILATION and warm boot for all three.
`validation.json` records the complete regression results and exact image hashes.
All 94,720 historical bytes reconstruct exactly. Validation passed 227 Python tests (including all 109 MINIMAL and 27 packet/continuation tests), the full project/native suites, all 640 fresh emitter cases and 8,096 exact-CPU index/flag cases. Global annotation changes
are RAW->UNDERSTOOD16, RAW->DECODED3, DECODED->UNDERSTOOD52; no PLI1 bytes change.

The resulting MINIMAL canonical dynamic tally changes 214,811->216,638 UNDERSTOOD instruction occurrences (48.820904%->49.236133%), from the justified resident annotations. PLI1 status and its dynamic tally remain unchanged.
