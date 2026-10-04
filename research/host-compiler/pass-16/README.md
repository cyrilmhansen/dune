# Faithful host compiler boundary reconnaissance — pass 16

Task `FAITHFUL_HOST_COMPILER_BOUNDARY_RECONNAISSANCE_16`; baseline
`095e384e4e99664800dee2ab6104a8dce9902078`.

**Start the native work with PLI1.OVL+7BBF, not with a whole printed pass or a
replacement REL encoder.** Its mapped-word shift loop and auxiliary publication
have a complete scoped contract, explicit state, bounded execution and 27
independent invocation oracles across three existing inputs. This is a meaningful
compiler-state transformation, although its source-language purpose is unknown.

No compiler rewrite, new source, compiler rerun, packet/CPU/Trace change,
annotation promotion or contract reinterpretation occurred. No pragmatic
historical divergence is needed. Checkpoint/resume and a native replacement
**have not yet been implemented or demonstrated**. This report establishes a
suitable boundary and its observed dependency closure, not an already-working
hybrid compiler.

## Capture and exact chronology

[fizzbuz-timeline.json](fizzbuz-timeline.json) retains selected markers, actual
register states, chronological prior writes to important state, file records,
canonical CALL counts and observed suffix dependencies. Reused capture:
`_build/evidence-packet-cross-run/fizzbuz-capture`, run
`FIZZBUZ:a7a657b3c9c758be44a16c4c76a2986744f01de34d773d2b9597d4758eff0f49`.
PASS1/PASS2/END succeed, with 1,145,517 steps and warm boot. FIZZBUZ.REL is
**768 bytes**, SHA-256
`68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`.
All instruction bytes, load coordinates and canonical occurrence counts are
checked against the capture and independent historical images. No dynamic
context or RoutineCandidate supplies procedure ownership.

| Observed interval / point | Image / activity | Concrete significance |
|---|---|---|
| 0 | PLI.COM+0000, runtime0100 | startup; initial registers zero, SPFFFE; step1 sets SP1C29 before later startup work |
| 563..14260; entry14310 | load PLI0; PLI0+0000 at2200 | overlay records are file reads, not an inferred semantic pass |
| 68185..68849 | make REL; open/read source | source records0..2 into FBFE/FC7E/FCFE; no REL record written yet |
| 79054 onward | resident +1140 | first REL bit output, while PLI0 is active |
| 291926..293166 | `NO ERROR(S) IN PASS 1` | BDOS console callbacks at runtime0005; preceding canonical bridge +19D4 is retained |
| 293434..319707; entry319757 | load PLI1; PLI1+0000 | substantial work continues after PASS1; entry followed by +4B69 reset and +8273 mapped initialization |
| 322350..323007 | make INT, reopen/read source | second source record sequence; source acquisition continues through +1376/+784E |
| 332035..637334 | PLI1+7D53 calls | 77 range operations; 96 +7C1B calls, 21 +7BBF calls; established mapped/recursive/INT channels |
| 478364,609551 | INT writes0,1 | exact128-byte records from1D8C; their hashes later match the corresponding reads |
| 637833..639073 | `NO ERROR(S) IN PASS 2` | another console marker, followed by overlay loading and substantial downstream work |
| 639361..664866; entry664916 | load PLI2; PLI2+0000 | REL state already has58 full bytes and5 bits; INT third record still pending |
| 670561..676671 | write INT2, close/reopen INT; reopen/read source | PLI2 entry is before final INT materialization and first INT read |
| 766468..1143986 | six REL sequential writes | records0..5, DMA1D0A; INT reads1/2 interleave at821467/1044463 |
| 1144084 | REL close | output complete before final message |
| 1144261..1145191 | `END  COMPILATION` | console marker after output close |
| 1145422..1145517 | delete INT, final +19E0 JMP0000, warm boot | cleanup/termination; no linking or generated program execution |

Source is read three times, with the same three record hashes. PLI1's normal
reset/traversal/initialization families have accumulated contracts; PLI2's
+1FB5 gateway and many handlers do not. These observations make the messages
useful navigation markers, **not self-sufficient architectural boundaries**.
There are 469 REL bit writes before PLI2 entry and 5,675 afterward. A supposed
"INT file to fresh REL" cut there would omit real carried state.

At the two overlay-entry candidates, the actual remaining execution first reads
631 and731 data bytes before any observed overwrite, respectively. The retained
ranges include stack, pointer tables, buffers and aliases. Guest writes, explicit
host writes and BDOS record reads all kill old input dependencies, even for
same-valued writes. BDOS output DMA reads also count. Instruction fetches are
verified separately. These suffix inventories are **observed-path dependencies**;
they are neither logical IR definitions nor proof that a minimal checkpoint
supports other paths. A full validation checkpoint would also need files, FCBs,
DMA/current drive/user, registers/flags and the loaded image. Runner currently
exposes live callbacks, not a tested resumable checkpoint interface. The current
BDOS record contains filesystem, DMA, current drive and user; file positions are
carried by guest FCB bytes. This explicit runtime inventory must accompany a
future raw checkpoint; it is not a logical compiler IR.

## REL oracle: three distinct mechanisms

[rel-pipeline.json](rel-pipeline.json) separates semantic item generation,
bit serialization and CP/M record output. Current established knowledge includes:

- +119E rotates the saved8-bit value before each bit call and decrements its
  count. +1140 shifts the selected REL buffer byte and inserts C.bit0, advancing
  bit/byte cursors and writing a record at128 bytes. Their contracts remain partial.
- +1207 caches a word, emits prefix10, low-byte bits and high-byte bits in order
  at its declared scope. PLI2+7557 emits an absolute-item prefix and delegates
  +753C; +7701 has partial external-chain/name behavior. Their upstream decisions
  and several control/name/address writers remain opaque.
- Buffer1D0A..1D89, indices1D8A/B, scratch20B6..20B8, gate2029 and FCB1CE4 belong
  to output state. +02EE/+0328/+19BB provide DMA/file effects, distinct from items.
  INT emission through +0EF6 is a separate buffer/file channel.

There is **no existing REL parser, grammar or parser test in this baseline's
tracked repository**; inspection of the available local historical tooling did
not find one either. A small read-only audit was added to the Pass16 checker,
using the [Digital Research LINK-80 guide, §1.6 and appendix E.1.7](https://deramp.com/downloads/digital_research/Manuals/LINK%20and%20RMAC.pdf).
It is not a host encoder, linker or a reconstructed compiler item generator.
It rejects truncated items and reserved controls4/8, accepts the observed
name-only control3, and retains alignment/trailing bits rather than discarding
them. Format interpretation does not upgrade the generator contracts.

The exact FIZZBUZ stream has **289 logical items, including END FILE**:
207 absolute bytes,23 relative words and59 special items. The first name is
**FIZZBU**, not the seven-character filename stem; control3 names **PLILIB**.
END MODULE occupies bits5150..5174; one zero bit aligns the next item.
END FILE occupies bits5176..5182, followed by **961 zero bits**: one bit completes
that byte, then120 zero bytes finish the six physical records. Every one of
those trailing zeros is an actual bit-writer argument; padding is not merely
assumed from file length or attributed to BDOS. All6,144 arguments reproduce
all768 bytes exactly. The general final-fill driver remains unestablished.

A future replacement must compare ordered items **and** bit arguments, buffer
cursors, record bytes and final REL. Byte identity alone could conceal
compensating item-generation/serialization errors. The observed six-character
name, module alignment and active zero fill must not be silently normalized.

## Ranked cuts and critical path

[candidate-boundaries.json](candidate-boundaries.json) gives exact points,
required state, observed access ranges, external dependencies, missing-archaeology estimates, risks and oracles.

1. **PLI1+7BBF at9DBF**, return+7C1A/resume+7C3A: mapped-word scan, scratch updates
   and independent auxiliary publication. Stable bounds, complete local CFG and
   complete nonaliasing contract. Best first faithful operation.
2. **Resident+119E with+1140**: meaningful counted serialization. Much repeated
   evidence, but a flush brings explicit BDOS/file state, and final padding/item
   generation belongs elsewhere. Do not implement a generic cleaner bit encoder
   as a substitute for the historical rotate/count mechanism.
3. **PLI1+7D53**: a larger mapped/reverse/forward transformation with distinct
   byte, auxiliary, word and recycler channels. Implementable at the selected
   FIZZBUZ states, but recursion and INT flush make the first adapter much larger.
   The known packet limitation at nonhistorical runtime0005 remains unchanged.
4. **PLI2+0000 entry**, step664916: attractive eventual late-pass cut, currently
   blocked by handler/item-generation contracts and carried REL/INT/file state.
5. **PLI1+0000 entry**, step319757: eventual upstream migration point, not yet an
   explicit faithful pass-wide operation or value-semantic IR boundary.

[critical-path-audit.json](critical-path-audit.json) checks **all137 established
hypotheses actually called by FIZZBUZ** against the current catalog, exact source
headers and capture CALLs. It also retains389 uncataloged CALL entries without
inventing bounds/ownership. Complete mapped/arithmetic/scan operations are ready
at their declared preconditions. Selected compositions +7C1B/+7D53/+4468 and
wrappers have usable observed-scope operations, with delegated gaps retained.
Source acquisition, PLI0+24BC, PLI1+28AA/46ED/666E and PLI2 handlers/item decisions
still block a source-to-REL host compiler. This classification is operation
readiness, not proof of every caller's aliases or a whole-image percentage.

FACTOR's positive +7E2B/+7E2E screening remains useful deferred archaeology.
Pass15 did not classify its transformed attribute dynamically, so an attr5 claim
is not promoted here. FIZZBUZ's absence of attr5 does not block its scoped path.

## Selected state and the Pass17 experiment

[recommended-cut.json](recommended-cut.json) and
[operation-captures.json](operation-captures.json) preserve the selected boundary
and all27 correlated historical oracles: MINIMAL3, FIZZBUZ21, PICTURE3.
Existing Pass7 validation checks the operation rather than a new interpretation.
FIZZBUZ includes three input-word-zero invocations that execute all16 shifts.

At entry, F=SP and C is the position. Exact initial data reads are:

```text
byte[AA1F+C] = j
word[AB49+2*j]                         // little-endian mapped word
byte[AE39]                            // raw validation read, discarded by +7A80
word[F]                               // original hardware continuation
```

AE39 is read by +7A7D LHLD AE38 then replaced in H by +7A80 MVI H00. It is
retained in raw validation state; it does not become a logical algorithm input.
The operation writes AE38, AE43/44, AE4B..4E and AD08+freshly reread j, plus the
six transient save/CALL bytes below F. No file or BDOS effects occur. Table,
scratch and stack nonaliasing are explicit preconditions; numerical table
proximity does not justify separate disjoint OCaml arrays or inferred capacities.

The loop shifts before testing its saved counter-nonzero mask and old/new top
bits. It performs1..16 shifts, decrementing only on continuation. It returns and
publishes16-shifts, leaves the shifted scratch word, and exposes historical
register/flag results, including DE's mixed counter/neighbor-byte word. Preserve
this algorithm, its ordered writes, stack-carried masks, fresh lookup and widths.
A bit-length/count-leading-zeros shortcut is not this first implementation.

Minimum future structure, **not implemented here**:

```text
Pli80_host.U8 / U16      wrapping operations and exact word access
Pli80_host.State         Bytes.t or bounded views with numeric addresses/aliases
Pli80_host.Packed_scan   faithful +7BBF operation with explicit preconditions
Pli80_host.Differential  raw snapshot, historical ABI adapter, exact comparisons
```

REL item/bit modules should be added when their own replacement boundary is
chosen; no guessed parser/code-generator/pass framework is needed now. Cpu8080
stays independent and supplies the concrete oracle. Raw memory/register/flag/file
snapshots are validation artifacts; they are not the future host compiler's
required Cpu object. Low-level historical Bytes.t state is an appropriate
representation, not modernization debt.

**Pass17:** first shadow the native operation against all27 input/post-state
pairs. Compare ordered persistent writes, shifted word/counter/auxiliary byte,
every final register/flag, SP/return identity, and transient memory effects through
an explicit validation bridge. Copy full64KiB memory for unchanged-byte checks.
Then replace the operation at the historical entry, resume+7C3A and require exact
MINIMAL/FIZZBUZ/PICTURE REL identity. The bridge may account for the existing
hardware boundary; it must not turn the host operation into an8080 interpreter.
Missing cells, unsupported aliases/states or any mismatch fail closed. If some
compatibility effect cannot be faithfully accounted for, stop there and name the
missing behavior. No guessed fallback or pragmatic divergence is authorized by
this reconnaissance.

## Reproduction and validation

```sh
python3 tools/annotated-assembly/check_host_boundary_pass_16.py --images /path/to/DISK1
python3 tools/annotated-assembly/test_host_boundary_pass_16.py --images /path/to/DISK1
dune runtest
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
```

Generated audit intermediates and the downloaded manual remain ignored under
`_build/host-compiler-pass-16`; no capture, memory dump or compiler binary is
committed. New tests validate capture/canonical/hash identity, byte-input closure,
selected post-state/address equations, independent adjacent-bit stopping points,
item fields/endianness/alignment, active padding, same-value-write handling and
closed unknown dependencies. [validation.json](validation.json) records checks.
All **94,720 historical bytes reconstruct exactly**; assembly semantics, roles,
statuses, contracts, completeness and MINIMAL progress remain unchanged.
