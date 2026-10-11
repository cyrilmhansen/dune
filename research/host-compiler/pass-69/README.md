# Pass69 — selector-dispatch ownership and gateway boundary

Pass69 establishes a useful discovery milestone. It does **not** install a native
replacement for the dispatcher: naturally required selectors reach the separate
broad `PLI2.OVL+1FB5` gateway. That subsystem is the substantive blocker.

The verified starting/published commit is
`4558e0515d9c8f83b3bcb801084f6b8f4772a1df`. No native, CPU, CP/M, Runner,
common transaction, journal, annotated-assembly, or historical contract code
changes in this pass. Only local proof/capture tools, category registration and
research evidence are added.

## Ownership and natural coverage

The local handler envelope is `[3DE4,3E36)`: 72 instruction bytes and ten table
bytes. `+3DE4` is an actual **software PCHL entry**, with zero hardware CALL roots.
`+3E0D` is an arm's CALL site; it is not a procedure entry. `+3E36` remains a
separate handler and is outside this investigation.

Every recorded incoming transfer is the gateway sequence:

```
PLI2+20AC  LXI H,42B4
PLI2+20AF  PUSH H
PLI2+20B0  LHLD AD1F
PLI2+20B3  PCHL             ; actual HL=5FE4, SP unchanged
```

The low/high continuation bytes at entry SP/SP+1 have the same actual writer,
`+20AF PUSH H`, in low/high little-endian representation. PUSH writes high first,
then low. The final `+3E35 RET` reads those exact bytes, returns to runtime
`42B4`, and advances SP by two. This is the gateway's software continuation,
not a CALL-created dispatcher frame. The enclosing observed hardware entry is
`+2149 CALL +1FB5`; it does not justify migrating that broad owner.

| Source | Dispatcher entries | Selector distribution |
|---|---:|---|
| MINIMAL | 0 | none |
| FIZZBUZ | 2 | 1 ×1, 2 ×1 |
| PICTURE | 1 | 1 ×1 |
| FACTOR | 2 | 4 ×2 |
| OPTIMIST | 3 | 1 ×1, 2 ×1, 4 ×1 |

These are fresh, image-qualified concrete executions. The earlier MINIMAL ≥1
orientation estimate was incorrect: a global `+3660` invocation does not imply
a dispatcher entry. An initial development capture also admitted matching
runtime coordinates in other overlays; the final capture requires the actual
Execution_map image and records actual current instruction origins. None of
those false overlay windows appears in the durable evidence.

`ownership.json` retains the exact producer/consumer states, software transfer,
arm child inputs/outputs, flags, stack last writers and complete journal hashes.
Exhaustive instruction journals and RAM snapshots live under ignored `_build`.
Unmatched hardware-call observations are evidence, not a generic stack ancestry
algorithm; software ownership is proved directly from the actual PUSH and RET.

## Dispatcher law and arm assessment

Canonical `+3660` supplies the actual A/flags. RAR exposes old A.bit0 as CY and
preserves NZPA; JNC bypasses the optional update when that bit is clear. All eight
natural entries return A=0 from `+3660` and bypass `+37CB`. The optional static
arm freshly reads paired AD0D/AD0E, passes its low byte as C to `+37CB`, and
stores the returned A at AD08. It has no natural coverage in these five sources.
`+37CB` itself has zero global calls here; its static body contains recursion
and a `+0992` dependency. No arbitrary contract or new helper promotion is claimed.

The common path independently reads AD0A/AD0B, takes AD0A as C, sets B=0,
loads HL=602B, and performs DAD B twice. It reads target low byte into E, increments
HL, reads target high byte into D, exchanges DE/HL, then PCHL. AD0B is fetched
but discarded; it is not the selector's high byte. The table at `[3E2B,3E35)` is
`05600D6013601B602360`, five little-endian words:

| Selector | Arm | Argument | Child |
|---:|---|---|---|
| 0 | +3E05 | literal C=0 | +3B7A |
| 1 | +3E0D | carried C=1 from table indexing | canonical +3D10 |
| 2 | +3E13 | literal C=1 | +3C27 |
| 3 | +3E1B | literal C=0 | +3C27 |
| 4 | +3E23 | literal C=1 | +3B7A |

All five static arms JMP to the shared `+3E35 RET`. JMP and RET preserve the
selected child's final flags. Selectors 0/3 are STATIC / UNOBSERVED; indices ≥5
are outside the five-entry domain. No host default or arbitrary target execution
is installed. Table bytes are data, not ten decoded instructions.

`+3B7A [3B7A,3BFB)` and `+3C27 [3C27,3D10)` are separate actual CALL children,
not aliases of the dispatcher. Natural selector 4 reaches `+3747`, which calls
`+1FB5` at `+374B`. Natural selector 2 reaches `+1FB5` at `+3CAE` directly.
FACTOR/OPTIMIST provide independent evidence of the selector-4 boundary; FIZZBUZ
and OPTIMIST independently exercise selector 2. These are demonstrated routes,
not speculative unobserved alternatives that can be excluded while claiming
all-natural closure. The gateway is a broad dispatch/save/restore compiler policy;
it is not replaced with a stub or swallowed as a small helper.

## Proof scope and knowledge state

The focused suite checks every natural incoming transfer and continuation,
child CALL words/RET consumers, fresh selector/table reads, actual-result RAR
and flags, shared RET and blocker correlation. Existing canonical `+3660` and
`+3D10` are independently shadowed within the captured handler windows, comparing
registers/flags, full RAM, ordered writes, stack residue and service state using
the existing proof machinery. No new root shadow is claimed.

Concrete CPU discriminants execute the exact common front-end instructions and
stop **before** arm children: selectors 0..5, incoming carry clear/set, adjacent
AD0B=0/255, target low-byte and high-byte mutations (72 cases). They check all
four ordered data reads, registers, unchanged SP and unchanged full RAM. Another
512 actual CPU executions prove RAR for all accumulator bytes and both carry
states, with varied NZPA. These are instruction/front-end proofs, not synthetic
closure of unresolved arm semantics. Four corrupted transfer-evidence cases
verify that the proof detects changed opcode, SP, target provenance and writer.
They do not claim native transactional rejection: no native transaction exists.

There are **zero** new or extended faithful contracts and zero promotions:
RAW→UNDERSTOOD 0; DECODED→UNDERSTOOD 0; STRUCTURED→UNDERSTOOD 0.
Discovery observes 46/72 instruction bytes and six/ten table-data bytes; the
remaining 26 instruction bytes and four table bytes remain STATIC / UNOBSERVED.
The procedure catalog, assembly headers, manifest, historical catalog epochs,
FACTOR/OPTIMIST totals and generated progress remain unchanged. No annotation
renderer is invoked. V1 checks ran before aggregate ACTIVE validation.

## Hierarchy, outputs and next boundary

No new native root is installed and no existing root is absorbed. Guest/host
counters therefore remain MINIMAL 294445/92, FIZZBUZ 560189/221 and PICTURE
339852/79; no instruction or transition savings are claimed. Standalone native
dispatcher testing is inapplicable. Existing cumulative hierarchy is rechecked
separately against concrete execution; its receipt is retained with this report.
Canonical `+3D10` remains enabled at the selector-1 CALL; `+3B7A` and `+3C27`
remain guest operations. Global child inventories are in `natural-inventory.json`.

Fresh concrete runs preserve the primary REL goldens:

- MINIMAL: `7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119`
- FIZZBUZ: `68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`
- PICTURE: `c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1`

Next: assess the independent true `+397F` parent (one FIZZBUZ and one OPTIMIST
hardware call), before attempting the broad `+1FB5` owner. `+18B3` has one
hardware call in every source but remains a distinct large traversal; raw dynamic
leverage does not establish coherence. `+3E36` is separate and not absorbed.
Future selector-dispatch migration requires genuine scoped contracts for the
naturally reached gateway-dependent policies, not an artificial CALL ABI for
`+3DE4`. The evidence establishes that a narrow PCHL ABI is plausible; it is not
implemented or generalized in this discovery milestone.

Semantic extraction intentionally leaves `candidate_modern_operation=null`.
The table and predicate mechanisms are known; a complete compiler operation is
not. No MIR design, faithful-code modernization or pragmatic semantic divergence
is introduced. Fidelity debt is the explicitly unresolved arm/gateway scope.
Oracle queries: zero.

## Validation and certification

ACTIVE extras: **pass69 only**. No runtime implementation or shared dispatch,
bounds, transfer or transaction path is modified, so no archived category is
materially affected. Local contained canonical-child shadows provide the needed
regression evidence. Pass69 is not added to the permanent ACTIVE core.

The historical-full **list-only** selection contains 100 categories and preserves
all 98 certified Pass67 categories, plus pass68/pass69. Historical-full is not
executed. Pass67 remains certified FULL epoch 1; the next ordinary FULL is
approximately Pass72. No FULL trigger fires.

Exact reconstruction is verified as 94720 bytes. Focused validation-runner tests,
Python compile checks, Dune build/runtest through ACTIVE, V1, global invariants,
category-set preservation and diff-check are required before publication.
Actual ACTIVE timing and test counts are recorded in `validation.json` after the
run. The implementation packet is problem-specific and below 28 KiB.

`scripts/view-optimist.sh` remains user-owned/untracked and untouched. No task
files are created under `/tmp`; transient results live under ignored `_build`.

Actual ACTIVE outcome: **28/28 categories initially passed**, 84 Python tests,
39 Dune test stanzas, four workers, 125.089s wall and
283.383s summed category time. No initial failures.
A post-run harness-only followup made the frozen-scope assertion compatible
with future legitimate epochs/semantic edits; the complete affected category
plus mandatory build/project passed 3/3, 11 Python tests,
22.610s wall / 22.607s summed time.
Both executions are preserved separately; test execution counts are not added
and called distinct tests. Sequential validation wall total is
147.699s.

There are 22 independently shadowed canonical3660 windows and three canonical
3D10 windows across primary/cross sources. No new dispatcher root shadow or
new descendant contract is claimed. The fresh cumulative hierarchy receipt
checks unchanged counters, full observable chronology and all three exact REL
goldens. The local residual map distinguishes contained direct calls from
global invocation counts rather than pretending a global external map.

Packet: 13638 bytes. Deterministic
driver phases: discovery (fresh natural capture, frontend CPU proofs, contained
canonical shadows), reports, hybrids (unchanged existing hierarchy), validate
(ACTIVE + pass69 only). No historical-full convenience phase exists.

Implementation correction: no faithful implementation change. Development
corrections were image-qualified capture attribution and a focused case-count
assertion, completed before ACTIVE. The later frozen-scope harness followup is
documented above. Historical correction: zero MINIMAL dispatcher entries,
not the earlier inferred one. Pragmatic divergence: none; no host substitution
is installed. Fidelity debt: unresolved naturally required gateway-dependent
selector arms, and unobserved selectors0/3/optional37CB.

**RUNES PLI2 SELECTOR DISPATCH PASS 69 BLOCKED AT PLI2.OVL+1FB5**
