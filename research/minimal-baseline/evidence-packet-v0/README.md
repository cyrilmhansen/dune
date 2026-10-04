# Procedure Evidence Packet V0 / V0.1 / V0.2 experiment

Task: `PROCEDURE_EVIDENCE_PACKET_V0`. Starting commit: `6679adb`.
Selected entry: **PLI0.OVL+24BC**, image SHA-256
`e78818eca27d051d604b42c6b3202b30e5db6c46df6cf4b498fca601a86d7bff`,
runtime entry `46BC`. This experiment mechanically joins existing MINIMAL
observations and accumulated knowledge for a fresh, independent decompilation
session. It does not interpret or improve the procedure's semantics.

Current extractor: **V0.2**, infrastructure task
`PROCEDURE_EVIDENCE_PACKET_V0_2_SOFTWARE_CONTINUATIONS`, starting at `bd2defd`.
The V0 and V0.1 results below are historical; the V0.2 report at the end records
the bounded software-child extension and remaining profile restrictions.

## Reproduce

From the repository root, with the existing full MINIMAL capture available:

```sh
python3 tools/annotated-assembly/procedure_evidence_packet.py \
  --images /home/john/pli/cpm/pli80/DISK1
```

`--images` must identify the independent historical DISK1 images. The default
capture is `_build/minimal-baseline/capture`; `--capture` can change its location.
Missing indexed witness chunks fail extraction. No compiler capture is made.

Persistent generated artifacts stay in ignored project build state:

- `_build/evidence-packet/PLI0+24BC.json`: deterministic, compact JSON.
- `_build/evidence-packet/PLI0+24BC.md`: human-readable block/class rendering.

Do not commit these witness-derived artifacts. The packet includes source-file
and witness-chunk hashes; paths are capture locators, not durable identities.
Determinism is for identical inputs, options and source locators. No wall-clock
data is introduced. JSON holds all concrete records; the rendering shows only
representative state references and links to the joined catalog contracts.

## Result and packet use

The selected evidence has **85 invocations**, **11,322 local instruction
occurrences**, **371 local instruction coordinates**, **60 derived blocks**,
**13 invocation/path classes**, and **20 separately projected recursive
children**. There are **246 direct call occurrences at 21 callsites**, with
paired pre-call/post-return states and original hardware-slot proofs. Separate
callee-subtree footprints retain **4,900 guest memory-access witnesses**;
subtrees overlap across recursive levels and must not be summed as exclusive
costs or merged into parent-local block footprints.

Instruction keys abbreviate exact image identity + file offset; each resolves
through `instructions` to the image hash, bytes, runtime PC and decoded text.
Block groups reuse the existing canonical report's selected partitions. Their
`Bnnn` IDs and class `Cnn` IDs are only presentation references in this packet.
Unobserved branch-target coordinates assert no instruction decoding or entry.

`steps` holds full before/after register and flag states and ordered byte
accesses. Block entries reference `before`; exits reference `after`. A block
ending in CALL exits before the callee executes; `calls` separately provides
the post-return state. Known word accesses are DEDUCED groups over the original
byte accesses, with their observed order retained. `invocations` preserves each
member's first-written local bytes (not an entry snapshot), local chronology, block visits and nested calls.

Classes use entry C, the first writes to **F+9/F+10**, and the **complete ordered
local transfer path**, including recursive callsites. This gives useful browsing
groups without discarding the distinct data flow of any of the 85 members.
For example, the 54-member C=0/F+9=80/F+10=00 path retains different first-written
F+11 values, concrete pointers and memory effects in separate invocation records.
No independent sets of register values or representative-only data flow replace
those correlated executions. Class IDs are not semantic categories.

OBSERVED states/accesses/counts are separate from DEDUCED address equations,
immediate 8080 predicate producers, and conservative local write/read relations.
The existing procedure metadata, contract, pseudocode, unresolved paths and
helper contracts are copied under **ACCUMULATED KNOWLEDGE**, without editing
or promoting them. Role evidence is retained as accumulated knowledge; numeric
role matching itself is marked DEDUCED. Unknown-length roles match only their
base byte, and roles remain scoped to catalog entries that reference them.

## Experiment report

1. **Directly available infrastructure:** exact canonical instructions and
   partitions; chronological states/flags and ordered byte accesses; transfer
   outcomes; corrected matched hardware returns; image hashes/load bases;
   existing procedure metadata, contracts, completeness and durable roles.
2. **Artifact joins:** image byte verification; instruction occurrence counters;
   callers and dynamic CALL inventories; branch observations with invocation
   classes; block states/accesses with their original chronology; concrete
   addresses with F offsets and catalog roles; calls with paired returns and
   catalog contracts; current +24BC knowledge with its unchanged scope.
3. **New projection code:** presentation grouping of the existing canonical
   partitions, per-invocation block executions/edges, path-class partitioning,
   separate callee-subtree memory footprints, and conservative local write/read
   links. The pass-3 frame-isolation algorithm is reused. Its small optional
   extension exposes nested matched returns and memory witnesses, and reads
   the witness index instead of trusting a directory glob. There is no new
   procedure ownership or basic-block identity algorithm.
4. **Unavailable or deliberately unjoined:** unobserved paths and their states;
   a complete entry memory snapshot; general register/memory provenance;
   earlier predicate producers beyond the immediate recorded instruction;
   host-side callee memory effects; missing/partial helper contracts. Most
   overwritten memory values are null in the witnesses. Read-source gaps are
   recorded without claiming that a producer does not exist outside the local
   projection. The packet's dedicated evidence-gap section lists one-outcome
   branches, opaque/partial helpers and unobserved extent byte ranges.
5. **Ticket-specific logic:** one profile: entry +24BC, the already established
   18-byte frame, and class discriminator slots 9/10. Extraction conditionally
   reuses the existing +24BC validator. There is no new per-offset semantic
   dispatch table, PL/I name, contract or pseudocode. Profile settings are CLI
   options (`--entry`, `--frame-bytes`, `--class-slots`); frame choice remains an
   explicit established hypothesis, not inferred ownership.
6. **Reuse prospects:** another cataloged procedure with matched ordinary CALL
   returns and a known frame can use the same joins with profile options.
   This is an inspection-based conclusion; V0 deliberately exercises only
   +24BC. Shared coordinates, partial source-block selections, missing returns
   or nonstandard continuations currently fail rather than invent ownership.
7. **Do not generalize yet:** class selection/semantic equivalence, arbitrary
   stack conventions, table bounds, static decoding of unobserved bytes,
   host-effect provenance, interprocedural data flow, procedure discovery,
   SSA or a permanent packet/schema architecture. Whether the join improves
   decompilation belongs to the next independent session.

## Validation

```sh
python3 tools/annotated-assembly/test_procedure_evidence_packet.py \
  --images /home/john/pli/cpm/pli80/DISK1 -v
python3 tools/annotated-assembly/check_minimal_pass_3.py \
  --capture _build/minimal-baseline/capture \
  --output _build/evidence-packet/check-pass-3.json
python3 tools/annotated-assembly/check_minimal_pass_4.py \
  --capture _build/minimal-baseline/capture \
  --output _build/evidence-packet/check-pass-4.json
python3 tools/annotated-assembly/test_minimal_pass_3.py \
  --images /home/john/pli/cpm/pli80/DISK1 -v
python3 tools/annotated-assembly/test_minimal_pass_4.py \
  --images /home/john/pli/cpm/pli80/DISK1 -v
python3 tools/annotated-assembly/test_decompilation_annotations.py -v
python3 tools/annotated-assembly/verify.py --images /home/john/pli/cpm/pli80/DISK1
git diff --check
```

The packet tests include deterministic regeneration, independent retained
pass-3 branch totals, synthetic recursion at identical coordinates, missing
chunk detection, and rejection of corrupt bytes, branch counts, local ownership,
frame offsets, role addresses and call-return joins. Default pass-3/pass-4
checkers continue to operate unchanged. Historical binaries, annotated assembly,
ProcedureHypotheses, completeness, roles and byte statuses remain unchanged.

Validation passed: eight packet tests, twenty existing pass-3/pass-4 tests,
nine conventions tests, both full-capture contract checkers, the historical-byte
verifier, and `git diff --check`. No task temporary directories remain.

## V0.1 report

Task: `PROCEDURE_EVIDENCE_PACKET_V0_1`; infrastructure baseline `b8c6b47`.
The corrected +24BC annotations are unchanged accumulated knowledge. No new
semantic decompilation, ProcedureHypothesis, data role, byte promotion, coverage
or compiler run is part of this change.

### Added representation and navigation

- `local_dependencies.nodes` retains bounded per-invocation definitions with
  exact instruction coordinates/step references, observed values, and **value**
  versus **flag** edges. `local_dependencies.branches` refers to each recorded
  conditional occurrence and its supported condition or explicit unresolved
  producer. Only branch/publication-reachable nodes survive serialization.
  This is a local experiment, not a permanent IR, SSA or general provenance.
- Supported local operations include comparisons, byte arithmetic/logical
  operations, complement, rotations, self-SBB, register copies and byte memory
  loads/stores. PUSH PSW's A byte survives through POP B and MOV C,B. Packed-flag
  restoration and unsupported producers remain unresolved. DAD/unknown pair
  arithmetic is not silently given an input relation.
- Branch polarity uses a small operational condition tree: bit tests,
  complement, Boolean bit combinations, equality, byte borrow and zero. The
  renderer shows source expressions, actual instruction transformations, tested
  flag, observed outcome counts/classes, and per-occurrence JSON references.
  Different source-chain groups retain their own counts; they are not merged
  into independent sets of source values.
- A returned register/flag is an **observed call-output boundary leaf**, never
  an inferred algorithmic relation to pre-call inputs. This permits the local
  +247C.A -> CMA -> RAR -> CY -> JNC chain while leaving +247C opaque.
- Calls visibly distinguish COMPLETE, PARTIAL, MISSING / OPAQUE and RECURSIVE
  inherited partial contracts. Every call keeps its original exact scope,
  declared clobbers and scope evidence. Callsite scope-status groups refer to
  individual calls rather than extrapolating a representative's scope result.
- Local write/read links and saved-byte definitions survive only supported
  explicit preservation clauses. The limited recognizer accepts declared
  unchanged registers/flags or memory, no-memory-write contracts, and explicit
  `Only stack writes (CALL/PUSH PSW)` / `nested CALL stack only` clauses for ordinary callees and known caller storage above pre-CALL SP. Explicit clobbers win;
  unspecified state is killed. Guest-only write absence does not establish full
  memory preservation when host effects are unavailable. Any observed write also kills the prior memory
  definition, even when its byte value is unchanged. Surviving relations name
  their intervening calls; dependency edges retain the permitting contract.
- Partial preservation is conditional on the complete retained contract scope.
  The one recognized guard form, `+XXXX returns A bit0=0/1`, is checked against
  the existing callee's recorded inner return coordinates and A states. For
  +240B this establishes the guard-false clause; alias preconditions remain
  visible and are not promoted into a universally valid helper contract.
  Other partial scopes stop preservation. The recognizer has no +24BC/offset
  semantic dispatch or register-value-equality heuristic.
- `operational_summaries[invocation]` supplies ordered watched caller-role word reads/writes,
  declared frame-word/byte writes, recursive child order/modes, frame decrement
  events, and separate role/indirect/frame/callee publication channels with
  concrete addresses and source definitions. Class entries reference all their
  individual member summaries. Representative Markdown rows show correlated
  pointer and frame chronologies. Full member states/accesses remain in JSON.
- Opaque-call `observed_effects` records guest write addresses, caller-frame
  offsets written and watched word roles without recorded guest writes. +242B
  therefore shows 6A97/6A98 writes, no caller-frame writes and no tested_pointer
  guest writes in its four invocations, alongside **algorithmic contract:
  unavailable**. Host effects are still unavailable; these observations do not
  establish general preservation or a helper contract.
- `initial_local_bytes` is replaced everywhere in the packet by
  `first_written_local_bytes`. These writes may occur late in an invocation;
  they are neither an entry-memory snapshot nor assumed initial contents.

Markdown now presents procedure/frame, classes, predicate dependencies,
callsite scopes/effects, correlated navigation, gaps, then compact blocks.
Large state/access lists, nested stack traffic and hardware proofs stay in JSON.
Code hashes for both generator modules accompany the existing source hashes.

### What is mechanical, and what still requires reasoning

The A/B manual PSW-save/register-copy join and complement/rotation polarity
calculation are now mechanically represented. +2798 is the original returned
A-bit OR; its ten observed FF results make JNC taken after CMA/RAR. +2601 is
JNC taken iff +247C's returned A bit0 is set; the observed clear bit instead
selects the patch. Helper carry is absent from that tested-bit dependency.

F+3 versus F+5 writes, pointer restoration/revisitation, child call order/modes,
F+11 decrements versus total children, and distinct publication destinations
are navigation facts with member links. Tests independently check the C05/C06
patterns and the separate F+16/indirect publication channels.

Models still must assess source-level hypotheses, helper algorithms, general
contract validity, alias preconditions, arbitrary termination, unexecuted paths,
and unresolved producers. The packet does not infer tree ownership or PL/I
meaning, propagate an opaque output back to its inputs, reconstruct host effects,
or recover overwritten/never-read memory. Word snapshots describe recorded byte
accesses/writes, not complete memory states.

A STATIC / UNOBSERVED decoding supplement is deliberately deferred. The current
inputs do not retain decoded instructions for the +24BC RAW holes. Supplying them
would require a decoder or a new authored static-evidence source and validation;
that would broaden this bounded ticket. Existing accumulated static comments
remain copied with their original status; no RAW bytes are decoded or promoted.

### Size and complexity

Measurements use the same retained MINIMAL capture and compact UTF-8 JSON.
Physical LOC includes comments/blank lines and **both** generator modules.

| Measurement | V0 at b8c6b47 | V0.1 |
|---|---:|---:|
| JSON bytes | 10,848,556 | 13,567,441 |
| Markdown bytes | 66,279 | 51,481 |
| Generator LOC | 611 | 1,171 |
| Test LOC | 219 | 385 |
| Generation seconds, one sample | 7.383 | 7.374 |

JSON grows about 25%; the Markdown working set shrinks about 22%. The code
nearly doubles: the conservative effect models, scope checks and correlated
navigation are a real complexity cost. There is no JSON compression/size
optimization in this ticket. Timing samples are not a controlled benchmark
(single samples, with filesystem-cache effects); no performance improvement is claimed.
The target retains 7,932 dependency nodes, 950 conditional occurrences and 189
local write/read links that survive explicitly supported calls.

### Secondary reuse check

The unchanged existing complete +23C3 procedure was extracted with its known
zero-byte frame and no discriminator slots:

```sh
python3 tools/annotated-assembly/procedure_evidence_packet.py \
  --images /home/john/pli/cpm/pli80/DISK1 \
  --entry PLI0.OVL+23C3 --frame-bytes 0 --class-slots \
  --output _build/evidence-packet/reuse
```

It succeeds: 334 ordinary invocations, 17 local instruction coordinates, 5,678
local instruction occurrences, two presentation blocks, twelve path classes,
no recursive children, and an empty first-written frame-byte map. No special
semantic code was added to make this secondary extraction work. The shared
frame/canonical-block restrictions still apply; one reuse case does not establish
arbitrary-procedure support.

### Validation and recommendation

Seventeen packet tests cover both polarity representations, all supported
per-occurrence conditions, scope/preservation rejection, same-value opaque
register outputs, same-value memory writes, call-aware links, correlated pointer
and child records, publication-channel separation, opaque +242B observations,
secondary reuse, corruption rejection and deterministic regeneration. Existing
MINIMAL passes 1–4 (37 tests), V1 annotations (nine tests), and the full historical
byte verifier pass. All 94,720 bytes, semantic annotations, procedure identities,
completeness, roles and MINIMAL coverage remain unchanged.

Generate a packet before difficult semantic passes **when the existing bounded
profile fits**: it makes the observed mechanical joins reviewable and keeps
contract gaps visible. V0.1 is useful as an experimental companion on those
targets, not yet a routine general-purpose interface for arbitrary difficult
procedures. Keep new scope/opcode recognizers small and tested. A new independent
decompilation experiment is required to claim improved reconstruction stability;
this infrastructure regression does not establish that claim.

Current regenerated artifacts remain ignored under `_build/evidence-packet`;
reuse artifacts are under its `reuse` subdirectory. No task temporary files remain.

## V0.2 software-continuation report

Task: `PROCEDURE_EVIDENCE_PACKET_V0_2_SOFTWARE_CONTINUATIONS`; infrastructure
baseline `bd2defd`. No semantic decompilation, annotation, contract, completeness,
data role, byte status or MINIMAL progress change accompanies this extension.

### Bounded support and proof authority

The packet now isolates nested children in the already-established POP-D cleanup
family. `software_profile()` reads the five pass-8 proof instances, validates them
with the unchanged `software_continuation.prove()`, and checks their consumed-byte
counts against the catalog. This explicitly authorizes +4468 (2), +6708 (8) and
+43D5 (2); it does not discover argument counts or new ABI families.

The shared pass-3 gatherer has an optional `software_callees` profile. Its default
ordinary-only behavior remains unchanged. With the packet's explicit profile,
it joins corrected software-return events to candidate CALLs only after the
existing proof succeeds. Return-address equality merely narrows candidates.
The original CALL slot, unique POP D, ordered caller-word reads, DE ancestry,
copied PUSH D writer, relocated slot equation, corrected latest writers and
actual RET consumer establish the relation. Failed or ambiguous relations leave
extraction unresolved; no context or same-value fallback supplies ownership.

Each direct child call now has a `return_convention` independent of its semantic
`contract_presentation`. Ordinary calls retain `hardware_return_proof`;
software children instead retain `software_return_proof`, containing exact
instruction/access/state witnesses and the corrected consumer event. The compact
projection supplies CALL/POP/argument/PUSH/RET step references, target/resume
coordinates, original/copied slots, DE, consumed bytes and final SP delta.
`observed_evidence` labels the concrete proof OBSERVED; `deduced_evidence` labels
the stack equations DEDUCED: S = pre-CALL SP, E = S-2, copy slot = E+N,
final SP = S+N (modulo 65536). No argument meanings are derived.

Child instruction windows are excluded through their proven software RET.
The next parent-local instruction is the resumed continuation. Child subtree
memory effects remain separate, and proof-prefix instructions have a callee
scope rather than a parent-local scope. All joined instruction bytes still pass
historical-image/canonical verification. Contracts and their scope remain the
only authority for preservation across calls; consumed caller-word addresses
are explicitly killed even under a memory-preservation clause. Equal bytes do
not carry a parent definition across a child.

Markdown shows SOFTWARE CLEANUP RETURN, consumed bytes, copied slot, final SP
delta and resumed coordinate beside the independently PARTIAL semantic contract.
Ordinary calls visibly show ORDINARY HARDWARE RETURN. Full proofs stay in JSON.

### Acceptance results and reproduction

```sh
python3 tools/annotated-assembly/procedure_evidence_packet.py \
  --images /path/to/DISK1 --entry PLI1.OVL+28AA \
  --frame-bytes 0 --class-slots --output _build/evidence-packet-v0.2
python3 tools/annotated-assembly/procedure_evidence_packet.py \
  --images /path/to/DISK1 --entry PLI1.OVL+4B69 \
  --frame-bytes 0 --class-slots --output _build/evidence-packet-v0.2
```

- +4468's two calls are checked through ordinary parent packets +4693/+4738.
  Its copied slot is E+2 and final SP delta is +2.
- +28AA excludes both +6708 windows and resumes at +2988/+2AB7. Each copy slot
  is E+8 and final SP delta is +8. Exactly 351 coordinates/occurrences remain
  local. +2988 POP B reads the earlier +2956 saved PSW, whose addresses remain
  disjoint from all eight argument bytes. +2ABF stays caller-owned. The outer
  RET retains the original outer hardware slot.
- +4B69 excludes +43D5 and resumes at +4BBD. Its child copy slot is E+2 and
  final SP delta is +2. All 2,088 local occurrences at 52 coordinates, including
  128 loop backedges, remain local; the outer hardware return remains intact.

The full packet suite now has 23 tests. The new tests check all five observed
calls and 55 corrupt/unsupported variants through both packet projection and
the actual stream join: wrong writer, argument address, DE clobber, relocated
slot, same-valued wrong original word, latest-writer identity, RET read, duplicate
POP D, other return register, PCHL and wrong declared consumption. Consumed-word
preservation rejection and unsupported software outer profiles are also checked.
Existing +24BC dependency/polarity, recursive ownership, scope and deterministic
regressions remain passing.

### Size and complexity

Before V0.2 the ordinary-only gatherer rejects both new parent targets at their
software children, so no comparable V0.1 packet sizes exist for them. Current
compact JSON / UTF-8 Markdown artifacts remain ignored under `_build`.

| Packet | JSON bytes | Markdown bytes | Generation seconds, one sample |
|---|---:|---:|---:|
| PLI1+28AA | 2,072,161 | 36,440 | 7.262 |
| PLI1+4B69 | 2,248,603 | 10,764 | 7.776 |
| PLI0+24BC regression | 13,600,351 | 53,240 | 7.748 |

Timing includes serialization/rendering and ran alongside validation; it is not
a controlled performance comparison. Physical LOC includes comments/blank lines.

| Component | bd2defd | V0.2 |
|---|---:|---:|
| Packet generator + local dependency module | 1,171 | 1,236 |
| Shared pass-3 gather/check module | 292 | 329 |
| Combined generator/projection modules | 1,463 | 1,565 |
| Existing software proof module | 61 | 61 |
| Packet tests | 385 | 521 |

The extension adds 102 production lines across the generator/projection modules,
reusing the existing proof unchanged. There is no second recognizer, generic ABI
engine, new static decoder or new ownership authority.

### Validation, limitations and readiness

Project tests, all MINIMAL baseline/pass-1–8 tests (78), packet tests (23), V1
annotation tests (9), verifier tests (11), the full historical byte verifier and
`git diff --check` pass. All **94,720 historical bytes remain exact**. Annotation
and progress files are unchanged, including the 3,662 executed UNDERSTOOD bytes
and 205,904 UNDERSTOOD instruction occurrences. Task test temporary directories
are automatically removed.

V0.2 is ready as the bounded evidence interface for +28AA semantic work with its
current accumulated extent and explicit zero-frame profile. This ticket performs
only infrastructure reuse, and makes no claim about decompilation stability.
Semantic helper gaps remain visible. Software outer packets, other continuation
registers, PCHL, arbitrary POP/count inference, stack switching and unsupported
families remain outside the profile. Existing canonical-block/count, ordinary
outer-return and explicit-frame restrictions still apply. Expanding those
restrictions requires a separate justified infrastructure change.

## Explicit cross-run capture selection (V0.2 unchanged)

Task `PROCEDURE_EVIDENCE_PACKET_CROSS_RUN_CAPTURE`, baseline
`63fd5da15e4ca44a8c99f49884a58bd4489a8be9`. No semantic decompilation,
annotation/status/contract/role/progress change or combined-run packet occurs.

`--run` selects a capture module label, independently of its directory name.
The default remains MINIMAL with the existing default capture; selecting another
run requires its explicit capture path. The Python API accepts keyword `run`.

```sh
python3 tools/annotated-assembly/procedure_evidence_packet.py \
  --run MINIMAL --capture _build/minimal-baseline/capture \
  --images /path/to/DISK1
python3 tools/annotated-assembly/procedure_evidence_packet.py \
  --run FIZZBUZ --capture _build/evidence-packet-cross-run/fizzbuz-capture \
  --images /path/to/DISK1 --entry PLI1.OVL+7C1B \
  --frame-bytes 5 --class-slots 0 3 --output _build/evidence-packet-fizzbuz
```

The second command currently fails clearly at the missing FIZZBUZ catalog count;
it is syntax documentation, not a claim that this procedure is packet-ready.
Required count: `observed_paths.invocations_by_run[selected_run]`. Caller-count
validation also selects that run, omitting rows with no observations for it.
Missing expected invocation metadata is never inferred from observed equality,
path names or another run's count.

The event index must name the requested run. Every indexed chunk must have that
exact full run identity and chunk ID/count; the summary module must agree.
Canonical reports do not carry a run ID, so each canonical instruction's exact
bytes, decoded text, runtime PC, count and first/last steps are checked against
the selected indexed witness chronology. Total instruction counts also agree
with index and run summary. Existing image hashes, byte/runtime checks, canonical
block/count restrictions, ordinary returns and software proof checks remain.
`evidence_packet_local.py`, the ownership gatherer and
`software_continuation.prove()` are unchanged.

### Capture and infrastructure smoke results

The existing `/var/tmp/runes-event-witness-corpus/fizzbuz` report contained
canonical/dynamic reports and REL, but no event witnesses or corrected returns.
No suitable FIZZBUZ witness capture existed in the inspected build/corpus state.
The missing capture was therefore generated once, reproducibly, using:

```sh
dune exec pli80-analyze -- \
  --toolchain /path/to/DISK1 --source examples/pli80/FIZZBUZ.PLI \
  --output-dir _build/evidence-packet-cross-run/fizzbuz-capture \
  --analysis execution --report summary --structure --event-witnesses
```

All artifacts remain ignored (about 930 MiB). PASS1/PASS2/END COMPILATION succeed;
1,145,517 instruction witnesses, zero transfer mismatches, 44,687 corrected
hardware returns and 93 software returns are recorded. The canonical report is
exactly equal to the existing FIZZBUZ corpus report. REL is byte-identical to the
existing 768-byte result, SHA-256
`68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`.

- **+7C1B:** extraction rejects missing
  `observed_paths.invocations_by_run['FIZZBUZ']`; its catalog contains MINIMAL 16
  only. Its caller rows likewise contain MINIMAL observations only.
- **+4468:** extraction rejects the same missing field (catalog MINIMAL 2 only).
  Independently, software *outer* packets remain unsupported. The known +4468
  convention must still be viewed through an ordinary parent projection.
- A bounded existing +4738 parent projection against FIZZBUZ isolates three
  +4468 children. Each passes the unchanged concrete proof: N2, copied slot E+2,
  final SP delta2, and no child steps in parent-local chronology. This is a
  mechanical proof smoke check, not a packet or semantic interpretation.
- An additional already-cataloged +8225 attempt has legitimate FIZZBUZ 25 metadata
  but rejects a callee-subtree access with unresolved historical origin (the
  existing host/nonhistorical-effect limitation). No fallback or widening occurs.

No successful FIZZBUZ packet was emitted; packet sizes are therefore not
applicable. Captures and bounded proof outputs are not committed. These failures
are retained profile/catalog limits, not permission to edit semantic knowledge.

### Regression, complexity and readiness

+24BC MINIMAL Markdown is byte-for-byte identical before/after. Its compact JSON
is byte-for-byte identical after replacing only the existing generator-source
SHA-256 (the generator itself changed). No new schema field or architecture
version is introduced. Default and explicit MINIMAL regeneration remain identical.
+28AA/+4B69 software-child ownership and all 55 corruption variants still pass.

Physical LOC: generator 729 -> 776 (+47); local dependency module 507 -> 507;
combined generator/local 1,236 -> 1,283 (+47); packet tests 521 -> 602 (+81).
New tests cover explicit content identity independent of paths, mixed chunks/
summary/canonical evidence, missing per-run catalog counts and selected-run
caller validation. The complete packet suite has 27 tests. All 109 MINIMAL
baseline/pass1–12 tests, V1 annotations, project tests and historical byte
verification pass, along with `git diff --check`. All **94,720 bytes remain
exact**; semantics, statuses and progress are unchanged.

Run selection and the reproducible FIZZBUZ witness capture are ready for Pass 13.
The requested +7C1B packet first needs independently established FIZZBUZ structural
invocation/caller metadata in that semantic pass; this ticket does not add it.
+4468 still requires a supported ordinary parent or existing bounded forensic
projection. Host/nonhistorical callee effects remain unsupported. No new ownership,
ABI inference, continuation family, semantic substitution or differential merge
is introduced.
