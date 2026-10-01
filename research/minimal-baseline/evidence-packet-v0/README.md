# Procedure Evidence Packet V0 experiment

Task: `PROCEDURE_EVIDENCE_PACKET_V0`. Starting commit: `6679adb`.
Selected entry: **PLI0.OVL+24BC**, image SHA-256
`e78818eca27d051d604b42c6b3202b30e5db6c46df6cf4b498fca601a86d7bff`,
runtime entry `46BC`. This experiment mechanically joins existing MINIMAL
observations and accumulated knowledge for a fresh, independent decompilation
session. It does not interpret or improve the procedure's semantics.

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
member's initial frame bytes, local chronology, block visits and nested calls.

Classes use entry C, the first writes to **F+9/F+10**, and the **complete ordered
local transfer path**, including recursive callsites. This gives useful browsing
groups without discarding the distinct data flow of any of the 85 members.
For example, the 54-member C=0/F+9=80/F+10=00 path retains different initial
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
