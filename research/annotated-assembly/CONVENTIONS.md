# Annotated decompilation conventions V1

These requirements apply to every future promotion or material update of a
ProcedureHypothesis, including Luna and Sol sessions. Read this file before
editing the reconstruction. Historical binaries remain authoritative; assembly
comments contain the accumulating readable decompilation. Detailed observations
remain in evidence JSON/reports.

## Identity and encodings

- Identity is exact image SHA-256 plus file offset. Runtime addresses are a
  separate coordinate, with the verified load base retained.
- Preserve address labels such as `PLI2_047D`. Semantic names supplement them.
  Secondary entries and shared tails keep distinct stable identities.
- When a prior RAW-row label lands inside a newly established instruction's
  operand bytes, retain it as a numeric coordinate-only `EQU`. List its file
  offset in the image's `coordinate_only_labels` manifest array. It emits no
  bytes and asserts no instruction entry; the verifier checks its stable name,
  literal runtime value and coordinate comment. Do not introduce semantic EQUs
  or substitute these labels for observed instruction starts.
- Preserve original opcode encodings, operands, raw directives and bytes. Do
  not canonicalize undocumented aliases or promote data/unprocessed paths.
- Section intervals remain nonoverlapping and gap-free. Whole-image equality
  and section hashes are mandatory, not a side effect of plausible assembly.

## Standard procedure header

Every existing evidence seed has one `procedures.json` entry and one source
header delimited by `; @procedure-v1 IMAGE+OFFSET` / `; @end-procedure-v1 ...`.
Keep these fields, in the documented order:

| Field | Required content |
|---|---|
| Entry | Stable label, image+offset, runtime entry and image SHA-256. |
| Extent | Hypothesized start/end file offsets, exclusive end, overlaps/secondary entries. |
| Callers | Observed coordinates and counts, with run identities kept separate. |
| Returns | Observed return sites and hardware/argument-consuming software/tail convention. |
| Inputs | Register, flag, memory and path preconditions; unknowns explicit. |
| Outputs | Supported registers/flags/memory results; delegated results identified. |
| Clobbers | Registers/state potentially written, not just values changed in one sample. |
| Memory | Important fixed and dynamic state, widths, stack-local layout and role names. |
| Direct callees | Actual direct targets; opaque helpers and external tail entries explicit. |
| Coverage | Observed runs/counts, represented bytes and concrete paths or case descriptions. |
| Unresolved | RAW paths, opaque effects, unobserved outcomes, counterevidence and semantic unknowns. |
| Contract | Useful low-level operational behavior, with its scope and completeness. |
| Hypothesis | Tentative higher-level role; `none` is valid. |
| Completeness | Independent `bounds`, `control_flow`, `contract` fields. |
| Evidence | Compact links to retained seed/report detail, not copied trace windows. |

Wrap prose at readable widths. Counts aggregate only the same stable coordinate
in the same run. Complete caller contexts and trace dumps do not belong here.
The one procedure-level pseudocode should explain the operation compactly;
local block pseudocode carries the detail.

Use **OBSERVED** for bytes/registers/accesses/branch outcomes/transfers actually
recorded; **DEDUCED** for constrained interpretations and documented instruction
effects; **HYPOTHESIS** for proposed procedure identity/bounds and semantic roles.
An extent remains a hypothesis even when its bounds are judged stable. Do not
turn RoutineCandidate, canonical-block or stack-context ownership into identity.

## Completeness is independent of byte status

`procedures.json` stores:

```json
{
  "completeness": {
    "bounds": "provisional",
    "control_flow": "partial",
    "contract": "partial"
  },
  "observed_paths": {
    "invocations_by_run": {"MINIMAL": 199},
    "represented_bytes": 90,
    "description": "observed path conditions and outcomes"
  },
  "contract_scope": "explicit preconditions for the supported contract",
  "unresolved_paths": ["remaining paths, effects or meanings"]
}
```

- **bounds stable:** the reviewed local entry/terminal sequence supports that
  envelope in this exact image. This is confidence in a hypothesis, not proof
  of an original source-language procedure. Shared-entry intervals may overlap.
- **bounds provisional:** RAW holes, escaping guards, continuation/body ownership
  or other evidence leave the envelope unsettled.
- **control_flow complete:** the local operational graph is represented, including
  return conditions and direct transfers. It does not mean every input or branch
  outcome ran. A three-byte comparison can have complete decoded control flow
  while its early RNZ outcomes are unobserved.
- **contract complete:** the stated low-level operation, inputs, outputs, flags,
  memory and clobbers are described at the declared scope. Table meanings and
  source-language roles may still be unknown. A defined loop does not imply a
  termination theorem for arbitrary data.
- **partial:** name its path restrictions/opaque effects. Never hide them behind
  an UNDERSTOOD label or a reassuring semantic name.

An UNDERSTOOD section can have a **partial procedure contract**: its represented
bytes have a useful scoped contract, while the enclosing hypothesis contains
RAW branches or opaque effects. Keep that qualification visible in the header.
Downgrade bytes if their behavioral justification fails; otherwise qualify the
scope/completeness. A comment-only review earns no additional decoded/understood
bytes. Execution coverage and understanding remain independent measurements.

## Local semantic comments

Explain effects, register roles, addresses, truncation, flags and ordering.
Retain the existing offset/runtime comment on every emitted line. For example:

```asm
PLI2_047D: LXI H,0ABF8H ; HL = &class_lookup_index (ABF8H) ; +047D runtime=267DH OBSERVED
PLI2_0480: MOV M,C     ; byte[class_lookup_index (ABF8H)] = C ; +0480 runtime=2680H OBSERVED
PLI2_0481: LHLD 0ABF8H ; L = saved index; H = adjacent byte ABF9H, later discarded
PLI2_0484: MVI H,00H   ; HL = zero_extend(L); flags preserved
```

The abbreviated last two lines illustrate meaning; committed rows must also
retain their coordinate comments. Names in square brackets identify addressed
storage. `byte[...]` and `little_endian_word[...]` distinguish widths. In
particular, fetching H from A917 reads its **first byte**, not the entire named
two-byte repair word. Literal guard values such as AE7AH are not dereferenced
storage just because they have a useful name.

Avoid replacing equations with mnemonic paraphrases when the established role
is known. Explain `BC=zero_extend(j)`, table indexing, preservation across helpers,
or the purpose of a flag mask. Keep raw addresses visible. Unknown meanings
stay unknown; low-level names do not imply PL/I source types.

Important examples already preserved locally:

- The append helper's final NZPA flags come from its **second INR**, not the
  earlier capacity CPI or returned data byte.
- A literal-mismatch predicate returns A=0 without recomputing comparison flags;
  CY is not its Boolean result.
- PLI1+4468 pops a caller argument and re-pushes its continuation two bytes above
  the original slot. Describe its software RET, not a conventional frame pop.
- The dispatch gateway pushes 42B4H before PCHL. PCHL itself creates no CALL word.
- A pointer/tag predicate reads the tag even if the bound test already succeeds.

## Near-code block pseudocode

Place `; @block-pseudo OFFSET`, `; pseudo:`, and `; | ...` lines immediately
before each established nontrivial instruction group. Example:

```asm
; @block-pseudo 1E43
; pseudo:
; | cursor--; positions[++processed] = cursor
```

Use known entry/branch/loop/helper-return groups. These are explanatory groups,
not new procedure identities or a static sweep. Never infer a procedure by taking
the minimum and maximum executed addresses. Shared tails reuse one physical
group and comment while retaining every distinct entry header.

## Durable role names

`data-roles.json` binds a low-level name, runtime address, width (or unknown
length), exact image identity and scope. Examples: `class_lookup_index@ABF8H`,
`walk_balance@AC3CH`, `record_top@1C36H`, and `text_index@1F06H`.

Roles are local evidence-backed names, not global source-language declarations.
The text index is a last-written index during building and a next-read index
in the reader; its header/pseudocode must retain that distinction. AD0A is saved
dispatch state and a candidate attempt byte in one scan, not an established type
ID. Aliases must not erase either the numeric address or code coordinate.

## Required update/verification workflow

1. Read the current source, evidence, procedure catalog and these conventions.
2. Within the authorized investigation scope, establish a hypothesis and useful
   contract from exact bytes and evidence. Reuse existing evidence where possible.
3. Update local assembly meaning and near-code pseudocode; preserve encodings and
   stable labels. Update `procedures.json`, relevant role records and evidence.
4. Review completeness independently from section status. State scopes and
   counterevidence before promoting a region.
5. Synchronize headers/body comments from the reviewed catalog if useful:

   ```sh
   python3 tools/annotated-assembly/decompilation_annotations.py --render
   ```

   This renderer only applies authored comments/catalog entries. It decodes no
   bytes, discovers no region and changes no executable statement or directive.
   Do not regenerate sources with older ad hoc scripts that discard V1 meaning.
6. Run the single full verifier and relevant checks:

   ```sh
   python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
   python3 tools/annotated-assembly/test_decompilation_annotations.py -v
   python3 tools/annotated-assembly/test_verify.py --images /path/to/DISK1 -v
   git diff --check
   ```

The normal verifier enforces V1 headers/local meaning/role references/completeness
alongside section hashes, whole-image identity and offset mapping. It rejects
complete claims over unrepresented RAW holes. Semantic truth still requires
review and independent contract checks; formatting validation is not a decompiler
or an oracle for comments.

## V1 review outcome

This formatting review covers all 44 existing hypotheses, including all 41
STRUCTURED/UNDERSTOOD entries and the three DECODED context seeds. It adds
1,054 physical instruction-effect comments and 145 near-code pseudocode groups.
There are 31 stable / 13 provisional bounds, 31 complete / 13 partial local
control-flow records, and 18 complete / 26 partial contracts.

Thirteen UNDERSTOOD hypotheses are explicitly qualified as partial rather than
presented as fully understood procedures. Their useful existing scoped contracts
remain valid, so no byte status is changed. No new compiler region, execution
capture, semantic category or procedure merge is introduced.

[conventions-v1-review.json](conventions-v1-review.json) records identical
before/after executable/directive-surface and stable-label hashes, unchanged
historical image identities, and the qualification list. All 94,720 bytes remain
exact. Future semantic promotions must preserve the conventions, while this
review remains a historical audit of the comment-only change.
