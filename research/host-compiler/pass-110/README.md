# Pass110 — declaration-to-expression attribute provenance

**Partial semantic recovery.** The actual `dcl i fixed;` record now has a
checked source-to-record-to-expression chain. Its retained `15h/0Fh/00h` tuple
reaches the selected `mod(i,15)` operand and contributes to the freshly computed
common context. General metadata encoding and the MOD result's own publication
remain unresolved. No typed frontend operation or MIR lowering is published.

Baseline: `977f0f795f9f422ececb82979ae383b0a8f87398`, verified as both HEAD and
origin/main before editing. The experiment extends the existing read-only
Pass109 observer with an opt-in declaration capture. Its default Pass109 journal
still has SHA256
`4e253960fb28b838bbb9c707394dad70c545e352e1f687e711afab225ad50a1e`.
The isolated Pass110 capture records the first 550,000 concrete instructions,
then retains the existing observer's selective events. Large journals, RAM and
replays stay under `_build/host-compiler-pass-110/capture`.

## Source, lexical processing and symbol ownership — OBSERVED

All offsets below are in the actual CRLF-normalized CP/M input, not the LF
repository file. The source-record DMA writer, resident raw-character scratch
chain, line-buffer writer, lexical read, normalizer and prefix writer are
checked separately. Matching characters alone do not establish these links.

| Item | Normalized source span | Source position | Prefix publications |
|---|---|---|---|
| `dcl` | [39,42) | line 2, columns 5–7 | 95486, 95570, 95654 |
| declaration `i` | [43,44) | line 2, column 9 | 96824 |
| `fixed` | [45,50) | line 2, columns 11–15 | 98003, 98087, 98171, 98255, 98339 |
| selected expression `i` | [89,90) | line 4, column 16 | source-to-prefix link in evidence |

The complete declaration occupies [39,51), including its semicolon. In the
repository file it occupies [38,50). Lowercase letters pass through the actual
resident `ANI 5Fh` normalization; this is distinct from the digit route.

PLI0's +1C6D path reads prefix width one and writes record `6FE8h+1`. Its
+1AA6 initialization clears attributes. +1CBE/+1CBF copies the current prefix
`I` into record+10 (step97845), after +1C7B/+1C7C accounts for the header and
name extent. +1E11 publishes the total record length, eleven. The proof ties the
record's name to declaration source byte43, not to an arbitrary ASCII `I`.

The selected `FIXED` prefix is compared backwards against the actual keyword
record by +439B/+439C. All five character comparisons succeed; the exhausted
walk reads the token at runtime63B1h and publishes A2h at20C3h. Declaration
processing consumes that token, computes ordinal21 and its four-byte table
index84, and reads qualifier bits14h from runtime22CAh. This is a concrete
keyword-dispatch/table chain, not a type name inferred from tag15h.

## Declaration defaulting and retained record — OBSERVED / DEDUCED

At PLI0+08BE, record+2 receives14h from the selected qualifier table. The actual
+0AE4 routine copies that byte and record+3/+4/+5 into stack locals. Its selected
path performs `14h OR 11h = 15h`, then `15h OR 14h = 15h`, and explicitly defaults
the local at FFDEh to0Fh (+0B97). +0CC0/+0CDC/+0CE9 publish the completed fields:

| Original field | Value | Last publication | Established meaning/limit |
|---|---|---|---|
| `6FE8h+2` | 15h | 100496 | completed declaration qualifier/tag; selected FIXED/default path |
| `6FE8h+4` | 0Fh | 100513 | defaulted numeric attribute, consistent with documented binary precision15 |
| `6FE8h+5` | 00h | 100522 | retained zero attribute; general scale encoding remains unproved |

The middle field has a precision-compatible local law; a universal field
meaning is not asserted. This does not decode each qualifier bit or identify15h
as a universal enum.
The 0Fh default is instruction-produced independently of literal value15.

The checker follows each field **and the name** through the actual copies:

`6FE8h → FBF3h → 6BC0h → FBF3h`.

The first and last copies use PLI0+1A70/+1A71, the middle copy +254A/+254B.
Every consumed byte has its last writer checked; intervening address reuse is
not ignored. In particular,6BC0h previously held unrelated data. The final name
at FBF3h+10 remains owned by this declaration. The selected expression's prefix
comes from source byte89; +45D0 loads it and +45D1 compares it to that retained
name (step388425). The equality branch succeeds after the record-length check.

## Expression context — OBSERVED

The resolved FBF3h pointer is stored through A66E/A66F, reread into A75A/A75B,
and then restored to A863/A864. +419F reads record+2; +4176 publishes A628.
+3FAA and +3FB3 read record+4/+5 and publish A62B/A62E. These are genuine
resolved-record reads, not a match to a tuple elsewhere in RAM.

The canonical mapped publishers/readers already implemented in
`Acquisition_family`, `Mapped_control` and the mapped publication families
explain the concrete carrier geometry. No canonical implementation is changed.
The observer verifies actual instructions and evolving memory; no host child
callback substitutes for any guest instruction.

Before common-context calculation, there is a same-valued middle-channel cap and a
mapped publication/remap. The tag and two attributes pass through
AC77h/AD0Ch/ADA1h and return into A629/A62C/A62F. The old A628/A62B/A62E contents
are not presumed to survive. The other operand is `[02h,02h,00h]`.

PLI1+30C1 then **computes** context `[15h,0Fh,00h]`:

- +3141 writes tag15h after the actual classifier branches.
- The first operand's last two attributes are freshly copied to A665/A666.
- The other operand's width2 indexes the guarded table and returns7.
- The selected path forces the context's zero channel to zero, compares the
  two zero channels, and computes the maximum of15 and7.
- It adds the selected zero channel and caps at the separately initialized
  A642 default limit15. The final middle byte is15.

The table observation proves the selected `2 → 7` lookup. It does not establish
an arbitrary decimal-to-binary precision formula or every table entry.
Pass109 separately proves the following +6708 E02 numeric conversion and
copy of this context into the literal slots, plus the mapped value/attribute
publications. That published proof is preserved, not replaced or reinterpreted.
Tag15h is decimal21; the constructed literal payload remains0F00h, numeric15.

### Natural discriminants

The same capture supplies source-correlated `mod(i,3)` and `mod(i,5)`:

| Literal source offset | Identifier source offset | Literal tuple | Declaration tuple | Width lookup | Common tuple |
|---|---|---|---|---|---|
| 167 (`3`) | 165 | 02/01/00 | 15/0F/00 | 1→4 | 15/0F/00 |
| 238 (`5`) | 236 | 02/01/00 | 15/0F/00 | 1→4 | 15/0F/00 |

Their actual name comparisons and declaration-field reads are checked against
the same retained record's last writers. This discriminates the literal's
one-digit attribute from the retained declaration's15, and the two-digit
`15` case's2→7 lookup. It supports a width/precision role for the middle
channel. These observations do **not** distinguish a scale interpretation of
the always-zero channel from every alternative. No synthetic context is claimed
as a natural observation.

## Independent checks and their limits

The following original entries are replayed on copied complete RAM and CPU
states, through their own original hardware continuations:

| Window | Steps [entry,exit) | Instructions | Data reads | Ordered writes | Actual continuation |
|---|---|---:|---:|---:|---|
| PLI0+0AE4 default completion | [100276,100600) | 324 | 111 | 56 | 362Dh |
| PLI1+30C1 selected `15` context | [393452,393793) | 341 | 142 | 77 | 550Ah |
| PLI1+30C1 selected `3` context | [463314,463655) | 341 | 142 | 77 | 550Ah |
| PLI1+30C1 selected `5` context | [530112,530453) | 341 | 142 | 77 | 550Ah |

Each comparison includes every register/flag, PC/SP, full64KiB RAM, ordered
reads and writes, same-valued writes, nested CALL words and surviving stack
residue. RET consumes the entry word and exitSP=entrySP+2. Entry/exit RAM digests
are recorded in `declaration-provenance.json`. These bounded windows make no
BDOS calls. The surrounding capture is ordinary concrete FIZZBUZ execution.

**Both executions use this repository's CPU engine.** This is an independent
window replay with independently stated copy/OR/default/min/max checks, not a
second independently implemented CPU engine or a proof of every opcode.
No post-state copying implements a compiler operation. Witness step numbers
identify evidence; they never select host compiler semantics.

## Primary language rules and semantic decision

The [Digital Research PL/I-80 Language Manual, second printing December1980](https://www.bitsavers.org/pdf/digitalResearch/pl1/PL1-80_Language_Manual_Dec80.pdf)
was downloaded again and its digest matched Pass109's primary-source PDF.
Sections3.1.1/3.1.2,7.2.1 and12.1.7 were checked directly. The compact
`language-evidence.json` separates documentary rules and execution evidence.

**DOCUMENTED:** FIXED alone denotes signed binary integer precision15; its
storage is two bytes. Decimal integer spellings acquire binary typing in a
requiring context; otherwise decimal spelling determines precision/scale.
Mixed fixed binary/decimal arithmetic uses binary, and MOD returns the common
arithmetic type. The documented MOD zero-divisor branch and out-of-range binary
assignment rules are separate from this successful case. The edition is
contemporary; universal point-release equivalence to v1.4 is not established.

**DEDUCED for this source:** `i` has the documented fixed-binary(15) declaration;
`mod(i,15)` therefore has a documented binary arithmetic context. This is now
corroborated by an actual declaration-to-operand-to-common-context ownership
chain, not merely the source spelling and matching output.

**OBSERVED:** the specific declaration/defaulting fields, their relocations,
resolved identifier reads, width-discriminating context calculations and the
already proved successful numeric15 construction.

**UNPROVED / HYPOTHESIS:** a universal tag/bit vocabulary; the general zero-field
encoding; standalone intrinsic literal representation before contextual
conversion; an operation-specific MOD result-type publication and its backend
consumer. In particular the result tuple in this evidence is a **common
conversion context**, not a newly proved MOD result record. Documentary MOD
semantics do not by themselves identify its implementation-level result fields.

Consequently the delivered contract is deliberately partial: **the selected
source declaration's retained metadata contributes causally to the literal's
common conversion context**. No fully typed OCaml expression record is added.
Neither a two-byte payload, an unchanged REL golden, nor a plausible scale name
closes the remaining result/encoding gap.

## Validation and preservation

```
python3 tools/annotated-assembly/run_host_compiler_regressions.py \
  --categories pass110,pass109,diff-check,validation-runner-tests \
  --images /home/john/pli/cpm/pli80/DISK1 \
  --output _build/host-compiler-pass-110/validation --workers 4
```

`validation.json` preserves the final measured receipt: **6/6 categories, 28
Python test executions, 9.500s wall, 11.805s summed category time, 4 workers**. The Pass110 category
captures in its own directory; Pass109 uses its original separate directory.
No captures are shared writable between those categories. Build/project remain
mandatory. The tests verify all four original image hashes and the preserved
annotated-assembly tree, totaling94,720 reconstructed bytes. No annotations or
classifications changed, so V1 regeneration is unnecessary.

Fresh FIZZBUZ REL remains
`68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`.
All five published golden records are preserved; this pass does not claim a
fresh five-program campaign. The image and unchanged runtime identities are
recorded in `preservation.json`.

No runtime semantics, native roots, knowledge classifications, MIR demos,
historical certificates or previous proof artifacts change. No FULL was run.
Pass74 epoch3 remains the last certified FULL; the isolated unsuccessful
Pass105 FULL and Pass79 failure evidence are untouched. Proof instruction
counts do not represent installed execution savings.

## Smallest next step before OCaml-to-MIR lowering

Trace the operation-specific MOD result publication after this proved common
context and its subsequent consumer, keeping the converted operand and result
attributes distinct. For the zero channel, select one already observed context
with a nonzero field and prove its producer/consumer law before assigning a
scale name. This is a specific remaining evidence requirement, not permission
for a broad type system or an exhaustive numeric parser. Combine that decoding
with the primary rules to decide a bounded typed expression contract; only then
lower recovered semantics to upstream MIR.
