# Pass108 — MIR architectural reassessment and semantic evidence gap

Baseline: `9cc23a96e1fc222749383bfa94efb1f6cf6f759e`.
Backend remains upstream `vnmakarov/mir` at
`a8ab7c31cd5f9b23b77d84c60b3d83e62d9d304c` (MIT).

**Outcome: no compiler-semantic lowering boundary was established in this bounded
review. No new MIR operation is published.** The user's architectural clarification
supersedes the initial byte-emission deliverable. This is an evidence-backed
assessment, not a completed byte-emission or PL/I compilation milestone.

The intended architecture is:

```
PL/I-80 source -> recovered language semantics implemented in OCaml
              -> upstream MIR's existing API/instructions -> host native code/JIT
```

A historical INT decoder could be another input only after it has an independently
proved semantic contract. INT/REL files are historical evidence and possible
compatibility outputs; serialization is not the required compiler/backend cut.
No independent IR, frontend, decoder, serializer or runtime is implemented here.

## Why the append experiment is set aside

The initial request's non-flush +0EF6 operation is well supported by Pass22/23:
write scratch20B0, append at1D8C+index, publish index+1; index127 enters the real
record-service chain. Its machine and buffer semantics are understood, but they
say nothing about the meaning of the emitted byte in a PL/I program.

Before the clarification, an uncommitted prototype compared a bounded MIR append
with six actual MINIMAL non-flush windows at indices0/1/63/64/125/126 and508
synthetic CPU inputs. Its local three-test run passed. That confirmed the API
technique; it did **not** recover language semantics. The prototype and its
journals were set aside under ignored
`_build/host-compiler-pass-108/set-aside` and `.../proof`. They are not published
implementation or evidence for a new architectural boundary. No emitter C stub,
MIR function, Dune executable or production change from that prototype remains
in this commit. No new filesystem/serialization machinery was pursued.

Pass106/107 remain valid technology demonstrations of synchronous OCaml/C/MIR
embedding and historical state projections. They do not establish the compiler's
language-semantic interface. Their source and published evidence are preserved.

## Bounded candidate review

| Candidate | Established evidence | Missing semantic connection |
|---|---|---|
| Resident +0EF6, Pass22/23 | Byte-buffer append, cursor and scoped flush behavior | No operation/type/value meaning for the payload byte |
| PLI1 +7A79, Pass24 | Fresh position-map lookup and little-endian mapped word | A mapped word is not independently identified as a typed PL/I value or INT record schema |
| Resident +15DA and +1376, Pass44 | ASCII-digit byte predicate and bounded digit-prefix acquisition | Classification/acquisition does not define literal type, precision, scale or generated-program behavior |
| PLI1 +6708 E02, canonical Acquisition_family | Bounded decimal construction machinery under inherited guards | No self-contained source-correlated typed-literal contract covering representation attributes and exceptional paths |
| INT file at PLI2 entry, Pass16 | Concrete INT lifecycle, pending data and carried-state dependencies | No complete semantic decoder or proof of file-only state closure |

This is not an exhaustive audit of the repository or a claim that a semantic
boundary cannot be recovered. It identifies what these inspected contracts do
and do not justify. Existing full machine contracts are not weakened.

### Concrete counterexample: acquisition accumulator is not a literal value

The archived Pass44 natural FIZZBUZ case has prefix bytes31h,35h (spelling `15`),
width2, selector02 and following byte29h. Its acquisition accumulator is **6**.
The canonical prefix append updates that field by adding the current byte and
masking with0Fh. The archived one-byte prefixes `3` and `5` give3 and5, which
could conceal a mistaken interpretation; the two-byte case distinguishes it:

```
(31h + 35h) mod 16 = 6
ordinary positional decimal digits "15" = 15
```

Therefore this field cannot simply be fed to MIR as the literal's numeric value.
This is a fact about the observed acquisition field, not a new theory about all
INT records, compiler hashing or PL/I numeric representation. We do not infer a
PL/I default type or precision from the spelling or the selector code.

The nearby +15DA classifier has exact bytes
`3A C1 20 D6 30 D6 0A 9F C9`: read20C1, wrapped subtract30h, subtract0Ah, self-SBB,
RET. It returns FFh for context bytes30h..39h and00h otherwise. Its caller uses
the mask in acquisition. This is a defensible lexical helper candidate, but
lowering the compiler's helper to MIR would still compile a piece of the compiler;
it would not establish how a PL/I program operation should lower to the backend.
No extra digit-classifier MIR demo was added merely to create an executable result.

### INT is not yet an independently specified semantic input

Pass16's archived FIZZBUZ PLI2 entry is step664916. Its measured suffix first
reads731 data bytes before overwriting them, alongside source/file state and
partial REL state. This is an **historical observed-path** dependency witness,
not a requirement that a future compiler retain those exact machine bytes.

It demonstrates why a file-only semantic decoder must be proved rather than
assumed. Later Pass102's8/8 software-dispatcher proofs and the installed gateway
contracts establish faithful historical effects in their supported domains.
They do not, by themselves, assign typed language meanings to INT fields or
prove that all carried state is reconstructible from INT. This report does not
reuse Pass16's old missing native dependencies as claims about current readiness.

## What a real lowering contract still needs

For one recovered source operation, establish its source span and binding,
operand values, language types, precision/scale/signedness and defined exceptional
behavior. Separate those semantic results from historical scratch and serialized
representation. Independently correlate the recovered operation with historical
behavior; do not use generated byte identity alone as its semantic definition.

Then the OCaml implementation can lower the established operation using upstream
MIR's existing types/instructions or an explicitly specified runtime helper.
MIR's integer widths/arithmetic do not supply missing PL/I precision, conversion,
overflow or decimal semantics. No new intermediate representation is proposed.
See the pinned [upstream API](https://github.com/vnmakarov/mir/blob/a8ab7c31cd5f9b23b77d84c60b3d83e62d9d304c/MIR.md).

For an INT route, first prove one actual record's producer-to-consumer ownership,
semantic meaning, value/type fields, ordering and required side inputs. Unknown
records must remain undecoded. A complete serialized file or a byte reader is
not a semantic schema. Historical adapters and optional compatibility encoders
remain separate from native host-code generation.

### Smallest next investigation

Trace the archived FIZZBUZ `15` prefix toward +6708 E02 and its consumers,
first verifying the producer/consumer connection with existing captures and
canonical guards. Identify
which field actually holds the constructed value and which fields establish its
attributes. Check the corresponding source context and independently establish
its applicable language rules before selecting MIR instructions.

Success would be **one source-correlated typed constant contract**, with exact
unsupported states and differential evidence, not a generic literal parser or
compiler rewrite. A new executable lowering must wait if type/precision or value
ownership remains unproved. No guessed token-code names or captured values may
substitute for those prerequisites.

## Evidence and validation

`boundary-assessment.json` records the concrete witnesses, scoped decisions,
next investigation and digests of the archived sources consulted. The focused
Pass108 category checks those immutable witnesses, the accumulator counterexample,
actual classifier bytes and all four historical image identities. It examines
canonical acquisition source at the assessment's immutable baseline via Git;
it does not require future HEAD to remain at this epoch.

These are evidence-consistency checks, **not independent proof of new language
semantics**. Pass106 and Pass107 execute their existing real MIR interpreter/JIT
checks unchanged. The incremental selection is:

```
python3 tools/annotated-assembly/run_host_compiler_regressions.py \
  --categories pass108,pass107,pass106,diff-check,validation-runner-tests \
  --images /home/john/pli/cpm/pli80/DISK1 \
  --output _build/host-compiler-pass-108/validation --workers 4
```

Build/project are mandatory. `validation.json` preserves the actual runner receipt.
No new emitter or semantic MIR execution is claimed by that receipt. The prototype
is not part of the selected regression and is not installed or published.

Historical reconstruction remains94,720 bytes by unchanged image hashes/lengths
and annotated-assembly tree. All prior goldens, sources, canonical operations,
controllers and certificates are unchanged. No five-source fresh run or fresh
reproduction of Pass22's635 non-flush/five flush proofs is claimed. No native
roots, knowledge promotions or annotation changes. No FULL was launched, scheduled
or awaited. Pass74 epoch3 remains the last certified FULL; the Pass79 failures
and isolated Pass105 FULL attempt remain untouched.
