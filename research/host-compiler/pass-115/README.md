# Pass115 — selected FIXED DECIMAL declaration provenance

Baseline HEAD and origin/main:
`64d356d7db363e2d3df4ae79537f286a8377c52a`.

**Partial result:** `dcl x fixed decimal(7,2);` has a concrete source-to-parameter-
to-record-to-consumer chain. Its retained raw tuple is **16h/07h/02h**. For this
selected declaration, the middle and final numeric fields retain the explicit
precision and nonzero scale arguments. Later attribute arithmetic provides
independent discrimination between their roles. Literal digits and decimal
points are source-owned, but retained literal typing/payload and the complete
multiplication-to-assignment relationship remain open. No decimal MIR or runtime
arithmetic implementation is introduced.

## Source and historical identity

`examples/pli80/FIXEDDEC.PLI` remains SHA256
`8936b0b20f6b5cb3def56c83e64e282cae06f2c74838b95579e2590fd9f59e92`.
Its normalized CP/M input is independently retained under ignored capture,
SHA256 `8d0a1cefe469daf60fc5bd067f39b4ea2379b6752856b92a0ff88efb0b95aa76`.
All offsets below refer to that normalized input, not LF repository offsets.

The existing discriminator/pass-15 screen and `docs/pli80-experiments.md`
provide structural compilation evidence. A fresh ordinary concrete compilation
reproduced **673,691 instructions**, warm boot and the **384-byte REL** with
SHA256 `b93cddf1e9dd85fa3ef7f8a27740b43da3396c69b10ff03eab248eef2f9e9938`.
This is compiler execution, not execution of the generated program.

`decimal_attribute_capture` reuses the existing read-only Experiment callbacks
and Pass109's copied-CPU replay pattern. The observer selects source/declaration
and attribute code/address regions, plus four bounded checkpoint windows. A
compact global write ledger includes repeated and same-valued CPU writes;
source-record events account separately for DMA publications. This prevents
omitted intervening writers without retaining every instruction of the run.
Large journals/RAM are isolated in `_build/host-compiler-pass-115/capture`.
No shared mutable earlier capture is used. `capture-evidence.json` identifies
all final journals and snapshots by size/digest.

## Source to keyword and symbol ownership — OBSERVED

The checker follows the actual source record/DMA byte, resident reader scratch
2098/209A, 20A9 paired transfer, 20AB line copy, lexical line-buffer read,
normalization and prefix publication. Each read is tied to its last writer;
a matching byte alone does not establish provenance.

| Source item | Normalized offsets | First prefix publication |
|---|---|---:|
| dcl | [40,43) | 96784 |
| x | [44,45) | 98122 |
| fixed | [46,51) | 99327 |
| decimal | [52,59) | 100983 |
| 7 | [60,61) | 102867 |
| 2 | [62,63) | 103383 |

The complete selected declaration is normalized [40,65). The keyword matcher
compares the acquired characters backwards against one successful historical
keyword record. Actual token publications are DCL=87h, FIXED=A2h,
DECIMAL=88h. The declaration path freshly consumes FIXED/DECIMAL tokens.
The selected qualifier ordinals are 21 and 18, and their four-byte table
entries supply **14h** and **12h**. PLI0+08B8 ORs the current declaration byte;
+08BE publishes `14h OR 12h = 16h`. These are selected dispatch/table facts,
not a universal enum interpretation of 16h.

The declaration's identifier is read from its source-owned prefix through
`LDAX B` at99168 and written as X to record **6FE9h+10** at99169. Attribute
ownership is therefore tied to the actual declaration name, rather than to
an arbitrary record containing an X or the expected numbers.

## Explicit numeric parameters and completion — OBSERVED

Precision and scale are separately acquired one-digit parameters. The resident
+1956/+1957 instructions read their respective current prefix and subtract30h;
the two-byte numeric scratch2153/2154 receives **0007** or **0002**. This
conversion is distinct from the prefix's modulo-16 acquisition checksum.

| Channel | Digit read | Numeric low write | Parameter local |
|---|---:|---:|---|
| first explicit argument7 | 103054 | 103074 | 6883 |
| second explicit argument2 | 103553 | 103573 | 6884 |

The actual local values pass via C/E to687E/687F, then through fresh reads to
record+4/+5 at103877/103882. No field meaning is inferred from a coincidental2.
The argument positions are source-owned and their separate consumers are checked.

At104662 the original CALL enters PLI0+0AE4 with this record. It copies the
qualifier, first parameter and second parameter into stack locals, checks the
actual selected conditions and republishes them:

| Field | Value | Completion publication | Scope of interpretation |
|---|---:|---:|---|
| record+2 | 16h | 104864 | completed FIXED/DECIMAL qualifier byte |
| record+4 | 07h | 104881 | retained explicit precision argument7 |
| record+5 | 02h | 104890 | retained explicit scale argument2 |

The first numeric field is nonzero, so this path preserves7 rather than taking
the binary precision15 default. Other flags in record+3 are not decoded. No
sign field, packed-decimal payload, sign nibble or storage width is inferred.

The named y and z declarations provide separate natural witnesses: their source
identifiers produce distinct records6FF4/6FFF, whose actual completion arguments
and RAM contain16h/07h/02h. Their complete completion windows are replayed. The
full source/parameter proof is not redundantly repeated for every character of
these otherwise identical declarations.

## Retention and consumers — OBSERVED / bounded DEDUCED

The checker follows each selected field **and the name**, with separate last
writers, through actual copies:

`6FE9 → FBDD → 6BB4 → FBDD`.

The first/last copies use PLI0+1A70/+1A71; the middle uses+254A/+254B. Actual
MOV/LDAX/STAX effects are checked, including address reuse and identical writes.
**FBDD is x's retained record; FBF3 belongs to z.** Equal attribute tuples do
not authorize joining those records.

Later +3FAA reads x's retained byte+4 at375682 and +3FAB publishes A62B=7.
+3FB3 reads byte+5 at375687 and +3FB4 publishes A62E=2. These are direct
consumers of the source-linked retained fields.

A later selected arithmetic witness supplies additional discrimination:

- PLI1+6440/+6446 reads middle channels7 and7; INR produces15, published by+6449.
- +644A/+6450 reads final channels2 and2; ADD produces4, published by+6452.

The different arithmetic laws agree with the documented precision/scale laws
for multiplication. This strengthens the selected declaration interpretation
beyond matching two bytes. **A full source-operator/operand-remapping/result-
owner/assignment chain is not claimed.** These witness channels are not silently
promoted into a complete typed expression result. The always-zero binary field
from FIZZBUZ is comparison evidence, not a universal scale encoding theorem.

## Decimal spellings — narrower completed acquisition boundary

The actual five bytes of `12.50` and four bytes of `2.25` are followed from
their source-record writers through the same lexical adapter to their prefix
slots. The decimal points have their own source ownership. On each actual
point, the code freshly reads20C1, compares2Eh and changes lexical class from2
to3 through MVI M,03H. This is a real syntax-dependent branch, not an integral
conversion applied to a decimal spelling.

`literal_acquisition` records both chains in `declaration-provenance.json`.
It does **not** connect fresh phase-one spellings to retained numeric construction,
decode decimal payload bytes, or establish the intrinsic attribute record and
literal-to-destination conversion. Interning/reuse and phase-two acquisition
must be checked before making that claim, as Pass109 required for its integer.

## Documentary rules, kept separate

The verified [Digital Research PL/I-80 Language Manual, second printing
December1980](https://www.bitsavers.org/pdf/digitalResearch/pl1/PL1-80_Language_Manual_Dec80.pdf)
retains PDF SHA256
`85e09fc830a3520d2e5e24d051cdf74593b393b1851ee982196555e6435b848a`.
Sections3.1.2 and7.2.1 were inspected directly. `language-evidence.json` records
pages and paraphrases, independently of execution-field interpretation.

**DOCUMENTED / documentary deduction:** DECIMAL(p,q) has p total and q fractional
digits. Constant form gives12.50 attributes(4,2), and2.25 attributes(3,2).
With declared operands(7,2), multiplication gives precision
`min(15,7+7+1)=15`, scale`2+2=4`. The mathematical product is28.1250. Positive
assignment to(7,2) truncates fractional excess, giving the documentary expectation
**28.12**, not rounding28.13. Integer-capacity overflow is a separate rule.
The manual describes packed BCD, but this pass does not verify the actual
payload layout or runtime implementation. Contemporary documentation is not
blanket proof of every v1.4 runtime behavior.

**OBSERVED:** source ownership, explicit qualifier/parameter processing, named
record publication/retention/reads, decimal-point classification, the selected
channel arithmetic and copied CPU comparisons.

**DEDUCED narrowly:** the chosen record fields retain this declaration's
precision7 and nonzero scale2, supported by parameter ownership and different
consumer laws. No universal tag/bit/sign/scale representation is established.

**UNPROVED:** complete typed literal construction; source-correlated multiplication
result ownership; z destination scale-reduction mechanism; actual stored/runtime
numeric result, exceptional conversions and general decimal encoding.

## CPU replay and validation

| Original window | Instructions | Reads | Ordered writes | Original return |
|---|---:|---:|---:|---|
| x completion104662..104968 | 306 | 108 | 54 | 362Dh |
| y completion116997..117303 | 306 | 108 | 54 | 362Dh |
| z completion129332..129638 | 306 | 108 | 54 | 362Dh |
| selected context380198..380532 | 334 | 141 | 73 | 54B9h |

Every replay starts from copied complete original CPU/RAM. The checker verifies
the original CALL, its word's last writer and final RET consumer, every register
and flag, PC/SP, full64KiB RAM and complete ordered reads/writes, including
same-valued writes and stack residue. The windows perform no BDOS services.
**Both executions use the same Intel8080 engine.** This is an independent window
replay and provenance/reference check, not a second CPU implementation.

```
python3 tools/annotated-assembly/run_host_compiler_regressions.py \
  --categories pass115,diff-check,validation-runner-tests \
  --images /home/john/pli/cpm/pli80/DISK1 \
  --output _build/host-compiler-pass-115/validation --workers 4
```

`validation.json` preserves the measured final receipt: **5/5 categories passed,
22 Python test executions, 4.241s wall, 4.435s summed category time, 4 workers**.
Build/project are mandatory. Earlier executable contracts are unchanged, so no
archived campaign was added. Fresh image hashes and the unchanged annotation
tree preserve all **94,720 historical bytes**. FIXEDDEC's REL is freshly checked;
all previous fixtures, goldens, Pass109–114 evidence/MIR experiments and FULL
records remain untouched. No native roots, promotions, annotation changes,
MIR decimal implementation, FULL run or linked-runtime probe. Pass74 epoch3
remains the last certified FULL.

## Exact next boundary before decimal MIR

Follow the selected phase-two `12.50` acquisition to its retained numeric record
and constructor, then to the candidate carrier publications at342455/342471/
342487 (raw3/4/2). Their ownership is not established by matching those values.
Next connect the actual multiplication result and z's destination read through
the scale-reduction operation. Only with those contracts and independently
justified overflow/conversion rules should a scaled-integer MIR representation
be chosen. No speculative rounding or decimal runtime is implemented here.

**RUNES PASS115 — DECIMAL ATTRIBUTE PROVENANCE PARTIALLY RECOVERED**
