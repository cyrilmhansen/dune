# Pass109 — source-correlated literal value chain, typing still partial

Baseline: `a7157adba19e3e3caeb608c0dcc9077b6baf0a31`.
**Partial result:** the selected source occurrence, retained digit ownership,
constructor input/output and immediate downstream publications are recovered.
A complete typed PL/I constant contract is not claimed. No new MIR operation or
compiler runtime implementation is introduced.

## Exact source and capture identity

The selected immutable Pass44 witness is FIZZBUZ acquisition entry390902,
original CALL390901, RET391183, resident +1376 called from PLI1+784E.
Fresh CPU/flag vectors match both archived entry and return exactly. Width2,
selector02, prefix31h/35h, following29h and accumulator6 remain distinct facts.

The occurrence is **`mod(i,15)`**, line4, columns18–19 of
`examples/pli80/FIZZBUZ.PLI`. Its half-open repository byte span is `[88,90)`;
after the existing CRLF/CP-M normalization it is `[91,93)`. The other occurrence
is the loop bound, normalized span `[69,71)`.

This identification does not use the spelling alone. The complete chain is:

| Stage | First digit | Second digit |
|---|---:|---:|
| Source record0 loaded at FBFE | file offset91 | file offset92 |
| Actual source-byte CPU read | step380123, FC59 | step380251, FC5A |
| Line-buffer publication | step380215, 1E9F | step380343, 1EA0 |
| Lexical line-buffer read | step388595 | step391005 |
| Acquired prefix publication | step390976, 20C6 | step391087, 20C7 |

The proof follows actual copy instructions through2098/209A/20A9/20AB and the
normalization of20C1. Each reread is tied to its last writer, including repeated
same-valued writes. Source records, their logical numbers and DMA destinations
are recorded; a last-writer check rejects a different file as the producer.
The current source line at acquisition is `        if mod(i,15) = 0 then`.
No source-location table or source-based implementation dispatch is invented.

The normalized source SHA256 is
`0afe923d4a0f994e1cb6dc77003722fac27fef824ff6f80a8e4b60c410de91a5`.
`source-value-chain.json` records the concrete intermediate writers/readers and
immutable Pass44 correlation. Fresh capture is isolated under ignored
`_build/host-compiler-pass-109/capture`; old mutable capture directories are not
used or rewritten.

## Important indirection: retained digits from the first occurrence

The MOD prefix is **not freshly copied into the constructor's digit storage**.
Its lookup compares the new prefix with a retained record at FBA8, digits at
FBB2/FBB3. At391547/391548 it loads20C7 and compares FBB3; at391573/391574 it
loads20C6 and compares FBB2. The concrete CMP results are equal. The proof checks
that the prefix reads still belong to390976/391087, before later acquisition
overwrites20C6.

The retained digits were published earlier by PLI1+44D9: second digit at365009,
first digit at365031. Their source ownership traces back independently to the
loop-bound spelling at normalized offsets69/70. There is no intervening write
to either retained digit before the selected constructor reads it. Thus the two
textual occurrences are distinguished, while reuse of their representation is
preserved. Equal bytes alone would not establish this relationship.

The original first digit uses the direct +12D9 reader/normalizer path; the later
MOD digits use the raw20C1 publication and normalization path. Both paths are
checked separately rather than assumed to share identical intermediates.

The observed FBA8 record and its +10 digit offset are this witness's ownership
facts, not a general record schema or runtime classifier. No entire intern table
or global constant-interning policy is inferred.

## Constructor: actual arguments, value and continuation

At393907, PLI1+2985 performs hardware CALL +6708. Entry393908 has SP=65402,
original continuation4B88h. +6708 POPs the continuation and four additional words,
saves actual arguments, and PUSHes the original continuation into the relocated
slot at entrySP+8. Its eventual RET resumes +2988 at394338, SP=65412. This is the
existing **N=8 stack-argument protocol**, not an ordinary balanced CALL ABI.

Fresh arguments at +6726 include digit pointerFBB2, count2, selectorE02 and
positive sign marker2Bh. The constructor first writes zero to A948/A949. Its
selected decimal loop reads the retained digits and invokes the already
understood multiply-by-ten and subtract30h helpers:

| Input read | Actual byte | Independent positional result | Little-endian publication |
|---|---:|---:|---|
|394113, FBB2|31h|0*10+1 = 1|394129: A948=01, A949=00|
|394235, FBB3|35h|1*10+5 = 15|394251: A948=0F, A949=00|

The independent calculation is a validation equation on the consumed bytes.
It is not a new compiler algorithm or a copied oracle result. The concrete
instruction law and canonical implementations were inspected; no unresolved
child is replaced by an expected output. The value field is **A948/A949**, two
bytes, little-endian integer15. A947 is a separate width/representation channel;
it must not be conflated with that payload.

An isolated CPU replay starts from the actual full entry RAM/register/flag state
and executes to the actual continuation, without a fabricated frame. Its430
instructions and71 ordered writes exactly match the full-program window; exit
registers/flags and all64KiB RAM match the actual +2988 checkpoint. The replay
uses the existing CPU engine, so it is not an independent CPU implementation.
The positional equation is independent of that execution mechanism.

## Immediate consumers and raw attributes

The caller reads the constructed word, assembles it into A863/A864, then
publishes it to A63F/A640 at394452/394454. It supplies DE=000F to canonical
+7AF0, whose +7B0F/+7B11 publish0F/00 at AB49/AB4A, steps394565/394567. These
are actual fresh reads and writes, not an association made by searching for15.

The observed current literal-slot tuple changes:

```
A62A / A62D / A630:  02 / 02 / 00  ->  15 / 0F / 00
```

The prior context slots contain15/0F/00. The mapped publications then write
AC73=15h, AD08=0Fh, AD9D=00h. These exact fields are recorded as **raw metadata**.
Their complete language-level encoding has not been independently decoded.
In particular, lexical selector02 and digit width2 are not automatically a
language type and final precision. The numeric payload's two-byte storage does
not independently establish signedness or precision either.

No semantic INT/REL record interpretation or generated MOD implementation is
claimed. The consumer proof stops at the mapped value/metadata publication.

## Primary language evidence and remaining typing gap

[Digital Research's PL/I-80 Language Manual, second printing December1980](https://www.bitsavers.org/pdf/digitalResearch/pl1/PL1-80_Language_Manual_Dec80.pdf)
provides the relevant declaration, contextual arithmetic and MOD rules.
`language-evidence.json` identifies sections3.1.1/3.1.2/7.2.1/12.1.7, printed/PDF
pages, a PDF digest and compact paraphrases. The PDF itself remains ignored.
This is contemporary primary documentation, not a modern PL/I interpretation;
its title page does not establish point-release identity for every v1.4 detail.

Those rules support a fixed-binary context for `mod(i,15)` from the declared `i`.
This documentary inference is kept separate from the observed metadata tuple.
A standalone lexical constant's attributes before contextual conversion, the
complete meaning of each tag, and the source-declaration-to-context-attribute
ownership are not all closed. The zero metadata channel has not been proved
to be a scale field merely because this context is integral.

The chosen value is positive and safely follows the successful numeric guards.
Negative, decimal-point, exponent, overflow/error and other context routes remain
outside this pass. No general exceptional-behavior contract is added.

### Confidence and contract boundary

- **OBSERVED:** exact source occurrence; source/line/prefix/retained-record
  ownership; successful comparisons; constructor inputs; numeric writes; raw
  metadata transition; actual consumer publications; CALL/argument/RET chronology.
- **DEDUCED:** selected positional value15 and its little-endian payload law;
  documentary contextual-type inference, explicitly distinct from tag decoding.
- **UNPROVED:** full intrinsic/effective typed-literal representation contract,
  complete attribute encoding and declared-variable attribute provenance;
  unobserved numeric/error domains; semantic INT/REL or generated-code ownership.

No speculative typed OCaml record or MIR lowering is introduced. The bounded
result is a **source-correlated positive integer value construction**, with raw
attribute observations attached as evidence, not silently promoted to semantics.

## Validation and preservation

```
python3 tools/annotated-assembly/run_host_compiler_regressions.py \
  --categories pass109,pass108,diff-check,validation-runner-tests \
  --images /home/john/pli/cpm/pli80/DISK1 \
  --output _build/host-compiler-pass-109/validation --workers 4
```

Build/project are mandatory. The new category performs a deterministic concrete
FIZZBUZ capture, rederives the ownership chain, checks the constructor replay and
independent value equation, and verifies image identity/reconstruction. Step IDs
locate published proof witnesses; they do not select any host compiler behavior.
Existing canonical implementations were not changed, so no archived native
campaign is added. Pass108's directly relevant assessment checks remain selected.

`validation.json` preserves the measured receipt. `implementation-packet.json`
binds compact evidence and code digests. Full journals, RAM checkpoints, replay
writes and the downloaded manual remain under isolated ignored `_build`.

Fresh FIZZBUZ REL remains
`68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`.
Other goldens are preserved; no five-source rerun is claimed. All four historical
image identities and unchanged annotations retain94,720 reconstruction bytes.
No native roots, knowledge promotions, active runtime changes or MIR changes.
No FULL run; Pass74 epoch3 and all historical failure/certification evidence stay
unchanged. Proof instruction counts are not native execution savings.

## Next smallest justified step

Trace the declaration `i fixed` into its actual context-attribute producer and
follow the copied15/0F/00 tuple through the relevant type tests. Establish the
language meaning and ownership of each needed field, distinguishing lexical
classification from the converted operand. Reconcile that mapping with the
primary manual and its version scope. Only then publish a typed constant
contract suitable for an independent OCaml frontend and subsequent upstream-MIR
lowering. Broad INT decoding or serialization work would not close this gap.
