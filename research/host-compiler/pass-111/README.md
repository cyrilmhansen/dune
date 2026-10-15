# Pass111 — MOD result attributes and equality consumption

**The selected result-type contract is established.** Source-correlated
`mod(i,15)` has a demonstrated result-attribute owner and a real subsequent
consumer in `mod(i,15) = 0`. The result uses a mapped expression carrier, not a
newly inferred symbol record. Its tag is retained from the common context;
its other attributes are recomputed and republished before equality reads them.
This establishes typing/ownership, **not runtime evaluation of MOD**.

Baseline HEAD and origin/main:
`ddab50a11d9a44fd351e32af3a40f006db0ac94a`.
Pass109/110's evidence and partial historical conclusions remain unchanged.
The old Pass110 capture was verified against its published SHA256 before reuse:
`ca4de96a24f4b6602a0d2569a774d89b4d231d5137f483f9b1bc354df48f81e6`.

## Actual operation ownership

The source is `examples/pli80/FIZZBUZ.PLI`. Normalized CP/M source offsets are
used below; Pass109 already distinguishes the selected `15` from the loop bound.
The selected MOD application is normalized [85,94), repository [82,91), line4.
Its literal is normalized [91,93), line4 columns18–19. Its equality sign and
right-hand zero are at normalized95 and97.

The existing resident source-copy/normalization law is checked for the actual
`m`, `o`, `d` bytes. Their acquired prefix publications383773/383857/383941
come from source85/86/87. Actual reverse name comparisons at385851/385877/385903
consume those prefix bytes against the retained name at FBD9/FBDA/FBDB. The
lookup result is recordFBCF. This identifies MOD through source ownership and
successful lookup, independently of the subsequent numeric dispatch selector.

The resolved pointer passes through the saved field at A66C/A66D and A75A/A75B,
then is freshly restored to A863/A864. PLI1+5F34 reads **that record's** byte+5,
20 decimal. The real hardware CALL at+5F3A enters+506E at step387503. Its byte-local
frame preserves the selector; +50AF/+50B1 read the two table bytes at78C7/78C8,
producing75BB. +50B3 executes the actual PCHL into+53BB. That arm calls+500F,
which prepares both arguments through+4F54/+3304. This ancestry is checked;
neither a matching token nor a suggestive routine label identifies the operation.

The selected +500F path reads the freshly retained common tag, chooses the
classifier result2, adds it to its saved CFh marker and calls+2511 with D1h.
This is an observed, source-correlated compiler emission path. It is not proof
of a runtime MOD calculation or a general INT opcode vocabulary.

The dispatcher returns through+570D at395969 to its original hardware word813D,
resuming+5F3D. Its private byte locals and original continuation are kept distinct
from the internal PCHL arm; no synthetic CALL convention is introduced.

## Operand preparation versus result attributes

The existing proofs supply the premises:

- **Pass109:** selected source spelling and positional value15; constructor
  +6708 E02/N=8; A948/A949=0F00; subsequent numeric and attribute publications.
- **Pass110:** the actual declaration `i fixed`, resolved record ownership,
  retained declaration attributes, and +30C1's common conversion context.

New capture checkpoints are bound to Pass110's complete entry/exit RAM digests
at+30C1. Pass109's selected constructor entry is likewise bound. These earlier
source/value proofs are reused rather than rederived in Pass111's checker.

The mapped operand readers populate left attributes A629/A62C/A62F with
15/0F/00 and right attributes A62A/A62D/A630 initially with02/02/00. After the
existing numeric construction, +2998/+29A3/+29AE freshly read the common channels
A628/A62B/A62E and copy them into the right operand channels. Each copy's last
writer belongs to the proved common-context window. The converted literal
therefore has15/0F/00; it is not assigned that tuple merely because its value is15.

The checker also records the historical operand word channels before conversion.
For the selected15 case both words are FBA8. They are compiler carrier state,
**not evidence that `i` or MOD has runtime value15**. Their general representation
is not decoded here. Source identifier ownership and numeric literal ownership
come from the independent earlier chains. No typed contract uses these opaque
words as runtime arithmetic inputs.

## Result ownership: retained, recomputed, then published

The earliest demonstrated result-associated metadata publications on this path
occur inside+500F's+2511/+240A sequence after the selected operation marker.
They use logical expression position4, freshly mapped through AA23 to carrier2.
They write AC75/AD0A/AD9F at395414/395437/395460. This does not claim those RAM
addresses had never been written for an earlier owner.

The MOD arm then calls **+4F2A** at395769. Its actual selected instruction law is:

```
require (current_tag & 14h) == 14h
z = max(left_zero_channel, converted_right_zero_channel)
m = (converted_right_middle - converted_right_zero_channel + z) modulo 256
retain current_tag
publish the current expression attributes through +4C4C -> +240A
```

For this state, `z=0`, `m=15`. +240A applies its existing selected cap against
A642=15, preserving15 with another same-valued write. This equation is checked
independently against actual instruction operands. It is a local byte law, not a
universal scale/precision formula or an implementation of MOD arithmetic.

The tag's last writer remains+3141 inside the common-context calculation.
The middle channel is rewritten at+4F4D and capped at+2437; the zero channel is
rewritten at+4F3F. The final publishers freshly read those owners, save and
reread their canonical scratch, and consult the current mapping again:

| Attribute | Final write step | Physical address | Value | Equality read step |
|---|---:|---|---|---:|
| tag | 395898 | AC75 | 15h | 400585 |
| middle | 395921 | AD0A | 0Fh | 400601 |
| zero channel | 395944 | AD9F | 00h | 400617 |

Both first and final publications are retained, including same-valued and
zero writes. Every equality read is tied to its **final** publication with no
intervening writer. Thus the proof distinguishes a computed result from an
identical-looking tuple, and from the converted literal's separate carrier.

The established result-attribute owner is the **current expression's mapped
carrier**. No separate result-symbol allocation is needed to establish this
path. The proof makes no global claim that other result records cannot exist.

## Actual equality consumer

The source byte95 passes through its real line-buffer/normalization/prefix chain
and becomes prefix `=` at395615. +78C7 publishes it as token20C3 at395737.
The relation-table search reads `>`, `<`, then `=` and succeeds on measured
index2. +6564 saves that derived index in the enclosing private operator byte;
the later+659D guard consumes the same saved byte, despite intervening parsing
of the right operand. +65A7 hardware-CALLs+345E at400417.

The right-hand zero is independently acquired from source97 (and172/243 in
the other cases). The first occurrence copies its acquired prefix into a new
spelling record at396942; the later occurrences compare their new prefixes to
that retained record without an intervening writer. Fresh lexical attribute
reads, canonical publications and right-operand reloads bind its02/01/00 tuple
to this consumer. A pre-existing zero record is not assumed.

+345E calls+31FB to acquire both operand attribute groups. The left group is
position4. Its +7AA0/+7AB6/+7ACC mapping reads still consume AA23's actual
carrier2 writer; +7AA7/+7ABD/+7AD3 read the result publications listed above.
The values are copied to A629/A62C/A62F and subsequently read by equality's
common-type preparation at+3481 -> +30C1. That preparation produces its own
15/0F/00 conversion context. It does not read a presumed unchanged global tuple:
lexical acquisition of the right-hand zero has already reused global channels.

The proof stops at equality operand conversion and its hardware return. It does
not claim the complete IF, branch generation, serialized INT/REL interpretation,
or an executable equality/MOD runtime implementation.

## Three natural discriminants

| MOD spelling | MOD source span | `=` source | Common context | Result carrier | Final tag/middle/zero writes | Consumer reads |
|---|---|---:|---|---:|---|---|
| `mod(i,15)` | [85,94) | 95 | 15/0F/00 | 2 | 395898/395921/395944 | 400585/400601/400617 |
| `mod(i,3)` | [161,169) | 170 | 15/0F/00 | 1 | 465638/465661/465684 | 470231/470247/470263 |
| `mod(i,5)` | [232,240) | 241 | 15/0F/00 | 0 | 532436/532459/532482 | 537029/537045/537061 |

Each name lookup and equality sign has its own source provenance. The differing
literal widths/values and different physical carriers corroborate common
result-type behavior. Selection never uses a source name, ordinal, expected
output or RAM digest as a compiler algorithm. Step coordinates locate proof
witnesses only. No synthetic-only observation is introduced.

## Validation evidence and semantic contract

For each natural case, the original full entry state is replayed on copied RAM:

| Interval | Instructions | Data reads | Ordered writes | Original hardware continuation |
|---|---:|---:|---:|---|
| +4F2A result finalizer | 181 | 89 | 43 | 75C3 |
| +345E equality operand preparation | 1804 | 719 | 371 | 87AA |

All **six** comparisons check registers/flags, PC/SP, full64KiB RAM, ordered
reads and writes, nested hardware frames and surviving residue. RET consumes the
original entry word once, SP advances by2. No external service is invoked in
these bounded replay intervals. The original and replay executions use the
**same CPU engine**; independent copy/arithmetic/ownership checks complement
that replay, not a second CPU-engine verification.

The [Digital Research PL/I-80 Language Manual, second printing December1980](https://www.bitsavers.org/pdf/digitalResearch/pl1/PL1-80_Language_Manual_Dec80.pdf)
was consulted directly, including3.1.1/3.1.2,7.2.1,12.1.7 and7.1.4 for equality.
Its verified PDF digest is recorded in `language-evidence.json`. Edition-wide
identity to every compiler v1.4 behavior is not assumed.

- **DOCUMENTED:** FIXED alone declares signed binary integer precision15;
  decimal integers take binary typing in a requiring context; arithmetic
  conversions select the common type; MOD returns that common arithmetic type;
  relational operands are converted to a common type before comparison.
- **OBSERVED:** source lookup/dispatch, converted operand metadata, MOD-specific
  result finalization/publication, mapping ownership, equality selection and
  reads. The value15 construction and declaration premises remain Pass109/110's.
- **DEDUCED, selected scope:** `i` and the converted15 operand have effective
  fixed-binary precision15; MOD's result has that type/precision, and equality
  consumes its attributes to choose its operand-conversion context.
- **UNPROVED:** universal tag/bit vocabulary, general zero-channel encoding,
  arbitrary precision/type combinations, complete compiler word-channel meaning,
  runtime arithmetic/exceptional behavior and final backend interpretation.

`semantic-contract.json` is a small descriptive typing contract, independent of
RAM addresses and CP/M mechanisms. It does not create an IR, AST, parser or
runtime API. It explicitly leaves the runtime result value unevaluated. A zero
metadata byte is not assigned a universal scale meaning.

## Incremental validation and preservation

```
python3 tools/annotated-assembly/run_host_compiler_regressions.py \
  --categories pass111,pass110,pass109,diff-check,validation-runner-tests \
  --images /home/john/pli/cpm/pli80/DISK1 \
  --output _build/host-compiler-pass-111/validation --workers 4
```

`validation.json` preserves the measured receipt: **7/7 categories,
34 Python test executions, 9.051s wall and
18.636s summed category time, 4 workers**. The three categories write to
separate pass-specific capture directories. The existing observer gains only an
opt-in `--mod-result` checkpoint/replay option; Pass109 and Pass110's default
journals retain their published digests. No tracing framework or canonical
operation changes are introduced.

FIZZBUZ REL remains
`68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`.
Tests verify all four original image hashes and the baseline annotation tree;
a separate diff check confirms this pass leaves annotations unchanged, preserving
94,720 reconstruction bytes without constraining future annotation work. Earlier golden evidence is untouched;
no fresh five-source campaign is claimed. No annotations, knowledge promotions,
native roots, installed runtime changes, MIR changes or FULL runs. Pass74 epoch3
remains the last certified FULL. Earlier failure receipts remain untouched.

Compact cases, ordered last-writer edges, RAM digests and preservation identities
are indexed by `implementation-packet.json`; large journals remain ignored under
`_build/host-compiler-pass-111`. The unsuccessful isolated FULL checkout is not
accessed. Proof instruction counts are not native execution savings.

## Smallest prerequisite before arithmetic MIR lowering

The selected **typing** premise is now available. Next establish an executable
numeric law for the selected runtime integer MOD path, initially nonnegative
values and positive divisor15, with exact historical conversion/width behavior.
Do not assume MIR's signed remainder matches the manual's floor-based MOD for
negative values or the documented zero-divisor branch. Those are separate
proof obligations. No MOD arithmetic or new MIR function is implemented here.
