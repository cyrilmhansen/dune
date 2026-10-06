# Pass 34 — accumulated natural +5A46 pointer acquisition

Baseline: `d7353e7a38e3de8c6219b7ea59a8abf719a8ffb8`.
This is archaeology, with no native replacement, new compiler fixture, capture,
or CPU/Runner/CP/M/packet change. Historical bytes remain authoritative.

The natural operation selects an existing working pointer through a checksum
bucket and exact payload comparison, then publishes that pointer into a nested
pointer-table slot. It does not demonstrate allocation or a PL/I-level object
operation. Its operational law uses current machine state and fresh reads;
corpus names and call steps identify evidence only.

## Selected evidence and bounds

All corrected ordinary windows were independently derived from the existing
MINIMAL, FIZZBUZ and PICTURE event-witness captures. Capture paths, run identity,
index/image hashes, actual callers/RET coordinates, entry/return state and
per-case correlations are in `natural-cases.json` and `dependency-cases.json`.
The proof checks canonical image+offset against immutable image bytes, original
CALL-word ancestry, RET consumption and surviving CALL/PUSH writers.

| Operation | MINIMAL | FIZZBUZ | PICTURE | Represented / extent | Completeness: bounds / control / contract |
|---|---:|---:|---:|---:|---|
| +5A46 | 0 | 9 | 4 | 66 / 108 | provisional / partial / partial |
| +45F0 | 2 | 11 | 6 | 17 / 17 | stable / complete / partial |
| +4562 | 3 | 22 | 7 | 11 / 11 | stable / complete / complete |
| +4584 | 4 | 25 | 8 | 97 / 108 | provisional / partial / partial |

Hypothesized extents are [5A46,5AB2), [45F0,4601), [4562,456D) and
[4584,45F0). +5A46 returns at +5AB1 in all 13 cases. FIZZBUZ callers are
+0971 once and +5EBD eight times; PICTURE callers are +0971 twice and +5EBD
twice. Thus all ten +5E98 children are included, along with three independent
calls. MINIMAL supplies no +5A46 window but discriminates its dependencies.
Represented bytes are the union of own instructions, excluding child bodies.
No absent MINIMAL execution is claimed as a dynamic route.

## OBSERVED +5A46 route; DEDUCED operational law

The main consumed inputs are fresh selector20C3 reads, the20C5 width and20C6
source bytes, selected checksum bucket words, record top1C36, reference pointer
A8AB, indexA6CA and baseA6CB/A6CC. A863/A864 is a child-produced working
pointer, freshly consumed later. Caller C is not a positional argument on this
route. Scratch carriers written before use are not silently treated as inherited
semantic inputs.

Every natural root follows the same route:

1. Complete +020E independently reads selector20C3 and returns mask FF.
   +5A49 RAR produces 7F with CY=1: NZPA are retained, bit7 comes from the
   incoming CY, and outgoing CY comes from mask.bit0. +5A4A JNC is not taken.
2. +45F0 acquires the working pointer described below. Complete +4275 then
   freshly compares word[A863] against reference word[A8AB]. Its returned FF
   means pointer >= reference; its CY still denotes the subtraction borrow.
   +5A53 RAR / +5A54 JC tests the **returned mask bit**, not that earlier CY.
3. +5A7A INR publishes u8(byte[A6CA]+1). All thirteen cases wrap FF -> 00;
   exact NZPA/AC are checked independently, with CY preserved by INR.
   Freshly read that index and word[A6CB], double the index, and form the first
   slot address modulo65536.
4. Pass HL=first slot and DE=A6A8 to complete resident PLI.COM+1A2C.
   It returns HL=u16(A6A8-slot), A=high(HL), and word borrow. +5A8A JC is not
   taken in any selected case: the unsigned slot is <= A6A8. A6A8 is an exact
   comparison limit, **not evidence of an abstract table capacity**.
5. +5A8D freshly reads the paired A6CA/A6CB bytes, then discards the high byte.
   Independently reread the base at A6CB/A6CC and recompute the destination.
   PUSH that address, freshly read the working pointer at A863/A864, XCHG,
   POP the destination, and publish pointer.low then pointer.high at +5A9E
   and +5AA0. Neither the bound-check slot nor +45F0's returned HL is silently
   substituted for these fresh reads.
6. Jump through +5AAB to RET +5AB1. No private local frame or loop exists on
   this represented route. Child checksum/matching termination is a separate
   obligation; no arbitrary acquisition termination theorem is asserted.

Observed bases are A66A/A66C/A66E. Selected pointer values are FBF3 (six)
and FBCF (three) for FIZZBUZ, FBD0 (three) and FBE0 (one) for PICTURE.
Local data writes are exactly A6CA, destination.low, destination.high in order.
Hash, working-pointer and matching scratch writes remain distinct child channels.

Return A is the resident difference's high byte (00 in these cases), not a
semantic success flag. BC is retained from +4275 through +1A2C; DE is the
fresh selected pointer; HL=final slot+1 modulo65536. NZPA are retained from
+1A2C; final CY is from the fresh base+2*index DAD. All natural final flags are
S=0,Z=1,AC=1,P=1,CY=0. SP=entrySP+2, PC=the actual caller continuation.
These observations do not impose one memorized register tuple on the algorithm.

## +45F0 and immediate complete leaf

+45F0's exact straight-line sequence is:

- +4562 reads word[20C5], including neighboring first source byte20C6, puts
  that pair in DE, sets BC=20C6, and calls complete +452B. E supplies the
  count; D retains the neighboring byte but is ignored for count. +452B visits
  source[count-1] through source[0], updates its accumulator at each iteration,
  and publishes the sum modulo128 at A760. The wrapper delegates its exact ABI.
- Complete +422F independently reads A760, discards its paired neighboring high
  byte, selects word[A761+2*index], and publishes that word to A863/A864.
- +45F0 **again** reads word[20C5], puts it in DE, sets BC=20C6, and calls
  +4584. The count is not reused from the earlier checksum invocation.
  RET delegates the scanner's state, including its flags.

All nineteen +45F0 calls find a positive-length exact payload match. Counts are
1/3/7 in FIZZBUZ, 5/6/11 in PICTURE, and 7 in MINIMAL. On that bounded route,
A=0, BC=10, DE=20C6, HL=working pointer+10; flags are final CMP0,0. HL is the
payload address, not an additional pointer-publication channel.

The eleven-byte +4562 wrapper is fully established in this pass. Exact dataflow
and all 32 natural calls reject using entry E or the paired high byte as count,
ascending traversal, or an unmasked sum. The complete +452B contract is reused,
not reopened. **Zero new historical-binary oracle queries were required**:
the wrapper has no competing local interpretation after instruction/dataflow
checks. This avoids redundant exhaustive queries of an already complete child.

## +4584 bounded scan refinement

All 37 accumulated calls were correlated independently. The wrapper saves
E -> A907, B -> A906, C -> A905 in that order. Complete resident +1A33 computes
word[1C36]-word[A863]. The immediate JNC returns at +45EF when the working
pointer is <= record top. This route is now OBSERVED in five FIZZBUZ and two
PICTURE calls; MINIMAL has none. It returns the subtraction state unchanged:
A=FB in all seven, with the working pointer still physically present. It does
not return a fabricated zero pointer or Boolean result.

The other 30 calls observe pointer>top, u8(header-10)==saved count, count>0,
and every descending payload comparison equal. Each iteration publishes the
decremented A908 before independently reading source[index] and
working_pointer+10+index. Equal values do not make these addresses one channel.
The final CPI remaining,0 leaves A=0, BC=10, DE=source, HL=pointer+10 and
S=0,Z=1,AC=1,P=1,CY=0. Only A905..A908 scratch is written on these routes;
selected pointer and payload remain unchanged. The newly observed floor RET
adds one represented byte without closing the RAW retry/mismatch alternatives.

## Stack and +5E98 interaction

Every recorded CALL writer is checked from runtime PC plus immutable instruction
length, and every PUSH H from its actual input registers. Retained per-case
last writers include overwrite ancestry, rather than copying post-state residue.
For +5A46 with S=entrySP, all roots leave:

| Slot | Final word | Exact writer |
|---|---|---|
| S-2 | recomputed publication destination | +5A98 PUSH H |
| S-4 | 647E | +427B CALL resident1A33 |
| S-6 | 20C6, the final source+index0 address | +45C0 PUSH H |

PUSH writes high then low; POP reads low then high without clearing RAM. The
outer CALL word is unchanged and consumed by the exact RET. The deepest observed
stack address is S-6. +4562 itself leaves only its child continuation 676C at
S-2, without an invented frame.

For each of the ten +5E98 child calls, corrected ancestry proves the sequence
+5A46 -> +784E -> +4275. +784E receives the acquired state and does not write
A6CA, A863/A864 or the selected pointer-table slot. The subsequent +4275 returns
mask FF. This is a bounded observed preservation statement, not global
immutability or a callee-save convention. Earlier +60E5 advanced the nested base;
+5A46 fills the selected slot used by later +5E65 working-pointer reloads.

## Status, RAW scope and next boundary

Three new hypotheses (+5A46/+45F0/+4562) and the existing +4584 refinement
explain **95 RAW -> UNDERSTOOD bytes**: 66+17+11+1. +5A46 remains
provisional/partial/partial; +45F0 stable/complete/partial; +4562
stable/complete/complete; +4584 provisional/partial/partial.
No previous established contract was contradicted. The floor return closes a
previously explicit observation gap, without claiming global scanner completeness.

STATIC / UNOBSERVED and RAW remain: +5A57..+5A76 pointer-mask-clear handling,
+5AA4..+5AAA slot-over-limit handling, +5AAE..+5AB0 gate-clear child operation,
and +4584's mismatch/zero-length/advance bodies +45E1..+45E5 and
+45E9..+45EE. Complete resident +1A2C was reused unchanged.

Required nonaliasing concerns are accessed code, scratch/source carriers,
selected publications and active CALL/PUSH slots. The operational law retains
fresh reads rather than assuming all tables are immutable. Arbitrary aliases,
capacities, ownership and PL/I types are not inferred.

**Decision B: recommend Pass35 on +3DD9**, the common state-dependent gate
on both +5E98 acquisition routes. It is reached by all ten retained +60E5
acquisitions, with two independent E0/E1 calls in the field80 route. It must
explain its result from state rather than remembered 1 values. Closing only the
three selected +506E/+500F dispatch cases would leave this common gate opaque.
The field15 +4601 cleanup and partial +784E acquisition contracts remain required,
as does the field80 dispatch/reentry operation. This recommendation compares
causal coverage, not spatial proximity. +5E98 and +61A4/+620C are **not
native-ready**, and +5929 is **not** the sole major blocker to native +6223.

Validation is retained in `validation.json`: fresh natural-case proofs, prior
archaeology/native/CP/M regressions, 109 MINIMAL and 27 packet/continuation tests,
V1 and exact reconstruction, using two aggregate final commands. All **94,720
historical bytes** reconstruct exactly. No native operation, new source fixture,
pragmatic divergence or fidelity debt is introduced.
