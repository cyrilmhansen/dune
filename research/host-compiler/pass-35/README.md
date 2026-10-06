# Pass 35 — common +3DD9 state gate

Baseline: `14639b52931391c188d2cbbcf1c16844c61162f8`.
This is accumulated-natural archaeology. No native operation, compiler fixture,
CPU, Runner, CP/M or packet change was made.

The work packet was generated before interpretation, using the authoritative
historical image and corrected CALL/RET ancestry. Only the target's reachable
instructions, invocation envelopes, branch states, writes, stack writers, direct
children and their prior contracts were selected. Additional capture projections
remain ignored under `_build/host-compiler-pass-35/`. The retained packet is the
machine-state interface; `state-transition.json` contains the operational
correlations without repeating its instruction windows.

| Run | +3DD9 | Callers | E=00 | E=01 | E=02 |
|---|---:|---|---:|---:|---:|
| MINIMAL | 0 | none | 0 | 0 | 0 |
| FIZZBUZ | 12 | +0989:1, +5F01:3, +5F23:3, +607D:5 | 3 | 8 | 1 |
| PICTURE | 4 | +0989:2, +607D:2 | 0 | 2 | 2 |

Every call has C=00, index[A6CA]=00, first pointer equal to selected last pointer,
and an ordinary return at +415D. These correlated observations are the bounded
scope, not a general constant-output law. No returned 00 is observed.

## Operational reconstruction

**OBSERVED / DEDUCED:** save E at A755 before C at A754. Read the first pointer
through word[A6CB], then independently reread the base and pointer for A75A.
Read the paired A6CA/A6CB carrier, discard its high byte, and select the last
pointer from a fresh base plus twice the low index; save it at A75C. The initial
mask is expanded `(field_low3 == 2) OR (index != 0)`. Its RAR tests mask bit0,
not the preceding helper's carry. All natural masks are clear.

E selects real effects:

- **E=00:** skip the publication/preparation block.
- **E nonzero:** +3C8A consumes fresh saved C and the selected pointer at A635.
  Save its returned HL separately; restore the first working pointer and
  republish it low then high through a fresh pointer-base destination. Run
  Balance_scan on fresh AE32. Its stopping cursor is saved at A75E. +415E
  supplies a field cache. Independently read and publish control AC73, primary
  AD08 and secondary AD9D channels; independently publish primary/secondary
  source bytes into A62B/A62E. Fresh +239A A is incremented at byte width for the
  mapped-byte publication, while the fresh working pointer feeds mapped-word
  publication. Pointer equality and the zero +3C8A word select three further
  independent publications at fresh AE32.

After optional publication, initialize A75E to zero and A758 to the saved first
pointer. The loop exits when a fresh resident subtraction observes unsigned
`scan > last`. Its body restores the working pointer, checks +421F, invokes
+387F, combines that returned byte with an independently formed pointer-equality
mask, and tests +3558's bit7 mask. All natural cases skip the RAW counter-update
arm. Read the record's size byte, independently reread the working pointer,
and publish their wrapping word sum as the next scan pointer. Each natural case
has one positive-size record, and the next pointer exceeds the last pointer.
This establishes these terminating states, not arbitrary traversal termination.

**E=01 only** takes a further postcheck: the +421F field differs from 40, and
saved C equals the zero counter. E=02 skips this check. Finally publish fresh
`u8(counter - saved_C)` at A631, restore the saved first pointer, and form
`expand(field_low3 == 6) AND expand(A631 != 0)`. All natural final masks are zero,
so +415B loads literal A=01. It does **not** recompute flags.

Natural final state: A=01, BC=0000, DE=A75D, HL=first_pointer+3,
S=0, Z=1, AC=0, P=1, CY=0; SP=entry_SP+2 and PC=the actual caller continuation.
BC comes from the mask POP/MOV sequence, DE from the last resident subtraction,
and HL from the restored-pointer +41AF call. There is no local allocated frame.

The gate therefore does not explain +5E98's two routes by different returned
bits: both field15 and field80 parent routes receive 01. E changes the gate's
side effects; the parent's separate fresh field tests select cleanup/dispatch.

## Immediate dependencies and stack

| Operation | MINIMAL/FIZZBUZ/PICTURE | Established scope |
|---|---|---|
| +3558 | 0 / 21 / 8 | Complete fresh field bit7 mask |
| +387F | 0 / 21 / 8 | pointer<=bound, fresh field!=70; literal 00 retains field CMP flags |
| +415E | 0 / 9 / 4 | saved C==fresh A6E2; field cache then A628 publication |
| +3C8A | 0 / 9 / 4 | C=00 six-byte frame, substantial +3A76 delegation, zero word cleanup |

The small +3558 leaf is closed in this pass. Its exact represented sequence is
+41A6, ANI80, SUI80, SUI01, self-SBB. It returns FF for field bit7 set, otherwise
00. BC=3, HL=pointer+3, DE preserved. Final flags are respectively
S1/Z0/AC0/P1/CY1 and S0/Z1/AC1/P1/CY0. All 29 natural fields have bit7 clear;
bit7-set is a **DEDUCED / STATIC / UNOBSERVED** result of the same complete graph.
A 256-field finite arithmetic check suffices; **zero historical-binary queries**
were needed. No unexecuted bytes were promoted.

+3C8A reserves six bytes, including inherited register bytes and an initially
unwritten byte. Its zero-input route writes AE32 into frame+1, zeros frame+4/+5,
and skips the RAW positive-count body. Three POP D instructions discard the
frame, return HL=DE=00, and retain +3A76's BC (observed 0000 and FFFF). Its
returned zero word is not a contract for +3A76's mutations.

CALL words and PUSH high/low writes, including PSW's fixed bit1, are checked
against the actual instruction/register state. Stack records preserve final
writers and overwrite chronology hashes. +4148 is the final root-level writer
at S-2/S-1: PSW=56 followed by A=00 in address order. The deeper frame residue
of delegated +3A76 remains explicitly delegated; this is not a completed native
compatibility planner. +3558's only body residue is its CALL continuation 575B.
Original caller words remain intact. No guest stack bytes are copied into a
native transition.

## Status and next boundary

596 bytes move RAW -> UNDERSTOOD: +3DD9 460, +3C8A 63, +415E 23, +387F 39,
+3558 11. Five hypotheses are added. +3558 is stable/complete/complete; the four
bounded enclosing operations remain provisional/partial/partial. +3DD9's
hypothesized envelope is [3DD9,415E), 901 bytes; its 441 unexplained bytes remain
RAW. +387F's [387F,38A9) is explicitly an observed-prefix envelope; its field70
branch escapes into an unrepresented continuation, so the full extent is not
claimed. Other RAW alternatives are enumerated in the catalog and tests.

No capacity, ownership, global immutability or arbitrary alias safety is
inferred. The bounded scope requires noninterference of code, active stack,
scratch, pointer carriers and selected data/publication cells where overlapping
writes would alter subsequent reads.

+3DD9 is an algorithmic publication/traversal unit, not a predicate leaf, and is
not native-ready. +5E98 and +61A4/+620C remain blocked. **Recommend Pass36 on
+3A76**, required by every nonzero-E gate: 13 natural windows contain 4,040
historical instruction occurrences (292..371 each). Close its immediate small
mechanical leaves together where possible. The remaining +4601 cleanup,
+506E/+500F dispatch/reentry and partial +784E acquisition obligations remain
explicit. They have not all been shown small enough for one combined migration.

Validation category totals and independent byte/status audits are retained in
`validation.json`; verbose logs stay ignored. No historical contract correction,
pragmatic divergence or fidelity debt was introduced.
