# Pass 32 — accumulated-natural +6223 archaeology

Baseline: `0f7da6067d89f878b910ba71c4b272f4421e6b1d`.
This is an archaeology pass, with no native replacement, fixture or new
compiler capture. Compiler regressions still run during validation. MINIMAL, FIZZBUZ and PICTURE remain independent natural observations.
Their existing corrected event captures are identified, hashed and validated in
[natural-roots.json](natural-roots.json). Historical bytes remain authoritative.

## Corrected ordinary windows and routes

Every selected window begins with an actual `PLI1.OVL+6273 CALL +6223`, returning ordinarily at
`+624C` through its unchanged original CALL word. Procedure ownership is derived
from corrected CALL/return ancestry, never from basic blocks.

| Source | Calls | B: +5929 / +2511 | A: +01E8 / +256C | A: early |
|---|---:|---:|---:|---:|
| MINIMAL | 1 | 1 | 0 | 0 |
| FIZZBUZ | 18 | 11 | 4 | 3 |
| PICTURE | 2 | 1 | 1 | 0 |
| Total | 21 | 13 | 5 | 3 |

FIZZBUZ has **six indirect re-entries** within three other +6223 windows,
through their +620C/+61A4/+60E5 descendants. Each outer early-route window
contains an A-processing and a B-processing window. There are12 outermost
FIZZBUZ windows, one MINIMAL and two PICTURE, with maximum +6223 window depth2.
These are corrected invocation envelopes, not inferred direct recursion or21
independent native root transitions. Per-invocation parent/envelope identities
are retained in `natural-roots.json`.

All 42 bytes in `[6223,624D)` were dynamically executed and explained. Bounds
are stable and local control flow complete; the contract remains partial because
child behavior remains delegated. There is no local private frame or non-stack
publication. Child CALLs reuse the word immediately below the root entry SP;
child saves and frames can extend farther below it.

**OBSERVED:** +020E returns `00` thirteen times and `FF` eight times. Its two
fresh `20C3` reads, complete accumulated contract, returned mask, flags and the
subsequent RAR are separate channels. RAR forms
`A=(incoming CY<<7)|(old A>>1)` and sets CY to old A.bit0. `+6227 JNC` takes
route B when that bit is clear. It does not test an invented Boolean return flag.
The witnessed incoming CY is zero, yielding post-RAR A=00 or7F. The two
selector reads agree within each invocation: MINIMAL observes05, FIZZBUZ
observes02 eight times,05 three times and01 seven times, and PICTURE observes
02 once and01 once. This is observed per-call continuity, not global immutability.

Route B calls +5929, **then freshly** calls +239A, executes `ADI13 / MOV C,A`,
and calls bounded +2511. Route A first calls +620C and independently rotates its
returned byte at +622D. `+622E JNC` takes +623D and the common RET when its bit0
is clear. Otherwise the ordered children are +01E8, **fresh** +239A and +256C.
Both processing routes delegate their final machine state to the last child.
The early route returns the second RAR state. Complete returned register/flag
records remain correlated per root.

**OBSERVED:** both processing routes obtain A=04 from their independent +239A
calls, then A/C=17H after ADI13. Flags from the addition replace the child's
flags. +5929 separately calls +239A and increments its result04 to05 before
its own +2511 call. These equal returned values do not establish shared
provenance or license replacing +239A with a constant.

## Immediate dependency scope

Counts below cover every corrected natural invocation of each selected entry,
including calls outside +6223. Wider observations are not attributed to the
+6223 roots.

| Entry | MINIMAL | FIZZBUZ | PICTURE | Represented / extent bytes | Completeness: bounds / CFG / contract |
|---|---:|---:|---:|---:|---|
| +620C | 0 | 7 | 1 | 23 / 23 | stable / complete / partial |
| +239A | 3 | 49 | 10 | 6 / 6 | stable / complete / partial |
| +256C | 0 | 7 | 3 | 61 / 61 | stable / complete / partial |
| +5929 | 1 | 11 | 1 | 131 / 285 | provisional / partial / partial |
| +01E8 | 0 | 7 | 2 | 15 / 38 | provisional / partial / partial |
| +61A4 | 0 | 8 | 2 | 9 / 9 | stable / complete / partial |

**+620C:** call +61A4; unconditionally cache returned A at A945; CPI00.
Zero returns literal01 with comparison flags. Nonzero freshly reloads A945,
performs wrapping SUI04, then SUI01, then SBB A. Only the **second** borrow
selects FF/00. DEDUCED: that nonzero local arithmetic yields FF for input04,
00 otherwise; input04 is STATIC / UNOBSERVED. Natural child outputs are zero
five times and one three times, producing results01 and00 respectively. The
caller RAR takes processing for01 and early return for00. BC/DE/HL remain the
child's returned values. NZPA/CY are from CPI00 or the final SBB, respectively.

**+61A4:** `[61A4,61AD)` unconditionally writes zero to A941 and delegates
+60E5, then returns ordinarily with its machine state. Eight of ten natural
calls are the +620C children; two are from +61B6. A=00/01 observations do not
explain +60E5's acquisition, mutations, branch decisions or termination. That
substantial child is intentionally opaque here.

**+01E8:** publish word0002 at A5B0, low byte then high byte; freshly read
A628; CPI70/JZ. All nine calls observe15H or02 and return at +01F6 with
HL=0002, BC/DE preserved and CPI70 flags. The five +6223 children all observe
15H. Equality branches to the still-RAW +01F7 arm, so the enclosing extent and
CFG remain provisional/partial; no claim that +01F6 ends the whole procedure.

**+239A:** set C=0 and freshly delegate +2355; ordinary RET preserves the
returned machine state. The +6223 route B and +5929 children select A628[0]=02/05; +6223 route A
selects15H. All return04 through the delegated +230E/+22CB scope, with different returned CY
for15H versus02/05. Equal A does not establish equal returned flags. Wider independent
calls return04/05/06. The incidental literal31 ->06 observation belongs to a
caller outside the selected parent; +2355 is not reopened or promoted here.
Its partial archaeological contract is not overwritten.

**+256C:** preserve MOV B,C/PUSH B/INX SP, leaving the historical input byte
at entry_SP-1 and duplicated-C residue below it. Freshly read the frame byte
for +7B64 and CPI06. Non6 calls bounded +2511 with another fresh frame read.
Attr6 calls +8048, then +7AF0 with fresh AE32/AE33 position and A5B0/A5B1 word,
then +23D2 with explicit C=0, then +7EC0 with another fresh frame read. Discard
one private byte and RET with the final child's machine state. All seven
FIZZBUZ calls and two PICTURE calls observe attr4; one PICTURE call from
+1C8B observes attr6. **That attr6 case is outside +6223.** Both local routes
are represented. Existing bounded native children make this a clean local
composition, but do not establish arbitrary child states.

**+5929:** all thirteen calls invoke complete +57B7 at BC=7923H and observe
its found result01; RAR/JNC enters work. Fresh paired20C3/20C4 supplies low C
to opaque +46A7. Fresh word[A863] is copied to A63B/A63C, then A635/A636;
A631 is cleared, fresh20C3 is copied to A628, fresh20C5 to A62B, and A62E
cleared. Separate wrapping equality masks for3 and4 pass through PUSH PSW /
POP B / ORA C / RAR. All observed selectors02/05 skip those and the7/8/9
alternatives. A fresh pointer+4 receives A62B; another fresh pointer+5 receives
A62E. The final children are +239A, +2511 after INR A, then partial +784E.
No source-language meaning is inferred from the byte adjustments or pointer
fields. +46A7's returned A varies00/FF and is not the later freshly read selector.

## Stack, scope and unresolved alternatives

[natural-roots.json](natural-roots.json) and
[child-correlations.json](child-correlations.json) retain entry/return identity,
ordered direct children, branch producers, scratch/publication chronology and
per-invocation final stack writers. Ordered child CALL and CPU memory-write
projections have digests and compact address-range inventories rather than
copied giant trace windows. These projections exclude host-effect events;
opaque acquisition children still require their own host-effect contracts. No
full-memory snapshot or external-state identity proof is claimed here. Stack writer
records carry exact address, coordinate, step and value; equal values never
substitute for writer ancestry. This is historical evidence, not a prepared
native compatibility implementation.

Required later scope includes disjoint executable code and active return/save
words, and the selected scratch/read/publication nonaliasing conditions of the
existing child contracts. Intentional shared-memory rereads and scratch reuse
must retain their order. Opaque child aliases, pointer/table producers, global
capacities, ownership and arbitrary termination are **not** established by this
pass. No full native-ready alias theorem is claimed.

STATIC / UNOBSERVED and still RAW:

- +5929 scan miss at +5A42;
- selector3/4 handling +5971..+59DA;
- selector7,8,9 local publication alternatives;
- +01E8 equality70 arm beginning +01F7.

Seven new ProcedureHypotheses and **287 RAW -> UNDERSTOOD bytes** record only
executed, explained local operations. All seven global contracts remain partial.
Existing native implementations, historical contracts and historical bytes are
unchanged. No CPU, Runner, CP/M or packet changes were required. The frozen
Pass16 audit now explicitly excludes these later hypotheses using `before.json`.

The live MINIMAL annotation metric was refreshed: UNDERSTOOD occurrences
216,638 ->216,714 and historical-image dynamic UNDERSTOOD49.236133% ->49.253406%.
This incidental reclassification is documented in
[progress-change.json](progress-change.json); frozen earlier pass reports remain
unchanged.

## Leverage and Pass33 decision

Fresh corrected interval measurement reproduces:

| Source | +6223 windows | Historical instructions | Residual after current native descendants |
|---|---:|---:|---:|
| MINIMAL | 1 | 1,987 | 1,211 |
| FIZZBUZ | 18 | 67,185 | 46,510 |
| PICTURE | 2 | 4,447 | 2,851 |
| Total | 21 | 73,619 | 50,572 |

The method unions corrected native-descendant body intervals, preserving each
parent's actual child CALL instruction. It is a residual leverage measurement,
not a native +6223 performance result. Summing selected parent windows counts
indirectly nested +6223 work again; it is not a whole-run instruction union. +5929 contributes16,741 residual
instructions across thirteen windows; +256C contributes only162 across ten.
+620C alone contains42,242 historical instructions inside these roots; almost
all lie beneath +61A4/+60E5.

**Decision C:** native +6223 is not yet justified. The specific unresolved discriminator is
the +60E5 state transition that produces returned0 versus1 at the +61A4/A941=0
scope, including its writes and acquisition effects. Both outcomes occur in
existing natural evidence; they are not yet a reconstructible contract. There
are separate remaining +5929
(+46A7/+784E) and +239A dependency blockers. No new discriminator fixture is
required: retained natural windows already expose the unknown computation.
Recommend **Pass33 focused accumulated-natural +60E5 archaeology** first.
+256C is inexpensive bounded composition but would remove only162 residual
instructions and would not resolve either major +6223 route.

## Validation

[validation.json](validation.json) records **53 passing categories,297 Python
tests and34 Dune test stanzas**, using two aggregate shell commands, and exact
reconstruction. Focused tests rederive every selected window, validate
bytes/canonical identities, child order, RAR/CPI/ADI flags and polarity, fresh
value/publication channels, one-byte frame and original CALL return ancestry;
corrupted rotate/addition evidence is rejected. Existing project/native, CP/M,
archaeology,109 MINIMAL and27 packet/continuation regressions are included.
All four historical images reconstruct **94,720 bytes EXACTLY**.
