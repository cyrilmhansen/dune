# Pass 33 — accumulated-natural +60E5 archaeology

Baseline: `b49a74e79c02ebf4628b9bca61ec4f6ce45e086c`.
No native replacement, compiler-source fixture or new compiler capture was added.
MINIMAL, FIZZBUZ and PICTURE are independent natural observations. Capture/run and
historical-image identities are validated in [natural-cases.json](natural-cases.json).

## Natural contract and returned result

| Source | +60E5 calls | Field15 scan/cleanup | Field80 dispatch | Returned00 /01 |
|---|---:|---:|---:|---|
| MINIMAL | 0 | 0 | 0 | 0 /0 |
| FIZZBUZ | 8 | 5 | 3 | 5 /3 |
| PICTURE | 2 | 2 | 0 | 2 /0 |

All ten calls come from +61A9 inside +61A4 and return ordinarily at +619C.
Two +61A4 calls are outside +620C; those remain independent observations.
The enclosing hypothesis is `[60E5,61A4)`,191 bytes, with118 bytes represented.
Bounds remain **provisional**, local CFG **partial**, contract **partial**:
several special/repeat arms remain RAW. The full *natural* local graph is exact;
that is not a claim of a complete graph for arbitrary historical state.

**DEDUCED from exact instructions and OBSERVED per invocation:** DCX SP and
two PUSH H establish five-byte frame F=entry_SP-5. Fresh word[A6CB] is saved in
F2/F3; zero-extended byte[A6CA] selects a new nested base
`u16(old_base + 2*old_index + 2)`, published low/high to A6CB/A6CC. The adjacent
byte fetched by LHLD A6CA is discarded. A fresh old-index read is saved in F4;
F0 is initialized zero. Call +5E98 and save its **direct returned A** in F1.

Then independently call +5E65(C0), +41AF, +5E65(C0), +41AF and +01AF(CFC).
Fresh field comparisons observe4 on acquisition-return0 cases and0 on return1
cases; neither equals the special3/5 values. The fresh F0 rotate skips +8214.
The FC selector check mismatches in every natural call. Its returned A0 is
rotated using incoming comparison CY; NZPA remain comparison flags and outgoing
CY becomes0. This ends the local operation without repeating acquisition.

Restore the saved pointer base **before** freshly restoring its old index;
then freshly load F1 for returned A. Two POP H restore the actual frame bytes:
`HL=old_base.high + 256*old_index`, `DE=F+1`, `BC=00FC`, SP=entry_SP+2 and the
original continuation. Flags remain the final RAR flags, independently of
returned00/01. Every register/flag and original CALL-word consumer is retained.
The local returned result is not a Boolean computed by the last comparison.

All natural old indices are0. Entry baseA66A occurs on **both** returned-result
classes, so that entry field cannot replace the acquisition algorithm. The
15/80 discriminator is an **intermediate freshly acquired field**, not a
sufficient entry-state predicate or a source-language classification.

## +5E98 acquisition and mutation chronology

The partial hypothesis `[5E98,60E5)` has246 represented bytes of589. It begins
with a six-byte inherited PUSH H frame. +5E7C calls +7FF3, publishes15 to A628,
fresh A642 to A62B and zero to A62E, then calls bounded +240A(C0). +7FF3 saves
BC high/low at AE66/AE65, freshly reloads the word into DE and calls bounded
+7E5F(C0A). Their native-known publication descendants remain distinct channels.

+5E98 publishes FF to A6CA, F1=0 and F0=1. Each selected loop iteration saves
fresh20C3 to F3, calls +5A46, +784E, then complete +4275. +5A46 increments A6CA
and publishes the working pointer into the nested pointer table. Complete
+4275 independently compares the current working pointer with its reference;
RAR/JNC tests the **returned mask.bit0**, not the helper's borrow flag. On its
set-mask path, save fresh A863 in F4/F5 and obtain fresh field byte +419F into
F2. Three distinct wrapping masks for40,41,80 are ORed and rotated.

**Field15 / returned00, seven cases:** all three masks are clear. +4601 receives
the saved pointer; a second +4275 returns00 and exits that scan. Fresh +01AF
checks for28 and2E mismatch; the latter clears F0. +3DD9(C0,E1) returns1.
Fresh +5E65(0), +419F observes a value unequal42, another +5E65(0), then +5E53
returns literal0. +60BF RAR clears CY; literal A0 and three POP H preserve those
flags. The saved working pointer is restored in HL. These are two actual
pointer comparisons, not a precomputed scan schedule.

**Field80 / returned01, three cases:** +3DD9(C0,E0) returns1; a fresh +5E65 at
fresh A6CA and +419F read80 again; a separate +3DD9(C0,E1) returns1. Fresh
pointer+5 supplies E, and independently reloaded saved F3 supplies C, to +506E.
That child returns01. Its full algorithm is delegated, but the selected output's
writer and subsequent fresh read are established below. +5E98 restores saved
HL and retains +506E BC/DE/flags, then +60E5 saves and later reloads its A.

[state-transition.json](state-transition.json) preserves every call independently,
including direct child order, predicate flags, scratch/frame writes and stack
last writers. [natural-cases.json](natural-cases.json) also records tracked shared
state writes and nested pointer-slot publications. Equal values never substitute
for address/writer chronology. These are CPU witness projections, not full RAM
or CP/M shadow comparisons. Acquisition external effects remain delegated.

## Indirect +6223 reentry and result publication

Three FIZZBUZ +60E5 windows each contain two +6223 windows. The corrected ancestry
is recorded in [reentry-ancestry.json](reentry-ancestry.json):

`60E5 ->5E98 ->506E ->500F ->4F54 ->6619 ->65F9 ->654E ->64F2 ->6477
 ->640D ->6314 ->625D ->6223`

The two +4F54 CALL sites are +4F5B and +4F65. The final CALL is +6273. The outer +6223 ->+620C ->+61A4 ->+60E5 frames are separately retained. Every
edge is checked against its corrected hardware frame, exact continuation word,
stack slot and actual RET consumer. This is **indirect reentry**, not a direct
recursive CALL in +60E5 or +6223. Maximum observed +60E5 nesting is2; the nested
return0 +60E5 occurs in the first nested +6223. Maximum +6223 nesting is also2
as established in Pass32. No software return is introduced on these spines.

The selected +506E input C1 dispatches through a fresh historical jump-table
word to +53BB. Its children include +81F1, +500F and +4F2A. +500F retains its
one-byte private input CF; after +4F54 returns1, it copies fresh A630 to A62E,
calls the C0 ->partial +22CB wrapper +2308, adds that returned2 to fresh saved CF modulo256, and calls native
+2511 with D1. After +4CD4 it **publishes literal1 at A932, at +5031**.
That write follows both nested +6223 returns. +506E calls +4F2A, then freshly
reads A932 at +5706; no intervening A932 writer exists in the selected evidence.
Its returned1 is therefore a fresh published result, not a guessed constant or
its previous child's equal value. +500F itself returns A128, not published1.

Nested calls mutate pointer, selector and publication state. Their exact effects
cannot be omitted because the final literal result is known. Frame PUSH H bytes are derived from inherited entry H/L, with high-then-low
write order and exact depth. Local PUSH PSW bytes are checked using the reserved
bit1 and S/Z/AC/P/CY encoding; matching concrete values alone cannot prove them.
All surviving stack
bytes are recorded with actual last-writer coordinates and digests; this pass
makes no claim to have constructed a native compatibility planner for them.

## Active small-operation reconstruction

Nine new ProcedureHypotheses promote **525 RAW bytes to UNDERSTOOD**. None of the
unexecuted byte arms is promoted. Complete small contracts were established
against every natural case and through immutable historical-binary queries:

| Entry | Natural MINIMAL/FIZZBUZ/PICTURE | Represented /extent | Contract |
|---|---|---:|---|
| +5E65 | 0 /29 /8 | 23 /23 | complete |
| +5E48 | 0 /5 /2 | 11 /11 | complete |
| +81F1 | 0 /4 /0 | 35 /35 | complete |
| +5E53 | 0 /5 /2 | 10 /18 | partial |
| +5E7C | 0 /8 /2 | 28 /28 | partial |
| +7FF3 | 3 /21 /4 | 16 /16 | partial |
| +500F | 0 /3 /0 | 38 /38 | partial |

+5E65 saves C at A942, actually reads/discards adjacent A943, doubles the
zero-extended byte, freshly reads the pointer base and selected word, then
publishes that word low/high at A863. A/BC/NZPA remain unchanged; DE is the
selected high-byte address; CY is the final address-addition overflow.
The law `BC=2*C` is rejected: doubling occurs in HL/DE, while BC is preserved.

+5E48 calls complete +41A6, applies ANI40, wrapping SUI40, then SUI1 and SBB A.
It returns FF iff fresh field.bit6 is set; final S/Z/AC/P/CY are respectively
`bit6 /!bit6 /!bit6 /1 /bit6`. A bit7-mask candidate is falsified by40 and80.
Its +5E53 caller rotates that mask and returns literal0 for bit6 set while
retaining S1/Z0; returned0 is not a zero-flag producer. The clear-bit branch
into +57ED remains RAW / UNOBSERVED.

+81F1 is a finite byte countdown under its inherited nonaliasing scope: save C
at AE77, compare fresh counter against0, decrement counter, freshly copy AE32
into AE35, call complete +7BA2, then freshly decrement AE32 and repeat. Final
A0/HL=AE77 and CMP0,0 flags are independent of entry flags. BC/DE are entry
values for C0 or the last child result otherwise. Its actual shared-memory
recycling and CALL residues are tested; no Boolean or precomputed-schedule
substitute is used.

[candidate-falsification.json](candidate-falsification.json) records the local
laws and counterexamples. The existing concrete CPU executed **32,768 machine
queries**:16,384 pointer selection cases,8,192 field-mask cases and8,192 countdown
cases. Byte counters/fields and all32 incoming flag combinations are covered;
pointer queries include address overflow and varied discarded neighbors.
Countdown queries use a legal shared-table state, with selected destination
AB7C disjoint from position-map reads, and exercise cursor wrapping. No PL/I
source was synthesized. Test-harness step assertions detect violations of the
reviewed finite oracle graphs; they introduce no compiler termination guard.

## Remaining scope and Pass34

+60E5 field3, F0-set, field5, FC-match/repeat and acquisition-tail arms remain
STATIC / UNOBSERVED and RAW. +5E98 alternative tags, predicate outcomes and
error/status paths remain RAW. The represented +500F clear-mask transfer to
its literal-publication tail is STATIC / UNOBSERVED, even though its target
instructions are observed via fallthrough. General aliases, producers,
capacities, ownership and arbitrary termination remain unproved.

+61A4/+620C headers now reference the bounded partial +60E5 contract. Their
completeness remains partial, with no correction to their established local
algorithm. Frozen Pass16/32 audits compare their original catalog snapshots.
No Cpu, Runner, CP/M, packet or native-host implementation changed.

**Decision B:** +5E98 is the remaining immediate acquisition blocker;
+61A4/+620C are **not native-ready**. Recommend **Pass34 focused +5A46 pointer
acquisition/publication archaeology**, including its +45F0 dependency and reused
complete resident PLI.COM+1A2C. This is the earliest missing producer in both observed routes.
+3DD9 and the selected +506E/+500F acquisition route remain explicit further
obligations. +5929 is **not** the only major blocker to +6223; Route A still
needs those contracts and the existing partial +239A chain. Existing natural
states suffice for the next investigation; no new source fixture is recommended.

## Validation

[validation.json](validation.json) retains aggregate project/native, CP/M,
archaeology, MINIMAL and packet/continuation results, plus active historical
queries, exact promotion/label audits and image reconstruction. All **94,720
historical bytes reconstruct exactly**. Logs/caches remain ignored under
`_build/host-compiler-pass-33`; no raw captures or RAM snapshots are committed.
