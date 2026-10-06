# Pass 37 — compact evidence and composed small gates

Baseline: `98a01655e0b7cad44f2909c96969cc051eadd174`. Archaeology only. The substantial +506E/+500F subtree and +784E were not investigated or migrated.

## Evidence interface

`work-packet.json` is the model-facing interface: one decoded coordinate union, interned routes/write layouts/child sequences, interned stack-writer patterns, and entry/return/write/stack value deltas. Complete child contracts are ID/hash references; partial-child I/O is retained explicitly. It contains 69 target roots (seven +4601 and 62 +239A), five root classes, 16 family route classes and 13 stack patterns. The checker independently validates 428 natural windows, including useful independent classifier-family calls. Detailed helper values and chronological witnesses remain queryable in ignored `_build/host-compiler-pass-37/full-proof.json`.

The final packet is 24,249 bytes, below the 32 KiB target. Full/rederivable proof JSON is 12,039,483 bytes: a 496.494-fold reduction to the model view. Root ABI/write delta encoding is lossless; helper proof detail is deliberately outside the view. This is a task work packet, not a change to Procedure Evidence Packet V0.2. `efficiency.json` retains exact sizes, hashes, timing and elimination counts; 412 repeated family route structures, 64 root route structures and 415 stack-pattern repetitions are interned away.

## +4601 cleanup

Natural calls: MINIMAL 0, FIZZBUZ 5, PICTURE 2; all use one represented 44-byte route, `[4601,462D)`. Save input BC high then low at A90A/A909; reload that word and publish A863 low/high. Reuse complete +4227 to read fresh field[p+1]&1F; cache its actual result at A90B. FIZZBUZ reads 1 and PICTURE 6, so neither is a constant law.

Fresh working pointer plus 10 modulo 65536 becomes A909/A90A. Reuse complete +428E to follow the separately read successor word[p+8]. Fresh A909 gives the final child's BC payload pointer. Read both A90B and neighboring A90C, exchange that pair into DE, then call existing bounded +4584. A90C is genuinely read/passed, although this child's count input uses low E.

All seven successors are zero and at/below the fresh top word[1C36]; Pass34's already-established floor-return contract applies. It returns resident +1A33's state: BC=successor, DE=1C37, HL=u16(top-successor), A=high(HL), CY=word borrow and NZPA/AC from the high SBB, not whole-word zero. Natural HL is nonzero. There is no local loop; the three children run once and the selected floor path returns directly. Other +4584 payload/retry routes are still delegated and unsupported by this bounded replacement scope.

Final stack words are derived from exact CALL writers: S-2/S-1=682CH from +4629; S-4/S-3=6795H from +4584's +4592 CALL. Original outer continuation and SP+2 are preserved. Bounds are stable, local control flow complete, contract partial because the child has unsupported alternatives.

## Classifier composition

Existing Pass9/10/32 laws are substituted and tested against accumulated natural calls; no constant-result substitution is used.

| Entry | MINIMAL | FIZZBUZ | PICTURE |
|---|---:|---:|---:|
| +239A | 3 | 49 | 10 |
| +2355 | 5 | 64 | 11 |
| +21AD | 6 | 88 | 15 |
| +230E | 4 | 60 | 8 |
| +213C | 2 | 26 | 2 |
| +22CB | 2 | 58 | 8 |

+239A sets C=0 and freshly calls +2355. +2355 saves the index, reads A628+index, and passes the selected byte to +21AD. Its RAR/JC consumes returned bit0 while preserving the independent NZPA/AC channel.

+21AD preserves the historical two expanded masks and PUSH PSW/POP B structure. It returns literal1 iff C!=30H and C<=31H, retaining ANA FF/RAR flags S1/Z0/AC1/P1/CY1; BC=FFFF, HL=A647, DE preserved. The slow domain C==30H or C>31H cannot equal +213C's literals 0B/0C/0D/02/03/04. Therefore the established false-comparison prefix completely covers every delegated byte: A=0, HL=A645, BC=(C==30H?0:FF00H)+C, DE preserved, flags CMP(C,04). A 256-byte finite algebra/domain proof and all 109 natural calls establish this complete nonaliasing contract. No new historical-binary queries are needed. Unreachable-from-this-caller equality arms remain RAW in +213C.

+2355's clear-bit route returns literal5 with the rotated child flags. Its set-bit route independently rereads the selector: 31H now dynamically reaches literal6 with matching CPI31 flags; 2AH remains RAW. Other supported selectors delegate +230E using a freshly reloaded index.

+230E retains its fresh 24/25 equality-mask checks, independently rereads for CPI28, and either returns literal1 or calls +22CB and increments A twice modulo 256. +22CB now dynamically reaches selector15H's literal2 with equality CPI15 flags. Its existing default selector02/05 route also returns2, but retains borrowed CY from CPI19. The two INR operations produce A=4 in both cases while preserving those different carry sources. Independent +213C calls also naturally reach equality02's literal1, with CPI02 flags.

Required +3DD9 caller +3FB7 correlations are intact: FIZZBUZ selector15→4/CY0 six times and selector80→5/CPI80,04 three times; PICTURE selector15→4/CY0 three times and selector31→6/CPI31,31 once. At established caller +3FBA, INR A changes these values to 5/6/7, replaces NZPA/AC and preserves child CY; fresh +3DD9 position carriers then feed mapped publication. The existing Pass35 parent regression retains the actual call/publication chronology.

All table/index/scratch reads and writes use the shared numerical addresses. Paired neighboring bytes are actually read even where addressing discards them. No table capacity, ownership, global immutability or PL/I meaning is inferred. Code/active stack/scratch/selected indexed sources must not interfere outside the declared child scopes.

## Promotions and deferred queue

53 RAW bytes become UNDERSTOOD: all 44 +4601 bytes, three +213C equality02 bytes, three +22CB equality15 bytes and three +2355 equality31 bytes. Only +21AD's contract becomes complete; other classifier contracts remain partial. RAW equality0B/0C/0D/03/04 in +213C, literal16/19 in +22CB, zero24/25 in +230E and literal2A in +2355 remain explicit.

The deferred native-ready queue contains complete +21AD, bounded +213C/+22CB/+230E/+2355/+239A, bounded floor +4601 and the demonstrated +3DD9 composition. No leaf migration is performed. +5E98 remains blocked by substantial +506E/+500F and +784E; +60E5 and +61A4/+620C inherit that blocker. Pass38 should tackle the +506E/+500F acquisition subtree, beginning with its +4F54 causal reentry obligation, rather than another isolated leaf. +784E retains its distinct resident counted-buffer/refill boundary.

## Validation

Targeted corruption checks and aggregate regressions regenerate the packet, value deltas, route counts, ABI/flags, stack writers and byte unions. Timing/category totals and the exact 94,720-byte reconstruction are recorded in `validation.json`. No CPU, Runner, CP/M or packet infrastructure changes; no semantic correction, pragmatic divergence or fidelity debt.

Final results: 59 categories passed, 362 Python tests (including 15 new Pass37, 109 MINIMAL and 27 packet/continuation tests), and 35 Dune test stanzas. Two aggregate validation commands plus one targeted 12-test rerun resolved an initial frozen Pass35 direct-contract reference mismatch. All four historical images reconstruct exactly, totaling 94,720 bytes. Aggregate validation elapsed 1093.792 seconds; initial packet generation 31.248 seconds and final compact build 0.066979 seconds. Zero new historical-oracle queries; prior binary-oracle regressions remain enabled.
