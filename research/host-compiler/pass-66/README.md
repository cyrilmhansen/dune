# Pass66 — saved generation composition

Published baseline verified: `9ce85f006bea3969a23decf975497cd8a20afa04`. Pass62 remains the last certified FULL epoch. No FULL trigger fired; historical-full was not executed. CPU8080, CP/M, Runner execution semantics and shared journal/capture interpretation are unchanged. Pass67 is the planned next ordinary FULL-certification epoch.

## Bounds and natural topology

**PLI2.OVL+8072 [8072,80B2), 64 bytes**; early RET8094 and final RET80B1 are owned by this local CFG. No overlapping natural entry was found. Following80B2 is separate and not promoted. [Exact decode/CFG](cfg.json), [inventory](inventory-summary.json), and [per-root paths](natural-paths.json) preserve evidence.

Primary logical/external roots: **MINIMAL3, FIZZBUZ11, PICTURE4**. All18 natural roots use fallback. Optional selector4 preparation occurs0/1/1; the other16 bypass7A17. Callers are2943/6ED7/6EE5; FIZZBUZ additionally3D8E/38A8 and PICTURE3D8E. Distributions are recorded exactly, with no caller/source semantic selector. Cross evidence: **FACTOR 5, OPTIMIST 14**, independently shadowed with their direct children. [Cross report](cross-evidence.json) keeps those cases separate.

## Instruction law and provenance

Entry LXI H,AE46; MOV M,D; DCX H; MOV M,E; DCX H; MOV M,C publishes **D→AE46, E→AE45, C→AE44** in order, including same-valued writes. Fresh AE44 CPI4 produces the predicate; only equality invokes canonical7A17. Its actual returned state precedes fresh saved-input restoration. The saved carriers preserve the original triple across clobbering preparation and lower-generation paths; the PICTURE scan visibly changes the child argument registers before the parent restores them.

LHLD AE44 reads C low and adjacent E high; MOV C,L. Independent LHLD AE45 reads E low/D high; XCHG supplies DE. Canonical7ED6 receives the freshly restored triple. **RAR consumes actual returned A/CY**, not a recomputed relation predicate: CY=oldA.bit0, A=(oldCY<<7)|(oldA>>1), NZPA preserved. JNC selects fallback; CYset RET8094 suppresses every later child. Natural child A is0 in all18; returned CY is0 in17 and1 in onePICTURE failed-scan case. That parent RAR yieldsA80/CY0, still fallback. Supported success cases are synthetic-only, clearly DEDUCED STATIC UNOBSERVED.

Fallback independently repeats LHLD AE44/MOV C,L and LHLD AE45/XCHG, invoking **canonical7338(C=entryC,D=entryD,E=entryE)**. It publishes adjacent relations using its established bounded law. No local duplication of7338 occurs.

Then **fresh LHLD AE44; XCHG; C=1; canonical75CE** supplies DE with **E=saved selector C, D=adjacent saved E**. It is not the original DE tuple.75CE emits its historically proved field representation from the low E channel. Finally **fresh LHLD AE45; B=H; C=L; canonical7619** receives **BC=savedD<<8 | savedE**. Final registers/flags come from actual7619; RET consumes the original caller word. All six paired reads remain independent and ordered low then high. Component journals show none of the preparation/publication children overwrites AE44..46 at the supported indices; the host retains fresh rereads nonetheless.

The representation-level policy is conditional preparation, actual-result-gated relation attempt, and fallback adjacent publication plus selector/word emission. Higher compiler meaning remains HYPOTHESIS. [Semantic extraction](semantic-extraction.json) separates that possible operation from scratch, register transfers, RAR and hardware stack mechanisms; no MIR/API design or faithful-code refactor.

## Independent proof and transaction

All primary and cross roots independently compare registers, all flags, SP/PC, ordered writes, complete65536-byte RAM, stack last writers, DMA/filesystem, record/service chronology and child CALLs. Canonical **7A17,7ED6,7338,75CE,7619** are independently shadowed at the exact contained windows. Intermediate CPU states and pointer/read/write witnesses are retained under ignored_build with durable proof hashes.

**432 independent concrete-CPU synthetic proofs** discriminate selector0/4/5/6, D/E and selector channels, stale overwritten scratch, both incoming carry values, pending preparation, each lower early gate, failed search, actual success equality/adjustment/match/search, early-return suppression and fallback emissions. Synthetic success is induced by valid lower memory inputs; child output is never patched. [Shadows](shadow-summary.json) retains route grouping and hashes.

Each ordinary child CALL writes its encoded continuation below the original outer CALL slot. No private frame is invented. Full journals retain7338 PSW transport,7ED6 nested frames and output-child residue. Parent has no PUSH/POP itself. Every root returns SP=entrySP+2 to its actual original continuation, unchanged. CPI4, lower flags, RAR and JNC are tracked instructionally.

Copied staging validates own and selected child code/CALLs, continuation, entry stack, scratch/sentinel/table aliases and all bounded child/output/position scopes before live mutation. Negatives cover own/child code, origin/CALL/continuation, stack and sentinel aliases, unsupported selector7, pending mode2, and a late fallback position-wrap rejection after staged preparation/publications. Live RAM/DMA/filesystem remain unchanged after rejection. No partial native effects precede fallback.

## Hierarchy and measured counters

|Source|Guest before → after|Removed|Host before → after|
|---|---:|---:|---:|
|MINIMAL|294693 → 294603|90|104 → 95|
|FIZZBUZ|561614 → 561279|335|268 → 235|
|PICTURE|340593 → 340468|125|96 → 84|

[Hierarchy/residual map](topology-summary.json) reports absorption by coordinate, internal counts and remaining external7ED6/7338/75CE/7619/7A17/8072/119E. No leaf interception was added. Standalone8072 and cumulative hybrids preserve exact MINIMAL/FIZZBUZ/PICTURE REL goldens, full REL/INT record chronology, filesystem, console/milestones, BDOS order/counts and warm boot. Both hybrid receipts retain actual whole-run counters and hashes; inclusive window sums are not savings.

**64 RAW→UNDERSTOOD, DECODED0, STRUCTURED0**. Naturally OBSERVED bytes: **63**; DEDUCED STATIC UNOBSERVED bytes: **1**. No helper-body promotion or adjacent procedure promotion. Bounds stable, local CFG complete, general contract partial over canonical index/pending/output/error/position/alias domains. Historical behavior correction: none. Native algorithm correction: none. Development test-harness fixes normalized JSON ancestry keys and separated archived hybrid synthetic records from the Pass66-only count. Pragmatic divergence: none. Fidelity debt is bounded inherited child domains, synthetic-only success coverage and unproved compiler meaning.

## Validation policy and handoff

ACTIVE extras are **pass66, pass65**. Pass66 independently proves/composes every required canonical child. Pass65 is a justified adjacent-child regression because this change extends shared PLI2 dispatch/bounds/preparation and local shadow selection.7338/75CE/7619/7A17 algorithms remain untouched, so pass62/pass54/pass57 are not accumulated as automatic multi-minute campaigns. [Rationale](active-dependencies.json) and [ACTIVE receipt](validation.json) record selection, timings, workers, tests and reruns. Compare measured cost with Pass65 782.972 seconds; no proof was removed to meet a time target.

Historical-full selection includes all92 Pass62 categories plus validation-runner-tests and pass63–66 (**97 categories**); listing proof only. Exact reconstruction remains **94720 bytes**, oracle queries **0**, packet **21326 bytes**. Driver phases: fresh discovery/inventory, components, cross evidence, contracts/CFG, topology, reports and explicit ACTIVE validation. Proof artifacts and temporary directories live under ignored_build and clean up on exit. User-owned scripts/view-optimist.sh is untouched.

[Next-boundary ranking](next-boundary-ranking.json) recommends bounded valid-entry discovery around the paired6ED7/6EE5 callsites, not artificial roots there. Nearest retained owning windows generally reach1FB5, a broader compiler policy;3D10/397F contexts have additional semantics and remain separate.18B3 remains an independent large traversal. No immediate caller was migrated. **Pass67 should run the planned historical-full epoch after its semantic work and metadata are finalized**; Pass66 ACTIVE is not FULL certification.
