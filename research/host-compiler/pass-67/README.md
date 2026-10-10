# Pass67 — bounded paired-generation software handler

Baseline `2e5b8c4e3ebe68fc7e100557772afdb4a4a4e4cb` was verified at HEAD and origin/main. This is a **semantic migration**, following discovery of the genuine software entry **PLI2.OVL+6EA5 [6EA5,6F19), 116 bytes**. 6ED7 and 6EE5 are CALL instructions; neither is a procedure entry. No artificial root was installed at 6ED1 or 6EE0. The hardware owner is the larger 1FB5 gateway, called at 2149. Its inclusive span is not the local handler extent. [Ownership](ownership-map.json), [CFG](cfg.json), and [root paths](natural-paths.json) retain independently derived evidence.

## Ownership and software continuation

The actual gateway executes 20AC LXI H,42B4;20AF PUSH H;20B0 fresh LHLD AD1F;20B3 PCHL. Fresh handler pointer 90A5 selects 6EA5. PCHL changes PC only; it creates **no hardware CALL word**. The PUSH writes 42 then B4 below the gateway SP. Every natural 6F18 RET readsB4/42 from that same untouched slot, returns to 20B4, and increases SP by 2. This ordinary explicit software continuation is distinct from established N2/N8 argument-consuming families. No private host frame or invented CALL word is used. Every child retains its genuine encoded hardware CALL/RET stack residue, including the 052C PSW carrier.

Primary logical/external handler roots: **MINIMAL 1, FIZZBUZ 4, PICTURE 1**. Cross evidence: **FACTOR 1, OPTIMIST 4**. All enter through 20B3 PCHL; the nearest enclosing matched hardware frame is 1FB5, not a manufactured6Exx CALL frame. Neighboring 6EA4 RET belongs to another handler. No natural overlapping CALL entry into this handler was found. Six new bounded child contracts are separately identified:04E9[04E9,04FF),04FF[04FF,0515),0515[0515,052C),052C[052C,0546),8350[8350,8357),8357[8357,8364).8350 is an actual CALL-selected shared tail; static 834D prefix is left untouched.

## Exact operation and paired relationship

Fresh low AD0C is mapped through AAB0.04FF independently reads the low component at A7F8+mapped index;04E9 independently reads the high component at A795+mapped index.052C saves the selector at AC01 and transports the first returned A through PUSH PSW/POP B across the second lookup.0515 publishes E/C at AC00/ABFF, uses canonical 83B4(C8) and 8398 to form HL=(high<<8)|low. No table capacity is inferred; selectors and mapped indices are zero-extended bytes. Scratch writes and paired adjacent reads remain visible.

6EA5 clears AD9F and publishes that actual returned word low/high at  ADA2.8350 masks HL with literalDE0400; canonical resident 1A29(A0) computes modulo-word negation. OR L, ADI FF, SBB A forms the nonzero mask, published at ADA4. RAR exposes bit0 in CY. All 11 natural handlers have the 0400 bit clear and skip the recursive 1FB5 call arm. That independent gateway arm remains RAW / STATIC / UNOBSERVED / unsupported, rather than being absorbed into this pass.

**6ED7 supplies C=2 and DE=fresh word[ADA2]**. Primary first tuples are 2/2/82; OPTIMIST additionally 2/2/144. After the actual 8072 return, canonical 742A resets gated indexed state, publishes FFFF at ADA6, and returns fresh1C2C inHL. The parent publishes that word low/high at  ADA0. **6EE5 then supplies literal C=0, DE=0**, independent of the first returned registers. The calls are ordered and both execute on every accepted path. They share evolving relation/output state; they are not two independent identical invocations. The first call's publications/output precede the 742A reset and position read, then the second publication/output. [Child checkpoints](shadow-summary.json) and root journals retain that inter-call state; no child result is recomputed or patched.

Fresh ADA4 is tested again. Supported clear paths proceed to 8357(A80,DEADA2), independently reading low/high and retaining DE increment. Canonical 1A29(A0), OR L tests the resulting word. Zero selects literalBC8F6E; nonzero selectsBC8F69. Both invoke canonical 8248. The alternate bit 80 route is naturally observed once inOPTIMIST; primary roots all select 8F6E. No speculative compiler meaning is assigned to these pointer literals or emitted fields.

## Independent proof, staging, and archaeology

All 11 roots and their exact 052C/04FF/04E9/0515/8350/8357/8072/742A/8248/1A29 windows independently compare registers, flags, SP/PC, ordered writes, all 65536 RAM bytes, stack last writers, child chronology, DMA/filesystem and record/service chronology. The 96 independent concrete-CPU synthetic discriminants separate low/high mapped bytes, selector from mapped index, indices 0/255, adjacent AD0D, incoming carry, final bit 80 selection, and valid first 8072 equality/adjacent-value success. The 742A reset forces the second attempt into its clear-gate fallback; no second-success child output is patched. Negative cases cover code/child/gateway/continuation corruption, table/scratch/stack/sentinel aliases, recursive 0400 selection and late position-wrap rejection. Complete copied staging precedes every live effect. Original RAM/DMA/filesystem remain unchanged after rejected preparation.

Canonical 8072/742A/8248/1A29/83B4/8398 algorithms are reused. CPU8080, CP/M, Runner and shared journal/capture interpretation are unchanged. The bridge adds one explicitly scoped local PUSH-H/PCHL ABI alongside existing CALL ABIs; historical CALL checking is preserved. No generic runtime or transaction redesign occurred. Annotation verification adds an explicit, canonical Pass67 PUSH-H/PCHL proof kind with separate negative tests; legacy CALL/N2/N8 checks retain their interpretation. This new local ABI is proved narrowly, with no shared capture reinterpretation; **no FULL trigger fired**.

[Knowledge accounting](knowledge-summary.json) reports 213 RAW→UNDERSTOOD (100 root-own and 113 helper bytes), zero DECODED/STRUCTURED promotions, all naturally OBSERVED. Sixteen root bytes remain RAW in the two recursive-gateway arms. The nine alternate-tail bytes have OPTIMIST natural evidence; no synthetic-only byte is promoted. Bounds stable, local control flow/contract partial over the supported nonrecursive and inherited canonical-child domains. No historical behavior correction. Implementation corrections during development removed an unjustified provisional 99 index limit exposed by cross-source inputs and fixed a test-only child-code coordinate. Pragmatic divergence: none. Fidelity debt: unsupported recursive arm, inherited pending/position/output/alias limits, and unknown compiler meaning.

## Measured hierarchy and outputs

|Source|Guest before → after|Removed|Host before → after|
|---|---:|---:|---:|
|MINIMAL|294603 → 294445|158|95 → 92|
|FIZZBUZ|561279 → 560647|632|235 → 223|
|PICTURE|340468 → 340310|158|84 → 81|

Each new handler absorbs two 8072 roots, one 742A root and one 8248 root. Actual transition deltas are -3/-12/-3. Remaining enabled 8072 roots outside this new handler are 1/3/2; guest-external 8072/7ED6/7338 calls remain zero. External119E remains 32/32/39. These are whole-run counter differences, not inclusive window sums. Standalone handler and cumulative hybrids preserve complete REL/INT, filesystem, console/milestones, BDOS and record chronology and warm boot. Exact REL SHA256: MINIMAL 7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119; FIZZBUZ 68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203; PICTURE c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1.

[Semantic extraction](semantic-extraction.json) separates mapped inputs and differentiated generation effects from absolute scratch, PSW transport and software/hardware continuation mechanisms. Compiler-level wording remains HYPOTHESIS; no MIR/API or faithful-code refactor. [Next ranking](next-boundary-ranking.json) recommends fresh bounded predicate/child discovery at the true 3D10 context before migration, ahead of the less converged 397F context and independent large 18B3 traversal. The broader 1FB5 gateway remains separate.

## ACTIVE validation and pending FULL handoff

ACTIVE extras: pass67 and pass66. Pass67 supplies exhaustive new local proofs; pass66 protects the materially extended shared PLI2 bridge identity/bounds path and legacy 8072 CALL dispatch. Immutable older child campaigns are not chronologically accumulated. [Receipt](validation.json) records actual category/test/worker/wall/summed timings and reruns. Exact historical reconstruction remains 94720 bytes; oracle queries 0. Packet size is recorded separately and stays below 32 KiB.

**Pass62 remains the last certified FULL epoch. Pass67 FULL status is PENDING EXTERNAL EXECUTION.** Historical-full has not been executed. List-only selection preserves all 92 Pass62 categories, validation-runner-tests, and pass63–67: 98 categories. Policy epoch is unchanged. After this semantic commit is pushed, run:

```sh
python3 tools/annotated-assembly/run_host_compiler_regressions.py --profile historical-full --images /home/john/pli/cpm/pli80/DISK1 --output _build/host-compiler-pass-67/full-validation --workers 4
```

The runner prints START/DONE/WAIT progress. A separate certification task must import the successful external receipt and update the FULL epoch; this semantic commit does not pre-certify it. [Handoff](full-checkpoint-handoff.json) deliberately records PENDING_UNTIL_COMMIT rather than a fabricated self-referencing SHA.

Driver phases: discovery, proof, contracts, annotations, topology, reports, focused, active validation. Exhaustive journals live under ignored _build. No task-owned /tmp directories. User-owned scripts/view-optimist.sh is untouched.

ACTIVE receipt: 29 categories, 101 Python tests, 39 Dune test stanzas, 4 workers; wall 767.061 seconds, summed 1001.524 seconds. Initial result and any complete-category reruns remain explicitly recorded in the receipt.

The initial ACTIVE run passed 28/29 categories in 405.467 seconds (640.861 summed). Pass67 failed before its tests because its setup invoked dune build inside a read-only aggregate worker. The driver was corrected to consume the serially prebuilt executable; no semantic/native implementation changed. The COMPLETE Pass67 category rerun passed 15 tests in 360.777 category seconds (361.594 rerun wall, including mandatory build/project). [Initial receipt](validation-initial.json) and [rerun receipt](validation-pass67-rerun.json) preserve the failure and recovery. The combined wall figure above covers both executions; it does not claim an initially green aggregate.
