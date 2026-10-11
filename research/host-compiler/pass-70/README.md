Pass70 is a discovery milestone. The naturally required arm of `PLI2.OVL+397F`
reaches the broad `PLI2.OVL+1FB5` gateway through `+373C` at `+3740`.
No native root, child contract, annotation change or byte promotion is installed.
Baseline: `1da471c4cda0f614574506de81306cb1240a11cd`, verified as HEAD and
origin/main before work. The exact historical binary remains the primary oracle.

Fresh concrete inventory finds zero calls in MINIMAL, PICTURE and FACTOR; one
in FIZZBUZ and one in OPTIMIST. Both hardware CALLs originate at `+4257`,
return to runtime `645A`, and select **15** from fresh byte `AD0A`.
The adjacent paired-read byte `AD0B` differs: 14 versus 94. It is discarded
when B is zeroed. Entry snapshots, actual CALL-word writers, child inputs and
outputs, final register/flag/RAM/filesystem hashes, and ordered-journal hashes
are preserved in `ownership.json`. Exhaustive instruction journals and RAM
seeds stay under ignored `_build/host-compiler-pass-70`.

Static ownership supports the local envelope **[397F,3B70)**, 497 bytes,
partitioned into instruction ranges [397F,3B3C) and [3B62,3B70), and the
38-byte data table [3B3C,3B62). There are 19 little-endian target words.
All targets are valid decoded arm starts. Local branch targets belong to
these instruction ranges; all 19 arms converge by JMP on `+3B62`.
The only local RET is `+3B6F`. Fresh five-source CALL inventory has no other
hardware entry in this envelope. This is a static/local extent assessment,
not a complete semantic contract or proof against every hypothetical external
transfer. The distinct following operation at `+3B70` is excluded.

The frontend performs fresh LHLD AD0A/AD0B, C=L, B=0, HL=5D3C, DAD B twice,
E=byte[HL], INX H, D=byte[HL], XCHG, PCHL. Thus low target then high target
are independently fetched, SP does not change, and the original hardware
continuation remains on the stack. Both natural executions reach file `+3ACC`.
The 19 table targets and complete local decode are in `dispatch-law.json` and
`cfg.json`. Table data is never treated as instructions.

The natural arm calls `373C / 3790 / 8386 / 382E / 7B99`, in that order.
`+373C` freshly reads AD0C, passes its low byte to the unresolved gateway at
`+3740`, then calls `+371B`. This is a substantive independent boundary;
Pass70 does not swallow, stub or hide that naturally executed gateway.
`+3790` and `+7B99` reuse canonical Pass68/Pass58 contracts in independent
contained component shadows, one each per source (four shadows total).
These compare full registers/flags/RAM, ordered writes, stack and services.
No new whole-parent native shadow is claimed.

After `+373C`, the parent sets C=1 and PUSHes B/C. It freshly reads AD0D/AD0E,
passes low AD0D to `+3790`, increments returned HL, then calls `+8386`.
FIZZBUZ passes selector 11 and obtains HL=15; OPTIMIST passes 91 and obtains
HL=6. The incremented words 16 and 7 become FFF0 and FFF9 respectively.
The static `+8386` candidate [8386,838E) implements SUB A; SUB L; L=A;
A=0; SBB H; H=A; RET. Its flags are high-byte SBB flags, not a whole-word
zero predicate. It is documented as a compact RAW candidate, not promoted
or installed merely to make the blocked parent look complete.

The parent then passes that word in BC and literal E=4 to `+382E`.
That child POPs the CALL word into DE, POPs the caller argument into BC,
writes its low byte to AD50, and PUSHes DE to relocate the continuation.
Its RET consumes the relocated `5CE4` word: final SP is two bytes above the
pre-CALL SP. This is not an ordinary CALL/RET balanced frame. The exact
POP/PUSH/read/write records are in `stack-argument-proof.json`.
Its broader policy remains unclosed. The final canonical `+7B99` receives
C=7/E=4. Actual child return registers and flags are retained throughout.

The common tail freshly rereads AD0A/AD0B, zeroes H, adds BC=579B, reads
byte[579B + low AD0A], publishes that byte to AD06, and RETs. NZPA are
inherited from the selected arm's last child; CY is from DAD. JMP, loads,
store and RET preserve those flags. The original `645A` word survives with
its original outer-CALL writers. Entry SPs are 65458 and 65432; final SPs are
65460 and 65434. OPTIMIST's window includes a captured BDOS record event;
FIZZBUZ's does not. Existing witness return-classification mismatches around
software argument consumption are retained, not normalized away. Original
continuation ownership is proved from concrete reads and writers, rather
than inferred from a generic frame classification.

There are **240 concrete CPU frontend discriminants**: selectors 0..19,
adjacent high bytes 0/255, incoming carry clear/set, and target-word XOR
0/1/256. These stop before executing any arm child. Corruption follows the
changed concrete target; it is not a native acceptance or rejection test.
Selector 19 is an out-of-table observation, never claimed supported.
There are also **18 concrete common-tail cases** varying selector/vector byte
and flags, proving fresh acquisition, exact ordered memory accesses, AD06
publication, original RET and flags. No arbitrary pointer/alias/continuation
acceptance is claimed, since there is no native transaction to accept it.

Knowledge accounting: 459 local instruction bytes, of which 64 are naturally
executed discovery bytes and 395 are static/unobserved. Two table bytes are
naturally read; 36 are static data. RAW -> UNDERSTOOD **0**;
DECODED -> UNDERSTOOD **0**; STRUCTURED -> UNDERSTOOD **0**.
No procedure catalog or progress manifest is changed. Synthetic frontend
execution does not close the unobserved arms.

Native hierarchy is unchanged: MINIMAL 294445 guest / 92 host, FIZZBUZ
560189 / 221, PICTURE 339852 / 79, as at the published baseline.
These are inherited cumulative counters, not newly measured migration savings.
New roots=0, absorbed roots=0, guest savings=0, host delta=0.
The guest-only inclusive windows contain 4454 and 4534 instructions; these
are discovery measurements, not procedure sizes or savings. A standalone
native +397F hybrid does not exist. No redundant unchanged cumulative-hybrid
campaign is run. Runtime sources and dispatch remain byte-for-byte unchanged.
Fresh five-source guest captures preserve primary REL goldens:

- MINIMAL: `7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119`
- FIZZBUZ: `68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`
- PICTURE: `c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1`

`natural-inventory.json` distinguishes global invocation counts from contained
calls; no inferred global native-external map is fabricated. The unresolved
+397F hardware roots remain one in FIZZBUZ and one in OPTIMIST. Next priorities
are a separately scoped +1FB5 gateway study, then assessment of the independent
+382E argument-consuming policy. The +4257 parent is not inferred from
adjacency. +18B3 remains an unrelated large traversal; +3E36 stays excluded.
Semantic extraction leaves `candidate_modern_operation = null` because the
complete policy is not established. No MIR/API design or faithful-code
refactor occurs. Oracle queries: **0**. Pragmatic divergence: none.
Fidelity debt: unresolved gateway and remaining arm policies. Historical
correction: inclusive instruction spans are not bounds, and +382E consumes
an explicit stack argument. No runtime implementation correction was needed.

Validation uses explicit dependency selection, never ACTIVE or historical-full:
`build` (proof executable build), `project` (mandatory unit suite), `pass70`
(new local exhaustive evidence), `diff-check` (patch integrity), and
`validation-runner-tests` (new catalog selection). Each rationale is durable
in `validation-rationale.json`. No annotated assembly was modified, so V1,
roundtrip categories and roundtrip-tests are omitted. Shared packet/continuation
machinery was not changed, so packet-continuation is omitted. No archived pass
implementation changed; chronological archived regression extras are omitted.
The exact reconstruction verifier independently checked **94720 bytes**;
all section/image hashes, partitions and mappings matched. List-only
historical-full selection contains **101 categories**, preserving all 98
certified Pass67 categories plus passes68/69/70. It was not executed.

Pass67 remains the current certified FULL epoch. Next ordinary FULL remains
approximately Pass72. No FULL trigger fired: there is no CPU, CP/M, Runner,
shared transaction/capture interpretation or reconstruction change.
Driver phases: discovery, reports, validate. Validation invokes only the
explicit five-category aggregate. Final execution timing and counts are in
`validation.json`; focused proof timing is reported separately below.

`scripts/view-optimist.sh` and `local-icybox-full-0-verify.state` remain
user-owned/untracked and untouched. No task directories are created under
/tmp. Transient evidence stays under ignored _build.

RUNES PLI2 397F PASS 70 BLOCKED AT PLI2.OVL+1FB5

Final explicit regression aggregate: **5/5 passed**, 28 Python tests,
39 Dune test stanzas, four workers, **20.557s wall / 20.764s summed**.
Focused discovery campaign (fresh five-source capture, component shadows,
frontend/tail proof) took **19.261s**, recorded separately in
`focused-proof-timing.json`; it is included inside the aggregate pass70
category, so the two figures must not be added as independent work.

The initial aggregate was **4/5**, with pass70 failing before any test ran
because the new driver attempted `dune build` inside a read-only parallel
worker. Initial wall was **3.913s**, summed **4.007s**, and 17 Python tests
were reported. `validation-initial.json` preserves this failure. The repair
only honors the existing `RUNES_HOST_IMAGES` serial-build marker.
The complete five-category aggregate was rerun and passed. A frontend flag
assertion was also strengthened before that rerun. No semantic/native repair
or historical campaign was needed. The successful receipt documents the
rerun rather than claiming an initially green run.

Implementation packet: **6354 bytes**. User-owned file hashes match their
pre-work values. All task execution processes have completed.
