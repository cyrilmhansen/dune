Pass71 decomposes the gateway; it does **not** install a native `+1FB5` root.
It also closes the naturally executed eight-byte candidate-success publication
[203E,2046). The full gateway contract remains partial because the descriptor
predicate and selected handler semantics are not all independently closed.
Baseline `21411f1283b52a0a96e5ae24d55e49637fc9bcad` was verified as HEAD and
origin/main before work. Pass67 remains the current certified FULL epoch.

Fresh hardware CALL inventory, in MINIMAL / FIZZBUZ / PICTURE / FACTOR /
OPTIMIST order: **11 / 61 / 12 / 33 / 120**, totaling **237**.
There are 38 actual caller coordinates, listed per source in
`natural-inventory.json`; MINIMAL retains +2149 ×8, +6862/+6FA0/+6FFA ×1.
Every entry is an actual CALL to runtime41B5. The gateway-own envelope is
[1FB5,20EB), **310 bytes**, with final hardware RET at20EA and no handler
body included. Local instruction/branch ownership is in `cfg.json`; selected
software handler targets leave this envelope. Bounds are stable; control-flow
and full semantic-domain completeness remain partial because trace arms and
opaque children are not closed.

For entry SP=S, LXI H,FFF5 / DAD SP / SPHL first sets SP=S-11. MOV B,C;
PUSH B writes high saved C atS-12 and low C atS-13; INX SP establishes S-12.
The subsequent temporary PUSH/POP counter/address carrier is also retained.
The ten-byte copy publishes AD0B..AD14 atS-11..S-2, in ascending order;
AD0A is independently saved atS-1. C remains atS-12. Original hardware
continuation bytes atS/S+1 are never rewritten within any observed invocation
or its descendants. These are mutable historical stack-local bytes, not a
conventional callee-save abstraction.

The fresh local C feeds canonical +047D at1FDE. Its actual returned A becomes
AD1C=k. Low then high reads from **3C21+2*k** select AD1D/AD1E; SHLD preserves
low/high publication order. Fresh byte[descriptor] becomes AD1A. AD0A is
cleared. Fresh low AD1C indexes **3DDD+2*k**, whose little-endian word is
published to AD1F/AD20. There are **47 natural indices and table tuples**,
recorded in `table-tuples.json`. No abstract descriptor/type meaning is assigned.
Canonical +047D is independently shadowed in all contained windows, including
handler/predicate use: **2064** windows across five sources. The 237 owning
lookup calls are a subset; their C and actual A/table provenance are checked
individually in Pass71.

Candidate scan: fresh AD1A, CPI0, JZ selects scan exit. Otherwise DCR remaining,
INR AD0A, increment/publish descriptor pointer, reread saved C, CALL +1DFF.
The actual child-return A and flags feed RAR; old A.bit0 becomes CY, JNC selects
failure/skip. On success, [203E,2046) writes **AD1A=0 then AD1B=1** using LXI,
MVI M, INX H, MVI M. All flags and other registers except HL are preserved;
same-valued writes remain visible. Both success and failure then execute the
shared skip: fresh byte[current AD1D] is zeroextended into DE, a separate
paired pointer reread supplies HL, DAD D wraps modulo65536, SHLD republishes
low/high, then JMP repeats the remaining-count test. The old “failure-only
skip” description was incomplete.

There are **161 scan calls**, scan iteration distribution:
0×160, 1×43, 2×20, 3×4, 4×4, 5×4, 15×2. These are measurements, not fixed
loop counts. A candidate success clears remaining and leads to the next zero
count check. **53 successes** are naturally observed: FIZZBUZ12, PICTURE2,
FACTOR10, OPTIMIST29; MINIMAL0. This corrects the old MINIMAL-only unobserved
classification. Only this eight-byte publication gains UNDERSTOOD status.

Fallback tests the complement of fresh AD1B through RAR. If the original low
bit was set, JNC bypasses fallback. Otherwise it clears AD0A, freshly uses
low AD1C as k, computes **j=byte[1B4B+k]&7**, independently reads low/high
pointer bytes from **3C13+2*j**, increments that pointer modulo65536, publishes
AD1D, rereads saved C and calls +1DFF again. Actual returned A becomes AD1B.
There are **184 fallback calls**; j distribution 0×91, 1×59, 2×33, 3×1.
This is a third distinct indexing formula, not the descriptor or handler table.
Unobserved j4..7 are not claimed as an accepted native domain.

+1DFF remains the partially understood descriptor predicate. Its gateway
scope contains **345 calls**, with concrete returned-A/flag signatures and
19 observed token values. Fresh descriptor bytes, literal mapped-token tests,
cache-slot operations and additional predicate branches are visible. Natural
children include +047D, +052C, +0572, +0588, +059E, +0992, +21AE and resident
+1A38. `descriptor-subset.json` retains exact token/child/offset distributions;
`frames.json` retains each root's token and result sequence with journal hashes.
There is no canonical native +1DFF contract to delegate, and no independent
native +1DFF shadow is claimed. The map does not pretend that every observed
signature closes arbitrary descriptor/cache domains. Pass71 does not expand
this multi-route predicate or its independent helper policy into a fabricated
opaque host operation.

Dispatch is exact LXI H,42B4; PUSH H; fresh LHLD AD1F; PCHL. PUSH writes high42
atS-13 then lowB4 atS-14. PCHL leaves SP=S-14. Every observed handler RET reads
that word, with last writers still the gateway's +20AF PUSH, and returns to
file20B4/runtime42B4 with SP=S-12. **47 natural handler targets** are recorded
with counts, sources, callers, k, RET sites and contract classification in
`handler-map.json`. Only +6EA5 has an established scoped canonical software
handler contract here; all **11** of its natural windows independently shadow.
+3DE4, +3E36, +20F7 and +4257 are already demonstrated separate/broad policies.
Other targets are candidates for assessment, not asserted compact closed
procedures simply because RETs are observed. No handler bytes are promoted.

Reentrancy is preserved: **222 nested invocations**, with three outer calls
per source and maximum nesting depth **13**. Each owns a separate twelve-byte
frame and original CALL word. Inner AD0A..AD14 mutations are restored before
outer restoration; shared scratch AD1A..AD20 is not restored by the gateway.
`frames.json` retains parent IDs, source-separated depths, entry/exit RAM and
filesystem hashes, DMA, saved bytes, tables, route, software last writers and
projected journal hashes. Representative witnesses and all own/descriptor
instructions plus control transfers and CPU writes remain under ignored
`_build/host-compiler-pass-71`. The capture is an explicit local observational
projection, not a redesign of shared capture semantics or a claim that omitted
child reads/host-service events form a complete native-parent shadow.

Both fresh202E trace gates are zero in every root. RAR consumes the actual
incoming child carry into A's high bit but exposes old202E.bit0 in CY; JNC
bypasses the trace paths. Pre-dispatch [2092,20AC) and post-handler
[20BB,20C8) remain RAW / STATIC / UNOBSERVED. Trace-set, corrupted tables,
unsupported handlers and arbitrary aliases have no native acceptance scope.
No generic callback/transaction architecture is introduced.

After the post-handler gate, the gateway restores AD0B..AD14 in ascending
order from the frame, then separately restores AD0A fromS-1. Across all237:
A=oldAD0A, BC=S-1, DE=AD15, HL=S, final flags S=0/Z=1/AC=1/P=1/CY=0.
SPHL establishes S; RET consumes the untouched original hardware word;
final SP=S+2. Each restoration read/value, write order, child-return-to-gate
state and original continuation are independently checked.

Pass69/70 are **not yet unblocked**. Their +374B/+3CAE/+3740 calls produce
16 independent five-source cases. Most select **k23, descriptor57C6,
handler +3E36**. Candidate token05 succeeds, or token05 then69 fails and
fallback FB/cache matching is used. FACTOR also selects k123/+256E and
k33/+3FFD; OPTIMIST's +374B selects k216/+6D47. `parent-unblocking.json`
contains exact input tuples and remaining child/handler boundaries. Scope
could eventually be based on k/descriptor/handler state, but not on those
caller coordinates. No such executable scope is installed now.

Synthetic proof contains **30 safe save/restore fragment cases** varying
C, saved bytes and SP, and **768 success-block CPU cases** spanning all
PSW byte patterns and old destination values. Restore tests explicitly use
an own-fragment boundary with independently changed shared bytes; they do
not patch handler outputs or pretend to execute a full gateway transaction.
Success tests compare all RAM, ordered writes, registers and flags. No
unobserved trace path is promoted by synthetic execution.

Knowledge: root-own310 bytes, **271 naturally executed instruction bytes**,
39 static trace bytes. **RAW -> UNDERSTOOD8 (all OBSERVED)**;
STRUCTURED -> UNDERSTOOD0; DECODED -> UNDERSTOOD0; synthetic-only promotions0;
helper/handler promotions0. The gateway catalog remains partial. Stable
coordinate2040 survives as operand-only EQU; no fake procedure entry is created.
Only the +1FB5 reviewed header is rendered; unrelated reviewed headers,
including +047D, remain unchanged. Historical catalog authorization references
the scoped Pass71 law. The old MINIMAL test removes only the stale203E RAW
expectation; both trace assertions and every unrelated RAW assertion remain.

No runtime or native implementation changes. Hierarchy remains MINIMAL
294445 guest/92 host, FIZZBUZ560189/221, PICTURE339852/79, inherited from the
published baseline. New roots0, absorbed roots0, savings0. No native gateway
hybrid exists; no redundant unchanged cumulative campaign is claimed.
Fresh five-source guest captures preserve primary REL hashes:

- MINIMAL `7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119`
- FIZZBUZ `68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`
- PICTURE `c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1`

Semantic extraction leaves candidate_modern_operation=null: gateway own
mechanism is established, complete compiler-policy meaning is not. No MIR,
API, source-specific dispatch or faithful-code refactor occurs. Oracle queries0.
Pass72 recommendation: a separately bounded +3E36 handler assessment together
with the necessary k23 descriptor-predicate subset, before revisiting69/70;
+382E is an independent alternative. A broad arbitrary-handler gateway is not
the next automatic migration. Ordinary FULL remains planned after Pass72's
semantic commit; Pass67 stays current until an actual later certification.

Validation uses explicit categories: build, project, pass71, diff-check,
validation-runner-tests, minimal-pass-1. The sole archived extra is the cheap
complete MINIMAL category whose assertion was actually narrowed. Rationale
is in validation-rationale.json. No ACTIVE or historical-full execution.
V1 ran separately before aggregate because annotations changed: **9 tests
passed, 43.990s**. Single exact reconstruction verifies **94720 bytes** and
all hashes/partitions/mappings; no roundtrip-tests. Minimal dynamic progress
is independently unchanged after the eight-byte promotion; it is not rerun
as an additional aggregate category. No shared packet/continuation code was
modified, so packet-continuation is omitted. Historical-full list-only count
**102**, preserving all98 certified Pass67 categories plus passes68–71.
No FULL trigger fired: CPU, CP/M, Runner, shared transaction/capture and
reconstruction mechanisms are unchanged.

Development corrections, completed before final aggregate: preserve JSON
insertion order for reviewed-header rendering; keep the2040 EQU encoding and
seed-derived section references; explicitly scope the eight-byte evidence
contract; compact the fresh packet; qualify +047D component shadows as PLI2
rather than resident image. No historical/native repair or service divergence.
V1's initial annotation-development failure was corrected before the successful
pre-aggregate V1 run; no aggregate initially-green claim is made in advance.
Fidelity debt remains the partial descriptor matcher and unresolved handlers.

Packet **17019 bytes**. Driver phases: discovery (five-source capture, owned
frame extraction, canonical components, fragment CPU proofs), reports, validate.
Annotation updater is narrowly scoped and deterministic from the published base.
Focused proof and final regression timings are recorded separately below and
in their receipts. Full witnesses remain in ignored_build; no giant trace
packet is committed. No Pass67 certification artifact is altered.

Protected scripts/view-optimist.sh and local-icybox-full-0-verify.state are
untouched. Task artifacts persist under the project tree, not/tmp; temporary
annotation-test fixtures were cleaned, and subsequent checks use ignored_build
TMPDIR. No temporary task process is left running.

RUNES PLI2 1FB5 PASS 71 DECOMPOSITION COMPLETE

Final aggregate outcome: **6/6 initially passed**, **36 Python tests**,
39 Dune test stanzas, four workers, **30.259s wall / 30.747s summed**,
zero aggregate reruns. Profile=legacy-categories, tier=INCREMENTAL, last
certified FULL=Pass67. The contained proof campaign (capture, frame extraction,
canonical shadows and CPU fragments) took **25.892s** and is included in the
aggregate wall; these times are not added as disjoint work. The earlier local
focused execution also passed11 tests. No historical-full was executed.
