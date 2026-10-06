# Pass 41 — accumulated acquisition at +784E / resident +1376

Baseline: `22c38cf8d83b61e602523c48aacf5147a69835ba` (Pass40 full checkpoint).
Archaeology only; no native implementation or CPU/Runner/CP/M/packet changes.

The required acquisition boundary is now reproducible at every demonstrated
+5E98 and +5929 scope. It is not globally complete. All 23 required acquisitions
use immediate counted-buffer reads: **none invokes refill +0D40**. This closes
the resident dependency rather than renaming it an opaque blocker.

| Operation | MINIMAL | FIZZBUZ | PICTURE |
|---|---:|---:|---:|
| +784E, all corrected ordinary calls | 19 | 86 | 37 |
| +1376, including independent PLI0 callers | 38 | 172 | 74 |
| +784E directly beneath +5E98 | 0 | 8 | 2 |
| +784E directly beneath +5929 | 1 | 11 | 1 |
| newly reconstructed resident +1616 | 0 | 20 | 4 |

All duplicate windows remain independent evidence. The 142 +784E routes comprise
60 literal-first-byte returns, 47 descriptor matches, 20 descriptor exhaustions
and 15 selector passthroughs. The required parent subset comprises 19 selector0A
single-byte acquisitions and four selector01 zero-word acquisitions; the latter
all occur under FIZZBUZ +5929. Callers and each source's routes are retained in
[route-distribution.json](route-distribution.json).

## Bounded resident acquisition

Entry EOF bit2012 and reuse bit20C4 are clear. +1376 resets 2088 then2087,
accumulator1C58, width20C5 and selector20C3. Fresh zero/space context20C1 causes
+12D9 calls until a nonwhite byte appears. Existing complete +15E3 selects01
for 41..5A or3F. Required remaining contexts are neither digits nor27, selecting0A.

Each iteration calls +1627 **before** acquiring the following byte. Its established
law publishes current context at20C6+width, increments width, then freshly rereads
context for the modulo16 accumulator. No prefix buffer is cleared. +1376 saves
previous context at20C2, invokes +12AE, publishes the raw following byte to20C1,
then independently reads the paired20C1/20C2 carrier and calls complete +0817
using its low byte. The transformed result is republished to20C1.

Each required +12AE call freshly observes index1F06<count1F08. It increments the
index before reading byte[1E8E+old_index]. Its flags derive from the intervening
DCR and address DAD, not from the returned byte. The 23 required windows contain
no refill, EOF, host input event or hidden input-register requirement.

Selector0A's previous-dot/following-digit conjunction is false in this scope;
return is at +15D5 with A=0A, BC=0, HL=208F, entry DE preserved and flags from
CPI(0A,05): S0 Z0 AC1 P1 CY0. Selector01 uses the actual +15F9 A.bit0 through
CMA/RAR to continue or terminate. On termination the fresh accumulator selects
a little-endian word at1C38+2*accumulator. Required selected words are zero;
publication to1C59/1C5A and subtract0/ORA yield A0, BC1C38, DE1C5A, HL0,
S0 Z1 AC0 P1 CY0. Retained following context remains physically separate from
the prefix. These are state predicates and historical operations, not case IDs.

## +784E and carry ancestry

The fresh selector/first/context triple rewrite test is false at the selected
scope. SUI(k); ADI FF; SBB A constructs inequality masks: the ADI carry is true
exactly when u8(selector-k) is nonzero. Self-SBB consumes **that** carry. This
resolves the old ADI-carry proof gap directly from instructions and all142 windows;
it does not change the previously inferred branch law.

Selector0A publishes the fresh first prefix byte into20C3 and returns after seven
nonmatching literal comparisons; final flags come from CPI5E. Selector01 uses
fresh width<=0D to select a descriptor pointer through9A32+2*width and publishes
AA16/AA17 and the header countAA18. Each attempt decrements count before copying
fresh width intoAA19. The reverse comparison actually reads prefix20C6+u8(j-1),
the descriptor at fresh_pointer+j, the neighboring carrier byte and21C5, including
when j=0. The zero/equality masks select decrement and repetition.

Fresh width+1 advances the pointer through complete resident +1A1C. Its low/high
publication precedes the stopping-index comparison. A match reads the byte at
the **advanced** pointer and publishes it20C3: A=result, BC0, DE=HL=advanced pointer,
flagsCMP(0,0). Exhaustion publishes20C3=01 while returning A00, HL20C3 and flags
from final CMP(0,count0). Equal concrete bytes do not merge these channels.

All body CALL/PUSH bytes are derived from their instruction operands, live input
registers/PSW and stack depth. Full proof retains ordered writers and surviving
last-writer projections; no residue comes from copied oracle post-memory.

## Reused and newly closed leaves

Existing +12AE/+12D9, +15DA/+15E3/+15F9, +1627, +0817, +1A1C/+1A40 and +4275
contracts are reused. All762 natural +1627 calls validate the established bounded
append law; its unexecuted width-overflow route remains unsupported.

The short resident +1616 leaf, naturally called from independent numeric
acquisitions, is closed in this pass: save C at2149, genuinely read2149/214A,
pass only low C through +0817, then SUI45/SUI01/SBB A. Return FF iff the transformed
byte equals45, otherwise00; BC/DE preserved, HL208F, exact final self-SBB flags.
Its sole body CALL leaves continuation1721 below entry SP. All24 natural cases
exercise the false outcome; the equality outcome is statically complete but
STATIC / UNOBSERVED. **17 RAW bytes become UNDERSTOOD**, with a stable/complete/
complete ProcedureHypothesis. Zero historical-binary queries were needed.

Existing +1376 and +784E retain provisional/partial/partial global classifications.
EOF/reuse/refill, quoted/numeric alternatives, nonzero selected-word handling,
wide descriptors and special rewrites remain explicitly outside required closure.
The +15F9 digit-true arm at+160A remains RAW. No arbitrary-input termination,
table capacity, global ownership or general alias safety is claimed.

## Cross-parent sufficiency and next boundary

For all10 +5E98 children, +5A46 produces the pointer before acquisition, and the
next +4275 receives the exact acquisition return state without intervening data
changes. Acquisition does not mutate working/reference pointer words A863/A8AB.
For all13 +5929 children, +2511 precedes acquisition and the shared parent RET
passes through its final data registers and flags. The independent entry/return
ancestry checks are in [parent-compatibility.json](parent-compatibility.json).

+784E is reproducible at these required scopes. +5929 remains blocked only by
+46A7; +5E98 is blocked transitively by the same operation through its indirect
+6223 reentry. +60E5 and +61A4/+620C are consequently **not native-ready yet**.
Pass42 should reconstruct +5929 -> +46A7, crossing small mechanical dependencies;
Pass43 should assess parent composition/native readiness and run the next full
checkpoint. Globally RAW unexecuted alternatives are not added as causal blockers.

## Evidence and validation

[work-packet.json](work-packet.json) interns decoded CFG, route/write layouts,
stack patterns and existing contract hashes. Full factual steps are interned once
in ignored `_build/host-compiler-pass-41/full-proof.json`; no RAM snapshots or raw
traces are committed. [efficiency.json](efficiency.json) records sizes and timing.
The proof is reproducible from canonical corrected captures using
`test_acquisition_pass_41.py --images <historical-image-directory>`.

Validation is incremental against the Pass40 full checkpoint. New acquisition
checks, directly affected MINIMAL5/6, Pass32/33 ancestry, V1, cheap Dune and exact
image reconstruction are executed; unrelated native/MINIMAL/packet suites are
explicitly deferred to the next checkpoint. Detailed category results and times
are in [validation.json](validation.json). Historical reconstruction remains
**94,720 exact bytes**. No contract correction, pragmatic divergence or fidelity
debt is introduced.
