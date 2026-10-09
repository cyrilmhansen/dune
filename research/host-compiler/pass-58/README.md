# Pass58 — indexed carrier transfer and emission

Baseline: `2c9bd0a2afa951080eaf57e2f73b797a1e0b1e13` (published Pass57). The current FULL checkpoint remains Pass56. This pass uses incremental validation.

Actual CALL/RET ownership establishes +7B99 `[7B99,7BB2)` (25 bytes) and +793C `[793C,79A2)` (102 bytes). No naturally called overlapping entry was found. Both have natural counts MINIMAL/FIZZBUZ/PICTURE = 0/10/0. FIZZBUZ root callers are +3AE8 ×1, +36F3 ×3, +3708 ×3 and +4205 ×3. All ten +793C calls originate at +7BAE. C/E pairs are 7/4 ×4, 5/7 ×3 and 4/7 ×3. There are no natural E=6 cases.

+7B99 saves low E at AE11, then low C at AE10. It freshly reads AE10/AE11 and passes L as C to canonical +7AE4. Preparation does not modify AE10/AE11/AE12 on these natural routes. Independent fresh reads then restore C from AE10 and DE from AE11/AE12 before canonical +793C. D comes from fresh AE12, rather than entry D; +793C consumes low E. All shared carrier writes remain visible.

+793C saves E at AE03, then C at AE02, and compares fresh AE03 with 6. The non6 route copies ADAB[E] to ADAB[C]. The E=6 route clears ADAB[C] and jumps to the common second transfer. Both routes copy ADB3[E] to ADB3[C]. Source addresses are formed from fresh paired reads and zero extension, pushed through the hardware stack, and recovered into DE; destination addresses and source bytes are independently acquired. Same-index writes remain observable. Supported indices 0..7 are an explicit bounded scope, not a claim about global table capacity.

Emission calls canonical +746F with C=40H, +74C7 with freshly reread saved C, +74C7 with freshly reread saved E, and +7557 with the derived field. Actual opcode 87 is ADD A: three additions, ORI 40H and ORA fresh AE03 yield `u8(C*8) OR 40H OR E`. Intermediate arithmetic flags are independently checked; the logical operations clear carry. No speculative REL item name is assigned.

The 14-byte E=6 block is DEDUCED / STATIC / UNOBSERVED from exact instructions, with synthetic destination-clear, common second-copy and source-address PUSH equations. Synthetic cases also cover self-copies, indices 0/1/4/5/6/7, cursor 127:7, and unsupported index/sentinel/stack/code/continuation rejection. All ten natural +793C components and +7B99 roots independently shadow registers, flags, SP/PC, ordered writes, full 64 KiB RAM, stack last writers, child/service/record chronology, DMA and filesystem. Checkpoint journals and hashes preserve the internal stages under ignored `_build/host-compiler-pass-58`.

No private frame is invented. Historical PUSH/POP carriers, child CALL words, service frames and the original RET derive surviving stack bytes. Both bounds are stable and local control flow is complete; contracts remain partial. Out-of-range indices, unsupported pending states, writer errors, position wrap, modes and aliases reject copied staging before live mutation. Canonical +7AE4 and emission children are reused internally without nested Runner transitions.

| Source | Pass57 guest | Pass58 guest | Removed | Host before → after | Roots |
|---|---:|---:|---:|---:|---:|
|MINIMAL|300443|300443|0|102 → 102|0|
|FIZZBUZ|570705|569925|780|287 → 277|10|
|PICTURE|346935|346935|0|90 → 90|0|

FIZZBUZ absorbs ten +7AE4 and ten +7557 roots, replacing them with ten +7B99 roots. Equivalent calls outside exact root windows remain enabled. Remaining external +119E counts are 36/36/43; remaining +7AE4 calls are 2/11/1, all under the separate +7E05 caller context. Standalone and cumulative hybrids preserve the exact REL goldens, REL/INT record chronology, filesystem, console, compiler markers, BDOS chronology/counts and warm boot.

RAW → UNDERSTOOD: +793C 102 bytes (including the 14 static/synthetic bytes), +7B99 25 bytes; total 127. DECODED/STRUCTURED promotions: zero. Historical reconstruction remains exactly 94720 bytes. Oracle queries: zero. Historical correction, pragmatic divergence and fidelity debt: none. The ADD and E=6 findings resolve supplied hypotheses, rather than correcting established contracts. Annotation development repairs are recorded in fidelity.json. Existing FACTOR/OPTIMIST historical totals are preserved; no additional natural coverage is claimed.

The packet is 13183 bytes. The deterministic driver handles inventory, route grouping, ownership, child checkpoints, component/root proofs, hybrids, hierarchy, residual maps, compact reports, semantic extraction and incremental validation. Interactive call count is not instrumented. The final validation receipt records category counts, test counts and timing.

semantic-extraction.json separates proved indexed-transfer/emission behavior from scratch addresses, paired reads, zero-extension, PUSH/POP carriers, field arithmetic and exact stack residue. It introduces no MIR API or faithful-code refactor.

+7B1B has a distinct input ABI and clear/emission operation and is deferred. +7E05 remains a broader generation family. Recommended Pass59 boundary: assess +7B1B before widening into +7E05. scripts/view-optimist.sh is untouched.
