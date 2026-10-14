# Pass94 — selected +6726/+667A front and +21AE predicate

Baseline `9e9a678184cdbb747920619557051e2c3d581c99`. Proof-only operations; no runtime interceptor changes.

The immutable OPTIMIST selector-4 journal matches its published SHA256 before inspection. Actual CALLs are +67DE→+6726 (word89E1), +672E→+667A (8931). The latter window has15,029 instructions; its selected +6792 ancestor has15,049. +6726 freshly reads both bytes of AD0F and AD0D, supplies C and DE, then calls +667A. The child copies E into D, PUSHes DE and increments SP, duplicates C into B, PUSHes BC and increments SP: two surviving one-byte private arguments, not two normal words. Its first direct child is +21AE. +2269 is reached later, inside nested k105; it is not the first direct +667A child.

Complete +21AE saves C at AD2A, freshly reloads the pair, invokes unchanged canonical +047D, writes the actual mapped index, computes the lower/upper range masks with SUI/SBB/CMA and SUB/SBB/CMA, preserves one mask through PUSH PSW/POP BC, then ANA with the actual other mask. Every subtraction's CY/AC and final ANA's 8080 AC are computed. No recorded lookup result or Boolean is supplied to the algorithm.

The selected composed prefix includes +6726, private frame construction, +21AE, RAR and the carry-set branch, fresh private argument read and actual +6691 CALL. It stops at41B5 before executing unproved k27. CPU shadow:52 instructions,17 ordered writes,13 owned reads, all registers/flags/PC/SP, full64KiB RAM, writer sites, DMA/filesystem and service chronology exact. It leaves SP six below +6726 entry; the original89E1/8F4A/42B4 ancestry words survive. Carry-clear +66A0 is excluded.

Standalone predicate shadows cover ten natural OPTIMIST calls at the three actual caller sites, including both Boolean outcomes. Each has31 instructions,7 writes and7 owned reads; canonical lookup read laws are inherited. Forty independent concrete CPU discriminants vary incoming CY/AC and stale AD2A, checking complete CPU/RAM and ordered writes. Stale scratch cannot bypass its historical overwrite. Synthetic cases do not establish additional OBSERVED coverage.

Preparation copies RAM and stages every write, including same-valued and private stack writes. Code corruption rejects without live mutation. High-stack bounds exclude scratch/code overlap; unchanged canonical eligibility guards remain in force. Unexpected child failures propagate. No captured exit state or guest callback computes host effects.

Focused validation:5/5 categories,20 Python executions, four workers;16.134s wall/16.318s summed. Actual receipt retained byte-for-byte. All five REL/INT goldens match Pass74. Existing verifier independently confirms94,720 exact reconstruction bytes, image/section hashes and mappings. No annotations/classifications, knowledge promotions, native roots or oracle queries. No FULL run; Pass74 remains certified epoch3. All earlier evidence and installed controller remain unchanged.

Next: k27 +22EA's actual private AD08 byte and +21AE-controlled branch, then nested k105 at +2329. k27/k105/k84 and k216 remain incomplete; dispatcher remains7/8.
