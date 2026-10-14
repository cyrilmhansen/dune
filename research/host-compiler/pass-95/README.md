# Pass95 — k27 private-byte handler segments

Baseline `4d5ce29b7a85ae240f92d3c40ebf069571257394`. Two independently executable segments of PLI2+22EA, not a complete handler or gateway transaction.

The actual software entry uses20AF PUSH42B4/PCHL. +22EA decrements SP by one, freshly reads AD08, stores it in that private slot, and clears live AD08. It freshly loads AD0D into C, CALLs the unchanged Pass94 +21AE contract, executes RAR, and follows the proved carry-clear route. A second independent AD0D pair read supplies C to the actual +2329 gateway CALL. The prefix stops at41B5; no unresolved gateway output is injected. Its final SP is entry-3: one private byte plus a real hardware word452C. Carry-set +2303 remains excluded.

The separately executable +2348..+2351 suffix freshly addresses the current private slot, reads its surviving value, writes AD08, increments SP, then RETs through the original software42B4 word. Last-writer evidence identifies +22F2 as the private slot's writer and +20AF as the software word's writer. No synthetic normal CALL frame is introduced. This suffix does not prove the intervening children.

All three natural OPTIMIST entries and all three return segments independently match CPU registers/flags, PC/SP, full64KiB RAM, ordered writes and writer sites, owned reads, DMA/filesystem and service chronology. Each prefix:46 instructions/13 writes/12 owned reads; each suffix:6/1/3. Canonical lookup read laws are inherited through independently checked +21AE. Twenty-four independent CPU discriminants vary saved AD08/private-slot bytes and incoming CY/AC; complete state/RAM and ordered writes agree. Code corruptions reject without live mutation; canonical child errors propagate. Every host effect derives from current state.

The archived three k27 gateway contexts have descriptor434E, handler44EA, initial candidate count0, zero scans, j2 fallback pointer3BF6 and FB/FC tokens. These are verified historical inventory facts, not a widened applicability predicate. Pass93 scanned-predicate record guards do not authorize these indices. The complete k27 fallback/frame transaction remains unproved. Its whole handler still requires k105 at+2329, counter+79D7, k84 at+2333 and subsequent predicate/output children; no installed controller changed.

Focused validation:5/5 categories,20 Python executions, four workers,16.322s wall/16.521s summed; actual receipt preserved. All five REL/INT goldens match. Reconstruction-bearing inputs remain byte-identical to Pass94's independently verified94,720 bytes. No annotations, knowledge promotions, native roots or oracle queries. No FULL; Pass74 remains certified epoch3 and historical failures remain intact.

Next in actual execution order: k105 +2352→canonical+052C→+2269. +2269 requires +21CD, canonical+052C, the actual +16F8 zero-return leaf, indexed carrier+77BF and the established +7D31 operation. Full k27/k216 and dispatcher7/8 remain unchanged.
