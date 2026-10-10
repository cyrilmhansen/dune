# Pass62 — paired carrier publication

The implementation baseline is published Pass61 `a409348e69e69e6760a0defc9b275ec1d30393c0`. Pass62 implementation was published separately as `90a7e9b8dc45f75fb8d158a6f2c7fc9fb3281694`, and the scheduled FULL checkpoint was subsequently completed manually and certified by commit `6d736b084417a64464d5868cf1946f735298a611`.

The FULL checkpoint passed initially: **92 categories, 643 distinct Python tests, 39 Dune stanzas, four workers, 2932.110 seconds wall time, 10788.750 summed category seconds, zero reruns**. Historical reconstruction remains exactly **94,720 bytes**. Pass62 is now the current FULL-checkpoint baseline. See [validation.json](validation.json) for the complete receipt.

## Entry, topology and scope

The real entry is PLI2.OVL+7338, with exact bounds `[7338,7365)` (**45 bytes**, rather than the approximate 43). No overlapping natural entry was found. All calls originate at +809D inside the broader +8072 policy. Primary logical/external counts are MINIMAL 3, FIZZBUZ 11 and PICTURE 4. Each root contains exactly two +7314 calls. FACTOR adds five independently shadowed roots and ten corresponding children. Prior FACTOR/OPTIMIST catalog totals are preserved.

Natural C values are 0, 2 and 4. [inventory-summary.json](inventory-summary.json) retains the complete C/D/E tuples, callers and returns; [route-summary.json](route-summary.json) records individual carrier distributions, early-return coverage and wrapping coverage. No natural C=6 case occurs. The early RET at +7348 has independent synthetic CPU proof and remains **DEDUCED / STATIC / UNOBSERVED**.

## Exact historical law

The parent writes ADBF=D, ADBE=E, ADBD=C, in that order. HL descends through these addresses; the saves preserve flags. A fresh ADBD read and CPI 6 select the early return.

Otherwise the parent independently reads the little-endian words at ADBE and ADBD. These reads select saved D as E and saved C as C for canonical +7314 at +7352. The first child publishes the relation `(C,D)`. Its supported table and scratch writes do not overlap ADBD..ADBF.

After the first child, a fresh ADBD read and INR compute `u8(C+1)`. INR replaces NZPA and preserves CY. Another paired ADBE read obtains saved E/D. PUSH PSW at +735C writes the incremented accumulator high and packed flags low below SP. MOV A,L and MOV E,A select saved E. POP B restores B as the incremented selector and temporarily C as the packed flags byte; MOV C,B restores the selector. Canonical +7314 at +7361 publishes `(u8(C+1),E)`. RET +7364 consumes the original continuation.

No cached entry values replace the fresh paired reads, flags or actual stack transport. Canonical +7314 is unchanged. Accepted scope is C=0..5 for two publications, plus C=6 for early return. Bounds are stable and local CFG complete; the general contract remains partial. C=7 rejects because its second child would use index 8. C=FF rejects because its first child index is unsupported; the parent does not pretend to support global wrapping indices. Code, caller, continuation, scratch/table, stack and sentinel aliases fail closed during copied staging. Both child indices are validated before any live mutation.

## Independent proofs and stack

All 18 primary and five FACTOR roots independently match registers, flags, SP/PC, ordered writes, all 65536 RAM bytes, stack last writers, child chronology, DMA, filesystem and record/service state. Canonical +7314 has separate useful global shadows: 8/33/9 primary calls and 12 FACTOR calls. Natural per-instruction checkpoints retain carrier saves, CPI, paired reads, both child windows, INR, PUSH/POP and RET. Full journals remain ignored under `_build/host-compiler-pass-62`; [shadow-summary.json](shadow-summary.json) retains hashes.

There are 54 targeted primary synthetic proofs: C=0, C=5 and C=6 with distinct D=91/E=2C, repeated at each natural entry state. The original concrete CPU independently compares full registers/flags/RAM, ordered writes and stack writer chronology. C=6 returns with A=6 and CPI flags, original BC/DE, HL=ADBD and only the three scratch writes. Unsupported C=7/7F/FE/FF and alias negatives reject before publication.

There is no private frame. The entry CALL word stays at entry SP. First child CALL writes continuation runtime 9555 below SP; canonical +7314 leaves its actual deeper PUSH/POP address carrier. Parent PUSH PSW reuses the child CALL slots, and POP B restores SP. Second child CALL overwrites those slots with runtime 9564 and leaves its own deeper residue. Final RET returns to the original caller with SP=entrySP+2. Last-writer journals account for surviving bytes, including overwritten PSW carriers.

## Measured hierarchy and hybrids

| Source | Pass61 → Pass62 guest | Removed | Host before → after | Roots |
|---|---:|---:|---:|---:|
|MINIMAL|300032 → 299837|195|99 → 102|3|
|FIZZBUZ|567517 → 566802|715|247 → 258|11|
|PICTURE|346578 → 346318|260|89 → 93|4|

The task's predicted minus-one transition per root assumed standalone +7314 interceptors. Current +7314 is a canonical internal primitive, **not an enabled Runner boundary**. External residual calls were guest work. The new parent therefore adds one measured transition per root and absorbs two guest +7314 calls, with no previously enabled native roots suppressed. No artificial leaf interceptor was added to manufacture the predicted savings. External +7314 becomes 0/0/0; +119E remains 36/36/43. Suppression is confined to exact accepted windows.

Standalone and cumulative hybrids preserve exact REL hashes, full REL/INT record chronology, filesystem, console, PASS1/PASS2/END, BDOS ordering/counts and warm boot. The hashes are:

- MINIMAL: `7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119`
- FIZZBUZ: `68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`
- PICTURE: `c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1`

## Archaeology and next boundary

RAW → UNDERSTOOD: 45; DECODED → UNDERSTOOD: 0; STRUCTURED → UNDERSTOOD: 0. Of the 45 represented bytes, 44 are naturally OBSERVED and 1 is DEDUCED / STATIC / UNOBSERVED (early RET). Prior canonical children are unchanged. Historical reconstruction remains exactly 94720 bytes. Oracle queries: zero. There is no historical correction, implementation correction or pragmatic divergence. The size and Runner-boundary findings correct task orientation/accounting, not historical behavior. Fidelity debt is explicit bounded index/alias scope and unproved higher compiler meaning.

[semantic-extraction.json](semantic-extraction.json) separates the possible adjacent relation publication concept from scratch addresses, paired reads, byte flags, PSW transport and hardware stack machinery. There is no faithful-code refactor or MIR/API design.

The immediate +8072 parent also uses +7ED6, +75CE, +7619 and sometimes +7A17; its wider generation policy is deferred. [next-boundary-ranking.json](next-boundary-ranking.json) compares +829C field generation, +82DD lifecycle/finalization and true +7ED6. All four PICTURE-only +7365 callsites (+7FBA/+7FD9/+8015/+802B) belong to +7ED6; they are not separate entries. +829C is the preferred compact Pass63 assessment, while +82DD has greater residual leverage but introduces a separate finalization/output lifecycle. Ranking values are not savings.

Packet: 13728 bytes. Driver phases automate discovery/inventory, contracts, component/root proofs, cross-evidence, topology, ranking, reports, focused checks and full-checkpoint dispatch. Interactive call count is not instrumented. Full logs remain ignored under `_build`. `scripts/view-optimist.sh` is untouched.
