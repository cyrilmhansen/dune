# PL/M-80 BYTE + ADDRESS parameter fingerprint

This fixture tests one minimal two-parameter call: first a BYTE actual with
value 42, then an ADDRESS actual naming the statically allocated BYTE `OBJ`.
The short ISIS-II basename is `BYADDR`; this directory is named
`v4-byte-address-parameters`.

`BYADDR.PLM` is the exact source, preserved as 137 CRLF bytes. It was copied
back from the guest paper-tape output and compared byte-for-byte with the
fixture source. PL/M-80 V4.0 reported zero program errors.

## Expectation versus observation

Intel's documented linkage convention says the first of two parameters is
passed as in the one-parameter case and the second in D/E; for the types here,
the expectation is X in C and Y in DE (D high, E low). The cited description
is in Intel's [PL/M linkage conventions](https://laundry.manualsonline.com/manuals/mfg/intel/8085_1.html?p=25).

The exact located V4.0 code sets DE directly with `LXI D,36A4H` (the address
of OBJ), sets C with `MVI C,2AH`, then calls P. The callee stores D and E to
Y's two-byte formal allocation, high byte at `36A7H` then low byte at
`36A6H`, and stores C to X at `36A5H`. See [`DISASSEMBLY.md`](DISASSEMBLY.md)
for the complete byte-by-byte decoding.

These are sample-specific emitted instructions and allocations. Together
with the prior one- and two-parameter fixtures, they strengthen the C+DE
expectation for this signature, but do not establish a general register
allocation algorithm. In particular, the inverse `ADDRESS + BYTE` ordering
is still required before drawing a stronger positional/type-width conclusion.
Other arities, mixed signatures, expression evaluation, nesting and
reentrancy remain untested.

## Environment and commands

- Simulator: z80pack Intel Intellec MDS-800 Simulator Release 1.39.
- Guest OS: ISIS-II V4.3.
- Compiler banner: `ISIS-II PL/M-80 COMPILER V4.0`.
- LINK: `ISIS-II OBJECT LINKER V3.0`.
- LOCATE: `ISIS-II OBJECT LOCATER V3.0` (printed spelling).
- The source disk recipe labels PLM80 and OV0–OV4 V4.0, but OV5–OV6 V3.1.
  This experiment did not trace overlay opens, so actual per-overlay
  provenance/use remains unresolved.

Commands on disposable copies of the existing three ISIS-II disk images:

```text
COPY :CI: TO :F0:BYADDR.PLM
PLM80 :F0:BYADDR.PLM DEBUG XREF
LINK :F0:BYADDR.OBJ TO :F0:BYADDR.SAT MAP PRINT(:F0:BYADDR.LMP)
LOCATE :F0:BYADDR.SAT TO :F0:BYADDR.LOC MAP PRINT(:F0:BYADDR.MAP)
OBJHEX :F0:BYADDR.LOC TO :F0:BYADDR.HEX
```

The preserved console transcript, listing, object/link/locate outputs, maps,
HEX, and their hashes are included here and indexed by `manifest.json`. The
listing reports CODE `0016H` (22 bytes), VARIABLE `0004H` (4 bytes), maximum
STACK `0002H` (2 bytes). LOCATE assigns CODE `3680H..3695H`, STACK
`3696H..36A3H`, and DATA `36A4H..36A7H`. The LINK map lists only
`BYADDR.OBJ(MAIN)`, so PLM80.LIB was not needed for this sample.

## Epistemic limits

The code shows this caller constructing the ADDRESS actual directly in DE;
it does not show whether other ADDRESS expressions or mixed parameter lists
use the same sequence. The callee's observed high-then-low stores are facts
about this formal allocation, not proof of a general callee prologue pattern.
The mixed-recipe overlay provenance caveat is unchanged.
