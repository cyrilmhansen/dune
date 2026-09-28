# PL/M-80 V4.0 local ADDRESS fingerprint

This fixture isolates a parameterless procedure `P` containing one local
`ADDRESS`, assigned the address of one static `BYTE` object `OBJ` in `MAIN`.
The preserved host source is `LOCALAD.PLM`; the ISIS-II basename is
`LOCADR`.

## Result and direct observations

PL/M-80 V4.0 reported zero program errors. The listing reports CODE=15 bytes,
VARIABLE=3 bytes, and maximum STACK=2 bytes. The LINK map includes only
`LOCADR.OBJ(MAIN)`; no library module was required. LOCATE assigns CODE
`3680H..368EH`, STACK `368FH..369CH`, and DATA `369DH..369FH`.

The cross-reference listing assigns `OBJ` DATA offset `0000H`, size 1, and
`LOCAL` offset `0001H`, size 2. With the locator's DATA base, these are
`OBJ=369DH` and `LOCAL=369EH..369FH`. The local ADDRESS is therefore exactly
two bytes in the VARIABLE/DATA area for this sample, not on P's stack.

P executes `LXI H,369DH; SHLD 369EH; RET`. `LXI H` forms the address of
`OBJ`; `SHLD` stores L at `369EH` and H at `369FH`. The resulting bytes are
`9DH 36H` in increasing memory-address order, the little-endian representation
of `369DH`. P's listing reports stack use zero; the main procedure's CALL
accounts for the two-byte maximum stack.

These facts come from this listing, locator map, and exact located bytes. They
do not establish a general storage or reentrancy model for ADDRESS locals.

## Comparison

| Fixture | CODE | VARIABLE | Maximum STACK |
|---|---:|---:|---:|
| zero-argument call (`v4-micro`) | 9 | 0 | 2 |
| local BYTE (`v4-local-byte`) | 14 | 1 | 2 |
| one ADDRESS parameter (`v4-address-parameter`) | 18 | 3 | 2 |
| local ADDRESS (this fixture) | 15 | 3 | 2 |

Relative to the local-BYTE fixture, this sample adds 1 CODE byte and 2
VARIABLE bytes, with no stack change. Relative to the one-ADDRESS-parameter
fixture it has 3 fewer CODE bytes and equal VARIABLE/STACK sizes. Relative to
`v4-micro`, the deltas are +6 CODE, +3 VARIABLE, and unchanged STACK. These
are comparisons among these exact programs only.

## Reproduction

The established headless ISIS-II V4.3 environment was used with PL/M-80
Compiler V4.0, LINK V3.0, and LOCATE V3.0. The launch and SPACE handshake are
documented in [`../HEADLESS-ISIS-II.md`](../HEADLESS-ISIS-II.md). Commands:

```text
COPY :CI: TO :F0:LOCADR.PLM
PLM80 :F0:LOCADR.PLM DEBUG XREF
LINK :F0:LOCADR.OBJ TO :F0:LOCADR.SAT MAP PRINT(:F0:LOCADR.LMP)
LOCATE :F0:LOCADR.SAT TO :F0:LOCADR.LOC MAP PRINT(:F0:LOCADR.MAP)
OBJHEX :F0:LOCADR.LOC TO :F0:LOCADR.HEX
DIR FOR LOCADR.*
```

Compiler output is preserved in `console.typescript`. Host `:HP:` artifact
copies are in `ptp-capture.typescript`. As recorded in the manifest, each
paper-tape transfer contained a 120-byte zero leader and trailer around the
file; the leader was stripped and the payload cut to the ISIS `DIR` length,
with only zero trailer bytes removed. Artifact sizes and hashes are in
`manifest.json`.

## Provenance limit

The local disk recipe has previously been described as mixing PLM80 V4.0
overlays 0–4 and V3.1 overlays 5–6. The V4.0 banner does not establish the
provenance or use of every overlay; this experiment did not trace overlay
opens.
