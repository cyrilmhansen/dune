# PL/M-80 V4.0 local BYTE fingerprint

This small fixture observes one procedure with no parameters and one local
`BYTE`, assigned decimal 42 (`2AH`). `LOCALB.PLM` is the preserved host source;
the ISIS-II short basename used for the build was `LOCVAR`.

## Result and direct observations

PL/M-80 V4.0 reported zero program errors. Its listing reports CODE=14 bytes,
VARIABLE=1 byte, and maximum STACK=2 bytes. The linker includes only
`LOCVAR.OBJ(MAIN)`; no library module was needed. LOCATE places CODE at
`3680H..368DH`, STACK at `368EH..369BH`, and DATA at `369CH`.

The cross-reference listing assigns `LOCAL` offset `0000H`, size 1. In the
located code, procedure `P` executes `LXI H,369CH; MVI M,2AH; RET`. Thus this
sample's local is in the one-byte VARIABLE/DATA area at `369CH`; it is not
allocated on P's stack. The address is formed as an immediate 16-bit constant
in HL and the nonzero value is stored through M. P's reported stack use is
zero; the main procedure's CALL accounts for the two-byte maximum stack.

This is a direct observation about this exact procedure and compiler output.
It does not establish how PL/M-80 allocates locals for recursion, reentrancy,
arrays, multiple procedures, or other storage classes.

## Comparison

| Fixture | CODE | VARIABLE | Maximum STACK |
|---|---:|---:|---:|
| zero-argument call (`v4-micro`) | 9 | 0 | 2 |
| one BYTE parameter | 15 | 1 | 2 |
| one ADDRESS parameter | 18 | 3 | 2 |
| one local BYTE (this fixture) | 14 | 1 | 2 |

Relative to `v4-micro`, this sample has 5 more CODE bytes, one VARIABLE byte,
and unchanged maximum STACK. The single-BYTE-parameter comparison has the
same VARIABLE and STACK sizes, with this sample's CODE one byte smaller.
These are sample-specific comparisons, not general code-size rules.

## Reproduction

The established headless ISIS-II V4.3 environment was used with PL/M-80
Compiler V4.0, LINK V3.0, and LOCATE V3.0. The durable launch and SPACE
handshake are documented in [`../HEADLESS-ISIS-II.md`](../HEADLESS-ISIS-II.md).
The commands were:

```text
COPY :CI: TO :F0:LOCVAR.PLM
PLM80 :F0:LOCVAR.PLM DEBUG XREF
LINK :F0:LOCVAR.OBJ TO :F0:LOCVAR.SAT MAP PRINT(:F0:LOCVAR.LMP)
LOCATE :F0:LOCVAR.SAT TO :F0:LOCVAR.LOC MAP PRINT(:F0:LOCVAR.MAP)
OBJHEX :F0:LOCVAR.LOC TO :F0:LOCVAR.HEX
DIR FOR LOCVAR.*
```

The compiler console transcript is in `console.typescript`; the host paper-
tape copies are recorded in `ptp-capture.typescript`. The latter captures
each `:HP:` transfer. Each stream had a 120-byte zero leader and a 120-byte
zero trailer around the file payload; the leader was stripped and the payload
was cut at the exact byte count reported by ISIS-II `DIR`. All trailer bytes
removed were zero. Artifact sizes and SHA-256 hashes are in `manifest.json`.

## Provenance limit

The local ISIS-II disk recipe has previously been described as mixing PLM80
V4.0 overlays 0–4 and V3.1 overlays 5–6. The banner identifies the compiler's
reported version; this experiment did not trace overlay opens and does not
resolve individual overlay provenance or use.
