# PL/M-80 BYTE parameter code-generation fingerprint

This fixture changes one language feature relative to
[`../v4-micro`](../v4-micro/README.md): procedure `P` receives one BYTE
argument, called with constant decimal 42. The program performs no I/O and
uses no unrelated language features.

## Source and environment

`BYTE.PLM` is preserved exactly (87 bytes, CRLF, SHA-256
`ad29be9580d27d72b52868d11094c414eeb926660c97b559e61b20745d044c24`).
The ISIS copy was round-tripped and matched these exact bytes.

- Simulator: z80pack Intel Intellec MDS-800 Simulator Release 1.39.
- Guest: ISIS-II V4.3.
- Compiler-reported version: ISIS-II PL/M-80 Compiler V4.0.
- LINK: ISIS-II Object Linker V3.0.
- LOCATE: ISIS-II Object Locater V3.0.
- Exact commands and all console output are in `console.typescript`.
- `BYTE.LST` reports CODE 15 (`000FH`), VARIABLE 1 (`0001H`), maximum STACK
  2 (`0002H`), and zero program errors.
- `BYTE.LMP` includes only `BYTE.OBJ(MAIN)`. PLM80.LIB was not needed for
  this program.
- `BYTE.MAP` assigns CODE `3680H..368EH`, STACK `368FH..369CH`, DATA
  `369DH`, and MEMORY beginning `369EH`.

The absolute bytes are in the type-00 data record in `BYTE.HEX`. See
[`DISASSEMBLY.md`](DISASSEMBLY.md) for the byte-for-byte disassembly and
limited argument-passing observation.

## Reproducible command sequence

On the already established local ISIS-II V4.3 system, the commands were:

```text
COPY :CI: TO :F0:BYTE.PLM
PLM80 :F0:BYTE.PLM DEBUG XREF
LINK :F0:BYTE.OBJ TO :F0:BYTE.SAT MAP PRINT(:F0:BYTE.LMP)
LOCATE :F0:BYTE.SAT TO :F0:BYTE.LOC MAP PRINT(:F0:BYTE.MAP)
OBJHEX :F0:BYTE.LOC TO :F0:BYTE.HEX
```

The experiment used disposable copies of the existing local system and hard
disk images. The source toolchain images were not modified. Their SHA-256
identities are recorded in `manifest.json`.

## Observations versus unresolved provenance

The compiler banner and listing establish the reported V4.0 compiler. They do
not prove the provenance of every overlay on the local mixed-recipe disk.
That disk recipe labels PLM80 and OV0–OV4 V4.0, but OV5–OV6 V3.1. This
experiment did not instrument file opens, so actual OV5/OV6 use is unknown.
Do not infer a general PL/M ABI or compiler-overlay provenance from this
single small program.

Artifact byte sizes, hashes, input image hashes, and the structured experiment
metadata are in `manifest.json`.
