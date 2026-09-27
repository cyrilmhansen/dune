# PL/M-80 ADDRESS parameter code-generation fingerprint

This is the next minimal local PL/M-80 V4.0 experiment after
[`v4-byte-parameter`](../v4-byte-parameter/README.md). It has one procedure
with one ADDRESS parameter, called with the address of a one-byte statically
allocated object. The procedure copies the parameter into a static ADDRESS
variable so the generated code must use the received value. There is no I/O.

## Environment and source

`ADDR.PLM` is 147 bytes with CRLF line endings. Its SHA-256 is
`a9f9c45dd2057c4d0947c8b2ce4c52db75faf9cbcedfc7cd09c05c91575efe2a`.
It was entered through ISIS console input and round-tripped through the
paper-tape punch path; the extracted bytes match the fixture source.

- Simulator: z80pack Intel Intellec MDS-800 Simulator Release 1.39.
- Guest OS: ISIS-II V4.3.
- Compiler-reported version: ISIS-II PL/M-80 Compiler V4.0.
- LINK: ISIS-II Object Linker V3.0.
- LOCATE: ISIS-II Object Locater V3.0.
- The compiler listing reports zero errors, CODE 24 (`0018H`), VARIABLE 5
  (`0005H`), and maximum STACK 2 (`0002H`).
- LINK includes only `ADDR.OBJ(MAIN)`; no library module is listed.
- LOCATE places CODE at `3680H..3697H`, STACK at `3698H..36A5H`, DATA at
  `36A6H..36AAH`, and MEMORY from `36ABH`.

The absolute bytes and disassembly are in `ADDR.HEX` and
[`DISASSEMBLY.md`](DISASSEMBLY.md). Exact sizes and hashes are in
`manifest.json`; the guest-console transcript is preserved in
`console.typescript`. In that readable transcript, `<Ctrl-Z>` denotes the
single `1AH` end-of-input keystroke; it is notation, not a literal source
line. The separate listing and maps preserve their original captured bytes.

## Reproducible ISIS-II commands

The compiler/linker sequence matches the existing fixtures, with the
experiment basename changed to ADDR:

```text
PLM80 :F0:ADDR.PLM DEBUG XREF
LINK :F0:ADDR.OBJ TO :F0:ADDR.SAT MAP PRINT(:F0:ADDR.LMP)
LOCATE :F0:ADDR.SAT TO :F0:ADDR.LOC MAP PRINT(:F0:ADDR.MAP)
OBJHEX :F0:ADDR.LOC TO :F0:ADDR.HEX
```

The local toolchain disk candidates were used through disposable working
copies; source toolchain images were not modified. Their hashes are recorded
in `manifest.json`.

## Comparison and limits

Compared with v4-byte-parameter, code grows from 15 to 24 bytes (+9), variable
area from 1 to 5 bytes (+4), and maximum stack remains 2 (delta 0). MAIN grows
from 10 to 11 code bytes; P grows from 5 to 13. The emitted sequence changes
from loading the BYTE constant into C to loading OBJ's address into BC. P
stores BC into the parameter allocation, reloads it into HL, and copies it to
SAVED. This is a comparison of these exact samples only.

Unresolved: the mixed-recipe ISIS disk labels PLM80/OV0–OV4 V4.0 and OV5–OV6
V3.1, but this run did not trace which overlays were opened. One sample does
not establish the general ADDRESS calling convention, parameter storage
strategy, or behavior for other address expressions and object layouts.
