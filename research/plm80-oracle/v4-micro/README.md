# First PL/M-80 code-generation fingerprint

This fixture preserves the first zero-argument procedure/call experiment from
the local Intel ISIS-II PL/M-80 V4.0 compiler, plus its LINK/LOCATE products.
The files were produced in the already established disposable ISIS-II work
disk; the toolchain disk was not modified. The console transcript records the
commands and their output.

## Environment and provenance

- Host: Linux, z80pack Intel Intellec MDS-800 simulator Release 1.39.
- Guest OS: ISIS-II V4.3.
- Compiler banner: `ISIS-II PL/M-80 COMPILER V4.0`.
- LINK banner: `ISIS-II OBJECT LINKER V3.0`.
- LOCATE banner: `ISIS-II OBJECT LOCATER V3.0` (spelling as printed).
- Toolchain files came from the local `disks/library/isis-ii-43.dsk` system
  disk candidate at `/home/john/pli/cpm/z80pack/intelmdssim`. Its recipe
  labels PLM80 and OV0–OV4 V4.0, but OV5–OV6 V3.1; this mixed overlay
  provenance remains unresolved.
- The source/listing/OBJ predate this LINK/LOCATE run and were preserved
  byte-for-byte from `/var/tmp/plm80-oracle-20260927-115215/`.

## Source and commands

`MICRO.PLM` is 61 bytes, CRLF line endings:

```plm
MAIN: DO;
P: PROCEDURE;
RETURN;
END P;
CALL P;
END MAIN;
```

The exact ISIS-II command sequence was:

```text
PLM80 :F0:MICRO.PLM DEBUG XREF
LINK :F0:MICRO.OBJ TO :F0:MICRO.SAT MAP PRINT(:F0:MICRO.LMP)
LOCATE :F0:MICRO.SAT TO :F0:MICRO.LOC MAP PRINT(:F0:MICRO.MAP)
OBJHEX :F0:MICRO.LOC TO :F0:MICRO.HEX
```

PLM80 reported `PL/M-80 COMPILATION COMPLETE. 0 PROGRAM ERRORS`. Its listing
reports CODE AREA SIZE `0009H`, VARIABLE AREA SIZE `0000H`, and MAXIMUM STACK
SIZE `0002H`. The PL/M cross-reference places `MAIN` at code offset `0000H`
with size 8 and `P` at offset `0008H` with size 1.

## Absolute code fingerprint

The locator map assigns CODE start `3680H`; the HEX output's type-00 record
also has address `3680H`, and its end record declares start address `3680H`.
The nine compiler-reported code bytes occupy `3680H..3688H` inclusive:

```text
3680  31 97 36       LXI SP,3697H
3683  CD 88 36       CALL 3688H
3686  FB             EI
3687  76             HLT
3688  C9             RET
```

Thus the module entry is `MAIN` at `3680H`; procedure `P` enters at `3688H`;
the call site is `3683H`; and `P` returns with the single-byte `RET` at
`3688H`. `EI; HLT` is the generated main-module termination sequence.

The LINK map lists only `:F0:MICRO.OBJ(MAIN)` as an included input module,
with CODE length 9 and STACK length 2. No library module or unresolved
external appears. The locator separately allocates STACK at `3689H..3696H`
and MEMORY at `3697H..F6BFH`. These are linker/locator segment placements,
not extra code bytes. The initial `LXI SP,3697H` is inside the 9-byte CODE
segment and therefore belongs to compiler-generated code; it is not an
additional runtime/startup stub inserted by LINK or LOCATE.

`PLM80.LIB` was not given to LINK and was not needed for this program: the
link map resolves the module from MICRO.OBJ alone. This says nothing about
other PL/M programs.

## Overlay-use question

This run did not instrument ISIS-II file OPENs. The ordinary compile output
does not establish whether the mixed-recipe OV5/OV6 files were opened. The
V4.0 operator documentation identifies the compiler code set as PLM80 plus
OV0–OV4, but that is not a per-run OPEN trace; OV5/OV6 use in this run remains
unverified.

## Preserved artifacts and SHA-256

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `MICRO.PLM` | 61 | `8fd4225b2d9b99c16348e5c9589b5587c001d17d8f46df3d66c09f7100fb1986` |
| `MICRO.LST` | 1087 | `87bd115091b6a73cefa5fcf6661501b82cc33cb62e36e1201ee67b7e909c58cc` |
| `MICRO.OBJ` | 137 | `829aa256632c92b89bde6426d639d314dbcb3d8e62c7af8adfa9f30cda706c5a` |
| `MICRO.SAT` (LINK output) | 140 | `e7850eee4d36c4a97ba4aaa0de8c300fb4ca39f310de7b0d452b643ec4b88f52` |
| `MICRO.LOC` (LOCATE output) | 109 | `0f105c8a2e5740948b2c625a64cb44c5928757085ff67082aa5a971e656e9640` |
| `MICRO.HEX` (OBJHEX output) | 44 | `932067234f99506dd774b2a1a8250cd3414ee9e34b18636d37b363c9457d9a6c` |
| `MICRO.LMP` (LINK map) | 359 | `5d1d5fed0c0469a2d3a9fba1cb69c252ee63a29921b5903e08bdca74c9ff0bf2` |
| `MICRO.MAP` (LOCATE map) | 360 | `992f7f5eadbd67f91c428a180abc0c3b3cde1629f609e12a0fab0ed82cc66174` |
| `console-link.typescript` | 4441 | `4eb734f2abb20b434850da474c5e68a8b9ceca1a9199b9a2710f53cab654f9b8` |

The `.HEX` records are preserved verbatim. Its data record is
`:09368000319736CD8836FB76C97E`; the start record is `:0036800149`.

## Remaining uncertainty

The installed system disk recipe combines compiler files attributed to two
versions. The V4.0 banner and successful run establish the reported compiler
version, not the exact provenance/version of every overlay actually loaded.
No attempt was made to trace overlay OPENs because that would require extra
simulator instrumentation beyond this compact experiment.

## Primary documentation consulted

- Intel, *ISIS-II PL/M-80 Compiler Operator's Manual*, Apr. 1981,
  [archival PDF](https://mark-ogden.uk/files/intel/publications/9800300-03%20ISIS-II%20PLM-80%20Compiler%20Operators%20Manual-Apr81.pdf).
- Intel, *ISIS-II User's Guide*, Order 9800306-06, May 1981,
  [Bitsavers archival copy](https://bitsavers.trailing-edge.com/pdf/intel/ISIS_II/9800306-06_ISIS-II_Users_Guide_May81.pdf). The “Working With Program Modules” chapter documents LINK/LOCATE behavior and controls; “File Creation and Management” documents OBJHEX.
