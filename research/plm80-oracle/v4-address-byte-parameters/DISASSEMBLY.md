# Absolute code disassembly

`ADBYTE.HEX` contains 22 bytes in two type-00 records. LOCATE places CODE at
`3680H..3695H`, matching those records. MAIN occupies relative code offsets
`0000H..000CH` (13 bytes); P begins at relative offset `000DH` / absolute
`368DH` and occupies 9 bytes.

| Address | Bytes | Intel 8080 instruction | Observation |
|---|---|---|---|
| `3680` | `31 A4 36` | `LXI SP,36A4H` | MAIN entry; initializes SP. |
| `3683` | `1E 2A` | `MVI E,2AH` | Loads decimal 42, the second actual Y. |
| `3685` | `01 A4 36` | `LXI B,36A4H` | Loads `.OBJ` address into BC: B=`36H` high, C=`A4H` low. |
| `3688` | `CD 8D 36` | `CALL 368DH` | Call site; P entry is `368DH`. Immediately before CALL, BC=`36A4H` and E=`2AH`. The caller does not set D as part of either argument. |
| `368B` | `FB` | `EI` | MAIN completion sequence. |
| `368C` | `76` | `HLT` | MAIN completion sequence. |
| `368D` | `21 A7 36` | `LXI H,36A7H` | P entry; addresses Y's byte. |
| `3690` | `73` | `MOV M,E` | Stores E (`2AH`) at Y=`36A7H`. |
| `3691` | `2B` | `DCX H` | Moves to `36A6H`, X's higher-address byte. |
| `3692` | `70` | `MOV M,B` | Stores B (`36H`) at `36A6H`. |
| `3693` | `2B` | `DCX H` | Moves to `36A5H`, X's lower-address byte. |
| `3694` | `71` | `MOV M,C` | Stores C (`A4H`) at `36A5H`. |
| `3695` | `C9` | `RET` | P returns. |

The listing assigns OBJ offset 0, X offset 1 with size 2, and Y offset 3.
DATA begins at `36A4H`, so OBJ=`36A4H`, X=`36A5H..36A6H`, and Y=`36A7H`.
The callee materializes Y first from E, then X from B/C. For X, B is stored
at the higher address and C at the lower address, consistent with the
observed ADDRESS value `BC=36A4H`.

## Documented expectation versus observed code

Intel's PL/M linkage-convention description says the first parameter follows
the one-parameter convention and the second uses D/E; applied to this
signature, that predicts X ADDRESS in BC (B high, C low) and Y BYTE in E.
See Intel's [PL/M linkage conventions](https://laundry.manualsonline.com/manuals/mfg/intel/8085_1.html?p=25).
The V4.0 output agrees for this sample. D is not set by the argument
preparation and is not read to materialize either formal; its value is not
established here.

## Comparison with the preceding fingerprints

| Fixture | CODE bytes | VARIABLE bytes | Maximum STACK | Observed arguments |
|---|---:|---:|---:|---|
| `v4-micro` | 9 | 0 | 2 | none |
| `v4-byte-parameter` | 15 | 1 | 2 | one BYTE in C |
| `v4-address-parameter` | 24 | 5 | 2 | one ADDRESS in BC |
| `v4-two-byte-parameters` | 19 | 2 | 2 | BYTE/BYTE: C, E |
| `v4-byte-address-parameters` | 22 | 4 | 2 | BYTE/ADDRESS: C, DE |
| this ADDRESS/BYTE fixture | 22 | 4 | 2 | ADDRESS/BYTE: BC, E |

Relative to BYTE+ADDRESS, CODE, VARIABLE and STACK sizes are unchanged. The
deltas against the two-BYTE fixture are +3 CODE / +2 VARIABLE; against one
ADDRESS, -2 / -1; against one BYTE, +7 / +3; and against no arguments, +13 /
+4. Stack remains 2 for each comparison. These are measurements of these
samples only.

The three two-parameter fixtures together exhibit a positional-width pattern
consistent with Intel's documented convention: position 1 BYTE uses C or
ADDRESS uses BC; position 2 BYTE uses E or ADDRESS uses DE. This is evidence
from the tested signatures, not a complete allocation algorithm. In
particular, the next three-parameter experiment is needed to investigate what
happens when parameter count exceeds these observed register slots.

All 22 bytes, including `LXI SP`, are in compiler-reported CODE. LINK includes
only `ADBYTE.OBJ(MAIN)`; PLM80.LIB was not needed for this sample.
