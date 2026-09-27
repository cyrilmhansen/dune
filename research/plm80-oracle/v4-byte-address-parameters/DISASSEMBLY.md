# Absolute code disassembly

`BYADDR.HEX` contains 22 bytes in two type-00 records. LOCATE places CODE at
`3680H..3695H`, exactly matching those records. MAIN occupies relative code
offsets `0000H..000CH` (13 bytes); P begins at relative offset `000DH` /
absolute `368DH` and occupies 9 bytes.

| Address | Bytes | Intel 8080 instruction | Observation |
|---|---|---|---|
| `3680` | `31 A4 36` | `LXI SP,36A4H` | MAIN entry; initializes SP. |
| `3683` | `11 A4 36` | `LXI D,36A4H` | Loads `.OBJ` address directly into DE: D=`36H` (high), E=`A4H` (low). |
| `3686` | `0E 2A` | `MVI C,2AH` | Loads decimal 42, the first actual argument X. |
| `3688` | `CD 8D 36` | `CALL 368DH` | Call site; P entry is `368DH`. Immediately before CALL, C=`2AH`, DE=`36A4H`. |
| `368B` | `FB` | `EI` | MAIN completion sequence. |
| `368C` | `76` | `HLT` | MAIN completion sequence. |
| `368D` | `21 A7 36` | `LXI H,36A7H` | P entry; addresses the high-address byte of Y's formal allocation. |
| `3690` | `72` | `MOV M,D` | Stores D (`36H`) at `36A7H`, the higher address of Y's two-byte slot. |
| `3691` | `2B` | `DCX H` | Moves to `36A6H`, Y's lower-address byte. |
| `3692` | `73` | `MOV M,E` | Stores E (`A4H`) at `36A6H`. |
| `3693` | `2B` | `DCX H` | Moves to `36A5H`, X's one-byte formal allocation. |
| `3694` | `71` | `MOV M,C` | Stores C (`2AH`) at `36A5H`. |
| `3695` | `C9` | `RET` | P returns. |

The listing assigns OBJ relative data offset 0, X offset 1 and Y offset 2
(size 2). LOCATE starts DATA at `36A4H`, so OBJ=`36A4H`, X=`36A5H`, and
Y=`36A6H..36A7H`. The callee materializes Y first (high byte, then low byte),
then X. This is directly visible in the instructions and addresses above.

## Documented expectation and observed code

Intel's PL/M linkage-convention description says the first parameter follows
the single-parameter convention and the second uses D/E; for BYTE+ADDRESS,
that suggests C for X and DE for Y (D high, E low). See the Intel 8085
manual's [PL/M linkage conventions](https://laundry.manualsonline.com/manuals/mfg/intel/8085_1.html?p=25).
The located V4.0 code agrees for this sample: DE is loaded directly with the
address of OBJ, while C is loaded with 2AH. This supports, but does not prove,
a positional/type-width rule for other signatures.

## Quantitative comparison

| Fixture | CODE bytes | VARIABLE bytes | Maximum STACK |
|---|---:|---:|---:|
| `v4-micro` | 9 | 0 | 2 |
| `v4-byte-parameter` | 15 | 1 | 2 |
| `v4-address-parameter` | 24 | 5 | 2 |
| `v4-two-byte-parameters` | 19 | 2 | 2 |
| this BYTE+ADDRESS fixture | 22 | 4 | 2 |

Against the two-BYTE fixture this is +3 CODE and +2 VARIABLE bytes; against
one ADDRESS it is -2 CODE and -1 VARIABLE bytes; against one BYTE it is +7
CODE and +3 VARIABLE bytes; against the zero-argument fixture it is +13 CODE
and +4 VARIABLE bytes. Maximum STACK remains 2 in each comparison. These are
sample size deltas only.

All 22 bytes, including `LXI SP`, are in the compiler-reported CODE segment.
LINK includes only `BYADDR.OBJ(MAIN)`; no PLM80.LIB code was needed. LINK and
LOCATE add segment placement, not executable bytes outside this CODE range.
