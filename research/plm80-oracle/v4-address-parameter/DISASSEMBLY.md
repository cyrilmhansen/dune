# Absolute code disassembly

`ADDR.HEX` contains two type-00 data records totaling 24 bytes. The LOCATE
map places the CODE segment at `3680H..3697H`, matching the records. STACK
and DATA are separate segments at `3698H..36A5H` and `36A6H..36AAH`.

| Address | Bytes | Intel 8080 instruction | Direct observation |
|---|---|---|---|
| `3680` | `31 A6 36` | `LXI SP,36A6H` | Main entry; initial SP is DATA start. |
| `3683` | `01 A6 36` | `LXI B,36A6H` | Loads `OBJ` address into BC. |
| `3686` | `CD 8B 36` | `CALL 368BH` | Call site; P entry is `368BH`. |
| `3689` | `FB` | `EI` | Main completion sequence. |
| `368A` | `76` | `HLT` | Main completion sequence. |
| `368B` | `21 AA 36` | `LXI H,36AAH` | P entry; points to the high byte of X's two-byte area. |
| `368E` | `70` | `MOV M,B` | Stores B at `36AAH`. |
| `368F` | `2B` | `DCX H` | Moves to `36A9H`. |
| `3690` | `71` | `MOV M,C` | Stores C at `36A9H`. |
| `3691` | `2A A9 36` | `LHLD 36A9H` | Loads the saved parameter pair into HL. |
| `3694` | `22 A7 36` | `SHLD 36A7H` | Copies HL to SAVED at `36A7H..36A8H`. |
| `3697` | `C9` | `RET` | Procedure return. |

The caller's `LXI B,36A6H` supplies the address of the statically allocated
one-byte `OBJ`. In this sample, the value is in BC at CALL. The callee copies
B/C into the two-byte X allocation at `36AAH/36A9H`, reloads that pair with
`LHLD`, and copies it to the outer `SAVED` ADDRESS variable with `SHLD`.
This describes these emitted instructions only; it is not a general PL/M ABI
claim.

The listing places MAIN at relative code offset 0, size 11, and P at offset
`000BH`, size 13. Its variable area is five bytes: OBJ (1), SAVED (2), and X
(2). P's reported local stack requirement is zero. LINK included only
`ADDR.OBJ(MAIN)`; no library module is listed. The 24 code bytes, including
`LXI SP`, are the compiler-reported CODE segment; LINK/LOCATE add no code
outside that segment.
