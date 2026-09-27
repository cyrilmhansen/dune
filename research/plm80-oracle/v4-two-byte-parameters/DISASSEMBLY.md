# Absolute code disassembly

`TBYTE.HEX` contains the 19-byte type-00 code image at `3680H`. The LOCATE
map assigns CODE `3680H..3692H`, exactly matching that record. MAIN occupies
relative offsets `0000H..000BH` (12 bytes); P begins at relative offset
`000CH` / absolute `368CH` and occupies 7 bytes. STACK and DATA are separate
segments.

| Address | Bytes | Intel 8080 instruction | Observation |
|---|---|---|---|
| `3680` | `31 A1 36` | `LXI SP,36A1H` | MAIN entry; initializes SP. |
| `3683` | `1E 55` | `MVI E,55H` | Loads decimal 85, the second BYTE actual. |
| `3685` | `0E 2A` | `MVI C,2AH` | Loads decimal 42, the first BYTE actual. |
| `3687` | `CD 8C 36` | `CALL 368CH` | Call site; P entry is `368CH`. Immediately before this instruction, the emitted code has set `C=2AH` and `E=55H`. |
| `368A` | `FB` | `EI` | MAIN completion sequence. |
| `368B` | `76` | `HLT` | MAIN completion sequence. |
| `368C` | `21 A2 36` | `LXI H,36A2H` | P entry; addresses the allocated second parameter Y. |
| `368F` | `73` | `MOV M,E` | Stores E (the second actual's observed value) at `36A2H`. |
| `3690` | `2B` | `DCX H` | Moves from Y's byte at `36A2H` to X's byte at `36A1H`. |
| `3691` | `71` | `MOV M,C` | Stores C (the first actual's observed value) at `36A1H`. |
| `3692` | `C9` | `RET` | P returns. |

Thus, in this exact V4.0 output, the caller places the first BYTE value in C
and the second in E. On entry, the generated procedure copies E to Y's
allocated byte, then C to X's allocated byte. The listing assigns X offset 0
and Y offset 1; LOCATE places those two DATA bytes at `36A1H` and `36A2H`.

## Comparison with the preceding fixtures

| Fixture | CODE bytes | VARIABLE bytes | Maximum STACK | Observed call preparation |
|---|---:|---:|---:|---|
| `v4-micro` | 9 | 0 | 2 | no arguments |
| `v4-byte-parameter` | 15 | 1 | 2 | first/only BYTE in C |
| `v4-address-parameter` | 24 | 5 | 2 | ADDRESS value in BC |
| this fixture | 19 | 2 | 2 | first BYTE in C, second BYTE in E |

Relative to the one-BYTE fixture, this sample adds 4 CODE bytes and 1
VARIABLE byte; maximum STACK is unchanged. Relative to the ADDRESS fixture,
it is 5 CODE bytes and 3 VARIABLE bytes smaller, with the same maximum STACK.
Relative to the zero-argument fixture, it adds 10 CODE bytes and 2 VARIABLE
bytes, again with the same maximum STACK. These are measurements of these
four programs, not general size formulas.

All 19 bytes, including `LXI SP`, are inside the compiler-reported CODE
segment. LINK includes only `TBYTE.OBJ(MAIN)`; it did not pull in PLM80.LIB.
LOCATE adds segment placement, not executable bytes outside this CODE range.
