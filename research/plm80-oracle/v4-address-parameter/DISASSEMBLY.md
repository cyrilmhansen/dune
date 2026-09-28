# Absolute code disassembly

`ADDR.HEX` contains two type-00 data records with 18 code bytes in total.
LOCATE places CODE at `3680H..3691H`, STACK at `3692H..369FH`, and DATA at
`36A0H..36A2H`. `OBJ` occupies `36A0H`; the formal `X ADDRESS` allocation is
`36A1H..36A2H`.

| Address | Bytes | Intel 8080 instruction | Direct observation |
|---|---|---|---|
| `3680` | `31 A0 36` | `LXI SP,36A0H` | MAIN entry; initial SP is `36A0H`. |
| `3683` | `01 A0 36` | `LXI B,36A0H` | Loads the address of OBJ into BC. |
| `3686` | `CD 8B 36` | `CALL 368BH` | Calls P; return PC is `3689H`. |
| `3689` | `FB` | `EI` | MAIN continuation. |
| `368A` | `76` | `HLT` | MAIN completion. |
| `368B` | `21 A2 36` | `LXI H,36A2H` | P entry; HL points to the high-byte formal slot. |
| `368E` | `70` | `MOV M,B` | Stores B=`36H` at `36A2H`. |
| `368F` | `2B` | `DCX H` | Moves HL to `36A1H`. |
| `3690` | `71` | `MOV M,C` | Stores C=`A0H` at `36A1H`. |
| `3691` | `C9` | `RET` | Returns to `3689H`. |

At CALL, BC=`36A0H`: B is the high byte and C the low byte. The value is
therefore passed in BC for this sample. The generated parameter materializer
stores B to the higher address first, then C to the lower address. The
resulting formal bytes at increasing addresses `36A1H,36A2H` are `A0H,36H`,
the little-endian representation of `36A0H`.

The stack snapshot follows only the emitted instructions and the ordinary
8080 CALL/RET stack effect:

```text
Before CALL: SP = 36A0H; no argument bytes are on the stack.
At P entry:  SP = 369EH
  369E  89H   CALL return address low byte
  369F  36H   CALL return address high byte
After RET:   SP = 36A0H
```

The listing gives MAIN at code offset 0 with size 11 and P at offset `000BH`
with size 7. VARIABLE is three bytes: OBJ (one byte) plus X (two bytes).
MAIN's reported stack is two; P's is zero. The observed maximum STACK is
two, used by the CALL return address. LINK includes only `ADDR.OBJ(MAIN)`;
no library module is listed. These facts describe this minimal compilation,
not a general PL/M-80 ABI rule.
