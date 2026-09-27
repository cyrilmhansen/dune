# Absolute code disassembly

The `BYTE.HEX` type-00 record contains 15 bytes at `3680H`. The LOCATE map
places the compiler-reported CODE segment at `3680H..368EH`, matching that
record exactly. The independent STACK and DATA segments begin at `368FH` and
`369DH`, respectively; they are not part of the code fingerprint.

| Address | Bytes | Intel 8080 instruction | Observation |
|---|---|---|---|
| `3680` | `31 9D 36` | `LXI SP,369DH` | Main entry; initializes SP to the located MEMORY base. |
| `3683` | `0E 2A` | `MVI C,2AH` | Loads decimal 42, the call's constant BYTE actual argument. |
| `3685` | `CD 8A 36` | `CALL 368AH` | Call site; procedure P entry is `368AH`. |
| `3688` | `FB` | `EI` | Main completion sequence. |
| `3689` | `76` | `HLT` | Main completion sequence. |
| `368A` | `21 9D 36` | `LXI H,369DH` | P addresses its one-byte DATA allocation. |
| `368D` | `71` | `MOV M,C` | Stores the byte in C through HL. |
| `368E` | `C9` | `RET` | P returns. |

Within this one generated sample, the argument is passed in register C: the
caller loads `2AH` into C immediately before CALL, and P stores C to its
one-byte allocated DATA location. This is an observation about this fixture,
not a general PL/M calling-convention claim.

LINK includes only `BYTE.OBJ(MAIN)`; no library module is included. LOCATE
places CODE, STACK and DATA separately. All 15 bytes above are in the
compiler-reported CODE area; no extra startup bytes were inserted outside
that area by LINK/LOCATE. The `LXI SP` instruction is itself part of CODE.

## Difference from `v4-micro`

The baseline has 9 code bytes, zero variable bytes and maximum stack 2. This
case has 15 code bytes, one variable byte and maximum stack 2. The code-size
delta is +6 bytes; stack-size delta is zero.

The baseline's caller is `LXI SP; CALL; EI; HLT`, with a one-byte `RET`
procedure. Here the caller adds `MVI C,2AH`; P is five bytes (`LXI H`,
`MOV M,C`, `RET`). The call target moves from `3688H` to `368AH`. These are
only the observed instruction and allocation differences between these two
fixtures; no broader ABI inference is made.
