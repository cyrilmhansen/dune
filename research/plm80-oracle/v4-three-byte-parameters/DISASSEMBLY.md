# Located code and stack analysis

`THREEB.HEX` contains the 27-byte type-00 code image at `3680H`. The LOCATE
map assigns CODE `3680H..369AH` inclusive, exactly 27 bytes. MAIN occupies
relative offsets `0000H..000EH` (15 bytes); P starts at relative offset
`000FH` / absolute `368FH` and occupies 12 bytes. DATA is `36ABH..36ADH`:
X at `36ABH`, Y at `36ACH`, Z at `36ADH` according to the listing's offsets
0, 1, and 2. The compiler reports maximum STACK 4.

## Exact 8080 disassembly

| Address | Bytes | Intel 8080 instruction | Observed effect |
|---|---|---|---|
| `3680` | `31 AB 36` | `LXI SP,36ABH` | Startup; establishes the stack pointer used by this code. |
| `3683` | `0E 11` | `MVI C,11H` | Places X's actual value (17) in C. |
| `3685` | `C5` | `PUSH B` | Decrements SP by 2 and pushes BC. C is the stack-passed X byte; B's value is not established here. |
| `3686` | `1E 55` | `MVI E,55H` | Places Z's actual value (85) in E. |
| `3688` | `0E 2A` | `MVI C,2AH` | Places Y's actual value (42) in C. |
| `368A` | `CD 8F 36` | `CALL 368FH` | Calls P. Immediately before CALL: C=`2AH`, E=`55H`; B and D are not initialized by this sequence; SP=`36A9H`. |
| `368D` | `FB` | `EI` | MAIN completion path after P returns. |
| `368E` | `76` | `HLT` | MAIN completion. |
| `368F` | `21 AD 36` | `LXI H,36ADH` | P entry; points at Z's allocated byte. |
| `3692` | `73` | `MOV M,E` | Stores Z from E (`55H`) at `36ADH`. |
| `3693` | `2B` | `DCX H` | Moves to Y's allocated byte at `36ACH`. |
| `3694` | `71` | `MOV M,C` | Stores Y from C (`2AH`) at `36ACH`. |
| `3695` | `2B` | `DCX H` | Moves to X's allocated byte at `36ABH`. |
| `3696` | `D1` | `POP D` | Pops the CALL return address from the stack into DE; SP advances by 2. |
| `3697` | `C1` | `POP B` | Pops the caller's pushed BC pair; C receives X=`11H`, B receives the companion byte; SP advances by 2. |
| `3698` | `71` | `MOV M,C` | Stores X (`11H`) at `36ABH`. |
| `3699` | `D5` | `PUSH D` | Restores the saved return address to the stack. |
| `369A` | `C9` | `RET` | Returns to `368DH`, consuming the restored return address. |

This establishes the materialization order Z, Y, X. It also shows that the
callee removes the two-byte pushed pair while temporarily popping and then
restoring the return address. The caller executes no separate argument
cleanup after return. The companion B byte is part of the pushed pair but is
not a meaningful BYTE argument in the observed sequence; its concrete value
is not inferred.

## Stack snapshots

The 8080 PUSH/CALL/POP stack effects below are interpreted from the emitted
instructions and the processor's documented little-endian stack behavior.
The diagrams list the byte at SP first. Addresses and observed values are
hexadecimal; `??` means this code did not establish the byte's value.

### A. Before argument setup

After `LXI SP,36ABH` and before `MVI C,11H`, SP=`36ABH`; there are no active
argument or return-address bytes. The code does not establish the contents
of memory below SP.

### B. Immediately before CALL

After `PUSH B`, then `MVI E,55H` and `MVI C,2AH`:

```text
SP = 36A9H
36A9  11H   pushed C: X = 17
36AA  ??    pushed B companion byte (B was not initialized by this code)

register arguments: C = 2AH (Y), E = 55H (Z)
other pair bytes:   B and D not established by argument setup
```

The stack slot is two bytes because the emitted instruction is `PUSH B`; the
sample passes X in its low byte. It does not establish that the high byte is
part of X's value.

### C. Immediately after CALL transfers to P

`CALL 368FH` pushes return address `368DH` and enters P with SP=`36A7H`:

```text
SP = 36A7H
36A7  8DH   return-address low byte
36A8  36H   return-address high byte
36A9  11H   X argument byte, still below the return address
36AA  ??    companion byte from pushed BC
```

P first stores Z and Y without disturbing SP. `POP D` then removes the
return address (SP=`36A9H`), `POP B` removes the argument pair (SP=`36ABH`),
and the routine stores C as X. `PUSH D` restores the saved return address
before `RET`. Upon return, SP is again `36ABH`, so no caller cleanup is
emitted.

## Quantitative comparison

| Fixture | CODE | VARIABLE | Maximum STACK | Delta vs this three-BYTE fixture (CODE / VARIABLE / STACK) |
|---|---:|---:|---:|---:|
| zero arguments (`v4-micro`) | 9 | 0 | 2 | +18 / +3 / +2 |
| one BYTE | 15 | 1 | 2 | +12 / +2 / +2 |
| two BYTE | 19 | 2 | 2 | +8 / +1 / +2 |
| BYTE + ADDRESS | 22 | 4 | 2 | +5 / -1 / +2 |
| ADDRESS + BYTE | 22 | 4 | 2 | +5 / -1 / +2 |
| this three-BYTE fixture | 27 | 3 | 4 | — |

The only direct inference from the stack delta is that this compiled sample
has maximum stack depth 2 bytes greater than the listed two-parameter and
one/two-argument references. Its listing reports MAIN stack 4 and P stack
2. The peak corresponds to the caller's two-byte `PUSH B` pair plus the
two-byte CALL return address; the LOCATE STACK reservation (16 bytes) is a
separate allocation. These sample size deltas are not general code-size or
stack formulas.
