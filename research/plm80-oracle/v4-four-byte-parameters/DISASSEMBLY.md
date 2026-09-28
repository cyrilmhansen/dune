# Located code and stack analysis

`FOURB.HEX` contains a 33-byte absolute code image at `3680H..36A0H`. The
listing reports CODE=33, VARIABLE=4, maximum STACK=6. The locator map places
the code at `3680H..36A0H`, a 18-byte reserved STACK segment at `36A1H..36B2H`,
and four DATA bytes at `36B3H..36B6H`. The listing assigns W, X, Y, Z to DATA
offsets 0, 1, 2, 3 respectively: W=`36B3H`, X=`36B4H`, Y=`36B5H`, Z=`36B6H`.
MAIN initializes SP to `36B3H`, one byte beyond the DATA area.

## Exact Intel 8080 disassembly

| Address | Bytes | Instruction | Directly observed effect |
|---|---|---|---|
| `3680` | `31 B3 36` | `LXI SP,36B3H` | Initializes SP. |
| `3683` | `0E 11` | `MVI C,11H` | Loads W's actual value into C. |
| `3685` | `C5` | `PUSH B` | Reserves/pushes a BC pair; C is `11H`, B is not established by this setup. |
| `3686` | `0E 22` | `MVI C,22H` | Loads X's actual value into C. |
| `3688` | `C5` | `PUSH B` | Pushes the next BC pair; C is `22H`, B remains unestablished by this setup. |
| `3689` | `1E 44` | `MVI E,44H` | Loads Z's actual value into E. |
| `368B` | `0E 33` | `MVI C,33H` | Loads Y's actual value into C. |
| `368D` | `CD 92 36` | `CALL 3692H` | Calls P. Before CALL: SP=`36AFH`, C=`33H`, E=`44H`. |
| `3690` | `FB` | `EI` | MAIN continuation after P returns. |
| `3691` | `76` | `HLT` | MAIN completion. |
| `3692` | `21 B6 36` | `LXI H,36B6H` | P points to Z's allocation. |
| `3695` | `73` | `MOV M,E` | Stores Z from E at `36B6H`. |
| `3696` | `2B` | `DCX H` | Moves to Y's allocation. |
| `3697` | `71` | `MOV M,C` | Stores Y from C at `36B5H`. |
| `3698` | `2B` | `DCX H` | Moves to X's allocation. |
| `3699` | `D1` | `POP D` | Removes CALL return address into DE. |
| `369A` | `C1` | `POP B` | Removes X's pushed pair; C is `22H`; B companion is unestablished. |
| `369B` | `71` | `MOV M,C` | Stores X at `36B4H`. |
| `369C` | `2B` | `DCX H` | Moves to W's allocation. |
| `369D` | `C1` | `POP B` | Removes W's pushed pair; C is `11H`; B companion is unestablished. |
| `369E` | `71` | `MOV M,C` | Stores W at `36B3H`. |
| `369F` | `D5` | `PUSH D` | Restores the saved return address. |
| `36A0` | `C9` | `RET` | Returns to `3690H`. |

Thus the emitted order is W push, X push, Z/E and Y/C preparation, CALL;
the callee materializes Z, Y, X, W. The listing's formal allocation order
and the destination addresses agree with these stores. The code does not
establish B or D as argument values.

## Stack reconstruction

The snapshots follow the actual `PUSH B`, `CALL`, `POP`, and `PUSH D`
instructions. A pushed BC pair places C at the lower address and B at the
next address on this 8080 stack. `??` marks a companion byte whose value is
not established by this caller sequence.

### A. Initial SP, before argument setup

```text
SP = 36B3H
no argument or return-address bytes have been pushed by this program
```

### B. After the first PUSH (W)

```text
SP = 36B1H
36B1  11H   C = W
36B2  ??    B companion; B was not established by argument setup
```

### C. After the second PUSH (X)

```text
SP = 36AFH
36AF  22H   C = X
36B0  ??    B companion; B was not established by argument setup
36B1  11H   earlier C = W
36B2  ??    earlier B companion
```

### D. Immediately before CALL

SP remains `36AFH`. The later `MVI E,44H` and `MVI C,33H` do not change the
stack:

```text
register arguments: C = 33H (Y), E = 44H (Z)
stack arguments:    X = 22H at 36AFH; W = 11H at 36B1H
unestablished:      B and D as argument-related registers; both B companions
```

### E. At P entry, immediately after CALL

CALL's return address is the top stack item. The CALL is at `368DH`, so the
return PC is `3690H`:

```text
SP = 36ADH
36AD  90H   return PC low byte
36AE  36H   return PC high byte
36AF  22H   X's meaningful C byte from second PUSH
36B0  ??    X slot's unestablished B companion
36B1  11H   W's meaningful C byte from first PUSH
36B2  ??    W slot's unestablished B companion
```

At entry, `POP D` consumes the return address (SP becomes `36AFH`), the first
`POP B` consumes X (SP=`36B1H`), and the second `POP B` consumes W
(SP=`36B3H`). `PUSH D` restores the return address and `RET` consumes it,
returning with SP=`36B3H`. The caller emits no argument cleanup. Maximum
depth from the initialized SP to the lowest SP (`36ADH`) is six bytes: four
bytes from two argument-pair pushes plus two bytes for CALL's return address.
The listing independently reports maximum STACK=6. The locator's 18-byte
reserved STACK segment is an allocation range, not the measured depth.

## Comparison and scope

| Fixture | CODE | VARIABLE | Maximum STACK |
|---|---:|---:|---:|
| zero arguments | 9 | 0 | 2 |
| one BYTE | 15 | 1 | 2 |
| two BYTE | 19 | 2 | 2 |
| three BYTE | 27 | 3 | 4 |
| four BYTE (this fixture) | 33 | 4 | 6 |

Against three BYTE, four BYTE adds 6 CODE bytes, one formal storage byte,
and 2 maximum-stack bytes. W is pushed first and X second; at callee entry X
is adjacent to the return address and is popped/materialized before W. This
establishes the ordering for these two stack-passed BYTE arguments only; it
does not establish multi-argument stack order for other widths or signatures.
