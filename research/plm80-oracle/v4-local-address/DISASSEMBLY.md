# Located code disassembly

The Intel HEX type-00 record starts at `3680H` and contains all 15 bytes in
the compiler-reported CODE area. The PL/M cross-reference listing gives
`MAIN` offset 0/size 8 and `P` offset 8/size 7.

```text
3680  31 9D 36       LXI SP,369DH
3683  CD 88 36       CALL 3688H
3686  FB             EI
3687  76             HLT
3688  21 9D 36       LXI H,369DH
368B  22 9E 36       SHLD 369EH
368E  C9             RET
```

`MAIN` occupies `3680H..3687H`. It initializes SP, calls `P`, then terminates
with `EI; HLT`. `P` occupies `3688H..368EH`; its CALL return address is
`3686H`.

The listing assigns static `OBJ` offset `0000H`, size one, and local `LOCAL`
offset `0001H`, size two. The locator DATA range is `369DH..369FH`, so
`OBJ=369DH` and `LOCAL=369EH..369FH`. In P, `LXI H,369DH` forms the address
`369DH` in HL. `SHLD 369EH` stores L (`9DH`) at `369EH`, then H (`36H`) at
`369FH`. Thus this sample's local ADDRESS value is stored low byte first in
increasing memory order.

Initial SP is `369DH`. CALL pushes return PC `3686H`, leaving SP=`369BH` at P
entry; the return address occupies the two stack bytes below the initial SP.
P does not adjust SP, and RET restores it. The reported maximum STACK is two.
The locator reserves STACK at `368FH..369CH`, DATA at `369DH..369FH`, and
MEMORY beginning `36A0H`, distinct from the code bytes.
