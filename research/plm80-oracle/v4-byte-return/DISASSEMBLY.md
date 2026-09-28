# Located 8080 code

LOCATE placed the 14-byte CODE segment at `3680H..368DH`. `RESULT` is the
one-byte DATA object at `369CH`. Intel 8080 decoding of the exact
`BYTRTN.HEX` bytes:

```text
Address  Bytes       Instruction       Observation
3680     31 9C 36    LXI SP,369CH      Main initializes SP to the DATA base
3683     CD 8B 36    CALL 368BH        Calls P
3686     32 9C 36    STA 369CH         Stores A into RESULT after return
3689     FB          EI                Main termination sequence
368A     76          HLT
368B     3E 2A       MVI A,2AH         P places its BYTE result in A
368D     C9          RET               Returns directly; no further epilogue
```

The CALL's return address is `3686H`. With initial SP=`369CH`, CALL pushes
that return address and P enters with SP=`369AH`; its direct RET restores
SP=`369CH`. P itself performs no push/pop and the listing reports
`PROCEDURE STACK=0000H`. The program's maximum stack is therefore the two
CALL return-address bytes.

The return-register conclusion is directly supported by both sides of the
call sequence: P executes `MVI A,2AH; RET`, and the caller immediately
executes `STA 369CH`. It is a sample-specific observation, not a generalized
PL/M ABI claim.
