# Located 8080 code

LOCATE placed the 15-byte CODE segment at `3680H..368EH`. The listing gives
`OBJ` data offset `0000H` and `RESULT` offset `0001H`, size 2. LOCATE maps
DATA to `369DH..369FH`; therefore `OBJ=369DH` and `RESULT=369EH..369FH`.
The following is a byte-for-byte decode of `ADRTRN.HEX`:

```text
Address  Bytes       Instruction       Observation
3680     31 9D 36    LXI SP,369DH      MAIN initializes SP to DATA base
3683     CD 8B 36    CALL 368BH        Calls P
3686     22 9E 36    SHLD 369EH        Stores returned HL into RESULT
3689     FB          EI                MAIN termination sequence
368A     76          HLT
368B     21 9D 36    LXI H,369DH       P forms the ADDRESS result in HL
368E     C9          RET               Direct return; no further epilogue
```

The caller's return PC is `3686H`. With initial SP=`369DH`, CALL consumes
two stack bytes and P enters with SP=`369BH`. P executes no PUSH or POP;
RET restores SP to `369DH`. The compiler reports maximum STACK=2 bytes,
with MAIN stack=2 and P stack=0.

`LXI H,369DH` sets `L=9DH` and `H=36H`. The immediately following caller
instruction is `SHLD 369EH`, whose 8080 semantics store L at the addressed
byte and H at the next byte. Thus RESULT receives `9DH` at `369EH` followed
by `36H` at `369FH`. The low-byte-first result representation is established
by these emitted instructions for this sample.
