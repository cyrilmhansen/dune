# Located code disassembly

The Intel HEX type-00 record is at `3680H` and contains the 14 bytes reported
by the compiler's CODE area. The procedure layout agrees with the PL/M
cross-reference listing (`MAIN` offset 0, size 8; `P` offset 8, size 6).

```text
3680  31 9C 36       LXI SP,369CH
3683  CD 88 36       CALL 3688H
3686  FB             EI
3687  76             HLT
3688  21 9C 36       LXI H,369CH
368B  36 2A          MVI M,2AH
368D  C9             RET
```

`3680H..3687H` is the eight-byte main procedure: initialize SP, call `P`,
then terminate with `EI; HLT`. The CALL at `3683H` targets `P` at `3688H` and
returns to `3686H`. `3688H..368DH` is the six-byte procedure.

The local `LOCAL` has cross-reference offset `0000H`, size one, and the
locator DATA range is the single address `369CH`. At entry, `P` loads that
absolute address into HL and stores `2AH` to `(HL)`, then returns. No
SP-relative local access or argument setup occurs. The initial SP is
`369CH`; CALL consumes two stack bytes for its return address, consistent
with the reported maximum STACK of two. The routine does not otherwise
adjust SP.

CODE is `3680H..368DH` inclusive (14 bytes). The locator reserves STACK at
`368EH..369BH`, DATA at `369CH`, and MEMORY beginning at `369DH`; these
placements are distinct from the 14 code bytes.
