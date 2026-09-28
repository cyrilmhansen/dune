# PL/M-80 V4.0 four-BYTE-parameter fingerprint

This experiment tests one procedure call with four distinct `BYTE` actual
arguments. `FOURB` is the short ISIS-II basename for this fixture. The source
uses W=`11H`, X=`22H`, Y=`33H`, and Z=`44H`; the compiler reports zero program
errors.

## Documented expectation and exact observation

Intel's documented linkage convention predicts that, with more than two
parameters, the final two use the register parameter positions and earlier
parameters are stack-passed. For this source that predicts W and X on the
stack, Y in C, and Z in E. The located V4.0 bytes support that expectation.

The caller loads W into C and executes `PUSH B`, then loads X into C and
executes another `PUSH B`. It then loads Z into E and Y into C and calls P.
Immediately before CALL, SP=`36AFH`, C=`33H`, E=`44H`; B and D are not
established by this argument-preparation sequence. At P entry, the return
address is above the X slot, which is above the W slot. Each pushed BYTE uses
the low C byte of a BC pair; the companion B bytes are not established as
argument values.

P stores Z from E and Y from C, temporarily removes the return address, pops
and stores X, then pops and stores W. It restores the return address and
executes RET. No caller-side argument cleanup appears in this sample. The
exact instruction and stack analysis is in [`DISASSEMBLY.md`](DISASSEMBLY.md).

This is direct evidence for this four-BYTE sample and strengthens the
observed final-two-register-slots pattern. It also shows the order of these
two stack-passed BYTE slots: W is pushed first and lies deeper; X is pushed
second and is retrieved first. It does not establish ordering for more than
two stack arguments generally, stack-passed ADDRESS or mixed-width values,
WORD parameters, expressions with side effects, or a universal cleanup rule.

## Quantitative comparison

| Fixture | CODE | VARIABLE | Maximum STACK |
|---|---:|---:|---:|
| zero arguments (`v4-micro`) | 9 | 0 | 2 |
| one BYTE | 15 | 1 | 2 |
| two BYTE | 19 | 2 | 2 |
| three BYTE | 27 | 3 | 4 |
| four BYTE (this fixture) | 33 | 4 | 6 |

Relative to the three-BYTE fixture, this sample adds 6 CODE bytes, one
VARIABLE byte, and 2 bytes of reported maximum stack. The emitted caller has
one additional two-byte PUSH slot; together with the CALL return address,
the deepest observed stack use is six bytes. These are sample-specific
deltas, not formulas for arbitrary signatures.

## Environment and reproducibility

- z80pack Intel Intellec MDS-800 Simulator Release 1.39
- ISIS-II V4.3
- compiler banner: `ISIS-II PL/M-80 COMPILER V4.0`
- LINK V3.0; LOCATE V3.0 (the console prints `LOCATER`)

The verified headless launch and console SPACE handshake are documented in
[`../HEADLESS-ISIS-II.md`](../HEADLESS-ISIS-II.md). The guest command sequence
was:

```text
COPY :CI: TO :F0:FOURB.PLM
PLM80 :F0:FOURB.PLM DEBUG XREF
LINK :F0:FOURB.OBJ TO :F0:FOURB.SAT MAP PRINT(:F0:FOURB.LMP)
LOCATE :F0:FOURB.SAT TO :F0:FOURB.LOC MAP PRINT(:F0:FOURB.MAP)
OBJHEX :F0:FOURB.LOC TO :F0:FOURB.HEX
```

The LINK map contains only `FOURB.OBJ(MAIN)`, so PLM80.LIB was not needed.
The fixture preserves the compiler listing, OBJ/SAT/LOC/HEX and both maps.
The manifest records artifact hashes, sizes, and the disk image hashes
observed for this run.

## Provenance caveat

The local disk recipe has historically been described as a mixed PLM80
overlay recipe (OV0-OV4 labelled V4.0, OV5-OV6 labelled V3.1). This run did
not trace individual overlay opens. The compiler banner establishes the
reported version, not the provenance or use of every overlay. The ISIS-II
system/user disk hashes observed for this run differ from hashes recorded by
some earlier fixtures; this discrepancy is preserved in the manifest rather
than attributed to a cause without evidence.
