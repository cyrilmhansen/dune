# PL/M-80 V4.0 BYTE-return fingerprint

This fixture contains one parameterless typed procedure returning the BYTE
constant 42 (`2AH`). `MAIN` assigns the function reference to one static BYTE
object. No other executable language feature is included. The ISIS-II guest
basename is `BYTRTN`; `BYTE-RETURN.PLM` is the preserved host source and
`BYTRTN.PLM` is the copy compiled by ISIS-II.

## Syntax basis

The Intel *PL/M-80 Programming Manual*, order no. 9800268B, describes typed
procedures as declarations whose type follows the `PROCEDURE` keyword; its
examples include `SUM$ARRAY: PROCEDURE (PTR, N) BYTE;` and `RETURN SUM;`.
Section 8.1.3 says typed procedures use `RETURN expression;`; Section 8.2
states that a typed procedure is referenced as a function in an expression.
This fixture uses the no-parameter form `P: PROCEDURE BYTE; RETURN 42;` and
the expression assignment `RESULT = P;`. The compiler accepted this exact
form with zero program errors. Archival manual: [Intel PL/M-80 Programming
Manual, Jan.  1980](https://mark-ogden.uk/files/intel/publications/9800268B%20PLM-80%20Programming%20Manual-Jan80.pdf).

## Direct observations

PL/M-80 V4.0 reports CODE=14 bytes, VARIABLE=1 byte, and maximum STACK=2
bytes. The listing assigns `P` code offset `000BH` and `RESULT` data offset
`0000H`. LOCATE places CODE at `3680H..368DH` and the one-byte DATA area at
`369CH`, so the caller's result object is at `369CH`.

At `368BH`, P executes `MVI A,2AH` followed immediately by `RET`. MAIN calls
P at `368BH`; on return, its next instruction is `STA 369CH`. Thus, in this
compiled example, the returned BYTE is present in A and the caller stores it
directly from A. The callee uses no additional epilogue beyond `RET` and
reports zero stack bytes; the call accounts for the two-byte maximum stack
use. These are observations of the emitted code and map, not a universal
return ABI rule.

## Comparison

| Fixture | CODE | VARIABLE | Maximum STACK | Sample difference from this fixture |
| --- | ---: | ---: | ---: | --- |
| zero-argument call (`v4-micro`) | 9 | 0 | 2 | this fixture: +5 / +1 / 0 |
| one local BYTE (`v4-local-byte`) | 14 | 1 | 2 | same reported sizes |
| one BYTE parameter (`v4-byte-parameter`) | 15 | 1 | 2 | this fixture: -1 / 0 / 0 |

The equal CODE/VARIABLE/STACK totals versus the local-BYTE fixture do not
imply equivalent code or storage behavior. Here the procedure produces a
value in A and the caller stores it; the local-BYTE fixture writes a constant
to its local data object.

## Reproduction

The isolated launcher is documented in
[`../tools/README.md`](../tools/README.md). It verifies canonical disk hashes
and boots on disposable copies; the upstream hard-linking wrapper was not
used. The ISIS-II V4.3 console used the established one-SPACE handshake.
Guest commands:

```text
COPY :CI: TO :F0:BYTRTN.PLM
PLM80 :F0:BYTRTN.PLM DEBUG XREF
LINK :F0:BYTRTN.OBJ TO :F0:BYTRTN.SAT MAP PRINT(:F0:BYTRTN.LMP)
LOCATE :F0:BYTRTN.SAT TO :F0:BYTRTN.LOC MAP PRINT(:F0:BYTRTN.MAP)
OBJHEX :F0:BYTRTN.LOC TO :F0:BYTRTN.HEX
DIR FOR BYTRTN.*
```

The compiler transcript is in `console.typescript`. The `:HP:` artifact
transfers and framing verification are listed in `ptp-capture.typescript`.
Artifact sizes and SHA-256 hashes are recorded in `manifest.json`.

## Limits

This proves only that this no-parameter BYTE-return sample uses A as observed
by its immediate caller. It does not establish the register convention for
ADDRESS or larger return values, nested expressions, calls with parameters,
external procedures, or other PL/M-80 compiler versions. The local compiler
disk recipe has a mixed-overlay provenance caveat: the compiler banner
reports V4.0, but this run did not trace individual overlay opens.
