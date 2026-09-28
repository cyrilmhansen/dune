# PL/M-80 V4.0 ADDRESS-return fingerprint

This fixture asks how one parameterless typed procedure returns the address
of one static `BYTE` object, and how its caller stores that result in a static
`ADDRESS`. It adds no other language feature. The ISIS-II guest basename is
`ADRTRN`; `ADDRESS-RETURN.PLM` is the preserved host source and `ADRTRN.PLM`
is the guest copy compiled by ISIS-II.

## Syntax basis

The Intel *PL/M-80 Programming Manual*, order no. 9800268B (January 1980),
documents typed procedures with the result type after `PROCEDURE`,
`RETURN expression;` for a typed procedure, and use of a typed procedure as
a function in an expression (sections 8.1.3 and 8.2). Thus this fixture uses
`P: PROCEDURE ADDRESS;`, `RETURN .OBJ;`, and `RESULT = P;`. The compiler
accepted this exact source with zero program errors. Archival manual:
[Intel PL/M-80 Programming Manual, Jan. 1980](https://mark-ogden.uk/files/intel/publications/9800268B%20PLM-80%20Programming%20Manual-Jan80.pdf).

## Direct observations

PL/M-80 V4.0 reports CODE=15 bytes, VARIABLE=3 bytes, and maximum STACK=2
bytes. The listing assigns `OBJ` data offset `0000H`, `RESULT` offset
`0001H` with size two, and procedure `P` code offset `000BH`. LOCATE places
CODE at `3680H..368EH` and DATA at `369DH..369FH`, so `OBJ` is at `369DH`
and `RESULT` occupies `369EH..369FH`.

At `368BH`, P executes `LXI H,369DH; RET`. MAIN calls P at `368BH`, then
executes `SHLD 369EH`. The emitted code therefore passes the returned
ADDRESS in `HL`; `SHLD` stores `L` at the lower address and `H` at the next
address. For this placement, the stored bytes are `9DH 36H`, the
little-endian representation of `369DH`. P uses no additional epilogue
instruction beyond `RET`.

These are observations of this exact emitted program. They are not a
generalized PL/M-80 return-ABI rule.

## Comparison

| Fixture | CODE | VARIABLE | Maximum STACK | This fixture minus comparison |
| --- | ---: | ---: | ---: | --- |
| zero-argument call (`v4-micro`) | 9 | 0 | 2 | +6 / +3 / 0 |
| one BYTE return (`v4-byte-return`) | 14 | 1 | 2 | +1 / +2 / 0 |
| one ADDRESS parameter (`v4-address-parameter`) | 18 | 3 | 2 | -3 / 0 / 0 |
| one local ADDRESS (`v4-local-address`) | 15 | 3 | 2 | 0 / 0 / 0 |

The same total sizes as the local-ADDRESS sample do not imply the same
behavior: here `HL` carries a procedure result which the caller stores;
there, the procedure assigns a local ADDRESS object.

## Reproduction

Use the non-destructive launcher and SPACE handshake documented in
[`../tools/README.md`](../tools/README.md). The upstream hard-linking
`isisii43-hd` wrapper was not used. The console command transcript and
paper-tape capture procedure are in `console.typescript` and
`ptp-capture.typescript`; artifact hashes are in `manifest.json`.

## Limits

This fixture supports only the observation that this parameterless ADDRESS
result is constructed in `HL` and immediately stored by its caller with
`SHLD`. It does not establish behavior for other ADDRESS expressions,
parameters, nested expressions, external procedures, larger results, or
other compiler versions. The local compiler disk recipe has a mixed-overlay
provenance caveat: the banner reports V4.0, but this run did not trace
individual overlay opens.
