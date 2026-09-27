# PL/M-80 ADDRESS + BYTE parameter fingerprint

This fixture is the inverse ordering of
[`v4-byte-address-parameters`](../v4-byte-address-parameters/README.md):
procedure P receives an ADDRESS actual naming statically allocated BYTE OBJ,
then a BYTE actual with value 42. The short ISIS-II basename is `ADBYTE`.

`ADBYTE.PLM` is preserved as 137 CRLF bytes and was copied back from the
guest paper-tape output and compared byte-for-byte. The ISIS-II PL/M-80 V4.0
compiler reported zero program errors.

## Documented expectation versus observation

Intel's documented PL/M linkage convention predicts the first ADDRESS
parameter in BC (B high, C low), and the second BYTE in E. See the Intel
[PL/M linkage conventions](https://laundry.manualsonline.com/manuals/mfg/intel/8085_1.html?p=25).
This is a documented expectation, not a substitute for the compiler output.

The exact V4.0 code loads `OBJ` directly with `LXI B,36A4H`, loads `42` with
`MVI E,2AH`, then calls P. Immediately before CALL, BC=`36A4H` and E=`2AH`.
The callee stores E to Y, then B and C to X. D is neither established by the
argument setup nor read by the callee's parameter materialization, so this
fixture does not determine D's value. See [`DISASSEMBLY.md`](DISASSEMBLY.md)
for byte-level detail and locations.

## Cross-fixture pattern and limits

Across the tested two-parameter signatures:

- BYTE/BYTE: position 1 in C; position 2 in E.
- BYTE/ADDRESS: position 1 in C; position 2 in DE.
- ADDRESS/BYTE: position 1 in BC; position 2 in E.

This pattern agrees with Intel's documented position-sensitive convention
for these tested types and signatures. Together with the one-parameter BYTE
and ADDRESS fixtures, it strengthens that interpretation, but it is not a
complete PL/M-80 ABI rule. Do not extrapolate to three or more parameters,
stack-passed parameters, WORD types, untested expression forms, return
values, external procedures, recursive procedures, interrupts, or other
compiler versions. The planned three-parameter experiment is the next test
of register capacity and overflow behavior.

The compiler listing reports CODE 22 (`0016H`), VARIABLE 4 (`0004H`), and
maximum STACK 2 (`0002H`). LOCATE places CODE `3680H..3695H`, STACK
`3696H..36A3H`, DATA `36A4H..36A7H`; OBJ is at `36A4H`, X at `36A5H..36A6H`,
and Y at `36A7H`. LINK includes only `ADBYTE.OBJ(MAIN)`, so PLM80.LIB was
not needed for this sample.

## Environment and commands

- Simulator: z80pack Intel Intellec MDS-800 Simulator Release 1.39.
- Guest: ISIS-II V4.3.
- Compiler: `ISIS-II PL/M-80 COMPILER V4.0`.
- LINK: `ISIS-II OBJECT LINKER V3.0`.
- LOCATE: `ISIS-II OBJECT LOCATER V3.0` (spelling printed by the tool).
- The local disk recipe labels PLM80 and OV0–OV4 V4.0, and OV5–OV6 V3.1.
  This run did not trace overlay opens, so actual per-overlay provenance/use
  remains unresolved.

The commands on disposable copies of the established disk images were:

```text
COPY :CI: TO :F0:ADBYTE.PLM
PLM80 :F0:ADBYTE.PLM DEBUG XREF
LINK :F0:ADBYTE.OBJ TO :F0:ADBYTE.SAT MAP PRINT(:F0:ADBYTE.LMP)
LOCATE :F0:ADBYTE.SAT TO :F0:ADBYTE.LOC MAP PRINT(:F0:ADBYTE.MAP)
OBJHEX :F0:ADBYTE.LOC TO :F0:ADBYTE.HEX
```

The console transcript and all compiler/link/locate artifacts are preserved.
Their byte sizes and hashes, along with source disk hashes and observations,
are in `manifest.json`.
