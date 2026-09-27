# PL/M-80 two-BYTE-parameter code-generation fingerprint

This fixture asks how the local ISIS-II PL/M-80 V4.0 compiler passes two
BYTE actual arguments and materializes the corresponding formal parameters.
The source is the minimal requested procedure/call, with constants 42 and 85.
It has no I/O or unrelated language feature.

`TBYTE.PLM` is preserved as 96 bytes of CRLF text (SHA-256 is in
`manifest.json`) and was round-tripped from the guest disk; its bytes matched.
The compiler reported zero program errors.

## Documented expectation versus observed output

Intel's PL/M linkage-convention description says that a single BYTE is passed
in C, and for two parameters the first follows that convention while the
second uses the D/E pair (E for a BYTE). See the Intel 8085 manual's
[PL/M linkage conventions](https://laundry.manualsonline.com/manuals/mfg/intel/8085_1.html?p=25).
That is a documented expectation, not evidence about which instructions this
particular compiler emitted.

The located V4.0 code independently shows `MVI E,55H`, `MVI C,2AH`, then
`CALL 368CH`; the callee stores E to Y and C to X. This fixture therefore
supports the expected register placement for these two BYTE constants and
this procedure shape. It does not establish a general ABI for other parameter
types, counts, expressions, nesting, or compiler builds. The exact bytes and
addresses are transcribed in [`DISASSEMBLY.md`](DISASSEMBLY.md).

## Environment and reproducible command sequence

- Simulator: z80pack Intel Intellec MDS-800 Simulator Release 1.39.
- Guest: ISIS-II V4.3.
- Compiler banner: `ISIS-II PL/M-80 COMPILER V4.0`.
- LINK banner: `ISIS-II OBJECT LINKER V3.0`.
- LOCATE banner: `ISIS-II OBJECT LOCATER V3.0` (printed spelling).
- The local system-disk recipe labels PLM80 and OV0–OV4 as V4.0 and OV5–OV6
  as V3.1. This remains a mixed-recipe provenance caveat; this run did not
  trace individual overlay opens and does not resolve actual overlay
  provenance/use.

On disposable copies of the three local images, the guest commands were:

```text
COPY :CI: TO :F0:TBYTE.PLM
PLM80 :F0:TBYTE.PLM DEBUG XREF
LINK :F0:TBYTE.OBJ TO :F0:TBYTE.SAT MAP PRINT(:F0:TBYTE.LMP)
LOCATE :F0:TBYTE.SAT TO :F0:TBYTE.LOC MAP PRINT(:F0:TBYTE.MAP)
OBJHEX :F0:TBYTE.LOC TO :F0:TBYTE.HEX
```

The complete captured command/result transcript is in `console.typescript`.
The LOCATE map gives CODE `3680H..3692H` (19 bytes), STACK `3693H..36A0H`
(14 bytes), DATA `36A1H..36A2H` (2 bytes), and MEMORY from `36A3H`. The PL/M
listing reports CODE 19, VARIABLE 2, and MAXIMUM STACK 2. The LINK map lists
only `TBYTE.OBJ(MAIN)`, so PLM80.LIB was not needed for this program.

Exact artifact sizes and SHA-256 values, plus the source toolchain image
hashes and observations, are recorded in `manifest.json`.

## Scope and unresolved questions

This experiment supports only the machine-code observations above. It does
not establish how BYTE parameters are passed when mixed with ADDRESS values,
when there are more than two parameters, or when arguments are expressions
whose evaluation has side effects. Nor does it establish reentrancy or
parameter storage behavior across recursion. The mixed-recipe compiler
overlay caveat remains unresolved.
