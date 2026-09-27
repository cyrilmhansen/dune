# PL/M-80 V4.0 three-BYTE-parameter fingerprint

This fixture tests how the local ISIS-II PL/M-80 V4.0 compiler passes three
distinct BYTE actual arguments. `THREEB.PLM` is the short ISIS basename for
this fixture. The constants are X=17 (`11H`), Y=42 (`2AH`), and Z=85 (`55H`).
The compiler reported zero program errors.

## Documented expectation and observed code

Intel's documented PL/M linkage convention says that with more than two
parameters, the final two use the register parameter slots and preceding
parameters are passed on the stack. Applied to this sample, the expectation
is X on the stack, Y in C, and Z in E. This is a documented expectation, not
an assumption used to decode the output. The relevant linkage discussion is
in Intel's [PL/M linkage conventions](https://laundry.manualsonline.com/manuals/mfg/intel/8085_1.html?p=25).

The exact located V4.0 code does that: it loads `11H` into C and pushes BC;
then loads `55H` into E, `2AH` into C, and calls P. At P entry it stores E
to Z, C to Y, then retrieves the return address and the pushed BC pair; C is
stored to X. The actual stack-passed value is the low byte C=`11H`. The
companion B byte pushed by `PUSH B` is not initialized by the observed code,
so its value is deliberately left unspecified here. Full disassembly and
the address-by-address stack reconstruction are in
[`DISASSEMBLY.md`](DISASSEMBLY.md).

This sample supports the documented final-two-register-slots expectation
for this exact three-BYTE call. Together with the two-parameter fixtures, it
also strengthens (but does not complete) the tested positional-width pattern:
position 1 BYTE/ADDRESS in C/BC and position 2 BYTE/ADDRESS in E/DE. It does
not establish ordering of multiple stack arguments, stack-passed ADDRESS or
mixed-width parameters, four or more parameters, WORD handling, other
expressions, or a universal cleanup convention.

## Environment and reproducible commands

- Simulator: z80pack Intel Intellec MDS-800 Simulator Release 1.39.
- Operating system: ISIS-II V4.3.
- Compiler banner: `ISIS-II PL/M-80 COMPILER V4.0`.
- LINK: `ISIS-II OBJECT LINKER V3.0`.
- LOCATE: `ISIS-II OBJECT LOCATER V3.0` (printed spelling).
- Short source basename: `THREEB`.

On disposable copies of the established disk images, the guest command
sequence was:

```text
COPY :CI: TO :F0:THREEB.PLM
PLM80 :F0:THREEB.PLM DEBUG XREF
LINK :F0:THREEB.OBJ TO :F0:THREEB.SAT MAP PRINT(:F0:THREEB.LMP)
LOCATE :F0:THREEB.SAT TO :F0:THREEB.LOC MAP PRINT(:F0:THREEB.MAP)
OBJHEX :F0:THREEB.LOC TO :F0:THREEB.HEX
```

The captured console transcript also records the artifact directory listing
and the retry of two file-copy commands whose first keystrokes were dropped.
Those were collection-only errors; compiler, LINK, LOCATE, and OBJHEX all
completed successfully. The LINK map includes only `THREEB.OBJ(MAIN)`, so
PLM80.LIB was not needed for this program.

The compiler reports CODE 27, VARIABLE 3, and maximum STACK 4. LOCATE places
the 27-byte CODE at `3680H..369AH`, STACK at `369BH..36AAH`, and the three
parameter bytes at `36ABH..36ADH`. The caller initializes SP to `36ABH`.
`PUSH B` reserves two bytes for the stack-passed first argument slot; the
subsequent CALL adds its two-byte return address, explaining the observed
maximum stack increase from 2 to 4 relative to the two-parameter fixture.
The locator's 16-byte STACK segment reservation is distinct from the
compiler-reported maximum stack depth.

The local `isis-ii-43.dsk` recipe labels PLM80 and overlays OV0–OV4 as V4.0
and OV5–OV6 as V3.1. This experiment did not trace individual overlay opens,
so actual overlay provenance/use remains unresolved; the banner alone does
not resolve that caveat.

Artifact sizes and SHA-256 hashes, toolchain disk hashes, and machine-readable
observations are in [`manifest.json`](manifest.json). The preserved HEX is
the absolute code image; no runtime/library module was linked in.
