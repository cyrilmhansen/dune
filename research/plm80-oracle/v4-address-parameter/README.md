# Minimal PL/M-80 V4.0 single-ADDRESS fingerprint

This fixture isolates one static `BYTE` object, a procedure with exactly one
`ADDRESS` formal, and one call passing `.OBJ`. The procedure body contains
only `RETURN`; no second variable or explicit assignment is used. The
compiler nevertheless emits stores that materialize the formal parameter.
This minimal source supersedes the earlier, nonminimal version of this
fixture that also copied the formal to a `SAVED` variable; that version
remains available in Git history.

## Source and toolchain result

`ADDR.PLM` is CRLF-terminated text, 111 bytes, SHA-256
`e8fa3e126833f5e7c5b05ce03f157724a4981251008c2ddc4922d4edbc108f9f`.
The `.OBJ` parameter syntax was already accepted by the prior fixture; this
minimal form also compiled directly with no syntax adjustment:

```plm
MAIN: DO;
DECLARE OBJ BYTE;
P: PROCEDURE(X);
DECLARE X ADDRESS;
RETURN;
END P;
CALL P(.OBJ);
END MAIN;
```

The reused local environment reported ISIS-II V4.3, PL/M-80 Compiler V4.0,
Object Linker V3.0, and Object Locater V3.0. Compilation completed with zero
program errors. LINK lists only `ADDR.OBJ(MAIN)`; no library module was
needed.

The listing reports CODE=18 (`0012H`), VARIABLE=3 (`0003H`), and maximum
STACK=2 (`0002H`). LOCATE places CODE at `3680H..3691H`, reserved STACK at
`3692H..369FH`, and DATA at `36A0H..36A2H`. `OBJ` is at `36A0H`; the two-byte
formal allocation begins at `36A1H`.

## Directly observed argument handling

At `3683H` the caller executes `LXI B,36A0H`, so immediately before the call
the object's address is in BC: B=`36H` (high byte), C=`A0H` (low byte). The
CALL at `3686H` targets P at `368BH`; the argument is in registers, not an
argument stack slot.

P executes `LXI H,36A2H`, `MOV M,B`, `DCX H`, `MOV M,C`, then `RET`. Thus the
compiler writes the high byte at the higher formal address (`36A2H`) and the
low byte at the lower address (`36A1H`). The formal occupies exactly two
bytes in this listing and DATA map: address value `36A0H` is stored as
`A0H` at `36A1H`, `36H` at `36A2H` (low byte first in increasing memory
address). These are observations from this generated code only.

Full byte-for-byte disassembly and the CALL stack return-address snapshot are
in [`DISASSEMBLY.md`](DISASSEMBLY.md). Captured compiler listing, object,
linker/locator outputs, maps, and Intel HEX are preserved beside this file;
hashes and sizes are recorded in `manifest.json`.

## Exact-sample comparisons

| Fixture | CODE | VARIABLE | Maximum STACK |
|---|---:|---:|---:|
| zero parameters (`v4-micro`) | 9 | 0 | 2 |
| one BYTE (`v4-byte-parameter`) | 15 | 1 | 2 |
| one ADDRESS (this minimal fixture) | 18 | 3 | 2 |

Relative to the one-BYTE fixture this sample adds 3 CODE bytes and 2
VARIABLE bytes, with no maximum-stack change. Relative to the zero-parameter
micro baseline it adds 9 CODE bytes and 3 VARIABLE bytes, also with no
maximum-stack change. These deltas describe only these samples. They are
consistent with BC carrying this ADDRESS argument, but do not establish a
general parameter-allocation rule.

## Evidence limits

No other address expressions, formal widths, multiple parameters,
stack-passed ADDRESS values, or return values are tested here. The observed
register assignment and low/high storage order must not be generalized
beyond this sample.
