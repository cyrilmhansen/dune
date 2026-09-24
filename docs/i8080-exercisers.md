# Intel 8080 exerciser acceptance record

This record documents an external acceptance run of the concrete 8080 core and
the minimal CP/M userspace runner. The four `.COM` files were downloaded into
task-owned temporary directories and were not added to this repository.

## Artifact provenance

The binaries came from the [AltairClone CPU test archive](https://altairclone.com/downloads/cpu_tests/).
For each filename, the corresponding binary in the
[superzazu/8080 corpus at commit `274ffd700b81baabea99b0963bc1260b67132185`](https://github.com/superzazu/8080/tree/274ffd700b81baabea99b0963bc1260b67132185/cpu_tests)
was also fetched and compared. All four files were byte-for-byte identical
across the two locations.

| Binary | Bytes | SHA-256 | Source / authorship and rights notes |
| --- | ---: | --- | --- |
| `TST8080.COM` | 1,536 | `9561c6fb6c99efe3de00eb77e4044fd102151058b39ac2d7bce10483838a08e7` | Microcosm Associates 8080/8085 CPU Diagnostic v1.0; source credits Kelly Smith and says it was donated to SIG/M. The included source has copyright notices but no explicit license grant. [Binary](https://altairclone.com/downloads/cpu_tests/TST8080.COM), [ASM source](https://altairclone.com/downloads/cpu_tests/TST8080.ASM) |
| `8080PRE.COM` | 1,024 | `18eb3c79cba42c0718f160be6a1853cb64cdce7aa47d65780189a57bdd98c4e0` | Preliminary 8080/8085 exerciser by Ian Bartholomew and Frank Cringle, based on Cringle's preliminary test. Its source contains GPL version 2-or-later terms; this record does not independently determine the binary's redistribution status. [Binary](https://altairclone.com/downloads/cpu_tests/8080PRE.COM), [MAC source](https://altairclone.com/downloads/cpu_tests/8080PRE.MAC) |
| `CPUTEST.COM` | 19,200 | `e61a9a75348c774486c2207080ea4effbf6c2367fdace31b0731081a4144030b` | SuperSoft Associates, *Diagnostics II*, copyright 1981, according to the binary's output and archive README. No source or explicit license was found in the inspected distributions. [Binary](https://altairclone.com/downloads/cpu_tests/CPUTEST.COM), [archive README](https://altairclone.com/downloads/cpu_tests/+README.TXT) |
| `8080EXM.COM` | 4,608 | `6e3286e11bb1a8f47b8ee1280b4a067be813193363e3223c99b0d21912f44aeb` | 8080 adaptation of Frank D. Cringle's Z80 `zexlax`, modified by Ian Bartholomew and Mike Douglas. The `.MAC` source states GPL version 2-or-later terms for the original and includes the 8080 CRC table. Binary redistribution status was not separately assessed. [Binary](https://altairclone.com/downloads/cpu_tests/8080EXM.COM), [MAC source](https://altairclone.com/downloads/cpu_tests/8080EXM.MAC) |

Because the binary rights are not explicit for every artifact, and to keep the
repository free of third-party test binaries, none is committed here.

## Expected results and independent reference

The archive's `+README.TXT` identifies the tests and describes their success
signals. `TST8080.ASM` defines its operational message; `8080PRE.MAC` says a
completed run displays its success message. The expected `8080EXM` CRCs below
are encoded as four bytes in `8080EXM.MAC`. That source retains a comment that
the original Z80 exerciser's CRCs were empirical, and separately says the
2013 8080 adaptation added success CRCs published for the 8080/8085 exerciser;
the archive README calls this the modified version with correct result CRCs.
Accordingly, the table is treated as the adapted test's expected result, not as
a new measurement of physical 8080 silicon by this project.

As an independent implementation cross-check, the C99 emulator
[superzazu/8080](https://github.com/superzazu/8080/tree/274ffd700b81baabea99b0963bc1260b67132185)
was built at that pinned revision and run against the same, hash-identical
corpus. Its README documents passing all four exercisers, and its executable
was run here as well; its test executable runs the complete fixed corpus on
each invocation. It reports the same four-program success results and all 25
`8080EXM` CRCs listed below. Its README lists MAME's i8085 among resources
used, so it is a separate implementation but not claimed to be wholly
independent of all other emulator work.

## Results from this repository

Commands used (no trace was enabled):

```sh
dune exec pli80-run -- --max-steps 4000000000 /path/to/TEST.COM
```

The executable was a native Dune build on x86-64 Linux, OCaml 5.4.0, Dune
3.20.2. Times below are wall-clock observations on this host, not cycle
measurements. Runner counts include CPU instructions only; BDOS dispatch and
the warm-boot trap are not CPU steps.

| Test | Result | Runner steps | CLI wall time | Termination |
| --- | --- | ---: | ---: | --- |
| `TST8080.COM` | PASS — `CPU IS OPERATIONAL` | 648 | 0.034 s | warm boot |
| `8080PRE.COM` | PASS — `8080 Preliminary tests complete` | 1,059 | 0.040 s | warm boot |
| `CPUTEST.COM` | PASS — `CPU TESTS OK` | 33,971,128 | 1.577 s | warm boot |
| `8080EXM.COM` | PASS — `Tests complete`; all CRC groups pass | 2,919,050,420 | 145.720 s | warm boot |

Captured output, with control characters written as OCaml-style escapes:

```text
TST8080: "MICROCOSM ASSOCIATES 8080/8085 CPU DIAGNOSTIC\r\n VERSION 1.0  (C) 1980\r\n\r\n CPU IS OPERATIONAL"
8080PRE: "8080 Preliminary tests complete"
CPUTEST: "\000\000\000\000\000\000\r\nDIAGNOSTICS II V1.2 - CPU TEST\r\nCOPYRIGHT (C) 1981 - SUPERSOFT ASSOCIATES\r\n\nABCDEFGHIJKLMNOPQRSTUVWXYZ\r\nCPU IS 8080/8085\r\nBEGIN TIMING TEST\r\n\007\007END TIMING TEST\r\nCPU TESTS OK\r\n"
```

`8080EXM` prints its 25 test labels and CRC values; each line reported `PASS!`
and matched the expected source value. Its exact expected/observed table is:

| Group | Expected CRC | Observed CRC | Result |
| --- | --- | --- | --- |
| `dad <b,d,h,sp>` | `14474ba6` | `14474ba6` | PASS |
| `aluop nn` | `9e922f9e` | `9e922f9e` | PASS |
| `aluop <b,c,d,e,h,l,m,a>` | `cf762c86` | `cf762c86` | PASS |
| `<daa,cma,stc,cmc>` | `bb3f030c` | `bb3f030c` | PASS |
| `<inr,dcr> a` | `adb6460e` | `adb6460e` | PASS |
| `<inr,dcr> b` | `83ed1345` | `83ed1345` | PASS |
| `<inx,dcx> b` | `f79287cd` | `f79287cd` | PASS |
| `<inr,dcr> c` | `e5f6721b` | `e5f6721b` | PASS |
| `<inr,dcr> d` | `15b5579a` | `15b5579a` | PASS |
| `<inx,dcx> d` | `7f4e2501` | `7f4e2501` | PASS |
| `<inr,dcr> e` | `cf2ab396` | `cf2ab396` | PASS |
| `<inr,dcr> h` | `12b2952c` | `12b2952c` | PASS |
| `<inx,dcx> h` | `9f2b23c0` | `9f2b23c0` | PASS |
| `<inr,dcr> l` | `ff57d356` | `ff57d356` | PASS |
| `<inr,dcr> m` | `92e963bd` | `92e963bd` | PASS |
| `<inx,dcx> sp` | `d5702fab` | `d5702fab` | PASS |
| `lhld nnnn` | `a9c3d5cb` | `a9c3d5cb` | PASS |
| `shld nnnn` | `e8864f26` | `e8864f26` | PASS |
| `lxi <b,d,h,sp>,nnnn` | `fcf46e12` | `fcf46e12` | PASS |
| `ldax <b,d>` | `2b821d5f` | `2b821d5f` | PASS |
| `mvi <b,c,d,e,h,l,m,a>,nn` | `eaa72044` | `eaa72044` | PASS |
| `mov <bcdehla>,<bcdehla>` | `10b58cee` | `10b58cee` | PASS |
| `sta nnnn / lda nnnn` | `ed57af72` | `ed57af72` | PASS |
| `<rlc,rrc,ral,rar>` | `e0d89235` | `e0d89235` | PASS |
| `stax <b,d>` | `2b0471e9` | `2b0471e9` | PASS |

### Timing baseline

For repeatable timing, a temporary native OCaml harness called the same
`Runner.run_file` API and read its returned step count. It was not committed.
CPUTEST had one warm-up and two measured runs:

| Test / run | Steps | Wall time | Approx. MIPS |
| --- | ---: | ---: | ---: |
| CPUTEST warm-up | 33,971,128 | 1.497 s | 22.69 |
| CPUTEST measured 1 | 33,971,128 | 1.470 s | 23.11 |
| CPUTEST measured 2 | 33,971,128 | 1.456 s | 23.33 |
| 8080EXM (single run) | 2,919,050,420 | 139.591 s | 20.91 |

The separate EXM harness timing differs from the CLI wall time because the
CLI/Dune process setup and captured output are included in the latter. The
instruction counts from superzazu are 651 (TST8080), 1,061 (8080PRE),
33,971,311 (CPUTEST), and 2,919,050,698 (8080EXM). These small differences
are diagnostic only. Its pinned test harness installs `OUT 1,A` at address
0005h and `OUT 0,A` at 0000h, and increments its counter before each
`i8080_step`; our runner handles BDOS outside the CPU and traps warm boot
before executing address 0000h. Thus the count difference reflects different
CP/M shim instructions and accounting, not an instruction-result comparison.
Success and every EXM CRC agree.

## Scope and limitations

No CPU or CP/M change was needed for this acceptance run. The evidence supports
the documented opcode semantics exercised by these programs, including all
25 CRC groups, but is not a formal proof, a cycle-accuracy claim, physical-chip
verification, exhaustive verification of undocumented behavior, or
interrupt-hardware validation. The tests exercise a minimal userspace CP/M
shim, not a full CP/M BIOS or filesystem.
