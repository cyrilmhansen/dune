# Intel 8080 ALU and flags

Audit date: 2026-09-24. These rules target the **8080**, not the Z80 or 8085.
All arithmetic results below are reduced to eight bits unless stated otherwise.
S is result bit 7, Z means zero, and P means an even number of one bits.
No instruction in this document changes undocumented/internal flag bits.

## References and evidence

* [Intel 8080/8085 Assembly Language Programming Manual, 1977/1978 scan](https://raw.githubusercontent.com/Mervill/Net8080/master/docs/Intel%208080-8085%20Assembly%20Language%20Programming%201977%20Intel.pdf):
  printed pp. 1-10–1-12 (flags and ANA differences), 2-8 (subtraction),
  3-12–3-14 (CMP), 3-18–3-21 (DAA/DAD/DCR), 3-25 (INR),
  3-57 (SBB example), 3-64–3-65 (SUB/SUI examples), and the individual
  rotation/logical instruction descriptions in chapter 3.
* [MAME i8085.cpp, revision 1c924ea79551fdfc3960bfa8ceb93fc1928c661b](https://github.com/mamedev/mame/blob/1c924ea79551fdfc3960bfa8ceb93fc1928c661b/src/devices/cpu/i8085/i8085.cpp):
  `op_add/adc/sub/sbb/cmp/inr/dcr/ana/xra/ora/dad` and opcode `0x27`.
  Inspect the **8080** branch of `op_ana`. Its 2012 history records the
  subtraction AC correction and passing the 8080/8085 CPU Exerciser.
* [superzazu/8080, revision 274ffd700b81baabea99b0963bc1260b67132185](https://github.com/superzazu/8080/blob/274ffd700b81baabea99b0963bc1260b67132185/i8080.c):
  complement-add subtraction and `i8080_daa` provide another formulation.
  Its [published test results](https://github.com/superzazu/8080/blob/274ffd700b81baabea99b0963bc1260b67132185/README.md)
  include 8080EXM (ALU, DAA/control flags, INR/DCR and rotations).
  This project cites MAME among its references: agreement is corroboration,
  not evidence of completely independent implementation ancestry.

No hardware measurements or complete historical exerciser run were performed
by this lab in this step. The local exhaustive tests are described below.

## Rules adopted

Let `a`, `b` be the original operands and `c` the input CY (0 or 1).
`lo(x) = x & 0x0F`. Immediate and register/memory forms share these rules.

| Family | Changed flags | Preserved | CY | AC |
| --- | --- | --- | --- | --- |
| ADD/ADI | S Z P AC CY | none | `a+b > 255` | `lo(a)+lo(b) > 15` |
| ADC/ACI | S Z P AC CY | none | `a+b+c > 255` | `lo(a)+lo(b)+c > 15` |
| SUB/SUI/CMP/CPI | S Z P AC CY | none | `a < b` (borrow) | `lo(a) >= lo(b)` |
| SBB/SBI | S Z P AC CY | none | `a < b+c` (borrow) | `lo(a) >= lo(b)+c` |
| INR | S Z P AC | CY | preserved | original low nibble is `F` |
| DCR | S Z P AC | CY | preserved | original low nibble is **not** `0` |
| ANA/ANI | S Z P AC CY | none | 0 | original `(a OR b)` bit 3 |
| XRA/XRI, ORA/ORI | S Z P AC CY | none | 0 | 0 |
| DAD | CY | S Z P AC | 16-bit sum exceeds `FFFF` | preserved |
| RLC/RAL | CY | S Z P AC | original A bit 7 | preserved |
| RRC/RAR | CY | S Z P AC | original A bit 0 | preserved |
| CMA | none | S Z P AC CY | preserved | preserved |
| STC/CMC | CY | S Z P AC | 1 / complement | preserved |
| DAA | S Z P AC CY | none | see below | carry of low correction |

CMP/CPI do not store the subtraction result in A. RAL/RAR insert the original
CY; RLC/RRC recirculate the bit shifted out. No other flag is recomputed for
rotations or DAD (not even Z/P when the result becomes zero).

### AC: resolved traps

Subtraction is complement-addition: `a + (~b & FF) + (1-c)`.
CY is the complement of the full carry; **AC is not complemented**.
This is the opposite of a Z80-style half-borrow indicator. Intel's SUB A
example (`3E-3E`) gives AC=1, CY=0; SUI (`09-01`) also gives AC=1.
Discriminating tests include `00-00` (AC=1), `10-01` (AC=0), and
SBB `04-02-1` (AC=1, Intel p. 3-57). DCR `01->00` sets AC;
`10->0F` clears it. MAME and superzazu agree with these rules.

The detailed Intel INR/DCR descriptions explicitly include AC and preserve CY;
a simplified flag table must not override those descriptions. For ANA, Intel
p. 1-12 explicitly distinguishes the 8080 bit-3 OR rule from the 8085's
unconditional AC=1. Thus `00 AND 00` clears AC, but `08 AND 00` sets it even
though the result is zero. XRA/ORA clear both AC and CY.

## DAA on all 1024 input states

Production chooses both corrections using the original A/flags:

1. Add `06` if `lo(A)>9` or input AC=1.
2. Add `60` if original `A>99` or input CY=1.
3. Store the reduced sum. S/Z/P describe it; AC is the carry out of bit 3
   of the correction addition. CY is `input CY OR original A>99`.

The independent test oracle follows Intel's sequential description: apply
the low correction in a wider integer; then test its upper portion against 9
and the original CY before applying the high correction. Keep the transient
carry through both stages. AC records the **low** correction, not an ordinary
flag-overwriting second ADD of `60`; input CY remains sticky.

Intel examples: `1A -> 20` (AC=1, CY=0), `9B -> 01` (AC=1, CY=1),
both with input AC=CY=0. Non-BCD discriminants: `FA,0,0 -> 60,1,1`;
`99,1,0 -> 9F,0,0`; `00,1,0 -> 06,0,0`; `00,0,1 -> 60,0,1`
(tuples are A,AC,CY). Truncating the low correction before observing its
carry would mis-handle `FA`. Replacing AC with the old AC, or deriving CY
only from the final addition overflow, also fails these states.

No disagreement remains between the adopted Intel interpretation, MAME's
8080 rules and superzazu over the 1024 states. This is a defined compatibility
choice backed by emulators/exerciser reports, not new physical-chip evidence.

## Local verification

`test/alu_flags.ml` uses bit-by-bit carry/borrow oracles, separately counted
parity, bit-by-bit logic, and a sequential DAA oracle. CPU tests independently
exercise instruction forms, preservation masks and ordered M accesses.

`test/reference/daa_superzazu.c` is an optional audit harness, outside Dune.
Compile it with the pinned upstream `i8080.c/.h` (`cc -std=c99 -O2 -I <ref-dir>
test/reference/daa_superzazu.c <ref-dir>/i8080.c -o <audit-exe>`).
It executes the upstream CPU, checks the two DAA formulations, and emits
two bytes per case: A then canonical PSW. Order: A=0..255, AC=0..1, CY=0..1,
CY varying fastest. The 2048-byte output has MD5
`deb0a1c2a7373b4578efc9139907abb0`, also checked by our offline OCaml tests.
This digest is an exact-output regression oracle, not a cryptographic trust
claim. Regular tests need only OCaml/Dune; no downloaded reference is required.

EI/DI and interrupt semantics remain outside this audit. The existing alias
classification and AT8TRACE v1 contract are unchanged.
