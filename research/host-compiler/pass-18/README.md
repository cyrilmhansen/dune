# Faithful native +7B7A and cumulative migration — pass 18

Task `FAITHFUL_HOST_COMPILER_NATIVE_7B7A_PASS_18`; baseline
`a4f751da243847f63edeacaf2e1033e9c066a005`.

**All184 natural +7B7A shadows, all three +7B7A-only compiler runs and all three
cumulative +7BBF/+7B7A runs pass.** Every operation entry/resume register/flag and
all65536 memory bytes match its independent historical oracle. INT and REL records
match byte for byte, compilation markers succeed and all runs warm boot. No
historical contract, annotation, status, role or completeness was changed. Runner,
Cpu, Trace and packet infrastructure are unchanged. No fidelity debt was required.

## Exact natural oracle set

Corrected ordinary-return windows, not old catalog counts or dynamic contexts,
select every actual CALL to PLI1+7B7A in the existing MINIMAL/FIZZBUZ/PICTURE captures.
Live shadows regenerate full memory through unchanged historical execution;
entry/return steps, states, helper reads and writes are independently checked
against those retained captures. No64KiB snapshot or giant witness trace is committed.

| Source | Invocations | Iterations | Iteration-count distribution | Cursor wrap events |
|---|---:|---:|---|---:|
| MINIMAL | 21 | 44 | 1:8,2:6,3:4,4:3 | 0 |
| FIZZBUZ | 136 | 346 | 1:36,2:56,3:16,4:14,5:6,6:1,7:1,8:3,9:3 | 0 |
| PICTURE | 27 | 50 | 1:14,2:7,3:2,4:4 | 0 |

The ten actual caller coordinates and counts are:

| PLI1 CALL site | MINIMAL | FIZZBUZ | PICTURE |
|---|---:|---:|---:|
| +103D | 0 | 1 | 0 |
| +10E4 | 0 | 1 | 0 |
| +1161 | 0 | 1 | 0 |
| +14CD | 6 | 24 | 2 |
| +2B95 | 1 | 12 | 1 |
| +322D | 0 | 10 | 1 |
| +3F71 | 0 | 9 | 4 |
| +7C6C | 0 | 1 | 0 |
| +7D3A | 5 | 42 | 8 |
| +7DA7 | 9 | 35 | 11 |

[balance-scan-cases.json](balance-scan-cases.json) retains all184 correlated
members: original entry/return steps, caller, complete register/flag states,
full-memory hashes, every cursor/index/mapped-byte/packed-byte/low3 attribute,
adjacent discarded bytes, balance before/sum/after, logical writes and ABI residue.
Starting/stopping cursor distributions are in
[scan-characterization.json](scan-characterization.json); startingFF cases are
not confused with an observed00->FF decrement inside a scan. Natural low3
attributes are only0/1/2, with counts224/176/40 across440 iterations.

Adjacent iterations repeat the same balance7/65/7 times by source: attr1 can
leave balance unchanged while cursor continues backward. None repeats the full
(cursor,balance) state or wraps cursor; maximum observed length is9. These are
terminating observations, **not an arbitrary termination theorem**. Synthetic
unit states separately exercise a terminating00->FF cursor wrap and a44-iteration
balance-wrap path1->253->255->0; they are not new PL/I sources or compiler runs.

## Reusable logical mapping primitives

`Pli80_host.Mapped_lookup` exposes faithful +7A4D mapped_byte and +7A63
low_attribute primitives. They are sub-operations of the new Balance_scan,
**not independent global interceptors**.

+7A63 first writes position toAE37, reads the AE37/AE38 word and passes only its
low byte. +7A4D writesAE36, reads AE36/AE37, discards the adjacent high byte,
reads index`byte[AA1F+unsigned_position]`, then mapped byte`byte[AAB4+index]`.
+7A63 uses that returned byte to read`byte[1B4B+mapped]&7`. Both discarded reads
remain visible in per-iteration metadata, without invented semantic dependence.
Native primitives read current byte-addressed memory each time and preserve the
AE37-before-AE36 write order.

The possible position-map range overlaps mapped-byte storage. They remain
numeric addresses in one Bytes.t, not falsely disjoint abstract arrays. No
capacity/ownership or source-language types were invented. Protected selected
scratch/table/return-stack aliases fail closed under the established scope.

## Native iterative scan

`Pli80_host.Balance_scan` implements the exact forty-byte operation:

```text
byte[AE48] = input C
byte[AE49] = 1
repeat:
    current_cursor = little_endian_word[AE48].low
    attr = faithful_low_attribute(current_cursor)
    balance = fresh byte[AE49]
    tmp = u8(attr + balance)
    new_balance = u8(tmp - 1)
    byte[AE49] = new_balance
    // CMP 0,new_balance; JNC exits iff new_balance==0
    if new_balance==0: break
    byte[AE48] = u8(fresh byte[AE48] - 1)
return fresh byte[AE48]
```

The logical trace has two initialization writes, AE37/AE36 helper writes and
AE49 publication each iteration, and AE48 decrement only on continuation:
`4*iterations+1` writes. Every trace matches actual historical guest writes in
chronological order. The scan is not rewritten as a bounded search, precomputed
skip count, tree walk or cached attribute function. It has **no iteration limit,
cycle detector, invented cycle-rejection precondition or alternative exit**.
Conditionally nonterminating historical states remain conditionally nonterminating.
Only proven terminating compiler states are used in the differential experiments.

## Multiple callers and final ABI state

`Pli80.Balance_scan_bridge` validates historical PLI1 hash, loaded scan/helper/caller
code and canonical image/offset identity. It consumes the actual immediately
preceding CPU CALL, verifying its exact origin, CD encoding/target9D7A, state/SP
ancestry and the actual writes to the original return slot. The continuation is
that CALL site's runtimePC+3, independently checked against word[entrySP].
It is **not hard-coded to one caller** or inferred from equal-valued words.

Final state:

```text
A=stopping cursor; B=0; C=0
DE=entry DE exactly
HL=AE49; byte[AE49]=0
SP=u16(entrySP+2); PC=actual caller continuation
S=0; Z=1; AC=1; P=1; CY=0
```

Flags are the actual CMP0,0 result at+7B93, retained across LDA/RET. Every
historical snapshot independently confirms all fields, including AC1. Returned
A remains cursor data; the zero flag describes the comparison, not returned A.

## Exact stack compatibility

The bridge leaves core logical primitives free of PUSH/CALL simulation. The last
iteration always makes the outer+7B87 CALL to+7A63 and nested+7A6B CALL to+7A4D.
There are no intervening saves in these established bodies. With entrySP F:

| Final residue slot | Actual last CALL writer | Derived continuation |
|---|---|---|
| F-2/F-1 | +7B87, runtime9D87 | 9D8A |
| F-4/F-3 | +7A6B, runtime9C6B | 9C6E |

Words are derived from verified CALL coordinates/encodings, not copied from
post-state oracles. All184 historical windows and live shadows verify the last
writer/site/address/value. Original continuation atF is unchanged. Full memory
is compared directly, including residue and all unchanged cells; no stack
exemption or equality-only ancestry substitution is used.

## Proof-first hybrids and small shared plumbing

The shadow-only workbench completed all184 cases before +7B7A interception was
added. The final CLI finishes both sets of historical shadows for all three
sources before any single or cumulative replacement. Private validated tokens
bind full memory/register oracles and output records to the exact input.
Any new/omitted invocation or differing complete state fails closed, with no
historical fallback for a mismatching replacement.

`Pli80.Native_dispatch` shares only obvious comparison/dispatch work: previous
actual CALL observations, full entry/prepared/applied state comparison, ordered
logical-write digests, pending resumes, INT/REL records and transition counts.
Targets and bounds are supplied explicitly by the two routine wrappers; nothing
is discovered from contexts. Every actual guest Step is checked to ensure neither
enabled replacement body executes historically. Unsupported native body entries,
changed input, incomplete oracle consumption or bad record order fail closed.

Pass17's Packed_scan algorithm and Packed_scan_bridge are unchanged. Its hybrid
wrapper now supplies the shared dispatcher; all Pass17 tests and durable output
comparisons still pass. Runner's existing host-transition API is reused unchanged:
no PL/I callbacks, synthetic CPU Steps, fake t-states or provenance events were added.

## Complete compiler results

| Source | +7B7A-only replacements / real guest instructions | Cumulative +7BBF/+7B7A / real guest instructions | REL bytes |
|---|---|---|---:|
| MINIMAL | 21 /440120 | 3+21 /437543 | 256 |
| FIZZBUZ | 136 /1131961 | 21+136 /1112494 | 768 |
| PICTURE | 27 /516232 | 3+27 /513791 | 256 |

Both experiments reproduce:

- MINIMAL SHA-256 `7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119`.
- FIZZBUZ SHA-256 `68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`.
- PICTURE SHA-256 `c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1`.

PASS1/PASS2/END COMPILATION and warm boot succeed in every run. Temporary INT
records1/3/1 and REL records2/6/2 match the independent historical captures byte
for byte and in exact order. Entry/prepared/actual resume RAM and all register/flag
fields match for every substitution. Guest instruction/t-state metrics count
only actually executed guest instructions; cumulative native transition counts
are24/157/30. No historical timing claim is made after replacement.

## Validation and Pass19 assessment

```sh
RUNES_HOST_IMAGES=/path/to/DISK1 dune runtest
RUNES_HOST_IMAGES=/path/to/DISK1 dune exec test/native_balance_scan.exe
dune exec pli80-native-7b7a -- --toolchain /path/to/DISK1 \
  --output-dir _build/host-compiler-pass-18/new-experiment
python3 tools/annotated-assembly/test_native_7b7a_pass_18.py --images /path/to/DISK1
```

New tests check every corrected invocation and caller, actual per-iteration
helper reads/discards, separate wrapping sum/decrement, immediate CMP/JNC
polarity, ordered writes, residue ancestry and independent record hashes.
Primitive tests cover256 cursor values,256 mapped indices,256 packed bytes,
all2048 balance/low3 arithmetic pairs and all256 cursor decrements. Negative
checks cover invalid memory/byte/address state, image/helper/entry/caller identity,
non-CALL ancestry, continuation and alias errors, extra/omitted invocations and
source/input proof mismatch. No known nonterminating state is run.

[validation.json](validation.json) records project, all Pass17 tests, Pass16,
Pass13–15, all109 MINIMAL tests, packet/continuation, V1 and exact reconstruction.
All **94720 historical bytes remain exact**. [fidelity.json](fidelity.json) records
no contract correction, divergence or fidelity debt. No FACTOR or unrelated
archaeology work occurred.

**Recommend B for Pass19: bounded native +7C1B composition.** The small
[parent-scope-audit.json](parent-scope-audit.json) navigates existing predicates
and corrected windows only; it is not a new parent decompilation. Counts are
MINIMAL16, FIZZBUZ96, PICTURE21. Their observed classes are default, mapped0A,
mapped17/predecessor0A, predecessor fallback, and the one FIZZBUZ mapped1E special
case. No mapped21 special invocation appears. These states have existing scoped
operational contracts and can use already-native mapped lookups, +7BBF and +7B7A.
Remaining unsupported mapped21/opposite-clamp or other unvalidated states must
fail closed, rather than receiving guessed semantics. Add faithful auxiliary
read/write sub-operations from their complete contracts where needed. Begin with
an exact parent-frame/recursive residue audit and preserve all independent child
oracles; if compatibility cannot be explained, stop instead of approximating it.
This is readiness for an observed-scope experiment, not complete PL/I support or
an arbitrary recursion-termination claim. No +7C1B implementation began here.
