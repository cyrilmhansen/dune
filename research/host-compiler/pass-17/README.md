# Faithful native +7BBF — pass 17

Task `FAITHFUL_HOST_COMPILER_NATIVE_7BBF_PASS_17`; baseline
`f5978c36ddcb75a30fa425553d36bec490463aab`.

**All27 historical shadows and all27 hybrid replacements pass without fidelity
debt.** MINIMAL3, FIZZBUZ21 and PICTURE3 are independent invocation oracles, not
unique-value representatives. Every operation's full65536-byte post-memory,
A/B/C/D/E/H/L, S/Z/AC/P/CY, SP and resume PC matches the original. Whole compiler
runs then succeed with native substitution at every selected occurrence, with
identical INT/REL record bytes and final golden REL files. No historical contract,
annotation, role, completeness, byte status, packet, Cpu or Trace change was made.

## Native operation and representation

`lib/pli80_host` is an independent Dune library with **no emulator, Runner or CP/M
dependency**. U8/U16 make widths/wrapping explicit; State owns a complete Bytes.t
address space and rejects missing memory or invalid addresses/bytes. Packed_scan
implements the established +7BBF operation, not instruction decoding/execution.
It keeps historical numeric addresses and aliases; no guessed tables, capacities,
parser, AST, pass framework or closed-form bit scan was added.

The actual +7BBF/+7A79/+7B2E setup/publication order is preserved:

```text
AE4B = input position
AE4C = 15                             // before the initial lookup
AE38 = saved position
read word[AE38], including AE39        // high byte discarded before addressing
j = byte[AA1F + position]
initial = little_endian_word[AB49 + 2*j]
word[AE4D] = initial                   // low then high
repeat:
    save positive mask from AE4C != 0
    old_top = word[AE4D] & 8000
    left = word[AE4D]; right = word[AE4D]
    shifted = u16(left + right)
    word[AE4D] = shifted               // every shift published low then high
    new_top = shifted & 8000
    exit unless saved counter != 0 AND old_top == new_top
    AE4C = u8(AE4C - 1)                // only on continuation
position = word[AE4B].low
publication_word = word[AE4C]          // counter + neighboring shifted-word low
AE44 = publication_word.low           // final helper saves E before C
AE43 = position
fresh_j = byte[AA1F + word[AE43].low]  // new lookup, not retained initial j
byte[AD08 + fresh_j] = byte[AE44]
returned_A = fresh byte[AE4C]
```

The input word is read through the selected map/word relationship; AE39 is
required/read/reported but has no invented semantic effect. Counter-nonzero and
top-bit equality remain distinct FF/00 masks. Every repeated scratch update and
counter decrement is retained in the logical write trace. Native write count is
`3*shifts+7`; counter decrements number`shifts-1`.

The final field-read channel is explicit: `publication_word` comes from the
historical neighboring AE4C/AE4D read; it is not reconstructed by equating a
returned word with another equal-valued channel. Native data writes reject selected
scratch/table/protected-stack aliases before mutation. Broad scratch exclusion
AE43..AE4E is the existing declared scope, not inferred storage ownership.

## Shadows first, then hybrid execution

A read-only generic Runner pre-instruction hook was added first. It provides an
immutable register/flag snapshot, bounded read access and a copying64KiB view.
Using that hook, all27 shadows passed in ignored `shadow-first` artifacts **before
interception support was added**. Full snapshots were regenerated live through
unchanged historical CPU execution; no partial snapshot was treated as full RAM.

`Pli80.Native_7bbf.shadow` compares native cloned memory with the real historical
memory immediately after the actual +7C1A RET, before +7C3A executes. It also
compares all register/flag fields, logical write chronology and final residue
writers. The first CALL is proven from the actual preceding CPU Step at+7C37,
including its target, state/SP and original-slot writes. The terminal RET and
original-slot preservation are checked separately. Native writes never supply
the historical oracle.

The CLI finishes every shadow for all three sources before any hybrid run.
An abstract validated token binds each case, private full-memory snapshot and
record oracle to the exact input. Snapshot bytes remain private in memory and
are never committed.
Hybrid execution checks each actual entry's entire memory byte array and register/flag
state against the corresponding shadow; it checks prepared and actually applied
resume states, consumes every oracle in order and rejects additional/missing calls.
There is **no fallback** to historical +7BBF on mismatch or unsupported state.

[native-cases.json](native-cases.json) retains all27 correlated cases, full-memory
hashes, entry/post-state fields, separate ABI writes and logical byte-write traces.
No64KiB snapshot or giant CPU trace is committed. New tests match entries/returns,
registers, values, logical order and residue ancestry to the retained Pass16
records and original corrected-return witness windows. Original capture record
hashes independently validate the live shadow/hybrid INT/REL write oracles.

| Initial word | Shifts | Counter | Invocation count across three sources |
|---|---:|---:|---:|
| 0000 | 16 | 0 | 3 |
| 0001 | 15 | 1 | 13 |
| 0003 | 14 | 2 | 1 |
| 0005 | 13 | 3 | 1 |
| 0007 | 13 | 3 | 1 |
| 000F | 12 | 4 | 2 |
| 0252 | 6 | 10 | 6 |

The independent unit oracle checks all65536 words using adjacent original bits
and an appended zero, rather than reusing the production shifting implementation.
It validates shift count, wrapping result, counter, publication and decrement
count. Tests also vary the discarded AE39 byte without changing the result.

## ABI bridge and full memory identity

`Pli80.Packed_scan_bridge` belongs to compatibility/differential execution, not
the native compiler algorithm. It validates historical COM/PLI1 hashes, canonical
PLI1+7BBF identity, loaded routine/helper/caller code, input bounds, continuation
9E3A at entrySP F, actual caller ancestry and stack/code/data nonaliasing.

Returned state is:

```text
A  = counter
BC = zero_extend(fresh_j)
HL = AD08 + fresh_j
DE = freshly read publication_word
SP = u16(F+2)
PC = 9E3A                             // PLI1+7C3A
S=0, Z=1, P=1, CY=0
AC = (equality_mask | saved_positive_mask).bit3
```

NZPA are the final ANA flags retained by RAR; final helper DAD clears carry.
All retained invocations happen to return AC1. **AC is not globally constant**:
a unit case FFFF reaches the sixteenth shift with counter0 and a changed top
bit, making both ANA operands zero and AC0. No contract correction was needed.

Historical execution leaves six residue bytes below F. The native core does not
simulate PUSH/CALL mechanics. The bridge derives the final words from three
verified CALL sites and writes only their final compatibility bytes:

| Byte pair | Actual last writer | Callee | Derived continuation |
|---|---|---|---|
| F-6/F-5 | +7BF3 | +82C9 | 9DF6 |
| F-4/F-3 | +7BF7 | resident+1A2C | 9DFA |
| F-2/F-1 | +7C14 | +7B2E | 9E17 |

+82C9 runs while both PSW/old-top saves are active; POP D then moves the next
CALL depth toF-4; POP B restores entrySP before the final +7B2E CALL. This
established control flow explains the last writers. All27 observed CPU write
histories independently prove the exact site/address/value relationship; equal
values alone are insufficient. The original return word atF is not rewritten.
The bridge never copies residue from the oracle. All65536 bytes match after
compatibility writes, with **no stack or unchanged-memory exemption**. Wrapping
SP/address behavior is tested independently as well.

## Narrow runtime support

Runner remains unaware of PL/I, mapped tables or this coordinate. Its generic
interceptor chooses Continue_guest_execution or Apply_host_transition containing
ordered byte writes and a complete next register/flag/SP/PC snapshot. All bounds
are validated before any transition mutation. Applied transitions skip the
intercepted instruction and re-enter the pre-instruction boundary; no decoded
instruction, Step, Trace event or guest t-state is manufactured. CPU hidden state
is left unchanged. Work budgets bound guest instructions plus host transitions;
reported guest steps/t-states/data accesses count only actually executed CPU
instructions. Native transitions are counted separately.

Pli80.Experiment exposes read-only step/record observers and canonical-origin
boundary callbacks. Hybrid mode permits execution-only analysis; structure,
provenance and event-witness modes are rejected rather than silently losing
ownership/provenance effects. Native writes to historical-image-origin cells are
rejected. This is not a debugger/checkpoint system or a new evidence model.

## Complete compiler continuation

[shadow-summary.json](shadow-summary.json) and
[hybrid-summary.json](hybrid-summary.json) retain exact compilation outcomes.

| Source | Shadows / replacements | Historical guest instructions | Hybrid actual guest instructions | REL bytes / SHA-256 |
|---|---:|---:|---:|---|
| MINIMAL | 3 / 3 | 441855 | 439278 | 256 / 7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119 |
| FIZZBUZ | 21 / 21 | 1145517 | 1126050 | 768 / 68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203 |
| PICTURE | 3 / 3 | 518213 | 515772 | 256 / c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1 |

These are actual guest execution counts after substitution, **not historical
instruction/timing counts**. All three runs retain PASS1 success, PASS2 success,
END COMPILATION and warm boot. All temporary INT records (1/3/1) and REL records
(2/6/2) match byte for byte, in file/record order, before INT deletion. REL identity
is an additional oracle, not a substitute for operation/full-memory comparisons.

## Validation and next increment

```sh
RUNES_HOST_IMAGES=/path/to/DISK1 dune runtest
RUNES_HOST_IMAGES=/path/to/DISK1 dune exec test/native_packed_scan.exe
dune exec pli80-native-7bbf -- --toolchain /path/to/DISK1 \
  --output-dir _build/host-compiler-pass-17/new-experiment
python3 tools/annotated-assembly/test_native_7bbf_pass_17.py --images /path/to/DISK1
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
```

The output directory must be new. Native/bridge negative tests reject missing
memory, invalid byte/address/position bounds, alias overlap, changed image/code,
wrong origin/entry/continuation and an invalid generic transition. Abstract proof
tokens and exact per-case binding prevent unvalidated hybrid inputs. Generic
Runner tests check independent snapshot copies, skipped-instruction accounting,
no fake Step and bounded host-only loops. [validation.json](validation.json)
records new tests, Pass16/15/14/13, every MINIMAL suite, packet/continuation,
project/V1 and exact reconstruction checks. All **94720 historical bytes remain
exact**, and all archaeology/progress metadata is unchanged.

[fidelity.json](fidelity.json) has no unresolved difference or historical-fidelity
debt. Machine transient mechanics are intentionally outside the core algorithm,
while all final guest-visible effects are accounted for explicitly. No pragmatic
substitute or guessed compiler semantics was necessary.

**Pass18 recommendation:** implement the existing complete +7B7A wrapping reverse
balance scan with the same proof-first, full-memory methodology. It is a reusable
FIZZBUZ-path algorithm with explicit table/cursor state, and a suitable next
building block before replacing the more complex partial +7C1B composition.
No FACTOR attr5 work, new fixture or other procedure implementation began here.
