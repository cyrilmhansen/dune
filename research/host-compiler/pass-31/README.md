# Pass 31 — bounded native +2511 composition

Baseline: `0630f8ea83a36e58f9e7edc27c067a3a7c99256f`.

Native `State_adaptation` represents four historical operations: cached unsigned
minimum (+23A0), three-channel publication (+23D2), bounded indexed adaptation
(+240A), and its one-byte-frame parent (+2511). The core uses shared byte-addressed
memory and existing publication operations; it has no CPU, Runner or CP/M
dependency. `State_adaptation_bridge` proves canonical CALL ancestry, constructs
path-specific machine results and derives compatibility writes. The existing
Runner transaction stages the complete root, including any descendant services.
No Runner or CP/M change was required.

## Supported algorithms

+23A0 writes E to A64F before C to A64E, compares the cached unsigned bytes, then
returns the minimum. Every returned flag remains the comparison flag, independent
of the selected byte. BC and DE are preserved; HL remains A64F. This leaf has no
body stack residue.

+23D2 saves the index at A652 and publishes three separate channels in order:
A628[index] to AC73, A62B[index] to AD08, A62E[index] to AD9D. Each channel freshly
loads AE32/AE33 before invoking its existing native publisher; every publisher
freshly reads the position map. Equal values do not merge channels or writes.

+240A saves the index at A653. Selector15 invokes the cached minimum using the
limiter and indexed primary byte, writes the result through a freshly computed
address, and requires a fresh extra byte equal to zero. The default route rejects
selector16 and selector19 through fresh reads. The common tail freshly selects
the little-endian pointer at A63B+2*index, publishes it through +7AF0 at fresh AE32,
then freshly reloads the saved index for +23D2. The final child's state is the
return state. Native selection does not whitelist observed indices 0/2; a legal
index7 dependency test also exercises the common tail.

+2511 preserves MOV B,C / PUSH B / INX SP: the surviving private byte is input C
at entrySP-1. It independently reloads that actual byte for +8048 and +7EC0,
and calls +240A with explicit C=0 between them. It discards exactly one private
byte before consuming the original caller's continuation. The native operation
never substitutes returned child A/C for this stored dependency.

Unsupported selectors and inherited child scopes fail closed. Source names,
steps and snapshot hashes exist only in differential proof binding. The adapter
requires a nonaliasing high stack (AEC0..FFFC) and rejects indexed source/cache
collisions; all descendant restrictions remain enforced. No termination limit or
fallback was introduced. +240A remains globally provisional/partial/partial;
its RAW selector arms and every historical annotation remain unchanged.

## Independent natural cases

Counts are freshly obtained from actual historical executions and independently
checked against the existing corrected MINIMAL, FIZZBUZ and PICTURE captures.
Duplicates remain independent cases.

| Operation | MINIMAL | FIZZBUZ | PICTURE | Total |
|---|---:|---:|---:|---:|
| +23A0 | 3 | 58 | 7 | 68 |
| +23D2 | 8 | 77 | 13 | 98 |
| +240A | 8 | 77 | 12 | 97 |
| +2511 | 8 | 64 | 9 | 81 |

The minimum has 59 C>=E and 9 C<E cases. +240A has selector15/extra0 counts
3/41/5 and default counts 5/36/7. All 344 shadows match every returned register,
flag, SP/continuation, ordered logical write, final CPU writer and all 65,536 RAM
bytes. DMA, filesystem, record data and file-event chronology also match.
These particular new roots contain no record-flush service; existing cumulative
native emitters still perform the actual 2/6/2 CP/M services across the sources.

`natural-cases.json` retains per-case identities, child correlations and proof digests covering every state/memory/filesystem
hash and logical/final-stack writer. Large RAM copies and
complete native journals remain ignored under `_build`.

## Stack and hierarchy

Compatibility writes are derived from immutable historical instructions and
native child results, never copied from oracle post-memory. For +2511 the last
writer of SP-1 is +2512 (input C). The final +2526 CALL writes 47H at SP-2 and
29H at SP-3. Deeper residue follows the ordered child plans, including +7AF0's
proven temporary destination PUSH and its later overwrite by +23D2's calls.
Every surviving writer/address/value is
checked against historical CPU evidence. See `stack-compatibility.json`.

Standalone native transition counts equal the natural counts above. In cumulative
execution +2511 absorbs its +8048/+240A/+7EC0 children, and +240A absorbs +23A0,
+7AF0 and +23D2. New residual roots, in order +2511/+240A/+23D2/+23A0, are:

| Source | Residual roots |
|---|---|
| MINIMAL | 8 / 0 / 0 / 0 |
| FIZZBUZ | 64 / 13 / 0 / 17 |
| PICTURE | 9 / 3 / 1 / 2 |

The complete 24-operation vectors and their coordinate order are retained in
`cumulative-hybrid-summary.json` and `transition-order.json`. Enabled body
isolation remains canonical-image-aware. Internal children do not generate
Runner transitions, guest Steps or t-states.

Every focused and cumulative compilation preserves ordered INT/REL records,
file events, complete filesystem, PASS1/PASS2/END COMPILATION and warm boot.
Cumulative golden REL results:

| Source | Bytes | SHA256 |
|---|---:|---|
| MINIMAL | 256 | `7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119` |
| FIZZBUZ | 768 | `68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203` |
| PICTURE | 256 | `c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1` |

## Reproduction and validation

```
dune exec pli80-native-state-adaptation -- --toolchain /path/to/DISK1 --output-dir _build/pass31-new
RUNES_HOST_IMAGES=/path/to/DISK1 dune runtest
python3 tools/annotated-assembly/test_native_2511_pass_31.py --images /path/to/DISK1 -q
```

The native unit suite exhausts all 65,536 C/E pairs and checks independent fresh
channel inputs, private-frame reloads, unsupported routes, code/image/entry,
CALL/continuation and alias rejection. New Python tests independently replay
corrected CALL/RET windows and compare every logical/final writer and the full
native differential reports. Existing native, CP/M, archaeology, MINIMAL and
packet/continuation regressions are aggregated; final totals are in
`validation.json`: 52 categories, 287 Python tests and 34 Dune test stanzas,
including 109 MINIMAL and 27 packet/continuation tests, in two aggregate shell
invocations. All 344 shadows and 15 complete hybrids passed. Exact
reconstruction remains 94,720 historical bytes.

There is no archaeological correction, pragmatic divergence or fidelity debt.
The next-boundary decision and measured residual leverage are recorded in
`boundary-assessment.json`; no additional parent is implemented here.

## Pass32 recommendation

Recommend focused accumulated-natural contract archaeology of +6223 before
native composition. It has 21 corrected ordinary windows and 50,572 guest
instructions remaining after already-native descendants are removed. +5929 has
13 windows / 16,741 residual instructions. These exposed parents offer much
more remaining leverage than +80CA (11 / 308) or +80EF (12 / 168), but their
unreviewed local/dependency behavior cannot yet be hidden inside a faithful
implementation. +0D6E (12 / 336) is a cheap later parent composition candidate
once its exact local contract is established. This decision selects a focused
parent investigation, with explicit missing contracts, rather than another
nearby leaf migration or a broad decompilation sweep.
