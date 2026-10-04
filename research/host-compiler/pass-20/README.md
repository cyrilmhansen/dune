# Faithful native mapped publication — pass 20

Task `FAITHFUL_HOST_COMPILER_NATIVE_MAPPED_PUBLICATION_PASS_20`; baseline
`fcc1373325d8b3d5a616b56a23687d7e42e3170c` (pushed Pass 19).

The native compiler now includes complete, scoped **PLI1+7AD5** publication and
**PLI1+7BA2** composition. All **476 natural operation shadows**, nine complete
compiler hybrids, and the final five-operation cumulative hierarchy pass.
Every register, flag, continuation and full 65,536-byte post-state matches its
independent historical oracle. All retained INT/REL records remain byte-identical
and ordered identically. PASS1/PASS2/END and warm boot succeed. No fallback,
pragmatic divergence or historical-fidelity debt was introduced.

Historical annotations, contracts, completeness, byte statuses, data roles and
MINIMAL progress remain unchanged. CPU, Runner, Trace and evidence-packet code
are unchanged. This work does not reinterpret +7D53, investigate FACTOR attr5,
or claim source-language meanings.

## Exact natural oracle set

Existing corrected captures are reused; live historical executions independently
regenerate full entry/post memory in process. No raw memory snapshot is committed.
Actual canonical CALL coordinates, original return-slot writes and matched RET
consumption establish each invocation, rather than catalog counts or context
ownership.

| Source | Capture | +7AD5 | +7BA2 |
|---|---|---:|---:|
| MINIMAL | `_build/minimal-baseline/capture` | 34 | 16 |
| FIZZBUZ | `_build/evidence-packet-cross-run/fizzbuz-capture` | 247 | 107 |
| PICTURE | `_build/discriminator-pass-15/selected-capture` | 50 | 22 |

Every duplicate invocation remains an independent oracle. The 331 setter cases
include the 145 children of recycling calls; both child and parent are shadowed
independently, without counting child interceptions inside native parents.

| PLI1 +7AD5 caller | MINIMAL | FIZZBUZ | PICTURE |
|---|---:|---:|---:|
| +2C07 | 1 | 12 | 1 |
| +2C4F | 1 | 12 | 1 |
| +3FC0 | 0 | 9 | 4 |
| +7BAE | 16 | 107 | 22 |
| +7E95 | 16 | 107 | 22 |

All MINIMAL/PICTURE recycling calls are from +7E35. FIZZBUZ has **102 from
+7E35 and five from +8209**, so a forward-iteration-only count would omit useful
natural oracles. These additional calls are included without interpreting their
parent operation.

[mapped-publication-cases.json](mapped-publication-cases.json) and
[recycle-cases.json](recycle-cases.json) retain caller, entry/return steps,
parent identity, complete returned states, entry scratch bytes, memory hashes,
selected destinations, old/new values, logical writes and ABI residue. The
independent Python checks recover these facts from corrected witnesses.

## Historical algorithm and shared storage

`Pli80_host.Mapped_publication` has no CPU, Runner, decoder, source label or
snapshot-whitelist dependency. Both operations mutate the same owned byte-addressed
`State`, shared with the existing native Mapped_lookup. There are no separate
copied arrays for position_map and mapped_byte_table. Their potentially overlapping
ranges remain physical historical addresses; only the selected forbidden alias
is rejected, without inventing table capacities or whole-array disjointness.

The +7AD5 operation preserves the exact sequence:

1. Write E to **AE3D**, then C to **AE3C**.
2. Read little-endian AE3C/AE3D; retain evidence of the adjacent high byte before
   discarding it for addressing.
3. Freshly read `j=byte[AA1F+saved_position]`.
4. Freshly read the saved value AE3D and unconditionally publish it to
   `byte[AAB4+j]`, even when equal to the old destination byte.

Its result is A=saved value, BC=zero-extended j, HL=AAB4+j, DE preserved.
NZPA remain entry flags; CY is clear from final DAD B. Returned flags are not a
Boolean interpretation of the stored value.

The +7BA2 operation preserves the exact composition:

1. Write C to **AE4A**.
2. Read little-endian AE4A/AE4B, including the discarded adjacent high byte.
3. Read little-endian **AE33/AE34** into DE; old AE33 is E and AE34 is D.
4. Call the **native +7AD5 primitive** with saved position and old AE33.
5. **After mapped-table publication**, independently reread AE4A/AE4B.
6. Freshly read position_map at that reread position, then replace **AE33**.

It returns A=the second map read, BC=AA1F, HL=AA1F+fresh saved position and
DE=the old AE33/AE34 word. NZPA are preserved and CY is clear. The child’s first
map index is recorded separately and is never substituted for the second read.
Ordered logical traces preserve AE4A, AE3D, AE3C, mapped destination, AE33.

### Read discriminator without weakening alias scope

With static nonaliasing memory, neither scratch nor the selected mapped write
modifies the accessed position-map byte; therefore first and second indices must
be equal. A *naturally differing static state* would violate the declared selected
map/destination nonaliasing contract and is explicitly rejected. Equality in the
476 natural oracles is not used to eliminate either read.

A focused test uses the established logical-write observer to **explicitly mutate
a distinct map byte after child publication**: child index2 selects AAB6, then the
observer changes AA1F to3, and recycling stores3 to AE33. A second chronological
probe changes the saved position after child publication and proves that its
carrier is reread as well. These are instrumented read-order tests, not claims
about a natural compiler state, concurrent historical mutation, a new ABI or
additional semantic scope. Production/differential callbacks only record writes.
No oracle post-state byte is copied into the algorithm.

For every 256×256 index/value pair, native publication followed by native
Mapped_lookup observes the new shared-memory value. Another256 position cases
exercise recycling, neighbor reads and exact write order. Both primitives are
tested at all32 entry flag combinations; unsupported bounds, selected aliases,
wrong images/code/canonical entries/CALL ancestry/continuations and extra/omitted
invocations fail closed before applying a historical transition.

## Machine compatibility stays outside the algorithm

`Pli80.Mapped_publication_bridge` verifies the independent historical PLI1 hash,
loaded operation/helper/caller bytes, actual canonical CALL, exact entry state,
SP ancestry and original two-byte continuation writer. Resume is **actual caller
CALL+3**, not a hard-coded parent continuation; SP returns to entrySP+2.

Standalone +7AD5 is a leaf with no body PUSH/CALL: it has **no below-entry residue
writes** to manufacture. Its original outer CALL word remains untouched and RET
consumes exactly that original slot. The full-memory oracle proves all other
bytes remain identical.

For +7BA2, the exact immutable **+7BAE CALL +7AD5** writes continuation **9DB1**
at entrySP−2/−1. No later instruction rewrites that slot, and the child has no
further stack writes. The bridge derives bytes **B1/9D** from verified CALL encoding
and runtime coordinate. Every shadow independently confirms the final writer
+7BAE, address, value, child RET and outer RET relationship. No residue byte is
copied from historical post-memory. All65,536 bytes are compared without any
stack exemption.

## Standalone, hierarchical and cumulative execution

`Native_mapped_publication` shares the established Native_dispatch comparison
machinery. Abstract proof tokens bind exact source/input, all natural entry
states, full prepared/applied post-states, ordered logical writes and INT/REL
records. Native +7BA2 executes its child internally; no synthetic Steps or
instruction/t-state/provenance events are created. Guest counters count only
actually executed instructions.

One narrow shared dispatcher fix was necessary: **select canonical image as
well as runtime PC**. FIZZBUZ executes another overlay through the numeric
+7BA2 runtime address without a selected PLI1 CALL. The old PC-only selection
would mistake that unrelated guest instruction for a native boundary. The new
selection leaves other known images executing normally; unknown/invalid selected
origins still fail through the unchanged CALL proof. A unit collision case and
the independent capture check cover this. No Runner API or ownership rule changed.

| Source | +7AD5-only | Hierarchical +7BA2 / external +7AD5 | Cumulative roots / ext Packed / ext Balance / +7BA2 / ext +7AD5 |
|---|---:|---|---|
| MINIMAL | 34 | 16 / 18 | 9 / 0 / 16 / 16 / 18 |
| FIZZBUZ | 247 | 107 / 140 | 35 / 0 / 93 / 107 / 140 |
| PICTURE | 50 | 22 / 28 | 11 / 0 / 19 / 22 / 28 |

Cumulative transition totals are **59/375/80**. Logical setter calls inside native
recycling are16/107/22. Inside native +7C1B roots, Packed_scan calls are3/21/3,
Balance_scan calls5/43/8 and logical recursive nodes16/96/21. The existing
+7C1B hierarchy and Pass17/18 algorithms are unchanged; suppressed child windows
are derived from proven historical CALL/RET ranges, never old transition counts.

All guest steps are checked against every enabled body. No replaced historical
+7C1B/+7BBF/+7B7A/+7AD5/+7BA2 body executes, including suppressed internal children.
The independent capture checks derive residual external counts separately.

| Source | Cumulative actual guest instructions | REL bytes | REL SHA-256 |
|---|---:|---:|---|
| MINIMAL | 435168 | 256 | 7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119 |
| FIZZBUZ | 1097505 | 768 | 68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203 |
| PICTURE | 510491 | 256 | c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1 |

INT records1/3/1 and REL records2/6/2 are independently matched byte-for-byte and
in order in **all nine hybrids**. Final REL, markers and warm boot agree.
[shadow-summary.json](shadow-summary.json),
[single-hybrid-summary.json](single-hybrid-summary.json),
[hierarchical-hybrid-summary.json](hierarchical-hybrid-summary.json) and
[cumulative-hybrid-summary.json](cumulative-hybrid-summary.json) retain exact counts
and oracles. [fidelity.json](fidelity.json) separates algorithm, returned ABI,
residue, shared-memory chronology and unsupported scope.

## Validation and next increment

```sh
RUNES_HOST_IMAGES=/path/to/DISK1 dune runtest
RUNES_HOST_IMAGES=/path/to/DISK1 dune exec test/native_mapped_publication.exe
dune exec pli80-native-mapped-publication -- --toolchain /path/to/DISK1 \
  --output-dir _build/host-compiler-pass-20/new-experiment
python3 tools/annotated-assembly/test_native_mapped_publication_pass_20.py \
  --images /path/to/DISK1
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
```

The output directory must be new. [validation.json](validation.json) records
**212 Python tests**, including seven new witness-backed checks, retained
Pass17–19/16/13–15 checks, all109 MINIMAL tests and27 packet/continuation tests,
packet/continuation corruption, V1, project tests and exact reconstruction of
**94,720 historical bytes**. Generated captures remain ignored. Temporary test
directories clean up automatically; no unrelated file is touched.

The smallest useful next pass should implement the **complete reusable +7B64
high3 packed-attribute operation and +7ABF second-auxiliary read**. Both are on
+7D53's direct path with exact scratch/table/flag contracts. They would extend
Mapped_lookup/Auxiliary without replacing an output boundary or inventing
historical semantics. +7A79 word lookup is already composed inside Packed_scan
but may need an explicit reusable primitive before an emission wrapper is native.

+7E46 and +7E56 have stable bounds/complete local flow but **partial contracts**:
low-word selection/cache publication and fresh high-cache reread are established,
yet both return resident +0EF6's actual machine/side-effect state. Resident
+0EF6 remains provisional/partial/partial, with buffering, nested resident/BDOS
activity and unobserved error/flush alternatives. Its exact emission boundary
requires a separate bounded archaeology/validation step; byte emission cannot
be approximated as appending to a modern output list. +7D53 should wait for that
boundary. Existing unobserved shortcuts, mapped>=F7, other attribute classes,
wrap states and arbitrary recursion/alias/provenance questions remain explicit.
No broader +7D53 investigation was conducted here.
