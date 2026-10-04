# Faithful bounded native +7C1B — pass 19

Task `FAITHFUL_HOST_COMPILER_NATIVE_7C1B_PASS_19`; baseline
`3f2e9e1cb305e98fb80d67c58bef934a4a4a1f6a`.

All **133 natural shadows**, all three +7C1B-only compiler runs and all three
hierarchical +7C1B/+7BBF/+7B7A runs pass. Every returned register, flag, continuation
and complete 65,536-byte memory matches its independent historical oracle.
INT/REL records match byte for byte, in order; all compilations retain
PASS1/PASS2/END success and warm boot. No historical annotations, contracts,
completeness, statuses, roles, progress, CPU, Runner, Trace or packet code changed.
There is no pragmatic divergence or fidelity debt.

This is a **bounded partial-scope implementation**, not a complete +7C1B contract
or general PL/I compiler. Mapped21 and the two unobserved special comparison
outcomes fail closed before any guest transition. Recursion and Balance_scan
remain conditionally terminating; no depth limit, cycle detector, memoization,
precomputed tree or guessed fallback was added.

## Natural forest and independent oracles

The existing corrected captures are reused for independent checks:

| Source | Capture | Total / roots / recursive children |
|---|---|---:|
| MINIMAL | `_build/minimal-baseline/capture` | 16 / 9 / 7 |
| FIZZBUZ | `_build/evidence-packet-cross-run/fizzbuz-capture` | 96 / 35 / 61 |
| PICTURE | `_build/discriminator-pass-15/selected-capture` | 21 / 11 / 10 |

Live shadows regenerate exact full memory through unchanged historical execution.
The preceding actual canonical CALL, its original slot writes, entry state and
matched terminal RET establish ownership. Recursion is explicit actual CALL
ancestry, not dynamic-context membership, catalog counts or equal-valued words.
All 133 invocations, including every recursive child, are independently shadowed;
duplicate value classes are not discarded. Snapshots remain private in process.

Every external caller is +7D9D. Recursive caller counts are:

| PLI1 CALL site | MINIMAL | FIZZBUZ | PICTURE |
|---|---:|---:|---:|
| +7C5D | 0 | 1 | 0 |
| +7C71 | 0 | 1 | 0 |
| +7CE3 | 2 | 17 | 2 |
| +7D2D | 5 | 42 | 8 |
| +7D9D | 9 | 35 | 11 |

[invocation-forest.json](invocation-forest.json) records all entries, actual caller
steps, parent entry identities, original return slots and resumes. Native root
trees in [recursive-cases.json](recursive-cases.json) preserve ordered descendants,
frame data, helpers, results, logical writes, hashes and final writers. Entry steps
are pre-instruction boundaries, one step after the associated CALL witness.

| Path | MINIMAL | FIZZBUZ | PICTURE |
|---|---:|---:|---:|
| default | 11 | 51 | 15 |
| mapped0A | 3 | 21 | 3 |
| mapped17 / predecessor0A | 2 | 17 | 2 |
| mapped17 / predecessor!=0A | 0 | 6 | 1 |
| mapped1E special | 0 | 1 | 0 |

Maximum recursive edges are 2/4/2, or **3/5/3 node levels**. Maximum actual stack
write depth below a root entry SP is 27/41/27 bytes. Default child-count
distributions are `{0:7,1:3,2:1}`, `{0:22,1:16,2:13}` and `{0:9,1:4,2:2}`.
These counts describe terminating observations, not arbitrary termination.

## Native representation and historical ordering

`Pli80_host.Auxiliary` adds reusable complete +7AA9 read and +7B2E publication
operations. The getter writes AE3A, reads its adjacent high byte and discards it,
freshly reads position_map and then AD08+j. The setter writes AE44 **before** AE43,
reads their neighboring word, freshly reads position_map and unconditionally
writes AD08+j. Read and publication channels remain separate; equal values never
substitute for address/write ancestry. Numeric tables remain one byte-addressed
state, including their permitted physical overlaps.

`Pli80_host.Recursive_mapped` reuses the unchanged Mapped_lookup, Packed_scan and
Balance_scan algorithms. It has no emulator/Runner dependency, instruction decoder,
CPU stepping, source/run labels or snapshot whitelist. Behavior is selected solely
by current memory and historical predicates. Explicit inherited HL/DE/SP represent
actual frame/return data; they are not a hidden CPU interpreter.

Let S be entry SP. Two PUSH H operations write high then low at S-1/S-2 and
S-3/S-4. MOV B,C / PUSH B writes input position to S-5 and a discarded copy to S-6.
INX SP establishes **F=S-5**:

```text
initial F[0..4] = [C, entryL, entryH, entryL, entryH]
F0 = input/current position
F1 = inherited L, then default low3 countdown when assigned
F2 = inherited H, then saved child/special result when assigned
F3 = inherited L, then mapped byte
F4 = inherited H, then cached auxiliary/second special child when assigned
```

Five retained frame bytes are logical compiler state. The discarded sixth byte
belongs to ABI compatibility. F1/F2/F4 are never zero-initialized or converted
into abstract optional locals. The mapped17 fallback retains inherited F1/F2/F4,
and final HL retains inherited H in its high byte.

After a fresh mapped lookup into F3:

- **0A:** call the existing faithful Packed_scan at F0, keep every repeated
  shifted-word/counter publication, return its counter and helper-derived ABI.
- **17 / predecessor0A:** fresh map at u8(F0-1), recurse there, store A in F2,
  publish F2 through Auxiliary at original F0, return F2.
- **17 / predecessor!=0A:** fresh original-position auxiliary read, return it,
  with no recursion or auxiliary publication. Natural predecessor values are05.
  The existing exact CPI0A/JZ dispatch and complete getter independently justify
  any non0A predecessor at the declared nonaliasing scope; 255 synthetic predecessor
  values test this local operation without widening the archaeological contract.
- **default:** cache original auxiliary in F4 before fresh low3 extraction into
  F1. While F1 is nonzero, decrement F0, recurse there, save child A in F2, run
  Balance_scan at that current position, replace F0 with its stopping cursor,
  then decrement F1. Return original cached F4, not the last child result.
- **1E special:** recurse at original F0-1 into F2, Balance_scan there, decrement
  its returned cursor and recurse into F4. Require the supported first<second
  comparison, replace F2 with F4, **increment modulo256**, require increment>0F,
  clamp F2 to0F, then publish at original F0. The one natural case is input5:
  child1=1, scan4->3, child2 at2 returns15, 15->16->15; publication is AD0D=15.
  Its constant clamp is a distinct producer, not inferred from equality with
  the second child's result.
- **21:** explicitly unsupported in this pass. Sharing code with1E is not used
  to invent a validated compiler-state scope.

Special first>=second, increment<=0F (including FF->00 wrapping) and unexpected
recursive mapped21 states reject the private cloned transition. No mutation reaches
historical execution on rejection. No semantic timeout/depth/cycle precondition
was invented. Table/frame/scratch/stack aliases outside declared scope also reject.

## Exact path-specific return state

All paths clean up five bytes and consume the unchanged original hardware slot.
SP=S+2 and PC is the actual CALL-site+3. Final POP H reconstructs
`HL=F3+256*F4`, including inherited data on unwritten paths.

Default returns cached F4; count0 BC is the fresh mapped byte, positive-child BC0;
DE is entry DE or last child DE retained by Balance_scan. NZPA are final CMP0,0
(S0/Z1/AC1/P1); frame address arithmetic clears CY. Mapped0A retains Packed_scan
BC/DE/NZPA. Mapped17/child retains child NZPA and getter/setter ABI distinctions.
Fallback preserves entry DE and predecessor CPI NZPA; auxiliary value does not
produce those flags. Special NZPA come from CMP0F against the wrapped increment,
while final frame arithmetic clears CY. The FIZZBUZ special return is
A15/BC5/DE000F/HL0F1E, S1/Z0/AC1/P1/CY0.

The native comparison metadata is checked against all65,536 operand pairs and
every natural returned snapshot. Important conditional branches are separately
tied to the actual immediate CPI/CMP/RAR producer in corrected witnesses.

## Recursive compatibility and final writers

`Pli80.Recursive_mapped_bridge` validates original COM/PLI1 hashes, loaded routine,
helper and caller code, canonical entry, actual preceding CALL and its original
slot writes. Private CALL proof tokens cannot be forged through the public API.
Continuation/entry/code/source mismatches fail closed.

The compatibility planner receives only explicit established CALL/carrier events.
It validates their exact image encodings/targets, derives continuation as runtime
CALL+3, and publishes the corresponding high/low stack bytes at proven depths.
It is not a decoder or general ABI recognizer. No oracle post-memory is copied.

- Recursive calls push at F-2; child entry SP=F-2 and child frame=F-7.
- Direct mapper/getter/setter CALL words share F-2/F-1 and obey actual order.
- +7A63's nested +7A6B/+7A4D CALL survives another two bytes below its call slot.
- Final Balance_scan iteration leaves +7B87 ->9D8A and +7A6B ->9C6E at its
  established helper depths.
- Packed_scan leaves its already-proven +7BF3 ->9DF6, +7BF7 ->9DFA and
  +7C14 ->9E17 words at depths6/4/2 below Packed_scan entry.
- The non0A dispatch PSW carrier is derived from SUI1/SBB A: equality maskFF
  with PSW87 or mask00 with PSW56. Its writes are bridge effects, not core
  compiler mutation. Frame PUSHes and later calls can overwrite those cells.

Deep child frames remain in memory after return and later same-depth children
reuse them. The planner tracks final last-writer identity across every overlap,
including logical frame writes that replace compatibility cells and the converse.
Native transitions replay chronological logical writes and then only final
compatibility-owned cells, so a stale CALL word cannot overwrite a later frame
assignment. The independent shadow compares **every actual written cell's final
writer coordinate and value**, its owning recursive depth, all logical write
chronology, and full memory with no stack/unchanged-memory exemption.

[stack-compatibility.json](stack-compatibility.json) retains each final stack cell's
address/value/writer/depth/kind. Depth means recursive +7C1B edges below that
individual shadow entry; nested helper byte depths are established by their
CALL/SP relation. The original outer continuation is untouched and is checked
separately by its writer/RET-consumer relation.

Transient instruction-by-instruction machine saves are intentionally outside
the native compiler algorithm. Fully explained final compatibility bytes remain
mandatory. No synthetic guest Step, t-state or provenance is manufactured.

## Hierarchical migration, not independent experiments

`Native_7c1b` shadows every natural invocation before any interception, and its
hybrid controller consumes **root** oracles only. Recursion takes place inside
the native operation. The same Native_dispatch and unchanged Runner API verify
complete entry/prepared/applied memory and register state, ordered logical writes,
all expected roots/resumes and exact output records. There is no guest fallback.

Pass17/18 controllers gained only an optional validated entry-step exclusion list
for proven child windows suppressed by a native ancestor. Primitive algorithms and
bridges are unchanged. Exact root CALL/RET windows select exclusions; arbitrary
invalid or duplicate exclusions reject. Their independent hybrids still pass.

| Source | +7C1B-only root transitions | Cumulative roots / external +7BBF / external +7B7A | Internal Packed / Balance / recursive nodes |
|---|---:|---|---|
| MINIMAL | 9 | 9 / 0 / 16 | 3 / 5 / 7 |
| FIZZBUZ | 35 | 35 / 0 / 93 | 21 / 43 / 61 |
| PICTURE | 11 | 11 / 0 / 19 | 3 / 8 / 10 |

Internal uses are counted once across native root trees, not summed again from
every overlapping child shadow. Direct Auxiliary read/write primitive counts are
11/2,57/18,16/2. Packed_scan separately contributes3/21/3 auxiliary publications,
giving5/39/5 total auxiliary writes. Internal Balance_scan performs8/111/14
iterations; Packed_scan performs36/273/34 shifts, each retaining its own updates.
All historical +7BBF entries belong to +7C1B roots; therefore its Runner-level
count is zero under hierarchy. Balance_scan has both internal and external callers.
All actual guest steps are checked: no enabled native body executes historically,
including recursive and internal Packed/Balance bodies under a replaced root.

| Source | Single actual guest instructions | Cumulative actual guest instructions | REL size / SHA-256 |
|---|---:|---:|---|
| MINIMAL | 437318 | 435902 | 256 / 7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119 |
| FIZZBUZ | 1111917 | 1102708 | 768 / 68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203 |
| PICTURE | 512974 | 511549 | 256 / c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1 |

These are real guest instructions after replacement, not historical timing.
INT records1/3/1 and REL records2/6/2 match independently retained original
capture hashes in both modes. All six runs retain all markers and warm boot.

## Validation and next boundary

```sh
RUNES_HOST_IMAGES=/path/to/DISK1 dune runtest
RUNES_HOST_IMAGES=/path/to/DISK1 dune exec test/native_recursive_mapped.exe
dune exec pli80-native-7c1b -- --toolchain /path/to/DISK1 \
  --output-dir _build/host-compiler-pass-19/new-experiment
python3 tools/annotated-assembly/test_native_7c1b_pass_19.py --images /path/to/DISK1
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
```

The output directory must be new. [validation.json](validation.json) records
native auxiliary/recursive tests, all natural shadows and six hybrids, retained
Pass17/18/16/13–15 suites, all109 MINIMAL tests, packet/corruption, V1, project
and historical reconstruction. Negative cases cover unsupported special paths,
recursive mapped21, bounds/missing memory, aliases, changed code/image/entry,
non-CALL/wrong-slot ancestry, continuation/source/input mismatch, extra roots
and omitted roots. No known nonterminating state is executed in a unit test.
Every **94,720 historical bytes reconstruct exactly**. Task temporary directories
are cleaned; ignored artifacts remain under `_build`, with no snapshots committed.

The next step should be **a remaining complete reusable stateful primitive**,
specifically +7BA2 with its complete +7AD5 sub-operation. Its mapped-byte
publication followed by a fresh map reread/AE33 update materially extends the
native state-transition surface and has an exact bounded contract/ordinary ABI.
It builds toward +7D53 without changing historical emission semantics.

+7D53 is a plausible later composition, and now inherits native recursive
processing, but it additionally requires faithful byte/word/auxiliary emission,
cursor/table recycling and resident +0EF6 buffering/host I/O at its partial scope.
It is a larger compatibility/output boundary than this next primitive. A broader
PLI1 replacement still needs targeted archaeology for unobserved shortcut/
mapped>=F7/wrap states, partial emitter error/flush scope and producer/alias/
termination questions. Neither a large parent nor more archaeology is selected
merely by size. No next routine, FACTOR attr5, fixture or archaeology change was
implemented here; +7C1B remains **stable/complete/partial**.
