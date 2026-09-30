# MINIMAL decompilation baseline V0

Task `MINIMAL_DECOMPILATION_BASELINE_V0`, building on annotated assembly commit
`3403dcc`. This is a coverage snapshot and a first set of low-level contracts,
not a compiler-wide procedure map.

**MINIMAL executes 21,012 image bytes. Of those, 148 bytes now have useful
UNDERSTOOD contracts, 138 are STRUCTURED, 304 are DECODED, and 20,422 remain
RAW.** Thus 0.70% of MINIMAL-exercised image bytes are behaviorally decompiled;
1.36% are STRUCTURED or UNDERSTOOD. Execution and understanding are separate
measurements. Unexecuted bytes are not classified as data or dead code.

## OBSERVED: coverage and execution

The existing four-run canonical reports are the coverage oracle. The MINIMAL
canonical report has 10,378 distinct image+offset instruction coordinates.
Its canonical instructions execute 439,998 times; the complete run executes
441,855 instructions. The remaining 1,857 are the modeled BDOS RET at runtime
`0005H`, whose origin is outside the historical images.

| Image | Total bytes | Executed coordinates | Executed bytes | Image coverage | Instruction executions |
|---|---:|---:|---:|---:|---:|
| PLI.COM | 8,064 | 1,544 | 3,321 | 41.18% | 266,524 |
| PLI0.OVL | 18,048 | 2,201 | 4,357 | 24.14% | 94,418 |
| PLI1.OVL | 34,816 | 3,580 | 7,148 | 20.53% | 42,875 |
| PLI2.OVL | 33,792 | 3,053 | 6,186 | 18.31% | 36,181 |
| Total | 94,720 | 10,378 | 21,012 | 22.18% | 439,998 |

Executed bytes are the union of fetched instruction-byte positions, counted
once per exact historical image. Operand bytes count. Runtime addresses alone
cannot identify overlaid code. The image SHA-256, file offset, runtime address,
exact bytes, decode, execution count, and first/last step are retained for every
coordinate in [instructions.jsonl](instructions.jsonl).

| Image | Executed + RAW | Executed + DECODED | Executed + STRUCTURED | Executed + UNDERSTOOD |
|---|---:|---:|---:|---:|
| PLI.COM | 3,006 | 142 | 65 | 108 |
| PLI0.OVL | 4,343 | 0 | 0 | 14 |
| PLI1.OVL | 7,148 | 0 | 0 | 0 |
| PLI2.OVL | 5,925 | 162 | 73 | 26 |
| Total after | 20,422 | 304 | 138 | 148 |
| Total before (3403dcc) | 20,570 | 332 | 110 | 0 |

Before/after per-image status intersections, byte ranges, capture provenance,
and the next coverage delta are in [coverage.json](coverage.json). The ten-byte
PLI2 `+6821` helper already UNDERSTOOD in V0 is **not executed by MINIMAL**;
its existing understanding contributes to whole-image progress, not this run's
understood-byte metric.

## OBSERVED: callable inventory and transfers

There are **391 distinct reached CALL targets**, with 18,412 invocations. No
RST executes in MINIMAL. Entries are grouped only by exact image+offset, never
by RoutineCandidate. The inventory retains callers/counts, invocation counts,
first/last call steps, matched RET sites/counts, return behavior, alternate
context overlaps, cross-run presence, source status, and ProcedureHypotheses.

| Image | CALL targets | Taken RET sites | Executed return-instruction sites | JMP/conditional-jump/PCHL targets | PCHL targets |
|---|---:|---:|---:|---:|---:|
| PLI.COM | 73 | 77 | 79 | 140 | 0 |
| PLI0.OVL | 64 | 70 | 70 | 152 | 2 |
| PLI1.OVL | 140 | 151 | 151 | 227 | 1 |
| PLI2.OVL | 114 | 131 | 131 | 180 | 17 |

Jump-target columns count distinct destination image coordinates, including
conditional taken jumps. PCHL targets are a subset. RET columns distinguish a
return instruction being fetched from a taken return: the two RNZs in the
three-byte comparison execute but never return in MINIMAL. Outside these image
columns, `JMP 0005H` executes 1,857 times, a jump to warm boot `0000H` executes
once, and the BDOS RET site executes 1,857 times. Full transfer edges, actual RET
counts, and software-continuation relations are in [inventory.json](inventory.json).

Current conservative entry classification is **371 unresolved, 5 STRUCTURED,
15 UNDERSTOOD** (before: 387 unresolved, 4 STRUCTURED, 0 UNDERSTOOD). Classification
requires a matching durable hypothesis and the corresponding section status at
the entry. A partial DECODED seed with a hypothesis is still unresolved by this
metric. Entry counts do not imply disjoint procedures or fully recovered bodies.

The current Event_witness reconstruction records 18,405 hardware-frame returns,
16 software-continuation returns, and **zero unexplained returns**. Seven CALL
frames do not receive an ordinary hardware return before termination: one at
PLI1 `+43D5`, two at `+4468`, two at `+6708`, one at PLI.COM `+047D`, and one at
`+19D7`. These are observations, not proof that their source procedures are
nonreturning. The last resident entry participates in warm boot. The inventory
keeps these calls distinct from software-continuation returns.

Twenty-eight entries have multiple matched RET sites. Nine pairs of callable
contexts share instruction coordinates. Clear secondary-entry families include
PLI.COM `+1A1C/+1A1D`, `+1A29/+1A2C`, `+1A33/+1A35/+1A38`, and `+1A40/+1A43`,
plus unprocessed PLI1 `+83A0/+83A3` and PLI2 `+83DC/+83DF`. PLI1 `+4693` and
`+4738` reach a common tail beginning at `+4470` and both witness a software
continuation at `+452A`. Their overlapping execution extents are retained;
they are not merged into a procedure.

The context extent in the inventory is a **DEDUCED observed stack context**:
the nearest intact hardware frame in the current upward stack-address range.
Coordinates, branches, downstream calls, and memory-access summaries under that
frame are useful evidence. They are not authoritative procedure membership.
Min/max offsets are summaries only; no procedure interval was created from them.
Software continuation counts attached to a context describe where they occur,
not an additional ordinary return assigned to that context's entry.

## DEDUCED: ten selected helper families

Priority was descriptive: shared infrastructure and repeatedly called small
primitives first. The resident word-difference entry has twenty caller sites;
the comparison guards the heavily used BDOS bridge; DMA/read wrappers lead to
all three overlay loads; the console wrapper is repeatedly exercised; the two
overlay helpers expose concrete cursor and carry conventions. Rare error paths
and unexecuted static regions were not investigated.

The table gives exclusive-end ranges. Bounds follow actual entries, documented
fall-through sequences, local branch targets and terminal RET instructions;
shared tails and secondary entries remain explicit. Every newly UNDERSTOOD
byte was already executed by MINIMAL.

| Family / primary coordinate | Exact file range | Primary CALLs | Additional observed entries | Useful contract |
|---|---|---:|---|---|
| PLI.COM+02EE | `[02EE,02FE)` | 710 | — | Save BC at 205F/2060, call BDOS 26 with DE=BC (DMA address). |
| PLI.COM+0318 | `[0318,0328)` | 687 | — | Save BC at 2063/2064, call BDOS 20 with DE=BC (FCB); delegate returned status. |
| PLI.COM+0380 | `[0380,0390)` | 424 | — | Save C at 206A, call BDOS 2 with DE=zero-extended C. |
| PLI.COM+1A0F | `[1A0F,1A1C)` | 1,858 | — | Compare three bytes through DE and HL, stopping at first unequal byte. |
| PLI.COM+1A1C | `[1A1C,1A29)` | 528 | +1A1D: 2 | Add unsigned A to indirect little-endian word; return HL and carry. |
| PLI.COM+1A29 | `[1A29,1A33)` | 43 | +1A2C: 240 | Compute DE−HL; primary entry first sets DE=unsigned A. |
| PLI.COM+1A33 | `[1A33,1A40)` | 2,230 | +1A35: 12; +1A38: 18 | Compute indirect word at DE minus loaded/supplied BC; return HL and borrow. |
| PLI.COM+1A40 | `[1A40,1A4B)` | 35 | +1A43: 677 | Compute indirect word at DE minus HL; primary zero-extends A into HL. |
| PLI0.OVL+210B | `[210B,2119)` | 225 | — | Increment word cursor at 6A6F; fetch byte at 65F3+old cursor. |
| PLI2.OVL+0F98 | `[0F98,0FB2)` | 262 | — | Return min(unsigned C+unsigned E,255), carry=overflow; keep wrapped sum at AC86. |

All **7,951** invocations of these fifteen entries were checked against explicit
arithmetic/address predicates, preserved-register claims, observed writes and
hardware return slots. The bridge adds another **1,857** checked invocations.
Representative complete local windows, register snapshots, important accesses,
contracts, pseudocode, branch edges, downstream calls and limits are retained in
[contracts.json](contracts.json); totals are in [invocation-checks.json](invocation-checks.json).
These checks compare mathematical/ABI contracts to observed states independently
of CPU semantic helpers. They do not claim exhaustive testing of all possible
inputs.

For the word primitives, carry is full-word unsigned overflow/borrow, while
other arithmetic flags come from the high-byte ADD/ADC/SUB/SBB operation;
whole-word zero/sign cannot be read from those flags. Pointer increments and
results wrap modulo 65536. The comparison preserves BC and changes DE/HL only
for matched bytes before the final comparison. MINIMAL witnesses only complete
three-byte equality: early RNZ exits are DEDUCED from the documented bytes,
not observed mismatches. The saturating-add helper has 172 matched returns at
`+0FAD` and 90 at `+0FB1`; both paths are retained and tested. Its flags other
than carry need not describe returned A.

The cursor helper's write occurs **before** its fetch; a future aliasing case
must preserve that ordering. No table length or table-content meaning is
inferred. Wrapper output registers/flags follow the observed BDOS return,
not an invented callee-save convention. The sequential-read FCB and DMA effects
come from existing BDOS semantics and file events.

The existing BDOS bridge `[19BB,19D7)` advances from DECODED to STRUCTURED. Its
1,857 calls preserve incoming BC/DE until the tail jump, then consume the
original CALL frame at host RET `0005H`. It has no local RET. Guard failure
branches to `1AE3H` remain unobserved, so the full bridge is not UNDERSTOOD.
Representative evidence is in [bridge-structure.json](bridge-structure.json).
The verifier now explicitly supports retained local RET alternatives and this
specific BDOS tail return, checking the same hardware stack-byte relation.

## OBSERVED: durable assembly progress and identity

Fifteen new address-based ProcedureHypotheses in ten families cover **148
previously RAW bytes**. All are UNDERSTOOD with the limited contracts above.
The bridge's 28 existing DECODED bytes become STRUCTURED. Semantic descriptions
accompany stable labels; none replaces image+offset identity. No PLI1 byte is
promoted in this ticket.

| Whole-image status | Before | After | Change |
|---|---:|---:|---:|
| RAW | 94,237 | 94,089 | −148 |
| DECODED | 332 | 304 | −28 |
| STRUCTURED | 141 | 169 | +28 |
| UNDERSTOOD | 10 | 158 | +148 |
| Total | 94,720 | 94,720 | 0 |

The initial progress snapshot is [annotated-progress-before.json](annotated-progress-before.json);
current per-image percentages are in the [assembly progress report](../annotated-assembly/progress.md).
All section hashes, both original/reconstructed full-image hashes, exact byte
equality, partitions and source/runtime mappings pass. Historical image hashes
remain unchanged. `dune runtest`, the ten reconstruction tests and the nine
MINIMAL baseline tests pass, including deliberate corruption and counterexamples.

## HYPOTHESIS and counterevidence

The source comments propose low-level roles such as indirect difference
primitive, indexed stream fetcher, and shared console/read/DMA gateway. Those
roles do not imply original compiler procedure names, source-language types,
or higher-level PL/I semantics. Multiple entries sharing a literal tail are
counterevidence to treating each entry as an independent disjoint procedure.

**No contradiction with the historical bytes or V0 behavioral contracts was
found.** The V0 bridge annotation's “no local RET” remains correct; new evidence
establishes its external hardware return. MINIMAL's lack of execution at PLI2
`+6821` is absence of evidence, not counterevidence to that helper's contract.
Dynamic_structure's ownership overlaps and old return-mismatch labels are not
procedure facts; the corrected Event_witness results are used instead.

## Remaining MINIMAL priorities

These are a next investigation queue, not decompiled regions:

- **Resident reader chain, PLI.COM+070C and +12AE:** 199 and 158 calls; three
  and two observed RET sites. Strong gateways into still-RAW buffer/refill code.
- **PLI.COM+09CB:** 199 calls, three RET sites, 36 context coordinates. Repeated
  branching with two downstream helpers; a useful next multi-exit reconstruction.
- **PLI0.OVL+23C3:** 334 calls from five sites, 17 context coordinates; calls the
  newly understood word-difference primitive and tests memory bits. Useful
  consumer of the recovered carry convention.
- **PLI1.OVL+4693/+4738 and nearby +4468:** shared observed tail and software
  continuation, plus hardware frames that do not return ordinarily. This needs
  stack/control-flow reconstruction before any contiguous procedure claim.
- **PLI2.OVL+1FB5:** eleven calls, 386 context coordinates and eleven software
  continuations in its reconstructed context. A larger still-RAW gateway where
  “CALL extent equals procedure body” would be particularly misleading.

## Next step: FIZZBUZ − MINIMAL

| Image | Newly executed instruction coordinates | Newly executed bytes |
|---|---:|---:|
| PLI.COM | 129 | 262 |
| PLI0.OVL | 803 | 1,471 |
| PLI1.OVL | 2,675 | 5,339 |
| PLI2.OVL | 1,164 | 2,406 |
| Total | **4,771** | **9,478** |

The coordinate delta is a set difference, not the difference of totals: six
MINIMAL coordinates are absent from FIZZBUZ. There are 135 callable targets
observed in FIZZBUZ but not MINIMAL. Examples are PLI.COM `+18FA` (30 calls),
PLI1 `+5E65` (29), `+23B9` (24), `+3558` (21), and `+387F` (21). Their bytes and
roles have **not** been investigated here. The main delta is in PLI1, then PLI2.

All fifteen selected entries are already present in the other three runs.
The cross-run inventory distinguishes “entry coordinate executed” from actual
CALL/RST-target counts: fall-through at a secondary entry can execute it without
a CALL. For example primary PLI.COM `+1A33` has 2,230 / 2,486 / 3,100 / 3,891
CALLs in MINIMAL / FIZZBUZ / FACTOR / OPTIMIST; PLI2 `+0F98` has 262 / 1,208 /
711 / 1,981. This is presence evidence, not validation of those runs' contracts.

## Reproduction and provenance

The retained MINIMAL corpus had canonical coverage but no chronological stack
or register witnesses. That gap blocked the selected contracts. One bounded
MINIMAL capture used the current Event_witness implementation; its canonical
report is exactly equal to the pre-existing report and its 256-byte REL is
byte-identical (SHA-256
`7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119`).
The approximately 394 MiB capture and intermediate analyses remain under ignored
`_build/minimal-baseline/`; they are not committed. No other new run or large
capture was generated. External corpus reports were read only.

To recreate the missing capture on Linux with the independent historical images:

```sh
dune exec pli80-analyze -- \
  --toolchain /path/to/DISK1 --source examples/pli80/MINIMAL.PLI \
  --output-dir _build/minimal-baseline/capture \
  --analysis execution --report summary --structure --event-witnesses
```

Use an unused output directory; the runner refuses to overwrite reports. Then
recompute the offline factual inventory and all selected invocation checks:

```sh
python3 tools/annotated-assembly/minimal_baseline.py \
  --capture _build/minimal-baseline/capture \
  --corpus /var/tmp/runes-event-witness-corpus \
  --optimist /var/tmp/runes-event-witness-opt-final4 \
  --images /path/to/DISK1 --output _build/minimal-baseline/recomputed
python3 tools/annotated-assembly/check_minimal_contracts.py \
  --capture _build/minimal-baseline/capture \
  --output _build/minimal-baseline/recomputed/selected-checks.json
```

`--corpus` contains `minimal/`, `fizzbuz/`, `factor/` reports; `--optimist` points
to the fourth existing run. These scripts produce ignored analysis only and do
not rewrite sources, decide procedure bounds, or assign contracts automatically.
Durable promotion is manual review of the explicit contracts, exact bytes and
control flow. Report/index/chunk hashes preserve provenance. Without the large
reports, the durable JSON/JSONL and representative windows still answer the
coverage and reconstruction questions; they cannot independently authenticate
every aggregate observation against the removed chronology.

Validate the durable result without a full capture:

```sh
dune runtest
python3 tools/annotated-assembly/test_minimal_baseline.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_verify.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
git diff --check
```

No CPU semantics, Dynamic_structure ownership, global visualization, generic
decompiler or broad static sweep was introduced.
