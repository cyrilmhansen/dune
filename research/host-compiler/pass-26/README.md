# Pass26 — faithful native publication primitives

Baseline: `6a8ba519e2fa56d6ba1c32322fac7381ca97148f`.

`Mapped_word.publish` implements complete PLI1+7AF0 alongside the existing
lookup; `Auxiliary.publish_secondary` implements complete PLI1+7B49 alongside
the distinct primary and secondary reads. They use the existing shared
byte-addressed State. No archaeology, Runner, CP/M, CPU or packet representation
changed. Neither +7E5F nor +8048 is implemented here.

## Independent natural oracles

The current historical MINIMAL, FIZZBUZ and PICTURE executions were rerun with
pre-instruction RAM snapshots and actual CALL/RET ancestry. Every invocation
remains an independent oracle; there is no value-class deduplication. The tests
independently reconstruct corrected windows from the existing event captures.

| Source | +7AF0 | +7B49 | Full-memory/register/flag shadows |
|---|---:|---:|---|
| MINIMAL | 26 | 38 | all 64 passed |
| FIZZBUZ | 209 | 304 | all 513 passed |
| PICTURE | 41 | 61 | all 102 passed |

Caller distributions, original entry/return steps, neighboring bytes, selected
addresses, returned states, write phases and memory hashes are retained in the
case files and fidelity manifest. No raw trace or RAM snapshot is committed.

## Historical chronology

+7AF0 writes DE high to AE40, low to AE3F, then C to AE3E. It reads the
AE3E/AE3F pair, discards its high byte for addressing, reads the fresh position
map, and performs the two successive index additions. The compatibility callback
saves that destination, then the native algorithm freshly reloads AE3F/AE40 and
publishes low then high to the selected word. A, DE and NZPA remain unchanged;
BC=j, HL=the high-byte destination, CY=0.

The temporary PUSH at +7B09 writes destination high at S-1 and low at S-2. POP
at +7B0E consumes these bytes without erasing them. The bridge derives both
bytes from the native destination and immutable PUSH/POP code, and every shadow
checks their actual last writer. It never copies historical post-memory. The
logical compiler writes and ABI residue remain separately identified.

+7B49 writes E to AE46 before C to AE45; reads their pair; reads the fresh
position map; freshly reloads AE46; and unconditionally writes AD9D+j, including
same-valued publications. A is saved E; BC=j; HL=AD9D+j; DE/NZPA preserved;
CY=0. There are no body CALL/PUSH writes. Return state is built from the actual
outer CALL continuation, not a fixed resume PC.

Width/order tests cover all 256 indices times 256 values, all positions/indices,
all 65,536 input words, both scratch/table
alias exclusions for secondary publication, unchanged-value writes, fresh
lookup visibility and all 32 entry flag combinations for each bridge. Existing
nonalias discipline remains explicit. Wrong image/entry, altered code,
non-CALL ancestry, malformed continuation, malformed byte/address inputs,
source proof mismatch and extra/omitted invocation failures are tested.

## Complete compiler experiments

Each primitive has three standalone hybrids. The full cumulative experiment
adds the two primitives to all twelve Pass25 controllers. A small refactor exposes
the existing controller list without changing its behavior. No fallback is used;
canonical image and range checks prove enabled historical bodies are absent.

Transition-vector order:
`7D53,7C1B,7BBF,7B7A,7BA2,7AD5,7B64,7ABF,0EF6,7A79,7E46,7E56,7AF0,7B49`.

| Source | Cumulative transitions | Host BDOS services |
|---|---|---:|
| MINIMAL | 21,0,0,7,0,18,0,13,88,1,0,0,26,38 | 2 |
| FIZZBUZ | 77,0,0,58,5,140,7,106,131,28,0,0,209,304 | 6 |
| PICTURE | 23,0,0,8,0,28,3,19,72,3,0,0,41,61 | 2 |

All nine hybrids preserve the ordered INT/REL records, normalized factual file
events and complete final filesystem. Both passes report no errors, END
COMPILATION is observed, and termination is warm boot. REL goldens:

| Source | Bytes | SHA256 |
|---|---:|---|
| MINIMAL | 256 | 7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119 |
| FIZZBUZ | 768 | 68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203 |
| PICTURE | 256 | c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1 |

## Reproduction and next boundary

```
RUNES_HOST_IMAGES=/path/to/DISK1 dune exec test/native_publication_primitives.exe
python3 tools/annotated-assembly/test_native_publication_primitives_pass_26.py --images /path/to/DISK1 -v
dune exec pli80-native-publication-primitives -- --toolchain /path/to/DISK1 --output-dir _build/new-pass26-results
```

Recommend Pass27 as bounded native +7E5F for unsigned end<=94. Its four
publication children now have native implementations. The exact CMP/JNC excludes
the still-unobserved +7E70 arm; reject end>94 before any live mutation. Preserve
the map-link and AE33 chronology rather than abstracting this as a record insert.
`boundary-assessment.json` lists the proof obligations. No divergence or
historical-fidelity debt was required.

Validation totals and exact 94,720-byte reconstruction are recorded in
`validation.json`.
