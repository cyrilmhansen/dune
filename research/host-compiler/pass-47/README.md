# Pass47 — bounded recursive +02F0 parent

Baseline: `2fc80f0b09af0c07e41ca37ed79e6846e1f600d2`.
Previous full checkpoint: Pass44 `430b75bb82187216731f26588b3bfb48e6fed435`.

One canonical `Pli80_host.Recursive_parent.Parent` composes the historical
+02F0 algorithm, its newly reconstructed reader/construction family and the
canonical +19F0/+6619/+6223 children. Only outer +02F0 calls are Runner roots.
Preparation executes against staged RAM/process/filesystem state; rejection
leaves live state unchanged. No guest fallback occurs inside accepted roots.

| Source | Logical | Outer | Nested | Maximum observed depth |
|---|---:|---:|---:|---:|
| MINIMAL | 1 | 1 | 0 | 1 |
| FIZZBUZ | 8 | 1 | 7 | 5 |
| PICTURE | 2 | 2 | 0 | 1 |

Six recursive FIZZBUZ edges are direct +03CD/+03E8 calls. The seventh follows
+045E -> +11E2 -> +1268 -> +0A32 -> +0B79 -> +02F0. Acquisition mutations
and fresh selector/probe predicates control descent and termination; observed
depth five is evidence, never an implementation limit or selector.

+02F0 saves the original BC word with PUSH B, composes +80CA/+02E9,
initializes A6CA, and consumes the actual resident +18DB mask through RAR.
Fresh predicates select the reader tail, direct recursive sequence, or
inherited-frame route. Unwinding calls +01D8, POP H restores original BC into
HL, and RET consumes the actual caller continuation. Eleven-byte +11E2 and
eight-byte +0A32 frames preserve inherited channels and individual writers.

The reader family +2006 -> +1C07 selects distinct +1D13/+1BBF/+1421 descriptor
construction or +4A26/+58BB structure publication. +1AFD retains a two-byte
frame, probes opening/closing delimiters and calls canonical +19F0 for its
actual C=0 route. Independent pointer/count/selector channels remain fresh;
+1421's balance traversal includes both observed carry arms and common restore.
Each of +2006/+1C07/+1AFD has six natural calls (1/4/1), independently proved.

Resident lookahead +18DB/+1688/+1843 uses historical cached/replay bytes and
state-dependent scans. Required source/refill operations preserve counted
reads, CR/LF/EOF predicates, CP/M DMA/record chronology and publications.
+1376 gains ten independently proved quoted-selector05 cases (2/6/2), including
PLI0 callers. This extends Pass41/44 bounded acquisition; it neither replaces
those proofs nor claims global reader completeness. Doubled quote, B suffix,
caret escape, quoted EOF, listing and unobserved scanner alternatives remain
unsupported.

Independent component proofs compare registers/flags, SP/PC, ordered logical
writes, all 65,536 RAM bytes, final writers and external state. All eleven
logical +02F0 windows and four outer windows match; internal canonical child
journals and +6223 state checkpoints are correlated independently. Hardware
recursion, +4468 N=2 and +6708 N=8 copied continuations remain distinct and exact.
No compatibility byte is copied from oracle final memory.

| Source | Pre47 guest | Post47 guest | Removed | Pre/post host |
|---|---:|---:|---:|---:|
| MINIMAL | 414704 | 405284 | 9420 | 112 / 89 |
| FIZZBUZ | 967554 | 869593 | 97961 | 340 / 119 |
| PICTURE | 494793 | 476266 | 18527 | 139 / 88 |

These are actual cumulative whole-run counters, not overlapping window sums.
Six +19F0 and six remaining external +6619 transitions are absorbed; no external
+19F0/+6619/+02F0 logical calls remain outside the new root coverage. +02F0
itself contributes 1/1/2 root transitions. Standalone and cumulative compiler
runs preserve REL256/768/256 goldens, complete filesystem, file/record events,
PASS1/PASS2/END COMPILATION and warm boot.

`implementation-packet.json` is compact model-facing evidence. Contract laws,
per-contract counts/promotions, hashes, route topology and hierarchy summaries
are durable; exhaustive journals remain ignored under `_build`.
The driver automates extraction, topology, component proofs, hybrid dispatch,
report generation and checkpoint dispatch:

```
python3 tools/annotated-assembly/run_recursive_parent_pass_47.py prove
python3 tools/annotated-assembly/run_recursive_parent_pass_47.py report
python3 tools/annotated-assembly/run_recursive_parent_pass_47.py checkpoint
```

3,768 previously RAW bytes are now causally represented (3,147 overlay,
621 resident). All new major contracts remain explicitly bounded/partial.
Seventy-one bounded catalog entries are added/extended; per-contract natural
counts and byte promotions are retained in the packet and archaeology summaries.
Zero new historical oracle queries; no historical correction, runtime change,
pragmatic divergence or fidelity debt. Development corrections are listed in
`fidelity.json`; they occurred before successful differential proof.

`validation.json` records the scheduled full checkpoint, including any initial
failures and complete affected-category reruns. Historical reconstruction is
exactly 94,720 bytes. Pass48 should compose the bounded +0A32 acquisition/frame parent: three
external windows have 7,521 / 16,125 / 31,861 residual ranking occurrences and
contain all four +02F0 outer roots. Broader +0C1B/+0C75 add initialization;
compare their coherence before widening. Ranking sums are not savings claims.

Full checkpoint: 77 categories, 502 distinct Python unittest cases, 37 Dune test stanzas, four workers. Initial wall 1047.176 seconds; affected-category/metadata rerun 179.42 seconds. Initial run was not all green: seven frozen-catalog assertions plus the draft1376 count regression. All affected categories passed in full after metadata-only repair; native/runtime categories passed initially. No second full checkpoint was run.
