# Pass46 — bounded native +19F0 parent

Baseline: `bba1b42d60b88461c637f15418605e38d89184ff`.

The selected native root is **PLI1.OVL+19F0**, with six independent natural
windows: MINIMAL 1, FIZZBUZ 4, PICTURE 1. +6639 contains all twelve external
+6619 windows but adds only fourteen instructions per call. +19F0 instead
composes acquisition, indexed transformation and publication as one historical
operation. Its immediate caller +1AFD adds separate resident reader operations;
this pass stops at +19F0 rather than widening into that family.

The root retains its two-byte private frame. MOV B,C / PUSH B / INX SP supplies
F0 from input C; a fresh old A619 supplies F1. It clears A619/A934, tests fresh
context/mode, composes +6639 and the canonical +6619/+6223 hierarchy, performs
independent classifiers and +3533 transformation, invokes canonical +2511, then
computes the fresh cursor difference. The witnessed clear saved-input bit calls
+80B1/+8048. Literal A=0 preserves the final child flags; POP H consumes F0/F1
and RET consumes the original hardware continuation. Unsupported sibling arms
reject on copied state without live RAM, DMA, filesystem or event mutation.

The mode-one +28AA family has two routes. Four selector05 calls construct;
two required selector15 calls return at the unsigned 10-versus-selector guard.
The selected indexed position is freshly read from A634 (naturally 2), separate
from caller mode C=1. The construction path contains two independent E05
+6708 acquisitions, +46ED traversal, +4738 construction, +666E resident bit
output and independent mapped publication channels.

E05 preserves the N=8 software continuation and freshly rereads its cached
argument index and indexed limit on every iteration. The first copy pads with
20H, eventually overwriting argument bytes A9DA..A9DD; the changed index causes
the next fresh length lookup to terminate. The second copy uses independently
supplied index/length. No iteration schedule, snapshot dispatch or cycle bound
is used. Active carrier aliases at A9DE and above are rejected.

+46ED follows pointer-reference predicates and successors, then independent
null tests, positive-count payload comparison, fresh tag comparison and
successor traversal until the witnessed null endpoint. +4738 invokes the
canonical constructor with source word A948, preserves N=2 continuation
consumption and repairs the reference word through low ADD/high ADC before
publishing the final link. +666E's field09 route emits the resident counted-bit
prefix, fresh cached word and fresh byte-prefix channels. All four required
output windows are no-flush; flush/error alternatives remain unsupported.

Independent full-state shadows pass for eight E05 acquisitions, eight
traversals, four constructions, four +666E outputs, ten mode-one +28AA cases
(including independent guard calls), and all six +19F0 roots. Root proofs also
correlate canonical internal +6619 journals/CALL words and +6223 entry/return,
RAM, stack-writer and external-state checkpoints. Ordinary hardware returns,
N=2 and N=8 software continuations remain distinct mechanisms.

| Source | Pass45 guest | Pass46 guest | Removed | Host before → after |
|---|---:|---:|---:|---:|
| MINIMAL | 424898 | 414704 | 10194 | 125 → 112 |
| FIZZBUZ | 995583 | 967554 | 28029 | 388 → 340 |
| PICTURE | 495210 | 494793 | 417 | 148 → 139 |

These are actual whole-run counters, not sums of overlapping windows. Six
+6619 transitions and additional native descendants are absorbed only within
the exact +19F0 windows. Remaining external +6619 roots are 0 / 5 / 1.
Root-only and cumulative hybrids preserve REL goldens, INT/REL record and file
events, final filesystem, PASS1/PASS2/END COMPILATION and warm boot. Total native
BDOS26/21 pairs remain 1 / 3 / 1.

Eighteen procedure contracts are added or boundedly extended; 570 formerly RAW
bytes are represented. Existing E02, traversal and constructor evidence remains
retained. No global completion is claimed for +19F0/+28AA/+6708 or their partial
children. No historical correction, pragmatic divergence or fidelity debt;
zero oracle queries; no CPU, Runner, CP/M or shared proof-schema changes.

`run_parent_pass_46.py` automates inventories, CFG/ancestry extraction, shadow
clusters, hybrids, compact reports and aggregate incremental validation.
`contract-laws.json` is the canonical authored law set; annotations reuse it.
`before.json` retains the older catalog epoch; older regressions check those
exact historical assertions. Full journals remain under ignored `_build`.

Pass47 should assess bounded recursive +02F0 and run the scheduled full
checkpoint. Its outer FIZZBUZ window retains 97,961 inclusive residual
occurrences and five external +6619 calls; +1014/+109E retain 3,269/1,229
respectively. These ranking counts overlap and are not claimed savings.
Prefer a coherent +02F0 route composition rather than migrate +6639 alone.

The unrelated `scripts/view-optimist.sh` remains untouched. No persistent task files remain under `/tmp`; tests clean their temporary
directories automatically. Full proof artifacts remain under ignored `_build`.
