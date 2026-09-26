# Reproducible PL/I-80 compiler experiments

`Pli80.Experiment` is the reusable in-process harness around the historical
PLI.COM compiler. Its inputs are the compiler COM and three overlays, a
CP/M-visible source filename and byte sequence, module name, command tail,
instruction budget, and one live-analysis level. It returns console output,
Runner termination/steps, the memory-backed virtual filesystem and REL/INT
bytes, plus setup and execution-plus-live-analysis timings. Report projection
is deliberately outside this module.

The CLI is `pli80-analyze`. For example:

```sh
mkdir -p /var/tmp/fizzbuzz-run-parent
dune exec pli80-analyze -- \
  --toolchain ~/pli/cpm/pli80/DISK1 \
  --source examples/pli80/FIZZBUZ.PLI \
  --output-dir /var/tmp/fizzbuzz-run-parent/fizzbuzz-run \
  --analysis path --report summary
```

The toolchain directory is read-only input. The output directory must not
already contain any file the command would produce. `--module NAME` overrides
the uppercased source basename and is validated as a CP/M base name of at most
eight characters. The raw tail is one leading space plus that name. `--max-steps`
must be positive.

For `.PLI`, default `--source-text cpm` normalizes LF to CRLF, preserves
existing CRLF without doubling CR, strips trailing Ctrl-Z markers and appends
exactly one. Those normalized bytes are both the compiler input and the source
bytes injected into Provenance. `--source-text raw` passes source bytes through
unchanged.

## Cost controls

Analysis and reporting are separate selections:

| Option | Live work |
|---|---|
| `--analysis run` | Concrete compiler only |
| `--analysis execution` | Execution Map |
| `--analysis data` | Execution Map and Value/Address/Flag provenance, without branch/path contexts |
| `--analysis path` | Execution Map and data plus shared concrete path-control provenance |

| Option | Post-run work |
|---|---|
| `--report none` | No report file |
| `--report summary` | Compact deterministic `RUNES_PLI80_EXPERIMENT 1` JSON |
| `--report explorer` | Execution/data report and, for `path`, control report for selected REL sinks |

Explorer sinks can be repeated with `--select-rel OFFSET`, using decimal or
`0x` hexadecimal offsets. If none are requested, the first, middle and last
bytes of the actual REL are selected and deduplicated. Exact raw slices are
expensive and opt-in through repeated `--raw-slice OFFSET`; they are not
created by ordinary analysis or explorer runs.

The existing env-gated OPTIMIST golden test remains the deep-validation path.
It checks historical selected-sink/data/path measurements, root coverage and
the exact compiler result. Its exact-slice JSON files are now only emitted when
`RUNES_RAW_SLICES` is set; report artifacts and the REL are written only when
`RUNES_PROVENANCE_OUT` points at an explicitly chosen output directory. This
keeps deep graph validation separate from ordinary generic CLI use.

Timings identify source load/normalization, setup, concrete execution plus
selected live analysis, report projections and serialization. Since analysis
runs online with instruction execution, `execution_and_live_analysis` is not a
concrete-only CPU timing. Host bytes written count files actually persisted by
the command (REL, surviving INT, reports, raw slices, summary); CP/M virtual
filesystem record writes remain memory-backed and are not host I/O.

The CLI's current JSON and explorer serializers may still build full report
strings before writing. These are remaining full-buffer serialization costs;
no Arrow, Cap'n Proto, database, or persistent provenance arena is introduced.
Future format candidates to compare against measured corpus data are streaming
zstd JSON, Arrow IPC for Perspective tables, and a compact persistent DAG.

## Validated source corpus

All examples below were compiled through `Pli80.Experiment` using the local
Digital Research PL/I-80 v1.4 toolchain. Each reported run reached warm boot,
reported successful Pass 1 and Pass 2, printed `END COMPILATION`, and produced
a REL. These results validate PLI source to REL only; no generated REL was
linked or executed.

| Source | Feature exercised | Steps | REL bytes | SHA-256 |
|---|---|---:|---:|---|
| `MINIMAL.PLI` | minimal main and output | 441,855 | 256 | `7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119` |
| `ARITH.PLI` | integer arithmetic, IF | 678,165 | 256 | `ca98a3a7e1900d65f2b8bf73b8ccdd9e0e49ce7f15768607348740b1b7a8e553` |
| `FIZZBUZ.PLI` | DO loop, MOD, conditional chain, character output | 1,145,517 | 768 | `68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203` |
| `FACTOR.PLI` | recursive function | 838,415 | 384 | `9a42e8341a013243036040c8db0e56939c699c7fbbfb20878f7ba5af8d6b470d` |
| `ARRAY.PLI` | indexed array | 668,822 | 256 | `875e6d15720691b7b1be7b537a709fb65e99efbcbb06f5761acefcffedbcb269` |
| `STRUCT.PLI` | structure and qualified field access | 653,850 | 256 | `af95363e5e428b38e0cc536ac6870cd91bc7203c86193a459c2d62e29f69ee3b` |
| `CHAR.PLI` | fixed CHARACTER data | 495,103 | 256 | `1caa65bc5823889c3a3983c48b9da1c20ac50eed0edf733ff48e2a566e757b59` |
| `FIXEDDEC.PLI` | FIXED DECIMAL arithmetic | 673,691 | 384 | `b93cddf1e9dd85fa3ef7f8a27740b43da3396c69b10ff03eab248eef2f9e9938` |
| `PICTURE.PLI` | PICTURE declaration and PUT EDIT | 518,213 | 256 | `c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1` |

Run the quick no-provenance corpus with:

```sh
scripts/test-pli80-corpus.sh ~/pli/cpm/pli80/DISK1
```

The script uses a uniquely named `/tmp/atlas-pli80-corpus-*` directory and
removes it on exit.

## Cost sample

Measurements below are one warm local sample, report disabled, with output
exported. They are indicative rather than a benchmark guarantee. Values are
wall-clock seconds from `execution+live_analysis`.

| Program | Steps | Run | Execution | Data | Path |
|---|---:|---:|---:|---:|---:|
| MINIMAL | 441,855 | 0.035 s | 0.206 s | 0.503 s | 0.587 s |
| FIZZBUZ | 1,145,517 | 0.090 s | 0.594 s | 1.339 s | 1.468 s |
| FACTOR | 838,415 | — | — | 1.090 s | 1.065 s |
| FIXEDDEC | 673,691 | — | — | 0.771 s | — |
| OPTIMIST | 2,535,509 | 0.201 s | 1.174 s | 3.000 s | 3.474 s |

The test-only deep OPTIMIST projections remain intentionally separate from
these timings. Existing historical report sizes are 9,173,753 bytes for the
data report and 1,347,372 bytes for the control report. The 1,408-byte REL is
the only host output in report-none runs. These measurements show the dominant
cost moves from concrete execution to live provenance construction; report
projection is separately timed when requested.

A generic `FIZZBUZ` path explorer run selecting REL offset `0x20` took about
1.52 s for execution/live analysis, 1.17 s for report projections and 1.23 s
for serialization. It wrote a 5,608,152-byte data report, a 609,764-byte
control report, and the 768-byte REL (6,218,684 host bytes total). This
illustrates why summary and no-report modes avoid projection walks by default.

I/O samples: a MINIMAL summary run wrote a 256-byte REL and a 658-byte
`run-summary.json`; a FIZZBUZ data run with explicitly requested
`--raw-slice 0` wrote a 768-byte REL plus a 2,447,926-byte raw slice. Without
that option, no slice file is created. The strict OPTIMIST explorer/golden
data and control JSON sizes were 9,173,753 and 1,347,372 bytes respectively.

## Explorer and legacy golden workflow

New source experiments should use `pli80-analyze --report explorer` and
explicit `--select-rel` sinks. It prints the exact bundle/open commands. The
legacy strict OPTIMIST explorer is still available when the proprietary
artifacts are present:

```sh
RUNES_HISTORICAL_DIR=/path/to/DISK1 \
RUNES_PROVENANCE_OUT=/path/to/new-report-dir \
dune exec ./test/provenance.exe
cd tools/provenance-explorer
npm run build
npm run bundle -- /path/to/new-report-dir/provenance-report.json \
  /path/to/new-report-dir/provenance-control-report.json \
  /path/to/new-report-dir/explorer-bundle
python3 -m http.server --directory /path/to/new-report-dir/explorer-bundle 8000
```

Set `RUNES_RAW_SLICES=1` in addition only when the three legacy exact slice
JSON files are specifically required. OPTIMIST-specific offsets, hashes and
deep assertions remain in the golden test, not in the generic experiment
library.
