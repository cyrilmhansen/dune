# Multi-run code evidence view

The explorer's Code evidence tab compares existing dynamic reports without
running the compiler again. Its primary coordinate is CP/M image identity
(drive, user, image name) plus file offset. The view checks fetched bytes
before it presents observations at a coordinate together. If bytes disagree,
it displays separate variants. A coordinate absent from a run remains visible
as “not observed” for that run.

The left pane lists exact image bytes and formatted 8080 instructions. Direct
navigation accepts coordinates such as `PLI.COM+0BDA` or
`PLI2.OVL+0x11E6`; previous/next navigation follows observed instruction
starts. The right pane keeps execution counts and first/last step ranges per
run. Step indexes are never averaged. Incoming/outgoing transitions retain
their observed kind and aggregate counts where the source reports contain
them.

Block intervals are evidence supplied by each run. They are not a canonical
partition: a new observation can add a boundary. RoutineCandidate contexts
are run-local analytical assignments and do not establish procedure
membership. Neither blocks nor candidate IDs are used as cross-run keys.
The view assigns no semantic compiler names and makes no procedure
hypotheses.

The bundle command accepts repeated `--code-run LABEL DIRECTORY` arguments.
Each directory must contain the existing `dynamic-structure.json`,
`dynamic-blocks.json`, and `canonical-code-blocks.json` reports. The bundler
projects those reports into a compact `code-evidence.json`; no source analysis
schema changes are needed. Example, assuming the four report directories each
contain those files:

```sh
npm run build
npm run bundle -- \
  /path/to/optimist/provenance-report.json \
  /path/to/optimist/provenance-control-report.json \
  /path/to/four-run-bundle \
  --structure /path/to/optimist/dynamic-structure.json \
  --blocks /path/to/optimist/dynamic-blocks.json \
  --canonical-code-blocks /path/to/optimist/canonical-code-blocks.json \
  --code-run MINIMAL /path/to/minimal-report \
  --code-run FIZZBUZ /path/to/fizzbuz-report \
  --code-run FACTOR /path/to/factor-report \
  --code-run OPTIMIST /path/to/optimist-report
```

The selected OPTIMIST reports also drive the existing Structure and
Provenance views. The multi-run code evidence is a read-only presentation of
the supplied reports. It cannot attribute an aggregate transfer to a
particular invocation, repair RoutineCandidate ownership, explain file
handoffs through INT, or supply machine state that the reports did not retain.
