# Event-time execution witnesses

`Analysis.Event_witness` records the concrete execution chronology needed to
inspect an external event in its requesting context. It does not recover
procedures, alter provenance, discard history, or assign compiler-phase
meaning.

## Evidence carried

The `RUNES_EVENT_WITNESSES 1` index identifies the run and summarizes retained
instruction and file-event counts. Chronological chunks use
`RUNES_EVENT_WITNESS_CHUNK 1`; their ordering preserves the interleaving of
guest instructions, BDOS entry, BDOS records and file operations, host-side
effects, resume snapshots, and termination.

Each instruction witness carries the step index, runtime PC, checked image/file
origin where available, fetched bytes and decoded text, pre- and post-CPU-step
register/flag snapshots, observed memory accesses, control-flow outcome, and
SP before/after. A CPU write's old byte is included when an earlier read in the
same Step establishes it (for example, a read/modify/write instruction); it is
`null` otherwise because the existing `Step` write observation only supplies
the new value. We do not reconstruct an old value from later memory. BDOS host memory effects may carry an old value
when it is directly available from the captured FCB at BDOS entry.

At BDOS entry the witness records the live guest registers, DMA, relevant FCB
address/bytes, and the immediately preceding bridge instruction. `bdos_resume`
is captured after CP/M has applied register and memory effects and before the
next guest instruction. The BDOS effect callbacks are the facts exposed by the
existing instrumentation boundary; register and FCB changes are emitted
after dispatch by comparison with the entry snapshot. Their list order is
callback/report order, not a claim about the exact internal order of host
mutations. Consequently a CPU post-step snapshot is never used as a substitute
for the post-BDOS guest state.

The chronological call-frame list is **DEDUCED**, not directly observed as a
whole. It is reconstructed from taken CALL/RST and RET outcomes and includes
call/return coordinates. A taken call's expected return PC is the sequential
address after its fetched instruction bytes; `pc_after` separately remains the
observed transfer destination. If a return does not match the top observed
frame, or has no frame, subsequent contexts are marked uncertain. This is
important for non-structured control flow and overlay changes; an uncertain
stack is not presented as a recovered procedure call tree.
Each such mismatch is also retained as a chronological
`call_context_mismatch` event with the observed target and expected frame (if
one existed), not merely as an aggregate count.

## Query and bundle workflow

Run `pli80-analyze` with `--analysis execution` (or `data` / `path`) and
`--event-witnesses`. The command writes a compact event index and all ordered
chunks under `event-witnesses/chunks/`. The report index maps canonical
image+offset coordinates and file events to the chunks containing their exact
witnesses. No Step history is exported in the ordinary summary report, and no
event-witness capture is enabled unless explicitly requested.

For the code-centric explorer bundle, pass the matching code report and
witness index, for example `--code-run OPTIMIST DIR --witness-run OPTIMIST
DIR/event-witnesses.json`. Selecting code loads its indexed chunks and shows
three representative executions first, with a paginated view over every
retained execution at that coordinate. Selecting a file-event row loads its
BDOS-entry chunk, shows the concrete request and deduced call frames, and
navigates to the bridge instruction. This is a local/offline view; it does not
reinterpret the history as procedure recovery.

File event rows also expose exact BDOS/file/record metadata and byte ranges.
File-operation and record-write observations at the same step are distinct
facts. Chunks keep one run identity and chronological position; their records
must be interpreted through the matching run index.

## OPTIMIST validation snapshot

With event witnesses enabled, OPTIMIST still terminates by warm boot after
2,535,509 instructions, reports both passes and `END COMPILATION`, emits the
same 1,408-byte `OPTIMIST.REL` SHA-256
`5fca1ffe38d11c30d20cfb99a23fe2baf002c569790bda83e09151cf36032b15`, and
removes `OPTIMIST.INT` before termination.

At the observed final `OPTIMIST.INT` record write (step 1,668,911), the BDOS
entry snapshot records function 21, `DE=1CA2H` (FCB), `DMA=1D8CH`, and bridge
origin `PLI.COM+19D4`. Its deduced active call frames include a requester in
`PLI2.OVL+045A`. The first INT record read (step 1,671,945) has a different
observed PLI2 call path, including callsites at `PLI2.OVL+152F` and
`PLI2.OVL+1399`. The separate CLOSE (1,668,996) and OPEN (1,669,083) are
retained as distinct events.

The same bridge also handles an earlier REL record write at step 840,539; its
reconstructed frames include callsites in `PLI1.OVL`, while the final REL
record write is at 2,533,978. At the latter event the frame context is marked
uncertain because an earlier observed RET mismatch occurred at step 1,681,339
(observed target `42B4H`, expected top-frame return `434CH`). These are
execution-context facts, not compiler-stage names.

The exact historical capture retained 2,535,509 instruction witnesses and 744
file events. The index plus chronological chunks occupied 2,008,933,805 bytes
(about 1.87 GiB); measured peak RSS was 4,851,452 KiB (about 4.62 GiB) and
total run/serialization wall time 17.38 seconds on the validation host. The
writer is currently full-buffer per chunk and stores the
complete witness graph in memory for the run; storage optimization is not a
goal of this milestone.

## Limits

Origins are omitted for unknown, host, or byte-inconsistent instruction
locations. Memory reads/writes are those already present in `Step`; no hidden
memory snapshot or static analysis is used. Reconstructed CALL frames can be
uncertain in the presence of computed control flow, stack manipulation,
interrupt entry, or overlay behavior not represented as conventional
CALL/RET. A bounded recent-transfer list is context, not a control-dependence
proof. Run-local routine ownership remains a separate analytical assignment.
