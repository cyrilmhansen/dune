# Intel 8080 interrupts: research notes

Audit date: 2026-09-24. Scope is the original maskable 8080 `INT`/`INTE`
mechanism, not the 8085 additions or Z80 interrupts. This is an evidence pack,
not an implementation specification for bus-cycle timing.

Evidence labels below mean: **Intel-established** is stated by Intel material;
**corroborated** is implementation evidence; **inferred** follows from the
documented rule but is not a separately spelled-out Intel corner case;
**uncertain** means the source set does not settle it.

## Primary-source findings

The *Intel 8080 Microcomputer Systems User's Manual* (Intel, 1974; instruction
manual scan) is unusually direct:

* §3.16, printed pp. 3-100–3-101: `EI` sets the interrupt-enable (`INTE`)
  flip-flop; `DI` resets it, and the disabled CPU ignores interrupts. Neither
  changes condition flags.
* §3.18, printed p. 3-104: `HLT` advances PC to the next sequential address and
  enters STOPPED; activity resumes on an interrupt. It warns that executing
  HLT with `INTE=0` requires power-down/repower to resume.
* §6.0, printed pp. 6-1–6-2: the CPU finishes its current instruction, clears
  `INTE`, and the interrupting device supplies one instruction via hardware;
  that instruction is not in memory and PC is not incremented before it. Intel
  says it is normally `RST`, but explicitly permits **any 8080 instruction**.
  The example supplies `RST 0`; that instruction pushes the still-next PC and
  vectors to zero.

The *8080/8085 Assembly Language Programming Manual* (Intel, copyright
1977/1978; the May 1981 revision is order no. 9800301-04) makes the delay
explicit. Chapter 3, `EI`, says the interrupt system is enabled following
execution of the next program instruction, to let an interrupt routine return
before another interrupt is acknowledged. Chapter 7, printed p. 74, says
acknowledge disables the interrupt system and an ISR may be interrupted one
instruction after executing EI. These are shared 8080/8085 instructions and
rules. Nearby discussion of the non-maskable `TRAP`, RIM/SIM, and 8085-specific
interrupts is **not** applicable to an 8080.

For the electrical/bus side, Intel's 8228 datasheet says its control signals
allow multi-byte instructions such as CALL in response to 8080A interrupt
acknowledge. Intel's 8259A datasheet, §7.2 “8086/8088 and 8080/8085 System
Connections”, describes the 8080/8085 mode's three INTA pulses: the first
supplies CALL (`CD`), the next two supply the low and high target bytes. This
corroborates that instruction-stream supply can include operands when the
system's acknowledge hardware is designed to do so; it does not mean the CPU
has an intrinsic interrupt vector.

## EI/DI semantics and delay

| Sequence / rule | Finding |
| --- | --- |
| `EI` alone | **Intel-established:** enables interrupt recognition only after one further program instruction has executed. No flags change. |
| `EI; NOP` | **Intel-established:** an enabled pending request is not accepted before NOP completes; it may be accepted at the next instruction boundary, before the following memory instruction. |
| `EI; DI` | **Inferred, corroborated by MAME:** no acceptance window exists between EI and DI. DI's immediate clear wins; the delayed eligibility does not re-enable interrupts after DI. Intel describes EI's one-instruction delay and DI's reset but does not spell out this two-opcode sequence in the cited manual. |
| `EI; EI` | **Inferred, corroborated by MAME:** the first EI cannot admit an interrupt before the second EI executes; the second EI starts/restarts its own one-instruction delay. Earliest acceptance is after the instruction following the second EI. |
| `EI; HLT` | **Inferred from Intel EI and HLT descriptions:** HLT is the protected next instruction. With an enabled request pending, it completes and the interrupt can then be accepted, releasing STOPPED. Without an acceptable interrupt, the processor remains stopped. |
| Internal mechanism | **Not established by the programming manual:** whether physical INTE changes immediately while recognition is inhibited, or changes only after the delay, is not an architectural distinction specified there. |

`DI` is immediate: it resets INTE and inhibits recognition; Intel specifies no
DI delay and no other side effect. `EI;DI` has no architecturally observable
acceptance point between the two instructions. The conclusion that DI cancels
the pending enable is a necessary practical reading of the two instructions'
effects and is implemented that way by MAME, but the exact internal latch
sequencing is not described by Intel in the sources above.

## Interrupt acknowledge and supplied instruction

**Intel-established:** this is not an implicit CPU call. At acknowledge, the
external device/controller places instruction data on the bus. The CPU executes
that instruction with the interrupted PC still pointing at the next ordinary
instruction. The CPU itself clears INTE on acknowledge. Stack activity occurs
only if the supplied instruction's normal semantics cause it: a supplied RST
or CALL pushes the interrupted PC; a supplied NOP does not. RST is customary,
not a restriction. Intel explicitly allows any 8080 instruction; Intel's 8228
and 8259 documentation demonstrates how a multi-byte CALL and its operands can
be supplied over acknowledge phases. Accordingly a future emulator input must
not be hard-coded to an RST vector. A byte stream of one to three bytes (or a
callback for acknowledge reads) is the fidelity-preserving boundary; a
restricted RST-only convenience API could sit above it but cannot be the only
model.

No 8080 equivalent of 8085 RST 5.5/6.5/7.5, TRAP, priority masks, RIM/SIM, or
Z80 IM modes is implied here. The 8080 exposes a single maskable interrupt
request; vector selection and any priority/latching policy belong to external
hardware.

## HLT interaction

Intel's visible PC after HLT is the address after HLT. While stopped, ordinary
instruction execution does not proceed. An enabled interrupt acknowledge
releases STOPPED and the supplied instruction executes with this next PC; if
that instruction is RST, it pushes the address after HLT. If interrupts are
disabled, an asserted request cannot be accepted and HLT does not resume by
that request. The 1974 manual gives the stronger operational warning that HLT
with INTE clear needs power-down/repower. No reset/power-cycle model is in our
current userspace CPU API, so eventual HLT recovery should be specifically
defined for accepted interrupts rather than simulated as arbitrary `step`.

This matches the current emulator's logical choice (`HLT` advances PC and sets
halted; another ordinary `step` returns `Cpu_halted`) at the architectural
boundary. It still needs an explicit accepted-interrupt path capable of
unhalting it; do not change current behavior as part of this research task.

## Post-acceptance state, nesting, and requests

**Intel-established:** INTE is cleared when an interrupt is acknowledged.
Thus a second maskable interrupt cannot nest until software executes EI and
then completes one further instruction. Intel's example permits nesting after
that point. The supplied RST/CALL does not itself alter INTE beyond the clear
performed on acknowledge; ordinary software RST/CALL likewise are not interrupt
acknowledges.

The CPU's documented architectural state includes the INTE flip-flop, PC,
registers and flags; there is no CPU-visible interrupt vector or 8080 pending-
interrupt register. Whether a short pulse while disabled is remembered is a
system/device property not safely modeled as an 8080-core queue. Keep request
level/latching and source priority outside Cpu; for a minimal harness, require
the requester to hold or latch a request until acceptance/acknowledge. Exact
electrical pulse capture is **uncertain/out of scope** here.

## Exerciser coverage

These are instruction/CPU exercisers, not interrupt-system validation. None of
the inspected material establishes an external INT + INTA test with a device
supplying opcodes, or HLT wake through acknowledge.

| Exerciser | Interrupt evidence | Future userspace-runner relevance |
| --- | --- | --- |
| [`8080PRE`](https://altairclone.com/downloads/cpu_tests/8080PRE.MAC) | Preliminary instruction checks; HLT is an error stop in the source. No request/acknowledge test found. | Runs as CP/M program using console BDOS; useful for ordinary instructions, not interrupts. |
| [`TST8080`](https://altairclone.com/downloads/cpu_tests/TST8080.ASM) | Source explicitly lists HLT, DI, EI (plus 8085 instructions) among instructions not tested. No interrupt test. | CP/M/BDOS-style executable; ordinary CPU checks can run in userspace. |
| [`8080EXM`](https://altairclone.com/downloads/cpu_tests/8080EXM.MAC) | Extensive instruction-group/CRC exerciser; no EI/DI/INT/acknowledge routine in inspected source. | CP/M program; valuable for CPU semantics but not hardware interrupt behavior. |
| `CPUTEST` | The inspected distribution provides only `CPUTEST.COM`, not its source. Its interrupt coverage cannot be established from that artifact listing; no external acknowledge hardware is documented. Do not claim it tests or definitively omits EI/DI without disassembly/source. | As a CP/M diagnostic it may run in a userspace runner for its supported BDOS needs; it cannot validate external INTA without an explicit harness. |

The AltairClone distribution lists all four artifacts and source for the first
three. `TST8080`'s exclusion comment is direct evidence. A comprehensive
pass-report from an emulator is not evidence that these programs tested
interrupt inputs.

## Emulator corroboration and family distinction

MAME source was inspected at exact revision
[`21799a0670b0915252c4cc956c62eaf1be378aff`](https://github.com/mamedev/mame/blob/21799a0670b0915252c4cc956c62eaf1be378aff/src/devices/cpu/i8085/i8085.cpp),
in its classic INTR path. It sets EI's INTE latch and a delayed-accept counter;
the execution loop suppresses recognition until the next instruction has
completed. DI clears INTE. On accepted classic INTR it breaks HLT, obtains an
opcode with `read_inta`, clears INTE, and executes that opcode. Operand reads
for a multi-byte supplied instruction also use acknowledge reads; RST pushes
the PC through its ordinary instruction helper. This closely corroborates the
Intel manual. It is an implementation, not a primary historical source, and
the file has shared 8085 machinery / acknowledged Z80-derived ancestry.

Do not copy its 8085-only paths: TRAP, RST 5.5/6.5/7.5, masks, RIM/SIM, SID/SOD
and 8085-specific timing/state are distinct. For original 8080, use only the
single classic maskable INTR/INTA path. MAME's `m_after_ei` counter is one
implementation of the architectural delay, not evidence that Intel exposed
that exact internal state machine.

No meaningful Intel-vs-MAME contradiction was found for the classic 8080
behavior. Exact physical latch timing and transient request retention remain
outside what this source set establishes.

## Smallest recommended emulator model

For a future implementation, keep the model to:

1. CPU-owned `interrupt_enabled` and a one-instruction EI inhibition/pending
   state, plus existing `halted`.
2. An externally owned held/latching request. At an instruction boundary, if
   enabled and eligible, accept it before the next memory fetch.
3. An acknowledge byte source supplying the opcode and any operand bytes. Feed
   those bytes through the existing decoder and concrete instruction semantics;
   do not synthesize a hidden CALL or force an RST vector.
4. On acceptance, clear INTE before executing the supplied instruction and
   release halted state. Let that instruction's normal semantics determine
   PC/stack effects.

The exact API should make the acknowledge source explicit (for example, a
callback returning up to three bytes at acceptance). Do not put PIC priority,
timer scheduling, or CP/M policy inside Cpu. Runner can own deterministic
request timing for experiments; a hardware-oriented harness can provide a
different source.

### Proposed invariants

* No acceptance during EI or before completion of its next instruction.
* DI takes effect immediately; `EI;DI` cannot leave interrupts enabled.
* A second EI restarts its one-instruction inhibit.
* Accepted interrupt clears INTE and cannot nest until EI plus one completed
  instruction.
* Interrupt acceptance itself does not push PC; injected instruction semantics
  alone cause stack effects.
* With HLT, no normal memory fetch occurs while stopped; accepted interrupt
  resumes at the already-advanced PC. A supplied RST pushes that PC.
* External request state and acknowledge bytes are explicit experiment inputs,
  not hidden nondeterminism in a default deterministic Runner.

## Step and future symbolic boundary

The accepted supplied instruction should be observable as one live `Step`:
`pc_before` is the interrupted next-instruction PC; decoded opcode/bytes are the
acknowledge-supplied bytes; stack accesses caused by supplied CALL/RST appear in
ordinary ordered memory accesses. Eventually distinguish memory-fetched bytes
from interrupt-acknowledge bytes in live instrumentation. AT8TRACE v1 need not
change now; persist interrupt-origin runs only with an explicit future format
version or event extension, not by silently pretending these bytes came from
memory.

For concolic/shadow work, request timing and acknowledge bytes are asynchronous
external inputs that can alter control flow. Keep their schedule explicit and
deterministic in Runner; carry instruction-byte origin online so an injected
opcode is not falsely attributed to program memory. No symbolic interrupt model
is specified here.

## References

* Intel, *8080 Microcomputer Systems User's Manual*, May 1974, Vol. 1:
  §§3.16, 3.18, 6.0, printed pp. 3-100–3-104 and 6-1–6-2. [Manual scan/transcription](https://manualzz.com/doc/12231281/intel-8080-microcomputer-system-user-manual); [Google Books catalog record](https://books.google.com/books/about/Intel_8080_Microcomputer_Systems_User_s.html?id=2VpGAAAAYAAJ).
* Intel, *8080/8085 Assembly Language Programming Manual*, copyright
  1977/1978; also revision 9800301-04, May 1981: ch. 3, EI instruction; ch. 7,
  “Interrupts” / “Writing Interrupt Subroutines,” printed p. 74. [May 1981 scan](https://archive.decromancer.ca/bitsavers.org/pdf/intel/ISIS_II/9800301-04_8080_8085_Assembly_Language_Programming_Manual_May81.pdf).
* Intel, *8228 System Controller and Bus Driver*, datasheet, “Features”:
  multi-byte interrupt-acknowledge instruction capability (e.g. CALL).
  [Intel 8228 scan](https://deramp.com/downloads/intel/8080%20Data%20Sheet.pdf).
* Intel, *8259A Programmable Interrupt Controller*, datasheet, §7.2,
  8080/8085 system connections (three INTA cycles, CALL plus address bytes).
  [Datasheet scan hosted by Renesas](https://www.renesas.com/en/document/dst/82c59a-datasheet).
* MAME source at the pinned commit linked above. It is corroboration only;
  classic INTR logic is in a source file also implementing 8085.
* Ian Bartholomew / Frank Cringle, 8080/8085 CPU Exerciser source distribution
  and manual, AltairClone: [file listing](https://altairclone.com/downloads/cpu_tests/),
  [exerciser PDF](https://altairclone.com/downloads/cpu_tests/8080_8085%20CPU%20Exerciser.pdf).

No exerciser binaries were downloaded or run for this research. CPUTEST remains
the notable source-coverage gap.
