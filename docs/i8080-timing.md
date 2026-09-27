# Intel 8080 T-state model v0

`I8080.Timing.cost` assigns the guest CPU instruction T-state cost to an
executed `Step`. Timing is derived after execution from its decoded
instruction and, for conditional CALL/RETURN, the observed control-flow
outcome. It does not feed back into or change concrete CPU semantics.

The table covers every byte value in the decoder's 256-opcode domain,
including the decoder's reported undocumented aliases. Aliases use the timing
of the instruction behavior to which the decoder maps them.

Conditional JMP uses 10 T-states whether taken or not taken. Conditional CALL
uses 17 taken / 11 not taken. Conditional RETURN uses 11 taken / 5 not taken.
Other implemented instruction timings use the conventional Intel 8080
instruction timing table (for example, register MOV 5, memory MOV 7, CALL 17,
RET 10, and XTHL 18 T-states).

Reference: Intel, *8080 Microcomputer Systems User's Manual* (September 1975),
[archival copy](https://www.nj7p.info/Manuals/PDFs/Intel/9800153B.pdf),
instruction-set/timing tables. The model uses the 8080 timings, not the later
8085 or Z80 timings.

`Runner.run_result.t_states` is the sum over executed CPU Steps only. BDOS
dispatch, BIOS services, wait states, disk/peripheral latency, interrupts
between instructions, and historical elapsed/wall-clock time are not modeled.
This is instruction timing, not elapsed machine time.
