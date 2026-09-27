# CP/M system-personality boundary

`Cpm.Personality` is the boundary between the generic runner and the current
CP/M transient-process environment. It owns COM loading, page-zero setup,
the synthetic BDOS entry and warm-boot addresses, the deterministic initial
stack convention, command-tail limit, process BDOS state, and dispatch.
`Runner` still observes CPU steps and timings, but no longer constructs these
CP/M details itself. The 8080, Step, trace, timing, provenance, and analysis
layers remain independent of CP/M.

Runes currently exposes one runtime personality: `Cpm22`. Its behavior is the
existing deterministic CP/M 2.2 userspace model. The QX-10 / CP/M Plus results
in [the PL/I-80 surface notes](pli80-cpm-surface.md) remain a differential
observation environment, not an implemented selectable Plus personality.
In particular, function 12 returns `HL=0022h`, and function 108 receives the
existing CP/M 2.2 out-of-range zero-return behavior; this does not implement
CP/M Plus Program Return Code semantics.

This boundary is an extraction of the current process contract, not a plugin
registry or an abstraction for unimplemented operating systems.
