# PL/I-80 Reverse Engineering Lab

## Purpose

This repository is a laboratory for reverse-engineering Digital Research PL/I-80 v1.4 for CP/M-80 and ultimately producing a modern, testable specification and reimplementation.

The immediate objective is not to reimplement PL/I-80.

The first objective is to build a small, correct, deterministic and deeply instrumentable Intel 8080 / CP/M userspace execution environment that can later support:

* structured execution tracing;
* dynamic analysis;
* provenance tracking;
* single-path concolic execution;
* symbolic tracing;
* dynamic slicing;
* differential testing against historical PL/I-80;
* static reverse-engineering data.

The concrete emulator must remain useful independently of all PL/I-specific work.

---

## Architectural principles

### Concrete execution first

The Intel 8080 emulator is a concrete execution engine.

`Cpu8080` must not know about:

* PL/I;
* CP/M semantics;
* symbolic expressions;
* provenance;
* taint;
* reverse-engineering hypotheses.

The symbolic system will be layered beside concrete execution, not embedded into it.

### Stable instrumentation boundary

Every executed instruction must eventually be observable through a structured execution-step interface.

Conceptually:

```
Cpu8080
    |
   Step
  / | \
```

Trace Shadow Debug/Analysis

`Step` is an online instrumentation boundary.

Persistent trace events are a separate representation and must not be assumed to contain all information necessary to reconstruct symbolic semantics.

Avoid designing the symbolic engine as a post-processing pass over an insufficient trace format.

### Separation of responsibilities

Initial conceptual components:

* `State`: 8080 registers, flags, PC and SP.
* `Flags`: centralized flag representation and helpers.
* `Instr`: structured representation of decoded 8080 instructions.
* `Decode`: byte stream to `Instr`.
* `Memory`: concrete 64 KiB address space.
* `Bus`: memory and I/O interface seen by the CPU.
* `Cpu8080`: concrete instruction semantics.
* `Step`: structured description of one executed instruction.
* `Loader`: loading of CP/M `.COM` programs.
* `Bdos`: minimal host-side CP/M BDOS implementation.
* `Filesystem`: deterministic CP/M-visible files backed by host files.
* `Trace`: structured execution events and serialization.
* `Runner`: one deterministic execution experiment.
* `Expr`: future symbolic-expression DAG.
* `Shadow`: future parallel symbolic state.
* `Provenance`: future input dependency tracking.
* `Analysis`: future coverage, CFG, call graph and slicing.
* `Pli80`: knowledge specific to the historical compiler.

Important dependency rule:

```
Cpu8080 knows neither CP/M nor PL/I.
Bdos knows neither PL/I nor symbolic expressions.
Expr knows neither CP/M nor PL/I.
PL/I-specific historical knowledge belongs under Pli80.
```

---

## Intel 8080 fidelity

Correctness is more important than performance.

In particular, prioritize:

1. instruction semantics;
2. flags;
3. PC/SP behaviour;
4. memory accesses;
5. undocumented or unspecified opcode behaviour where it can be established;
6. deterministic external behaviour.

Exact cycle timing is initially secondary unless required by a test.

Do not silently treat undocumented opcodes as impossible.

Maintain an explicit model of all 256 opcode byte values.

For every opcode, the project should eventually classify its behaviour as one of:

* documented Intel 8080 instruction;
* undocumented alias or behaviour established with sufficient evidence;
* processor-dependent / insufficiently established;
* intentionally unsupported, with an explicit reason.

Where undocumented behaviour differs between Intel 8080, 8085, Z80 or emulator implementations, do not guess.

Record the distinction and preserve evidence.

The primary historical target is Intel 8080-compatible behaviour relevant to PL/I-80 under CP/M-80.

---

## Testing strategy

Do not rely on a single oracle.

Use several independent forms of validation.

### Unit tests

Test individual instruction families and edge cases.

Special attention should be paid to:

* carry;
* auxiliary carry;
* parity;
* sign;
* zero;
* ADC/SBB;
* CMP;
* INR/DCR;
* DAD;
* DAA;
* conditional calls/returns/jumps;
* PUSH/POP PSW;
* RST;
* XTHL;
* PCHL;
* interrupt-related instructions;
* undocumented opcodes.

Expected values in tests should not reuse the same helper implementation as production code when that would make a test tautological.

### Exhaustive tests

Where the state space is small, prefer exhaustive enumeration over representative examples.

Examples:

* all 256 × 256 operand pairs for binary 8-bit ALU operations;
* both carry states where relevant;
* all 256 inputs for unary operations;
* relevant flag-state combinations.

The 8080 is small enough that exhaustive validation is often practical.

### Historical exercisers

Support established 8080 CPU exercisers where legally and technically possible.

Keep long-running exercisers separate from fast unit tests if necessary.

### Differential testing

Compare selected CPU states and instruction executions against one or more independent 8080 implementations.

Avoid treating one third-party emulator as unquestionable truth.

When implementations disagree, preserve the disagreement as evidence and investigate.

### Fuzzing

Use fuzzing primarily as differential and invariant testing.

Useful fuzz targets include:

* decoder robustness;
* single-instruction state transitions;
* short generated instruction sequences;
* stack operations;
* control flow;
* memory access boundaries;
* comparison with an independent emulator.

Fuzzing complements exhaustive and historical tests; it does not replace them.

---

## Undocumented behaviour

Undocumented CPU behaviour is in scope.

However:

* do not invent semantics merely to fill the opcode table;
* distinguish evidence from assumptions;
* prefer hardware documentation, historical test programs or independent experimental agreement;
* record CPU-family differences explicitly;
* make uncertainty representable in tests and documentation.

The goal is historically useful fidelity, not artificial completeness.

---

## CP/M model

The initial environment is a userspace CP/M execution model, not a complete machine emulator.

Initial assumptions:

* 64 KiB address space;
* `.COM` program loaded at `0x0100`;
* deterministic initial machine state;
* interception/handling of BDOS entry at `0x0005`;
* host-side implementation of required BDOS calls;
* deterministic console;
* host-backed CP/M files.

MAME/QX-10 remains the realistic machine-level reference for cases requiring BIOS or hardware behaviour.

Our runner is a microscope, not a replacement for MAME.

---

## Determinism

Given the same:

* executable;
* input files;
* command-line configuration;
* initial machine state;

a run should produce the same:

* CPU-visible behaviour;
* outputs;
* files;
* diagnostics;
* trace.

Avoid hidden dependencies on:

* wall-clock time;
* host locale;
* random values;
* unordered filesystem enumeration;
* unspecified host behaviour.

---

## OCaml implementation style

Use OCaml pragmatically.

The CPU execution core should be imperative where appropriate:

* mutable registers;
* mutable PC/SP;
* `Bytes` or `Bigarray` for RAM;
* arrays for future shadow state;
* straightforward fetch/decode/execute loop.

Use algebraic data types and pattern matching where they provide semantic clarity:

* decoded instructions;
* operands;
* conditions;
* control-flow classification;
* trace events;
* future symbolic expressions.

Do not force functional purity into the CPU hot path.

Do not optimize prematurely.

---

## Repository discipline

Prefer small increments.

Each implementation task should:

1. state its exact objective;
2. inspect existing code before modifying it;
3. change the minimum necessary surface;
4. add or update tests;
5. run relevant tests;
6. report exactly what changed;
7. report remaining known limitations.

Do not perform opportunistic large refactors unrelated to the current task.

Avoid speculative abstractions unless an imminent requirement justifies them.

---

## Initial roadmap

The initial sequence is:

1. establish repository structure and Dune build;
2. implement minimal CPU state, memory, decoding and execution needed for a tiny CP/M program;
3. implement `.COM` loading;
4. implement minimal BDOS;
5. run a handcrafted `HELLO.COM`;
6. expose structured `Step` instrumentation;
7. complete documented Intel 8080 semantics;
8. classify and implement useful undocumented opcode behaviour;
9. add exhaustive ALU/flag tests;
10. run historical CPU exercisers;
11. add differential/fuzz testing;
12. implement sufficient CP/M file handling;
13. run a real PL/I-80 microtest;
14. add provenance tracking;
15. add symbolic expression DAG and shadow state;
16. add dynamic slicing and higher-level analyses.

Do not introduce SMT solving, path forking or exhaustive symbolic execution during the initial phases.

---

## Current milestone

The first meaningful executable milestone is:

```
pli80-run HELLO.COM
```

where:

* the `.COM` file is loaded at `0x0100`;
* the required 8080 instructions execute correctly;
* BDOS functions required by the program work;
* the program prints the expected output;
* termination is explicit and deterministic;
* each executed instruction can be exposed through the instrumentation boundary.

The repository should reach this milestone before attempting broad symbolic machinery.
