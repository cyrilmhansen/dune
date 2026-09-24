# Runes

**Executable software archaeology.**

Runes is a laboratory for understanding old software by combining:

* faithful concrete execution;
* detailed runtime observation;
* static reverse engineering;
* differential testing;
* symbolic and concolic execution;
* progressive reconstruction of higher-level semantics.

The initial target is **Digital Research PL/I-80 v1.4 for CP/M-80**, running on an Intel 8080-compatible environment.

The long-term goal is not merely to emulate the original compiler, but to recover enough of its internal semantics to build a modern, testable and independent representation of its compilation pipeline.

---

## Why execution?

Static disassembly is useful, but old binary software often becomes much easier to understand when its behavior can be observed precisely.

Runes therefore treats execution as an investigative tool:

```text
binary
  │
  ▼
concrete execution
  │
  ├── instruction trace
  ├── memory accesses
  ├── control flow
  ├── filesystem effects
  └── eventually symbolic provenance
           │
           ▼
     recovered semantics
```

The concrete emulator is intended to remain small, deterministic and inspectable.

More sophisticated analyses are layered on top rather than embedded into the CPU itself.

---

## Current target

The first case study is the Digital Research PL/I-80 compiler for CP/M.

The project aims to understand and eventually reconstruct parts of the original compilation chain, including intermediate representations, compiler passes and generated code behavior.

The working method combines three complementary approaches:

1. **Static analysis and decompilation**
2. **Concrete execution with deep instrumentation**
3. **Behavioral and differential experiments**

Later stages will add single-path concolic execution and symbolic provenance.

---

## Architecture

The current architecture deliberately separates machine semantics from higher-level analysis.

```text
                   Runner
                     │
          ┌──────────┼──────────┐
          │          │          │
        CP/M       Trace     Analysis
          │
          │
       Cpu8080
          │
         Bus
          │
       Memory
```

The important boundary is:

```text
Cpu8080
   │
   ▼
 Step
   │
   ├── Trace
   ├── Debugging
   ├── Shadow execution
   └── Provenance
```

`Step` is the live observation interface for one successfully executed instruction.

Persistent traces are represented separately so that the internal CPU instrumentation can evolve without implicitly changing the trace format.

---

## Intel 8080 core

The emulator is written in OCaml.

The design favors:

* correctness over cycle accuracy;
* explicit state transitions;
* deterministic behavior;
* exhaustive testing where practical;
* visibility of memory accesses and control flow;
* architectural separation from CP/M and symbolic execution.

The decoder covers all 256 opcode values, including known undocumented aliases.

The execution core currently implements the full arithmetic, logical, memory, stack and control-flow instruction set, with interrupt semantics handled separately.

Special attention is paid to historically subtle Intel 8080 behavior such as:

* auxiliary carry on subtraction;
* 8080 versus 8085 logical-instruction flag behavior;
* DAA;
* undocumented opcode aliases.

The ALU is implemented as a pure component so that its semantics can be exhaustively tested independently from the CPU state machine.

---

## CP/M userspace environment

Runes does not aim to reproduce an entire historical computer.

Instead, it provides a small CP/M userspace environment sufficient to execute real transient programs.

The current runner provides:

* `.COM` loading at `0x0100`;
* deterministic initial CPU state;
* the standard BDOS entry at `0x0005`;
* minimal BDOS services;
* bounded execution;
* observable execution events.

The first integration program is a tiny CP/M program that prints:

```text
HELLO
```

through BDOS function 9 and terminates through BDOS function 0.

The intended direction is to grow this into a practical userspace CP/M environment with:

* command tails;
* FCBs;
* DMA;
* drives;
* user numbers;
* a host-backed filesystem;
* an in-memory RAM disk.

The goal is eventually to execute the real PL/I-80 toolchain without emulating a complete machine, disk controller or BIOS.

MAME remains the reference tool when full historical hardware behavior is required.

---

## Deterministic traces

Runes defines a simple persistent trace format:

```text
AT8TRACE    1
```

A trace records execution events such as:

* instructions;
* original opcode bytes;
* control-flow decisions;
* ordered memory reads and writes;
* BDOS calls;
* termination.

The format is deliberately deterministic:

> the same execution should produce byte-for-byte identical output.

This makes traces useful for:

* regression testing;
* dynamic CFG construction;
* call-graph recovery;
* differential execution;
* debugging;
* documentation of observed behavior.

Persistent traces are not intended to replace live symbolic instrumentation.

---

## Testing philosophy

The project tries to avoid self-confirming tests.

Depending on the component, validation may include:

* unit tests;
* exhaustive enumeration;
* independent reference formulas;
* historical CPU exercisers;
* differential execution against mature emulators;
* fuzzing;
* comparison with original software behavior.

For example, the 8-bit ALU is tested exhaustively across close to one million cases, including all DAA input states.

Whenever possible, the test oracle is structurally different from the production implementation.

---

## Future analysis layers

The concrete machine is only the foundation.

The intended analysis stack is roughly:

```text
Concrete execution
       │
       ▼
Runtime observation
       │
       ▼
Shadow state
       │
       ▼
Symbolic expressions
       │
       ▼
Provenance
       │
       ▼
Compiler-level semantics
```

A future memory cell may conceptually carry both:

```text
concrete byte
symbolic origin
```

This should allow data to be followed through memory, files and successive compiler passes.

The initial concolic model is deliberately single-path: concrete execution determines control flow while symbolic state explains where values came from and how they were transformed.

---

## PL/I-80 research goals

The PL/I-80 work is intended to progress incrementally.

Near-term goals include:

* running more of the real compiler under the CP/M runner;
* expanding the BDOS/filesystem environment;
* executing historical 8080 exercisers;
* comparing behavior against existing emulators;
* tracing PL/I-80 compiler passes;
* identifying intermediate files and structures;
* reconstructing internal representations.

Longer term:

* symbolic provenance;
* compiler-pass reconstruction;
* decompilation informed by dynamic evidence;
* a clean modern IR;
* an independent implementation of recovered PL/I-80 semantics.

---

## Building

Runes currently uses:

* OCaml
* Dune

Typical development commands:

```sh
dune build
dune runtest
```

Run a CP/M `.COM` program:

```sh
dune exec pli80-run -- PROGRAM.COM
```

Produce an execution trace:

```sh
dune exec pli80-run -- --trace run.at8trace PROGRAM.COM
```

---

## Project principles

A few rules guide the implementation:

**Concrete first.**
Get deterministic execution correct before adding symbolic complexity.

**Keep layers separate.**
The Intel 8080 core should not know about PL/I, CP/M, tracing or symbolic execution.

**Instrumentation is a first-class interface.**
Observation should not require invasive changes to execution semantics.

**Do not optimize before establishing an oracle.**
The readable implementation is the reference model. Faster generated or specialized backends can come later.

**Prefer evidence over intuition.**
Historical CPUs contain enough edge cases that apparently obvious behavior should still be verified.

**Make uncertainty explicit.**
Undocumented or historically ambiguous behavior should be identified as such rather than silently normalized.

---

## Why “Runes”?

The name has several intended associations.

A **run** is the fundamental experimental unit of the project: execute old software and observe what it actually does.

**Runes** are inscriptions whose meaning has to be recovered from surviving evidence.

The name is also a small nod to **TUNES**, an ambitious research project from the early history of the web that explored alternative approaches to programming languages and operating systems.

Runes is much narrower in scope, but shares some of the same attraction to understanding computing systems from first principles.

---

## Status

Runes is an experimental research project.

Interfaces, trace formats beyond explicitly versioned formats, and internal representations may evolve substantially while the PL/I-80 case study develops.

The repository should therefore be treated as a laboratory rather than as a stable emulator distribution.
