# AT8TRACE v1

AT8TRACE v1 is a deterministic, line-oriented record of selected execution
events. Its first line is exactly `AT8TRACE<TAB>1` followed by LF. The file is
UTF-8-compatible ASCII; fields are separated by one TAB and each record ends
in LF. Hexadecimal digits are uppercase. There are no timestamps, host paths,
or environment-derived fields.

## Records

An instruction is written as:

```text
STEP<TAB>step-index<TAB>pc-before<TAB>pc-after<TAB>opcode<TAB>bytes<TAB>status<TAB>control-flow
```

`step-index` is an unsigned decimal integer starting at 0. PCs and addresses
are exactly four hexadecimal digits (`0000`–`FFFF`); opcode and byte values
are exactly two digits (`00`–`FF`). `bytes` is the concatenation of the exact
instruction bytes fetched, with two digits per byte, and is never empty.
`status` is `documented`, `undocumented_alias`, or `uncertain`. An uncertain
reason, if held by the decoder, is deliberately not persisted in v1.

`control-flow` is one of `sequential`, `halt`, `jump:<taken>:<target>`,
`call:<taken>:<target>`, `return:<taken>:<target-or-none>`, or
`restart:<target>`. `<taken>` is `0` or `1`; targets use four uppercase hex
digits. `none` is used for a return whose target is not available.

Each data-memory access immediately follows its STEP, preserving access order:

```text
MEMR<TAB>step-index<TAB>address<TAB>value
MEMW<TAB>step-index<TAB>address<TAB>value
```

`address` has four hex digits and `value` has two. These records are data
accesses only; instruction fetches are represented by the STEP `bytes` field.

At BDOS entry, the runner emits:

```text
BDOS<TAB>step-index<TAB>function-number<TAB>DE
```

The step index is the number of CPU instructions already completed. The
function number is unsigned decimal and DE is four uppercase hex digits.

Normal BDOS termination is:

```text
TERM<TAB>step-index<TAB>bdos:function-number
```

The termination index is also the count of CPU instructions completed.

## Ordering and determinism

The header appears exactly once. Events follow execution order. A CPU event is
followed immediately by its zero or more memory-access subrecords; then later
events (including BDOS entry and termination) follow. CPU step indices are
contiguous from zero. BDOS and termination indices equal the number of steps
already emitted. For the same program, initial state, inputs and deterministic
runner configuration, the serialized bytes are identical.

The format is intentionally not a complete machine snapshot and makes no
claim to contain all information needed for future symbolic analyses. Any
incompatible grammar change requires an explicit format-version change.
