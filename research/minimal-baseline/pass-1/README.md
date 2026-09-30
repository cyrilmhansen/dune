# MINIMAL decompilation pass 1

Base commit: `6c77397`. The five anchor groups were investigated in the requested
order using the existing MINIMAL capture. No FIZZBUZ body was investigated and
no new full capture, CPU semantics, ownership model, or visualization was added.

## OBSERVED: progress

MINIMAL still executes 10,378 canonical coordinates and **21,012 image bytes**.
All **94,720 historical bytes** reproduce exactly.

| Executed status | Before | After | Change |
|---|---:|---:|---:|
| RAW | 20,422 | 19,574 | −848 |
| DECODED | 304 | 304 | 0 |
| STRUCTURED | 138 | 659 | +521 |
| UNDERSTOOD | 148 | 475 | +327 |
| Total | 21,012 | 21,012 | 0 |

Behaviorally understood bytes now cover **2.26%** of MINIMAL execution coverage;
STRUCTURED plus UNDERSTOOD cover **5.40%**. These are byte metrics, not claims
that every branch of every annotated procedure has been recovered.

| Image | Executed RAW | DECODED | STRUCTURED | UNDERSTOOD |
|---|---:|---:|---:|---:|
| PLI.COM | 2,727 | 142 | 65 | 387 |
| PLI0.OVL | 4,315 | 0 | 0 | 42 |
| PLI1.OVL | 6,870 | 0 | 258 | 20 |
| PLI2.OVL | 5,662 | 162 | 336 | 26 |

The 391 CALL/RST targets remain unchanged. Their classifications change from
15 UNDERSTOOD / 5 STRUCTURED / 371 unresolved to **21 / 8 / 362**. Eleven
additional PCHL handler coordinates are recorded separately and remain unresolved,
making 402 inventoried callable coordinates; they are not newly executed code.

Whole-image UNDERSTOOD increases 158→485, STRUCTURED 169→690, RAW
94,089→93,241; DECODED stays 304. Before/after metrics and unchanged hashes are
in [progress.json](progress.json) and [before.json](before.json). Current baseline
status intersections and callable classifications are updated in the parent.

## DEDUCED: bounded ProcedureHypotheses

Envelopes below have exclusive ends. Bounds come from entries, local branches,
nested transfers and terminal returns, not context min/max. Only MINIMAL-fetched
instructions were promoted; unobserved holes remain RAW.

| Entry | Envelope | Invocations checked | New status | Promoted bytes |
|---|---|---:|---|---:|
| PLI2+1FB5 | `[1FB5,20EB)` | 11 | STRUCTURED | 263 |
| PLI.COM+070C | `[070C,0788)` | 199 | UNDERSTOOD | 124 |
| PLI.COM+12AE | `[12AE,12D9)` | 158 | UNDERSTOOD | 43 |
| PLI1+4693 | `[4693,46A7)` | 1 | UNDERSTOOD | 20 |
| PLI1+4468 | `[4468,452B)` | 2 | STRUCTURED | 173 |
| PLI1+4738 | `[4738,478D)` | 1 | STRUCTURED | 85 |
| PLI0+23C3 | `[23C3,23DF)` | 334 | UNDERSTOOD | 28 |
| PLI.COM+09CB | `[09CB,0AA5)` | 199 | UNDERSTOOD, scoped | 90 |
| PLI.COM+0AA9 | `[0AA9,0AE9)` | 199 | UNDERSTOOD, scoped | 22 |

[regions.json](regions.json) retains exact image identities, callers/counts,
returns, inputs/effects, pseudocode, direct nested calls, branch outcomes,
cross-run presence, representative registers/memory and limits. Explicit
predicates check all **1,104 selected invocations** and eleven PCHL/return pairs.
Representatives include refill, retry/EOF, both constructor callers, separate
bound/tag results, and quote opening/closing. Other runs only corroborate entry
presence/counts; MINIMAL supplies the contracts.

### 1. PLI2 gateway +1FB5

OBSERVED: eleven CALLs from `+2149` (eight), `+6862`, `+6FA0`, and `+6FFA`.
All hardware frames return at `+20EA`. Three are nested re-entries from handlers.
The local core calls `+047D` eleven times and `+1DFF` thirteen times; calls
inside handlers are not assigned to its body.

DEDUCED: with entry SP=S, it reserves twelve bytes. Input C is at S−12;
AD0B..AD14 are copied to S−11..S−2, AD0A to S−1. The result k of `+047D`
selects words from 3C21+2*k and 3DDD+2*k, saved at AD1D and AD1F. The scan
decrements AD1A, increments AD0A, advances AD1D, and invokes `+1DFF`. Its
observed failure path skips by the next record byte. The fallback uses low
three bits of byte[1B4B+k] to select a word from 3C13, increments it and calls
`+1DFF` again.

PUSH H writes 42B4H at S−14; PCHL enters the handler currently in AD1F. Its
software RET consumes that PUSH and resumes gateway `+20B4`. All eleven calls
restore the eleven saved global bytes; final A=old AD0A, BC=S−1, DE=AD15H,
HL=S, and hardware RET leaves SP=S+2. AD1A..AD20 and handler effects are not
restored. This is not a conventional callee-save register interface.

HYPOTHESIS: reentrant table/record dispatcher. It remains STRUCTURED because
record success and tracing-mode semantics are unresolved. Bit0[202E] is always
zero in MINIMAL; `+203E..+2045`, `+2092..+20AB`, `+20BB..+20C7` remain RAW.

The anchor expands into the gateway and eleven distinct PCHL entries:

| Entry | Software RET |
|---|---|
| PLI2+20F7 | +2128 |
| PLI2+2659 | +2839 |
| PLI2+2926 | +294C |
| PLI2+294D | +295E |
| PLI2+3E36 | +3EF5 |
| PLI2+684A | +6853 |
| PLI2+685E | +6874 |
| PLI2+6EA5 | +6F18 |
| PLI2+6F9C | +6FB6 |
| PLI2+6FF6 | +7011 |
| PLI2+7019 | +7027 |

Each occurs once from `+20B3`, consuming a distinct guest-written continuation
back to `+20B4`. [continuation-entries.json](continuation-entries.json) retains
entry/return registers, exact bytes and writer/slot relations. Stable RAW labels
preserve these identities; no handler body range is invented. AD0A was examined
only as directly saved state; no runtime-symbol investigation was resumed.

### 2. Resident readers +070C / +12AE

OBSERVED: +070C has 199 CALLs from +0ADA, with RETs +0715 (two), +072F (194),
+0787 (three). +12AE has 158 CALLs from +12D9 (28) and +141A (130), with RETs
+12C4 (four) and +12D8 (154). Four local retries explain 162 executions of
+12AE, not extra CALLs. All use original hardware slots.

DEDUCED: +070C tests bit0[2012]. Set means return 1AH without advancing
word[1D08]. Otherwise it increments that word; below 512 it returns the byte at
word[1D06]+index. Exhaustion calls +05B2, resets the index and reads FCB 005CH
through +0318 in 128-byte increments, using DMA setter +02EE. Nonzero status
inserts 1AH at the next record start and stops refill. It resets index to zero
and returns the buffer's first byte. Each of three observed refills has one
successful read followed by one nonzero status; four successful reads are not
dynamically established.

On the immediate indexed path BC is preserved, DE=index, HL=buffer+index,
A=fetched byte; carry comes from DAD. Other flags describe the preceding
high-byte comparison. Refill effects are delegated to helpers. The EOF gate's
carry is the tested bit, not a general carry/EOF convention across all paths.

+12AE compares byte[1F06] to byte[1F08]. If smaller, it increments the byte
index and returns byte[1E8E+old_index], BC=old_index, HL=1E8E+old_index. Otherwise
it calls +0D40, returns 1AH if bit0[2012] is set, or retries. These are separate
UNDERSTOOD readers with opaque refill effects stated explicitly.

### 3. PLI1 wrappers +4693 / +4738 and callee +4468

OBSERVED: one CALL per wrapper, hardware RETs +46A6 / +478C. Both call +4468,
whose two RETs at +452A are software continuations. Those are the two original
hardware frames left unretired in V0's inventory.

DEDUCED: callee C=count, E=tag, and word[entry_SP+2]=source pointer. POP D
consumes the CALL word, POP B the argument, then PUSH D re-pushes the return PC
at entry_SP+2. RET leaves SP=entry_SP+4: a two-byte callee-cleanup convention.

The callee saves source at A8FD/A8FE, count at A8FF, tag at A900, and calls
+4394. It writes tag at record+2, zeroes +3..+9, and copies payload bytes in
descending index order to record+10+i. Both invocations have count seven,
sources 20C6H/A948H, tags 05H/28H. Later +422F/+4281/+83A0/+428E operations
traverse/update +8 links. Allocation/list semantics and +44E7..+44FC remain
unresolved, so the callee is STRUCTURED.

+4693 is an UNDERSTOOD adapter: save C at A910, PUSH fixed source 20C6H,
pass count byte[20C5] and tag E=saved C, call constructor, RET. Outputs are
delegated. +4738 saves C at A916 and calls +46ED/+4281; only the zero-bit path
occurs. It constructs from A948, saves word[word[A8AB]+2] at A917, adds byte[A947]
to that original word through resident +1A1D, and copies the saved word to a new
record's +6 field. Helper and early-return semantics are unresolved: STRUCTURED.

**Refinement of V0's shared-tail hypothesis:** reconstructed parent contexts
contained +4470..+452A after the child popped its hardware return. Explicit
CALL/software-return windows identify that code as separate callee +4468's
common body, not body shared by the wrappers. Contexts remain exploratory;
no historical-byte contradiction was found.

### 4. PLI0 +23C3

OBSERVED: 334 calls from five sites, all RET +23DE, each calling resident +1A33.
332 results are false, one true from the pointer bound, one true from the tag.

DEDUCED: p=word[6A82], limit=word[1C32], t=byte[p+1]. A=FF iff p>=limit OR
(t&E0)==20, else 00. BC=FFFF iff the bound alone is true, else 0000; HL=p+1;
DE=6A83. Final ORA clears carry and sets S/Z/P from A. The tag byte is always
read, including bound-true cases. Only stack writes occur. UNDERSTOOD, while
any higher-level tag interpretation remains HYPOTHESIS.

### 5. Resident +09CB and separate cache adapter +0AA9

OBSERVED: 199 calls each. +09CB returns at +0A01 (16), +0A3B (two), +0AA4 (181);
+0AA9 always at +0AE8. All match hardware slots; opening/closing mode changes
are separately retained.

DEDUCED scoped contract: with byte[200E]=0, bit0[200C]=0, and mode byte[200D]
in {0,2}, +0AA9 calls +070C, stores raw byte at 2098 and raw&7F at 2099, returns
masked A with ANI flags. +09CB returns raw[2098] in mode two, clearing mode on
masked 27H. In mode zero, masked 27H sets mode two and returns 27H; witnessed
ordinary bytes return raw[2098]. Registers follow the reader; flags vary by path.

These are UNDERSTOOD contracts for the promoted MINIMAL fragments, **not full
contracts for all modes**. Nonzero reuse, mode three, slash, percent, alternate
source paths stay RAW. “Quote-state byte filter” is HYPOTHESIS, not a complete
lexer/string/comment model.

## Next MINIMAL targets — not investigated here

- PLI2+047D: 67 calls/seven sites; shared classification/decoding gateway.
- PLI2+1DFF: thirteen calls/two sites; record scan/fallback and success path.
- PLI.COM+0D40: eleven calls/two sites; counted-reader refill/count/EOF effects.
- PLI1+4394: three calls/two sites; supplies constructor record pointer.
- PLI.COM+05B2: fourteen calls/two sites; 512-byte reader/buffer setup.

## Reproduce and verify

Reuse `_build/minimal-baseline/capture`; its index/chunk hashes are already in
the baseline. New analysis windows stay in ignored `_build/minimal-pass-1`.
Durable selected evidence is here; no new full capture is needed.

```sh
python3 tools/annotated-assembly/check_minimal_pass_1.py \
  --capture _build/minimal-baseline/capture --output _build/minimal-pass-1/rechecked.json
dune runtest --force
python3 tools/annotated-assembly/test_minimal_pass_1.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_baseline.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_verify.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
git diff --check
```

The annotated verifier now checks the constructor's exact PUSH D writer,
consumed bytes, relocated slot, return target, two-byte cleanup, latest-writer
facts and image coordinates. It does not label that return a hardware frame.
Section/full-image hashes, exact equality, partitions and mappings pass after
each annotation batch. Project tests and 27 annotated/baseline/pass tests pass.
