# Pass29 — faithful bounded native +7EC0 and +80B7

Baseline: `6a803634bc4c580db7b602ef642ec7b92a4d6e22`.

`Pli80_host.Attribute_gate.gate` implements +7EC0. It publishes C at AE57,
reads the AE57/AE58 pair, discards the neighboring high byte, and selects the
packed byte **directly at 1B4B+C**, without position_map. Its explicit RLC then
RAR restores the original byte in A and leaves original bit7 in CY. NZPA/AC
remain inherited. The skip path returns BC=1B4B, HL=table address and preserves
DE. The set-bit path invokes the existing bounded native Range_processing
(+7D53), including its exact child state and effects.

`Attribute_gate.saved` implements +80B7: publish C at AE6B, read AE6B/AE6C,
invoke native Input_processing(+8048), **freshly reread AE6B/AE6C**, then invoke
native +7EC0 using the reloaded low byte. Neither +8048's returned A nor C is
used as the second child's input. The high byte is genuinely read both times;
B is retained independently. A dependency test mutates the saved pair between
child test doubles and proves the fresh read; this makes no new natural
compiler-state claim.

Each root is one ordered private transaction. The adapter composes existing
child programs through the existing Runner preview API and actual CP/M services.
Unsupported child branches, service outcomes, aliases or malformed proofs discard
the root without changing live RAM/registers/DMA/files or delivering callbacks.
All existing +8048/+7D53/+7E5F/Recursive_mapped/Int_emitter restrictions remain.
The native algorithms never consult source, step, snapshot identity or hashes.
No termination guards, alternative semantics or fallback were added.

## Independent natural evidence

Every duplicate invocation is a separate oracle. Fresh historical executions
retain entry/post RAM and filesystem in process; tests independently reconstruct
corrected CALL/return windows from the existing three ignored witness captures.
No capture or full-memory snapshot is committed.

| Source | +7EC0 calls | Bit7 clear | Bit7 set / +7D53 | +80B7 roots |
|---|---:|---:|---:|---:|
| MINIMAL | 18 | 11 | 7 | 10 |
| FIZZBUZ | 89 | 64 | 25 | 25 |
| PICTURE | 21 | 13 | 8 | 11 |

All **174** independent shadows match all registers/flags, actual SP/continuation,
**65,536 RAM bytes**, ordered logical writes and final stack-writer ancestry.
Service-bearing cases also match DMA, physical/logical filesystem contents,
record bytes and file-event chronology. These standalone totals overlap nested
parent coverage and must not be treated as disjoint execution counts.

+7EC0 callers: MINIMAL 80C6:10,2526:8; FIZZBUZ 80C6:25,2526:64;
PICTURE 80C6:11,2526:9,2599:1. +80B7 caller distributions are retained in
[hierarchy-summary.json](hierarchy-summary.json); all actual caller CALL words
and canonical origins are validated, rather than trusting catalog counts.

Beneath +80B7 the observed counts are:

| Source | +8048 | +7EC0 | +7D53 | +7E5F | +7D53 equal/gate/work | Emitter calls | BDOS26/21 |
|---|---:|---:|---:|---:|---|---:|---|
| MINIMAL | 10 | 10 | 10 | 4 | 6/1/3 | 12 | 0/0 |
| FIZZBUZ | 25 | 25 | 25 | 13 | 12/4/9 | 90 | 1/1 |
| PICTURE | 11 | 11 | 11 | 5 | 6/1/4 | 21 | 0/0 |

These children remain internal native logical operations. Each +80B7 root is
one Runner transition, including the FIZZBUZ nested successful record flush.

## ABI and stack proof

The original outer CALL slot is validated and consumed unchanged; final SP=S+2
and PC is actual caller+3. Gate skip has no body stack writes. Gate call derives
the A0D6 continuation from exact `CD 53 9F` at +7ED3, high byte first at S-1
then low at S-2. +80B7 derives A2C2 from +80BF `CD 48 A2`, followed by A2C9
from +80C6 `CD C0 A0`; the latter is the surviving S-2/S-1 word. Deeper bytes
come from the unchanged proven +8048/+7D53 child journals, including recursive
frames, temporary mapped-word destination saves, PUSH PSW and resident flush
wrappers/BDOS bridge.

[stack-compatibility.json](stack-compatibility.json) retains per-byte relative
addresses, derived values, writer coordinates, depths and planner overwrite
ancestry. Inherited scan bridges retain final transient helper residue, not a
synthetic instruction trace. Tests separately verify ordered logical mutations,
new direct CALL/return chronology, every final CPU writer, and full RAM. No
post-oracle stack byte is copied into an implementation.

## Standalone and cumulative hybrids

+7EC0-only transitions: **18/89/21**. +80B7-only transitions: **10/25/11**.
All enabled historical bodies are absent under canonical image-aware dispatch.
There are no fabricated Steps, guest BDOS entries or t-states.

The cumulative residual vector order is:

`80B7,7EC0,8048,7E5F,7D53,7C1B,7BBF,7B7A,7BA2,7AD5,7B64,7ABF,0EF6,7A79,7E46,7E56,7AF0,7B49,7A93,7B13`.

All entries after 80B7 are external Runner transitions; suppressed descendants
are counted separately as logical children.

* MINIMAL: `10,8,12,4,4,0,0,7,0,2,0,1,78,1,0,0,10,10,1,10`.
* FIZZBUZ: `25,64,83,29,22,0,0,58,5,33,7,28,101,28,0,0,102,119,28,119`.
* PICTURE: `11,10,15,6,5,0,0,8,0,6,3,3,62,3,0,0,19,23,3,23`.

Total cumulative BDOS26/21 services remain **1/1,3/3,1/1**. INT/REL record bytes
and ordering, file-event sequence and final filesystem are identical. All runs
print PASS1/PASS2 success and END COMPILATION, then warm boot.

| Source | REL bytes | SHA256 |
|---|---:|---|
| MINIMAL | 256 | `7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119` |
| FIZZBUZ | 768 | `68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203` |
| PICTURE | 256 | `c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1` |

## Scope, regressions and next boundary

The new unit suite enumerates all 256 positions ×256 packed bytes ×32 incoming
flag combinations, proves fresh saved-byte dependencies, and exercises actual
historical CALL ancestry, both gate routes, successful nested flush and rejection
of malformed image/code/entry/continuation, saved-byte/table/stack aliases,
unsupported children, missing files/status failures, guard failures and reordered
or duplicated service plans. Rejections preserve live state and callback counts.
Source and invocation-count proof mismatches are also rejected. Existing
regressions remain enabled; see [validation.json](validation.json).

A small existing adapter refactor exposes validated internal +8048 CALLs and
optional ancestor-window exclusions for cumulative controllers. Default Pass28
behavior stays unchanged. An independently detected inherited proof-label error was corrected: direct
Balance_scan balance initialization is written by +7B81 (MVI M,01), not
+7B80 (the preceding LXI operand). This changes journal writer metadata only,
not the algorithm, memory, ABI or any archaeological contract. Runner, CPU,
CP/M, packets, annotated assembly,
archaeological contracts and statuses are unchanged. No divergence or fidelity
debt remains. All **94,720 historical bytes** reconstruct exactly.

The corrected boundary screen identifies +2511 as the largest compared parent:
**81 calls /52,445 historical inclusive instructions** across these inputs,
versus RAW candidate +80CA **11/5,709** and +80EF **12/1,152**. These are observed
historical windows, not promised incremental savings: many descendants are now
native. +2511's +8048/+7EC0 children are native, but its **partial +240A dependency
and delegated +23A0/+23D2 state remain explicit blockers**. Recommend Pass30 as a
focused accumulated-natural-state contract audit of +240A and those dependencies
before native +2511. This prioritizes the substantial parent without hiding
unresolved selector branches. Nearby RAW parents still need local contracts;
the all-native-child +80EF candidate is smaller and lower leverage.

No +2511/+240A/RAW80B1 decompilation, FACTOR investigation, new source fixture,
or second parent migration was performed here.
