# FIZZBUZ differential pass 14 — PLI1+7D53

Task `FIZZBUZ_DIFFERENTIAL_PASS_14_7D53`, baseline
`f9be7d2fd104e38143d239d12f729f9917afea3a`. This pass is bounded to the
accumulated `[7D53,7E46)` hypothesis and its already-known direct helper effects.
No broad FIZZBUZ sweep, new fixture/capture, helper decompilation, packet/CPU/trace
change or unrelated semantic promotion occurred.

The two questions have different answers: **no new local instruction coordinate
or individual branch outcome**, but **new operand states and recursive composition
correlations**. The six RAW +7E2B..+7E30 bytes remain unexecuted and RAW.

## Capture and structural evidence

Reused `_build/evidence-packet-cross-run/fizzbuz-capture`, identity
`FIZZBUZ:a7a657b3c9c758be44a16c4c76a2986744f01de34d773d2b9597d4758eff0f49`.
Compilation success and REL **768 bytes** were rechecked; SHA-256
`68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`.

[structural.json](structural.json) derives exact CALL entries and corrected
original-slot returns, excluding every nested child window. No basic-block,
RoutineCandidate or surrounding context supplies ownership. Both runs have the
same 99 own instruction coordinates and 237-byte observed union:

| Measure | MINIMAL | FIZZBUZ |
|---|---:|---:|
| Invocations | 21 | 77 |
| Own instruction occurrences | 1,144 | 6,018 |
| +7D5D equal-range returns | 12 | 40 |
| +7D65 gate-bit returns | 2 | 8 |
| +7E45 work returns | 7 | 29 |
| Reverse +7D9D selections | 9 | 35 |
| Forward iterations | 16 | 102 |

FIZZBUZ callers: +7ED3 **25**, +8069 **30**, +80EB **8**, new exact CALL-site
+811B **2**, +816B **12**. These counts are now in the catalog alongside the
unchanged MINIMAL counts. The new caller is a coordinate, not a discovered
procedure or an annotation promotion. Seed instructions/callers add separate
FIZZBUZ observations; represented_bytes stays the union 237, not 474.

Direct FIZZBUZ CALL-site counts: +7D91/+7D9D/+7DA7 each 35;
+7DC5/+7DCC/+7DDB/+7E35 each 102; +7DE6/+7DF1 each 42;
+7DFB/+7E20 each 60; +7E0D/+7E11 each 7. The RAW-arm CALLs have zero observations.

There are **five new ordered own transfer sequences**, with 7 FIZZBUZ members:
361768; 375015; 403330/472976/539774; 608084; 618086. The comparison has 7 MINIMAL
versus 12 FIZZBUZ patterns, defined by ordered own CALL/jump/RET coordinates,
outcomes and internal/callee targets; caller RET destinations and register values
are excluded. These are task-local path patterns, **not packet classes**.
Longer/differently composed loops can create a new sequence without a new
instruction or branch outcome.

[states.json](states.json) separately navigates exact operand states. Examples:
loaded end4/9 are new; mapped bytes0F/6A/6C/A8/B2 are new at +7D94; top-level
returned bytes1/15 are new at +7DA0. Forward mapped values include new1E, while
transformed attributes remain2/3/4. Every causal conclusion uses individual
[iterations.json](iterations.json) members, not Cartesian combinations of sets.

## V0.2 packet attempt and bounded fallback

The required command was attempted with explicit FIZZBUZ capture and frame0:

```sh
python3 tools/annotated-assembly/procedure_evidence_packet.py \
  --run FIZZBUZ --capture _build/evidence-packet-cross-run/fizzbuz-capture \
  --images /path/to/DISK1 --entry PLI1.OVL+7D53 \
  --frame-bytes 0 --class-slots --output _build/fizzbuz-pass-14/packet
```

**Full extraction fails closed:** `Packet boundary has unresolved historical
origin`. Parent CALL **472976** at +7ED3 contains mapped-byte emission CALL
**478274** at +7DCC to resident +0EF6. Its subtree contains RET accesses at
**478324/478364**, runtime **0005**, with no historical image origin. Those are
observed effects, not coordinates that may be assigned to PLI.COM by byte equality.
The generator has already validated selected-run capture/canonical chronology;
the failure concerns its historical-only subtree presentation profile.

No full FIZZBUZ +7D53 packet was emitted: JSON/Markdown sizes, packet class count
and packet block count are **N/A**. No event was removed or relabeled to make
extraction succeed. No schema/profile/version or whole-capture cache was added.

Analysis continued using the already-isolated corrected return projections and
**the existing Pass7 `validate_d53()` channel/endpoint checks**, through a small
in-memory compatibility adapter in `check_fizzbuz_pass_14.py`. It retains both
nonhistorical accesses with null coordinates and numeric runtime PCs. It is
explicitly **not a V0.2 packet** and makes no packet-validation claim. A compact
ignored projection Markdown working set was read before detailed child queries;
full states stay under `_build`. Pass13's independently generated +7C1B packet
supplies recursive child edges/states. Its procedure knowledge and capture
identity match the unchanged current +7C1B contract; tests regenerate it normally.
No combined-run packet or parallel helper interpretation was introduced.

## Early/reverse paths and unobserved shortcuts

40 equal-range invocations return before work. Eight nonempty ranges return on
AA1A.bit0 set. The remaining29 work invocations all have202B.bit0 clear and2011
zero. Both shortcuts remain **STATIC / UNOBSERVED**. No reverse +7D96 or forward
+7DD4 test observes a mapped byte>=F7. These guards test mapping/cache data,
not the later returned byte of +7C1B: one top-level child returns **FE**, which
is cached despite the earlier mapped<F7 guard.

| Decision | Actual immediate flag producer | Taken condition / FIZZBUZ observation |
|---|---|---|
| +7D5A JNZ | +7D59 CMP end-begin | end!=begin;37 taken /40 fallthrough |
| +7D62 JNC | +7D61 RAR gate byte | original gate.bit0 clear;29 taken /8 fallthrough |
| +7D70 JC | +7D6F RAR202B | original202B.bit0 set;0 taken / 29 fallthrough |
| +7D78 JNZ | +7D76 CPI00 | byte2011!=0;0 taken / 29 fallthrough |
| +7D8A JZ | +7D89 CMP u8(begin-1), saved decremented cursor | equality;29 taken,35 processing decisions |
| +7D96 JNC | +7D94 CPI F7 | mapped>=F7;0 taken / 35 fallthrough |
| +7DBE JC | +7DBD CMP u8(end-1), fresh cursor | unsigned end-minus1<cursor;29 exits /102 iterations |
| +7DD4 JNC | +7DD2 CPI F7 | fresh mapped cache>=F7;0 taken / 102 fallthrough |
| +7E19 JZ | +7E17 CPI06 | attr==6;0 taken / 60 fallthrough |
| +7E28 JC | +7E26 CPI05 | attr<5;60 taken / 60 fallthrough |
| +7E3C JNZ | +7E3B INR cursor | new cursor!=0;102 taken /0 fallthrough |

RAR's tested carry comes from original bit0, independently of incoming carry.
CPI/CMP flags are comparison flags, not data provenance or normalized helper
results. Reverse predecrement0->FF is observed as the begin0-minus1 sentinel;
**forward INR FF->00 is not observed**. Work exits by the unsigned endpoint
comparison and publishes end=fresh begin0. The final loaded A0 does not recompute
that comparison's flags or imply a Boolean procedure result.

## Pass13 recursive behavior composed into six parent windows

[composition.json](composition.json) follows actual recursive CALL edges and
matched windows. All seven selected new cases (one special, six fallback) are
**descendants**, not the direct +7D9D child itself. Every parent below is called
at +7ED3 with begin0; the direct children are default mapped cases.

| Parent CALL | Initial end | Direct child CALL / input | Top mapped / returned A -> AE50 | +7B7A input -> stop | Selected descendants |
|---:|---:|---|---|---|---|
| 375015 | 7 | 375060 /6 | 6A /1 | 6->1 | fallback376381, pos2 |
| 403330 | 9 | 403375 /8 | 6C /1 | 8->0 | fallback406180, pos1 |
| 472976 | 9 | 473021 /8 | 6C /1 | 8->0 | fallback475962, pos1 |
| 539774 | 9 | 539819 /8 | 6C /1 | 8->0 | fallback542692, pos1 |
| 608084 | 4 | 608129 /3 | B2 /FE | 3->0 | fallback608347, pos1 |
| 618086 | 7 | 618131 /6 | 0F /15 | 6->0 | special618240, pos5; fallback619581, pos2 |

Each direct returned A is copied by its actual +7DA0 STA to AE50. The independent
+7DA7 call receives the fresh **outer** cursor; +7DAA writes its returned stopping
position to AE4F. A private child cursor is not this global replacement. Parent
375015 then predecrements1 to0, takes another processing iteration at0, and only
later reaches FF/end sentinel. The other listed initial selections stop at0 and
next predecrement toFF immediately ends reverse work. All reset forward cursor0,
visit0..end-1 and eventually publish end0. Identical returned A1/cache1 and
stopping cursor1 in the first row are separate producers/channels.

The special parent illustrates why equal values are insufficient:

- Direct child618131 maps0F/default. At618193 it reads initial auxiliary15 from
  **AD0B** (position6 maps to slot3); +7D0D caches it at private F+4 at618197.
- Descendant618240 maps1E and produces clamped15; descendant619581 maps17 with
  predecessor05 and reads current auxiliary15. Neither identifies the top-level
  mapped case or its eventual return producer.
- The direct child's F+2 receives15 twice, but its return +7D4E reads the original
  **F+4** at620113. The last recorded writer of that slot is618197. Direct A15
  therefore has a different origin from the matching descendant clamp byte.
- The caller writes direct A15 to AE50 at620118. +7B7A(input6) returns0, and the
  caller writes that stopping cursor at620391. The next branch at620402 observes
  saved cursorFF==begin-minus1FF, then forward reset occurs at620404.
- Independently, the special clamp is published to **AD0D** at619714. The later
  forward iteration at cursor5 maps1E/attribute4, reads AD0D at621220 and emits
  primary auxiliary15 at621231. The actual last guest writer, address and
  chronology establish this scoped relation; there is no intervening recorded
  guest write or nonhistorical callee effect in this parent window.

[flow.json](flow.json) records the distinct private-frame, caller-cache,
auxiliary-table and emission facts. No tree/operator ownership or general
producer-provenance theorem follows. Fresh forward mapping overwrites AE50;
its direct-child-return cache and the auxiliary publication are not merged.

## Forward classes and distinct channel order

All 102 transformed attributes come from actual +7B64 returned A followed by
+7DDE's cache write. Getter arguments, caches, fresh mapped-word reads and
recycling publications remain per-iteration correlated. Channel order:

| Transformed attr | MINIMAL count | FIZZBUZ count | Status / order |
|---:|---:|---:|---|
| 0 | 0 | 0 | STATIC / UNOBSERVED: mapped, word-low |
| 1 | 0 | 0 | STATIC / UNOBSERVED: mapped, word-low |
| 2 | 7 | 42 | OBSERVED: mapped, word-low, word-high |
| 3 | 1 | 7 | OBSERVED: mapped, second-auxiliary, primary-auxiliary |
| 4 | 8 | 53 | OBSERVED: mapped, primary-auxiliary |
| 5 | 0 | 0 | STATIC / UNOBSERVED: mapped, primary-auxiliary, word-low, word-high |
| 6 | 0 | 0 | STATIC / UNOBSERVED: mapped, suppress primary emission, word-low, word-high |
| 7 | 0 | 0 | STATIC / UNOBSERVED: mapped, primary-auxiliary, word-low, word-high |

There are 169 direct emitter arguments (102 mapped,7 second auxiliary,60 primary)
and 84 low/high wrapper arguments, **253 channels total**, versus 40 in MINIMAL.
No additional transformed attribute class is observed. Equal zero word bytes
still have two separate wrapper calls, cache accesses and emissions.

For all 42 attr2 pairs, +7E46 selects the mapped word, writes AE52/53 before low
emission, and +7E56 separately rereads those exact cache bytes for high emission.
Pass7's existing checks establish those relations. The helper's returned registers
and flags remain emitter-derived; the next +7BA2 argument reloads the fresh
cursor, not an inferred preserved register. +7BA2 writes oldAE33 to the selected
AAB4 mapped slot, then independently reads AA1F+cursor and writes that index to
AE33. Those two publication channels remain distinct for all 102 iterations.

### RAW pair and attr6

Neither +7E2B nor +7E2E appears in the selected projections or the FIZZBUZ global
instruction index. Exact six bytes `CD46A0CD56A0` are retained as RAW:
**STATIC / UNOBSERVED** +7E2B CALL7E46, then +7E2E CALL7E56.

Static control specifically **includes6**: CPI06/JZ +7E19 skips only primary
AE51 emission and targets +7E23. CPI05/JC +7E28 then falls through for6>=5 into
the mapped-word pair. Primary auxiliary is still read earlier; its emission is
suppressed, and the pair's low/high emissions are different channels. No dynamic
claim for this row is made. No forward cursor-wrap return is observed either.

## The observed buffer-threshold call and retained packet blocker

In parent472976, mapped-byte CALL478274 passes C=6C. Resident +0EF6 writes it to
buffer slot1E0B, changes index1E0C from127 to128, calls the already-delegated
resident buffer/file helpers, then resets the index to0 and returns normally.
Its actual return is A0, BC0015, DE1CA2, HL0, Z1/S0/P1/AC1/CY0. The two runtime0005
RET accesses remain unassigned to a historical image. This concrete observation
is recorded separately from a general flush/error algorithm; those helpers were
not decompiled and +0EF6's accumulated contract was not widened.

The parent continues through fresh cache loads/comparisons and subsequent mapped
recycling. Its emission argument6C, returned registers/flags, cache state and
later cursor are distinct channels. The record is useful semantic evidence but
cannot produce a successful full V0.2 historical-subtree packet under the current
profile. A separately authorized small infrastructure ticket could address that
presentation limit; this pass does not implement it or weaken validation.

## Annotation, status and completeness

Only +7D53's catalog and corresponding V1 header/block/local comments gain semantic
refinements. FIZZBUZ counts and the new caller coordinate are factual additions.
Pass13's now-known recursive cases replace the obsolete caller claim that those
arms remain RAW, with exact scope qualifications. Static attr6 routing is made
explicit beside its existing comparison group; the RAW rows remain DB directives.
[before.json](before.json) and [after.json](after.json) preserve the contracts.

Represented bytes remain **237/243**. **RAW -> STRUCTURED 0; RAW -> UNDERSTOOD 0**;
all byte statuses, image/section hashes and stable coordinate labels are unchanged.
Bounds/control-flow/contract remain **provisional/partial/partial**. Unobserved
six-byte arm, shortcut outcomes and scoped helper effects prevent a stronger
claim; independent original CALL/return ownership remains supported. No helper
metadata/contract, data role, CPU/trace architecture or packet code changed.
MINIMAL coverage/instruction/inventory/dynamic-progress files remain byte-identical.

Remaining blockers are exact: shortcut202B.bit0/2011, reverse/forward mapped>=F7,
transformed classes0/1/5/6/7, forward wrap, recursive mapped21/opposite comparisons,
resident error/opaque buffer-host algorithms, arbitrary scan/recursion termination,
full aliases and earlier table/control producers. The packet failure is an
additional presentation limitation, not uncertainty about which local coordinates
ran. All dynamic observations stay separate from STATIC / UNOBSERVED expectations.

## Validation and next strategy

Eight new tests verify selected-run counts/callers/returns/union, expected packet
rejection with unsupported effects retained, exact top-level/flag-producing
branches, ordered local path differences, recursive ancestor ownership, top-level
return/cache and independent cursor writers, frame/auxiliary writer identity,
all per-class channel orders, word caches, recycling and unexecuted RAW/wrap.
Existing Pass7 correlation functions are reused. Pass13's eight tests, all 109
MINIMAL tests, the 27-test packet suite including 55 continuation corruptions, V1
and verifier tests, project tests and `git diff --check` pass. **All 94,720
historical bytes reconstruct EXACTLY.** Captures, raw projections and generated
packets remain ignored; committed correlations are compact facts, not trace windows.

For **this +7D53 target**, matched microfixtures now have higher expected value
than another pass over the same natural FIZZBUZ states. Attribute6 is the first
useful discriminator: primary suppression while still executing the low/high pair;
classes5/7, shortcut and mapped>=F7/wrap states are also absent from both inputs.
This is planning, not fixture design or execution. Other natural FIZZBUZ slices
may still be useful, but this bounded audit does not claim a global ranking or
exhaustion of their semantic value. Any full-packet use that reaches this emitter
threshold needs the independently scoped nonhistorical-effect presentation issue
resolved first. No improved decompilation stability is inferred from one session.
