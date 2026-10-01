# MINIMAL decompilation pass 2

Starting commit: `7fa7340`. The five anchors were studied in the requested order
using the existing corrected MINIMAL capture. Five immediate leaf helpers were
needed for their contracts. FIZZBUZ/FACTOR/OPTIMIST supplied existing
corroboration only; their bodies were not decompiled. No new full capture,
generic decompiler, visualization or ownership implementation was introduced.

## OBSERVED: procedure and byte progress

MINIMAL coverage remains **10,378 coordinates / 21,012 bytes**. All **94,720
historical bytes** reproduce exactly, with unchanged full-image hashes.

| Executed status | Before | After | Change |
|---|---:|---:|---:|
| RAW | 19,574 | 18,991 | −583 |
| DECODED | 304 | 304 | 0 |
| STRUCTURED | 659 | 862 | +203 |
| UNDERSTOOD | 475 | 855 | +380 |
| Total | 21,012 | 21,012 | 0 |

| Image | Executed RAW | DECODED | STRUCTURED | UNDERSTOOD |
|---|---:|---:|---:|---:|
| PLI.COM | 2,500 | 142 | 65 | 614 |
| PLI0.OVL | 4,315 | 0 | 0 | 42 |
| PLI1.OVL | 6,801 | 0 | 258 | 89 |
| PLI2.OVL | 5,375 | 162 | 539 | 110 |

There are still **391 CALL/RST entries plus eleven separate PCHL continuation
entries = 402 callable coordinates**. CALL-entry classifications are now
**30 UNDERSTOOD, 9 STRUCTURED, 352 unresolved**, versus 21 / 8 / 362 before.
The eleven PCHL entries remain unresolved, for 363 unresolved coordinates overall.

Executed UNDERSTOOD bytes now cover **4.07%** of MINIMAL coverage; STRUCTURED
plus UNDERSTOOD cover **8.17%**. These measure annotated executed bytes, not
complete recovery of all branches. Whole-image RAW changes 93,241→92,658,
STRUCTURED 690→893, UNDERSTOOD 485→865; DECODED remains 304. The ten unexecuted
UNDERSTOOD bytes and 31 unexecuted STRUCTURED bytes retain prior statuses.

[progress.json](progress.json) and [before.json](before.json) retain per-image
before/after counts and hashes. Parent coverage/instruction/inventory files now
describe this pass. Source identity remains exact image SHA-256 plus file offset.

## ProcedureHypotheses and supported extents

Bounds are exclusive-end envelopes supported by CALL entries, local branches
and RETs; they are hypotheses, not min/max ownership intervals. Only fetched
MINIMAL instructions were promoted. Unexecuted holes and table data remain RAW.

| Entry | Envelope | Calls checked | Status | Newly promoted bytes |
|---|---|---:|---|---:|
| PLI2+1DFF | `[1DFF,1FB5)` | 13 | STRUCTURED | 203 |
| PLI2+0992 | `[0992,09BA)` | 24 | UNDERSTOOD | 40 |
| PLI2+047D | `[047D,0493)` | 67 | UNDERSTOOD | 22 |
| PLI2+04A9 | `[04A9,04BF)` | 70 | UNDERSTOOD | 22 |
| PLI.COM+0D40 | `[0D40,0E1F)` | 11 | UNDERSTOOD, scoped | 175 |
| PLI.COM+0E1F | `[0E1F,0E47)` | 195 | UNDERSTOOD, scoped | 35 |
| PLI1+4394 | `[4394,43D5)` | 3 | UNDERSTOOD, guard-success | 59 |
| PLI1+8396 | `[8396,83A0)` | 6 | UNDERSTOOD | 10 |
| PLI.COM+05B2 | `[05B2,05F8)` | 14 | UNDERSTOOD, no-key path | 8 |
| PLI.COM+0341 | `[0341,034A)` | 14 | UNDERSTOOD | 9 |

All ten use ordinary hardware-frame returns with exact original stack slots,
bytes and return targets: **417 checked invocations**. They are not assigned
software continuations because a parent uses one. [regions.json](regions.json)
retains callers/counts, return sites, entry/output snapshots, direct nested
calls, observed branches, contracts, pseudocode, limits and cross-run presence.
Per-step data is a curated projection, not a full replay trace.

### 1. PLI2+1DFF: descriptor predicate

OBSERVED: two CALLs from `+2037`, eleven from `+2085`; two RETs at `+1E74`
and eleven at `+1FB4`. C is the cursor; word[AD1D] points to a counted descriptor.
Own temporary PUSH PSW/POP B is balanced. No software continuation, PCHL, or
alternate entry is observed. Direct nested calls are `+047D` twice and `+0992`
six times. In MINIMAL the predicate does not access AD0A.

DEDUCED: save C at AD21/AD0B, descriptor count at AD25; initialize AD15..AD19
to FF and processed count AD22 to zero. For each item, decrement remaining
count and cursor, increment processed count, and write the pre-skip cursor to
AD0B+processed. Literal descriptors below ED compare against `+047D(cursor)`.
The two observed comparisons mismatch and return A=0. First-use FB/FC markers
store the processed position in cache AD15+(descriptor−FB), then replace cursor
with the result of `+0992`. Exhaustion returns A=1.

| MINIMAL descriptor case | Calls | Result |
|---|---:|---|
| Empty fallback | 6 | A=1 |
| One first-use FB marker | 4 | A=1 |
| FB then FC | 1 | A=1 |
| Literal 05 mismatch | 1 | A=0, CY=0 |
| Literal 69 mismatch | 1 | A=0, CY=1 |

CY is **not the Boolean result**: rejection preserves the unsigned comparison
carry, while completion has CY=0 and Z=1 from the final count comparison.
MVI A=0/1 does not recompute flags. The caller's RAR converts A bit0 to carry
for its branch. B/C/D/E/H/L are work registers; complete case outputs remain in
the representative snapshots.

This is a useful mechanically checked local predicate contract, but the region
stays STRUCTURED: literal success, repeated cache references, and ED..FA paths
remain unprocessed RAW. HYPOTHESIS: descriptor matching over a backward cursor;
no PL/I category/type is assigned.

The necessary `+0992` helper initializes cursor AC3B=C and byte balance AC3C=1,
repeats `balance=(balance+weight(cursor)-1) mod 256`, decrements cursor modulo
256 while balance is nonzero, and returns the terminal cursor. Twenty-four
calls use 38 weight lookups and fourteen cursor decrements. Return BC=0,
HL=AC3C, DE preserved, Z=1/CY=0. No termination guarantee for arbitrary tables
or interpretation as a source-language tree is asserted.

### Existing cross-run comparison, after MINIMAL reconstruction

Existing canonical evidence records predicate CALL counts MINIMAL/FIZZBUZ/
FACTOR/OPTIMIST = **13 / 97 / 44 / 179**. Bounded OPTIMIST archaeology shows
acceptance at ordinal one, and a separate sequence rejecting ordinals 1/2/3
then accepting four. Physical CALL/RET slots and bytes are independently checked;
old caller-context labels are not used. Dense observations between ordinal
increment and CALL verify no intervening AD0A write.

MINIMAL instead has **two rejected candidates at ordinals 1 and 2**, followed
by eleven successful fallback predicate calls. There is no successful MINIMAL
candidate ordinal. AD0A belongs to the caller's scan, not to this predicate's
input/output contract; the gateway later restores its saved state.
[corroboration.json](corroboration.json) preserves source hash, explicit scan
groups, frames and ordinal writers. Another bounded OPTIMIST call is explicitly
not grouped with either compared scan. Corroboration does not promote extra
OPTIMIST-only branches or transfer its semantics unchanged to MINIMAL.

### 2. PLI2+047D: leaf, not dispatcher

OBSERVED: 67 calls from seven sites, all RET `+0492`; no nested transfer or
rewritten slot. DEDUCED: save C at ABF8; j=byte[AAB0+C]; return A=byte[A609+j],
BC=j, HL=A609+j, DE preserved. CY clears through DAD; S/Z/P/AC retain entry
values. LHLD physically reads ABF9 too, then MVI H,0 discards it. It is a small
stateful table leaf, not a dispatcher inferred from frequency.

Needed weight helper `+04A9` has the same separate shape with scratch ABFA
and second table A6CF. It has seventy calls, including the 38 from `+0992`;
the other callers were not decompiled. Adjacent lookup leaves were not merged.
HYPOTHESIS: classification/weight table roles; table contents remain RAW data.

### 3. Resident +0D40: counted buffer builder

OBSERVED: three CALLs from `+113C`, eight from `+12B8`, all RET `+0E1E`.
Seven segments and four immediate 1A EOFs are observed. The preceding `+0D09`
has its own two overlay callers and RET `+0D3F`; no observed fallthrough to
`+0D40`. Inspection found no durable seed defining that earlier exit region;
its bytes and unexercised exit branch remain RAW with coordinate notes.

DEDUCED, scoped to witnessed seven-bit, non-tab, non-full input: clear 20AA,
call `+0CD9`, set index[1F06]=FF and bytes[1F07/1F08]=0. Fetch via `+0AF5`.
Immediate 1A stops without clearing old buffer bytes. Otherwise increment
word[2036], delegate formatting to `+0B86`, and collect until LF/1A. CR appends
NUL; printable 20..7E bytes append unchanged; other controls are skipped.
Count includes CR's NUL but excludes a subsequent terminal NUL; flag[200A]=1.
Finally index=0, HL=1F06, and A/CY=0 on the witnessed flag20AA=0 path.

The useful buffer transformation is UNDERSTOOD with delegated formatter/fetch
effects explicit. Tabs, high-bit transformations, and capacity/reporting paths
are RAW. HYPOTHESIS: source segment/line preparation, not complete text parsing.

Necessary append leaf `+0E1F` saves C at 20AB, wraps next=(index+1) mod 256,
and on witnessed next<120 writes index and byte[1E8E+next]. All 195 calls use
this path. Return A=input C, BC=next, HL=1E8E+next, DE preserved; DAD clears CY.
**S/Z/P/AC come from the second INR, not CPI or returned data.** Initial FF→0
therefore sets Z while A may be nonzero. Capacity rejection remains RAW.

### 4. PLI1+4394: ordinary child allocator

OBSERVED: one call from `+43E2`, two from constructor `+4479`; three original
hardware slots return at `+43D4`. No stack arguments or own-slot rewrite occur.
Adjacent `+43D5` and pass-1 `+4468` are distinct software-return constructors;
that parent convention is not inherited by this child.

DEDUCED: n=C saved at A8F6; P=word[1C36]; p=(P−9−n) mod 65536, using two
`+8396` calls. Set A863=p; test p>=AE7A via resident `+1A2C`. On all three
guard-success paths, set word[1C36]=p−1, byte[p]=(n+10) mod 256, byte[p+1]=0.
Return DE=p, HL=p+1, BC=n, A=size byte. Flags come from final size ADI;
carry is byte-size overflow, not allocation success. Observed n=0,7,7.
Failure branch +43B8..+43BD remains RAW; no generic heap ownership is assumed.

The separate six-call leaf `+8396` computes HL=DE−unsigned(A), preserving DE,
setting BC=unsigned(A), A=high result, CY=borrow; other flags describe high SBB,
not full-word zero/sign. RET +839F separates it from distinct entry +83A0.
HYPOTHESIS: downward variable-record reservation and a byte-subtraction adapter.

### 5. Resident +05B2: polling gate, not observed buffer setup

OBSERVED: eleven calls from `+05F8`, three from `+0730`, all RET `+05F7`.
The only local path is CALL `+0341`, RAR, taken JNC to RET. No-key is observed
in all fourteen cases. DEDUCED: rotate poll A through carry; when old A bit0=0,
return the rotated byte, CY=0, with other registers/NZPA flags following poll.
The local body performs no buffer initialization; only its CALL stack writes.

Necessary leaf `+0341` sets DE=0, C=11, invokes guarded BDOS bridge +19BB,
and RETs at +0349. Host registers/flags are delegated to existing CP/M semantics,
not generalized into a hardware timing/ABI promise. All MINIMAL polls return A=0.
The key-present path remains RAW. Larger parent +05F8 also calls +03E9;
it remains a separate unresolved operation.

## Refined hypotheses and next MINIMAL targets

No historical-byte contradiction or boundary merge was needed. The provisional
dispatcher role of +047D is refined to a lookup leaf; +05B2's provisional
buffer/setup role is refined to a reusable no-key gate. +0D40 remains separate
from +0D09, allocator +4394 from +43D5, and arithmetic +8396 from +83A0.
Current parent annotations +12AE/+4468 now reference the known refill/allocator
contracts while preserving their remaining unknown paths/helpers.

Next queue, identified from existing inventory only; bodies not investigated:

- **PLI.COM+0AF5:** 199 calls/two sites; connects new segment builder with the
  already annotated byte-filter/read chain.
- **PLI2+09BA:** nine calls, 82 observed context coordinates; composes balanced
  cursor/table helpers and needs its own controlled extent reconstruction.
- **PLI2+04BF:** 32 calls/two sites; connects the class lookup to larger consumers.
- **PLI1+4281:** eleven calls/six sites; common predicate in constructor and
  field-repair paths, a remaining barrier to a fuller record contract.
- **PLI0+24BC:** 85 calls/four sites, 371 observed context coordinates; a large
  still-RAW context whose procedure extent must first be established.

## Reproduce and validate

Ignored `_build/minimal-pass-2` contains analysis windows; the existing full
MINIMAL capture is reused. Durable projections are not sufficient for arbitrary
replay/ownership analysis; complete chronology remains separate evidence.

```sh
python3 tools/annotated-assembly/check_minimal_pass_2.py \
  --capture _build/minimal-baseline/capture --output _build/minimal-pass-2/rechecked.json
dune runtest --force
python3 tools/annotated-assembly/test_minimal_pass_2.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_pass_1.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_minimal_baseline.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/test_verify.py --images /path/to/DISK1 -v
python3 tools/annotated-assembly/verify.py --images /path/to/DISK1
git diff --check
```

Project tests and 36 annotated/baseline/pass tests pass. Modified and complete
section hashes, whole-image hashes/equality, partitions and offset mappings
pass after every annotation batch. No historical encoding is cleaned up.
