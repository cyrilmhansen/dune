# Faithful native mapped-word emitters — Pass24

Baseline: `519c1eb5ec10d18bb9be51c732961dab45f0a4e4`.

The host compiler now has one reusable complete `PLI1.OVL+7A79` implementation,
used by Packed_scan and the new distinct low/high word-emission wrappers.
All 242 independent natural shadows match every register/flag, original return,
full 64 KiB memory and complete external CP/M state. Nine single-replacement,
three hierarchical-wrapper and three full cumulative compiler runs preserve
ordered INT/REL records, file events, final filesystems and all golden REL files.
No historical annotation, byte status, contract or completeness changed.

## Historical operations

`Pli80_host.Mapped_word.lookup` publishes position at AE38, reads the AE38/AE39
pair, retains the discarded neighbor, zero-extends the low byte, freshly reads
position_map, performs the two16-bit index additions and reads mapped-word low
then high. Its adapter preserves A/NZPA, clearsCY and returns BC=j, DE=high-address,
HL=selectedword. It has no internal CALL/PUSH residue. Packed_scan uses this
same implementation, retaining all original write phases, shift ordering and
fresh final auxiliary lookup. There is no second mapped-word lookup algorithm.

`Pli80_host.Word_emitter.low` genuinely reads both AE4F/AE50, uses only low cursor
as +7A79 position, and publishes cache low AE52 then high AE53. Only afterward
it invokes native Int_emitter with the selected low byte. Both A and C are set
by the wrapper before the child. `Word_emitter.high` accepts no previous word
result: it freshly reads both cache bytes, retains unused low-byte metadata and
sets A/C to the freshly read high byte before native emission.

The native child continuation is composed in the PL/I adapter. The host module
has no Cpu, I8080, Runner or CP/M dependency. Its child-operation continuation
connects the proven native emitter; it is not a simplified output callback.
A shared-memory test mutates AE52/AE53 between the operations and proves the
high wrapper emits the new high byte while still recording the new low read.

## Ownership, transaction and compatibility

Every outer entry is proved from an actual canonical historical CALL, fetched
bytes, SP ancestry and original continuation writes; the terminal original RET
is independently checked. Internal CALL residue is derived from immutable
callsites, never copied from post-memory:

- Low: +7E4A CALL writes A04D at S-2; +7E52 CALL later overwrites it with A055.
- High: +7E5B CALL writes A05E at S-2.
- The child emitter entry is concretely T=S-2. A successful flush additionally
  uses its ordered resident service CALL/PUSH planner. Final words are
  T-2=1024, T-4=0437, T-6=1C15, T-8=1CA2 and T-10=1AC6.

Both wrappers return the emitter machine state, followed by their own outer RET
(SP=S+2 and actual outer continuation). They do not return word-selection ABI.
The ordered wrapper program contains cache/scratch/compatibility writes followed
by the existing emitter program in one root transaction. Runner and CP/M need no
change. The existing staged real BDOS26/21 mechanism keeps all prefix/cache,
DMA, FCB, filesystem, record and callback effects private until validation.

No natural wrapper invocation flushes. Accordingly the report makes no natural
wrapper-flush claim. Separate synthetic tests run **both exact historical CPU
wrappers and native wrappers** in legal flushing states using actual CP/M
services. Full memory, machine state, DMA, filesystem and record data agree.
Nonzero status, reordered effects and duplicated services are rejected; live
RAM/DMA/filesystem/callbacks remain unchanged. Those tests also validate deeper
flush residues and preserved physical buffer contents. They make no new compiler
source-semantic claim.

## Natural independent oracles

Fresh execution rederives all calls and original returns; the Pass24 Python
checks independently join them to the existing corrected captures. Duplicate
values remain independent cases. Existing capture identities are MINIMAL
`MINIMAL:efb57286cd9ece9983df85452329dda70f2f05a63d0835fd8e10f4f6a1dd90c4`,
FIZZBUZ `FIZZBUZ:a7a657b3c9c758be44a16c4c76a2986744f01de34d773d2b9597d4758eff0f49`,
and PICTURE `PICTURE:690dbdc67d1a01c466bb359e3c28dcfc2bfb3635455616355c779599b38bcec2`.
No new source or witness capture was required. Private memory/service snapshots
and generated proofs remain ignored under `_build/host-compiler-pass-24*`.

| Source | +7A79 shadows/single transitions | Low shadows/roots | High shadows/roots | Wrapper nonflush/flush |
|---|---:|---:|---:|---:|
| MINIMAL | 11 | 7 | 7 | 14 /0 |
| FIZZBUZ | 91 | 42 | 42 | 84 /0 |
| PICTURE | 18 | 12 | 12 | 24 /0 |

Mapped-word callers (counts MINIMAL/FIZZBUZ/PICTURE): +3293=1/8/1,
+7BCC=3/21/3, +7E4A=7/42/12, plus +3223=0/10/1 and +3256=0/10/1.
Low callers are +7DE6=7/42/10 and +7E2B=0/0/2; high callers are
+7DF1=7/42/10 and +7E2E=0/0/2. The two PICTURE attribute6 word-pair iterations
select word0; their channels remain separate. All selected-word and emitted-byte
frequency distributions are retained in [host-service-summary.json](host-service-summary.json).
High-byte distributions are 00/02/FB: MINIMAL3/1/3, FIZZBUZ25/4/13,
PICTURE6/1/5; the low-byte distribution is independent.

## Cumulative hierarchy and output

Count order is +7C1B roots, external +7BBF, external +7B7A, +7BA2 roots,
external +7AD5, +7B64, +7ABF, external +0EF6, external +7A79, +7E46 roots,
+7E56 roots.

| Source | Runner transition vector | Total | Native BDOS26 /21 |
|---|---|---:|---:|
| MINIMAL | 9,0,16,16,18,16,14,114,1,7,7 | 218 | 1 /1 |
| FIZZBUZ | 35,0,93,107,140,109,113,300,28,42,42 | 1009 | 3 /3 |
| PICTURE | 11,0,19,22,28,25,19,104,3,12,12 | 255 | 1 /1 |

Logical +7A79 inside low wrappers=7/42/12. Logical emitters inside low and high
are respectively7/42/12 each. Another3/21/3 mapped-word lookups remain native
inside Packed_scan beneath Recursive_mapped. Existing recursive nodes and
Balance_scan/Packed_scan hierarchy are unchanged. Child windows are excluded by
corrected original-return ancestry, never by dynamic context counts.
No enabled historical body executes; canonical image identity prevents overlay
PC collisions. No synthetic Steps/t-states/BDOS guest entries are produced.

All retained INT/REL records are byte-identical and ordered identically; complete
file events and final physical/logical filesystems match. INT bytes remain
historically deleted after PASS2, so record identity and later reads establish
its lifecycle rather than an invented surviving file. INT record counts are
1/3/1, REL record counts2/6/2. Native flushes retain DMA1D8C, FCB1CA2, actual
record numbers0 (MINIMAL/PICTURE) or0/1/2 (FIZZBUZ), and real FCB writes.
Record hashes are in [shadow-summary.json](shadow-summary.json).

| Source | REL bytes | SHA256 |
|---|---:|---|
| MINIMAL | 256 | 7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119 |
| FIZZBUZ | 768 | 68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203 |
| PICTURE | 256 | c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1 |

Every experiment reaches `NO ERROR(S) IN PASS 1`, `NO ERROR(S) IN PASS 2`,
`END  COMPILATION` and warm boot. Emitter guards/errors, invalid index domains,
unsupported aliases/code/CALL/source states fail closed with no historical
fallback. +7E46/+7E56 remain stable/complete/**partial**; bounded native success
support does not establish their emitter error behavior.

## Validation and next boundary

Native tests cover65,536 position/index pairs,65,536 word values,8,192 returned
ABI flag cases, cache mutation, canonical CALL/code/alias/continuation/count
negatives, actual historical and native low/high flushes and failed transaction
atomicity. Seven fresh Pass24 evidence tests check all242 corrected natural
windows and all15 hybrid experiments. Prior native, CP/M, archaeology, MINIMAL,
packet/continuation, V1 and exact-byte suites are retained; final results appear
in [validation.json](validation.json). All 94,720 historical bytes remain exact.
No archaeology correction, Runner/CP/M change, pragmatic divergence or fidelity
debt was introduced.

Pass25 can attempt bounded native +7D53 on actual-state predicates: normal
reverse work, mapped<F7, currently supported recursive cases, attributes2/3/4/6,
normal endpoint exit and successful emitter services. Equal/gate returns need
independent path ABI proof; the gate is already dynamically observed and must
not be called globally unobserved. Shortcut flags/byte, mapped>=F7, forward wrap,
attributes0/1/5/7 and unsupported recursive outcomes must remain fail-closed.
The next implementation must compose the entire root's interleaved recursive,
cache and real-service chronology in one transaction, prove root-depth stack
last writers and shadow every natural root. No snapshot whitelist or added
termination guard may select native semantics. [boundary-assessment.json](boundary-assessment.json)
records these obligations. FACTOR attr5 remains deferred.
