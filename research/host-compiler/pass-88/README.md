# Pass88 — scoped +382E stack-argument operation

Baseline `4679aeb0921bf370ef0bfee3446aaa742e3a04a2`. Complete host execution for the two natural +397F argument calls, with inherited canonical eligibility guards. No interception installed.

The operation POPs the hardware continuation into DE, POPs a separate caller argument into BC, writes its low byte to AD50 and PUSHes DE into the consumed argument slot. Its RET consumes that relocated word: final SP is entry SP + 4. Surviving writes preserve both original CALL residue and relocated continuation.

Direct instruction effects, the one-iteration +83A3 rotate, +8386 SUB/SBB negation and non-6 +80B2 adapter are computed from current state. Unchanged resident +1A40 and canonical +8072/+73CA/+75CE operations supply child effects through copied staged RAM/filesystem/DMA. No final-state replay or guest callback supplies effects.

Both independently executed natural windows have 1,934 instructions and 471 ordered writes. Complete registers/flags, PC/SP, 65,536-byte RAM, writer/order, direct instruction-owned read chronology and filesystem/DMA/service chronology match. Both windows contain zero services; OPTIMIST's record activity occurs outside +382E. Canonical child read effects retain their existing contracts; the bridge does not expose an aggregate read journal. Sixty-four synthetic negation/flag cases independently match CPU execution.

The carry-loop +3863..+388F and +80B2 index-6 path remain unsupported. Child guards retain unsupported output, alias and error domains. No knowledge promotions, native roots or oracle queries. Five complete guest runs preserve historical REL goldens, including FACTOR's `9a42e8341a013243036040c8db0e56939c699c7fbbfb20878f7ba5af8d6b470d`.

Next: assess actual +373C nested gateway eligibility and compose selector15 +397F. Pass74 remains certified FULL epoch3. No FULL requested or run.

Validation: explicit incremental selection passed 5/5 categories, 20 Python executions; measured wall 11.294 seconds, summed category time 11.484 seconds, four workers. Existing reconstruction verifier passed all four images (94,720 bytes). Receipt SHA256 `2b90b606332ffc88be4a63456402387d35372f1c332126b6fc25918e404a5335`.
