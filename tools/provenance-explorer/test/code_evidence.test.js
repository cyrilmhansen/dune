import test from "node:test";
import assert from "node:assert/strict";
import { adjacentInstructions, coordinateEvidence, parseCodeCoordinate, projectCodeRun } from "../src/code_evidence.js";

const image = { drive: 0, user: 0, name: "PLI.COM" };
function reports({ split = false, contexts = [1], bytes = "C30001", withCode = true } = {}) {
  const canonical = { instructions: withCode ? [{ image, offset: 0x100, bytes, text: "JMP 0100H", execution_count: 4,
    first_step: 5, last_step: 12, contexts: contexts.map(routine_id => ({ routine_id, runtime_pcs: [0x200], execution_count: 2, first_step: 5, last_step: 12 })) },
    { image, offset: 0x103, bytes: "C9", text: "RET", execution_count: 1, first_step: 13, last_step: 13, contexts: [] }] : [],
    blocks: split ? [{ id: 0, image, start_offset: 0x100, end_offset: 0x103, byte_length: 3, instruction_offsets: [0x100] },
      { id: 1, image, start_offset: 0x103, end_offset: 0x104, byte_length: 1, instruction_offsets: [0x103] }] :
      [{ id: 0, image, start_offset: 0x100, end_offset: 0x104, byte_length: 4, instruction_offsets: [0x100, 0x103] }],
    routine_block_relations: [{ canonical_block_id: 0, routine_id: 1, tags: ["routine-entry"], first_step: 5, last_step: 12, execution_count: 4 }] };
  const dynamic = withCode ? [{ id: 10, origin: { kind: "image", image: "PLI.COM", offset: 0x100 } },
    { id: 11, origin: { kind: "image", image: "PLI.COM", offset: 0x103 } }] : [];
  return { structure: { routines: [{ id: 1, display: "R001 · PLI.COM+0100", image, offset: 0x100, tags: ["called"] }] },
    blocks: { instructions: dynamic, instruction_transitions: withCode ? [{ from: 10, to: 11, kind: "branch-taken", count: 3, first_step: 5, last_step: 12 }] : [] }, canonical };
}

test("same coordinate retains per-run block partitions and multiple analytical contexts", () => {
  const a = reports(), b = reports({ split: true, contexts: [2, 3] });
  const pa = projectCodeRun("MINIMAL", a.structure, a.blocks, a.canonical);
  const pb = projectCodeRun("FIZZBUZ", b.structure, b.blocks, b.canonical);
  const selected = coordinateEvidence([pa, pb], "PLI.COM", 0x100);
  assert.equal(selected.byte_disagreement, false);
  const blockFor = (run, instruction) => run.blocks.find(b => instruction.block_ids.includes(b.id));
  assert.equal(blockFor(pa, selected.observations[0].instruction).end, 0x104);
  assert.equal(blockFor(pb, selected.observations[1].instruction).end, 0x103);
  assert.equal(selected.observations[1].instruction.contexts.length, 2);
  assert.equal(pb.transitions[0].kind, "branch-taken");
});

test("byte disagreement is kept as variants and missing run coordinates remain explicit", () => {
  const a = reports(), b = reports({ bytes: "C30101" }), c = reports({ withCode: false });
  const runs = [projectCodeRun("OPTIMIST", c.structure, c.blocks, c.canonical),
    projectCodeRun("FACTOR", a.structure, a.blocks, a.canonical), projectCodeRun("OTHER", b.structure, b.blocks, b.canonical)];
  const selected = coordinateEvidence(runs, "PLI.COM", 0x100);
  assert.equal(selected.byte_disagreement, true);
  assert.deepEqual(selected.variants.map(x => x.bytes).sort(), ["C30001", "C30101"]);
  assert.equal(selected.observations[0].run, "OPTIMIST");
  assert.equal(selected.observations[0].instruction, null);
  assert.ok(selected.observations[1].instruction, "coordinate remains available from another run");
});

test("direct image plus hexadecimal offset navigation and adjacent instruction stepping", () => {
  assert.deepEqual(parseCodeCoordinate(" PLI.COM+0BDAh "), { image: "PLI.COM", offset: 0xBDA });
  assert.deepEqual(parseCodeCoordinate("PLI2.OVL+0x11E6"), { image: "PLI2.OVL", offset: 0x11E6 });
  assert.equal(parseCodeCoordinate("not-a-coordinate"), null);
  const r = reports(), projected = projectCodeRun("A", r.structure, r.blocks, r.canonical);
  assert.deepEqual(adjacentInstructions([projected], "PLI.COM", 0x100, 8), [0x100, 0x103]);
});
