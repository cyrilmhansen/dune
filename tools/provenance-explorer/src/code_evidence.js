const imageKey = image => `${image.drive ?? 0}:${image.user ?? 0}:${image.name}`;
const coordinateKey = (image, offset) => `${imageKey(image)}:${offset}`;
const hexBytes = value => String(value ?? "").replace(/\s+/g, "").toUpperCase();

/** Project existing run reports into a compact, run-qualified code index. */
export function projectCodeRun(label, structure, blocks, canonical) {
  const routines = new Map((structure.routines ?? []).map(r => [r.id, r]));
  const instructions = canonical.instructions ?? [];
  const blockRelations = new Map();
  for (const relation of canonical.routine_block_relations ?? []) {
    const list = blockRelations.get(relation.canonical_block_id) ?? [];
    list.push([relation.routine_id, relation.tags, relation.first_step, relation.last_step, relation.execution_count]);
    blockRelations.set(relation.canonical_block_id, list);
  }
  const projectedBlocks = (canonical.blocks ?? []).map(block => ({ id: block.id, image: block.image.name,
    start: block.start_offset, end: block.end_offset, byte_length: block.byte_length,
    contexts: blockRelations.get(block.id) ?? [] }));
  const memberBlocks = new Map();
  for (const block of canonical.blocks ?? []) {
    for (const offset of block.instruction_offsets ?? []) {
      const coord = `${block.image.name}:${offset}`, ids = memberBlocks.get(coord) ?? [];
      ids.push(block.id); memberBlocks.set(coord, ids);
    }
  }
  const dynamicInstructions = new Map((blocks.instructions ?? []).map(i => [i.id, i]));
  const projectedTransfers = [];
  const coordOfDynamic = instruction => {
    const origin = instruction?.origin;
    if (!origin || origin.kind !== "image") return null;
    return { image: { drive: origin.drive ?? 0, user: origin.user ?? 0, name: origin.image }, offset: origin.offset };
  };
  for (const edge of blocks.instruction_transitions ?? []) {
    const from = coordOfDynamic(dynamicInstructions.get(edge.from));
    const to = coordOfDynamic(dynamicInstructions.get(edge.to));
    if (!from || !to) continue;
    projectedTransfers.push({ from_image: from.image.name, from_offset: from.offset,
      to_image: to.image.name, to_offset: to.offset, kind: edge.kind, count: edge.count,
      first_step: edge.first_step, last_step: edge.last_step });
  }
  const projected = instructions.map(instruction => {
    const coord = coordinateKey(instruction.image, instruction.offset);
    const contexts = (instruction.contexts ?? []).map(context => [context.routine_id, context.execution_count,
      context.first_step, context.last_step, context.runtime_pcs ?? []]);
    return { image: instruction.image.name, offset: instruction.offset, runtime_pcs: [...new Set(instruction.contexts?.flatMap(x => x.runtime_pcs) ?? [])],
      bytes: hexBytes(instruction.bytes), text: instruction.text, executions: instruction.execution_count,
      first_step: instruction.first_step, last_step: instruction.last_step,
      contexts, block_ids: memberBlocks.get(`${instruction.image.name}:${instruction.offset}`) ?? [] };
  });
  const routineTransitions = (structure.transitions ?? []).map(t => ({ from: t.from, to: t.to, count: t.count,
    first_step: t.first_step, last_step: t.last_step, kinds: t.kinds }));
  return { label, images: [...new Map(instructions.map(i => [i.image.name, [i.image.drive ?? 0, i.image.user ?? 0]])).entries()],
    routines: [...routines.values()].map(r => [r.id, r.display, r.image?.name ?? null, r.offset ?? null, r.tags ?? []]),
    routine_transitions: routineTransitions, blocks: projectedBlocks,
    transitions: projectedTransfers.sort(transferOrder), instructions: projected };
}

function transferOrder(a, b) {
  return a.first_step - b.first_step || a.kind.localeCompare(b.kind) ||
    String(a.from_image ?? a.image?.name).localeCompare(String(b.from_image ?? b.image?.name)) ||
    (a.from_offset ?? a.offset ?? 0) - (b.from_offset ?? b.offset ?? 0) ||
    String(a.to_image ?? "").localeCompare(String(b.to_image ?? "")) || (a.to_offset ?? 0) - (b.to_offset ?? 0);
}

/** Group only byte-identical observations; conflicting bytes remain variants. */
export function coordinateEvidence(runs, imageName, offset) {
  const observations = [];
  for (const run of runs) {
    const found = run.instructions.find(i => i.image.toUpperCase() === imageName.toUpperCase() && i.offset === offset);
    observations.push(found ? { run: run.label, instruction: found } : { run: run.label, instruction: null });
  }
  const variants = new Map();
  for (const observation of observations) {
    const instruction = observation.instruction;
    if (!instruction) continue;
    const group = variants.get(instruction.bytes) ?? [];
    group.push(observation);
    variants.set(instruction.bytes, group);
  }
  return { image: imageName, offset, observations,
    variants: [...variants.entries()].map(([bytes, members]) => ({ bytes, members })),
    byte_disagreement: variants.size > 1 };
}

export function parseCodeCoordinate(text) {
  const match = /^\s*([A-Za-z0-9_$.-]+)\s*\+\s*(?:0x)?([0-9A-Fa-f]{1,8})h?\s*$/i.exec(text);
  if (!match) return null;
  const offset = Number.parseInt(match[2], 16);
  return Number.isSafeInteger(offset) ? { image: match[1].toUpperCase(), offset } : null;
}

export function adjacentInstructions(runs, imageName, offset, limit = 24) {
  const coordinates = new Map();
  for (const run of runs) for (const instruction of run.instructions) {
    if (instruction.image.toUpperCase() !== imageName.toUpperCase()) continue;
    const key = instruction.offset, variants = coordinates.get(key) ?? new Set();
    variants.add(instruction.bytes); coordinates.set(key, variants);
  }
  const offsets = [...coordinates.keys()].sort((a, b) => a - b);
  const start = Math.max(0, offsets.indexOf(offset));
  return offsets.slice(start, start + limit);
}

export function witnessChunkIds(index, imageName, offset) {
  return index.instruction_index?.find(x => x.image.name.toUpperCase() === imageName.toUpperCase() && x.offset === offset)?.chunks ?? [];
}

export function selectInstructionWitnesses(chunks, imageName, offset) {
  return chunks.flatMap(chunk => chunk.events ?? [])
    .filter(event => event.type === "instruction" && event.witness.origin?.image.name.toUpperCase() === imageName.toUpperCase() && event.witness.origin.offset === offset)
    .map(event => event.witness);
}

export function indexedFileEventChunks(event) {
  return [...new Set([event.chunk, event.bdos_call_chunk].filter(id => id != null))];
}
