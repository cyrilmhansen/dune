// Keep assembler output in memory: no intermediate binaries or listings.
import { readFileSync } from 'node:fs';
import { asm, asmJson } from 'asm8080';
const source = readFileSync(process.argv[2], 'utf8');
try {
  const sections = asm(source);
  const listing = asmJson(source, sections);
  process.stdout.write(JSON.stringify({
    sections: sections.map(s => ({start: s.start, bytes: s.data})),
    listing,
  }));
} catch (error) {
  process.stderr.write(`ASSEMBLY FAILED: ${error.message}\n`);
  process.exitCode = 1;
}
