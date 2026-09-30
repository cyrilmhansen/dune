#!/usr/bin/env python3
"""Verify durable sources against separately supplied historical images."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
DEFAULT_MANIFEST = HERE.parent.parent / 'research/annotated-assembly/manifest.json'
STATUSES = ('RAW', 'DECODED', 'STRUCTURED', 'UNDERSTOOD')
ALIASES = {0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0xCB, 0xD9, 0xDD, 0xED, 0xFD}


class VerificationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def assemble(source):
    package = HERE / 'node_modules/asm8080/package.json'
    require(package.exists(), 'Assembler missing: run npm ci --prefix tools/annotated-assembly --ignore-scripts')
    require(read_json(package)['version'] == '1.0.34', 'Assembler version must be 1.0.34')
    result = subprocess.run(['node', str(HERE / 'assemble.mjs'), str(source)],
                            capture_output=True, text=True)
    require(result.returncode == 0, f'{source.name}: {result.stderr.strip()}')
    return json.loads(result.stdout)


def check_partition(image):
    cursor = 0
    for section in image['sections']:
        start, end = section['start_offset'], section['end_offset']
        require(type(start) is int and type(end) is int, f'{image["name"]}: noninteger range')
        require(start == cursor, f'{image["name"]}: manifest gap/overlap at +{cursor:04X}, next +{start:04X}')
        require(start < end <= image['length'], f'{image["name"]}: invalid section end +{end:04X}')
        require(section['length'] == end - start, f'{image["name"]}+{start:04X}: wrong section length')
        require(section['status'] in STATUSES, f'{image["name"]}+{start:04X}: unknown status')
        require(section['image_sha256'] == image['sha256'], f'{image["name"]}: section image identity mismatch')
        require(section['runtime_start'] == image['runtime_base'] + start and
                section['runtime_end'] == image['runtime_base'] + end,
                f'{image["name"]}+{start:04X}: section runtime mapping mismatch')
        cursor = end
    require(cursor == image['length'], f'{image["name"]}: manifest trailing gap at +{cursor:04X}')


def check_section_hashes(image, original, rebuilt):
    for section in image['sections']:
        start, end = section['start_offset'], section['end_offset']
        where = f'{image["name"]}+{start:04X}..+{end:04X}'
        require(sha256(original[start:end]) == section['original_sha256'], f'{where}: original section SHA-256 mismatch')
        require(sha256(rebuilt[start:end]) == section['reassembled_sha256'], f'{where}: reassembled section SHA-256 mismatch')
        require(section['exact_match'] is True and original[start:end] == rebuilt[start:end],
                f'{where}: section bytes differ / exact_match is not true')


def normal_mnemonic(text):
    return re.sub(r'\b([0-9A-F]+)H\b', lambda m: f'{int(m[1], 16):X}H', text.upper()).replace(' ', '')


def check_source(image, source, assembly, seeds):
    base = image['runtime_base']
    sections = assembly['sections']
    require(len(sections) == 1 and sections[0]['start'] == base,
            f'{image["name"]}: source must have one contiguous section at runtime base')
    rebuilt = bytes(sections[0]['bytes'])
    require(len(rebuilt) == image['length'], f'{image["name"]}: reconstructed image length mismatch')
    text = source.read_text()
    require(f'; Image SHA-256: {image["sha256"]}' in text, f'{image["name"]}: source image identity missing')
    markers = re.findall(r'^; SECTION \[([0-9A-F]+),([0-9A-F]+)\) (\w+)$', text, re.M)
    expected = [(f'{s["start_offset"]:04X}', f'{s["end_offset"]:04X}', s['status']) for s in image['sections']]
    require(markers == expected, f'{image["name"]}: source section markers differ from manifest')
    symbols = assembly['listing']['symbols']
    for section in image['sections']:
        label = f'{image["label_prefix"]}_{section["start_offset"]:04X}'
        require(symbols.get(label) == f'{base + section["start_offset"]:04X}',
                f'{image["name"]}: stable section label {label} mapping mismatch')
    facts = {i['offset']: i for seed in seeds for i in seed['instructions']}
    cursor = 0
    section_index = 0
    for row in assembly['listing']['code']:
        if not row.get('bytes'):
            require(row.get('op') in (None, 'org', 'end'), f'{image["name"]}: unsupported layout directive')
            continue
        while cursor >= image['sections'][section_index]['end_offset']:
            section_index += 1
        section = image['sections'][section_index]
        raw = bytes.fromhex(''.join(row['bytes']))
        where = f'{image["name"]}+{cursor:04X} (source line {row["line"]})'
        require(row['addr'] == f'{base + cursor:04X}', f'{where}: source/runtime offset mapping mismatch')
        label = f'{image["label_prefix"]}_{cursor:04X}'
        require(row.get('label') == label and symbols.get(label) == row['addr'], f'{where}: stable label mapping mismatch')
        require(re.search(rf'\+{cursor:04X} runtime={base + cursor:04X}H\b', row.get('comment', '')),
                f'{where}: source coordinate comment mismatch')
        require(cursor + len(raw) <= section['end_offset'], f'{where}: source row crosses section boundary')
        require(rebuilt[cursor:cursor + len(raw)] == raw, f'{where}: listing and assembler bytes disagree')
        if section['status'] == 'RAW':
            require(row['op'] == 'db', f'{where}: RAW section must use explicit DB')
        else:
            fact = facts.get(cursor)
            require(fact is not None and fact['bytes'] == raw.hex().upper(), f'{where}: mnemonic has no matching retained evidence')
            require(raw[0] not in ALIASES and row['op'] != 'db', f'{where}: alias/raw encoding cannot be promoted')
            statement = text.splitlines()[row['line'] - 1].split(';', 1)[0].split(':', 1)[1]
            require(normal_mnemonic(statement) == normal_mnemonic(fact['decoded']), f'{where}: mnemonic differs from evidence')
        cursor += len(raw)
    require(cursor == image['length'], f'{image["name"]}: source listing gap')
    return rebuilt


def check_software_return(seed, images, originals):
    """The reviewed PLI1 argument-consuming return; preserve byte/slot checks."""
    proof = seed['software_return_sample']
    call, writer, ret, relation = (proof[k] for k in ('call', 'writer', 'ret', 'relation'))
    for witness in (call, writer, ret):
        origin = witness['origin']
        require(origin is not None, f'{seed["id"]}: software proof lacks image origin')
        name, offset = origin['image']['name'], origin['offset']
        raw = bytes.fromhex(witness['bytes'])
        require(originals[name][offset:offset + len(raw)] == raw and
                witness['pc'] == images[name]['runtime_base'] + offset,
                f'{seed["id"]}: software proof coordinate/bytes mismatch')
    require(call['bytes'] == 'CD' + (images[seed['image']]['runtime_base'] + seed['start_offset']).to_bytes(2, 'little').hex().upper() and call['pc_after'] == images[seed['image']]['runtime_base'] + seed['start_offset'] and
            writer['origin']['image']['name'] == seed['image'] and
            seed['start_offset'] <= writer['origin']['offset'] < seed['end_offset'] and writer['bytes'] == 'D5' and
            ret['origin']['image']['name'] == seed['image'] and ret['origin']['offset'] in seed['observed_return_offsets'] and ret['bytes'] == 'C9',
            f'{seed["id"]}: software entry/writer/exit mismatch')
    # This optional proof admits only the established two-byte stack argument ABI.
    require(proof['stack_argument_bytes'] == 2 and ret['sp_before'] == call['sp_after'] + 2 and
            ret['pc_after'] == call['pc'] + 3 and ret['sp_after'] == call['sp_after'] + 4,
            f'{seed["id"]}: software return argument/target mismatch')
    writes = {w['address']: w['new_value'] for w in writer['writes']}
    reads = {r['address']: r['value'] for r in ret['reads']}
    slot = ret['sp_before']
    require(writes == reads and set(reads) == {slot, (slot + 1) & 65535} and writer['sp_after'] == slot and
            call['step_index'] < writer['step_index'] < ret['step_index'] and
            reads[slot] + 256 * reads[(slot + 1) & 65535] == ret['pc_after'],
            f'{seed["id"]}: software writer/stack bytes mismatch')
    require(relation['type'] == 'software_continuation_return' and relation['step_index'] == ret['step_index'] and
            relation['stack_slot'] == slot and relation['return_address'] == ret['pc_after'],
            f'{seed["id"]}: software continuation relation mismatch')
    for field, address in [('low_byte_writer', slot), ('high_byte_writer', (slot + 1) & 65535)]:
        fact = relation[field]
        require(fact['step'] == writer['step_index'] and fact['pc'] == writer['pc'] and fact['origin'] == writer['origin'] and
                fact['value'] == writes[address], f'{seed["id"]}: software latest-writer fact mismatch')


def check_evidence(evidence, images, originals):
    bases = {b['image']: b for b in evidence['load_bases']}
    for name, image in images.items():
        b = bases[name]
        require(b['image_sha256'] == image['sha256'] and b['offset'] == 0 and
                b['runtime_pcs'] == [image['runtime_base']], f'{name}: runtime base differs from Runes evidence')
        require(originals[name].startswith(bytes.fromhex(b['bytes'])), f'{name}: load-base instruction bytes differ')
    for seed in evidence['seeds']:
        image = images[seed['image']]
        data = originals[seed['image']]
        require(seed['image_sha256'] == image['sha256'], f'{seed["id"]}: seed identity mismatch')
        last = seed['start_offset']
        for instruction in seed['instructions']:
            offset = instruction['offset']
            raw = bytes.fromhex(instruction['bytes'])
            require(last <= offset and offset + len(raw) <= seed['end_offset'], f'{seed["id"]}: evidence overlap/out of range')
            require(data[offset:offset + len(raw)] == raw, f'{seed["id"]}+{offset:04X}: evidence byte mismatch')
            require(instruction['runtime_pc'] == image['runtime_base'] + offset,
                    f'{seed["id"]}: evidence runtime mapping mismatch')
            last = offset + len(raw)
        for caller in seed['observed_callers']:
            offset = caller['offset']
            raw = bytes.fromhex(caller['bytes'])
            require(originals[caller['image']][offset:offset + len(raw)] == raw,
                    f'{seed["id"]}: caller bytes differ')
            require(raw == b'\xcd' + (image['runtime_base'] + seed['start_offset']).to_bytes(2, 'little'),
                    f'{seed["id"]}: caller does not CALL seed entry')
        for offset in seed.get('observed_return_offsets', []):
            require(seed['start_offset'] <= offset < seed['end_offset'] and
                    any(i['offset'] == offset and i['bytes'] == 'C9' for i in seed['instructions']),
                    f'{seed["id"]}: declared RET site is not a retained in-range RET instruction')
        if seed.get('tail_return_runtime_pc') is not None:
            require(seed['tail_return_runtime_pc'] == 5 and
                    any(i['offset'] == seed['end_offset'] - 3 and i['bytes'] == 'C30500'
                        for i in seed['instructions']),
                    f'{seed["id"]}: external BDOS return without retained terminal JMP 0005H')
        if seed.get('software_return_sample'):
            check_software_return(seed, images, originals)
        match = seed['matched_return_sample']
        if match:
            call, ret = match['call'], match['ret']
            for w in (call, ret):
                origin = w['origin']
                if origin is None:
                    require(w is ret and seed.get('tail_return_runtime_pc') == 5 and w['pc'] == 5 and w['bytes'] == 'C9',
                            f'{seed["id"]}: unsupported external return witness')
                    continue
                name = origin['image']['name']; offset = origin['offset']
                raw = bytes.fromhex(w['bytes'])
                require(originals[name][offset:offset + len(raw)] == raw and
                        w['pc'] == images[name]['runtime_base'] + offset,
                        f'{seed["id"]}: stack-pair witness coordinate/bytes mismatch')
            require(call['pc_after'] == image['runtime_base'] + seed['start_offset'] and
                    ((ret['origin'] is not None and ret['origin']['image']['name'] == seed['image'] and ret['origin']['offset'] in seed.get('observed_return_offsets', [seed['end_offset'] - 1])) or
                     (ret['origin'] is None and seed.get('tail_return_runtime_pc') == 5)) and ret['bytes'] == 'C9',
                    f'{seed["id"]}: matched pair is not seed entry/exit')
            writes = {w['address']: w['new_value'] for w in call['writes']}
            reads = {r['address']: r['value'] for r in ret['reads']}
            require(call['control']['kind'] == 'call' and ret['control']['kind'] == 'return' and
                    call['step_index'] < ret['step_index'] and call['sp_after'] == ret['sp_before'] and
                    call['pc'] + 3 == ret['pc_after'] and writes == reads and len(reads) == 2,
                    f'{seed["id"]}: CALL/RET stack-byte relation does not match')


def verify(manifest_path, images_dir):
    manifest_path = Path(manifest_path)
    manifest = read_json(manifest_path)
    require(manifest['schema_version'] == 1, 'Unknown manifest schema')
    require(manifest['assembler'] == {'package': 'asm8080', 'version': '1.0.34'}, 'Unexpected assembler pin')
    images = {i['name']: i for i in manifest['images']}
    require(len(images) == len(manifest['images']) == 4 and
            set(images) == {'PLI.COM', 'PLI0.OVL', 'PLI1.OVL', 'PLI2.OVL'}, 'Manifest must contain each of the four images once')
    originals = {name: (Path(images_dir) / i['original_filename']).read_bytes() for name, i in images.items()}
    evidence = read_json(manifest_path.parent / manifest['evidence'])
    require(evidence['schema_version'] == 1, 'Unknown evidence schema')
    for image in images.values():
        check_partition(image)
    check_evidence(evidence, images, originals)
    progress = []
    for name, image in images.items():
        seeds = [s for s in evidence['seeds'] if s['image'] == name]
        for section in image['sections']:
            refs = [s for s in seeds if section['start_offset'] >= s['start_offset'] and section['end_offset'] <= s['end_offset']]
            expected_refs = [f'evidence.json#seeds/{s["id"]}' for s in refs]
            require(section['evidence_refs'] == expected_refs, f'{name}: section evidence reference mismatch')
            if section['status'] != 'RAW':
                require(refs, f'{name}: promoted section without seed evidence')
            if section['status'] in ('STRUCTURED', 'UNDERSTOOD'):
                require(any(s['matched_return_sample'] or s.get('software_return_sample') for s in refs), f'{name}: structure without matched pair')
            if section['status'] == 'UNDERSTOOD':
                require(any(s.get('behavioral_contract') for s in refs), f'{name}: understood section without contract')
        source = manifest_path.parent / image['source']
        rebuilt = check_source(image, source, assemble(source), seeds)
        original = originals[name]
        check_section_hashes(image, original, rebuilt)
        require(len(original) == image['length'] and sha256(original) == image['sha256'], f'{name}: historical full-image SHA-256/length mismatch')
        require(sha256(rebuilt) == image['sha256'], f'{name}: reconstructed full-image SHA-256 mismatch')
        require(original == rebuilt, f'{name}: full-image byte discrepancy')
        counts = {status: sum(s['length'] for s in image['sections'] if s['status'] == status) for status in STATUSES}
        progress.append({'image': name, 'sha256': image['sha256'], 'bytes_total': image['length'],
                         'statuses': {s: {'bytes': counts[s], 'percent': round(100 * counts[s] / image['length'], 4)} for s in STATUSES}})
    return progress


def progress_markdown(progress):
    rows = ['<!-- Generated only after successful verify.py; mutually exclusive statuses. -->',
            '| Image | Bytes total | RAW | DECODED | STRUCTURED | UNDERSTOOD |',
            '|---|---:|---:|---:|---:|---:|']
    for image in progress:
        columns = [f'{image["statuses"][s]["bytes"]} ({image["statuses"][s]["percent"]:.2f}%)' for s in STATUSES]
        rows.append(f'| {image["image"]} | {image["bytes_total"]} | ' + ' | '.join(columns) + ' |')
    return '\n'.join(rows) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--images', type=Path, required=True, help='directory of original historical binaries')
    parser.add_argument('--manifest', type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument('--write-progress', action='store_true', help='update durable progress report after all checks pass')
    args = parser.parse_args()
    try:
        progress = verify(args.manifest, args.images)
        report = progress_markdown(progress)
        if args.write_progress:
            (args.manifest.parent / 'progress.json').write_text(json.dumps(progress, indent=2) + '\n')
            (args.manifest.parent / 'progress.md').write_text(report)
        print(report, end='')
        print('VERIFIED: all section hashes, full-image hashes, exact bytes, partitions, and source/runtime mappings')
    except (VerificationError, OSError, ValueError, KeyError, IndexError) as error:
        print(f'VERIFICATION FAILED: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
