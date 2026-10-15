"""Bounded declaration/operand provenance from concrete instruction journals.

Step numbers select published witnesses, never host compiler behavior. This is
an evidence checker, not a symbol resolver or a PL/I type implementation.
"""
import bisect
import hashlib
import json
from pathlib import Path


def derive(directory):
    directory = Path(directory)
    steps, writers, checkpoints = {}, {}, {}
    source = (directory / 'source.bin').read_bytes()
    identity = json.loads((directory / 'identity.json').read_text())

    def need(ok, message):
        if not ok:
            raise AssertionError('Pass110: ' + message)

    def remember(address, step, value, owner):
        writers.setdefault(address, []).append((step, value, owner))

    with (directory / 'events.jsonl').open() as stream:
        for line in stream:
            q = json.loads(line)
            if q['kind'] == 'record_read':
                for i, v in enumerate(bytes.fromhex(q['data'])):
                    remember(q['dma'] + i, q['step'], v, q)
            elif q['kind'] == 'checkpoint':
                checkpoints[q['step']] = q
            elif q['kind'] == 'step' and q['step'] <= 550000:
                steps[q['step']] = q
                for kind, address, value in q['accesses']:
                    if kind == 'W':
                        remember(address, q['step'], value, None)
    need(all(i in steps for i in range(550000)), 'complete bounded original instruction journal')
    need(hashlib.sha256(source).hexdigest() == identity['source_sha256'], 'source identity')
    edges = []

    def last(address, step):
        ws = writers.get(address, [])
        i = bisect.bisect_left(ws, (step,)) - 1
        need(i >= 0, 'known last writer for ' + hex(address))
        return ws[i]

    def read(step, address, writer=None):
        q = steps[step]
        values = [v for k, a, v in q['accesses'] if k == 'R' and a == address]
        need(len(values) == 1, 'one owned read')
        w = last(address, step)
        need(w[1] == values[0], 'last-writer value agrees')
        if writer is not None:
            need(w[0] == writer, 'no intervening writer')
        edges.append(dict(read_step=step, address=address, writer_step=w[0], value=w[1]))
        return w

    def instruction(step, name):
        need(steps[step]['instruction'] == name, 'instruction ' + str(step))

    def writes(step, expected):
        need([a[1:] for a in steps[step]['accesses'] if a[0] == 'W'] == expected,
             'ordered publication ' + str(step))

    def load_before_store(step, address):
        # This resident source adapter transfers A across only a RET.
        for j in reversed(range(step - 4, step)):
            if ['R', address, steps[step]['before']['a']] in steps[j]['accesses']:
                need(all(steps[k]['instruction'] == 'RET' for k in range(j + 1, step)),
                     'source adapter A ownership across return')
                return j
        raise AssertionError('Pass110: missing resident source read')

    def file_origin(address, before):
        w = last(address, before)
        store = w[0]
        need(w[2] is None and steps[store]['image'] == 'PLI.COM' and
             steps[store]['offset'] == 0xe3d, 'actual source line-copy owner')
        instruction(store - 1, 'LDA 20ABH')
        ab = read(store - 1, 0x20ab)[0]
        instruction(ab, 'MOV M,C')
        instruction(ab - 3, 'MOV C,L')
        instruction(ab - 4, 'LHLD 20A9H')
        need(steps[ab - 3]['after']['c'] == w[1], 'paired transfer reaches C')
        a9 = read(ab - 4, 0x20a9)[0]
        instruction(a9, 'STA 20A9H')
        a9load = load_before_store(a9, 0x209a)
        a = read(a9load, 0x209a)[0]
        instruction(a, 'STA 209AH')
        aload = load_before_store(a, 0x2098)
        first = read(aload, 0x2098)[0]
        instruction(first, 'STA 2098H')
        glyph = first - 2
        instruction(glyph, 'MOV A,M')
        instruction(first - 1, 'RET')
        access = steps[glyph]['accesses']
        need(len(access) == 1 and access[0][0] == 'R', 'actual source address')
        raw_address = access[0][1]
        owner = read(glyph, raw_address)
        record = owner[2]
        need(record is not None and record['file'] == 'FIZZBUZ.PLI', 'source record owns byte')
        offset = record['record'] * 128 + raw_address - record['dma']
        need(source[offset] == w[1] == steps[glyph]['after']['a'], 'source-copy byte identity')
        return dict(source_offset=offset, value=w[1], record_read_step=record['step'],
                    raw_read_step=glyph, line_address=address, line_write_step=store)

    def prefix_origin(write):
        q = steps[write]
        instruction(write - 1, 'LDA 20C1H')
        context = read(write - 1, 0x20c1)[0]
        candidates = [steps[i] for i in range(context - 25, context)]
        raw = next(r for r in candidates if r['instruction'] == 'MOV A,M' and
                   any(k == 'R' and 0x1e8e <= a <= 0x1f0d for k, a, v in r['accesses']))
        raw_step = raw['step']
        scratch = next(r for r in candidates if r['instruction'] == 'MOV M,C' and
                       any(k == 'W' and a == 0x208f for k, a, v in r['accesses']))
        need(scratch['before']['c'] == raw['after']['a'], 'normalizer input is lexical byte')
        masks = [r for r in candidates if r['instruction'] == 'ANI 5FH']
        if masks:
            mask = masks[-1]
            read(mask['step'] - 1, 0x208f, scratch['step'])
            need(mask['after']['a'] == (raw['after']['a'] & 0x5f) == q['before']['a'],
                 'observed lowercase normalization')
        else:
            fresh = next(r for r in reversed(candidates) if r['instruction'] == 'LDA 208FH')
            read(fresh['step'], 0x208f, scratch['step'])
            need(raw['after']['a'] <= 0x5f and fresh['after']['a'] == q['before']['a'],
                 'observed unchanged digit normalization')
        need(steps[context]['before']['a'] == q['before']['a'], 'normalized context publication')
        origin = file_origin(raw['accesses'][0][1], raw_step)
        return dict(prefix_write_step=write, normalized=q['before']['a'], **origin)

    # Source ownership, not a character/value match to a presumed symbol record.
    dcl = [prefix_origin(i) for i in [95486, 95570, 95654]]
    identifier = prefix_origin(96824)
    fixed = [prefix_origin(i) for i in [98003, 98087, 98171, 98255, 98339]]
    need([q['source_offset'] for q in dcl] == [39, 40, 41], 'actual DCL spelling')
    need(identifier['source_offset'] == 43 and source[43:44] == b'i', 'declaration identifier span')
    need([q['source_offset'] for q in fixed] == list(range(45, 50)), 'actual FIXED spelling')
    need(source[39:51] == b'dcl i fixed;', 'bounded declaration source')
    read(97735, 0x20c5, 96830); writes(97736, [[0x6fe9, 1]])
    instruction(97844, 'LDAX B'); read(97844, 0x20c6, 96824)
    writes(97845, [[0x6ff2, 0x49]])
    need(steps[97844]['after']['a'] == steps[97845]['before']['a'], 'identifier reaches record+10')
    # The keyword matcher consumes all five current prefix bytes against one
    # immutable keyword record, then obtains that record's token.
    keyword = []
    for j, step in enumerate([98822, 98852, 98882, 98912, 98942]):
        p = 4 - j
        read(step, 0x20c6 + p, fixed[p]['prefix_write_step'])
        instruction(step + 1, 'SUB M')
        need(steps[step + 1]['after']['a'] == 0, 'keyword character equality')
        read(step + 1, 0x63ac + p)
        keyword.append(step)
    read(99006, 0x63b1)
    writes(99007, [[0x20c3, 0xa2]])
    read(99371, 0x20c3, 99007)
    need(steps[99372]['after']['flags']['zero'], 'declaration dispatch consumes matched token')
    need(steps[99379]['after']['a'] == 21, 'keyword ordinal plus historical table bias')
    writes(99398, [[0x6890, 84]])
    read(99467, 0x22ca)
    need(steps[99467]['after']['a'] == 0x14, 'selected immutable qualifier bits')
    read(99469, 0x6fea, 97741)
    writes(99473, [[0x6fea, 0x14]])
    read(100310, 0x6fea, 99473)
    writes(100313, [[0xffdc, 0x14]])
    instruction(100347, 'MVI A,11H'); read(100350, 0xffdc, 100313)
    writes(100351, [[0xffdc, 0x15]])
    instruction(100358, 'MVI A,14H'); read(100361, 0xffdc, 100351)
    writes(100362, [[0xffdc, 0x15]])
    instruction(100392, 'MVI M,0FH'); writes(100392, [[0xffde, 15]])
    read(100494, 0xffdc, 100362); writes(100496, [[0x6fea, 0x15]])
    read(100511, 0xffde, 100392); writes(100513, [[0x6fec, 15]])
    read(100520, 0xffdf, 100334); writes(100522, [[0x6fed, 0]])

    # Follow all actual relocations, including the name, before the expression
    # lookup. Addresses are immutable capture witnesses, not a runtime classifier.
    relocations = []
    for delta, middle_copy, final_read in [
        (2, 288884, 389340),
        (4, 288896, 389417),
        (5, 288902, 389422),
        (10, 288932, 388425),
    ]:
        # Locate copy steps from their real address and predecessor load rather
        # than treating relocation spacing as a semantic rule.
        original = 0x6fe8 + delta
        initial_writer = {2:100496, 4:100513, 5:100522, 10:97845}[delta]
        first = next(q for q in steps.values() if 214000 < q['step'] < 215000 and
                     ['W', 0xfbf3 + delta, last(original, 214000)[1]] in q['accesses'])
        first_copy = first['step']
        read(first_copy - 1, original, initial_writer)
        read(middle_copy - 1, 0xfbf3 + delta, first_copy)
        writes(middle_copy, [[0x6bc0 + delta, last(original, 214000)[1]]])
        final = next(q for q in steps.values() if 289900 < q['step'] < 290300 and
                     ['W', 0xfbf3 + delta, last(original, 214000)[1]] in q['accesses'])
        final_copy = final['step']
        read(final_copy - 1, 0x6bc0 + delta, middle_copy)
        read(final_read, 0xfbf3 + delta, final_copy)
        relocations.append(dict(record_offset=delta, initial_writer=initial_writer,
                                copy_steps=[first_copy, middle_copy, final_copy], read_step=final_read))
    # Selected expression identifier is independently sourced before name compare.
    expression_prefix = last(0x20c6, 388424)[0]
    expr = prefix_origin(expression_prefix)
    need(expr['source_offset'] == 89, 'actual i in MOD, not loop or declaration')
    read(388424, 0x20c6, expression_prefix)
    need(steps[388425]['after']['flags']['zero'], 'actual selected name equality')
    read(388479, 0xa863)
    need(steps[388479]['after']['h'] == 0xfb and steps[388479]['after']['l'] == 0xf3,
         'resolved record pointer reaches context through actual XCHG')
    instruction(388480, 'XCHG'); writes(388482, [[0xa66e, 0xf3]]); writes(388484, [[0xa66f, 0xfb]])
    read(388897, 0xa66e, 388482); read(388899, 0xa66f, 388484)
    instruction(388900, 'XCHG'); writes(388901, [[0xa863, 0xf3], [0xa864, 0xfb]])
    read(388903, 0xa66e, 388482); read(388905, 0xa66f, 388484)
    writes(388907, [[0xa75a, 0xf3], [0xa75b, 0xfb]])
    read(389280, 0xa75a, 388907); read(389280, 0xa75b, 388907)
    writes(389281, [[0xa863, 0xf3], [0xa864, 0xfb]])
    read(389337, 0xa863, 389281); read(389337, 0xa864, 389281)
    read(389340, 0xfbf5)
    read(389347, 0xa75f, 389342); writes(389348, [[0xa628, 0x15]])
    writes(389418, [[0xa62b, 15]]); writes(389423, [[0xa62e, 0]])
    # There is an intervening carrier publication and remapping. Follow it,
    # rather than claiming A628 survives unchanged until conversion.
    read(390479, 0xa628, 389348)
    read(390409, 0xa62b, 389418)
    read(390410, 0xa642, 319767)
    read(390418, 0xa64e, 390416); read(390419, 0xa64f, 390414)
    read(390421, 0xa64f, 390414)
    need(steps[390421]['after']['a'] == 15, 'selected cap preserves declaration precision')
    writes(390427, [[0xa62b, 15]])
    read(390502, 0xa62b, 390427); read(390525, 0xa62e, 389423)
    for entry, store, scratch, scratch_write in [(390479,390496,0xae42,390484),
                                                (390502,390519,0xae44,390507),
                                                (390525,390542,0xae46,390530)]:
        need(steps[entry]['after']['e'] == steps[scratch_write]['before']['e'],
             'fresh attribute reaches canonical publisher E')
        need(all(steps[i]['before']['e'] == steps[i]['after']['e'] == steps[entry]['after']['e']
                 for i in range(entry+1, scratch_write)), 'no intervening publisher E mutation')
        read(store-1, scratch, scratch_write)
        need(steps[store]['before']['a'] == steps[entry]['after']['e'],
             'canonical publisher stores freshly read attribute')
    read(393393, 0xac77, 390496); writes(393395, [[0xa629, 0x15]])
    read(393409, 0xad0c, 390519); writes(393411, [[0xa62c, 15]])
    read(393425, 0xada1, 390542); writes(393427, [[0xa62f, 0]])
    # A62B/E are copied, adjusted and recomputed, not simply retained.
    read(393595, 0xa62c, 393411); read(393597, 0xa62f, 393427)
    read(393643, 0xa665, 393596); read(393645, 0xa666, 393598)
    instruction(393593, 'MVI M,15H')
    need(steps[393713]['accesses'] == [['R', 0x42de, 7]], 'actual decimal-width lookup result')
    need(steps[393766]['after']['a'] == max(15, 7), 'observed maximum selects 15')
    need(steps[393769]['after']['a'] == 15, 'zero-field addition')
    read(393776, 0xa642, 319767)
    need(steps[393787]['after']['a'] == min(15, 15), 'observed cap')
    writes(393789, [[0xa62b, 15]])

    replays = []
    for entry_step, exit_step in [(100276, 100600), (393452, 393793), (463314, 463655), (530112, 530453)]:
        start, end = checkpoints[entry_step], checkpoints[exit_step]
        replay = json.loads((directory / (start['ram'] + '-replay.json')).read_text())
        actual = [a for i in range(entry_step, exit_step) for a in steps[i]['accesses']]
        need(replay['state'] == end['state'], 'separate replay complete CPU/flags')
        need((directory / (start['ram'] + '-replay.ram')).read_bytes() ==
             (directory / end['ram']).read_bytes(), 'separate replay full 64 KiB RAM')
        need(replay['writes'] == [a[1:] for a in actual if a[0] == 'W'], 'complete ordered writes')
        need(json.loads((directory / (start['ram'] + '-accesses.json')).read_text()) == actual,
             'complete ordered data reads and writes')
        need(replay['instructions'] == exit_step - entry_step, 'owned instruction window')
        need(end['state']['sp'] == start['state']['sp'] + 2, 'original hardware RET geometry')
        replays.append(dict(entry_step=entry_step, exit_step=exit_step,
                            image=start['image'], offset=start['offset'],
                            instructions=replay['instructions'],
                            ordered_reads=sum(a[0] == 'R' for a in actual),
                            ordered_writes=len(replay['writes']),
                            entry_RAM_sha256=start['RAM_sha256'], exit_RAM_sha256=end['RAM_sha256'],
                            continuation=end['state']['pc'], full_RAM_CPU_accesses_equal=True))
    discriminants = []
    for glyph, prefix_step, entry_step, end_step, record_read in [
        ('3', 460896, 463314, 463655, 459337),
        ('5', 527694, 530112, 530453, 526135),
    ]:
        origin = prefix_origin(prefix_step)
        source_start = source.index(('mod(i,' + glyph + ')').encode())
        need(origin['source_offset'] == source_start + 6, 'actual comparison literal source')
        name_compare = max(i for i, q in steps.items() if i < record_read and
                           q['instruction'] == 'CMP M' and ['R', 0xfbfd, 0x49] in q['accesses'])
        name_prefix = last(0x20c6, name_compare - 1)[0]
        name_origin = prefix_origin(name_prefix)
        need(name_origin['source_offset'] == source_start + 4, 'same actual MOD operand identifier')
        read(name_compare - 1, 0x20c6, name_prefix)
        read(name_compare, 0xfbfd, relocations[3]['copy_steps'][-1])
        need(steps[name_compare]['after']['flags']['zero'], 'comparison context resolves same declaration')
        read(record_read, 0xfbf7, relocations[1]['copy_steps'][-1])
        read(record_read + 5, 0xfbf8, relocations[2]['copy_steps'][-1])
        before = (directory / checkpoints[entry_step]['ram']).read_bytes()
        after = (directory / checkpoints[end_step]['ram']).read_bytes()
        need([before[a] for a in [0xa629,0xa62c,0xa62f]] == [21,15,0], 'retained variable tuple')
        need([before[a] for a in [0xa62a,0xa62d,0xa630]] == [2,1,0], 'one-digit literal tuple')
        need([after[a] for a in [0xa628,0xa62b,0xa62e]] == [21,15,0], 'fresh common context')
        lookup = steps[entry_step + 261]
        need(lookup['offset'] == 0x25ea and lookup['accesses'] == [['R',0x42dd,4]],
             'one-digit width lookup differs from two-digit lookup')
        discriminants.append(dict(literal=glyph, source=origin, identifier_source=name_origin,
                                  name_compare_step=name_compare, record_middle_read=record_read,
                                  context_entry=entry_step, context_exit=end_step,
                                  operand_tuple=[2,1,0], variable_tuple=[21,15,0],
                                  width_lookup=4, result_tuple=[21,15,0]))
    return dict(all_passed=True, identity=identity,
                capture_SHA256=hashlib.sha256((directory / 'events.jsonl').read_bytes()).hexdigest(),
                source=dict(declaration_span=[39,51], dcl=dcl, identifier=identifier, fixed=fixed,
                            expression_identifier=expr),
                declaration=dict(record=0x6fe8, name_offset=10, qualifier_bits=0x14,
                                 defaulted_tag=0x15, defaulted_middle_attribute=15, zero_field=0),
                record_relocations=relocations, last_writer_edges=edges, CPU_replays=replays,
                natural_discriminants=discriminants,
                metadata_law=dict(operand1=[21,15,0], operand2=[2,2,0],
                                  context=[21,15,0], decimal_width_lookup=7,
                                  middle_channel_calculation='min(default_cap_15, max(15,7)+0)=15'),
                semantic_status='PARTIAL: source ownership and declaration-to-context byte provenance proved; '
                                'general field encoding and MOD result publication not independently decoded',
                engine_limit='Original and separate window replay use the same Intel 8080 engine; not independent CPU engines')
