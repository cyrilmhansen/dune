#!/usr/bin/env python3
"""Pass-5 concrete contract checks; packet candidates use their joined interface.

Structural selection uses corrected hardware returns, never context ownership.
No compiler execution or new capture is performed.
"""
import argparse
import json
from collections import Counter
from pathlib import Path

from check_minimal_pass_2 import at, coord, pair, require, word
from check_minimal_pass_3 import gather
from procedure_evidence_packet import build, verify_return

ROOT = Path(__file__).resolve().parents[2]
BOUNDS = {'PLI0.OVL+1E0B': (0x1E0B, 0x1E2D), 'PLI1.OVL+784E': (0x784E, 0x7A15),
          'PLI1.OVL+4929': (0x4929, 0x4986), 'PLI1.OVL+8273': (0x8273, 0x82AC),
          'PLI1.OVL+7D53': (0x7D53, 0x7E46)}
PACKET_TARGETS = ('PLI1.OVL+784E', 'PLI1.OVL+4929', 'PLI1.OVL+7D53')


def own(record):
    return record['own_witnesses']


def nonstack_writes(ws):
    return [(q['address'], q['new_value']) for w in ws
            if w['disassembly'].split()[0] not in ('CALL', 'PUSH', 'XTHL') for q in w['writes']]


def validate_direct(record):
    key = record['entry_key']; ws = own(record)
    verify_return(record['call'], record['ret'], record['relation'])
    a, b = BOUNDS[key]
    require(all(w['origin']['image']['name'] == key.split('+')[0] and a <= w['origin']['offset'] < b for w in ws), 'Direct extent mismatch')
    if key == 'PLI0.OVL+1E0B':
        working = word(at(ws, 0x1E0B)[0]); count = at(ws, 0x1E0E)[0]['reads'][0]['value']
        call = at(ws, 0x1E15)[0]
        nested = record['nested_returns'].get(call['step_index'], record['nested_returns'].get(str(call['step_index'])))
        reads = {q['address']: q['value'] for w in nested['memory_witnesses'] for q in w['reads']}
        stage = reads[0x69C3] + 256 * reads[0x69C4]
        index = at(ws, 0x1E19)[0]['reads'][0]['value']
        next_pointer = (stage + count) % 65536
        expected = [(working, count), (0x6A0D + 2*index, next_pointer % 256),
                    (0x6A0E + 2*index, next_pointer // 256), (0x69C3, next_pointer % 256), (0x69C4, next_pointer // 256)]
        require(nonstack_writes(ws) == expected, 'Count-header/staging publication mismatch')
        out = record['ret']['after']
        require((out['a'], pair(out, 'b', 'c'), pair(out, 'd', 'e'), pair(out, 'h', 'l')) ==
                (next_pointer // 256, next_pointer, 0x6A0E+2*index, 0x69C4), 'Commit output registers mismatch')
        require(not out['flags']['carry'] and all(out['flags'][f] == nested['ret']['after']['flags'][f]
                for f in ('zero', 'sign', 'parity', 'auxiliary_carry')), 'Commit flags mismatch')
        return {'working': working, 'count': count, 'stage_before': stage, 'next': next_pointer, 'index': index}
    require(key == 'PLI1.OVL+8273', 'Unknown direct target')
    expected = [(0xAE33, 0)]
    for i in range(149):
        expected.extend([(0xAAB4+i, i+1), (0xAE33, i+1)])
    expected.extend([(a, 0) for a in (0xAA1A, 0xAA1B, 0xAA1C, 0xAE35, 0xAE34, 0xAE33)])
    require(nonstack_writes(ws) == expected, '149-byte initializer write order mismatch')
    out = record['ret']['after']; before = record['entry']['before']
    require((out['a'], pair(out, 'b', 'c'), pair(out, 'h', 'l')) == (0, 0xAAB4, 0xAA1C)
            and pair(out, 'd', 'e') == pair(before, 'd', 'e'), 'Initializer register mismatch')
    require(out['flags'] == at(ws, 0x827D)[-1]['after']['flags'], 'Initializer flags must retain final CMP')
    require(len(at(ws, 0x828E)) == 149 and at(ws, 0x827D)[-1]['reads'][0]['value'] == 149, 'Initializer guard mismatch')
    return {'table_start': 0xAAB4, 'writes': 149, 'last_value': 149}


def packet_local(packet, invocation):
    # Adapt only the already joined steps; do not independently re-mine witnesses.
    return [dict(packet['steps'][str(n)], step_index=n,
                 origin={'image': {'name': packet['entry'].split('+')[0]},
                         'offset': int(packet['steps'][str(n)]['coordinate'].split('+')[1], 16)},
                 disassembly=packet['instructions'][packet['steps'][str(n)]['coordinate']]['decoded'])
            for n in invocation['local_steps']]


def validate_packet_member(packet, invocation):
    key = packet['entry']; ws = packet_local(packet, invocation)
    out = packet['steps'][str(invocation['return_step'])]['after']
    if key == 'PLI1.OVL+4929':
        limit = pair(ws[0]['before'], 'b', 'c')
        require(at(ws, 0x492C)[0]['writes'][0]['new_value'] == limit // 256 and
                at(ws, 0x492E)[0]['writes'][0]['new_value'] == limit % 256, 'Saved link limit mismatch')
        indexes = [q['value'] for w in at(ws, 0x4939) for q in w['reads']]
        require(indexes == list(range(129)), '128-slot unsigned scan mismatch')
        for call in [packet['calls'][str(s)] for s in invocation['nested_calls']]:
            post = packet['steps'][str(call['post_return_state_step'])]['after']
            effects = call['callee_memory_effects']['guest_instruction_accesses']
            reads = {q['address']: q['value'] for e in effects for q in e['reads']}
            cursor = reads[0xA863] + 256 * reads[0xA864]
            require(post['flags']['carry'] == (cursor < limit), 'Word comparison borrow mismatch')
        for w in at(ws, 0x4965):
            # Independently locate paired reads and the subsequent duplicate link
            # reads/stores, retaining the old pointer address across XCHG/DCX.
            n = ws.index(w)
            lo, hi = ws[n-4]['reads'][0], ws[n-2]['reads'][0]
            require(hi['address'] == (lo['address']+1) % 65536, 'Offset8 link pair mismatch')
            next_pointer = lo['value'] + 256*hi['value']
            rereads = [x for x in ws[n+1:] if x['origin']['offset'] in (0x4974, 0x4976)][:2]
            require([x['reads'][0] for x in rereads] == [lo, hi], 'Old link address was not retained')
            stores = [x for x in ws[n+1:] if x['origin']['offset'] in (0x4978, 0x497A)][:2]
            index = next(x for x in ws[n+1:] if x['origin']['offset'] == 0x4968)['reads'][0]['value']
            require([(x['writes'][0]['address'], x['writes'][0]['new_value']) for x in stores] ==
                    [(0xA761+2*index, next_pointer % 256), (0xA762+2*index, next_pointer // 256)], 'Link slot publication mismatch')
        require((out['a'], pair(out, 'b', 'c'), pair(out, 'd', 'e'), pair(out, 'h', 'l')) ==
                (127, limit, 0xA864, 0xA922), 'Link sweep return mismatch')
        return {'limit': limit, 'slots': 128, 'repairs': len(at(ws, 0x4978))}
    if key == 'PLI1.OVL+784E':
        selector = at(ws, 0x7851)[0]['reads'][0]['value']
        first = at(ws, 0x785A)[0]['reads'][0]['value']; context = at(ws, 0x7866)[0]['reads'][0]['value']
        require(at(ws, 0x7872)[0]['control']['taken'] == (not (selector == 10 and first == 47 and context == 42)), 'Triple equality polarity mismatch')
        require(at(ws, 0x78B8)[0]['control']['taken'] == (selector in (1, 10)), 'ADI inequality polarity mismatch')
        for subtract, add, mask, k in [(0x78A6, 0x78A8, 0x78AA, 10), (0x78AF, 0x78B1, 0x78B3, 1)]:
            require(at(ws, subtract)[0]['after']['a'] == (selector-k) % 256, 'Wrapped SUI mismatch')
            require(at(ws, add)[0]['after']['flags']['carry'] == (selector != k)
                    and at(ws, mask)[0]['after']['a'] == (255 if selector != k else 0), 'Inequality mask mismatch')
        comparisons = at(ws, 0x79E3)
        for w in comparisons:
            n = ws.index(w); group = ws[n-26:n+1]
            j = at(group, 0x79C5)[0]['reads'][0]['value']
            input_read = at(group, 0x79DA)[0]['reads'][0]
            record_read = at(group, 0x79DB)[0]['reads'][0]
            require(input_read['address'] == 0x20C6 + ((j-1) % 256), 'Input reverse-index address mismatch')
            pointer = word(at(group, 0x79D5)[0])
            require(record_read['address'] == (pointer+j) % 65536, 'Descriptor compare address mismatch')
            require(w['control']['taken'] == (not (j != 0 and input_read['value'] == record_read['value'])), 'Reverse guard polarity mismatch')
            if j == 0:
                require(input_read['address'] == 0x21C5, 'Zero-index extra read was hidden')
        for call in [packet['calls'][str(s)] for s in invocation['nested_calls'] if packet['calls'][str(s)]['callsite'] == 'PLI1.OVL+79F4']:
            pre = packet['steps'][str(call['pre_call_state_step'])]['before']
            reads = {q['address']: q['value'] for e in call['callee_memory_effects']['guest_instruction_accesses'] for q in e['reads']}
            old = reads[0xAA16] + 256*reads[0xAA17]
            post = packet['steps'][str(call['post_return_state_step'])]['after']
            require(pair(post, 'h', 'l') == (old+pre['a']) % 65536, 'Descriptor advance mismatch')
        ret = packet['steps'][str(invocation['return_step'])]['coordinate']
        if ret.endswith('+78BB'):
            require(out['a'] == 127 and out['flags']['carry'], 'Passthrough return mask mismatch')
            require(not any(a == 0x20C3 for a,v in nonstack_writes(ws)), 'Passthrough must not publish selector')
        elif ret.endswith('+798B'):
            require(out['a'] == first and at(ws, 0x78C7)[0]['writes'][0]['new_value'] == first, 'Literal-byte publication mismatch')
        elif ret.endswith('+7A0B'):
            pointer = word(at(ws, 0x7A04)[0]); result = at(ws, 0x7A07)[0]['reads'][0]
            require(result['address'] == pointer and out['a'] == result['value'] and
                    at(ws, 0x7A08)[0]['writes'][0]['new_value'] == result['value'], 'Advanced-byte publication mismatch')
            require(pair(out, 'h', 'l') == pointer == pair(out, 'd', 'e') and pair(out, 'b', 'c') == 0
                    and out['flags'] == at(ws, 0x79FF)[-1]['after']['flags'], 'Match result/flag channels mismatch')
        else:
            require(ret.endswith('+7A14') and out['a'] == 0 and at(ws, 0x7A12)[0]['writes'][0]['new_value'] == 1,
                    'Exhaustion must store1 while returning A=0')
        return {'selector_after_prelude': selector, 'first_byte': first, 'context': context,
                'return': ret, 'A': out['a'], 'scan_advances': len(at(ws, 0x79F4)),
                'positive_equal_decrements': len(at(ws, 0x79E9))}
    require(key == 'PLI1.OVL+7D53', 'Unknown packet target')
    begin = at(ws, 0x7D59)[0]['reads'][0]['value']; end = at(ws, 0x7D56)[0]['reads'][0]['value']
    require(at(ws, 0x7D5A)[0]['control']['taken'] == (begin != end), 'Mapped empty-range polarity mismatch')
    if at(ws, 0x7D62):
        gate = at(ws, 0x7D5E)[0]['reads'][0]['value']
        require(at(ws, 0x7D62)[0]['control']['taken'] == (gate & 1 == 0), 'Mapped gate polarity mismatch')
    for w in at(ws, 0x7D8A):
        require(w['control']['taken'] == (w['before']['a'] == w['before']['c']), 'Saved decrement comparison mismatch')
    for call in [packet['calls'][str(s)] for s in invocation['nested_calls'] if packet['calls'][str(s)]['target'] == 'PLI1.OVL+7A4D']:
        argument = packet['steps'][str(call['pre_call_state_step'])]['before']['c']
        effects = call['callee_memory_effects']['guest_instruction_accesses']
        mapping = next(q for e in effects for q in e['reads'] if q['address'] == 0xAA1F+argument)
        result = next(q for e in effects for q in e['reads'] if q['address'] == 0xAAB4+mapping['value'])
        require(packet['steps'][str(call['post_return_state_step'])]['after']['a'] == result['value'], 'Current mapped table lookup mismatch')
    for w in at(ws, 0x7DBE):
        comparison = ws[ws.index(w)-1]
        require(w['control']['taken'] == (w['before']['a'] < comparison['reads'][0]['value']), 'Forward unsigned endpoint polarity mismatch')
    if at(ws, 0x7E42):
        require(at(ws, 0x7E42)[0]['writes'][0]['new_value'] == at(ws, 0x7E3F)[0]['reads'][0]['value'], 'End reset publication mismatch')
    emit_calls = [packet['calls'][str(s)] for s in invocation['nested_calls'] if packet['calls'][str(s)]['target'] == 'PLI.COM+0EF6']
    emitted = [packet['steps'][str(c['pre_call_state_step'])]['before']['c'] for c in emit_calls]
    return {'begin': begin, 'end': end, 'return': packet['steps'][str(invocation['return_step'])]['coordinate'],
            'emission_C_bytes': emitted, 'forward_iterations': len(at(ws, 0x7DC5))}


def extract(capture, images, packet_directory):
    packet_directory.mkdir(parents=True, exist_ok=True)
    packets = {}
    # Generate before interpreting; rendering is the primary dynamic interface.
    from procedure_evidence_packet import render
    for key in PACKET_TARGETS:
        p = build(capture, images, entry=key, frame_bytes=0, class_slots=())
        stem = key.replace('.OVL','')
        (packet_directory/(stem+'.json')).write_text(json.dumps(p,separators=(',',':'))+'\n')
        (packet_directory/(stem+'.md')).write_text(render(p))
        packets[key] = p
    direct = gather(capture, {k:BOUNDS[k] for k in BOUNDS if k not in PACKET_TARGETS}, include_nested_returns=True)
    return packets, direct


def summarize(packets, direct):
    result = []
    for key in BOUNDS:
        if key in packets:
            p = packets[key]; invocations = p['invocations']
            members = [{'call_step':i['call_step'], 'class':i['class'], **validate_packet_member(p,i)} for i in invocations]
            count = p['quality_checks']['local_instruction_occurrences']
            branches = [{'coordinate':k,'outcomes':v['outcomes']} for k,v in p['branches'].items()]
        else:
            records = direct[key];members = [{'call_step':r['call']['step_index'], **validate_direct(r)} for r in records]
            count = sum(len(own(r)) for r in records)
            branches = []
        result.append({'entry':key,'invocations_checked':len(members),'own_instruction_occurrences':count,
                       'members':members,'branches':branches})
    return result


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--images',type=Path,required=True)
    parser.add_argument('--capture',type=Path,default=ROOT/'_build/minimal-baseline/capture')
    parser.add_argument('--packets',type=Path,default=ROOT/'_build/minimal-pass-5/packets')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=summarize(*extract(args.capture,args.images,args.packets))
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print('Validated',sum(r['invocations_checked'] for r in result),'invocations;',sum(r['own_instruction_occurrences'] for r in result),'local occurrences')
