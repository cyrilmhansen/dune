#!/usr/bin/env python3
"""Scoped pass-6 contract checks against corrected witnesses / bounded packets.

No capture, procedure discovery, or new packet inference is performed here.
"""
import argparse
import json
from pathlib import Path

from check_minimal_pass_2 import at, pair, require, word
from check_minimal_pass_3 import gather
from check_minimal_pass_5 import nonstack_writes, packet_local
from procedure_evidence_packet import build, verify_return

ROOT = Path(__file__).resolve().parents[2]
PACKETS = {'PLI.COM+1376': (0, ()), 'PLI1.OVL+7C1B': (5, (0, 3)),
           'PLI1.OVL+7B7A': (0, ()), 'PLI1.OVL+7BBF': (0, ())}
DIRECT = ('PLI.COM+0817', 'PLI.COM+12D9', 'PLI.COM+15DA', 'PLI.COM+15E3',
          'PLI.COM+15F9', 'PLI.COM+1627', 'PLI1.OVL+7A63', 'PLI1.OVL+7AA9',
          'PLI1.OVL+7AD5', 'PLI1.OVL+7B2E', 'PLI1.OVL+7B64', 'PLI1.OVL+7BA2')


def read(ws, offset):
    return at(ws, offset)[0]['reads'][0]['value']


def nested(record, w):
    return record['nested_returns'].get(w['step_index'],
           record['nested_returns'].get(str(w['step_index'])))


def validate_direct(r):
    verify_return(r['call'], r['ret'], r['relation'])
    key = r['entry_key']; ws = r['own_witnesses']
    inp, out = r['entry']['before'], r['ret']['after']
    writes = nonstack_writes(ws)
    if key == 'PLI.COM+0817':
        c = inp['c']; expected = c & 0x5F if c > 0x5F else c
        require(out['a'] == expected and writes == [(0x208F, c)], 'Conditional mask/write mismatch')
        require(pair(out, 'h', 'l') == 0x208F and all(out[n] == inp[n] for n in 'bcde'), 'Mask preservation mismatch')
        require(at(ws, 0x0821)[0]['control']['taken'] == (c <= 0x5F), '5F comparison polarity mismatch')
        return {'input': c, 'returned': expected}
    if key == 'PLI.COM+12D9':
        raw = nested(r, at(ws, 0x12D9)[0])['ret']['after']['a']
        require(out['c'] == raw and out['a'] == (raw & 0x5F if raw > 0x5F else raw), 'Reader adapter mismatch')
        require(not writes, 'Adapter own memory writes')
        return {'raw': raw, 'returned': out['a']}
    if key in ('PLI.COM+15DA', 'PLI.COM+15E3', 'PLI.COM+15F9'):
        effects = ws if key != 'PLI.COM+15F9' else [w for n in r['nested_returns'].values() for w in n['memory_witnesses']]
        x = next(q['value'] for w in effects for q in w['reads'] if q['address'] == 0x20C1)
        if key.endswith('+15DA'):
            expected = 255 if 0x30 <= x <= 0x39 else 0
        elif key.endswith('+15E3'):
            expected = 1 if 0x41 <= x <= 0x5A else 255 if x == 0x3F else 0
        else:
            require(not 0x30 <= x <= 0x39, 'Unobserved range30..39 return arm outside pass-6 scope')
            expected = (1 if 0x41 <= x <= 0x5A or x == 0x3F
                        else 255 if x == 0x5F else 0)
        require(out['a'] == expected, 'Context predicate mismatch')
        require(all(out[n] == inp[n] for n in 'bcdehl') and not writes, 'Predicate preservation mismatch')
        return {'context': x, 'returned': expected}
    if key == 'PLI.COM+1627':
        width = read(ws, 0x162C); x = read(ws, 0x1639); old_sum = read(ws, 0x1649)
        expected = [(0x20C6 + width, x), (0x20C5, (width+1) % 256), (0x1C58, (old_sum+x) & 15)]
        require(width <= 127 and writes == expected, 'Prefix append/accumulator mismatch')
        require((out['a'], pair(out, 'b', 'c'), pair(out, 'h', 'l')) == (expected[-1][1], 0x20C5, 0x1C58) and all(out[n] == inp[n] for n in 'de'), 'Append registers mismatch')
        return {'width_before': width, 'appended': x, 'accumulator_after': out['a']}
    if key == 'PLI1.OVL+7B64':
        t = at(ws, 0x7B71)[0]['reads'][0]; c = inp['c']
        require(t['address'] == 0x1B4B+c and out['a'] == (t['value'] >> 3) & 7, 'Packed bits3..5 mismatch')
        require(writes == [(0xAE47, c)] and pair(out, 'b', 'c') == 0x1B4B and pair(out, 'h', 'l') == t['address'] and all(out[n] == inp[n] for n in 'de'), 'Packed transform state mismatch')
        require(not out['flags']['carry'], 'Packed transform final carry mismatch')
        return {'input': c, 'table_address': t['address'], 'table_byte': t['value'], 'returned': out['a']}
    if key == 'PLI1.OVL+7A63':
        call = at(ws, 0x7A6B)[0]; mapped = nested(r, call)['ret']['after']['a']
        q = at(ws, 0x7A77)[0]['reads'][0]
        require(q['address'] == 0x1B4B+mapped and out['a'] == q['value'] & 7 and writes == [(0xAE37, inp['c'])], 'Low3 attribute lookup mismatch')
        require(all(out[n] == inp[n] for n in 'de') and not out['flags']['carry'], 'Low3 attribute preservation mismatch')
        return {'position': inp['c'], 'mapped': mapped, 'attribute_byte': q['value'], 'returned': out['a']}
    if key in ('PLI1.OVL+7AD5', 'PLI1.OVL+7B2E', 'PLI1.OVL+7AA9'):
        start = int(key.split('+')[1], 16); jread = at(ws, start+13 if key.endswith('+7AA9') else start+15)[0]['reads'][0]
        require(jread['address'] == 0xAA1F+inp['c'], 'Position-map address mismatch')
        j = jread['value']; table = 0xAAB4 if key.endswith('+7AD5') else 0xAD08
        if key.endswith('+7AA9'):
            q = at(ws, 0x7ABD)[0]['reads'][0]
            require(q['address'] == table+j and out['a'] == q['value'] and writes == [(0xAE3A, inp['c'])], 'Auxiliary read mismatch')
        else:
            pos, value = (0xAE3C, 0xAE3D) if key.endswith('+7AD5') else (0xAE43, 0xAE44)
            require(writes == [(value, inp['e']), (pos, inp['c']), (table+j, inp['e'])] and out['a'] == inp['e'], 'Mapped table publication mismatch')
        require(pair(out, 'b', 'c') == j and pair(out, 'h', 'l') == table+j and all(out[n] == inp[n] for n in 'de'), 'Mapped helper registers mismatch')
        require(not out['flags']['carry'] and all(out['flags'][f] == inp['flags'][f] for f in ('sign', 'zero', 'parity', 'auxiliary_carry')), 'Mapped helper flag preservation mismatch')
        return {'position': inp['c'], 'index': j, 'address': table+j, 'value': out['a']}
    require(key == 'PLI1.OVL+7BA2', 'Unknown direct helper')
    old = word(at(ws, 0x7BAA)[0]); c = inp['c']; call = at(ws, 0x7BAE)[0]
    child = nested(r, call); j = read(child['memory_witnesses'], 0x7AE4)
    child_writes = nonstack_writes(child['memory_witnesses'])
    fresh = at(ws, 0x7BBA)[0]['reads'][0]
    require(child_writes == [(0xAE3D, old & 255), (0xAE3C, c), (0xAAB4+j, old & 255)], 'Old cached mapped-slot publication mismatch')
    require(fresh['address'] == 0xAA1F+c and writes == [(0xAE4A, c), (0xAE33, fresh['value'])], 'Fresh map/cache publication mismatch')
    require((out['a'], pair(out, 'b', 'c'), pair(out, 'h', 'l'), pair(out, 'd', 'e')) == (fresh['value'], 0xAA1F, 0xAA1F+c, old), 'Recycle registers mismatch')
    return {'position': c, 'old_cached': old & 255, 'written_slot': 0xAAB4+j, 'new_cached': fresh['value'], 'neighbor_read': old >> 8}


def call_states(p, c):
    return (p['steps'][str(c['pre_call_state_step'])]['before'],
            p['steps'][str(c['post_return_state_step'])]['after'])


def validate_member(p, iv):
    ws = packet_local(p, iv); key = p['entry']; out = ws[-1]['after']
    calls = [p['calls'][str(s)] for s in iv['nested_calls']]
    if key == 'PLI1.OVL+7B7A':
        cursor = ws[0]['before']['c']; balance = 1; changes = []
        updates = at(ws, 0x7B8F); branches = at(ws, 0x7B94)
        for c, update, branch in zip(calls, updates, branches, strict=True):
            pre, post = call_states(p, c)
            require(pre['c'] == cursor, 'Reverse scan cursor argument mismatch')
            balance = (balance+post['a']-1) % 256
            require(update['writes'][0]['new_value'] == balance and branch['control']['taken'] == (balance == 0), 'Reverse balance/polarity mismatch')
            changes.append({'cursor': cursor, 'attribute': post['a'], 'balance': balance})
            if balance: cursor = (cursor-1) % 256
        require(balance == 0 and out['a'] == cursor and pair(out, 'b', 'c') == 0 and pair(out, 'h', 'l') == 0xAE49 and all(out[n] == ws[0]['before'][n] for n in 'de'), 'Reverse stopping state mismatch')
        return {'input': ws[0]['before']['c'], 'returned': cursor, 'iterations': changes}
    if key == 'PLI1.OVL+7C1B':
        f = iv['F']; mapped = call_states(p, calls[0])[1]['a']
        children = [{'callsite': c['callsite'], 'child': c['recursive_child_invocation'], 'cursor': call_states(p,c)[0]['c'], 'returned': call_states(p,c)[1]['a']} for c in calls if c['target'] == key]
        require(read(ws, 0x7C24) == ws[0]['before']['c'] and at(ws, 0x7C2C)[0]['writes'][0]['address'] == f+3, 'Recursive frame position/mapped distinction mismatch')
        if mapped == 10:
            require(out['a'] == call_states(p, next(c for c in calls if c['callsite'].endswith('+7C37')))[1]['a'] and not children, '0A delegated result mismatch')
        elif mapped == 23:
            require(len(children) == 1 and children[0]['cursor'] == (ws[0]['before']['c']-1) % 256 and out['a'] == children[0]['returned'], '17 preceding-child/result mismatch')
            writer = next(c for c in calls if c['callsite'].endswith('+7CF5'))
            require(call_states(p,writer)[0]['c'] == ws[0]['before']['c'] and call_states(p,writer)[0]['e'] == out['a'], '17 original-position auxiliary publication mismatch')
        else:
            cached = call_states(p, next(c for c in calls if c['callsite'].endswith('+7D06')))[1]['a']
            count = call_states(p, next(c for c in calls if c['callsite'].endswith('+7D13')))[1]['a']
            require(len(children) == count and len(at(ws, 0x7D46)) == count and out['a'] == cached, 'Default child count/cached result mismatch')
            skips = [c for c in calls if c['callsite'].endswith('+7D3A')]
            cursor = ws[0]['before']['c']
            for child, skip in zip(children, skips, strict=True):
                require(child['cursor'] == (cursor-1) % 256 and call_states(p,skip)[0]['c'] == child['cursor'], 'Recursive child/skip ordering mismatch')
                cursor = call_states(p,skip)[1]['a']
            require(out['flags']['zero'] and not out['flags']['carry'], 'Default final CMP flags mismatch')
        slots = {q['address']-f:q['new_value'] for w in ws for q in w['writes'] if f <= q['address'] < f+5}
        require(pair(out,'h','l') == slots[3]+256*slots[4] and not out['flags']['carry'], 'Recursive final POP/flag result mismatch')
        return {'input': ws[0]['before']['c'], 'mapped': mapped, 'returned': out['a'], 'children': children, 'final_slots': slots}
    if key == 'PLI1.OVL+7BBF':
        counter = 15; comparisons = at(ws, 0x7C02)
        for w in comparisons:
            n = ws.index(w); saved = at(ws[:n], 0x7BD8)[-1]['after']['a']
            difference = at(ws[:n], 0x7BFA)[-1]['after']['a']
            # Saved stack byte is checked concretely; opaque calls do not gain
            # a general preservation contract from this observation.
            restored = at(ws[:n], 0x7BFE)[-1]['after']['b']
            require(restored == saved == (255 if counter else 0), 'Opaque saved predicate byte mismatch')
            stop = counter == 0 or difference != 0
            require(w['control']['taken'] == stop, 'Packed loop polarity mismatch')
            if not stop: counter -= 1
        require(out['a'] == counter, 'Packed counter return mismatch')
        return {'input': ws[0]['before']['c'], 'returned': counter, 'comparisons': len(comparisons), 'opaque_helpers': ['+7A79', '+82E1', '+82BB', '+82C9']}
    require(key == 'PLI.COM+1376', 'Unknown packet target')
    context_entry = read(ws, 0x13AD); prefix = []; reads = []; mem = {}
    for w in ws:
        mem.update((q['address'],q['new_value']) for q in w['writes'])
    for c in calls:
        pre, post = call_states(p,c)
        if c['target'] == 'PLI.COM+1627':
            effects = c['callee_memory_effects']['guest_instruction_accesses']
            values = [(q['address'],q['new_value']) for e in effects for q in e['writes'] if 0x20C6 <= q['address'] <= 0x2145]
            require(len(values) == 1 and values[0][0] == 0x20C6+len(prefix), 'Acquired prefix address/count mismatch')
            prefix.append(values[0][1])
        if c['target'] in ('PLI.COM+12AE', 'PLI.COM+12D9'):
            reads.append({'callsite':c['callsite'],'returned':post['a']})
        if c['target'] == 'PLI.COM+15F9':
            branch = next(w for w in ws if w['step_index'] > c['post_return_state_step'] and w['origin']['offset'] == 0x145F)
            require(branch['control']['taken'] == bool(post['a'] & 1), 'Acquisition complement polarity mismatch')
    require(mem[0x2087] == mem[0x2088] == 0 and mem[0x20C3] in (1,5,10), 'Acquisition output/reset mismatch')
    selector = mem[0x20C3]; ret = ws[-1]['origin']['offset']
    require(ret == (0x14B5 if selector == 1 else 0x15AB if selector == 5 else 0x15D5), 'Acquisition result path mismatch')
    require(out['a'] == (0 if selector == 1 else mem[0x20C1] if selector == 5 else 10), 'Acquisition A versus context mismatch')
    require(len(prefix) > 0 and mem[0x20C1] == (reads[-1]['returned'] if selector == 5 else (reads[-1]['returned'] & 0x5F if reads[-1]['returned'] > 0x5F else reads[-1]['returned'])), 'Retained following byte mismatch')
    return {'caller':iv['caller'],'context_entry':context_entry,'selector':selector,'width':len(prefix),'prefix':prefix,'following_context':mem[0x20C1],'returned_A':out['a'],'reader_calls':reads}


def collect(capture, images):
    cat = {p['id']:p for p in json.loads((ROOT/'research/annotated-assembly/procedures.json').read_text())['procedures']}
    bounds = {k:(cat[k]['start_offset'],cat[k]['end_offset']) for k in DIRECT}
    direct = gather(capture, bounds, include_nested_returns=True)
    packets = {k:build(capture,images,k,frame,slots) for k,(frame,slots) in PACKETS.items()}
    regions = []
    for k in (*DIRECT,*PACKETS):
        members = ([dict(validate_direct(r),call_step=r['call']['step_index']) for r in direct[k]] if k in DIRECT else
                   [dict(validate_member(packets[k],iv),call_step=iv['call_step'],invocation_class=iv['class']) for iv in packets[k]['invocations']])
        regions.append({'entry':k,'invocations_checked':len(members),'members':members})
    return regions,direct,packets


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',type=Path,default=ROOT/'_build/minimal-baseline/capture')
    parser.add_argument('--images',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args(); result,_,_ = collect(args.capture,args.images)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print('PASS6:',sum(r['invocations_checked'] for r in result),'correlated invocations checked')
