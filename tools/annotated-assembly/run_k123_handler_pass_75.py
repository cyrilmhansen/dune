#!/usr/bin/env python3
"""Focused FACTOR k123 capture and instruction-derived +2578 tail proof."""
import collections, hashlib, json, os, subprocess
from pathlib import Path

OUT = Path('_build/host-compiler-pass-75')
CAPTURE = OUT / 'capture'
REPORT = Path('research/host-compiler/pass-75')
IMAGES = '/home/john/pli/cpm/pli80/DISK1'
BASE = '2f40490236460fe07ca38be5ff19d7961d4c5677'

def load(path): return json.loads(Path(path).read_text())
def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def psw(state):
    return (128 if state['S'] else 0) | (64 if state['Z'] else 0) | (16 if state['AC'] else 0) | (4 if state['P'] else 0) | 2 | int(state['CY'])
def argv_state(prefix, state):
    values = dict(pc=state['pc'], sp=state['sp'], a=state['a'], bc=state['b']*256+state['c'], de=state['d']*256+state['e'], hl=state['h']*256+state['l'], psw=psw(state))
    return [part for key, value in values.items() for part in ('--'+prefix+key, str(value))]

def prove(images=IMAGES):
    CAPTURE.mkdir(parents=True, exist_ok=True)
    if not os.environ.get('RUNES_HOST_IMAGES'):
        subprocess.run(['dune', 'build', 'bin/k123_handler_capture.exe', 'bin/k123_tail_proof.exe'], check=True)
    subprocess.run(['_build/default/bin/k123_handler_capture.exe', '--images', str(images), '--output', str(CAPTURE)], check=True)
    boundaries = [json.loads(line) for line in (CAPTURE/'handler-boundaries.jsonl').read_text().splitlines()]
    rows = [json.loads(line) for line in (CAPTURE/'handler-steps.jsonl').read_text().splitlines()]
    frames = [f for f in load('research/host-compiler/pass-71/frames.json') if f['k'] == 123]
    handler_map = [h for h in load('research/host-compiler/pass-71/handler-map.json') if h['target'] == '256E']
    assert len(frames) == 2 and len(handler_map) == 1
    assert handler_map[0]['sources'] == {'FACTOR': 2} and handler_map[0]['software_RET_sites'] == ['259A']
    assert len(boundaries) == 6 and len(rows) > 6000
    cases = []
    for case in (1, 2):
        events = {q['boundary']: q for q in boundaries if q['case'] == case}
        assert set(events) == {'entry', 'tail', 'exit'}
        entry, tail, exit_ = (events[k] for k in ('entry', 'tail', 'exit'))
        frame = next(f for f in frames if f['entry_step'] < entry['step'] < f['return_step'])
        steps = [w for w in rows if w['case'] == case]
        assert steps and steps[0]['step'] == entry['step'] and steps[-1]['step'] == exit_['step']
        assert len(steps) == steps[-1]['step']-steps[0]['step']+1
        assert all(w['step'] == entry['step']+i for i,w in enumerate(steps))
        assert steps[0]['image'] == steps[-1]['image'] == 'PLI2.OVL'
        assert (steps[0]['offset'], steps[-1]['offset']) == (0x256e, 0x259a)
        assert (entry['state']['pc'], tail['state']['pc'], exit_['state']['pc']) == (0x476e, 0x4778, 0x42b4)
        assert frame['source'] == 'FACTOR' and frame['caller'] == '374B' and frame['handler'] == 0x476e
        assert frame['descriptor'] == 0x4357 and frame['k'] == 123 and frame['scan_calls'] == 0
        assert frame['predicate_tokens'] == [0xfb, 0xfc] and frame['software_return_site'] == '259A'
        assert len(frame['predicate_results']) == 1 and frame['predicate_results'][0]['callsite'] == '2085'
        assert frame['entry']['sp']-14 == entry['state']['sp'] == tail['state']['sp']
        assert exit_['state']['sp'] == entry['state']['sp']+2
        assert entry['transfer']['image'] == 'PLI2.OVL' and entry['transfer']['offset'] == 0x20b3
        assert entry['transfer']['bytes'] == 'E9' and entry['transfer']['step'] == entry['step']-1
        assert entry['transfer']['after']['pc'] == 0x476e and entry['transfer']['after']['sp'] == entry['state']['sp']
        writers = frame['software_last_writers']
        assert [w['offset'] for w in writers] == [0x20af, 0x20af]
        assert [w['value'] for w in writers] == [0xb4, 0x42] and writers[0]['step'] == writers[1]['step']
        ram = bytearray((CAPTURE/f'case-{case}-entry.ram').read_bytes())
        assert len(ram) == 65536 and ram[entry['state']['sp']:entry['state']['sp']+2] == b'\xb4\x42'
        assert sha(CAPTURE/f'case-{case}-entry.ram') == entry['RAM_sha256']
        assert sha(CAPTURE/f'case-{case}-tail.ram') == tail['RAM_sha256']
        assert sha(CAPTURE/f'case-{case}-exit.ram') == exit_['RAM_sha256']
        accesses, writes, reads = [], [], []
        for step in steps:
            for access in step['accesses']:
                addr, value = access['address'], access['value']
                assert 0 <= addr < 65536 and 0 <= value < 256
                record = [step['step'], step['image'], step['offset'], access['kind'], addr, value]
                accesses.append(record)
                if access['kind'] == 'read':
                    assert ram[addr] == value, (case, step['step'], addr)
                    reads.append(record)
                else:
                    assert access['kind'] == 'write'
                    ram[addr] = value
                    writes.append(record)
        assert bytes(ram) == (CAPTURE/f'case-{case}-exit.ram').read_bytes()
        assert entry['filesystem_sha256'] == tail['filesystem_sha256'] == exit_['filesystem_sha256']
        assert entry['DMA'] == tail['DMA'] == exit_['DMA'] and exit_['service_events'] == 0
        stack, graph = [], collections.Counter()
        for step in steps:
            if step['kind'] == 'call' and step['taken']:
                parent = stack[-1][1] if stack else 'k123'
                graph[(parent, step['image'], step['offset'], step['target'])] += 1
                stack.append((step['before']['pc']+3, step['target']))
            elif step['kind'] == 'return' and step['taken']:
                if stack:
                    assert step['after']['pc'] == stack[-1][0]
                    stack.pop()
                else:
                    assert step is steps[-1] and step['after']['pc'] == 0x42b4
        assert not stack
        direct = [[f'{offset:04X}', f'{target:04X}', count] for (parent, image, offset, target),count in sorted(graph.items(),key=lambda x:str(x[0])) if parent == 'k123']
        assert direct == [['256E','467B',1], ['2575','279E',1]]
        child_direct = [[f'{offset:04X}',f'{target:04X}',count] for (parent,image,offset,target),count in sorted(graph.items(),key=lambda x:str(x[0])) if parent == 0x467b]
        tail_steps = [w for w in steps if w['step'] >= tail['step']]
        assert tail_steps[0]['offset'] == 0x2578 and tail_steps[-1]['offset'] == 0x259a
        assert tail_steps[-1]['accesses'] == [{'kind':'read','address':entry['state']['sp'],'value':0xb4},{'kind':'read','address':entry['state']['sp']+1,'value':0x42}]
        proof_file = CAPTURE/f'case-{case}-tail-proof.json'
        command = ['_build/default/bin/k123_tail_proof.exe', '--ram', str(CAPTURE/f'case-{case}-tail.ram'), '--expected-ram', str(CAPTURE/f'case-{case}-exit.ram'), '--output', str(proof_file), *argv_state('', tail['state']), *argv_state('expected-', exit_['state'])]
        subprocess.run(command, check=True)
        proof = load(proof_file)
        assert proof['natural_passed'] and proof['all_passed'] and proof['synthetic_cases'] == 24
        address_counts = collections.Counter(w[4] for w in writes)
        cases.append(dict(source='FACTOR', gateway_id=frame['id'], parent_gateway_id=frame['parent'], gateway_depth=frame['depth'], gateway_entry_step=frame['entry_step'], gateway_caller=frame['caller'], original_hardware_continuation=frame['continuation'], gateway_input_C=frame['entry']['c'], canonical_index=frame['k'], descriptor_pointer=frame['descriptor'], handler_runtime=frame['handler'], predicate_tokens=frame['predicate_tokens'], predicate_results=frame['predicate_results'], scan_calls=frame['scan_calls'], handler_entry_step=entry['step'], handler_entry_state=entry['state'], handler_entry_RAM_sha256=entry['RAM_sha256'], handler_exit_step=exit_['step'], handler_exit_state=exit_['state'], handler_exit_RAM_sha256=exit_['RAM_sha256'], software_transfer=entry['transfer'], software_continuation_word=[0xb4,0x42], software_word_writers=writers, software_RET_site='259A', full_instruction_steps=len(steps), direct_calls=direct, child_247B_direct_calls=child_direct, total_hardware_calls=sum(graph.values()), complete_call_graph=[[str(parent),image,f'{offset:04X}',f'{target:04X}',n] for (parent,image,offset,target),n in sorted(graph.items(),key=lambda x:str(x[0]))], ordered_reads=len(reads), ordered_writes=len(writes), ordered_read_sha256=digest(reads), ordered_write_sha256=digest(writes), full_access_sha256=digest(accesses), repeated_write_addresses=sum(n>1 for n in address_counts.values()), ADxx_writes=[[f'{w[2]:04X}',f'{w[4]:04X}',w[5]] for w in writes if 0xad00 <= w[4] < 0xae00], trace_sha256=digest(steps), filesystem_sha256=entry['filesystem_sha256'], DMA=entry['DMA'], BDOS_record_events=0, tail_entry_state=tail['state'], tail_entry_RAM_sha256=tail['RAM_sha256'], tail_own_offsets=[f'{w["offset"]:04X}' for w in tail_steps], tail_proof=proof))
    rel_sha = sha(CAPTURE/'FACTOR.rel')
    historical = load('research/host-compiler/pass-71/natural-inventory.json')['FACTOR']['REL_sha256']
    assert rel_sha == historical
    boundary_proof = dict(baseline=BASE, source='FACTOR', observed_k123_count=2, five_source_handler_map=handler_map[0], FACTOR_REL_sha256=rel_sha, archived_FACTOR_REL_sha256=historical, cases=cases, capture='ignored _build/host-compiler-pass-75/capture', complete_trace_retained_under_build=True, journal_replay_full_RAM_matches=True, full_handler_native_shadow=False)
    save(REPORT/'execution-boundary-proof.json', boundary_proof)
    dependency = dict(handler='PLI2.OVL+256E', naturally_observed_cases=2, observed_sources={'FACTOR':2}, direct_calls=[['PLI2.OVL+256E','PLI2.OVL+247B'],['PLI2.OVL+2575','PLI2.OVL+059E']], proved={'PLI2.OVL+2578..259B':'faithful host tail operation with exact 8080 state, full RAM, ordered access, and software RET shadows','PLI2.OVL+059E':'previously complete canonical mapped lookup; actual nested input/result retained in traces'}, unresolved={'PLI2.OVL+247B':'large state-dependent child; distinct observed direct call paths and descendant effects, no faithful host contract','full_PLI2.OVL+256E':'requires +247B operation and composition before native gateway readiness'}, child_247B_direct_calls_by_case=[c['child_247B_direct_calls'] for c in cases], other_indices_out_of_scope=['k33/PLI2.OVL+3FFD','k216/PLI2.OVL+6D47'], native_roots_installed=0)
    save(REPORT/'child-dependencies.json', dependency)
    semantic = dict(historical_root='PLI2.OVL+256E', supported_executable_sub_contract='PLI2.OVL+2578..259B tail after canonical +059E returns', semantic_inputs=['actual A/flags and full RAM at +2578','software continuation word at current SP','immutable historical +2578..+259A bytes'], semantic_outputs=['AD07 gets actual A; zero arm overwrites AD07 with 10H','fresh AD07 reread; CPI 1 sets final flags','AD06 gets 01H if A=1 else 0FH','RET consumes current mutable stack word; PC and SP follow actual bytes'], shared_historical_state=['AD06','AD07','software stack word at SP/SP+1','earlier +247B child ADxx effects retained as concrete evidence'], historical_mechanism=['8080 STA/CPI/JNZ/LXI/MVI/LDA/JMP/RET sequence','no normal CALL ABI at +256E entry','gateway20AF PUSH H supplies software return 42B4'], candidate_modern_operation=None, confidence='Executable and CPU-shadowed for tail; full handler and gateway composition remain partial', mir_relevance=None)
    save(REPORT/'semantic-extraction.json', semantic)
    packet = dict(task='RUNES_PLI2_K123_SOFTWARE_HANDLER_PASS_75', baseline=BASE, outcome='bounded executable +2578 tail; full +256E remains guest', observed_k123_cases=2, five_source_k123_sources={'FACTOR':2}, handler_steps=[c['full_instruction_steps'] for c in cases], direct_calls=dependency['direct_calls'], distinct_247B_paths=dependency['child_247B_direct_calls_by_case'], software_continuation='gateway +20AF PUSH H high/low 42B4; +20B3 PCHL; +259A RET consumes same word and resumes +20B4', tail_cpu_shadows={'natural':2,'synthetic':sum(c['tail_proof']['synthetic_cases'] for c in cases),'full_RAM_and_ordered_access':True}, all_handler_writes_replayed_to_exact_exit_RAM=True, BDOS_record_events=0, knowledge_promotions=0, native_roots_installed=0, oracle_queries=0, full_trigger=False, next_dependency='Faithful +247B child law on both observed state-dependent paths, then +256E/+1FB5 composition', evidence=['execution-boundary-proof.json','child-dependencies.json','semantic-extraction.json'])
    save(REPORT/'implementation-packet.json', packet)
    assert (REPORT/'implementation-packet.json').stat().st_size < 28672
    return boundary_proof

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--images', default=IMAGES)
    args = p.parse_args()
    prove(args.images)
