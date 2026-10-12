#!/usr/bin/env python3
"""Pass76: retained +247B trace and independent +24BC branch shadow."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

BASE = '142087da112a04927bc0ea39f6148b734ce630b7'
OUT = Path('_build/host-compiler-pass-76')
REPORT = Path('research/host-compiler/pass-76')
CAPTURE = Path('_build/host-compiler-pass-75/capture')
GOLDEN = '9a42e8341a013243036040c8db0e56939c699c7fbbfb20878f7ba5af8d6b470d'

def load(path):
    return json.loads(Path(path).read_text())

def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def sha(data):
    return hashlib.sha256(data).hexdigest()

def digest(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())

def psw(q):
    return 2 | sum(weight for key, weight in
                   [('S',128),('Z',64),('AC',16),('P',4),('CY',1)] if q[key])

def args(prefix, q):
    values = dict(pc=q['pc'], sp=q['sp'], a=q['a'],
                  bc=q['b']*256+q['c'], de=q['d']*256+q['e'],
                  hl=q['h']*256+q['l'], psw=psw(q))
    return [part for key, value in values.items()
            for part in ('--'+prefix+key, str(value))]

def replay(ram, steps):
    reads = writes = 0
    for step in steps:
        for access in step['accesses']:
            address, value = access['address'], access['value']
            assert 0 <= address < 65536 and 0 <= value < 256
            if access['kind'] == 'read':
                assert ram[address] == value, (step['step'], address)
                reads += 1
            else:
                assert access['kind'] == 'write'
                ram[address] = value
                writes += 1
    return reads, writes

def prove(images='/home/john/pli/cpm/pli80/DISK1'):
    OUT.mkdir(parents=True, exist_ok=True)
    capture = CAPTURE
    if not (capture/'handler-steps.jsonl').is_file():
        capture = OUT/'capture'
        capture.mkdir(parents=True, exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/k123_handler_capture.exe',
                            'bin/k123_branch_proof.exe'], check=True)
        subprocess.run(['_build/default/bin/k123_handler_capture.exe',
                        '--images',str(images),'--output',str(capture)], check=True)
    elif not os.environ.get('RUNES_HOST_IMAGES'):
        subprocess.run(['dune','build','bin/k123_branch_proof.exe'], check=True)
    assert sha((capture/'FACTOR.rel').read_bytes()) == GOLDEN
    rows = [json.loads(line) for line in
            (capture/'handler-steps.jsonl').read_text().splitlines()]
    old = load('research/host-compiler/pass-75/execution-boundary-proof.json')
    cases = []
    for number in (1,2):
        whole = [row for row in rows if row['case'] == number]
        archived = old['cases'][number-1]
        assert digest(whole) == archived['trace_sha256']
        ram = bytearray((capture/f'case-{number}-entry.ram').read_bytes())
        assert len(ram) == 65536
        assert sha(ram) == archived['handler_entry_RAM_sha256']
        parent_call = whole[0]
        assert (parent_call['offset'],parent_call['target'],parent_call['kind']) == (0x256e,0x467b,'call')
        replay(ram,[parent_call])
        entry_ram_sha = sha(ram)
        assert whole[1]['offset'] == 0x247b
        entry = whole[1]['before']
        assert entry['sp'] == parent_call['before']['sp']-2
        assert ram[entry['sp']:entry['sp']+2] == b'\x71\x47'
        gate_index = next(i for i,row in enumerate(whole) if row['offset']==0x24bc)
        replay(ram,whole[1:gate_index])
        gate = whole[gate_index]
        gate_ram_sha = sha(ram)
        gate_path = OUT/f'case-{number}-branch.ram'
        gate_path.write_bytes(ram)
        call_index = next(i for i,row in enumerate(whole)
                          if i>gate_index and row['offset'] in (0x24c6,0x24d5))
        branch = whole[gate_index:call_index+1]
        assert all(row['image']=='PLI2.OVL' for row in branch)
        branch_reads, branch_writes = replay(ram,branch)
        child_call = whole[call_index]
        assert child_call['kind']=='call' and child_call['target'] in (0xa3aa,0xa5dc)
        next_path = OUT/f'case-{number}-next-child.ram'
        next_path.write_bytes(ram)
        proof_path = OUT/f'case-{number}-branch-proof.json'
        subprocess.run(['_build/default/bin/k123_branch_proof.exe',
                        '--ram',str(gate_path),'--expected-ram',str(next_path),
                        '--output',str(proof_path),
                        *args('',gate['before']),*args('expected-',child_call['after'])],
                       check=True)
        proof = load(proof_path)
        assert proof['natural_passed'] and proof['synthetic_cases']==48
        end = next(i for i,row in enumerate(whole)
                   if i>call_index and row['offset']==0x256d)
        root = whole[1:end+1]
        replay(ram,whole[call_index+1:end+1])
        assert root[-1]['kind']=='return' and root[-1]['after']['pc']==0x4771
        assert whole[end+1]['before']==root[-1]['after']
        assert root[-1]['accesses'] == [
            {'kind':'read','address':entry['sp'],'value':0x71},
            {'kind':'read','address':entry['sp']+1,'value':0x47}]
        assert ram[entry['sp']:entry['sp']+2] == b'\x71\x47'
        continuation_ram = bytearray(ram)
        tail_index = next(i for i,row in enumerate(whole) if row['offset']==0x2578)
        replay(continuation_ram, whole[end+1:tail_index])
        assert sha(continuation_ram) == archived['tail_entry_RAM_sha256']
        replay(continuation_ram, whole[tail_index:])
        assert sha(continuation_ram) == archived['handler_exit_RAM_sha256']
        stack, direct = [], []
        for i,row in enumerate(root):
            if row['kind']=='call' and row['taken']:
                if not stack:
                    child = root[i+1]
                    assert child['before']['pc']==row['target']
                    direct.append([f"{row['offset']:04X}",f"{row['target']:04X}",
                                   child['image'],f"{child['offset']:04X}"])
                stack.append(row['before']['pc']+3)
            elif row['kind']=='return' and row['taken']:
                if stack:
                    assert stack.pop()==row['after']['pc']
                else:
                    assert row is root[-1]
        assert not stack
        writes = [[step['step'],step['image'],f"{step['offset']:04X}",
                   access['address'],access['value']]
                  for step in root for access in step['accesses']
                  if access['kind']=='write']
        assert not any(w[3] in (entry['sp'],entry['sp']+1) for w in writes)
        cases.append(dict(case=number,root_entry_step=root[0]['step'],
                          root_exit_step=root[-1]['step'],
                          root_entry=entry,root_exit=root[-1]['after'],
                          root_entry_RAM_sha256=entry_ram_sha,
                          root_exit_RAM_sha256=sha(ram),
                          root_instruction_steps=len(root),
                          root_ordered_reads=sum(a['kind']=='read' for s in root for a in s['accesses']),
                          root_ordered_writes=len(writes),
                          root_hardware_CALL_count=sum(s['kind']=='call' and s['taken'] for s in root),
                          hardware_frame_last_writer='PLI2.OVL+256E CALL',
                          root_ordered_write_sha256=digest(writes),
                          root_ADxx_writes=[w for w in writes if 0xad00<=w[3]<0xae00],
                          direct_children=direct,
                          branch_entry_step=gate['step'],branch_entry=gate['before'],
                          branch_entry_RAM_sha256=gate_ram_sha,
                          branch_next_child=child_call['target'],
                          branch_next_child_state=child_call['after'],
                          branch_next_child_RAM_sha256=sha(next_path.read_bytes()),
                          branch_instruction_steps=len(branch),
                          branch_reads=branch_reads,branch_writes=branch_writes,
                          branch_proof=proof,DMA=archived['DMA'],
                          filesystem_sha256=archived['filesystem_sha256'],
                          service_events=0))
    assert [c['branch_next_child'] for c in cases]==[0xa5dc,0xa3aa]
    boundary=dict(baseline=BASE,source='FACTOR',capture=str(capture),
                  Pass75_trace_digest_verified=True,FACTOR_REL_sha256=GOLDEN,
                  hardware_child_return='PLI2.OVL+2571',
                  gateway_software_return='PLI2.OVL+20B4',
                  complete_child_host_shadow=False,cases=cases)
    save(REPORT/'natural-shadow.json',boundary)
    law=dict(operation='PLI2.OVL+24BC through child CALL',
             scope='stop before first instruction of +A3AA or +A5DC',
             condition='RAR sets CY to incoming A.bit0; JNC tests that carry',
             carry_clear='fresh AC9F word + 6 via DAD B; A=0; CALL A5DC',
             carry_set='fresh AD0D word to DE via XCHG; C=9; CALL A3AA',
             old_carry='rotated into A.bit7, not used for branch choice',
             natural_CPU_shadows=2,synthetic_CPU_shadows=96,
             full_register_flags_RAM_ordered_access=True,
             no_descendant_effects_claimed=True)
    save(REPORT/'child-law.json',law)
    unresolved=dict(
        first_unclosed_direct_child='PLI2.OVL+16B3 via +2492',
        common_major_descendant='PLI2.OVL+7D31 via +24B2: 1550 instructions and 59 nested CALLs in each observed case',
        common_later='PLI2.OVL+245D via +24B9: 98 instructions and six nested CALLs',
        carry_clear='PLI2.OVL+83DC then +81C0 and +742A remain guest',
        carry_set='PLI2.OVL+81AA remains guest',
        full_247B='unproved',full_256E='unproved',native_roots_installed=0)
    save(REPORT/'unresolved-dependencies.json',unresolved)
    semantic=dict(root='PLI2.OVL+247B',
                  executable_sub_contract='state-defined +24BC branch and exact child CALL',
                  inputs=['A/flags returned by +245D','fresh AD0D or AC9F word','current SP and RAM'],
                  outputs=['8080 RAR and DAD flags','next child PC and entry registers',
                           'ordered pointer reads and hardware CALL writes'],
                  natural_targets=['A5DC','A3AA'],
                  complete_child_contract=False,complete_handler_contract=False)
    save(REPORT/'semantic-extraction.json',semantic)
    packet=dict(task='RUNES_PLI2_K123_CHILD_247B_PASS_76',
                baseline=BASE,outcome='bounded branch adapter; full +247B remains guest',
                root_steps=[c['root_instruction_steps'] for c in cases],
                root_writes=[c['root_ordered_writes'] for c in cases],
                branch_targets=['A5DC','A3AA'],child_law=law,
                unresolved=unresolved,FACTOR_REL_sha256=GOLDEN,
                knowledge_promotions=0,native_roots_installed=0,oracle_queries=0,
                full_trigger=False,
                next_dependency='Faithful +16B3, then +7D31 and branch descendants',
                evidence=['natural-shadow.json','child-law.json',
                          'unresolved-dependencies.json','semantic-extraction.json'])
    save(REPORT/'implementation-packet.json',packet)
    assert (REPORT/'implementation-packet.json').stat().st_size<28672
    return boundary

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--images',default='/home/john/pli/cpm/pli80/DISK1')
    options=parser.parse_args()
    prove(options.images)
