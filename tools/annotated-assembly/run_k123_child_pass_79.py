#!/usr/bin/env python3
"""The actual +7D31 descendant and CPU-shadowed +7D05 front."""
import collections
import json
import os
import subprocess
from pathlib import Path
import run_k123_child_pass_76 as base

BASE = 'f6f440384050fddd9ed4414fca7e889b0b564a6b'
OUT = Path('_build/host-compiler-pass-79')
REPORT = Path('research/host-compiler/pass-79')

def graph(steps):
    frames=[]
    edges=collections.Counter()
    for index,row in enumerate(steps):
        if row['kind']=='call' and row['taken']:
            child=steps[index+1]
            assert child['before']['pc']==row['target']
            parent=frames[-1][1] if frames else 'root'
            edges[(parent,row['image'],row['offset'],row['target'],
                   child['image'],child['offset'])]+=1
            frames.append((row['before']['pc']+3,row['target']))
        elif row['kind']=='return' and row['taken']:
            if frames:
                assert frames.pop()[0]==row['after']['pc']
            else:
                assert row is steps[-1]
    assert not frames
    return [[str(parent),caller_image,f"{site:04X}",f"{target:04X}",
             child_image,f"{child_offset:04X}",count]
            for (parent,caller_image,site,target,child_image,child_offset),count
            in sorted(edges.items(),key=lambda pair:str(pair[0]))]

def prove(images='/home/john/pli/cpm/pli80/DISK1'):
    OUT.mkdir(parents=True,exist_ok=True)
    capture=base.CAPTURE
    if not (capture/'handler-steps.jsonl').is_file():
        capture=OUT/'capture'
        capture.mkdir(parents=True,exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/k123_handler_capture.exe',
                            'bin/k123_7d05_front_proof.exe'],check=True)
        subprocess.run(['_build/default/bin/k123_handler_capture.exe',
                        '--images',str(images),'--output',str(capture)],check=True)
    elif not os.environ.get('RUNES_HOST_IMAGES'):
        subprocess.run(['dune','build','bin/k123_7d05_front_proof.exe'],check=True)
    assert base.sha((capture/'FACTOR.rel').read_bytes())==base.GOLDEN
    rows=[json.loads(line) for line in (capture/'handler-steps.jsonl').read_text().splitlines()]
    archived=base.load('research/host-compiler/pass-75/execution-boundary-proof.json')
    catalog=base.load('research/annotated-assembly/procedures.json')['procedures']
    catalog_scope={p['id']:p['completeness'] for p in catalog}
    cases=[]
    for number in (1,2):
        whole=[row for row in rows if row['case']==number]
        old=archived['cases'][number-1]
        assert base.digest(whole)==old['trace_sha256']
        call_index=next(i for i,row in enumerate(whole)
                        if row['offset']==0x24b2 and row['kind']=='call')
        call=whole[call_index]
        assert call['target']==0x9f31
        end=next(i for i in range(call_index+1,len(whole))
                 if whole[i]['offset']==0x24b5)
        root=whole[call_index+1:end]
        assert len(root)==1550
        assert (root[0]['offset'],root[-1]['offset'])==(0x7d31,0x7d46)
        assert root[0]['before']==call['after']
        assert root[-1]['after']==whole[end]['before']
        assert root[-1]['kind']=='return'
        assert root[-1]['accesses']==[
            {'kind':'read','address':root[0]['before']['sp'],'value':0xb5},
            {'kind':'read','address':root[0]['before']['sp']+1,'value':0x46}]
        calls=graph(root)
        assert sum(edge[-1] for edge in calls)==59
        direct=[edge for edge in calls if edge[0]=='root']
        assert [(e[2],e[3],e[5]) for e in direct]==[
            ('7D3B','272C','052C'),('7D43','9F05','7D05')]
        child_call=next(i for i,row in enumerate(root)
                        if row['offset']==0x7d43 and row['kind']=='call')
        child_start=child_call+1
        child_end=next(i for i in range(child_start,len(root))
                       if root[i]['offset']==0x7d46)
        child=root[child_start:child_end]
        assert len(child)==1455
        assert child[0]['offset']==0x7d05 and child[-1]['offset']==0x7d30
        assert sum(edge[-1] for edge in graph(child))==52
        front_end=next(i for i in range(child_start,len(root))
                       if root[i]['offset']==0x73a7)
        front=root[child_start:front_end]
        assert len(front)==17
        assert front[0]['offset']==0x7d05
        assert front[-1]['offset']==0x7d1c and front[-1]['target']==0x95a7
        assert [(row['offset'],row['target']) for row in front
                if row['kind']=='call']==[(0x7d15,0x9c17),(0x7d1c,0x95a7)]
        ram=bytearray((capture/f'case-{number}-entry.ram').read_bytes())
        base.replay(ram,whole[:call_index+1])
        entry_hash=base.sha(ram)
        root_reads,root_writes=base.replay(ram,root[:child_start])
        front_path=OUT/f'case-{number}-7d05-entry.ram'
        front_path.write_bytes(ram)
        front_hash=base.sha(ram)
        front_reads,front_writes=base.replay(ram,front)
        next_path=OUT/f'case-{number}-73a7-entry.ram'
        next_path.write_bytes(ram)
        proof_path=OUT/f'case-{number}-7d05-proof.json'
        subprocess.run(['_build/default/bin/k123_7d05_front_proof.exe',
                        '--ram',str(front_path),'--expected-ram',str(next_path),
                        '--output',str(proof_path),
                        *base.args('',front[0]['before']),
                        *base.args('expected-',front[-1]['after'])],check=True)
        proof=base.load(proof_path)
        assert proof['natural_passed'] and proof['synthetic_cases']==21
        assert proof['unsupported_nonzero_AE04_rejected']
        after_front_reads,after_front_writes=base.replay(ram,root[front_end:])
        assert root_reads+front_reads+after_front_reads==sum(
            a['kind']=='read' for s in root for a in s['accesses'])
        assert root_writes+front_writes+after_front_writes==sum(
            a['kind']=='write' for s in root for a in s['accesses'])
        exit_hash=base.sha(ram)
        continuation=bytearray(ram)
        base.replay(continuation,whole[end:])
        assert base.sha(continuation)==old['handler_exit_RAM_sha256']
        writes=[[row['step'],row['image'],f"{row['offset']:04X}",
                 a['address'],a['value']]
                for row in root for a in row['accesses'] if a['kind']=='write']
        counts=collections.Counter(w[3] for w in writes)
        adxx=[w for w in writes if 0xad00<=w[3]<0xae00]
        assert not any(w[3] in (root[0]['before']['sp'],root[0]['before']['sp']+1)
                       for w in writes)
        cases.append(dict(case=number,caller='PLI2.OVL+24B2',
                          root='PLI2.OVL+7D31',hardware_continuation='PLI2.OVL+24B5',
                          root_entry_step=root[0]['step'],root_exit_step=root[-1]['step'],
                          root_entry=root[0]['before'],root_exit=root[-1]['after'],
                          root_entry_RAM_sha256=entry_hash,
                          root_exit_RAM_sha256=exit_hash,
                          root_instruction_steps=len(root),
                          root_ordered_reads=root_reads+front_reads+after_front_reads,
                          root_ordered_writes=len(writes),
                          root_ordered_write_sha256=base.digest(writes),
                          root_ADxx_writes=adxx,
                          repeated_write_addresses=sum(n>1 for n in counts.values()),
                          hardware_CALL_count=sum(edge[-1] for edge in calls),
                          direct_calls=direct,complete_child_call_graph=calls,
                          child_7D05_steps=len(child),
                          child_7D05_direct_calls=[e for e in graph(child) if e[0]=='root'],
                          front_entry_step=front[0]['step'],
                          front_entry=front[0]['before'],
                          front_entry_RAM_sha256=front_hash,
                          front_exit_step=front[-1]['step'],
                          front_next_child=front[-1]['target'],
                          front_next_child_state=front[-1]['after'],
                          front_next_child_RAM_sha256=base.sha(next_path.read_bytes()),
                          front_reads=front_reads,front_writes=front_writes,
                          front_proof=proof,DMA=old['DMA'],
                          filesystem_sha256=old['filesystem_sha256'],
                          BDOS_record_events=0))
    evidence=dict(baseline=BASE,source='FACTOR',capture=str(capture),
                  Pass75_trace_digest_verified=True,
                  FACTOR_REL_sha256=base.GOLDEN,
                  root_hardware_frame_owned_by='PLI2.OVL+24B2 CALL',
                  gateway_software_frame_separate=True,
                  cases=cases,full_7D31_host_shadow=False)
    base.save(REPORT/'natural-shadow.json',evidence)
    law=dict(operation='PLI2.OVL+7D05 front through CALL +73A7',
             scope='root scratch AE2D..AE2F, C=4 gate, scoped +7A17 early return, fresh paired reread and CALL frame',
             branch='fresh AE2D CPI 4; non4 skips +7A17; C4 requires fresh AE04=0',
             unsupported='C4 and fresh AE04 nonzero rejects before claiming +7A17 later arm',
             natural_shadows=2,synthetic_shadows=42,
             full_register_flags_RAM_ordered_access=True,
             descendant_73A7_executed=False,complete_7D05=False,complete_7D31=False)
    base.save(REPORT/'child-law.json',law)
    scopes={key:catalog_scope.get('PLI2.OVL+'+key)
            for key in ['052C','7A17','73A7','75CE','785C','7397','77CC']}
    unresolved=dict(root='PLI2.OVL+7D31',direct_children=['PLI2.OVL+052C','PLI2.OVL+7D05'],
                    child_7D05_direct=['PLI2.OVL+7A17','PLI2.OVL+73A7',
                                        'PLI2.OVL+75CE','PLI2.OVL+785C'],
                    first_uncomposed='PLI2.OVL+73A7 after proved +7D05 front',
                    later_uncomposed=['PLI2.OVL+75CE','PLI2.OVL+785C'],
                    deeper_partial='PLI2.OVL+77CC under +785C',
                    catalog_completeness=scopes,
                    full_7D31=False,full_247B=False,native_roots_installed=0)
    base.save(REPORT/'unresolved-dependencies.json',unresolved)
    semantic=dict(historical_root='PLI2.OVL+7D31',
                  executable_sub_contract='PLI2.OVL+7D05 front to +73A7 CALL',
                  state_inputs=['C,D,E and flags','fresh AE04','mutable AE2D..AE2F and stack bytes'],
                  state_outputs=['ordered AE2F,AE2E,AE2D writes',
                                 'CPI 4 and optional scoped +7A17 CPI 0 flags',
                                 'fresh paired AE2D/AE2E read to HL and C',
                                 'actual +73A7 hardware frame, PC/SP'],
                  natural_domain='C4, AE04 zero in both FACTOR cases',
                  synthetic_non4='skip +7A17; no OBSERVED promotion',
                  no_case_or_source_dispatch=True,
                  full_7D31_contract=False)
    base.save(REPORT/'semantic-extraction.json',semantic)
    packet=dict(task='RUNES_K123_EXTENDED_DEPENDENCY_CLOSURE_77_79',
                pass_number=79,baseline=BASE,
                outcome='bounded +7D05 front; +7D31 and +247B remain guest',
                root_steps=[case['root_instruction_steps'] for case in cases],
                root_hardware_CALLs=[case['hardware_CALL_count'] for case in cases],
                front_law=law,unresolved=unresolved,
                FACTOR_REL_sha256=base.GOLDEN,knowledge_promotions=0,
                native_roots_installed=0,oracle_queries=0,
                ordinary_FULL_due=True,FULL_certification_status='PENDING EXTERNAL MANUAL FULL',
                evidence=['natural-shadow.json','child-law.json',
                          'unresolved-dependencies.json','semantic-extraction.json',
                          'full-checkpoint-handoff.json'])
    base.save(REPORT/'implementation-packet.json',packet)
    assert (REPORT/'implementation-packet.json').stat().st_size<28672
    return evidence

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--images',default='/home/john/pli/cpm/pli80/DISK1')
    prove(parser.parse_args().images)
