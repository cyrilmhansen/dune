#!/usr/bin/env python3
"""Natural +245D frame and CPU-shadowed post-052C composition."""
import json
import os
import subprocess
from pathlib import Path
import run_k123_child_pass_76 as base

BASE = '401018d88fdc2f073294798d2aeffe6aea58d945'
OUT = Path('_build/host-compiler-pass-78')
REPORT = Path('research/host-compiler/pass-78')

def prove(images='/home/john/pli/cpm/pli80/DISK1'):
    OUT.mkdir(parents=True,exist_ok=True)
    capture=base.CAPTURE
    if not (capture/'handler-steps.jsonl').is_file():
        capture=OUT/'capture'
        capture.mkdir(parents=True,exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/k123_handler_capture.exe',
                            'bin/k123_245d_tail_proof.exe'],check=True)
        subprocess.run(['_build/default/bin/k123_handler_capture.exe',
                        '--images',str(images),'--output',str(capture)],check=True)
    elif not os.environ.get('RUNES_HOST_IMAGES'):
        subprocess.run(['dune','build','bin/k123_245d_tail_proof.exe'],check=True)
    assert base.sha((capture/'FACTOR.rel').read_bytes())==base.GOLDEN
    rows=[json.loads(line) for line in (capture/'handler-steps.jsonl').read_text().splitlines()]
    archived=base.load('research/host-compiler/pass-75/execution-boundary-proof.json')
    catalog=base.load('research/annotated-assembly/procedures.json')['procedures']
    canonical=next(p for p in catalog if p['id']=='PLI2.OVL+052C')
    assert canonical['completeness']['contract']=='complete'
    cases=[]
    for number in (1,2):
        whole=[row for row in rows if row['case']==number]
        old=archived['cases'][number-1]
        assert base.digest(whole)==old['trace_sha256']
        call_index=next(i for i,row in enumerate(whole)
                        if row['offset']==0x24b9 and row['kind']=='call')
        call=whole[call_index]
        assert call['target']==0x465d and call['image']=='PLI2.OVL'
        branch_index=next(i for i in range(call_index+1,len(whole))
                          if whole[i]['offset']==0x24bc)
        root=whole[call_index+1:branch_index]
        assert len(root)==98
        assert root[0]['offset']==0x245d and root[-1]['offset']==0x247a
        assert root[-1]['kind']=='return'
        entry=root[0]['before']
        exit_=root[-1]['after']
        assert entry==call['after'] and exit_==whole[branch_index]['before']
        assert (entry['sp'],exit_['sp'])==(call['before']['sp']-2,call['before']['sp'])
        assert root[-1]['accesses']==[
            {'kind':'read','address':entry['sp'],'value':0xbc},
            {'kind':'read','address':entry['sp']+1,'value':0x46}]
        direct=next(row for row in root if row['offset']==0x2465)
        assert direct['kind']=='call' and direct['target']==0x272c
        child_index=next(i for i,row in enumerate(root) if row is direct)
        assert root[child_index+1]['image']=='PLI2.OVL'
        assert root[child_index+1]['offset']==0x052c
        tail_index=next(i for i,row in enumerate(root) if row['offset']==0x2468)
        tail=root[tail_index:]
        assert [row['offset'] for row in tail]==[
            0x2468,0x246b,0x246e,0x2471,0x2472,
            0x2474,0x2475,0x2477,0x2479,0x247a]
        calls=[[f"{row['offset']:04X}",f"{row['target']:04X}",
                root[i+1]['image'],f"{root[i+1]['offset']:04X}"]
               for i,row in enumerate(root) if row['kind']=='call']
        assert len(calls)==6
        stack=[]
        for row in root:
            if row['kind']=='call' and row['taken']:
                stack.append(row['before']['pc']+3)
            elif row['kind']=='return' and row['taken']:
                if stack:
                    assert stack.pop()==row['after']['pc']
                else:
                    assert row is root[-1]
        assert not stack
        ram=bytearray((capture/f'case-{number}-entry.ram').read_bytes())
        base.replay(ram,whole[:call_index+1])
        entry_ram_hash=base.sha(ram)
        root_reads,root_writes=base.replay(ram,root[:tail_index])
        seed_path=OUT/f'case-{number}-245d-tail-entry.ram'
        seed_path.write_bytes(ram)
        tail_entry_hash=base.sha(ram)
        tail_reads,tail_writes=base.replay(ram,tail)
        tail_path=OUT/f'case-{number}-245d-tail-exit.ram'
        tail_path.write_bytes(ram)
        tail_exit_hash=base.sha(ram)
        assert tail[-1]['after']==whole[branch_index]['before']
        next_index=next(i for i in range(branch_index,len(whole))
                        if whole[i]['offset'] in (0x24c6,0x24d5))
        branch=whole[branch_index:next_index+1]
        branch_reads,branch_writes=base.replay(ram,branch)
        next_call=whole[next_index]
        assert next_call['kind']=='call' and next_call['target'] in (0xa3aa,0xa5dc)
        next_path=OUT/f'case-{number}-next-child.ram'
        next_path.write_bytes(ram)
        proof_path=OUT/f'case-{number}-245d-tail-proof.json'
        subprocess.run(['_build/default/bin/k123_245d_tail_proof.exe',
                        '--ram',str(seed_path),'--tail-ram',str(tail_path),
                        '--next-ram',str(next_path),'--output',str(proof_path),
                        '--next-target',str(next_call['target']),
                        *base.args('',tail[0]['before']),
                        *base.args('expected-',tail[-1]['after'])],check=True)
        proof=base.load(proof_path)
        assert proof['natural_tail'] and proof['natural_composed']
        assert (proof['synthetic_tail'],proof['synthetic_composed'])==(48,16)
        remaining=bytearray(ram)
        base.replay(remaining,whole[next_index+1:])
        assert base.sha(remaining)==old['handler_exit_RAM_sha256']
        writes=[[row['step'],row['image'],f"{row['offset']:04X}",
                 a['address'],a['value']]
                for row in root for a in row['accesses'] if a['kind']=='write']
        assert not any(w[3] in (entry['sp'],entry['sp']+1) for w in writes)
        cases.append(dict(case=number,root_entry_step=root[0]['step'],
                          root_exit_step=root[-1]['step'],
                          caller='PLI2.OVL+24B9',root='PLI2.OVL+245D',
                          hardware_continuation='PLI2.OVL+24BC',
                          root_entry=entry,root_exit=exit_,
                          root_entry_RAM_sha256=entry_ram_hash,
                          root_exit_RAM_sha256=tail_exit_hash,
                          root_steps=len(root),root_reads=root_reads+tail_reads,
                          root_writes=root_writes+tail_writes,
                          root_write_sha256=base.digest(writes),
                          root_ADxx_writes=[w for w in writes if 0xad00<=w[3]<0xae00],
                          nested_calls=calls,nested_CALL_count=len(calls),
                          canonical_052C_return=tail[0]['before'],
                          tail_entry_RAM_sha256=tail_entry_hash,
                          tail_exit=tail[-1]['after'],
                          tail_steps=len(tail),tail_reads=tail_reads,
                          tail_writes=tail_writes,
                          branch_target=next_call['target'],
                          branch_entry=whole[branch_index]['before'],
                          branch_reads=branch_reads,
                          branch_writes=branch_writes,
                          next_child_state=next_call['after'],
                          next_child_RAM_sha256=base.sha(next_path.read_bytes()),
                          proof=proof,DMA=old['DMA'],
                          filesystem_sha256=old['filesystem_sha256'],
                          BDOS_record_events=0))
    assert [case['branch_target'] for case in cases]==[0xa5dc,0xa3aa]
    evidence=dict(baseline=BASE,source='FACTOR',capture=str(capture),
                  Pass75_trace_digest_verified=True,
                  FACTOR_REL_sha256=base.GOLDEN,
                  canonical_052C_catalog_contract='complete',
                  full_245D_host_shadow=False,cases=cases)
    base.save(REPORT/'natural-shadow.json',evidence)
    law=dict(operation='PLI2.OVL+2468..247A after canonical +052C',
             inputs=['actual +052C return registers/flags/RAM','mutable hardware return word'],
             effects=['SHLD AC9F, fresh LHLD AC9F','DAD B with BC=3',
                      'fresh pointed bit7 through ANA/SUI80/SUI1/SBB A',
                      'RET through current stack word'],
             composition='tail RET to +24BC then Pass76 state-defined branch through next CALL',
             natural_tail_shadows=2,natural_composition_shadows=2,
             synthetic_tail_shadows=96,synthetic_composition_shadows=32,
             full_register_flags_RAM_ordered_access=True,
             full_245D=False)
    base.save(REPORT/'child-law.json',law)
    unresolved=dict(canonical_child='PLI2.OVL+052C independently complete in catalog but not newly host-shadowed as part of full +245D here',
                    uncomposed_prefix='PLI2.OVL+245D..2465 before canonical +052C',
                    full_245D='partial: prefix and child composition require an independent full-window host shadow',
                    full_247B='unproved: common +7D31 and later branch descendants remain',
                    native_roots_installed=0)
    base.save(REPORT/'unresolved-dependencies.json',unresolved)
    semantic=dict(root='PLI2.OVL+245D',executable_sub_contract='post-052C +2468..247A and +24BC adapter',
                  branch_condition='fresh [word[AC9F]+3].bit7 through 8080 ANA/SUI/SBB produces 0 or FF',
                  natural_values=[0,255],not_dispatched_by_case=True,
                  canonical_child='PLI2.OVL+052C; six nested CALLs in observed window',
                  full_child_contract=False)
    base.save(REPORT/'semantic-extraction.json',semantic)
    packet=dict(task='RUNES_K123_EXTENDED_DEPENDENCY_CLOSURE_77_79',
                pass_number=78,baseline=BASE,
                outcome='post-052C +245D tail and Pass76 branch composition proved; full +245D remains guest',
                root_steps=[c['root_steps'] for c in cases],
                branch_targets=['A5DC','A3AA'],
                law=law,unresolved=unresolved,
                FACTOR_REL_sha256=base.GOLDEN,knowledge_promotions=0,
                native_roots_installed=0,oracle_queries=0,full_trigger=False,
                next_dependency='Independent full-window +245D composition; common +7D31',
                evidence=['natural-shadow.json','child-law.json',
                          'unresolved-dependencies.json','semantic-extraction.json'])
    base.save(REPORT/'implementation-packet.json',packet)
    assert (REPORT/'implementation-packet.json').stat().st_size<28672
    return evidence

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--images',default='/home/john/pli/cpm/pli80/DISK1')
    prove(parser.parse_args().images)
