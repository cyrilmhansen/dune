#!/usr/bin/env python3
"""Natural +16B3 child extraction and independent CPU/host shadows."""
import json
import os
import subprocess
from pathlib import Path
import run_k123_child_pass_76 as base

BASE = '009a2408b394547b11ab2021b575c06c1a5a2322'
OUT = Path('_build/host-compiler-pass-77')
REPORT = Path('research/host-compiler/pass-77')

def prove(images='/home/john/pli/cpm/pli80/DISK1'):
    OUT.mkdir(parents=True, exist_ok=True)
    capture = base.CAPTURE
    if not (capture/'handler-steps.jsonl').is_file():
        capture = OUT/'capture'
        capture.mkdir(parents=True, exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/k123_handler_capture.exe',
                            'bin/k123_16b3_proof.exe'],check=True)
        subprocess.run(['_build/default/bin/k123_handler_capture.exe',
                        '--images',str(images),'--output',str(capture)],check=True)
    elif not os.environ.get('RUNES_HOST_IMAGES'):
        subprocess.run(['dune','build','bin/k123_16b3_proof.exe'],check=True)
    assert base.sha((capture/'FACTOR.rel').read_bytes())==base.GOLDEN
    rows=[json.loads(line) for line in
          (capture/'handler-steps.jsonl').read_text().splitlines()]
    archived=base.load('research/host-compiler/pass-75/execution-boundary-proof.json')
    cases=[]
    for number in (1,2):
        whole=[row for row in rows if row['case']==number]
        old=archived['cases'][number-1]
        assert base.digest(whole)==old['trace_sha256']
        call_index=next(i for i,row in enumerate(whole)
                        if row['offset']==0x2492 and row['kind']=='call')
        call=whole[call_index]
        assert call['target']==0x38b3 and call['image']=='PLI2.OVL'
        exit_index=next(i for i in range(call_index+1,len(whole))
                        if whole[i]['offset']==0x2495)
        leaf=whole[call_index+1:exit_index]
        assert len(leaf)==14
        assert leaf[0]['offset']==0x16b3 and leaf[-1]['offset']==0x16cb
        assert all(row['image']=='PLI2.OVL' for row in leaf)
        assert all(row['kind']!='call' for row in leaf)
        assert leaf[-1]['kind']=='return'
        entry=leaf[0]['before']
        expected=leaf[-1]['after']
        assert entry==call['after'] and expected==whole[exit_index]['before']
        assert (entry['sp'],expected['sp'])==(call['before']['sp']-2,call['before']['sp'])
        assert leaf[-1]['accesses']==[
            {'kind':'read','address':entry['sp'],'value':0x95},
            {'kind':'read','address':entry['sp']+1,'value':0x46}]
        ram=bytearray((capture/f'case-{number}-entry.ram').read_bytes())
        base.replay(ram,whole[:call_index+1])
        entry_path=OUT/f'case-{number}-16b3-entry.ram'
        entry_path.write_bytes(ram)
        entry_hash=base.sha(ram)
        reads,writes=base.replay(ram,leaf)
        exit_path=OUT/f'case-{number}-16b3-exit.ram'
        exit_path.write_bytes(ram)
        proof_path=OUT/f'case-{number}-16b3-proof.json'
        subprocess.run(['_build/default/bin/k123_16b3_proof.exe',
                        '--ram',str(entry_path),'--expected-ram',str(exit_path),
                        '--output',str(proof_path),
                        *base.args('',entry),*base.args('expected-',expected)],
                       check=True)
        proof=base.load(proof_path)
        assert proof['natural_passed'] and proof['synthetic_cases']==48
        accesses=[[row['step'],f"{row['offset']:04X}",a['kind'],
                   a['address'],a['value']]
                  for row in leaf for a in row['accesses']]
        cases.append(dict(case=number,call_step=call['step'],
                          caller='PLI2.OVL+2492',runtime_target='38B3',
                          child='PLI2.OVL+16B3',hardware_return='4695',
                          entry_step=leaf[0]['step'],exit_step=leaf[-1]['step'],
                          entry=entry,exit=expected,entry_RAM_sha256=entry_hash,
                          exit_RAM_sha256=base.sha(ram),instruction_count=len(leaf),
                          instruction_offsets=[f"{row['offset']:04X}" for row in leaf],
                          ordered_reads=reads,ordered_writes=writes,
                          ordered_access_sha256=base.digest(accesses),
                          ACEE_after=ram[0xacee],ACEF_after=ram[0xacef],
                          AC9F_after=[ram[0xac9f],ram[0xaca0]],
                          stack_continuation_last_writer='PLI2.OVL+2492 CALL',
                          nested_CALLs=0,BDOS_record_events=0,
                          DMA=old['DMA'],filesystem_sha256=old['filesystem_sha256'],
                          proof=proof))
    evidence=dict(baseline=BASE,source='FACTOR',capture=str(capture),
                  Pass75_trace_digest_verified=True,
                  FACTOR_REL_sha256=base.GOLDEN,cases=cases)
    base.save(REPORT/'natural-shadow.json',evidence)
    law=dict(root='PLI2.OVL+16B3',extent='actual +16B3..+16CB leaf RET',
             entry='hardware CALL from PLI2.OVL+2492; mutable return word at SP',
             carrier='write B to ACEF, then C to ACEE; reread both before SHLD AC9F',
             pointer='fresh carrier word plus 3 modulo 65536, DAD carry exact',
             mask='A=7 ANA fresh [HL]; SUI 0; SUI 1; SBB A using immediate prior borrow',
             return_law='RET reads current SP/SP+1, including aliases',
             flags='ANA AC and DAD carry computed; final SBB flags exact',
             natural_shadows=2,synthetic_shadows=96,
             full_register_flags_RAM_ordered_access=True,
             complete_leaf=True,complete_247B=False)
    base.save(REPORT/'child-law.json',law)
    unresolved=dict(next_common_child='PLI2.OVL+245D via +24B9',
                    major_common_child='PLI2.OVL+7D31 via +24B2',
                    complete_247B=False,complete_256E=False,
                    native_roots_installed=0)
    base.save(REPORT/'unresolved-dependencies.json',unresolved)
    semantic=dict(historical_root='PLI2.OVL+16B3',
                  operation='publish actual BC carrier to ACEE/ACEF and AC9F; derive masked flag from fresh [carrier+3]',
                  input_domain='state-defined immutable code and 16-bit RAM, including stack/pointer aliases',
                  output='exact registers, flags, PC/SP, ordered memory accesses and full RAM',
                  no_parent_or_gateway_claim=True)
    base.save(REPORT/'semantic-extraction.json',semantic)
    packet=dict(task='RUNES_K123_EXTENDED_DEPENDENCY_CLOSURE_77_79',
                pass_number=77,baseline=BASE,outcome='complete +16B3 leaf; +247B remains guest',
                law=law,entry_steps=[c['entry_step'] for c in cases],
                exit_steps=[c['exit_step'] for c in cases],
                FACTOR_REL_sha256=base.GOLDEN,
                knowledge_promotions=0,native_roots_installed=0,
                oracle_queries=0,full_trigger=False,
                next_dependency='+245D, then +7D31',
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
