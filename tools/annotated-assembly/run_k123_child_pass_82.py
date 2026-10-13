#!/usr/bin/env python3
"""Pass82: canonical +785C/+77CC and scoped full +7D05 CPU composition."""
import json
import os
import subprocess
from pathlib import Path
import run_k123_child_pass_76 as base

BASE='963afd14bfeb92017949a00cdf390fc6c272d1fe'
OUT=Path('_build/host-compiler-pass-82')
CAPTURE=OUT/'capture'
REPORT=Path('research/host-compiler/pass-82')

def prove(images='/home/john/pli/cpm/pli80/DISK1'):
    OUT.mkdir(parents=True,exist_ok=True)
    if not (CAPTURE/'handler-steps.jsonl').is_file():
        if CAPTURE.exists():
            raise RuntimeError('incomplete isolated Pass82 capture')
        CAPTURE.mkdir(parents=True)
        subprocess.run(['dune','build','bin/k123_handler_capture.exe'],check=True)
        subprocess.run(['_build/default/bin/k123_handler_capture.exe',
                        '--images',str(images),'--output',str(CAPTURE)],check=True)
    if not os.environ.get('RUNES_HOST_IMAGES'):
        subprocess.run(['dune','build','bin/k123_785c_proof.exe',
                        'bin/k123_7d05_complete_proof.exe'],check=True,
                       stdout=subprocess.DEVNULL)
    assert base.sha((CAPTURE/'FACTOR.rel').read_bytes())==base.GOLDEN
    with (CAPTURE/'handler-steps.jsonl').open() as journal:
        rows=[json.loads(line) for line in journal]
    archived=base.load('research/host-compiler/pass-75/execution-boundary-proof.json')
    cases=[]
    for number in (1,2):
        whole=[r for r in rows if r['case']==number]
        old=archived['cases'][number-1]
        assert base.digest(whole)==old['trace_sha256']
        assert old['BDOS_record_events']==0
        start=next(i for i,r in enumerate(whole) if r['offset']==0x7d05)
        finish=next(i for i in range(start,len(whole))
                    if whole[i]['offset']==0x7d46)
        full=whole[start:finish]
        assert len(full)==1455
        assert (full[0]['offset'],full[-1]['offset'])==(0x7d05,0x7d30)
        assert full[-1]['kind']=='return' and full[-1]['after']==whole[finish]['before']
        child_start=next(i for i in range(start,finish)
                         if whole[i]['offset']==0x785c)
        child_end=next(i for i in range(child_start,finish)
                       if whole[i]['offset']==0x7d30)
        child=whole[child_start:child_end]
        assert len(child)==963
        assert child[0]['offset']==0x785c and child[-1]['offset']==0x7896
        assert child[-1]['kind']=='return'
        assert child[-1]['after']==whole[child_end]['before']
        assert [(r['offset'],r['target']) for r in child
                if r['offset']==0x786d and r['kind']=='call']==[(0x786d,0x99cc)]
        assert [(r['offset'],r['target']) for r in child
                if r['offset'] in (0x77f3,0x7852) and r['kind']=='call']==[
                    (0x77f3,0xa542),(0x7852,0x985e)]
        assert sum(r['kind']=='call' for r in child)==31
        assert child[0]['before']['sp']+2==full[0]['before']['sp']
        assert child[-1]['after']['sp']==full[0]['before']['sp']
        assert full[-1]['after']['sp']==full[0]['before']['sp']+2
        ram=bytearray((CAPTURE/f'case-{number}-entry.ram').read_bytes())
        assert len(ram)==65536
        base.replay(ram,whole[:start])
        full_entry=OUT/f'case-{number}-7d05-entry.ram';full_entry.write_bytes(ram)
        full_before=base.sha(ram)
        base.replay(ram,whole[start:child_start])
        child_entry=OUT/f'case-{number}-785c-entry.ram';child_entry.write_bytes(ram)
        pointer=child[0]['before']['b']*256+child[0]['before']['c']
        assert pointer>=0xae6d and pointer+8<child[0]['before']['sp']-512
        pointed_bytes=list(ram[pointer:pointer+8])
        assert pointed_bytes[3]&0x1f==0x0c
        owned={r['offset']:r for r in child if r['offset'] in
               (0x77cf,0x77d1,0x77d2,0x77d5,0x77da,0x77e1,
                0x77e5,0x77ec,0x7858)}
        assert owned[0x77cf]['accesses']==[
            {'kind':'write','address':0xadf4,'value':pointer>>8}]
        assert owned[0x77d1]['accesses']==[
            {'kind':'write','address':0xadf3,'value':pointer&255}]
        assert owned[0x77d2]['accesses']==[
            {'kind':'read','address':0xadf3,'value':pointer&255},
            {'kind':'read','address':0xadf4,'value':pointer>>8}]
        assert owned[0x77d5]['accesses']==[
            {'kind':'write','address':0xac9f,'value':pointer&255},
            {'kind':'write','address':0xaca0,'value':pointer>>8}]
        assert owned[0x77da]['accesses']==[
            {'kind':'read','address':pointer+2,'value':pointed_bytes[2]}]
        assert owned[0x77e5]['accesses']==[
            {'kind':'read','address':pointer+3,'value':pointed_bytes[3]}]
        assert owned[0x7858]['accesses']==[
            {'kind':'write','address':0xadef,'value':0},
            {'kind':'write','address':0xadf0,'value':0}]
        child_before=base.sha(ram)
        child_reads,child_writes=base.replay(ram,child)
        assert (child_reads,child_writes)==(347,224)
        child_after=base.sha(ram)
        child_exit=OUT/f'case-{number}-785c-return.ram';child_exit.write_bytes(ram)
        child_proof_path=OUT/f'case-{number}-785c-proof.json'
        subprocess.run(['_build/default/bin/k123_785c_proof.exe',
                        '--pli2',str(Path(images)/'PLI2.OVL'),
                        '--ram',str(child_entry),'--expected-ram',str(child_exit),
                        '--output',str(child_proof_path),
                        *base.args('',child[0]['before']),
                        *base.args('expected-',whole[child_end]['before'])],check=True)
        child_proof=base.load(child_proof_path)
        assert child_proof['natural_passed']
        base.replay(ram,whole[child_end:finish])
        full_after=base.sha(ram)
        full_exit=OUT/f'case-{number}-7d05-return.ram';full_exit.write_bytes(ram)
        full_proof_path=OUT/f'case-{number}-7d05-proof.json'
        subprocess.run(['_build/default/bin/k123_7d05_complete_proof.exe',
                        '--pli2',str(Path(images)/'PLI2.OVL'),
                        '--ram',str(full_entry),'--expected-ram',str(full_exit),
                        '--output',str(full_proof_path),
                        *base.args('',full[0]['before']),
                        *base.args('expected-',whole[finish]['before'])],check=True)
        full_proof=base.load(full_proof_path)
        assert full_proof['natural_passed'] and full_proof['synthetic_cases']==4
        cases.append(dict(case=number,full_entry=full[0]['before'],
                          full_return=whole[finish]['before'],
                          full_steps=len(full),
                          full_reads=sum(a['kind']=='read' for r in full for a in r['accesses']),
                          full_writes=sum(a['kind']=='write' for r in full for a in r['accesses']),
                          full_hardware_calls=sum(r['kind']=='call' for r in full),
                          full_entry_RAM_sha256=full_before,
                          full_return_RAM_sha256=full_after,
                          full_proof=full_proof,
                          child_entry=child[0]['before'],
                          child_return=whole[child_end]['before'],
                          child_steps=len(child),
                          child_reads=child_reads,child_writes=child_writes,
                          child_hardware_calls=31,
                          child_entry_RAM_sha256=child_before,
                          child_return_RAM_sha256=child_after,
                          child_proof=child_proof,
                          actual_pointer=pointer,
                          pointed_bytes=pointed_bytes,
                          fresh_type=pointed_bytes[3]&0x1f,
                          pointer_last_writers=['+77CF -> ADF4',
                                                '+77D1 -> ADF3',
                                                '+77D5 -> AC9F/ACA0'],
                          total_785c_in_case=sum(r['offset']==0x785c for r in whole),
                          service_events=old['BDOS_record_events'],DMA=old['DMA'],
                          filesystem_sha256=old['filesystem_sha256']))
    evidence=dict(baseline=BASE,capture=str(CAPTURE),
                  capture_digests_match_Pass75=True,
                  FACTOR_REL_sha256=base.GOLDEN,
                  operation='PLI2.OVL+785C/+77CC and scoped complete +7D05',
                  canonical_reused=['Pass68 +785C/+77CC/+8342/+765E',
                                    'Pass81 +75CE prefix','Pass80 +73A7 prefix'],
                  cases=cases,full_7D05_natural=True,
                  full_7D31=False,full_247B=False,native_roots_installed=0)
    base.save(REPORT/'natural-shadow.json',evidence)
    base.save(REPORT/'child-law.json',dict(
        operation='fresh +7D28 AE2E/AE2F to BC; canonical +785C/+77CC; actual +7D30 RET',
        natural_pointer_source='BC saved by +77CC at ADF3/ADF4 then freshly reread',
        natural_type=0x0c,
        natural_child_route='+77F3 canonical +8342, +7852 canonical +765E',
        natural_785c_shadows=2,natural_full_7D05_shadows=2,
        synthetic_full_7D05_shadows=8,
        unsupported=['+77CC type 10h/11h','+785C listing-set',
                     'pointer/output/stack aliases','writer errors and record flush',
                     'other +785C invocation in second FACTOR capture',
                     'parent +7D31/+247B/+256E'],
        complete_785c_natural=True,complete_7D05_natural=True,
        complete_7D31=False))
    base.save(REPORT/'implementation-packet.json',dict(
        task='RUNES_PLI2_7D05_COMPOSITION_PASS80_82',pass_number=82,
        baseline=BASE,outcome='scoped +785C and full +7D05 natural composition',
        natural_child_shadows=2,natural_parent_shadows=2,
        synthetic_parent_shadows=8,
        next_boundary='PLI2.OVL+7D31 own +052C and +7D31/+7D46 instructions',
        evidence=['natural-shadow.json','child-law.json','validation.json'],
        knowledge_promotions=0,native_roots_installed=0,oracle_queries=0,
        FULL_status='Pass74 epoch 3; no FULL run'))
    assert (REPORT/'implementation-packet.json').stat().st_size<28672
    return evidence

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--images',default='/home/john/pli/cpm/pli80/DISK1')
    prove(parser.parse_args().images)
