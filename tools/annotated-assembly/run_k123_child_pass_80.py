#!/usr/bin/env python3
"""Pass80: verified FACTOR capture, canonical +73A7, composed CPU shadow."""
import json
import os
import subprocess
from pathlib import Path
import run_k123_child_pass_76 as base

BASE = 'c0bf5f5e30aa00c8500131f8366b45a776da310f'
CAPTURE = Path('_build/host-compiler-pass-80/capture')
OUT = Path('_build/host-compiler-pass-80')
REPORT = Path('research/host-compiler/pass-80')

def prove(images='/home/john/pli/cpm/pli80/DISK1'):
    OUT.mkdir(parents=True, exist_ok=True)
    if not (CAPTURE/'handler-steps.jsonl').is_file():
        if CAPTURE.exists():
            raise RuntimeError('incomplete isolated Pass80 capture')
        CAPTURE.mkdir(parents=True)
        subprocess.run(['dune','build','bin/k123_handler_capture.exe'],check=True)
        subprocess.run(['_build/default/bin/k123_handler_capture.exe',
                        '--images',str(images),'--output',str(CAPTURE)],check=True)
    if not os.environ.get('RUNES_HOST_IMAGES'):
        subprocess.run(['dune','build','bin/k123_7d05_clear_proof.exe'],check=True,
                       stdout=subprocess.DEVNULL)
    if base.sha((CAPTURE/'FACTOR.rel').read_bytes()) != base.GOLDEN:
        raise AssertionError('FACTOR REL golden changed')
    with (CAPTURE/'handler-steps.jsonl').open() as journal:
        rows = [json.loads(line) for line in journal]
    archived = base.load('research/host-compiler/pass-75/execution-boundary-proof.json')
    cases = []
    for number in (1,2):
        whole = [row for row in rows if row['case']==number]
        original = archived['cases'][number-1]
        assert base.digest(whole)==original['trace_sha256']
        start = next(i for i,row in enumerate(whole) if row['offset']==0x7d05)
        finish = next(i for i in range(start,len(whole))
                      if whole[i]['offset']==0x7d1f)
        window = whole[start:finish]
        assert len(window)==46
        assert [(r['offset'],r['target']) for r in window if r['kind']=='call']==[
            (0x7d15,0x9c17),(0x7d1c,0x95a7),
            (0x73b8,0x9597),(0x73c0,0x9597)]
        assert window[0]['before']['c']==4
        assert window[-1]['offset']==0x73c3 and window[-1]['kind']=='return'
        assert window[-1]['after']==whole[finish]['before']
        assert window[-1]['accesses']==[
            {'kind':'read','address':window[-1]['before']['sp'],'value':0x1f},
            {'kind':'read','address':window[-1]['before']['sp']+1,'value':0x9f}]
        sp=window[0]['before']['sp']
        read_sites=[(r['offset'],a['address']) for r in window
                    for a in r['accesses'] if a['kind']=='read']
        assert read_sites==[
            (0x7d0d,0xae2d),(0x7a17,0xae04),
            (0x7a1f,sp-2),(0x7a1f,sp-1),
            (0x7d18,0xae2d),(0x7d18,0xae2e),
            (0x73ab,0xadc3),(0x73b4,0xadc3),(0x73b4,0xadc4),
            (0x739b,0xadc2),(0x739b,0xadc3),
            (0x73a6,sp-4),(0x73a6,sp-3),
            (0x73bb,0xadc3),(0x739b,0xadc2),(0x739b,0xadc3),
            (0x73a6,sp-4),(0x73a6,sp-3),
            (0x73c3,sp-2),(0x73c3,sp-1)]
        ram=bytearray((CAPTURE/f'case-{number}-entry.ram').read_bytes())
        assert len(ram)==65536
        base.replay(ram,whole[:start])
        entry=OUT/f'case-{number}-front.ram';entry.write_bytes(ram)
        assert ram[0x201d]&1==0 and ram[0x2029]&1==0 and ram[0x1c2c]!=0
        assert window[0]['before']['sp']>=0xb000
        before=base.sha(ram)
        reads,writes=base.replay(ram,window)
        assert (reads,writes)==(20,16)
        after=base.sha(ram)
        exit_path=OUT/f'case-{number}-clear-return.ram';exit_path.write_bytes(ram)
        proof_path=OUT/f'case-{number}-clear-proof.json'
        subprocess.run(['_build/default/bin/k123_7d05_clear_proof.exe',
                        '--ram',str(entry),'--expected-ram',str(exit_path),
                        '--output',str(proof_path),
                        *base.args('',window[0]['before']),
                        *base.args('expected-',whole[finish]['before'])],check=True)
        proof=base.load(proof_path)
        assert proof['natural_passed'] and proof['synthetic_cases']==5
        calls=[dict(site=f"{r['offset']:04X}",target=f"{r['target']:04X}",
                    sp=r['after']['sp'],continuation=r['before']['pc']+3)
               for r in window if r['kind']=='call']
        cases.append(dict(case=number,entry=window[0]['before'],
                          return_state=whole[finish]['before'],
                          entry_RAM_sha256=before,return_RAM_sha256=after,
                          instructions=len(window),ordered_reads=reads,
                          ordered_read_sites=read_sites,
                          ordered_writes=writes,hardware_calls=calls,
                          actual_index=window[0]['before']['c'],
                          inherited_201D=ram[0x201d],
                          inherited_2029=ram[0x2029],
                          proof=proof,DMA=original['DMA'],
                          filesystem_sha256=original['filesystem_sha256'],
                          service_events=0))
    evidence=dict(baseline=BASE,capture=str(CAPTURE),
                  capture_digests_match_Pass75=True,
                  FACTOR_REL_sha256=base.GOLDEN,
                  operation='PLI2.OVL+7D05 front through +73A7 return',
                  canonical_children=['PLI2.OVL+73A7','PLI2.OVL+7397'],
                  cases=cases,full_7D05=False,native_roots_installed=0)
    base.save(REPORT/'natural-shadow.json',evidence)
    base.save(REPORT/'child-law.json',dict(
        operation='+7D05 front plus canonical +73A7 non-6 and two +7397 clears',
        natural_index=4,synthetic_indices=[0,1,2,3,5],
        required=['immutable +73A7/+7397 code','index<6','safe high stack',
                  '201D and 2029 clear','nonzero output position',
                  'fresh ADC2/ADC3 reads and indexed ADAB writes'],
        unsupported=['index6 early RET','index7 second +7397 out of scope',
                     '+7A17 AE04 nonzero','later +75CE/+785C'],
        complete_73A7_natural=True,complete_7D05=False))
    base.save(REPORT/'implementation-packet.json',dict(
        task='RUNES_PLI2_7D05_COMPOSITION_PASS80_82',pass_number=80,
        baseline=BASE,executable='Pass79 front plus reused Pass57 +73A7/+7397',
        natural_shadows=2,synthetic_shadows=10,
        first_uncomposed='PLI2.OVL+7D1F before +75CE',
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
