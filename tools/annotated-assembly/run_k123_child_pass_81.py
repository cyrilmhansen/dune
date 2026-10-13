#!/usr/bin/env python3
"""Pass81: actual +75CE output state and composed canonical CPU shadows."""
import json
import os
import subprocess
from pathlib import Path
import run_k123_child_pass_76 as base

BASE='f2cef443f244b732600aa47da8ae7a46978db000'
OUT=Path('_build/host-compiler-pass-81')
CAPTURE=OUT/'capture'
REPORT=Path('research/host-compiler/pass-81')

def prove(images='/home/john/pli/cpm/pli80/DISK1'):
    OUT.mkdir(parents=True,exist_ok=True)
    if not (CAPTURE/'handler-steps.jsonl').is_file():
        if CAPTURE.exists():
            raise RuntimeError('incomplete isolated Pass81 capture')
        CAPTURE.mkdir(parents=True)
        subprocess.run(['dune','build','bin/k123_handler_capture.exe'],check=True)
        subprocess.run(['_build/default/bin/k123_handler_capture.exe',
                        '--images',str(images),'--output',str(CAPTURE)],check=True)
    if not os.environ.get('RUNES_HOST_IMAGES'):
        subprocess.run(['dune','build','bin/k123_7d05_emit_proof.exe'],check=True,
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
        start=next(i for i,r in enumerate(whole) if r['offset']==0x7d05)
        finish=next(i for i in range(start,len(whole))
                    if whole[i]['offset']==0x7d28)
        window=whole[start:finish]
        assert len(window)==487
        assert window[-1]['offset']==0x75f0 and window[-1]['kind']=='return'
        assert window[-1]['after']==whole[finish]['before']
        assert [(r['offset'],r['target']) for r in window if r['kind']=='call'
                and r['offset'] in (0x75d8,0x75df,0x75ed)]==[
                    (0x75d8,0x966f),(0x75df,0x96c7),(0x75ed,0x9757)]
        field_reads=[(r['offset'],a['address'],a['value'])
                     for r in window for a in r['accesses']
                     if r['offset'] in (0x75d4,0x75db,0x75e2,0x75eb)
                     and a['kind']=='read']
        assert [(site,address) for site,address,_ in field_reads]==[
            (0x75d4,0xadd6),(0x75d4,0xadd7),
            (0x75db,0xadd7),(0x75db,0xadd8),
            (0x75e2,0xadd7),(0x75eb,0xadd6)]
        ram=bytearray((CAPTURE/f'case-{number}-entry.ram').read_bytes())
        assert len(ram)==65536
        base.replay(ram,whole[:start])
        entry=OUT/f'case-{number}-front.ram';entry.write_bytes(ram)
        before=base.sha(ram)
        emit_index=next(i for i,r in enumerate(window) if r['offset']==0x75ce)
        base.replay(ram,window[:emit_index])
        output_before=dict(record=ram[0x1d8a],bit=ram[0x1d8b],
                           position=ram[0x1c2c]|ram[0x1c2d]<<8,
                           buffer_sha256=base.sha(bytes(ram[0x1d0a:0x1d8a])))
        assert ram[0x201d]&1==0 and ram[0x2029]&1==0
        assert ram[0x1d8a]<=125 and ram[0x1d8b]<8
        emit_entry=window[emit_index]['before']
        assert (emit_entry['c'],emit_entry['e'])==(1,4)
        emit_window=window[emit_index:]
        assert len(emit_window)==437
        assert sum(a['kind']=='read' for r in emit_window for a in r['accesses'])==160
        assert sum(a['kind']=='write' for r in emit_window for a in r['accesses'])==101
        base.replay(ram,emit_window)
        output_after=dict(record=ram[0x1d8a],bit=ram[0x1d8b],
                          position=ram[0x1c2c]|ram[0x1c2d]<<8,
                          buffer_sha256=base.sha(bytes(ram[0x1d0a:0x1d8a])))
        after=base.sha(ram)
        exit_path=OUT/f'case-{number}-emit-return.ram';exit_path.write_bytes(ram)
        proof_path=OUT/f'case-{number}-emit-proof.json'
        subprocess.run(['_build/default/bin/k123_7d05_emit_proof.exe',
                        '--ram',str(entry),'--expected-ram',str(exit_path),
                        '--output',str(proof_path),
                        *base.args('',window[0]['before']),
                        *base.args('expected-',whole[finish]['before'])],check=True)
        proof=base.load(proof_path)
        assert proof['natural_passed'] and proof['synthetic_cases']==4
        cases.append(dict(case=number,entry=window[0]['before'],
                          emit_entry=emit_entry,return_state=whole[finish]['before'],
                          entry_RAM_sha256=before,return_RAM_sha256=after,
                          composed_steps=len(window),
                          ordered_reads=sum(a['kind']=='read' for r in window for a in r['accesses']),
                          ordered_writes=sum(a['kind']=='write' for r in window for a in r['accesses']),
                          emit_steps=len(emit_window),field_reads=field_reads,
                          output_before=output_before,output_after=output_after,
                          proof=proof,DMA=old['DMA'],
                          filesystem_sha256=old['filesystem_sha256'],
                          BDOS_events=0))
    evidence=dict(baseline=BASE,capture=str(CAPTURE),
                  capture_digests_match_Pass75=True,
                  FACTOR_REL_sha256=base.GOLDEN,
                  operation='PLI2.OVL+7D05 front through +75CE return',
                  canonical_reused=['+73A7','+7397','+75CE','+746F','+74C7',
                                    '+7557','+1140','+119E','+753C'],
                  cases=cases,full_7D05=False,native_roots_installed=0)
    base.save(REPORT/'natural-shadow.json',evidence)
    base.save(REPORT/'child-law.json',dict(
        operation='Pass80 prefix; fresh +7D1F AE2D/AE2E reload and XCHG; C=1; canonical +75CE',
        fresh_field_reads=['ADD6/ADD7 at +75D4','ADD7/ADD8 at +75DB',
                           'ADD7 at +75E2','ADD6 at +75EB'],
        natural_carriers={'C':1,'E':4,'emitted_field_byte':0x21},
        output_scope='201D/2029 clear, record cursor<=125, bit<8, nonzero nonwrapping position, nonalias stack/sentinel',
        natural_shadows=2,synthetic_shadows=8,
        unsupported=['writer error','record flush','gate-set arms',
                     'position wrap','output and stack aliases','later +785C'],
        complete_75CE_natural=True,complete_7D05=False))
    base.save(REPORT/'implementation-packet.json',dict(
        task='RUNES_PLI2_7D05_COMPOSITION_PASS80_82',pass_number=81,
        baseline=BASE,executable='Pass80 prefix through canonical Pass54 +75CE return',
        natural_shadows=2,synthetic_shadows=8,
        first_uncomposed='PLI2.OVL+7D28 before +785C',
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
