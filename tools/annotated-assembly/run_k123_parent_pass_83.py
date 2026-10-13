#!/usr/bin/env python3
"""Scoped +7D31 parent proof, isolated capture and fresh CPU access journal."""
import json
import os
import subprocess
from pathlib import Path
import run_k123_child_pass_76 as base

BASE='6c1d20870589bb50aa0396eb59546199ed55d065'
OUT=Path('_build/host-compiler-pass-83')
CAPTURE=OUT/'capture'
REPORT=Path('research/host-compiler/pass-83')

def prove(images='/home/john/pli/cpm/pli80/DISK1'):
    OUT.mkdir(parents=True,exist_ok=True)
    if not (CAPTURE/'handler-steps.jsonl').exists():
        if CAPTURE.exists():
            raise RuntimeError('incomplete isolated capture')
        CAPTURE.mkdir()
        subprocess.run(['dune','build','bin/k123_handler_capture.exe'],check=True)
        subprocess.run(['_build/default/bin/k123_handler_capture.exe',
                        '--images',str(images),'--output',str(CAPTURE)],check=True)
    if not os.environ.get('RUNES_HOST_IMAGES'):
        subprocess.run(['dune','build','bin/k123_7d31_proof.exe'],check=True,
                       stdout=subprocess.DEVNULL)
    assert base.sha((CAPTURE/'FACTOR.rel').read_bytes())==base.GOLDEN
    rows=[json.loads(line) for line in (CAPTURE/'handler-steps.jsonl').read_text().splitlines()]
    old=base.load('research/host-compiler/pass-75/execution-boundary-proof.json')
    cases=[]
    for number in (1,2):
        whole=[r for r in rows if r['case']==number]
        archived=old['cases'][number-1]
        assert base.digest(whole)==archived['trace_sha256']
        ram=bytearray((CAPTURE/f'case-{number}-entry.ram').read_bytes())
        assert len(ram)==65536 and base.sha(ram)==archived['handler_entry_RAM_sha256']
        start=next(i for i,r in enumerate(whole) if r['offset']==0x7d31)
        finish=next(i for i in range(start,len(whole)) if whole[i]['offset']==0x24b5)
        window=whole[start:finish]
        assert len(window)==1550 and window[-1]['offset']==0x7d46
        assert whole[start-1]['offset']==0x24b2 and whole[start-1]['target']==0x9f31
        base.replay(ram,whole[:start])
        entry=OUT/f'case-{number}-entry.ram';entry.write_bytes(ram)
        before=base.sha(ram)
        reads,writes=base.replay(ram,window)
        assert (reads,writes)==(568,368)
        exit_path=OUT/f'case-{number}-return.ram';exit_path.write_bytes(ram)
        journal=OUT/f'case-{number}-cpu-accesses.csv'
        proof_path=OUT/f'case-{number}-proof.json'
        subprocess.run(['_build/default/bin/k123_7d31_proof.exe',
                        '--pli2',str(Path(images)/'PLI2.OVL'),
                        '--ram',str(entry),'--expected-ram',str(exit_path),
                        '--journal',str(journal),'--output',str(proof_path),
                        *base.args('',window[0]['before']),
                        *base.args('expected-',whole[finish]['before'])],check=True)
        expected=[('R' if a['kind']=='read' else 'W',a['address'],a['value'])
                  for r in window for a in r['accesses']]
        actual=[(kind,int(address),int(value)) for kind,address,value in
                (line.split(',') for line in journal.read_text().splitlines())]
        assert actual==expected
        proof=base.load(proof_path)
        assert proof['natural_passed'] and proof['synthetic_cases']==4
        child_states=[dict(site=f"{r['offset']:04X}",entry=r['after'])
                      for r in window if r['offset'] in (0x7d3b,0x7d43)]
        assert [c['site'] for c in child_states]==['7D3B','7D43']
        assert archived['BDOS_record_events']==0
        assert not any(r['before']['pc']==5 for r in window)
        cases.append(dict(case=number,entry=window[0]['before'],
                          returned=whole[finish]['before'],children=child_states,
                          entry_RAM_sha256=before,return_RAM_sha256=base.sha(ram),
                          instructions=len(window),reads=reads,writes=writes,
                          ordered_access_sha256=base.digest(expected),
                          fresh_CPU_accesses_match_capture=True,proof=proof,
                          DMA=archived['DMA'],filesystem_sha256=archived['filesystem_sha256'],
                          BDOS_events=0))
    evidence=dict(baseline=BASE,capture=str(CAPTURE),capture_integrity_verified=True,
                  FACTOR_REL_sha256=base.GOLDEN,cases=cases,
                  complete_natural_7D31=True,native_roots_installed=0)
    base.save(REPORT/'natural-shadow.json',evidence)
    base.save(REPORT/'implementation-packet.json',dict(
        baseline=BASE,pass_number=83,operation='PLI2.OVL+7D31',
        law='save E/C at AE31/AE30; fresh E -> canonical052C; XCHG; fresh C -> complete7D05; RET original hardware word',
        reused=['canonical052C','Pass82 complete7D05'],
        natural_shadows=2,synthetic_shadows=8,knowledge_promotions=0,
        native_roots_installed=0,oracle_queries=0,
        limitations=['inherited output/pointer/code/frame domains','no247B or gateway installation'],
        next='full245D and branch descendants under247B'))
    assert (REPORT/'implementation-packet.json').stat().st_size<28672
    return evidence

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--images',required=True)
    prove(parser.parse_args().images)
