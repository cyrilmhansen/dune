#!/usr/bin/env python3
"""Complete +245D and natural common +247B prefix, with isolated proof outputs."""
import json
import os
import subprocess
from pathlib import Path
import run_k123_child_pass_76 as base
BASE='0f2e81d60073ebcbb3d964ef3ed6ef515dd9a80f'
OUT=Path('_build/host-compiler-pass-84');CAPTURE=OUT/'capture'
REPORT=Path('research/host-compiler/pass-84')

def prove(images='/home/john/pli/cpm/pli80/DISK1'):
    OUT.mkdir(parents=True,exist_ok=True)
    if not (CAPTURE/'handler-steps.jsonl').exists():
        if CAPTURE.exists():raise RuntimeError('incomplete isolated capture')
        CAPTURE.mkdir()
        subprocess.run(['dune','build','bin/k123_handler_capture.exe'],check=True)
        subprocess.run(['_build/default/bin/k123_handler_capture.exe','--images',str(images),'--output',str(CAPTURE)],check=True)
    if not os.environ.get('RUNES_HOST_IMAGES'):
        subprocess.run(['dune','build','bin/k123_245d_proof.exe','bin/k123_247b_prefix_proof.exe'],check=True,stdout=subprocess.DEVNULL)
    assert base.sha((CAPTURE/'FACTOR.rel').read_bytes())==base.GOLDEN
    rows=[json.loads(line) for line in (CAPTURE/'handler-steps.jsonl').read_text().splitlines()]
    old=base.load('research/host-compiler/pass-75/execution-boundary-proof.json')
    cases=[]
    for number in (1,2):
        whole=[r for r in rows if r['case']==number];archived=old['cases'][number-1]
        assert base.digest(whole)==archived['trace_sha256']
        initial=(CAPTURE/f'case-{number}-entry.ram').read_bytes()
        assert len(initial)==65536 and base.sha(initial)==archived['handler_entry_RAM_sha256']
        gate=next(i for i,r in enumerate(whole) if r['offset']==0x24bc)
        finish=next(i+1 for i,r in enumerate(whole) if r['offset'] in (0x24c6,0x24d5))
        start245d=next(i for i,r in enumerate(whole) if r['offset']==0x245d)
        def shadow(label,start,end,binary,synthetics):
            window=whole[start:end];ram=bytearray(initial);base.replay(ram,whole[:start])
            entry=OUT/f'case-{number}-{label}-entry.ram';entry.write_bytes(ram);before=base.sha(ram)
            reads,writes=base.replay(ram,window)
            exit_path=OUT/f'case-{number}-{label}-return.ram';exit_path.write_bytes(ram)
            journal=OUT/f'case-{number}-{label}-cpu.csv';proof_path=OUT/f'case-{number}-{label}-proof.json'
            subprocess.run(['_build/default/bin/'+binary+'.exe','--pli2',str(Path(images)/'PLI2.OVL'),
                            '--ram',str(entry),'--expected-ram',str(exit_path),'--journal',str(journal),
                            '--output',str(proof_path),*base.args('',window[0]['before']),
                            *base.args('expected-',whole[end]['before'])],check=True)
            expected=[('R' if a['kind']=='read' else 'W',a['address'],a['value']) for r in window for a in r['accesses']]
            actual=[(k,int(a),int(v)) for k,a,v in (line.split(',') for line in journal.read_text().splitlines())]
            assert actual==expected
            proof=base.load(proof_path);assert proof['natural_passed'] and proof['synthetic_cases']==synthetics
            return dict(entry=window[0]['before'],returned=whole[end]['before'],
                        instructions=len(window),reads=reads,writes=writes,proof=proof,
                        entry_RAM_sha256=before,return_RAM_sha256=base.sha(ram),
                        fresh_CPU_accesses_match_capture=True,ordered_access_sha256=base.digest(expected))
        child=shadow('245d',start245d,gate,'k123_245d_proof',3)
        assert (child['instructions'],child['reads'],child['writes'])==(98,36,22)
        prefix=shadow('prefix',1,finish,'k123_247b_prefix_proof',2)
        assert (prefix['instructions'],prefix['reads'],prefix['writes'])==((1889 if number==1 else 1888),689,449)
        assert prefix['returned']['pc'] in (0xa5dc,0xa3aa)
        assert archived['BDOS_record_events']==0
        cases.append(dict(case=number,child245d=child,prefix=prefix,
                          remaining_target=f"PLI2.OVL+{prefix['returned']['pc']-0x2200:04X}",
                          DMA=archived['DMA'],filesystem_sha256=archived['filesystem_sha256'],BDOS_events=0))
    evidence=dict(baseline=BASE,capture=str(CAPTURE),capture_integrity_verified=True,
                  FACTOR_REL_sha256=base.GOLDEN,cases=cases,complete_245D_natural=True,
                  complete_247B=False,native_roots_installed=0)
    base.save(REPORT/'natural-shadow.json',evidence)
    base.save(REPORT/'implementation-packet.json',dict(
        baseline=BASE,pass_number=84,operations=['full245D','common247B prefix through selected child CALL'],
        reused=['047D','052C','Pass77 16B3','resident1A29','Pass83 7D31','Pass78 tail','Pass76 branch'],
        law='actual PUSH H and PSW ownership; predicate mask; canonical child effects; fresh saved index ->052C ->245D tail; RAR selects actual branch',
        natural_child_shadows=2,natural_prefix_shadows=2,synthetic_child_shadows=6,synthetic_prefix_shadows=4,
        unsupported=['initial predicate-clear path','zero difference bypass','unexecuted83DC/81AA descendants'],
        knowledge_promotions=0,native_roots_installed=0,oracle_queries=0,
        next=['83DC subtraction leaf','81C0 emission adapter','81AA/8187 structure adapter','742A']))
    assert (REPORT/'implementation-packet.json').stat().st_size<28672
    return evidence
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);prove(p.parse_args().images)
