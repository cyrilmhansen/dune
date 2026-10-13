#!/usr/bin/env python3
"""Proof-only, copied k123 gateway transaction and unchanged k23 scope audit."""
import json
import os
import subprocess
from pathlib import Path
import run_k123_child_pass_76 as base
BASE='192333cf574b333ed8cefbca34dd9ebeea77e2b1'
OUT=Path('_build/host-compiler-pass-86')
REPORT=Path('research/host-compiler/pass-86')

def prove(images='/home/john/pli/cpm/pli80/DISK1'):
    OUT.mkdir(parents=True,exist_ok=True)
    if not os.environ.get('RUNES_HOST_IMAGES'):
        subprocess.run(['dune','build','bin/k123_gateway_capture.exe','bin/k123_gateway_proof.exe'],check=True,stdout=subprocess.DEVNULL)
    inventory=[]
    for source in ['MINIMAL','FIZZBUZ','PICTURE','FACTOR','OPTIMIST']:
        capture=OUT/'capture'/source
        complete=capture/'complete.json'
        if not complete.exists():
            capture.mkdir(parents=True,exist_ok=True)
            subprocess.run(['_build/default/bin/k123_gateway_capture.exe','--images',str(images),'--output',str(capture),'--source',source],check=True)
            base.save(complete,{p.name:base.sha(p.read_bytes()) for p in capture.iterdir() if p.is_file()})
        for name,digest in base.load(complete).items():
            assert base.sha((capture/name).read_bytes())==digest, (source,name)
        inventory.extend(json.loads(s) for s in (capture/'inventory.jsonl').read_text().splitlines())
    capture=OUT/'capture'/'FACTOR'
    assert base.sha((capture/'FACTOR.rel').read_bytes())==base.GOLDEN
    rows=[json.loads(s) for s in (capture/'gateway-steps.jsonl').read_text().splitlines()]
    boundaries=[json.loads(s) for s in (capture/'gateway-boundaries.jsonl').read_text().splitlines()]
    published=base.load('research/host-compiler/pass-71/frames.json')
    # Published frame schema is immutable; use actual historical facts.
    if isinstance(published,dict):published=published['frames']
    old=base.load('research/host-compiler/pass-75/execution-boundary-proof.json')['cases']
    cases=[]
    for number in (1,2):
        window=[r for r in rows if r['case']==number]
        before=next(b for b in boundaries if b['case']==number and b['boundary']=='entry')
        after=next(b for b in boundaries if b['case']==number and b['boundary']=='exit')
        before.pop('transfer',None)  # legacy capture field belongs to a prior gateway, never this entry
        archived=next(f for f in published if f['source']=='FACTOR' and f['entry_step']==before['step'])
        initial=(capture/f'case-{number}-entry.ram').read_bytes()
        ram=bytearray(initial);reads,writes=base.replay(ram,window)
        assert len(initial)==65536 and base.sha(initial)==archived['entry_RAM_sha256']
        assert base.sha(ram)==archived['exit_RAM_sha256']
        assert bytes(ram)==(capture/f'case-{number}-exit.ram').read_bytes()
        start=next(i for i,r in enumerate(window) if r['offset']==0x256e)
        end=next(i+1 for i,r in enumerate(window) if r['offset']==0x259a)
        assert base.digest(window[start:end])==old[number-1]['trace_sha256']
        assert before['DMA']==after['DMA'] and before['filesystem_sha256']==after['filesystem_sha256']
        assert after['service_events']==0 and not any(r['before']['pc']==5 for r in window)
        assert window[0]['before']==before['state'] and window[-1]['after']==after['state']
        handler_ram=bytearray(initial);base.replay(handler_ram,window[:start])
        index=handler_ram[0xaab0+handler_ram[0xad0d]]
        pointer=handler_ram[0xa795+index]|handler_ram[0xa7f8+index]<<8
        journal=OUT/f'case-{number}-cpu.csv';proof_path=OUT/f'case-{number}-proof.json'
        subprocess.run(['_build/default/bin/k123_gateway_proof.exe',
                        '--handler-c0',str(handler_ram[0xad0c]),'--discriminant-address',str(pointer+3),'--call-site',str(before['call_site']),
                        '--com',str(Path(images)/'PLI.COM'),'--pli2',str(Path(images)/'PLI2.OVL'),
                        '--ram',str(capture/f'case-{number}-entry.ram'),
                        '--expected-ram',str(capture/f'case-{number}-exit.ram'),
                        '--journal',str(journal),'--output',str(proof_path),
                        *base.args('',before['state']),*base.args('expected-',after['state'])],check=True)
        expected=[('R' if a['kind']=='read' else 'W',a['address'],a['value']) for r in window for a in r['accesses']]
        actual=[(k,int(a),int(v)) for k,a,v in (s.split(',') for s in journal.read_text().splitlines())]
        assert actual==expected
        calls=[dict(offset=r['offset'],target=r['target'],sp=r['after']['sp']) for r in window if r['kind']=='call' and r['taken']]
        assert sum(c['offset']==0x1fa9 for c in calls)==2
        assert not any(c['offset']==0x2037 for c in calls)
        software_push=next(r for r in window if r['offset']==0x20af)
        software_ret=next(r for r in window if r['offset']==0x259a)
        assert software_ret['after']['pc']==0x42b4
        assert software_push['accesses']==[
            dict(kind='write',address=software_push['before']['sp']-1,value=0x42),
            dict(kind='write',address=software_push['before']['sp']-2,value=0xb4)]
        assert after['state']['pc']==before['call_site']+3
        assert after['state']['sp']==before['state']['sp']+2
        assert not any(a['address'] in [before['state']['sp'],before['state']['sp']+1]
                       for r in window for a in r['accesses'] if a['kind']=='write')
        cases.append(dict(case=number,entry=before,returned=after,instructions=len(window),reads=reads,writes=writes,
                          hardware_CALLs=len(calls),CALL_chronology_sha256=base.digest(calls),
                          gateway_direct_CALLs=[c for c in calls if c['offset'] in [0x1fde,0x2037,0x2085]],software_push=software_push,software_RET=software_ret,
                          trace_sha256=base.digest(window),ordered_access_sha256=base.digest(expected),
                          independent_CPU_accesses_match_capture=True,proof=base.load(proof_path),
                          canonical_index=archived['k'],descriptor=archived['descriptor'],handler=archived['handler'],
                          fallback_pointer=archived['fallback_pointer'],predicate_tokens=archived['predicate_tokens']))
    sources=[]
    for source in sorted({r['source'] for r in inventory}):
        rs=[r for r in inventory if r['source']==source]
        assert not any(r['k23'] and r['k123'] for r in rs)
        sources.append(dict(source=source,roots=len(rs),k23=sum(r['k23'] for r in rs),
                            k123=sum(r['k123'] for r in rs),declined=sum(not(r['k23'] or r['k123']) for r in rs)))
    evidence=dict(baseline=BASE,cases=cases,mixed_inventory=sources,inventory_sha256=base.digest(inventory),
                  capture_integrity_verified=True,FACTOR_REL_sha256=base.GOLDEN,
                  native_roots_installed=0,knowledge_promotions=0,oracle_queries=0)
    base.save(REPORT/'natural-shadow.json',evidence)
    return evidence
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);prove(p.parse_args().images)
