#!/usr/bin/env python3
"""Scoped k123 branch, full +247B and software +256E closure."""
import json
import os
import subprocess
from pathlib import Path
import run_k123_child_pass_76 as base
BASE='c173fc70c00cea070828d67e0cda3d09945c1d21'
OUT=Path('_build/host-compiler-pass-85');CAPTURE=OUT/'capture'
REPORT=Path('research/host-compiler/pass-85')

def prove(images='/home/john/pli/cpm/pli80/DISK1'):
    OUT.mkdir(parents=True,exist_ok=True)
    if not (CAPTURE/'handler-steps.jsonl').exists():
        if CAPTURE.exists():raise RuntimeError('incomplete isolated capture')
        CAPTURE.mkdir()
        subprocess.run(['dune','build','bin/k123_handler_capture.exe'],check=True)
        subprocess.run(['_build/default/bin/k123_handler_capture.exe','--images',str(images),'--output',str(CAPTURE)],check=True)
    if not os.environ.get('RUNES_HOST_IMAGES'):
        subprocess.run(['dune','build','bin/k123_completion_proof.exe'],check=True,stdout=subprocess.DEVNULL)
    assert base.sha((CAPTURE/'FACTOR.rel').read_bytes())==base.GOLDEN
    rows=[json.loads(line) for line in (CAPTURE/'handler-steps.jsonl').read_text().splitlines()]
    boundaries=[json.loads(line) for line in (CAPTURE/'handler-boundaries.jsonl').read_text().splitlines()]
    old=base.load('research/host-compiler/pass-75/execution-boundary-proof.json')
    cases=[]
    for number in (1,2):
        whole=[r for r in rows if r['case']==number];archived=old['cases'][number-1]
        assert base.digest(whole)==archived['trace_sha256']
        initial=(CAPTURE/f'case-{number}-entry.ram').read_bytes()
        assert len(initial)==65536 and base.sha(initial)==archived['handler_entry_RAM_sha256']
        entry_service=next(r for r in boundaries if r['case']==number and r['boundary']=='entry')
        exit_service=next(r for r in boundaries if r['case']==number and r['boundary']=='exit')
        assert entry_service['DMA']==exit_service['DMA']==archived['DMA']
        assert entry_service['filesystem_sha256']==exit_service['filesystem_sha256']==archived['filesystem_sha256']
        assert exit_service['service_events']==0 and archived['BDOS_record_events']==0
        def shadow(label,start,end,mode,synthetics):
            window=whole[start:end];ram=bytearray(initial);base.replay(ram,whole[:start])
            entry=OUT/f'case-{number}-{label}-entry.ram';entry.write_bytes(ram);before=base.sha(ram)
            scope=dict(output_index=ram[0x1d8a],output_bit=ram[0x1d8b],
                       position=ram[0x1c2c]|ram[0x1c2d]<<8,
                       mode201D=ram[0x201d],mode2029=ram[0x2029],
                       pendingAE04=ram[0xae04],preparationAE05=ram[0xae05])
            reads,writes=base.replay(ram,window)
            exit_path=OUT/f'case-{number}-{label}-return.ram';exit_path.write_bytes(ram)
            journal=OUT/f'case-{number}-{label}-cpu.csv';proof_path=OUT/f'case-{number}-{label}-proof.json'
            subprocess.run(['_build/default/bin/k123_completion_proof.exe','--operation',mode,
                            '--com',str(Path(images)/'PLI.COM'),'--pli2',str(Path(images)/'PLI2.OVL'),
                            '--ram',str(entry),'--expected-ram',str(exit_path),'--journal',str(journal),
                            '--output',str(proof_path),*base.args('',window[0]['before']),
                            *base.args('expected-',window[-1]['after'])],check=True)
            expected=[('R' if a['kind']=='read' else 'W',a['address'],a['value']) for r in window for a in r['accesses']]
            actual=[(k,int(a),int(v)) for k,a,v in (line.split(',') for line in journal.read_text().splitlines())]
            assert actual==expected
            proof=base.load(proof_path);assert proof['natural_passed'] and proof['synthetic_cases']==synthetics
            assert not any(r['before']['pc']==5 for r in window)
            return dict(entry=window[0]['before'],returned=window[-1]['after'],
                        instructions=len(window),reads=reads,writes=writes,
                        hardware_CALLs=sum(r['kind']=='call' and r['taken'] for r in window),proof=proof,entry_scope=scope,
                        entry_RAM_sha256=before,return_RAM_sha256=base.sha(ram),
                        fresh_CPU_accesses_match_capture=True,ordered_access_sha256=base.digest(expected))
        parent_end=next(i+1 for i,r in enumerate(whole) if r['offset']==0x256d)
        parent=shadow('247b',1,parent_end,'parent',2)
        handler=shadow('256e',0,len(whole),'handler',2)
        assert (parent['instructions'],parent['reads'],parent['writes'],parent['hardware_CALLs'])==(
            (3238,1185,768,133) if number==1 else (3413,1247,808,140))
        assert (handler['instructions'],handler['reads'],handler['writes'],handler['hardware_CALLs'])==(
            (3263,1196,775,135) if number==1 else (3438,1258,815,142))
        assert parent['returned']['pc']==0x4771 and parent['returned']['sp']==parent['entry']['sp']+2
        assert handler['returned']==archived['handler_exit_state']
        assert handler['return_RAM_sha256']==archived['handler_exit_RAM_sha256']
        assert handler['returned']['pc']==0x42b4 and handler['returned']['sp']==handler['entry']['sp']+2
        components={}
        selected=[(0x83dc,0x24d8,'leaf',10),(0x81c0,0x24e4,'generation',2),(0x742a,0x24f3,'generation',2)] if number==1 else [(0x81aa,0x24c9,'generation',2),(0x8187,0x81bf,'generation',2)]
        for offset,resume,mode,synthetics in selected:
            start=next(i for i,r in enumerate(whole) if r['offset']==offset)
            end=next(i for i in range(start,len(whole)) if whole[i]['offset']==resume)
            components[f'{offset:04X}']=shadow(f'{offset:x}',start,end,mode,synthetics)
        extra_structure=None
        if number==2:
            entries=[i for i,r in enumerate(whole) if r['offset']==0x785c]
            assert len(entries)==2
            index=entries[1];ram=bytearray(initial);base.replay(ram,whole[:index])
            state=whole[index]['before'];pointer=state['b']*256+state['c']
            assert pointer>=0xf000 and pointer+8<state['sp']-512
            assert ram[pointer+3]&31==8
            extra_structure=dict(entry=state,pointer=pointer,
                                 pointed_type=ram[pointer+3],masked_type=8,
                                 required_child='canonical7630 via +7832',
                                 scope='only within the independently shadowed81AA/8187 window')
        cases.append(dict(case=number,parent=parent,handler=handler,components=components,
                          extra_structure=extra_structure,
                          canonical_index=archived['canonical_index'],descriptor_pointer=archived['descriptor_pointer'],
                          software_transfer=archived['software_transfer'],software_word_writers=archived['software_word_writers'],
                          original_hardware_continuation=archived['original_hardware_continuation'],
                          DMA=archived['DMA'],filesystem_sha256=archived['filesystem_sha256'],service_events=0))
    evidence=dict(baseline=BASE,capture=str(CAPTURE),capture_integrity_verified=True,
                  FACTOR_REL_sha256=base.GOLDEN,cases=cases,complete_natural_247B=True,
                  complete_natural_256E=True,native_roots_installed=0)
    base.save(REPORT/'natural-shadow.json',evidence)
    base.save(REPORT/'implementation-packet.json',dict(
        baseline=BASE,pass_number=85,operations=['83DC subtraction','81C0 saved-word emission','81AA/8187 mapped structure emission','complete247B','software256E'],
        new_laws=['instruction-derived83DC low SUB/high SBB with inherited borrow','fresh saved carriers and canonical child order in81C0/81AA/8187','parent suffix stack restore and pointed word publication','hardware child composition under original gateway software continuation'],
        reused=['canonical79E2/7A17/73D0/756D/7619/742A','052C','785C/77CC type8 natural extension','Pass84 prefix','059E','Pass75 tail'],
        natural_shadows=9,synthetic_shadows=26,
        supported='two published FACTOR k123 states plus explicit synthetic discriminants within guards',
        unsupported=['initial247B predicate-clear and zero-difference paths','nonzero83DC route','listing/output errors/record flush/pointer aliases','general gateway indices and arbitrary k123 inputs'],
        knowledge_promotions=0,native_roots_installed=0,oracle_queries=0,
        native_installation='deferred; handler is executable at scoped software entry, gateway eligibility/dispatch proof requires a separate pass',
        FULL='Pass74 epoch3; external Pass79 failure evidence unchanged; no FULL campaign',
        evidence=['natural-shadow.json','validation.json']))
    assert (REPORT/'implementation-packet.json').stat().st_size<28672
    return evidence
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);prove(p.parse_args().images)
