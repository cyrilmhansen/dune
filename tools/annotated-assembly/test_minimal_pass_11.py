#!/usr/bin/env python3
"""Shared-entry subtraction, mapped composition, frame and full RAW-entry audit."""
import argparse
import json
import sys
import unittest
from pathlib import Path

from check_minimal_pass_2 import at,coord,pair
from check_minimal_pass_3 import gather
from check_minimal_pass_8 import gather as gather_cleanup
from minimal_baseline import load
from minimal_dynamic_progress import calculate
from procedure_evidence_packet import ROOT,build,software_profile,verify_return
from software_continuation import prove


def local(p,iv,offset):
    return [p['steps'][str(n)] for n in iv['local_steps']
            if p['steps'][str(n)]['coordinate']==f'PLI1.OVL+{offset:04X}']


class MinimalPassElevenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packets={s:build(CAPTURE,IMAGES,'PLI1.OVL+'+s,0,()) for s in ['7E5F','8048','240A']}
        cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
        keys=['PLI1.OVL+'+s for s in ['83A0','83A3','7A93','7EC0','80B7','2511','01AF','4227','23A0','23D2']]
        cls.direct=gather(CAPTURE,{k:(0,0) for k in keys},include_nested_returns=True)
        # Ordinary outer packets do not own +4468's cleanup frame. Reuse the
        # established pass-8 gatherer/prove authority without another recognizer.
        cls.constructors=gather_cleanup(CAPTURE)['PLI1.OVL+4468']

    def test_independent_shared_entries_subtract_without_writes(self):
        for suffix,count in [('83A0',6),('83A3',3)]:
            self.assertEqual(len(self.direct['PLI1.OVL+'+suffix]),count)
            p=self.catalog['PLI1.OVL+'+suffix]
            self.assertEqual(p['overlapping_entries'],['PLI1.OVL+'+('83A3' if suffix=='83A0' else '83A0')])
            for r in self.direct['PLI1.OVL+'+suffix]:
                entry=r['entry']['before'];out=r['ret']['after'];ws=r['own_witnesses'];address=pair(entry,'h','l')
                lo=at(ws,0x83A4)[0]['reads'][0];hi=at(ws,0x83A8)[0]['reads'][0]
                self.assertEqual([lo['address'],hi['address']],[address,(address+1)&65535])
                operand=lo['value']+256*hi['value'];minuend=entry['a'] if suffix=='83A0' else pair(entry,'d','e')
                result=(minuend-operand)&65535
                self.assertEqual(pair(out,'h','l'),result)
                self.assertEqual(pair(out,'d','e'),(address+1)&65535)
                self.assertEqual(pair(out,'b','c'),pair(entry,'b','c'))
                self.assertEqual(out['a'],result>>8)
                self.assertEqual(out['flags']['carry'],minuend<operand)
                self.assertEqual(out['flags']['zero'],(result>>8)==0)
                self.assertFalse(any(w['writes'] for w in ws))
                verify_return(r['call'],r['ret'],r['relation'])

    def test_constructor_negation_gate_and_actual_link_writer(self):
        for r in self.constructors:
            sample=r['continuation_sample']; proof=prove(dict(call=r['call'],prefix=sample['prefix'],ret=r['ret'],relation=r['relation'],stack_argument_bytes=2))
            self.assertEqual(proof['final_SP_minus_preCALL'],2)
            ws=r['own_witnesses'];calls=at(ws,0x4506);branches=at(ws,0x450A)
            for call,branch in zip(calls,branches):
                self.assertEqual(call['before']['a'],0)
                child=r['nested_returns'][call['step_index']]
                result=pair(child['ret']['after'],'h','l')
                self.assertEqual(branch['control']['taken'],result==0)
                self.assertFalse(any(w['writes'] for w in child['memory_witnesses']))
            newp=pair(at(ws,0x4527)[0]['before'],'h','l')
            low=at(ws,0x4520)[0]['writes'][0];high=at(ws,0x4522)[0]['writes'][0]
            self.assertEqual([low['new_value'],high['new_value']],[newp&255,newp>>8])
            self.assertEqual(high['address'],(low['address']+1)&65535)
            last=at(ws,0x451B)[0]['reads'];last=last[0]['value']+256*last[1]['value']
            self.assertEqual(low['address'],(last+8)&65535)
            self.assertEqual(r['ret']['after']['flags']['carry'],at(ws,0x451E)[0]['after']['flags']['carry'])

    def test_recycle_state_and_four_publications_remain_correlated(self):
        p=self.packets['7E5F'];self.assertEqual(len(p['invocations']),16)
        for iv in p['invocations']:
            entry=p['steps'][str(iv['entry_step'])]['before'];pos=local(p,iv,0x7E6C)[0]['reads'][0]['value']
            slot=local(p,iv,0x7E7C)[0]['reads'][0]['value'];displaced=local(p,iv,0x7E89)[0]['reads'][0]
            self.assertEqual(displaced['address'],0xAAB4+slot)
            self.assertEqual(local(p,iv,0x7E7F)[0]['writes'][0]['address'],0xAA1F+pos)
            self.assertEqual(local(p,iv,0x7E7F)[0]['writes'][0]['new_value'],slot)
            self.assertEqual(local(p,iv,0x7E8A)[0]['writes'][0]['new_value'],displaced['value'])
            calls=[p['calls'][str(n)] for n in iv['nested_calls']]
            self.assertEqual([c['target'] for c in calls],['PLI1.OVL+'+s for s in ['7AD5','7AF0','7B2E','7B49']])
            args=[p['steps'][str(c['pre_call_state_step'])]['before'] for c in calls]
            self.assertEqual([a['c'] for a in args],[pos]*4)
            self.assertEqual(args[0]['e'],entry['c']);self.assertEqual(pair(args[1],'d','e'),pair(entry,'d','e'))
            self.assertEqual([a['e'] for a in args[2:]],[0,0])
            expected=[{0xAAB4+slot:entry['c']},{0xAB49+2*slot:entry['e'],0xAB4A+2*slot:entry['d']},{0xAD08+slot:0},{0xAD9D+slot:0}]
            for c,dest in zip(calls,expected):
                writes={q['address']:q['new_value'] for w in c['callee_memory_effects']['guest_instruction_accesses'] for q in w['writes']}
                self.assertEqual({a:writes[a] for a in dest},dest)
            out=p['steps'][str(iv['return_step'])]['after']
            self.assertEqual((out['a'],pair(out,'b','c'),pair(out,'d','e'),pair(out,'h','l')),(pos,slot,entry['d']<<8,0xAE35))
            self.assertEqual(local(p,iv,0x7EBE)[0]['writes'][0]['new_value'],(pos+1)&255)
            self.assertEqual(out['flags'],local(p,iv,0x7EBE)[0]['after']['flags'])

    def test_threshold_modes_copy_three_independent_predecessor_bytes(self):
        p=self.packets['8048'];modes={True:0,False:0}
        for iv in p['invocations']:
            inputc=p['steps'][str(iv['entry_step'])]['before']['c'];low=inputc<=0xDD;modes[low]+=1
            self.assertEqual(local(p,iv,0x8052)[0]['control']['taken'],low)
            calls=[p['calls'][str(n)] for n in iv['nested_calls']]
            if low:
                self.assertEqual(calls[0]['target'],'PLI1.OVL+7E5F')
                previous=None
                for reader,setter in [(calls[1],calls[2]),(calls[3],calls[4]),(calls[5],calls[6])]:
                    source=p['steps'][str(reader['pre_call_state_step'])]['before'];value=p['steps'][str(reader['post_return_state_step'])]['after']['a']
                    dest=p['steps'][str(setter['pre_call_state_step'])]['before']
                    self.assertEqual(source['c'],(dest['c']-1)&255);self.assertEqual(dest['e'],value)
                    if previous is not None:self.assertEqual(dest['c'],previous)
                    previous=dest['c']
                self.assertEqual(p['steps'][str(iv['return_step'])]['after']['flags'],local(p,iv,0x80A3)[0]['after']['flags'])
            else:
                self.assertEqual([c['target'] for c in calls],['PLI1.OVL+7D53','PLI.COM+0EF6'])
                self.assertTrue(local(p,iv,0x8059)[0]['control']['taken'])
                self.assertEqual(p['steps'][str(calls[1]['pre_call_state_step'])]['before']['c'],inputc)
        self.assertEqual(modes,{True:12,False:10})

    def test_leaf_and_rotated_attribute_gate_values_are_not_masks(self):
        for r in self.direct['PLI1.OVL+7A93']:
            ws=r['own_witnesses'];position=r['entry']['before']['c'];m=at(ws,0x7AA0)[0]['reads'][0];out=r['ret']['after']
            self.assertEqual(m['address'],0xAA1F+position)
            self.assertEqual(at(ws,0x7AA7)[0]['reads'][0]['address'],0xAC73+m['value'])
            self.assertEqual(out['a'],at(ws,0x7AA7)[0]['reads'][0]['value'])
            self.assertEqual(pair(out,'d','e'),pair(r['entry']['before'],'d','e'))
        called=0
        for r in self.direct['PLI1.OVL+7EC0']:
            ws=r['own_witnesses'];t=at(ws,0x7ECD)[0]['reads'][0]['value'];branch=at(ws,0x7ED0)[0]
            self.assertEqual(at(ws,0x7ECF)[0]['after']['a'],t)
            self.assertEqual(branch['control']['taken'],not bool(t&128))
            if branch['control']['taken']:self.assertEqual(r['ret']['after']['a'],t)
            else:called+=1
        self.assertEqual(called,7)
        for r in self.direct['PLI1.OVL+4227']:
            ws=r['own_witnesses'];v=at(ws,0x422D)[0]['reads'][0]['value'];self.assertEqual(r['ret']['after']['a'],v&31)

    def test_one_byte_frame_compositions_and_selector_adapter(self):
        for r in self.direct['PLI1.OVL+2511']:
            ws=r['own_witnesses'];frame=(r['entry']['sp_before']-1)&65535;inputc=r['entry']['before']['c']
            self.assertEqual(at(ws,0x2513)[0]['sp_after'],frame)
            self.assertEqual([at(ws,o)[0]['reads'] for o in [0x2518,0x2525]],[[{'address':frame,'value':inputc}]]*2)
            self.assertEqual([at(ws,o)[0]['before']['c'] for o in [0x2519,0x251E,0x2526]],[inputc,0,inputc])
            verify_return(r['call'],r['ret'],r['relation'])
        for r in self.direct['PLI1.OVL+80B7']:
            ws=r['own_witnesses'];c=r['entry']['before']['c']
            self.assertEqual([at(ws,o)[0]['before']['c'] for o in [0x80BF,0x80C6]],[c,c])
        matches=0
        for r in self.direct['PLI1.OVL+01AF']:
            ws=r['own_witnesses'];selector=at(ws,0x01B6)[0]['after']['a'];inputc=r['entry']['before']['c'];match=selector==inputc
            self.assertEqual(at(ws,0x01BA)[0]['control']['taken'],not match)
            self.assertEqual(r['ret']['after']['a'],int(match));matches+=match
            if match:
                child=r['nested_returns'][at(ws,0x01BD)[0]['step_index']]
                self.assertEqual(r['ret']['after']['flags'],child['ret']['after']['flags'])
        self.assertEqual(matches,9)

    def test_minimum_and_selected_state_composition(self):
        for r in self.direct['PLI1.OVL+23A0']:
            ws=r['own_witnesses'];c=r['entry']['before']['c'];e=r['entry']['before']['e']
            self.assertEqual(at(ws,0x23AD)[0]['control']['taken'],c>=e)
            self.assertEqual(r['ret']['after']['a'],min(c,e))
            self.assertEqual(r['ret']['after']['flags'],at(ws,0x23AC)[0]['after']['flags'])
        p=self.packets['240A']
        for iv in p['invocations']:
            calls=[p['calls'][str(n)] for n in iv['nested_calls']]
            v=local(p,iv,0x2417)[0]['reads'][0]['value']
            self.assertEqual(local(p,iv,0x241A)[0]['control']['taken'],v!=0x15)
            self.assertEqual(calls[-2]['target'],'PLI1.OVL+7AF0');self.assertEqual(calls[-1]['target'],'PLI1.OVL+23D2')
            if v==0x15:self.assertEqual(calls[0]['target'],'PLI1.OVL+23A0')

    def test_fresh_category1_windows_match_exact_report(self):
        audit=json.loads((ROOT/'research/minimal-baseline/pass-11/category1-audit.json').read_text())
        keys={r['entry']:(0,0) for r in audit['category1']}
        frames=gather(CAPTURE,keys,include_nested_returns=True,software_callees=software_profile(self.catalog))
        steps=set();total=repeated=0
        for row in audit['category1']:
            rs=frames[row['entry']];ws=[w for r in rs for w in r['own_witnesses']]
            own={w['step_index'] for w in ws};self.assertFalse(steps&own);steps|=own
            self.assertEqual((len(rs),len({coord(w['origin']) for w in ws}),len(ws)),(row['calls'],row['own_coordinates'],row['own_occurrences']))
            for r in rs:verify_return(r['call'],r['ret'],r['relation'])
            total+=len(ws);repeated+=len(ws) if len(rs)>1 else 0
        self.assertEqual((total,repeated),(3517,1731));self.assertFalse(audit['unresolved_return_entries'])
        manifest=load(ROOT/'research/annotated-assembly/manifest.json');rows=[json.loads(s) for s in (ROOT/'research/minimal-baseline/instructions.jsonl').read_text().splitlines()]
        self.assertEqual(calculate(manifest,rows),load(ROOT/'research/minimal-baseline/dynamic-progress.json'))
        self.assertEqual(sum(i['length'] for i in manifest['images']),94720)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--images',type=Path,required=True)
    parser.add_argument('--capture',type=Path,default=ROOT/'_build/minimal-baseline/capture')
    args,remaining=parser.parse_known_args();IMAGES,CAPTURE=args.images,args.capture
    unittest.main(argv=[sys.argv[0],*remaining])
