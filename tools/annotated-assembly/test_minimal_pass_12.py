#!/usr/bin/env python3
"""Byte scan, masked readback, shifts and exact remaining RAW-entry isolation."""
import argparse
import json
import sys
import unittest
from pathlib import Path
from check_minimal_pass_2 import at,coord,pair,word
from check_minimal_pass_3 import gather
from minimal_baseline import load
from minimal_dynamic_progress import calculate
from procedure_evidence_packet import ROOT,build,software_profile,verify_return

KEYS=['57B7','41AF','421F','47E2','4890','4802','8386','2221','020E','13E3','14C8','8380','8268']

def local(p,iv,o):
    return [p['steps'][str(n)] for n in iv['local_steps'] if p['steps'][str(n)]['coordinate']==f'PLI1.OVL+{o:04X}']

class MinimalPassTwelveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
        cls.direct=gather(CAPTURE,{'PLI1.OVL+'+k:(0,0) for k in KEYS},include_nested_returns=True,software_callees=software_profile(cls.catalog))
        cls.packets={k:build(CAPTURE,IMAGES,'PLI1.OVL+'+k,0,()) for k in ['4890','4802']}

    def test_all_selected_hardware_slots_and_exact_bounds(self):
        structural=json.loads((ROOT/'research/minimal-baseline/pass-12/structural.json').read_text())
        for row in structural:
            rr=self.direct[row['entry']];p=self.catalog[row['entry']];ws=[w for r in rr for w in r['own_witnesses']]
            self.assertEqual((len(rr),len({coord(w['origin']) for w in ws}),len(ws)),(row['calls'],row['own_coordinates'],row['own_occurrences']))
            for r in rr:verify_return(r['call'],r['ret'],r['relation'])
            self.assertTrue(all(p['start_offset']<=w['origin']['offset']<p['end_offset'] for w in ws))
        self.assertEqual(self.catalog['PLI1.OVL+4890']['completeness'],dict(bounds='provisional',control_flow='partial',contract='partial'))
        self.assertEqual(self.catalog['PLI1.OVL+4802']['completeness'],dict(bounds='provisional',control_flow='partial',contract='partial'))

    def test_scan_addresses_indices_zero_precedence_and_compare_flags(self):
        lengths=[]
        for r in self.direct['PLI1.OVL+57B7']:
            ws=r['own_witnesses'];entry=r['entry']['before'];base=pair(entry,'b','c');out=r['ret']['after']
            samples=at(ws,0x57D0);indices=at(ws,0x57C6);lengths.append(len(samples))
            self.assertEqual([w['writes'][0]['new_value'] for w in indices],list(range(len(samples))))
            for i,w in enumerate(samples):self.assertEqual(w['reads'][0]['address'],(base+i)&65535)
            final=samples[-1]['reads'][0]['value'];match=final!=0
            self.assertEqual(out['a'],int(match));self.assertEqual(pair(out,'b','c'),len(samples)-1)
            self.assertEqual(pair(out,'d','e'),pair(entry,'d','e'))
            for b in at(ws,0x57D6):self.assertEqual(b['control']['taken'],b['before']['a']!=0)
            for b in at(ws,0x57E3):self.assertEqual(b['control']['taken'],not b['before']['flags']['zero'])
            if match:
                self.assertEqual(final,at(ws,0x57DF)[-1]['reads'][0]['value'])
                self.assertEqual(pair(out,'h','l'),0xA938);producer=at(ws,0x57E2)[-1]
            else:
                self.assertEqual(pair(out,'h','l'),(base+len(samples)-1)&65535);producer=at(ws,0x57D4)[-1]
            self.assertEqual(out['flags'],producer['after']['flags']);self.assertTrue(out['flags']['zero'])
            self.assertEqual({q['address'] for w in ws for q in w['writes']},{0xA935,0xA936,0xA937,0xA938})
        self.assertEqual(lengths,[4,4,7,3,3,9])

    def test_masked_field_leaves_and_index_gate(self):
        for k,o,delta,mask in [('41AF',0x41B8,3,7),('421F',0x4225,1,0xE0)]:
            for r in self.direct['PLI1.OVL+'+k]:
                ws=r['own_witnesses'];p=word(at(ws,0x41B2 if k=='41AF' else 0x421F)[0]);read=at(ws,o)[0]['reads'][0];out=r['ret']['after']
                self.assertEqual(read['address'],(p+delta)&65535);self.assertEqual(out['a'],read['value']&mask)
                self.assertEqual(pair(out,'h','l'),(p+delta)&65535);self.assertFalse(out['flags']['carry'])
                self.assertEqual(pair(out,'d','e'),pair(r['entry']['before'],'d','e'))
                self.assertEqual(pair(out,'b','c'),3 if k=='41AF' else pair(r['entry']['before'],'b','c'))
                self.assertFalse(any(w['writes'] for w in ws))
        for r in self.direct['PLI1.OVL+47E2']:
            ws=r['own_witnesses'];old=at(ws,0x47E2)[0]['reads'][0]['value'];new=(old+1)&255
            self.assertEqual(at(ws,0x47E6)[0]['writes'][0]['new_value'],new)
            self.assertEqual(at(ws,0x47ED)[0]['control']['taken'],new<=30)
            self.assertEqual((r['ret']['after']['a'],r['ret']['after']['c']),(30,new))
            self.assertEqual(r['ret']['after']['flags'],at(ws,0x47EC)[0]['after']['flags'])

    def test_right_shift_loaded_word_and_independent_left_shift(self):
        for r in self.direct['PLI1.OVL+8386']:
            ws=r['own_witnesses'];s=r['entry']['before'];out=r['ret']['after'];address=pair(s,'h','l');n=s['c'] or 256
            lo=at(ws,0x8386)[0]['reads'][0];hi=at(ws,0x8388)[0]['reads'][0]
            self.assertEqual([lo['address'],hi['address']],[address,(address+1)&65535]);value=lo['value']+256*hi['value']
            self.assertEqual(len(at(ws,0x838A)),n);self.assertEqual(pair(out,'h','l'),value>>n)
            self.assertEqual((out['a'],out['b'],out['c'],pair(out,'d','e')),(value>>n&255,s['b'],0,(address+1)&65535))
            self.assertEqual(out['flags']['carry'],bool(value>>(n-1)&1));self.assertEqual(out['flags'],at(ws,0x8391)[-1]['after']['flags'])
            self.assertFalse(any(w['writes'] for w in ws))
        for r in self.direct['PLI1.OVL+8380']:
            s=r['entry']['before'];out=r['ret']['after'];n=s['c'] or 256
            self.assertEqual(pair(out,'h','l'),(pair(s,'h','l')<<n)&65535)
            self.assertEqual(len(at(r['own_witnesses'],0x8380)),n)
            self.assertEqual((out['a'],out['b'],pair(out,'d','e')),(s['a'],s['b'],pair(s,'d','e')))
            self.assertEqual(out['flags']['carry'],bool((pair(s,'h','l')<<(n-1))&0x8000))

    def test_readback_advance_masks_and_distinct_word_publications(self):
        p=self.packets['4890'];published=0
        for iv in p['invocations']:
            old=word(local(p,iv,0x4890)[0]);size=local(p,iv,0x4899)[0]['reads'][0]['value']
            write=local(p,iv,0x48A0)[0]['writes'];self.assertEqual(write[0]['new_value']+256*write[1]['new_value'],(old+size)&65535)
            high=local(p,iv,0x48D6)[0]['before']['a'];count=local(p,iv,0x48DF)[0]['before']['a'];action=high==0 and count>0
            self.assertEqual(local(p,iv,0x48E8)[0]['control']['taken'],not action)
            if action:
                published+=1;c=next(p['calls'][str(n)] for n in iv['nested_calls'] if p['calls'][str(n)]['target']=='PLI1.OVL+452B')
                args=p['steps'][str(c['pre_call_state_step'])]['before'];self.assertEqual((pair(args,'b','c'),args['e']),((old+10)&65535,count))
                reads=[q for w in c['callee_memory_effects']['guest_instruction_accesses'] for q in w['reads'] if old+10<=q['address']<old+10+count]
                j=sum(q['value'] for q in reads)&127;slot=0xA761+2*j
                nextlo=local(p,iv,0x490E)[0]['reads'][0];nexthi=local(p,iv,0x4910)[0]['reads'][0]
                self.assertEqual([nextlo['address'],nexthi['address']],[slot,slot+1])
                for off,address,value in [(0x4912,old+8,nextlo['value']),(0x4914,old+9,nexthi['value']),(0x4925,slot,old&255),(0x4927,slot+1,old>>8)]:
                    q=local(p,iv,off)[0]['writes'][0];self.assertEqual((q['address'],q['new_value']),(address,value))
        self.assertEqual(published,1)

    def test_parent_growth_two_tables_and_ADI_replaces_borrow(self):
        p=self.packets['4802'];growth=[];continuations=0
        for iv in p['invocations']:
            saved=word(local(p,iv,0x4814)[0]);index=local(p,iv,0x484B)[0]['reads'][0]['value'];growth.append(len(local(p,iv,0x4835)))
            self.assertTrue(local(p,iv,0x4810)[0]['control']['taken'])
            for o,base in [(0x485B,0xA8AB),(0x4868,0xA86D)]:
                lo=local(p,iv,o)[0]['writes'][0];hi=local(p,iv,o+2)[0]['writes'][0]
                self.assertEqual((lo['address'],hi['address']),(base+2*index,base+2*index+1));self.assertEqual(lo['new_value']+256*hi['new_value'],saved)
            for b in local(p,iv,0x4832):self.assertEqual(b['control']['taken'],b['before']['a']>=b['before']['c'])
            for subtract,add,branch in zip(local(p,iv,0x487D),local(p,iv,0x487F),local(p,iv,0x4886)):
                high=subtract['before']['a'];x=(high-32)&255
                self.assertEqual(add['before']['a'],x);self.assertEqual(add['after']['flags']['carry'],x!=0)
                # Saved SBB mask is restored into B; flags come from later ANA/RAR.
                below=branch['before']['b']!=0;again=below and high!=32
                self.assertEqual(branch['control']['taken'],not again);continuations+=again
            out=p['steps'][str(iv['return_step'])]['after'];self.assertEqual(out['a'],0);self.assertFalse(out['flags']['carry']);self.assertTrue(out['flags']['zero'])
        self.assertEqual(growth,[0,2]);self.assertEqual(continuations,1)

    def test_secondary_masks_setters_and_scoped_adapter(self):
        for r in self.direct['PLI1.OVL+020E']:
            ws=r['own_witnesses'];v=at(ws,0x020E)[0]['reads'][0]['value'];v2=at(ws,0x0217)[0]['reads'][0]['value']
            self.assertEqual(r['ret']['after']['a'],255 if v==1 or v2>=129 else 0);self.assertFalse(r['ret']['after']['flags']['carry'])
        for r in self.direct['PLI1.OVL+2221']:
            ws=r['own_witnesses'];v=at(ws,0x2252)[0]['reads'][0]['value']
            self.assertEqual(r['ret']['after']['a'],255 if 6<=v<=9 else 0)
        for r in self.direct['PLI1.OVL+13E3']:
            ws=r['own_witnesses'];s=r['entry']['before'];i=at(ws,0x13F4)[0]['reads'][0]['value']
            self.assertEqual(at(ws,0x13F3)[0]['writes'][0]['address'],0xA5FE+i);self.assertEqual(at(ws,0x13F3)[0]['writes'][0]['new_value'],s['c'])
            self.assertEqual(at(ws,0x13F9)[0]['control']['taken'],i>=7)
            if i<7:self.assertEqual(at(ws,0x140A)[0]['writes'][0]['address'],0xA5FE+i+1);self.assertEqual(at(ws,0x140A)[0]['writes'][0]['new_value'],255)
        for r in self.direct['PLI1.OVL+14C8']:
            ws=r['own_witnesses'];initial=at(ws,0x14C8)[0]['reads'][0]['value'];call=at(ws,0x14CD)[0];child=r['nested_returns'][call['step_index']]
            self.assertEqual(call['before']['c'],(initial-1)&255);self.assertEqual(at(ws,0x14D0)[0]['writes'][0]['new_value'],child['ret']['after']['a']);self.assertEqual(r['ret']['after']['flags'],child['ret']['after']['flags'])
        for r in self.direct['PLI1.OVL+8268']:
            self.assertEqual([(q['address'],q['new_value']) for w in r['own_witnesses'] for q in w['writes']],[(0xAE79,r['entry']['before']['c']),(0xAA1A,r['entry']['before']['c'])]);self.assertEqual(r['ret']['after']['flags'],r['entry']['before']['flags'])

    def test_fresh_remaining_RAW_entry_windows_and_progress(self):
        report=load(ROOT/'research/minimal-baseline/pass-12/category1-audit.json');frames=gather(CAPTURE,{r['entry']:(0,0) for r in report['category1']},include_nested_returns=True,software_callees=software_profile(self.catalog))
        steps=set();total=repeated=0
        for row in report['category1']:
            rr=frames[row['entry']];ws=[w for r in rr for w in r['own_witnesses']];own={w['step_index'] for w in ws};self.assertFalse(steps&own);steps|=own
            self.assertEqual((len(rr),len({coord(w['origin']) for w in ws}),len(ws)),(row['calls'],row['own_coordinates'],row['own_occurrences']))
            for r in rr:verify_return(r['call'],r['ret'],r['relation'])
            total+=len(ws);repeated+=len(ws) if len(rr)>1 else 0
        self.assertEqual((len(frames),total,sum(len(r)>1 for r in frames.values()),repeated),(62,2258,18,472));self.assertFalse(report['unresolved_return_entries'])
        inventory=load(ROOT/'research/minimal-baseline/inventory.json');raw={e['entry'] for e in inventory['callable_entries'] if e['image']=='PLI1.OVL' and e['status_at_entry']=='RAW'};self.assertEqual(set(frames),raw)
        manifest=load(ROOT/'research/annotated-assembly/manifest.json');rows=[json.loads(s) for s in (ROOT/'research/minimal-baseline/instructions.jsonl').read_text().splitlines()];self.assertEqual(calculate(manifest,rows),load(ROOT/'research/minimal-baseline/dynamic-progress.json'))
        self.assertEqual(sum(i['length'] for i in manifest['images']),94720)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--images',type=Path,required=True);parser.add_argument('--capture',type=Path,default=ROOT/'_build/minimal-baseline/capture')
    args,remaining=parser.parse_known_args();IMAGES,CAPTURE=args.images,args.capture
    unittest.main(argv=[sys.argv[0],*remaining])
