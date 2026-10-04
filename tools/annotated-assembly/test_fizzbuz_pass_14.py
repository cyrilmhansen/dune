#!/usr/bin/env python3
"""Bounded parent correlations; unavailable packet stays fail-closed, RAW stays RAW."""
import argparse
import copy
import hashlib
import json
import sys
import unittest
from collections import Counter
from pathlib import Path
from check_minimal_pass_2 import at,coord,pair
from check_minimal_pass_3 import gather
from check_fizzbuz_pass_14 import checker_input,summarize,compose,local_path_signature
from minimal_baseline import load,status_at
from minimal_dynamic_progress import calculate
from procedure_evidence_packet import ROOT,build,software_profile,verify_return

KEY='PLI1.OVL+7D53'

class FizzbuzPassFourteenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
        cls.records=gather(CAPTURE,{KEY:(0x7D53,0x7E46)},include_nested_returns=True,software_callees=software_profile(cls.catalog))[KEY]
        cls.minimal=gather(ROOT/'_build/minimal-baseline/capture',{KEY:(0x7D53,0x7E46)},include_nested_returns=True,software_callees=software_profile(cls.catalog))[KEY]
        cls.rows=[summarize(r) for r in cls.records]
        cls.recursive=build(CAPTURE,IMAGES,'PLI1.OVL+7C1B',5,(0,3),run='FIZZBUZ')
        cls.composition=[c for row in cls.rows for c in compose(row,cls.recursive)]

    def test_capture_structure_callers_returns_and_byte_union(self):
        summary=load(CAPTURE/'run-summary.json');self.assertTrue(all(summary[k] for k in ['pass1_success','pass2_success','end_compilation']))
        rel=(CAPTURE/'FIZZBUZ.REL').read_bytes();self.assertEqual((len(rel),hashlib.sha256(rel).hexdigest()),(768,'68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203'))
        identity=load(CAPTURE/'event-witnesses.json')['run_id'];self.assertTrue(identity.startswith('FIZZBUZ:'));self.assertEqual(self.recursive['run_id'],identity)
        p=self.catalog[KEY];self.assertEqual(p['observed_paths']['invocations_by_run']['FIZZBUZ'],len(self.records));self.assertEqual(len(self.records),77);self.assertEqual(p['observed_paths']['invocations_by_run']['MINIMAL'],21)
        callers=Counter(coord(r['call']['origin']) for r in self.records);self.assertEqual(callers,Counter({c['coordinate']:c['counts_by_run']['FIZZBUZ'] for c in p['callers'] if 'FIZZBUZ' in c['counts_by_run']}))
        self.assertEqual(callers,Counter({'PLI1.OVL+7ED3':25,'PLI1.OVL+8069':30,'PLI1.OVL+80EB':8,'PLI1.OVL+811B':2,'PLI1.OVL+816B':12}))
        self.assertEqual(Counter(r['ret']['origin']['offset'] for r in self.records),Counter({0x7D5D:40,0x7D65:8,0x7E45:29}))
        for r in self.records:verify_return(r['call'],r['ret'],r['relation'])
        own=[w for r in self.records for w in r['own_witnesses']];self.assertEqual((len(own),len({w['step_index'] for w in own}),len({coord(w['origin']) for w in own})),(6018,6018,99))
        union={o for w in own for o in range(w['origin']['offset'],w['origin']['offset']+len(bytes.fromhex(w['bytes'])))};seed=next(s for s in load(ROOT/'research/annotated-assembly/evidence.json')['seeds'] if s['id']==KEY)
        self.assertEqual(len(union),237);self.assertEqual(p['observed_paths']['represented_bytes'],237);self.assertEqual(sum(len(bytes.fromhex(i['bytes'])) for i in seed['instructions']),237)

    def test_packet_rejection_does_not_drop_nonhistorical_evidence(self):
        with self.assertRaisesRegex(ValueError,'Packet boundary has unresolved historical origin'):
            build(CAPTURE,IMAGES,KEY,0,(),run='FIZZBUZ')
        row=next(r for r in self.rows if r['call_step']==472976)
        self.assertEqual([e['step'] for e in row['unsupported_effects']],[478324,478364]);self.assertTrue(all(e['coordinate'] is None and e['runtime_pc']==5 for e in row['unsupported_effects']))
        # Actual scalar before/after states remain available; this is not packet validation.
        record=next(r for r in self.records if r['call']['step_index']==472976);view,iv=checker_input(record)
        self.assertEqual(sum(e['coordinate'] is None for c in view['calls'].values() for e in c['callee_memory_effects']['guest_instruction_accesses']),2)
        self.assertEqual(sum(len(r['forward']) for r in self.rows),102)

    def test_top_paths_and_all_shortcut_threshold_flag_producers(self):
        self.assertEqual(Counter(r['path'] for r in self.rows),Counter(equal_range=40,gate=8,work=29))
        producers={0x7D5A:0x7D59,0x7D62:0x7D61,0x7D70:0x7D6F,0x7D78:0x7D76,0x7D96:0x7D94,0x7DD4:0x7DD2}
        for r in self.records:
            ws=r['own_witnesses']
            for branch,producer in producers.items():
                for w in at(ws,branch):
                    previous=ws[ws.index(w)-1];self.assertEqual(previous['origin']['offset'],producer);self.assertEqual(w['before']['flags'],previous['after']['flags'])
                    a=previous['before']['a']
                    if branch==0x7D5A:expected=a!=previous['reads'][0]['value']
                    elif branch==0x7D62:expected=not(a&1)
                    elif branch==0x7D70:expected=bool(a&1)
                    elif branch==0x7D78:expected=a!=0
                    else:expected=a>=0xF7
                    self.assertEqual(w['control']['taken'],expected)
                    if branch in [0x7D70,0x7D78,0x7D96,0x7DD4]:self.assertFalse(expected)

    def test_no_new_local_coordinates_outcomes_but_new_sequences(self):
        coordinates=lambda rr:{w['origin']['offset'] for r in rr for w in r['own_witnesses']};self.assertEqual(coordinates(self.records),coordinates(self.minimal))
        outcomes=lambda rr:{(w['origin']['offset'],w['control']['taken']) for r in rr for w in r['own_witnesses'] if w['control']['kind']=='jump'};self.assertEqual(outcomes(self.records),outcomes(self.minimal))
        before={local_path_signature(r) for r in self.minimal};after={local_path_signature(r) for r in self.records};self.assertEqual((len(before),len(after),len(after-before)),(7,12,5))
        top_values=lambda rr:{w['before']['a'] for r in rr for w in at(r['own_witnesses'],0x7DA0)};self.assertEqual(top_values(self.records)-top_values(self.minimal),{1,15})

    def test_recursive_descendants_are_not_direct_children(self):
        self.assertEqual({c['parent_call_step'] for c in self.composition},{375015,403330,472976,539774,608084,618086})
        self.assertEqual(sum(len(c['selected_descendants']) for c in self.composition),7)
        for c in self.composition:
            self.assertTrue(all(not d['top_level'] and d['call_step']!=c['reverse']['call_step'] for d in c['selected_descendants']))
            r=next(r for r in self.records if r['call']['step_index']==c['parent_call_step']);ws=r['own_witnesses'];direct=next(w for w in ws if w['step_index']==c['reverse']['call_step']);self.assertEqual(direct['origin']['offset'],0x7D9D)
            ret=r['nested_returns'].get(direct['step_index'],r['nested_returns'].get(str(direct['step_index'])))['ret'];self.assertEqual(ret['step_index'],c['reverse']['return_step']);self.assertEqual(c['reverse']['returned_A'],ret['after']['a'])
            cache=next(w for w in ws if w['step_index']==c['reverse']['AE50_write_step']);self.assertEqual((cache['before']['a'],cache['writes'][0]['new_value']),(ret['after']['a'],ret['after']['a']))
            skip=next(w for w in ws if w['step_index']==c['reverse']['skip_call_step']);self.assertEqual(skip['origin']['offset'],0x7DA7);self.assertEqual(skip['before']['c'],direct['before']['c'])
            replace=next(w for w in ws if w['step_index']==c['reverse']['cursor_write_step']);self.assertEqual(replace['writes'][0]['new_value'],c['reverse']['skip_return'])
            next_branch=next(w for w in ws if w['step_index']==c['reverse']['next_loop_branch_step']);self.assertEqual(next_branch['before']['c'],(c['reverse']['skip_return']-1)&255);self.assertEqual(next_branch['control']['taken'],next_branch['before']['a']==next_branch['before']['c'])
            self.assertEqual(c['forward_start']['cursor'],c['begin']);self.assertEqual(c['end_publication']['value'],c['begin'])
        special=next(c for c in self.composition if c['parent_call_step']==618086);self.assertEqual(special['top_child_mapped'],15);self.assertEqual(special['selected_descendants'][0]['mapped'],30)
        # Corrupt the direct return relation; equality of output bytes is insufficient.
        bad=copy.deepcopy(special);row=next(r for r in self.rows if r['call_step']==618086);badrow=copy.deepcopy(row);badrow['reverse'][0]['return_step']+=1
        with self.assertRaisesRegex(ValueError,'exact parent chronology'):compose(badrow,self.recursive)

    def test_equal_values_keep_frame_and_auxiliary_producers_separate(self):
        p=self.recursive;iv=next(i for i in p['invocations'] if i['call_step']==618131)
        step=lambda o:next(p['steps'][str(n)] for n in iv['local_steps'] if p['steps'][str(n)]['coordinate']==f'PLI1.OVL+{o:04X}')
        cache=step(0x7D0D)['writes'][0];read=step(0x7D4E)['reads'][0];self.assertEqual((cache['address'],read['address']),(iv['F']+4,iv['F']+4));self.assertEqual((cache['new_value'],read['value']),(15,15))
        f2=[p['steps'][str(n)] for n in iv['local_steps'] if p['steps'][str(n)]['coordinate']=='PLI1.OVL+7D34'];self.assertEqual(len(f2),2);self.assertTrue(all(w['writes'][0]['address']==iv['F']+2 for w in f2))
        self.assertNotEqual(cache['address'],f2[0]['writes'][0]['address'])
        own=[dict(p['steps'][str(n)],step=n) for n in iv['local_steps']]
        cache_step=next(w['step'] for w in own if w['coordinate']=='PLI1.OVL+7D0D')
        read_step=next(w['step'] for w in own if w['coordinate']=='PLI1.OVL+7D4E')
        accesses=own+[e for n in iv['nested_calls'] for e in p['calls'][str(n)]['callee_memory_effects']['guest_instruction_accesses']]
        last_writer=max((w for w in accesses if w['step']<read_step and any(q['address']==cache['address'] for q in w['writes'])),key=lambda w:w['step'])
        self.assertEqual(last_writer['step'],cache_step)  # actual writer ancestry, not matching byte15
        record=next(r for r in self.records if r['call']['step_index']==618086);allws=record['own_witnesses']+[w for c in record['nested_returns'].values() for w in c['memory_witnesses']]
        auxread=next(w for w in allws if any(q['address']==0xAD0D for q in w['reads']));last=max((w for w in allws if w['step_index']<auxread['step_index'] and any(q['address']==0xAD0D for q in w['writes'])),key=lambda w:w['step_index'])
        self.assertEqual((last['step_index'],auxread['step_index']),(619714,621220));self.assertEqual(last['writes'][0]['new_value'],15)
        iteration=next(i for r in self.rows if r['call_step']==618086 for i in r['forward'] if i['cursor']==5);self.assertEqual([(c['channel'],c['byte']) for c in iteration['channels']],[('mapped-byte',30),('primary-auxiliary-byte',15)])

    def test_attributes_channels_word_cache_and_recycle_correlate(self):
        expected={2:['mapped-byte','mapped-word-low','mapped-word-high'],3:['mapped-byte','second-auxiliary-byte','primary-auxiliary-byte'],4:['mapped-byte','primary-auxiliary-byte']}
        iterations=[i for r in self.rows for i in r['forward']];self.assertEqual(Counter(i['attribute'] for i in iterations),Counter({2:42,3:7,4:53}));self.assertEqual(sum(len(i['channels']) for i in iterations),253)
        for r,row in zip(self.records,self.rows):
            view,iv=checker_input(r);ws=r['own_witnesses']
            for i in row['forward']:
                transform=view['calls'][str(i['transform_call_step'])];ret=view['steps'][str(transform['post_return_state_step'])]['after'];write=next(w for w in at(ws,0x7DDE) if w['step_index']>transform['post_return_state_step']);self.assertEqual((i['attribute'],write['before']['a'],write['writes'][0]['new_value']),(ret['a'],ret['a'],ret['a']))
                self.assertEqual([c['channel'] for c in i['channels']],expected[i['attribute']]);self.assertEqual(i['channels'][0]['byte'],i['mapped'])
                if i['attribute']==2:
                    low,high=i['channels'][1:];self.assertLess(low['wrapper_call_step'],high['wrapper_call_step']);self.assertEqual(low['word'],high['word']);self.assertEqual((low['byte'],high['byte']),(low['word']&255,low['word']>>8))
                self.assertEqual(i['recycle_write']['new_value'],i['recycle_old_index']);self.assertEqual(i['fresh_map_read']['address'],0xAA1F+i['cursor']);self.assertEqual(i['new_index_write']['new_value'],i['fresh_map_read']['value'])
        # Equal-valued word bytes still have distinct wrapper call identities.
        zeros=[i for i in iterations if i['attribute']==2 and i['channels'][1]['byte']==i['channels'][2]['byte']];self.assertTrue(zeros);self.assertTrue(all(i['channels'][1]['wrapper_call_step']!=i['channels'][2]['wrapper_call_step'] for i in zeros))

    def test_RAW_pair_attr6_and_forward_wrap_stay_unobserved(self):
        manifest=load(ROOT/'research/annotated-assembly/manifest.json');image=next(i for i in manifest['images'] if i['name']=='PLI1.OVL');raw=(IMAGES/'PLI1.OVL').read_bytes();self.assertEqual(raw[0x7E2B:0x7E31],bytes.fromhex('CD46A0CD56A0'))
        for o in range(0x7E2B,0x7E31):self.assertEqual(status_at(image,o),'RAW')
        for r in self.records:
            ws=r['own_witnesses'];self.assertFalse(at(ws,0x7E2B));self.assertFalse(at(ws,0x7E2E))
            for w in at(ws,0x7E19):self.assertFalse(w['control']['taken']);self.assertEqual(ws[ws.index(w)-1]['origin']['offset'],0x7E17)
            for w in at(ws,0x7E28):self.assertTrue(w['control']['taken']);self.assertEqual(ws[ws.index(w)-1]['origin']['offset'],0x7E26)
            for w in at(ws,0x7E3C):
                producer=ws[ws.index(w)-1];self.assertEqual(producer['origin']['offset'],0x7E3B);self.assertEqual(w['before']['flags'],producer['after']['flags']);value=producer['writes'][0]['new_value'];self.assertEqual(value,(producer['reads'][0]['value']+1)&255);self.assertEqual(w['control']['taken'],value!=0);self.assertNotEqual(value,0)
        p=self.catalog[KEY];self.assertEqual(p['completeness'],dict(bounds='provisional',control_flow='partial',contract='partial'));self.assertEqual(p['observed_paths']['represented_bytes'],237)
        rows=[json.loads(s) for s in (ROOT/'research/minimal-baseline/instructions.jsonl').read_text().splitlines()];self.assertEqual(calculate(manifest,rows),load(ROOT/'research/minimal-baseline/dynamic-progress.json'));self.assertEqual(sum(i['length'] for i in manifest['images']),94720)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--images',type=Path,required=True);parser.add_argument('--capture',type=Path,default=ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture')
    args,remaining=parser.parse_known_args();IMAGES,CAPTURE=args.images,args.capture
    unittest.main(argv=[sys.argv[0],*remaining])
