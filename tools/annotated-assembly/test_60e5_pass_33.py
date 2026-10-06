"""Independent natural transition, ancestry and historical-byte regressions."""
import argparse,copy,hashlib,json,sys,unittest
from pathlib import Path
from collections import Counter
from check_60e5_pass_33 import *
class PassThirtyThreeTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.rows={s:gather(c,BOUNDS,include_nested_returns=True)for s,c in CAPTURES.items()}
  cls.relations={s:relation_index(c,cls.rows[s]['PLI1.OVL+60E5'])for s,c in CAPTURES.items()}
  cls.analyses=[analyze(s,c,IMAGES,cls.rows[s],cls.relations[s])for s,c in CAPTURES.items()]
  cls.actual=derive(cls.analyses);cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
 def test_durable_reports_and_selected_capture_identity(self):
  for n in FILES:self.assertEqual(self.actual[n],load(REPORT/(n+'.json')))
  self.assertEqual([len(a['cases'])for a in self.analyses],[0,8,2]);self.assertEqual([counts(str(c['output']['a'])for c in a['cases'])for a in self.analyses],[{},{'0':5,'1':3},{'0':2}])
 def test_catalog_counts_callers_and_represented_byte_union(self):
  for key,p in load(REPORT/'after.json').items():
   self.assertEqual(p,self.catalog[key]);rs={s:g[key]for s,g in self.rows.items()if key in g}
   if not rs:continue
   self.assertEqual(p['observed_paths']['invocations_by_run'],{s:len(v)for s,v in rs.items()})
   for s,v in rs.items():self.assertEqual(Counter(coord(r['call']['origin'])for r in v),{c['coordinate']:c['counts_by_run'][s]for c in p['callers']if s in c['counts_by_run']})
   union={w['origin']['offset']+i for v in rs.values()for r in v for w in r['own_witnesses']for i in range(len(bytes.fromhex(w['bytes'])))}
   self.assertEqual(p['observed_paths']['represented_bytes'],len(union))
 def test_frame_setup_pointer_advance_restore_and_return_byte(self):
  for a in self.analyses:
   for r in a['cases']:
    self.assertEqual(r['old_index'],0);self.assertEqual(r['new_pointer_base'],r['old_pointer_base']+2)
    self.assertEqual(r['output']['a'],r['children'][0]['output']['a']);self.assertEqual(pair(r['output'],'h','l'),(r['old_pointer_base']>>8)+256*r['old_index'])
    self.assertEqual(pair(r['output'],'d','e'),r['frame_base']+1);self.assertEqual(pair(r['output'],'b','c'),0xfc)
    writes=r['local_writes'];self.assertEqual([x['writer']for x in writes][-3:],['PLI1.OVL+618D','PLI1.OVL+618D','PLI1.OVL+6192'])
    self.assertEqual([x['value']for x in writes][-3:],[r['old_pointer_base']&255,r['old_pointer_base']>>8,r['old_index']])
    self.assertEqual(r['output']['flags'],r['final_RAR']['flags'])
 def test_exact_natural_child_order_and_fresh_pointer_rereads(self):
  for a in self.analyses:
   for r in a['cases']:
    self.assertEqual([c['target']for c in r['children']],['PLI1.OVL+5E98','PLI1.OVL+5E65','PLI1.OVL+41AF','PLI1.OVL+5E65','PLI1.OVL+41AF','PLI1.OVL+01AF'])
    first,second=r['children'][1],r['children'][3];self.assertNotEqual(first['call_step'],second['call_step']);self.assertEqual(first['entry']['c'],0);self.assertEqual(second['entry']['c'],0)
    expected=4 if r['output']['a']==0 else 0;self.assertEqual([r['children'][i]['output']['a']for i in [2,4]],[expected,expected])
 def test_acquisition_masks_loop_exit_and_return_flags(self):
  for a in self.analyses:
   for r in a['acquisitions']:
    self.assertEqual(r['field_byte'],0x80 if r['output']['a']else 0x15)
    cs=r['children']
    if r['field_byte']==0x15:
     self.assertEqual([q['output']['a']for q in cs if q['target']=='PLI1.OVL+4275'],[255,0])
     self.assertEqual(r['output']['flags'],dict(sign=True,zero=False,auxiliary_carry=False,parity=True,carry=False))
    else:self.assertEqual([q['output']['a']for q in cs if q['target']=='PLI1.OVL+3DD9'],[1,1])
 def test_literal_one_writer_follows_nested_reentry(self):
  for a in self.analyses:
   for d in a['dispatch']:
    pub=d['literal_result_writers'][-1];self.assertEqual(pub['writer'],'PLI1.OVL+5031');self.assertEqual(pub['value'],1)
    nested=[r for outer in a['reentries']for r in outer['nested']if d['call_step']<r['call_step']<d['return_step']]
    self.assertEqual(len(nested),2);self.assertTrue(all(n['return_step']<pub['step']for n in nested));self.assertEqual(d['output']['a'],1)
 def test_reentry_corrected_call_spine_and_depth(self):
  a=next(a for a in self.analyses if a['source']=='FIZZBUZ');self.assertEqual(len(a['reentries']),3)
  self.assertEqual(sum(len(c['nested'])for c in a['reentries']),6)
  for c in a['reentries']:
   self.assertEqual(c['maximum_60E5_window_depth'],2)
   self.assertEqual([p['caller']for p in c['outer_context']],['PLI1.OVL+6273','PLI1.OVL+622A','PLI1.OVL+620C'])
   self.assertTrue(all(p['call_step']<c['outer_60E5_call_step']<p['return_step']for p in c['outer_context']))
   for n in c['nested']:
    spine=n['spine'];self.assertEqual(spine[0]['callsite'],'PLI1.OVL+610F');self.assertEqual(spine[-1]['callsite'],'PLI1.OVL+6273')
    self.assertEqual([x['target']for x in spine[:4]],['PLI1.OVL+5E98','PLI1.OVL+506E','PLI1.OVL+500F','PLI1.OVL+4F54'])
    self.assertTrue(all(x['call_step']<=n['call_step']and x['return_step']>=n['return_step']for x in spine));self.assertTrue(all(x['stack_slot']>y['stack_slot']for x,y in zip(spine,spine[1:])))
 def test_leaf_laws_against_every_natural_invocation(self):
  for s,g in self.rows.items():
   for key in ['PLI1.OVL+5E65','PLI1.OVL+5E48','PLI1.OVL+5E53']:
    for r in g[key]:self.assertIsNotNone(validate_leaf(r))
  self.assertEqual([len(g['PLI1.OVL+5E65'])for g in self.rows.values()],[0,29,8]);self.assertEqual([len(g['PLI1.OVL+5E48'])for g in self.rows.values()],[0,5,2])
  for key in ['PLI1.OVL+5E65','PLI1.OVL+5E48','PLI1.OVL+81F1']:self.assertEqual(self.catalog[key]['completeness'],dict(bounds='stable',control_flow='complete',contract='complete'))
 def test_flag_or_pointer_corruption_rejected(self):
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+5E65'][0]);r['ret']['after']['flags']['carry']=not r['ret']['after']['flags']['carry']
  with self.assertRaises(ValueError):validate_leaf(r)
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+5E65'][0]);one(r['own_witnesses'],0x5e74)['reads'][0]['address']+=1
  with self.assertRaises(ValueError):validate_leaf(r)
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+5E48'][0]);r['ret']['after']['flags']['zero']=True
  with self.assertRaises(ValueError):validate_leaf(r)
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+5E98'][0]);w=next(w for w in r['own_witnesses']if w['disassembly']=='PUSH PSW');w['writes'][1]['new_value']^=2
  with self.assertRaises(ValueError):frame_setup(r)
 def test_raw_alternatives_remain_raw_and_partial_scope(self):
  im=next(i for i in load(ROOT/'research/annotated-assembly/manifest.json')['images']if i['name']=='PLI1.OVL')
  for lo,hi in [(0x5e5d,0x5e65),(0x6124,0x6127),(0x6135,0x6146),(0x614e,0x6153),(0x615c,0x6185),(0x619d,0x61a4)]:
   self.assertTrue(all(s['status']=='RAW'for s in im['sections']if s['start_offset']<hi and s['end_offset']>lo))
  for key in ['PLI1.OVL+60E5','PLI1.OVL+5E98','PLI1.OVL+5E53']:self.assertEqual(self.catalog[key]['completeness']['contract'],'partial')
 def test_exact_return_slots_and_stack_last_writer_evidence(self):
  for g in self.rows.values():
   for key in ['PLI1.OVL+60E5','PLI1.OVL+5E98']:
    for r in g[key]:
     verify_return(r['call'],r['ret'],r['relation']);self.assertEqual(r['ret']['after']['sp'],r['entry']['before']['sp']+2)
     q=chronology(r);self.assertTrue(q['final_stack_writers']);self.assertTrue(all(x['relative_address']<2 for x in q['final_stack_writers']))
 def test_candidate_query_design_and_no_native_runtime_changes(self):
  facts=load(REPORT/'candidate-falsification.json');self.assertEqual(facts['historical_binary_query_cases'],32768);self.assertEqual(facts['state_selection'],'machine byte/register/memory law; no corpus/step/hash selection')
  self.assertFalse(load(REPORT/'boundary-assessment.json')['native_6223_ready'])
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);args,rest=p.parse_known_args();IMAGES=args.images.resolve();unittest.main(argv=[sys.argv[0],*rest])
