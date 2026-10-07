#!/usr/bin/env python3
"""Independent path, value, flag, ownership and scoped-promotion regressions."""
import argparse,copy,hashlib,json,sys,unittest
from pathlib import Path
from collections import Counter
from check_6223_pass_32 import *
class PassThirtyTwoTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.rows={s:gather(c,BOUNDS,include_nested_returns=True)for s,c in CAPTURES.items()}
  cls.actual=derive([analyze(s,CAPTURES[s],IMAGES,rs)for s,rs in cls.rows.items()])
  cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
 def test_fresh_reports_counts_and_exact_callers(self):
  for n in FILES:self.assertEqual(self.actual[n],load(REPORT/(n+'.json')))
  for s,rs in self.rows.items():
   for key,rows in rs.items():
    p=self.catalog[key];self.assertEqual(len(rows),p['observed_paths']['invocations_by_run'][s])
    self.assertEqual(Counter(coord(r['call']['origin'])for r in rows),{c['coordinate']:c['counts_by_run'][s]for c in p['callers']if s in c['counts_by_run']})
  self.assertEqual([len(rs['PLI1.OVL+6223'])for rs in self.rows.values()],[1,18,2])
 def test_routes_rotate_carry_and_immediate_producer(self):
  routes=Counter()
  for source in self.actual['natural-roots']['sources']:
   for r in source['roots']:
    routes[r['route']]+=1;rot=r['first_RAR'];self.assertEqual(rot['output_A'],(rot['input_A']//2)+(128 if rot['input_CY']else 0));self.assertEqual(rot['flags']['carry'],bool(rot['input_A']%2))
    if r['route']=='B_5929_2511':self.assertEqual(r['predicate'],0);self.assertIsNone(r['second_RAR'])
    else:
     self.assertEqual(r['predicate'],255);second=r['second_RAR'];self.assertEqual(second['flags']['carry'],bool(r['local_predicate']&1))
     self.assertEqual(r['route']=='A_early',r['local_predicate']==0)
  self.assertEqual(routes,{'B_5929_2511':13,'A_01E8_256C':5,'A_early':3})
  nested=Counter()
  for source in self.actual['natural-roots']['sources']:
   by_step={r['call_step']:r for r in source['roots']}
   for r in source['roots']:
    if r['nearest_enclosing_6223_call_step']is None:continue
    nested[source['source']]+=1;parent=by_step[r['nearest_enclosing_6223_call_step']]
    self.assertEqual(parent['route'],'A_early');self.assertEqual(r['enclosing_direct_child'],'PLI1.OVL+620C');self.assertEqual(r['window_depth'],2)
    self.assertLess(parent['call_step'],r['call_step']);self.assertLess(r['return_step'],parent['return_step']);self.assertGreaterEqual(parent['entry']['sp'],r['entry']['sp']+2)
  self.assertEqual(nested,{'FIZZBUZ':6})
  for rs in self.rows.values():
   for r in rs['PLI1.OVL+6223']:
    ws=r['own_witnesses']
    for jump,producer in [(0x6227,0x6226),(0x622e,0x622d)]:
     if not any(w['origin']['offset']==jump for w in ws):continue
     self.assertEqual(one(ws,jump)['before']['flags'],one(ws,producer)['after']['flags']);self.assertEqual(one(ws,jump)['control']['taken'],not one(ws,producer)['after']['flags']['carry'])
 def test_independent_fresh239A_values_and_channel_order(self):
  selections={(s['source'],c['call_step']):c for s in self.actual['child-correlations']['sources']for c in s['dependencies']['PLI1.OVL+239A']['cases']}
  for source in self.actual['natural-roots']['sources']:
   for r in source['roots']:
    if r['value_flow']is None:continue
    f=r['value_flow'];self.assertEqual((f['returned_A'],f['after_ADI13'],f['input_C']),(4,23,23))
    calls=r['children'];selected=next(c for c in calls if c['target']=='PLI1.OVL+239A');self.assertLess(selected['return_step'],calls[-1]['call_step'])
    detail=selections[source['source'],selected['call_step']];v=detail['selected_A628'];self.assertIn(v,[2,5,21]);self.assertEqual(v==21,r['route']=='A_01E8_256C')
    self.assertEqual([q['target']for q in detail['dispatch_child_calls']],['PLI1.OVL+21AD','PLI1.OVL+230E','PLI1.OVL+22CB']);self.assertEqual(selected['output']['flags']['carry'],v!=21)
    self.assertEqual({k:r['output'][k]for k in 'abcdehl'},{k:calls[-1]['output'][k]for k in 'abcdehl'})
  for rs in self.rows.values():
   for r in rs['PLI1.OVL+239A']:
    call=one(r['own_witnesses'],0x239c);self.assertEqual(call['before']['c'],0)
    self.assertEqual(r['ret']['after']['flags'],r['nested_returns'][call['step_index']]['ret']['after']['flags'])
 def test620C_cache_second_borrow_flags_and_child_domain(self):
  distribution=Counter()
  for s in self.actual['child-correlations']['sources']:
   for r in s['dependencies']['PLI1.OVL+620C']['cases']:
    distribution[r['child_A'],r['result']]+=1;self.assertEqual(r['local_writes'],[dict(step=r['entry_step']+r['children'][0]['instruction_occurrences']+1,coordinate='PLI1.OVL+620F',address=0xa945,value=r['child_A'])])
    if r['child_A']==0:self.assertEqual(r['output']['flags'],dict(sign=False,zero=True,auxiliary_carry=True,parity=True,carry=False))
    else:self.assertEqual(r['child_A'],1);self.assertEqual(r['result'],0)
  self.assertEqual(distribution,{(0,1):5,(1,0):3})
 def test256C_frame_attr6_distinction_and_child_abi(self):
  attr=Counter()
  for rs in self.rows.values():
   for r in rs['PLI1.OVL+256C']:
    ws=r['own_witnesses'];input_C=r['entry']['before']['c'];sp=r['entry']['before']['sp'];push=one(ws,0x256d)
    self.assertEqual([(q['address'],q['new_value'])for q in push['writes']],[(sp-1,input_C),(sp-2,input_C)])
    call=one(ws,0x2574);a=r['nested_returns'][call['step_index']]['ret']['after']['a'];attr[a]+=1
    self.assertEqual(one(ws,0x2579)['control']['taken'],a!=6)
    if a==6:
     self.assertEqual(input_C,24);self.assertEqual(one(ws,0x2591)['before']['c'],0)
     self.assertEqual(one(ws,0x258c)['before']['c'],one(ws,0x2584)['reads'][0]['value'])
  self.assertEqual(attr,{4:9,6:1})
 def test5929_fresh_pointer_publications_and_nonconstant_results(self):
  for rs in self.rows.values():
   for r in rs['PLI1.OVL+5929']:
    ws=r['own_witnesses'];self.assertEqual(one(ws,0x5929)['after']['b']*256+one(ws,0x5929)['after']['c'],0x7923)
    self.assertTrue(one(ws,0x596e)['control']['taken']);self.assertFalse(one(ws,0x5930)['control']['taken'])
    for off in [0x59e0,0x59f6,0x5a11]:self.assertTrue(one(ws,off)['control']['taken'])
    self.assertEqual([q['address']for q in one(ws,0x593a)['reads']],[0xa863,0xa864]);self.assertEqual([q['address']for q in one(ws,0x5a23)['reads']],[0xa863,0xa864]);self.assertEqual([q['address']for q in one(ws,0x5a2b)['reads']],[0xa863,0xa864])
    self.assertEqual(one(ws,0x5948)['reads'][0]['address'],0x20c3);self.assertEqual(one(ws,0x594e)['reads'][0]['address'],0x20c5)
 def test_small_delegated_dependencies_and_raw_alternatives(self):
  image=(IMAGES/'PLI1.OVL').read_bytes();manifest=load(ROOT/'research/annotated-assembly/manifest.json');im=next(x for x in manifest['images']if x['name']=='PLI1.OVL')
  self.assertEqual(image[0x61a4:0x61ad],bytes.fromhex('2141A93600CDE582C9'))
  self.assertEqual(image[0x239a:0x23a0],bytes.fromhex('0E00CD5545C9'))
  for a,b in [(0x01f7,0x020e),(0x5971,0x59db),(0x59e3,0x59f1),(0x59f9,0x5a0c),(0x5a14,0x5a20),(0x5a42,0x5a45)]:
   self.assertTrue(all(x['status']=='RAW'for x in im['sections']if x['start_offset']<b and x['end_offset']>a))
  for key,p in load(REPORT/'after.json').items():
   prior33=load(ROOT/'research/host-compiler/pass-33/before.json')
   prior37=load(ROOT/'research/host-compiler/pass-37/before.json')
   self.assertEqual(p,prior33.get(key,prior37.get(key) or load(ROOT/'research/host-compiler/pass-42/before.json').get(key)or self.catalog[key]));union={w['origin']['offset']+i for rs in self.rows.values()for r in rs[key]for w in r['own_witnesses']for i in range(len(bytes.fromhex(w['bytes'])))}
   self.assertEqual(len(union),p['observed_paths']['represented_bytes']);self.assertEqual(p['completeness']['contract'],'partial')
  self.assertEqual(self.catalog['PLI1.OVL+6223']['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'))
 def test_stack_ancestry_and_per_invocation_final_writers(self):
  for s,rs in self.rows.items():
   for r in rs['PLI1.OVL+6223']:
    verify_return(r['call'],r['ret'],r['relation']);self.assertEqual(r['ret']['after']['sp'],r['entry']['before']['sp']+2)
    allws=body(r);final={q['address']:(w['step_index'],coord(w['origin']),q['new_value'])for w in allws for q in w['writes']if r['entry']['before']['sp']-256<=q['address']<r['entry']['before']['sp']+2}
    actual=chronology(r)['final_stack_writers'];self.assertEqual({q['address']:(q['step'],q['writer'],q['value'])for q in actual},final)
 def test_corruption_rejected(self):
  rows=copy.deepcopy(self.rows['FIZZBUZ']);r=rows['PLI1.OVL+6223'][0];one(r['own_witnesses'],0x6226)['after']['flags']['carry']=True
  with self.assertRaisesRegex(ValueError,'RAR'):analyze('FIZZBUZ',CAPTURES['FIZZBUZ'],IMAGES,rows)
  rows=copy.deepcopy(self.rows['FIZZBUZ']);r=rows['PLI1.OVL+6223'][0];one(r['own_witnesses'],0x6246)['after']['a']=24
  with self.assertRaisesRegex(ValueError,'ADI13'):analyze('FIZZBUZ',CAPTURES['FIZZBUZ'],IMAGES,rows)
 def test_images_outputs_and_next_boundary(self):
  manifest=load(ROOT/'research/annotated-assembly/manifest.json');self.assertEqual(sum(x['length']for x in manifest['images']),94720)
  for x in manifest['images']:self.assertEqual(hashlib.sha256((IMAGES/x['original_filename']).read_bytes()).hexdigest(),x['sha256'])
  for s,size,sha in [('MINIMAL',256,'7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119'),('FIZZBUZ',768,'68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203'),('PICTURE',256,'c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1')]:
   raw=(CAPTURES[s]/(s+'.REL')).read_bytes();self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()),(size,sha))
  assessment=load(REPORT/'boundary-assessment.json');self.assertFalse(assessment['native_6223_ready']);self.assertFalse(assessment['new_fixture_required']);self.assertIn('+60E5',assessment['recommendation'])
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--images',type=Path,required=True);args,rest=p.parse_known_args();IMAGES=args.images.resolve();unittest.main(argv=[sys.argv[0],*rest])
