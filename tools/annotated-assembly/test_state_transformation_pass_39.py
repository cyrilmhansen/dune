"""Incremental state-transformation, publication provenance and delegated-scope checks."""
import argparse,copy,subprocess,json,unittest
from collections import Counter
from check_state_transformation_pass_39 import *
BASE='fe6e25bdae01f787731cb45e1bef17296d7d3b2e'
class PassThirtyNineTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.rows={s:gather(c,BOUNDS,include_nested_returns=True,software_callees=SOFTWARE)for s,c in CAPTURES.items()};cls.analyses=analyze(cls.rows,IMAGES)
  cls.base={p['id']:p for p in json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json'],text=True))['procedures']};cls.reference=cls.base|load(REPORT/'after.json');cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
 def test_fresh_counts_callers_and_all_independent_windows(self):
  self.assertEqual(summary(self.rows,self.analyses),load(REPORT/'natural-summary.json'))
  self.assertEqual(sum(len(rs)for g in self.rows.values()for rs in g.values()),160)
  self.assertEqual([len(g['PLI1.OVL+30C1'])for g in self.rows.values()],[0,8,0]);self.assertEqual([len(g['PLI1.OVL+2C59'])for g in self.rows.values()],[0,10,1])
  self.assertEqual(Counter(coord(r['call']['origin'])for r in self.rows['FIZZBUZ']['PLI1.OVL+30C1']),{'PLI1.OVL+3307':5,'PLI1.OVL+3481':3})
 def test_compact_packet_regeneration_and_interning(self):
  p=build_packet(self.rows,self.reference);self.assertEqual(p,load(REPORT/'work-packet.json'));self.assertLessEqual((REPORT/'work-packet.json').stat().st_size,32768);self.assertEqual((len(p['cases']),len(p['routes']),len(p['stack_patterns'])),(19,2,4))
 def test_single_copy_full_proof_hash(self):
  b=encode_full_proof(self.rows,self.analyses);e=load(REPORT/'efficiency.json');self.assertEqual(hashlib.sha256(b).hexdigest(),e['full_rederivable_evidence_sha256']);self.assertEqual(len(b),e['full_rederivable_evidence_bytes']);self.assertEqual(e['oracle_queries'],0)
 def test_catalog_preserves_old_contracts(self):
  epoch=load(ROOT/'research/host-compiler/pass-40/before.json')
  self.assertTrue(all((epoch.get(k) or self.catalog[k])==p for k,p in self.base.items()))
  for k,p in load(REPORT/'after.json').items():
   self.assertEqual(p,self.catalog[k]);self.assertEqual(p['observed_paths']['invocations_by_run'],{s:len(g[k])for s,g in self.rows.items()});union={w['origin']['offset']+i for g in self.rows.values()for r in g[k]for w in r['own_witnesses']for i in range(len(bytes.fromhex(w['bytes'])))};self.assertEqual(len(union),p['observed_paths']['represented_bytes'])
 def test_zero_mask_leaf_AND_and_rotate_channels(self):
  for g in self.rows.values():
   for r in g['PLI1.OVL+21D4']:self.assertEqual(validate(r)['result'],255)
   for r in g['PLI1.OVL+22C0']:self.assertEqual(r['ret']['after']['a'],127);self.assertTrue(r['ret']['after']['flags']['carry'])
 def test_clamped_lookup_indices_and_flags_independent_of_result(self):
  rs=self.rows['FIZZBUZ']['PLI1.OVL+25D6'];self.assertEqual(Counter(validate(r)['value']for r in rs),{7:2,4:5})
  for r in rs:
   q=validate(r);self.assertEqual(q['index'],min(r['entry']['before']['c'],16));self.assertEqual(r['ret']['after']['flags'],dict(cmp(r['entry']['before']['c'],16),carry=False))
 def test_secondary_conversion_true_false_and_order(self):
  rs=self.rows['FIZZBUZ']['PLI1.OVL+2FC2'];self.assertEqual(Counter(validate(r)['route']for r in rs),{'selector15_transform':7,'selector15_no_transform':1})
  for r in rs:
   cs=children(r);self.assertEqual([c['target'].split('+')[-1]for c in cs[-3:]],['23B9','23B9','23A0']);self.assertEqual(r['ret']['after']['d'],0x35);self.assertEqual(validate(r)['result'],15)
 def test_fresh_parent_publications_and_child_registers(self):
  for r in self.rows['FIZZBUZ']['PLI1.OVL+30C1']:
   q=validate(r);self.assertEqual(q['primary'],15);self.assertEqual(q['extra'],0);self.assertEqual(q['result'],15);self.assertEqual(r['ret']['after']['flags'],children(r)[-1]['output']['flags'])
 def test_post_acquisition_selected_bytes_and_no_local_publication(self):
  for g in self.rows.values():
   for r in g['PLI1.OVL+2C59']:
    q=validate(r);self.assertEqual((q['index'],q['selected'],q['base']),(2,21,21));self.assertFalse(writes(r['own_witnesses']));self.assertEqual(r['ret']['after']['flags'],cmp(21,22))
 def test_required_acquisition_alternate_arm_is_real(self):
  rs=[r for g in self.rows.values()for r in g['PLI1.OVL+28AA']if acquisition_interface(r)['route']=='selected02_copy'];self.assertEqual(len(rs),10)
  for r in rs:
   q=acquisition_interface(r);c=q['children'][1];self.assertEqual(c['target'],'PLI1.OVL+6708');self.assertEqual(c['E'],2);self.assertEqual(c['software_argument_bytes'],8)
  self.assertEqual({acquisition_interface(r)['children'][1]['C']for r in rs},{1,2})
 def test_word_OR_leaf_read_order_and_final_flags(self):
  for g in self.rows.values():
   for r in g['PLI1.OVL+834F']:
    q=validate(r);self.assertEqual(q['result'],q['input_HL']|(q['low']+256*q['high']));self.assertFalse(r['ret']['after']['flags']['carry']);self.assertFalse(r['ret']['after']['flags']['auxiliary_carry']);self.assertFalse(writes(r['own_witnesses']))
 def test_stack_derived_CALL_and_PSW_last_writers(self):
  for g in self.rows.values():
   for rs in g.values():
    for r in rs:
     st=stack(r);self.assertEqual(st,[q for q in self.analyses[next(s for s,x in self.rows.items()if x is g)][r['entry_key']]if q['call_step']==r['call']['step_index']][0]['stack'])
 def test_parent_child_identity_and_second_channel_mutation(self):
  p=json.loads((REPORT/'parent-correlations.json').read_text());self.assertEqual(len(p),5);self.assertEqual(sum(q['second_child']is not None for q in p),4)
  actual={r['call']['step_index']:r for r in self.rows['FIZZBUZ']['PLI1.OVL+30C1']}
  for q in p:
   self.assertEqual(q['first_child_law'],validate(actual[q['first_child_call']]))
   if q['second_child']:
    x=q['second_child'];self.assertEqual((x['selected_before'],x['selected_after']),(2,21));self.assertEqual(x['software_child'][0]['E'],2)
   self.assertEqual(q['final_return']['flags'],q['final329F']['flags'])
 def test_RAW_alternatives_not_promoted(self):
  im=next(i for i in load(ROOT/'research/annotated-assembly/manifest.json')['images']if i['name']=='PLI1.OVL');st={n:s['status']for s in im['sections']for n in range(s['start_offset'],s['end_offset'])}
  for a,b in [(0x310c,0x3114),(0x3146,0x314b),(0x317c,0x3198),(0x3005,0x300f),(0x3026,0x3037),(0x3083,0x30c0),(0x22c7,0x22ca)]:self.assertTrue(all(st[n]=='RAW'for n in range(a,b)))
 def test_equal_value_wrong_source_address_rejected(self):
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+30C1'][0]);one(r['own_witnesses'],0x3151)['reads'][0]['address']=0xa630
  with self.assertRaises(ValueError):validate(r)
 def test_changed_publication_or_return_flags_rejected(self):
  for kind in ['write','flags']:
   r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+2FC2'][0])
   if kind=='write':one(r['own_witnesses'],0x3067)['writes'][0]['new_value']^=1
   else:r['ret']['after']['flags']['carry']=True
   with self.assertRaises(ValueError):validate(r)
 def test_stack_residue_corruption_rejected(self):
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+30C1'][0]);next(w for w in r['own_witnesses']if w['disassembly']=='PUSH PSW')['writes'][0]['new_value']^=1
  with self.assertRaises(ValueError):stack(r)
 def test_changed_canonical_bytes_rejected(self):
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+25D6'][0]);r['own_witnesses'][0]['bytes']='00'
  g={s:{k:[]for k in BOUNDS}for s in self.rows};g['FIZZBUZ']['PLI1.OVL+25D6']=[r]
  with self.assertRaises(ValueError):analyze(g,IMAGES)
 def test_native_readiness_not_implied_by_parent_return(self):
  q=load(REPORT/'boundary-assessment.json');self.assertFalse(q['3304_reproducible']);self.assertFalse(q['784E_sole_blocker']);self.assertEqual(q['next_causal_blocker'],'PLI1.OVL+28AA selected02 / +6708 alternate67BE')
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--images',type=Path,required=True);args,rest=parser.parse_known_args();IMAGES=args.images;unittest.main(argv=[__file__]+rest)
