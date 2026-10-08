"""Alternate acquisition arithmetic, copied continuation and independent channels."""
import argparse,copy,subprocess,unittest
from collections import Counter
from check_selector02_pass_40 import *
BASE='6010894d20941e9e3dfe2706a6cb37224862a6f8'
class PassFortyTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.rows={s:gather_selected(c,BOUNDS,include_nested_returns=True,software_callees=SOFTWARE)for s,c in CAPTURES.items()};cls.a=analyze(cls.rows,IMAGES);cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
  future=load(ROOT/'research/host-compiler/pass-46/before.json')
  cls.catalog={k:future.get(k) or v for k,v in cls.catalog.items()if k not in future or future[k]is not None}
 def selected(self,k):return [r for g in self.rows.values()for r in g[k]if k.endswith('28AA')and val(one(r['own_witnesses'],0x28b7),0xa628+(word_read(one(r['own_witnesses'],0x28ae),0xa634)&255))==2 or k.endswith('6708')and r['entry']['before']['e']==2]
 def test_counts_and_route_distributions(self):
  self.assertEqual(projection(self.rows,self.a),load(REPORT/'route-distribution.json'));self.assertEqual(sum(len(v)for g in self.rows.values()for v in g.values()),107)
  self.assertEqual([len(g['PLI1.OVL+6708'])for g in self.rows.values()],[2,15,1]);self.assertEqual(len(self.selected('PLI1.OVL+6708')),10);self.assertEqual(len(self.selected('PLI1.OVL+28AA')),10)
 def test_compact_packet_exact_regeneration(self):
  self.assertEqual(build_packet(self.rows,self.a,self.catalog),load(REPORT/'work-packet.json'));self.assertLessEqual((REPORT/'work-packet.json').stat().st_size,32768)
 def test_rederivable_full_proof_hash(self):
  b=encode_full_proof(self.rows,self.a);e=load(REPORT/'efficiency.json');self.assertEqual(hashlib.sha256(b).hexdigest(),e['full_rederivable_evidence_sha256']);self.assertEqual(len(b),e['full_rederivable_evidence_bytes'])
 def test_E02_actual_decimal_routes_and_count_lengths(self):
  rs=self.selected('PLI1.OVL+6708');self.assertEqual(Counter(r['entry']['before']['c']for r in rs),{1:7,2:3});self.assertEqual(Counter(validate_alternate(r)['result']for r in rs),{0:3,1:1,15:3,3:1,5:1,7:1})
  for r in rs:self.assertIn(0x67be,{w['origin']['offset']for w in r['own_witnesses']});self.assertEqual(validate_alternate(r)['result'],sum((b-48)*10**i for i,b in enumerate(reversed(validate_alternate(r)['digits']))))
 def test_four_argument_words_and_eight_byte_consumption(self):
  for r in self.selected('PLI1.OVL+6708'):
   q=validate_alternate(r);self.assertEqual(q['selector'],q['args'][1]&255);self.assertEqual(q['prefix'],q['args'][3]&255);self.assertEqual(r['ret']['after']['sp'],r['entry']['before']['sp']+10);self.assertEqual(r['ret']['after']['pc'],r['call']['call_return_address'])
 def test_consumed_stack_cells_have_derived_last_writers(self):
  for r in self.selected('PLI1.OVL+6708'):
   st=stack_extended(r);self.assertTrue(any(q['relative_address']>=0 for q in st));self.assertTrue(all(q['relative_address']<10 for q in st));self.assertEqual([q['writer']for q in st if q['relative_address']in[8,9]],['PLI1.OVL+671F']*2)
 def test_final_A_not_final_flags_or_parent_publication(self):
  for r in self.selected('PLI1.OVL+6708'):self.assertEqual(r['ret']['after']['a'],1);self.assertEqual(r['ret']['after']['flags'],cmp(7,15))
  for r in self.selected('PLI1.OVL+28AA'):self.assertEqual(validate_parent(r)['output_A'],23)
 def test_iterative_multiply10_return_and_stack(self):
  for g in self.rows.values():
   for r in g['PLI1.OVL+8309']:
    q=validate_leaf(r);self.assertEqual(q['result'],(10*q['word'])&65535);self.assertEqual(pair(r['ret']['after'],'b','c'),q['twice']);self.assertEqual({z['writer']for z in stack_extended(r)},{'PLI1.OVL+830E'})
 def test_nibble_and_classifier_bit_routes_observed(self):
  allroutes={validate_leaf(r)['route']for g in self.rows.values()for r in g['PLI1.OVL+2185']};self.assertEqual(allroutes,{'nibble10_literal1','child_bit_literal1','fallback_equal31_mask'})
 def test_parent_child_order_and_separate_publications(self):
  for r in self.selected('PLI1.OVL+28AA'):
   q=validate_parent(r);self.assertEqual(q['selected_after'],21);self.assertEqual(q['adjusted'],23);self.assertEqual(q['second_position'],(q['stop']+1)&255)
 def test_catalog_statuses_and_prior_unchanged_entries(self):
  before=load(REPORT/'before.json');after=load(REPORT/'after.json');base={p['id']:p for p in json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json'],text=True))['procedures']}
  epoch=load(ROOT/'research/host-compiler/pass-45/before.json')|(load(ROOT/'research/host-compiler/pass-42/before.json')|load(ROOT/'research/host-compiler/pass-41/before.json'));self.assertTrue(all((epoch.get(k)or self.catalog[k])==p for k,p in base.items()if k not in after));self.assertEqual({k:self.catalog[k]for k in after},after)
  for k in ['28AA','6708']:self.assertEqual(self.catalog['PLI1.OVL+'+k]['completeness'],dict(bounds='provisional',control_flow='partial',contract='partial'))
  self.assertEqual(self.catalog['PLI1.OVL+8309']['completeness']['contract'],'complete');self.assertEqual(self.catalog['PLI1.OVL+2185']['completeness']['contract'],'partial')
 def test_unobserved_alternatives_RAW(self):
  im=next(i for i in load(ROOT/'research/annotated-assembly/manifest.json')['images']if i['name']=='PLI1.OVL');st={n:s['status']for s in im['sections']for n in range(s['start_offset'],s['end_offset'])}
  for a,b in [(0x6bf3,0x6bf6),(0x6c2c,0x6c2f),(0x6c6e,0x6c71),(0x6c79,0x6c82),(0x6c91,0x6c99)]:self.assertTrue(all(st[n]=='RAW'for n in range(a,b)))
 def test_changed_equal_valued_source_rejected(self):
  r=copy.deepcopy(self.selected('PLI1.OVL+6708')[0]);one(r['own_witnesses'],0x6c20)['reads'][0]['address']+=1
  with self.assertRaises(ValueError):validate_alternate(r)
 def test_changed_return_flags_or_logical_write_rejected(self):
  for kind in ['flags','write']:
   r=copy.deepcopy(self.selected('PLI1.OVL+6708')[0])
   if kind=='flags':r['ret']['after']['flags']['carry']=False
   else:one(r['own_witnesses'],0x6ba3)['writes'][0]['new_value']^=1
   with self.assertRaises(ValueError):validate_alternate(r)
 def test_changed_copied_continuation_rejected(self):
  r=copy.deepcopy(self.selected('PLI1.OVL+6708')[0]);one(r['software_proof']['prefix'],0x671f)['writes'][0]['new_value']^=1
  with self.assertRaises(ValueError):validate_alternate(r)
 def test_changed_canonical_bytes_rejected(self):
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+8309'][0]);r['own_witnesses'][0]['bytes']='00';g={s:{k:[]for k in BOUNDS}for s in self.rows};g['FIZZBUZ']['PLI1.OVL+8309']=[r]
  with self.assertRaises(ValueError):analyze(g,IMAGES)
 def test_scope_readiness_and_required_blockers(self):
  q=load(REPORT/'boundary-assessment.json');self.assertTrue(q['selector02_28AA_reproducible']and q['2C59_reproducible']and q['3304_reproducible']);self.assertEqual(q['next_causal_blocker'],'PLI1.OVL+784E');self.assertEqual(load(REPORT/'candidate-falsification.json')['oracle_queries'],0)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=[__file__]+rest)
