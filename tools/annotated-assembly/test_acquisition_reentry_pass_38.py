"""Fresh corrected natural acquisition, causal reentry, ABI and corruption tests."""
import argparse,copy,json,sys,subprocess,unittest
from collections import Counter
from check_acquisition_reentry_pass_38 import *
class PassThirtyEightTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.rows={s:gather(c,BOUNDS,include_nested_returns=True)for s,c in CAPTURES.items()};cls.analyses=[analyze(s,c,IMAGES,cls.rows[s])for s,c in CAPTURES.items()]
  base=json.loads(subprocess.check_output(['git','show','280f491:research/annotated-assembly/procedures.json'],text=True));cls.reference={p['id']:p for p in base['procedures']};cls.reference.update(load(REPORT/'after.json'));cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
 def test_durable_reports_regenerate(self):
  self.assertEqual(derive(self.rows,self.analyses),load(REPORT/'natural-summary.json'));self.assertEqual(build_packet(self.rows,self.reference),load(REPORT/'work-packet.json'))
 def test_compact_packet_and_independent_windows(self):
  p=load(REPORT/'work-packet.json');self.assertLessEqual((REPORT/'work-packet.json').stat().st_size,32768);self.assertEqual((len(p['cases']),len(p['routes']),len(p['stack_patterns'])),(9,3,3));self.assertEqual(sum(len(rs)for g in self.rows.values()for rs in g.values()),252)
 def test_single_copy_full_proof_size_hash(self):
  import hashlib
  b=encode_full_proof(self.rows,self.analyses);e=load(REPORT/'efficiency.json');self.assertEqual(len(b),e['full_rederivable_evidence_bytes']);self.assertEqual(hashlib.sha256(b).hexdigest(),e['full_rederivable_evidence_sha256']);self.assertEqual(e['oracle_queries'],0)
 def test_catalog_counts_and_supported_coordinate_union(self):
  for k,p in load(REPORT/'after.json').items():
   # Pass45 extends the previously RAW654E arm; the immutable Pass38 epoch remains its clear-route proof.
   if k!='PLI1.OVL+654E':self.assertEqual(p,self.catalog[k])
   else:self.assertEqual(p,self.reference[k])
   union=set()
   for s,g in self.rows.items():
    rs=g[k];self.assertEqual(len(rs),p['observed_paths']['invocations_by_run'][s]);self.assertEqual(Counter(coord(r['call']['origin'])for r in rs),{c['coordinate']:c['counts_by_run'][s]for c in p['callers']if s in c['counts_by_run']})
    for r in rs:
     if k.endswith('654E')and len(children(r))>2:continue
     union|={w['origin']['offset']+i for w in r['own_witnesses']for i in range(len(bytes.fromhex(w['bytes'])))}
   self.assertEqual(p['observed_paths']['represented_bytes'],len(union))
 def test_root_counts_callers(self):
  for k in ['506E','500F','4F54']:
   self.assertEqual([len(g['PLI1.OVL+'+k])for g in self.rows.values()],[0,3,0])
  self.assertEqual({coord(r['call']['origin'])for r in self.rows['FIZZBUZ']['PLI1.OVL+506E']},{'PLI1.OVL+5F3A'})
 def test_saved_E_selects_dispatch_not_C(self):
  for r in self.rows['FIZZBUZ']['PLI1.OVL+506E']:
   q=validate(r);self.assertEqual((q['input_C'],q['saved_E'],q['jump_slot'],q['jump_target']),(1,0x14,0x78c7,0x75bb));self.assertNotEqual(q['jump_slot'],0x789f+2*q['input_C'])
 def test_eight_byte_frame_and_return_carrier(self):
  for r in self.rows['FIZZBUZ']['PLI1.OVL+506E']:
   q=validate(r);self.assertEqual(q['frame_base'],r['entry']['before']['sp']-8);self.assertEqual(pair(r['ret']['after'],'d','e'),q['frame_base']+3);self.assertNotEqual(pair(r['ret']['after'],'d','e'),q['saved_pointer'])
 def test_indirect_spine_and_sequential_reentry(self):
  rs=reentries(self.rows);self.assertEqual(len(rs),3)
  for r in rs:
   self.assertEqual(len(r['reentries']),2);self.assertEqual([q['next_selector']for q in r['reentries']],[1,2]);self.assertEqual([q['reentry']['route']for q in r['reentries']],['A_01E8_256C','B_5929_2511']);self.assertEqual([q['reentry']['predicate']for q in r['reentries']],[255,0])
   self.assertTrue(all(len(q['spine_calls'])==8 for q in r['reentries']))
 def test_selected_clear_repeat_and_independent_loop_retention(self):
  for r in self.rows['FIZZBUZ']['PLI1.OVL+4F54']:
   for q in self.rows['FIZZBUZ']['PLI1.OVL+654E']:
    if r['call']['step_index']<q['call']['step_index']<q['ret']['step_index']<r['ret']['step_index']:self.assertEqual(validate(q)['route'],'clear_repeat_spine')
  self.assertEqual(sum(validate(r)['route']=='independent_substantial654E_loop'for r in self.rows['FIZZBUZ']['PLI1.OVL+654E']),3)
 def test_A932_publication_fresh_reread_not_child_A(self):
  g=self.rows['FIZZBUZ']
  for root in g['PLI1.OVL+506E']:
   r=next(q for q in g['PLI1.OVL+500F']if root['call']['step_index']<q['call']['step_index']<q['ret']['step_index']<root['ret']['step_index']);pub=one(r['own_witnesses'],0x5031);later=[(w,q)for w in body(root)for q in w['writes']if q['address']==0xa932]
   self.assertEqual([(w['step_index'],q['new_value'])for w,q in later],[(pub['step_index'],1)]);self.assertEqual(r['ret']['after']['a'],0x80);self.assertEqual(one(root['own_witnesses'],0x5706)['reads'][0]['value'],1)
 def test_classifier_wrapper_and_private_sum(self):
  for r in self.rows['FIZZBUZ']['PLI1.OVL+500F']:
   q=validate(r);self.assertEqual((q['saved_input'],q['adjustment_input'],q['adjusted_C']),(0xcf,2,0xd1));self.assertNotEqual(children(r)[1]['entry']['c'],0)
 def test_maximum_flags_two_routes_and_write_order(self):
  rs=self.rows['FIZZBUZ']['PLI1.OVL+23B9'];self.assertEqual(len(rs),24);self.assertEqual({validate(r)['route']for r in rs},{'E_ge_C','C_gt_E'});self.assertEqual(self.catalog['PLI1.OVL+23B9']['completeness'],dict(bounds='stable',control_flow='complete',contract='complete'))
  for r in rs:self.assertEqual(r['ret']['after']['flags'],cmp(r['entry']['before']['e'],r['entry']['before']['c']))
 def test_distinct_flags_and_returns(self):
  for a in self.analyses:
   for r in a['cases']['PLI1.OVL+4F54']:
    self.assertEqual(r['output']['a'],1);self.assertTrue(r['output']['flags']['zero']);self.assertEqual(r['law']['final_child_A'],15)
   for r in a['cases']['PLI1.OVL+4F2A']:self.assertEqual(r['output']['a'],0)
 def test_raw_arms_remain_raw(self):
  im=next(i for i in load(ROOT/'research/annotated-assembly/manifest.json')['images']if i['name']=='PLI1.OVL');st={n:s['status']for s in im['sections']for n in range(s['start_offset'],s['end_offset'])}
  for a,b in [(0x4f6e,0x4f71),(0x4cdd,0x4ce0),(0x4cce,0x4cd4),(0x4ced,0x4cf3),(0x65a1,0x65a7),(0x65ae,0x65c5),(0x3314,0x3317),(0x270d,0x2710)]:self.assertTrue(all(st[n]=='RAW'for n in range(a,b)))
 def test_packet_values_restore_return_and_stack(self):
  p=build_packet(self.rows,self.reference);by={(s,r['call']['step_index']):r for s,g in self.rows.items()for rs in g.values()for r in rs}
  for c in p['cases']:
   r=by[p['sources'][c[0]],c[2]];base=p['routes'][c[4]]['base_abi'][1][:]
   for i,v in c[7]:base[i]=v
   self.assertEqual(base[:9],[r['ret']['after'][q]for q in ['a','b','c','d','e','h','l','sp','pc']]);sv=p['stack_patterns'][c[5]]['base_values'][:]
   for i,v in c[9]:sv[i]=v
   self.assertEqual(sv,[q['value']for q in stack(r)]);self.assertEqual(c[11],chronology(r)['stack_writes_sha256'])
 def test_two_acquisition_groups_preserve_independent_channels(self):
  for a in self.analyses:
   for r in a['cases']['PLI1.OVL+31FB']:
    q=r['law'];self.assertEqual(q['second_position'],(q['balance_stop']-1)&255);self.assertEqual(len(q['children']),9)
  self.assertEqual(self.catalog['PLI1.OVL+31FB']['completeness'],dict(bounds='stable',control_flow='complete',contract='complete'))
 def test_extra_zero_after_neighbor_read_and_maximum(self):
  for a in self.analyses:
   for r in a['cases']['PLI1.OVL+329F']:self.assertEqual(r['output']['a'],max(r['law']['C'],r['law']['E']))
  self.assertEqual(self.catalog['PLI1.OVL+329F']['completeness']['contract'],'complete')
  for g in self.rows.values():
   for r in g['PLI1.OVL+2705']:self.assertNotEqual(validate(r)['selector'],0x16)
 def test_code_image_call_and_stack_corruption_rejected(self):
  rows=copy.deepcopy(self.rows['FIZZBUZ']);rows['PLI1.OVL+4F54'][0]['own_witnesses'][0]['bytes']='00'
  with self.assertRaises(ValueError):analyze('FIZZBUZ',CAPTURES['FIZZBUZ'],IMAGES,rows)
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+500F'][0]);one(r['own_witnesses'],0x5010)['writes'][0]['new_value']^=1
  with self.assertRaises(ValueError):stack(r)
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+506E'][0]);one(r['own_witnesses'],0x50af)['reads'][0]['address']-=2
  with self.assertRaises(ValueError):validate(r)
 def test_bad_comparison_fresh_read_and_result_provenance(self):
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+23B9'][0]);one(r['own_witnesses'],0x23bf)['reads'][0]['address']=0xa650
  with self.assertRaises(ValueError):validate(r)
  for off,change in [(0x507f,lambda w:w['writes'][0].__setitem__('address',0)),(0x5706,lambda w:w['reads'][0].__setitem__('value',0)),(0x56ea,lambda w:w['after']['flags'].__setitem__('carry',True))]:
   r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+506E'][0]);change(one(r['own_witnesses'],off))
   with self.assertRaises(ValueError):validate(r)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images.resolve();unittest.main(argv=[sys.argv[0],*rest])
