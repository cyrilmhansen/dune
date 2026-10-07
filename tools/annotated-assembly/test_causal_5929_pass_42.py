"""Natural causal closure, existing constructor scope, source and continuation ancestry."""
import argparse,copy,subprocess,unittest
from collections import Counter
from check_causal_5929_pass_42 import *
class PassFortyTwoTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.rows={s:gather_selected(c,BOUNDS,include_nested_returns=True,software_callees=SOFTWARE)for s,c in CAPTURES.items()};cls.a=analyze(cls.rows,IMAGES);cls.cat={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
 def by(self,source):return {r['call']['step_index']:r for rs in self.rows[source].values()for r in rs}
 def test_all_duplicate_natural_windows_retained(self):
  self.assertEqual(projection(self.rows,self.a),load(REPORT/'route-distribution.json'));self.assertEqual(sum(len(rs)for g in self.a.values()for rs in g.values()),63)
  for key in ['5929','46A7','4651']:self.assertEqual([len(g['PLI1.OVL+'+key])for g in self.rows.values()],[1,11,1])
  self.assertEqual([len(g['PLI1.OVL+4693'])for g in self.rows.values()],[1,8,1]);self.assertEqual([len(g['PLI1.OVL+4468'])for g in self.rows.values()],[2,11,1])
 def test_compact_packet_exact_regeneration(self):
  self.assertEqual(build_packet(self.rows,self.a,self.cat),load(REPORT/'work-packet.json'));self.assertLessEqual((REPORT/'work-packet.json').stat().st_size,32768)
 def test_full_proof_hash_exact_regeneration(self):
  b=encode_full_proof(self.rows,self.a);q=load(REPORT/'efficiency.json');self.assertEqual(hashlib.sha256(b).hexdigest(),q['full_rederivable_evidence_sha256']);self.assertEqual(len(b),q['full_rederivable_evidence_bytes'])
 def test_required_routes_selected_by_current_state(self):
  self.assertEqual(Counter(q['law']['route']for g in self.a.values()for q in g['PLI1.OVL+46A7']),dict(existing_empty_slot=9,existing_nonempty_terminal_link=1,reuse_nonnull=3))
  self.assertEqual(Counter(q['law']['route']for g in self.a.values()for q in g['PLI1.OVL+4651']),dict(null_selected_slot=9,null_after_reference_walk=1,existing_payload_and_tag_match=3))
 def test_C_provenance_and_A_not_later_selector(self):
  for g in self.a.values():
   for q in g['PLI1.OVL+5929']:
    law=q['law'];self.assertEqual(law['input_selector'],law['fresh_selector']);self.assertIn(law['gate_A'],[0,255]);self.assertNotEqual(law['gate_A'],law['fresh_selector']);self.assertEqual(law['input2511'],(law['result239A']+1)&255)
 def test_fresh_pointer_reference_loop_two_outcomes(self):
  outcomes=Counter()
  for g in self.a.values():
   for q in g['PLI1.OVL+4651']:
    for c in q['law']['comparisons']:outcomes[c['returned_bit']]+=1
    self.assertEqual(q['law']['comparisons'][-1]['returned_bit'],0)
  self.assertEqual(outcomes,{0:13,1:1})
 def test_4651_result_tag_not_46A7_nullmask(self):
  self.assertEqual(Counter(q['output']['a']for g in self.a.values()for q in g['PLI1.OVL+4651']),{0:10,2:3});self.assertEqual(Counter(q['output']['a']for g in self.a.values()for q in g['PLI1.OVL+46A7']),{0:10,255:3})
 def test_three_reuse_flags_independent_from_tag_byte(self):
  for g in self.a.values():
   for q in g['PLI1.OVL+46A7']:
    if q['law']['route']=='reuse_nonnull':self.assertEqual(q['output']['flags'],dict(sign=True,zero=False,auxiliary_carry=False,parity=True,carry=True))
 def test_empty_nonempty_constructor_equal_A_different_AC(self):
  for g in self.a.values():
   for q in g['PLI1.OVL+46A7']:
    if q['law']['route']=='reuse_nonnull':continue
    self.assertEqual(q['output']['a'],0);self.assertEqual(q['output']['flags']['auxiliary_carry'],q['law']['route']=='existing_empty_slot');self.assertFalse(q['output']['flags']['carry'])
 def test_required_N2_scope_reused_source_not_continuation(self):
  cases=[q for g in self.a.values()for q in g['PLI1.OVL+4693']];self.assertEqual(len(cases),10)
  for q in cases:
   law=q['law']['constructor'];self.assertEqual(law['source'],0x20c6);self.assertEqual(law['tag'],q['entry']['c']);self.assertEqual(q['output']['sp'],q['entry']['sp']+2)
  for source,g in self.rows.items():
   for r in g['PLI1.OVL+4468']:
    proof=prove(r['software_proof']);self.assertEqual(r['ret']['after']['sp'],r['entry']['before']['sp']+4);self.assertEqual(r['ret']['after']['pc'],r['call']['call_return_address']);self.assertEqual(proof['consumed_caller_bytes'],2)
 def test_derived_stack_preserves_positive_consumed_cells(self):
  for g in self.a.values():
   for q in g['PLI1.OVL+4468']:
    self.assertEqual([z['writer']for z in q['stack']if z['relative_address']in[2,3]],['PLI1.OVL+4474']*2);self.assertTrue(all(z['relative_address']<4 for z in q['stack']))
 def test_exact_Pass41_cross_parent_compatibility(self):
  self.assertEqual(acquisition_compatibility(self.rows),load(REPORT/'acquisition-compatibility.json')['cases']);self.assertEqual(len(acquisition_compatibility(self.rows)),13)
 def test_old_complete_children_and_global_constructor_unchanged(self):
  base={p['id']:p for p in json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json'],text=True))['procedures']};after=load(REPORT/'after.json');epoch=dict(self.cat);extension=ROOT/'research/host-compiler/pass-44/numeric-contract-before.json';epoch.update({'PLI.COM+1376':load(extension)}if extension.exists()else{});self.assertTrue(all(epoch[k]==p for k,p in base.items()if k not in after));self.assertEqual({k:self.cat[k]for k in after},after)
  self.assertEqual(self.cat['PLI1.OVL+46A7']['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'));self.assertEqual(self.cat['PLI1.OVL+4651']['completeness'],dict(bounds='stable',control_flow='partial',contract='partial'))
 def test_unexecuted_local_paths_remain_RAW(self):
  im=next(i for i in load(ROOT/'research/annotated-assembly/manifest.json')['images']if i['name']=='PLI1.OVL');status=lambda o:next(s['status']for s in im['sections']if s['start_offset']<=o<s['end_offset']);self.assertEqual(status(0x4680),'RAW');self.assertTrue(all(status(o)=='RAW'for o in range(0x468c,0x4692)))
 def test_modified_return_flags_rejected(self):
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+46A7'][2]);r['ret']['after']['flags']['carry']^=True
  with self.assertRaises(ValueError):gate(r,self.by('FIZZBUZ'))
 def test_changed_tag_or_child_order_rejected(self):
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+4651'][2]);one(r['own_witnesses'],0x4687)['reads'][0]['value']^=1
  with self.assertRaises(ValueError):selection(r,self.by('FIZZBUZ'))
  r=copy.deepcopy(self.rows['MINIMAL']['PLI1.OVL+4651'][0]);one(r['own_witnesses'],0x4655)['target_origin']['offset']=0x422f
  with self.assertRaises(ValueError):selection(r,self.by('MINIMAL'))
 def test_corrupted_continuation_writer_or_argument_rejected(self):
  r=copy.deepcopy(self.rows['MINIMAL']['PLI1.OVL+4468'][0]);r['software_proof']['relation']['low_byte_writer']['pc']+=1
  with self.assertRaises(ValueError):prove(r['software_proof'])
  r=copy.deepcopy(self.rows['MINIMAL']['PLI1.OVL+4693'][0]);one(r['own_witnesses'],0x469a)['writes'][0]['new_value']^=1
  with self.assertRaises(ValueError):wrapper(r,self.by('MINIMAL'))
 def test_wrong_canonical_bytes_rejected(self):
  g={s:{k:[]for k in BOUNDS}for s in self.rows};r=copy.deepcopy(self.rows['MINIMAL']['PLI1.OVL+46A7'][0]);r['own_witnesses'][0]['bytes']='00';g['MINIMAL']['PLI1.OVL+46A7']=[r]
  with self.assertRaises(ValueError):analyze(g,IMAGES)
 def test_upward_scope_closed_without_global_completion(self):
  b=load(REPORT/'boundary-assessment.json');self.assertTrue(b['procedure_5929_native_ready']);self.assertEqual(b['procedure_6223_Route_B_required_blockers'],[]);self.assertEqual(b['procedure_5E98_required_causal_blockers'],[]);self.assertEqual(b['checkpoint_due'],43);self.assertEqual(load(REPORT/'candidate-falsification.json')['oracle_queries'],0)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);args,rest=p.parse_known_args();IMAGES=args.images;unittest.main(argv=[__file__]+rest)
