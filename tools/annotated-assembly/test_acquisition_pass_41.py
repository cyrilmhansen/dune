"""Required resident acquisition, descriptor carry provenance and parent compatibility."""
import argparse,copy,subprocess,unittest
from collections import Counter
from check_acquisition_pass_41 import *
class PassFortyOneTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.rows={s:gather_selected(c,BOUNDS,include_nested_returns=True,software_callees=SOFTWARE)for s,c in CAPTURES.items()};cls.a=analyze(cls.rows,IMAGES);cls.cat={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
 def required(self):return [q for g in self.a.values()for q in g['PLI1.OVL+784E']if'resident'in q['law']]
 def test_every_corrected_duplicate_window_retained(self):
  self.assertEqual(projection(self.rows,self.a),load(REPORT/'route-distribution.json'));self.assertEqual([len(g['PLI1.OVL+784E'])for g in self.rows.values()],[19,86,37]);self.assertEqual([len(g['PLI.COM+1376'])for g in self.rows.values()],[38,172,74]);self.assertEqual(sum(len(rs)for g in self.a.values()for rs in g.values()),1212)
 def test_compact_packet_regenerates_exactly(self):
  self.assertEqual(build_packet(self.rows,self.a,self.cat),load(REPORT/'work-packet.json'));self.assertLessEqual((REPORT/'work-packet.json').stat().st_size,32768)
 def test_full_proof_hash_is_rederivable(self):
  b=encode_full_proof(self.rows,self.a);e=load(REPORT/'efficiency.json');self.assertEqual(len(b),e['full_rederivable_evidence_bytes']);self.assertEqual(hashlib.sha256(b).hexdigest(),e['full_rederivable_evidence_sha256'])
 def test_parent_compatibility_independent_ancestry(self):
  actual=parent_compatibility(self.rows);self.assertEqual(actual,load(REPORT/'parent-compatibility.json')['cases']);self.assertEqual(Counter(q['parent']for q in actual),{'PLI1.OVL+5E98':10,'PLI1.OVL+5929':13})
 def test_required_routes_and_no_refill(self):
  qs=self.required();self.assertEqual(len(qs),23);self.assertEqual(Counter(q['law']['resident']['selector']for q in qs),{1:4,10:19})
  for q in qs:
   law=q['law']['resident'];self.assertEqual(law['width'],len(law['prefix']));self.assertEqual(law['accumulator'],sum(law['prefix'])&15);self.assertTrue(all(z['index']<z['count']for z in law['reads']))
 def test_required_return_flags_independently_derived(self):
  for source,g in self.a.items():
   by={r['call']['step_index']:r for r in self.rows[source]['PLI.COM+1376']};roots={r['call']['step_index']:r for r in self.rows[source]['PLI1.OVL+784E']}
   for q in g['PLI1.OVL+784E']:
    if 'resident'not in q['law']:continue
    r=by[children_any(roots[q['call_step']])[0]['call_step']];selector=q['law']['resident']['selector'];expected=cmp(10,5)if selector==10 else dict(sign=False,zero=True,auxiliary_carry=False,parity=True,carry=False);self.assertEqual(r['ret']['after']['flags'],expected)
 def test_all_descriptor_paths_and_exhaustion_publication_distinction(self):
  self.assertEqual(Counter(q['law']['route']for g in self.a.values()for q in g['PLI1.OVL+784E']),dict(descriptor_match=47,descriptor_exhausted=20,literal_first_byte=60,passthrough=15))
  for g in self.a.values():
   for q in g['PLI1.OVL+784E']:
    if q['law']['route']=='descriptor_exhausted':self.assertEqual(q['output']['a'],0);self.assertEqual(pair(q['output'],'h','l'),0x20c3)
 def test_ADI_carry_producer_not_SUI_carry(self):
  for g in self.rows.values():
   for r in g['PLI1.OVL+784E']:
    ws=r['own_witnesses'];s=val(one(ws,0x7851),0x20c3)
    for off,k in [(0x78a8,10),(0x78b1,1)]:self.assertEqual(one(ws,off)['after']['flags']['carry'],s!=k)
 def test_new_leaf_complete_no_invented_residue(self):
  self.assertEqual([len(g['PLI.COM+1616'])for g in self.rows.values()],[0,20,4]);self.assertEqual(self.cat['PLI.COM+1616']['completeness'],dict(bounds='stable',control_flow='complete',contract='complete'))
  for g in self.a.values():
   for q in g['PLI.COM+1616']:
    self.assertEqual({z['writer']for z in q['stack']},{'PLI.COM+161E'});self.assertEqual([z['value']for z in q['stack']],[0x21,0x17]);self.assertEqual(q['law']['result'],0)
 def test_reused_append_law_all_natural_cases(self):
  self.assertEqual([len(g['PLI.COM+1627'])for g in self.rows.values()],[128,402,232]);self.assertEqual(sum(len(g['PLI.COM+1627'])for g in self.rows.values()),762)
 def test_existing_scopes_remain_partial_and_RAW(self):
  for k in ['PLI1.OVL+784E','PLI.COM+1376']:
   self.assertEqual(self.cat[k]['completeness'],dict(bounds='provisional',control_flow='partial',contract='partial'))
  image=next(i for i in load(ROOT/'research/annotated-assembly/manifest.json')['images']if i['name']=='PLI.COM');status=lambda o:next(s['status']for s in image['sections']if s['start_offset']<=o<s['end_offset']);self.assertEqual(status(0x160a),'RAW')
 def test_only_documented_catalog_entries_changed(self):
  before=load(REPORT/'before.json');after=load(REPORT/'after.json');base={p['id']:p for p in json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json'],text=True))['procedures']};self.assertEqual({k:base.get(k)for k in before},before);self.assertTrue(all(self.cat[k]==p for k,p in base.items()if k not in after));self.assertEqual({k:self.cat[k]for k in after},after)
 def test_modified_carry_or_return_flag_falsifies_law(self):
  for kind in ['carry','return']:
   r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+784E'][0])
   if kind=='carry':one(r['own_witnesses'],0x78a8)['after']['flags']['carry']^=True
   else:r['ret']['after']['flags']['zero']^=True
   with self.assertRaises(ValueError):validate_784e(r)
 def test_changed_append_write_or_scratch_neighbor_rejected(self):
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI.COM+1627'][0]);one(r['own_witnesses'],0x163c)['writes'][0]['new_value']^=1
  with self.assertRaises(ValueError):mask_result(r)
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI.COM+1616'][0]);one(r['own_witnesses'],0x161a)['reads'][1]['address']^=1
  with self.assertRaises(ValueError):mask_result(r)
 def test_wrong_historical_encoding_rejected(self):
  rs={s:{k:[]for k in BOUNDS}for s in self.rows};r=copy.deepcopy(self.rows['FIZZBUZ']['PLI.COM+1616'][0]);r['own_witnesses'][0]['bytes']='00';rs['FIZZBUZ']['PLI.COM+1616']=[r]
  with self.assertRaises(ValueError):analyze(rs,IMAGES)
 def test_next_required_blocker_is46A7(self):
  b=load(REPORT/'boundary-assessment.json');self.assertTrue(b['procedure_784E_required_scopes_reproducible']);self.assertEqual(b['procedure_5929_remaining_required_blockers'],['PLI1.OVL+46A7']);self.assertEqual(load(REPORT/'candidate-falsification.json')['oracle_queries'],0)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);args,rest=p.parse_known_args();IMAGES=args.images;unittest.main(argv=[__file__]+rest)
