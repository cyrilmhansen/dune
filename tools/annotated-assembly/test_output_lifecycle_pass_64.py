#!/usr/bin/env python3
"""Pass64 exact instruction, provenance, component and hybrid regressions."""
import argparse,json,unittest
from pathlib import Path
from run_output_lifecycle_pass_64 import prove,OUT,REPORT,RESIDENT,BASE
from check_selector02_pass_40 import children_any

def load(p):return json.loads(Path(p).read_text())
def own(r):return{w['origin']['offset']:w for w in r['own_witnesses']}
def writes(w):return[(q['address'],q['new_value'])for q in w['writes']]
class OutputLifecycle(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  prove(IMAGES);cls.rows=load(OUT/'rows.json');cls.nat=load(OUT/'proof/natural-cases.json')['sources']
 def parents(self):return[r for g in self.rows.values()for r in g['PLI2.OVL+82DD']]
 def test_natural_entry_bounds_and_returns(self):
  self.assertEqual([len(g['PLI2.OVL+82DD'])for g in self.rows.values()],[1,1,1])
  for r in self.parents():
   self.assertEqual(r['call']['origin']['offset'],0x046e);self.assertEqual(r['ret']['origin']['offset'],0x833f);self.assertEqual(r['ret']['after']['sp'],r['entry']['before']['sp']+2)
 def test_header_width_rotation_bit_order(self):
  for r in self.parents():
   w=own(r)
   for site,value,bits in[(0x82e1,0x9a,[1,0,0,1,1,0,1]),(0x82f0,0x9c,[1,0,0,1,1,1,0])]:
    self.assertEqual((w[site]['before']['c'],w[site]['before']['e']),(value,7))
    q=r['nested_returns'][str(w[site]['step_index'])];rot=[v['new_value']for x in q['memory_witnesses']for v in x['writes']if v['address']==0x20b7][1:];self.assertEqual([v&1 for v in rot],bits)
 def test_gate_old_bit0_and_natural_tag40(self):
  for r in self.parents():
   w=own(r);gate=w[0x82f3]['reads'][0]['value'];self.assertEqual(gate&1,1);self.assertEqual(w[0x82f6]['after']['flags']['carry'],bool(gate&1));self.assertFalse(w[0x82f7]['control']['taken']);self.assertEqual((w[0x82fd]['before']['b'],w[0x82fd]['before']['c']),(0,0));self.assertNotIn(0x8306,w)
 def test_exact_direct_chronology(self):
  expected=['PLI.COM+119E','PLI.COM+11E5','PLI.COM+119E','PLI.COM+11E5','PLI.COM+124B','PLI.COM+05FF','PLI.COM+0466','PLI.COM+05FF','PLI.COM+0466','PLI.COM+05FF','PLI.COM+0466']
  for r in self.parents():self.assertEqual([c['target']for c in children_any({**r,'nested_returns':{int(k):v for k,v in r['nested_returns'].items()}})],expected)
 def test_pointer_publication_and_payload_freshness(self):
  for r in self.parents():
   w=own(r);rs=w[0x8320]['reads'];self.assertEqual([q['address']for q in rs],[0xaca3,0xaca4]);p=rs[0]['value']+(rs[1]['value']<<8)
   self.assertEqual(writes(w[0x8323]),[(0xac9f,rs[0]['value']),(0xaca0,rs[1]['value'])]);self.assertEqual([q['address']for q in w[0x8326]['reads']],[0xac9f,0xaca0]);self.assertEqual([q['address']for site in[0x832b,0x832d]for q in w[site]['reads']],[p+2,p+3]);self.assertEqual((w[0x832e]['before']['c'],w[0x832e]['before']['b']),(w[0x832b]['reads'][0]['value'],w[0x832d]['reads'][0]['value']))
 def test_distinct_three_word_sources_and_literal_strings(self):
  for r in self.parents():
   w=own(r);self.assertEqual([q['address']for q in w[0x8312]['reads']],[0x1c2c,0x1c2d]);self.assertEqual([q['address']for q in w[0x8337]['reads']],[0x1c2e,0x1c2f])
   self.assertEqual([w[site]['before']['b']*256+w[site]['before']['c']for site in[0x830f,0x831d,0x8334]],[0x94eb,0x94fa,0x9507])
 def test_alignment_not_file_close(self):
  for source,g in self.rows.items():
   r=g['PLI.COM+124B'][0];w=own(r);self.assertNotIn(0x064c,[(q.get('target_origin')or{}).get('offset')for q in r['own_witnesses']]);self.assertEqual((w[0x126e]['before']['c'],w[0x126e]['before']['e']),(0x9e,7))
   calls=[x['origin']['offset']for x in r['own_witnesses']if x['control']['kind']=='call'];self.assertTrue(all(x==0x1264 for x in calls[:-1]));self.assertEqual(calls[-1],0x126e)
 def test_all_resident_components_independent(self):
  for s in self.nat:
   by={q['offset']:q['members']for q in s['entries']};self.assertEqual(len(by[0x82dd]),1)
   for off,n in[(0x124b,1),(0x05ff,3),(0x0466,3),(0x05f8,3),(0x03e9,3),(0x03f4,3),(0x0390,56),(0x0380,56),(0x044b,6),(0x0421,12)]:self.assertEqual(len(by[off]),n)
 def test_all_register_flags_RAM_write_stack_service_shadows(self):
  for s in self.nat:
   r=s['entries'][0]['members'][0];sp=r['input']['sp'];last={q[0]:q for q in r['journal']};self.assertNotIn(sp,last);self.assertNotIn(sp+1,last);self.assertEqual((last[sp-1][2],last[sp-2][2]),(0xa53c,0xa53c));self.assertEqual([q['function']for q in r['service_details']],[11]+[2]*20+[11]+[2]*18+[11]+[2]*18)
 def test_synthetic_original_CPU_branch_pointer_words_string_and_boundary(self):
  cs=[q for q in load(OUT/'proof/synthetic-checkpoints.json')['cases']if q['route'].startswith('82DD_')];self.assertEqual(len(cs),42);self.assertEqual(len({q['route']for q in cs}),14);self.assertTrue(all(q['all_passed']for q in cs))
  for q in cs:self.assertIn(0xa53f,[w['pc']for w in q['checkpoints']])
 def test_factor_optimist_natural_cross_evidence(self):
  for source in['FACTOR','OPTIMIST']:
   rows=load(OUT/(source+'-natural-cases.json'))['sources'];self.assertEqual(rows[0]['source'],source);self.assertEqual(len(rows[0]['entries'][0]['members']),1)
 def test_standalone_cumulative_goldens_and_actual_savings(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for name in['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   rows=load(OUT/'proof'/name)['sources'];self.assertEqual([q['result']['REL_sha256']for q in rows],hashes);self.assertTrue(all(q['result']['termination']=='warm_boot'for q in rows))
  rows=load(OUT/'proof/cumulative-hybrid-summary.json')['sources'];self.assertEqual([q['pre_guest_instructions']for q in rows],[299516,566481,345997]);self.assertTrue(all(q['guest_instructions_removed']>4000 for q in rows));self.assertEqual([q['result']['host_transitions']for q in rows],[101,257,92])
 def test_catalog_status_and_coverage_preservation(self):
  from historical_catalog_epoch import _checkpoint
  cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};p=cat['PLI2.OVL+82DD'];self.assertEqual((p['start_offset'],p['end_offset']),(0x82dd,0x8340));self.assertEqual(p['observed_paths']['represented_bytes'],99);self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'))
  for k,v in _checkpoint(BASE).items():
   for source,n in v['observed_paths']['invocations_by_run'].items():self.assertGreaterEqual(cat[k]['observed_paths']['invocations_by_run'].get(source,0),n)
  self.assertLess((REPORT/'implementation-packet.json').stat().st_size,28672)
 def test_historical_full_selection_preserves_epoch_and_new_categories(self):
  import run_host_compiler_regressions as runner
  cmds=runner.commands(str(IMAGES),OUT);policy=load('research/host-compiler/validation-policy.json');_,selected,_=runner.select_categories(cmds,policy,'historical-full')
  old=load('research/host-compiler/pass-62/validation.json');names={q['category']for q in old['categories']}if isinstance(old['categories'],list)and isinstance(old['categories'][0],dict)else set(old['categories'])
  self.assertLessEqual(names,set(selected));self.assertTrue({'validation-runner-tests','pass63','pass64'}<=set(selected));self.assertGreaterEqual(len(selected),95)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=[__file__]+rest)
