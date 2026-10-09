#!/usr/bin/env python3
"""Independent natural full-state proofs plus trim/byte/record equations."""
import argparse,json,unittest
from pathlib import Path
from run_pli2_pointer_generation_pass_55 import prove,OUT,REPORT
class PointerGeneration(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  prove(IMAGES)
  cls.rows=json.loads((OUT/'natural-cases.json').read_text())['sources']
  cls.post=json.loads((OUT/'cumulative-hybrid-summary.json').read_text())['sources']
 def test_corrected_topology(self):
  self.assertEqual([len(r['entries'][0]['members'])for r in self.rows],[7,25,7])
  for r in self.rows:
   self.assertTrue(all(c['caller']=='PLI2.OVL+8244'for c in r['entries'][0]['members']))
  top=json.loads((REPORT/'topology-summary.json').read_text())
  self.assertEqual([r['external']for r in top.values()],[7,25,7])
  self.assertTrue(all(r['nested']==0 for r in top.values()))
 def test_pointer_save_and_length_publications(self):
  for r in self.rows:
   for c in r['entries'][0]['members']:
    q=c['journal'];entry=c['input']
    self.assertEqual([(w[0],w[1])for w in q if w[2]in[0x9904,0x9906]],[(0xadeb,entry['b']),(0xadea,entry['c'])])
    self.assertEqual([w[1]for w in q if w[2]in[0x9921,0x994d,0x994e]],[4,5,6])
    self.assertEqual([w[1]for w in q if w[2]==0x99ba],[1,2,3,4,5])
    self.assertFalse(any(w[2]==0x9946 for w in q))
 def test_serializer_arguments_and_child_order(self):
  for r in self.rows:
   for c in r['entries'][0]['members']:
    q=c['journal'];self.assertEqual([w[1]for w in q if w[2]==0x12a1],[8,8,7,2,8,8,3,8,8,8,8,8,8])
    values=[w[1]for w in q if w[2]==0x12a3]
    self.assertEqual(values[:4],[0,0,0x8c,0x40]);self.assertEqual(values[6:8],[0xc0,0x3f])
    self.assertEqual(values[8:],[w[1]for w in q if w[2]==0x999c])
    self.assertEqual(len([w for w in q if w[2]==0x9740]),4)
 def test_stack_and_final_flags(self):
  for r in self.rows:
   for c in r['entries'][0]['members']:
    entry=c['input'];q=c['output'];S=entry['sp'];self.assertEqual(q['sp'],S+2)
    self.assertEqual(q['pc'],0xa447);self.assertEqual(q['h']*256+q['l'],0xadec)
    self.assertTrue(q['flags']['carry']);self.assertFalse(any(w[0]in[S,S+1]for w in c['journal']))
    self.assertEqual([(w[0],w[2])for w in c['journal']if w[2]==0x9933],[(S-1,0x9933),(S-2,0x9933)])
 def test_component_proofs(self):
  q=json.loads((OUT/'component-shadows.json').read_text())
  self.assertTrue(q['all_passed']);self.assertEqual([r['serializer_shadows']for r in q['sources']],[91,325,91]);self.assertEqual([r['bit_writer_shadows']for r in q['sources']],[658,2350,658])
 def test_hierarchy_and_remaining_serializers(self):
  top=json.loads((REPORT/'topology-summary.json').read_text())
  self.assertEqual([g['serializer_remaining']for g in top.values()],[36,36,43]);self.assertEqual([g['serializer_absorbed']for g in top.values()],[56,200,56])
  for g,r in zip(top.values(),self.post):
   self.assertEqual(r['family_roots'],g['external']);self.assertEqual(r['result']['host_transitions']-sum(r['pre_transition_vector']),g['net_new_transitions'])
   self.assertEqual(g['absorbed_native'],{'PLI2.OVL+75F1':g['external'],'PLI.COM+11E5':g['external']})
   self.assertFalse(any(c in g['remaining_callers']for c in ['PLI2.OVL+7711','PLI2.OVL+775A','PLI2.OVL+777D','PLI2.OVL+77A2']))
 def test_actual_whole_run_baseline_and_goldens(self):
  self.assertEqual([r['pre_guest_instructions']for r in self.post],[320378,642630,366662])
  self.assertEqual([sum(r['pre_transition_vector'])for r in self.post],[114,319,103]);self.assertEqual([r['result']['host_transitions']for r in self.post],[107,294,96])
  for r in self.post:self.assertEqual(r['guest_instructions_removed'],r['pre_guest_instructions']-r['result']['actual_guest_instructions']);self.assertGreater(r['guest_instructions_removed'],0)
  golden=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   q=[r['result']for r in json.loads((OUT/name).read_text())['sources']];self.assertEqual([r['REL_sha256']for r in q],golden)
   self.assertTrue(all(r['PASS1']and r['PASS2']and r['END_COMPILATION']and r['termination']=='warm_boot'for r in q))
 def test_contract_scoping_static_vs_observed(self):
  cat=json.loads(Path('research/annotated-assembly/procedures.json').read_text())
  p=next(p for p in cat['procedures']if p['id']=='PLI2.OVL+7701');self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='partial',contract='partial'));self.assertEqual(p['observed_paths']['represented_bytes'],169)
  self.assertEqual(p['observed_paths']['invocations_by_run']['FACTOR'],11);self.assertEqual(p['observed_paths']['invocations_by_run']['OPTIMIST'],46)
  ev=json.loads(Path('research/annotated-assembly/evidence.json').read_text());seed=next(s for s in ev['seeds']if s['id']==p['id'])
  for o in [0x7743,0x7746,0x7747]:
   w=next(w for w in seed['instructions']if w['offset']==o);self.assertEqual(w['runs'],[]);self.assertEqual(w['evidence_class'],'DEDUCED STATIC UNOBSERVED')
  self.assertFalse(any(w['offset']in range(a,b)for a,b in [(0x7764,0x776f),(0x7776,0x7779),(0x77b0,0x77b7)]for w in seed['instructions']))
  self.assertLess((REPORT/'implementation-packet.json').stat().st_size,28672)
 def test_cross_corpus_and_loop_provenance(self):
  s=json.loads((REPORT/'shadow-summary.json').read_text())['cross_corpus'];self.assertEqual(s['natural_calls'],11);self.assertTrue(s['all_full_states_matched']);self.assertEqual(s['trim_counts'],{'0':11});self.assertEqual(s['loop_counts'],{'5':11})
  for s in json.loads((REPORT/'loop-summary.json').read_text()).values():self.assertTrue(s['local_chronology_matches']);self.assertEqual(s['trim_counts'],{'0':s['cases']});self.assertEqual(s['loop_counts'],{'5':s['cases']})
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
