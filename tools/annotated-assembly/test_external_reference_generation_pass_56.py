#!/usr/bin/env python3
"""Natural full-state preparation and parent proofs; independent ABI/economics."""
import argparse,json,unittest
from pathlib import Path
from run_external_reference_generation_pass_56 import prove,OUT,REPORT
class ReferenceGeneration(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  prove(IMAGES)
  cls.rows=json.loads((OUT/'proof/natural-cases.json').read_text())['sources'];cls.post=json.loads((OUT/'proof/cumulative-hybrid-summary.json').read_text())['sources']
 def test_logical_parent_and_outer_topology(self):
  self.assertEqual([[len(e['members'])for e in r['entries'][:2]]for r in self.rows],[[7,7],[25,25],[7,7]])
  top=json.loads((REPORT/'topology-summary.json').read_text())
  for g in top.values():self.assertEqual(g['logical8225'],g['logical8248']);self.assertEqual(g['independent8225'],0)
  self.assertEqual([g['outer']for g in top.values()],[7,25,7])
 def test_preparation_cross_cases(self):
  self.assertEqual([[len(e['members'])for e in r['entries'][2:5]]for r in self.rows],[[9,8,12],[40,38,51],[8,10,12]])
  for r in self.rows:
   for e in r['entries'][2:4]:
    for c in e['members']:
     q=c['output'];p=c['input'];self.assertEqual(q['a'],0)
     self.assertEqual({k:q[k]for k in ['b','c','d','e','h','l']},{k:p[k]for k in ['b','c','d','e','h','l']})
     self.assertEqual(q['flags'],dict(sign=False,zero=True,auxiliary_carry=True,parity=True,carry=False));self.assertFalse(any(w[4]=='logical'for w in c['journal']))
 def test_indexed_reset_destinations_and_flags(self):
  for r in self.rows:
   for c in r['entries'][4]['members']:
    q=c['output'];writes=[w for w in c['journal']if w[4]=='logical']
    if writes:
     self.assertEqual([(w[0],w[1])for w in writes if w[2]==0x95f4],[(0xadab+i,0)for i in range(8)])
     self.assertEqual([w[1]for w in writes if w[2]==0x95f9],list(range(1,9)))
     self.assertEqual(q['a'],7);self.assertTrue(q['flags']['carry']);self.assertEqual(q['b']*256+q['c'],0xadab);self.assertEqual(q['h']*256+q['l'],0xadc4)
    else:self.assertFalse(q['flags']['carry']);self.assertEqual({k:q['flags'][k]for k in ['sign','zero','auxiliary_carry','parity']},{k:c['input']['flags'][k]for k in ['sign','zero','auxiliary_carry','parity']})
 def test_tag_pointer_save_order_and_fresh_child_arguments(self):
  for r in self.rows:
   for c in r['entries'][1]['members']:
    p=c['input'];q=c['journal'];self.assertEqual([(w[0],w[1])for w in q if w[2]in[0xa428,0xa42a,0xa42c]],[(0xae63,p['d']),(0xae62,p['e']),(0xae61,p['c'])])
    self.assertEqual([w[1]for w in q if w[2]in[0x9770,0x9772]],[9,p['c']])
    self.assertEqual([(w[0],w[1])for w in q if w[2]in[0x9904,0x9906]],[(0xadeb,p['d']),(0xadea,p['e'])])
   for c in r['entries'][0]['members']:
    p=c['input'];q=c['journal'];self.assertEqual([(w[0],w[1])for w in q if w[2]in[0xa44b,0xa44d]],[(0xae65,p['b']),(0xae64,p['c'])]);self.assertEqual([w[1]for w in q if w[2]==0xa42c],[0xc4])
 def test_stack_derived_without_private_frame(self):
  for r in self.rows:
   for e in r['entries']:
    for c in e['members']:
     S=c['input']['sp'];self.assertEqual(c['output']['sp'],S+2);self.assertFalse(any(w[0]in[S,S+1]for w in c['journal']))
     if e['offset']==0x8225:self.assertEqual(c['output']['pc'],0xa457)
 def test_components(self):
  q=json.loads((OUT/'proof/component-shadows.json').read_text());self.assertTrue(q['all_passed']);self.assertEqual([g['serializer_shadows']for g in q['sources']],[98,350,98]);self.assertEqual([g['bit_writer_shadows']for g in q['sources']],[721,2575,721])
 def test_hierarchy_and_actual_counters(self):
  top=json.loads((REPORT/'topology-summary.json').read_text());self.assertEqual([p['pre_guest_instructions']for p in self.post],[301190,574055,347549]);self.assertEqual([sum(p['pre_transition_vector'])for p in self.post],[107,294,96]);self.assertEqual([p['result']['host_transitions']for p in self.post],[100,269,89])
  for g,p in zip(top.values(),self.post):
   self.assertEqual(g['absorbed_native'],{'PLI2.OVL+756D':g['outer'],'PLI2.OVL+7701':g['outer']});self.assertEqual(p['result']['host_transitions']-sum(p['pre_transition_vector']),g['net_host_delta']);self.assertEqual(p['guest_instructions_removed'],p['pre_guest_instructions']-p['result']['actual_guest_instructions']);self.assertGreater(p['guest_instructions_removed'],0)
   for k in ['PLI2.OVL+7701','PLI2.OVL+8225','PLI2.OVL+8248']:self.assertEqual(g['remaining_generation'][k]['calls'],0)
  self.assertEqual([g['serializer_remaining']for g in top.values()],[36,36,43])
 def test_all_hybrid_channels_and_goldens(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for name in ['8225-only-hybrid-summary.json','single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   rows=[r['result']for r in json.loads((OUT/'proof'/name).read_text())['sources']];self.assertEqual([r['REL_sha256']for r in rows],hashes);self.assertTrue(all(r['PASS1']and r['PASS2']and r['END_COMPILATION']and r['termination']=='warm_boot'for r in rows))
 def test_scoped_catalog_and_historical_totals(self):
  cat={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
  for key in ['PLI2.OVL+8225','PLI2.OVL+8248']:
   p=cat[key];self.assertEqual(p['observed_paths']['invocations_by_run']['FACTOR'],11);self.assertEqual(p['observed_paths']['invocations_by_run']['OPTIMIST'],46);self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'))
  self.assertEqual(cat['PLI2.OVL+73D0']['completeness'],dict(bounds='stable',control_flow='complete',contract='complete'))
  for key in ['PLI2.OVL+79E2','PLI2.OVL+7A17']:self.assertEqual(cat[key]['observed_paths']['represented_bytes'],9);self.assertEqual(cat[key]['completeness']['contract'],'partial')
  f=json.loads((REPORT/'fidelity.json').read_text());self.assertEqual(f['promotions'],dict(RAW=64,STRUCTURED=51));self.assertLess((REPORT/'implementation-packet.json').stat().st_size,32768)
 def test_canonical_child_checkpoints_and_factor(self):
  s=json.loads((REPORT/'shadow-summary.json').read_text());self.assertEqual([e['cases']for e in s['FACTOR']['entries']],[11]*7)
  for q in json.loads((REPORT/'dependency-summary.json').read_text()).values():self.assertFalse(q['preparation_mutates_saved_carriers'])
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
