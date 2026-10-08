#!/usr/bin/env python3
"""Fresh bounded component, full parent and hierarchy differential proofs."""
import argparse,json,unittest
from pathlib import Path
from run_initialization_parent_pass_49 import prove
REPORT=Path('research/host-compiler/pass-49')
class InitializationParent(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.proof=prove(IMAGES,persist=True)
  cls.packet=json.loads((REPORT/'implementation-packet.json').read_text())
  cls.roots=json.loads((cls.proof/'natural-cases.json').read_text())['sources']
  cls.post=json.loads((cls.proof/'cumulative-hybrid-summary.json').read_text())['sources']
 def test_root_topology_and_scope(self):
  self.assertEqual(self.packet['selected_root'],'PLI1.OVL+0C1B')
  self.assertIn('A5D9',self.packet['selection'])
  for source in ['MINIMAL','FIZZBUZ','PICTURE']:
   cases=self.packet['cases'][source]['PLI1.OVL+0C1B'];self.assertEqual(len(cases),1);self.assertEqual(cases[0]['caller'],'PLI1.OVL+0CD7')
  self.assertEqual([len(r['members'])for r in self.roots],[1,1,1])
 def test_all_natural_component_shadows(self):
  rows=json.loads((self.proof/'components.json').read_text())['sources'];counts={}
  for r in rows:
   self.assertEqual(r['field80_boundary_matched'],0);self.assertEqual(len(r['cases']),r['field15_matched']);counts[r['operation']]=counts.get(r['operation'],0)+r['field15_matched']
  self.assertEqual(counts,{'47F7':2,'3563':1,'47E2':6,'4890':15,'4802':6,'013D':6,'01C6':3,'0B84':3})
 def test_four_byte_context_frame_and_restore_order(self):
  for r in self.roots:
   c=r['members'][0];F=c['input']['sp']-4;js=c['journal'];q=c['input'];old=c['output']['h']*256+c['output']['l']
   self.assertIn([F,q['c'],0x2e1c,0,'compatibility'],js);self.assertIn([F+1,q['b'],0x2e1c,0,'compatibility'],js)
   self.assertIn([F+2,old&255,0x2e25,0,'logical'],js);self.assertIn([F+3,old>>8,0x2e27,0,'logical'],js)
   pubs=[w for w in js if w[3]==0 and w[0]in [0xa5b5,0xa5b6]]
   self.assertEqual([(w[0],w[1],w[2])for w in pubs],[(0xa5b5,q['c'],0x2e2f),(0xa5b6,q['b'],0x2e2f),(0xa5b5,old&255,0x2e6f),(0xa5b6,old>>8,0x2e6f)])
   self.assertEqual(c['output']['sp'],c['input']['sp']+2);self.assertEqual(c['output']['pc'],0x2eda)
 def test_exact_direct_child_order(self):
  wanted=[0x2e32,0x2e35,0x2e38,0x2e42,0x2e47,0x2e55,0x2e61,0x2e64]
  for r in self.roots:
   js=r['members'][0]['journal'];calls=[]
   for i,w in enumerate(js[:-1]):
    if w[3]==1 and w[4]=='compatibility'and w[2]in wanted and js[i+1][2]==w[2]and w[0]==js[i+1][0]+1:calls.append(w[2])
   # CALL writes occur before incrementing depth, unlike child-body writes.
   if not calls:
    calls=[w[2]for i,w in enumerate(js[:-1])if w[3]==0 and w[4]=='compatibility'and w[2]in wanted and js[i+1][2]==w[2]and w[0]==js[i+1][0]+1]
   self.assertEqual(calls,wanted)
 def test_full_state_and_internal_frame(self):
  for r in self.roots:
   c=r['members'][0];self.assertTrue(c['post_memory_sha256']);self.assertEqual(c['result']['route'],'context_cursor_initialization')
   js=c['journal'];self.assertTrue(any(w[2]==0x2c38 for w in js));self.assertTrue(any(w[2]==0x2e61 and w[1]==0x64 for w in js))
 def test_actual_cumulative_leverage(self):
  self.assertEqual([r['pre_guest_instructions']for r in self.post],[397763,853468,444405])
  self.assertEqual([sum(r['pre_transition_vector'])for r in self.post],[85,108,69])
  self.assertEqual([r['result']['actual_guest_instructions']for r in self.post],[391255,849221,439060])
  self.assertEqual([sum(r['transition_vector'])for r in self.post],[80,103,64])
  self.assertEqual([r['guest_instructions_removed']for r in self.post],[6508,4247,5345])
 def test_exact_root_hierarchy(self):
  for r in self.post:
   self.assertEqual(r['transition_vector'][:7],[1,0,0,0,0,0,0])
   self.assertEqual(r['pre_transition_vector'][0]-r['transition_vector'][1],1)
   self.assertEqual(r['pre_transition_vector'][6]-r['transition_vector'][7],2)
   self.assertEqual(r['pre_transition_vector'][10]-r['transition_vector'][11],1)
   self.assertEqual(r['pre_transition_vector'][22]-r['transition_vector'][23],2)
 def test_both_hybrid_goldens(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for file in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   rows=[r.get('result',r)for r in json.loads((self.proof/file).read_text())['sources']];self.assertEqual([r['REL_sha256']for r in rows],hashes)
   self.assertTrue(all(r['PASS1']and r['PASS2']and r['END_COMPILATION']and r['termination']=='warm_boot'for r in rows))
 def test_truthful_catalog_completeness(self):
  catalog={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
  for offset in ['0C1B','013D','01C6','0B84','4802','4890','47E2','3563']:
   self.assertEqual(catalog['PLI1.OVL+'+offset]['completeness']['contract'],'partial')
  self.assertEqual(catalog['PLI1.OVL+47F7']['completeness'],dict(bounds='stable',control_flow='complete',contract='complete'))
  self.assertIn('bit40 was clear',catalog['PLI1.OVL+47F7']['contract'])
 def test_packet_and_algorithmic_host(self):
  self.assertLessEqual((REPORT/'implementation-packet.json').stat().st_size,28672)
  host=Path('lib/pli80_host/initialization_parent.ml').read_text()
  for name in ['source_name','entry_step','sha256','Runner.','Cpu8080','invocation']:self.assertNotIn(name,host)
  self.assertIn('let rec grow()',host);self.assertIn('let rec loop()',host)
 def test_fidelity_and_promotions(self):
  f=json.loads((REPORT/'fidelity.json').read_text());self.assertEqual(f['RAW_to_UNDERSTOOD'],184);self.assertEqual(f['oracle_queries'],0)
  for k in ['historical_correction','pragmatic_divergence','fidelity_debt']:self.assertIsNone(f[k])
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
