#!/usr/bin/env python3
"""Independent fresh frame/root proofs and whole-run hierarchy checks."""
import argparse,json,unittest
from pathlib import Path
from run_acquisition_frame_pass_48 import prove
REPORT=Path('research/host-compiler/pass-48')
class AcquisitionFrame(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.proof=prove(IMAGES)
  cls.packet=json.loads((REPORT/'implementation-packet.json').read_text())
  cls.roots=json.loads((cls.proof/'natural-cases.json').read_text())['sources']
 def test_fresh_logical_and_outer_topology(self):
  for s,n in [('MINIMAL',1),('FIZZBUZ',2),('PICTURE',1)]:
   rs=self.packet['cases'][s]['PLI1.OVL+0A32'];self.assertEqual(len(rs),n)
   self.assertEqual(sum(r['external']for r in rs),1)
   self.assertEqual([r['caller']for r in rs if r['external']],['PLI1.OVL+0C61'])
 def test_root_selection(self):
  self.assertEqual(self.packet['selected_root'],'PLI1.OVL+0A32')
  self.assertIn('A5B5',self.packet['selection']);self.assertIn('A5D9',self.packet['selection'])
 def test_all_logical_and_outer_shadows(self):
  q=json.loads((self.proof/'shadow-summary.json').read_text())['sources']
  self.assertEqual([r['invocations']for r in q],[1,2,1])
  self.assertEqual([len(r['members'])for r in self.roots],[1,1,1])
  for r in self.roots:
   for c in r['members']:
    self.assertEqual(c['output']['sp'],c['input']['sp']+2)
    self.assertTrue(c['post_memory_sha256']);self.assertTrue(c['journal'])
 def test_frame_writers_and_iteration_results(self):
  for r,n in zip(self.roots,[2,3,5]):
   c=r['members'][0];F=c['input']['sp']-8;js=c['journal'];e=c['input']
   self.assertEqual(c['result']['route'],f'frame_iterations_{n}')
   self.assertEqual(sum(w[2]==0x2c3f and w[3]==0 for w in js),n)
   self.assertIn([F,e['c'],0x2c38,0,'compatibility'],js)
   self.assertIn([F+1,e['b'],0x2c38,0,'compatibility'],js)
   self.assertIn([F+2,e['e'],0x2c36,0,'compatibility'],js)
   self.assertIn([F+5,e['l'],0x2c33,0,'compatibility'],js)
   self.assertIn([F+6,e['h'],0x2c33,0,'compatibility'],js)
   self.assertFalse(any(w[0]==F+7 and w[3]==0 for w in js))
 def test_internal_recursive_calls_are_absorbed(self):
  rows=json.loads((self.proof/'cumulative-hybrid-summary.json').read_text())['sources']
  self.assertEqual([r['transition_vector'][0]for r in rows],[1,1,1])
  self.assertEqual([r['transition_vector'][1]for r in rows],[0,0,0])
  for r in self.roots:
   calls=[w for w in r['members'][0]['journal']if w[4]=='compatibility'and w[2]in [0x2cbb,0x2d79]]
   self.assertTrue(calls)
 def test_actual_baseline_and_cumulative_savings(self):
  rows=json.loads((self.proof/'cumulative-hybrid-summary.json').read_text())['sources']
  self.assertEqual([r['pre_guest_instructions']for r in rows],[405284,869593,476266])
  self.assertEqual([sum(r['pre_transition_vector'])for r in rows],[89,119,88])
  for r in rows:self.assertEqual(r['guest_instructions_removed'],r['pre_guest_instructions']-r['result']['actual_guest_instructions'])
 def test_both_hybrid_goldens(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for file in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   rows=json.loads((self.proof/file).read_text())['sources'];rows=[r.get('result',r)for r in rows]
   self.assertEqual([r['REL_sha256']for r in rows],hashes)
   self.assertTrue(all(r['PASS1']and r['PASS2']and r['END_COMPILATION']and r['termination']=='warm_boot'for r in rows))
 def test_no_archaeological_widening_or_duplicate_algorithm(self):
  x=json.loads((REPORT/'fidelity.json').read_text());self.assertEqual(x['RAW_to_UNDERSTOOD'],0);self.assertEqual(x['new_contracts'],[])
  host=Path('lib/pli80_host/recursive_parent.ml').read_text()
  for f in ['source_name','entry_step','sha256','Cpu8080','Runner.']:self.assertNotIn(f,host)
  catalog={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
  self.assertEqual(catalog['PLI1.OVL+0A32']['completeness'],dict(bounds='provisional',control_flow='partial',contract='partial'))
 def test_compact_packet(self):self.assertLessEqual((REPORT/'implementation-packet.json').stat().st_size,32768)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
