#!/usr/bin/env python3
"""Pass44 staged child proofs; deliberately not a complete-root/controller claim."""
import argparse,json,subprocess,tempfile,unittest
from pathlib import Path
from check_6223_pass_32 import ROOT
class FamilyDevelopmentTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.proofs=[]
  with tempfile.TemporaryDirectory(prefix='pass44-family-',dir=ROOT/'_build')as directory:
   for spine in (False,True):
    path=Path(directory)/('recursive.json'if spine else'field15.json')
    command=['dune','exec','pli80-native-acquisition-family','--','--toolchain',str(IMAGES),'--output',str(path)]
    if spine:command.append('--spine')
    p=subprocess.run(command,cwd=ROOT,capture_output=True,text=True)
    if p.returncode:raise AssertionError(p.stderr[-1400:]+p.stdout[-400:])
    cls.proofs.append(json.loads(path.read_text()))
    (ROOT/'_build/host-compiler-pass-44'/path.name).write_bytes(path.read_bytes())
 def test_field15_complete_boundaries_each_invocation(self):
  for proof in self.proofs:
   self.assertEqual([(s['source'],s['operation'],s['field15_matched'])for s in proof['sources']],
    [('FIZZBUZ','60E5',8 if proof is self.proofs[1] else 5),('FIZZBUZ','5E98',8 if proof is self.proofs[1] else 5),('PICTURE','60E5',2),('PICTURE','5E98',2)])
   for source in proof['sources']:
    for case in source['cases']:
     self.assertEqual(len(case['memory_sha256']),64)
     self.assertGreater(case['ordered_writes'],0);self.assertGreater(case['final_writer_cells'],0)
 def test_all_three_field80_4f54_entries(self):
  self.assertEqual([s['field80_boundary_matched']for s in self.proofs[0]['sources']],[3,3,0,0])
  for source in self.proofs[0]['sources']:
   for case in source['cases']:
    if case['kind']=='4F54_entry':self.assertEqual(case['pc'],0x7154)
 def test_both_recursive_calls_and_full_field80_returns(self):
  self.assertEqual([s['field80_boundary_matched']for s in self.proofs[1]['sources']],[0,0,0,0])
  self.assertEqual([s['field15_matched']for s in self.proofs[1]['sources']],[8,8,2,2])
 def test_core_is_independent_and_no_controller_enabled(self):
  for name in ('acquisition_family','input_gate'):
   code=(ROOT/f'lib/pli80_host/{name}.ml').read_text()
   for forbidden in ('Runner.','Cpm.','I8080.','sha256','source_name','entry_step'):self.assertNotIn(forbidden,code)
  for proof in self.proofs:self.assertIn('no hybrid controller',proof['status'])
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
