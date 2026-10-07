#!/usr/bin/env python3
"""Independent resident operation shadows for the newly required bounded numeric law."""
import argparse,json,subprocess,tempfile,unittest
from pathlib import Path
from check_acquisition_pass_41 import ROOT,BOUNDS,CAPTURES,SOFTWARE,gather_selected
from check_numeric_acquisition_pass_44 import derive_numeric
class NumericAcquisitionTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.evidence=json.loads((ROOT/'research/host-compiler/pass-44/numeric-acquisition-cases.json').read_text())
  with tempfile.TemporaryDirectory(prefix='pass44-numeric-',dir=ROOT/'_build')as directory:
   path=Path(directory)/'shadow.json'
   p=subprocess.run(['dune','exec','pli80-native-numeric-acquisition','--','--toolchain',str(IMAGES),'--output',str(path)],cwd=ROOT,capture_output=True,text=True)
   if p.returncode:raise AssertionError(p.stderr[-1800:]+p.stdout[-300:])
   cls.shadow=json.loads(path.read_text());(ROOT/'_build/host-compiler-pass-44/numeric/shadow.json').write_bytes(path.read_bytes())
 def test_three_independent_full_state_shadows(self):
  self.assertEqual(self.shadow['sources'][0]['field15_matched'],3)
  self.assertEqual([c['initial_context']for c in self.evidence['cases']],[0x31,0x33,0x35])
  for c in self.shadow['sources'][0]['cases']:self.assertEqual(len(c['memory_sha256']),64)
 def test_accumulation_is_not_constant_or_single_append(self):
  self.assertEqual([c['prefix']for c in self.evidence['cases']],[[0x31,0x35],[0x33],[0x35]])
  self.assertEqual([c['accumulator']for c in self.evidence['cases']],[6,3,5])
  self.assertEqual([len(c['reads'])for c in self.evidence['cases']],[2,1,1])
  for c in self.evidence['cases']:
   self.assertEqual(c['selector'],2);self.assertEqual(c['following_context'],0x29)
   self.assertEqual(c['width'],len(c['prefix']))
   self.assertTrue(all(r['index']<r['count']for r in c['reads']))
 def test_return_flags_are_independent_of_return_A(self):
  for c in self.evidence['cases']:
   self.assertEqual(c['output']['a'],0x7f)
   self.assertEqual(c['output']['flags'],dict(sign=False,zero=True,auxiliary_carry=True,parity=True,carry=True))
   self.assertEqual(c['output']['sp'],c['entry']['sp']+2)
 def test_corrected_witnesses_independently_rederive_complete_cases(self):
  rows={'FIZZBUZ':gather_selected(CAPTURES['FIZZBUZ'],BOUNDS,include_nested_returns=True,software_callees=SOFTWARE)}
  expected=self.evidence['cases']
  self.assertEqual(derive_numeric(rows,[c['call_step']for c in expected]),expected)
 def test_extension_keeps_global_contract_partial(self):
  catalog=json.loads((ROOT/'research/annotated-assembly/procedures.json').read_text())
  p=next(p for p in catalog['procedures']if p['id']=='PLI.COM+1376')
  self.assertEqual(p['completeness'],dict(bounds='provisional',control_flow='partial',contract='partial'))
  self.assertIn('Pass44 digit-selected selector02',p['contract_scope'])
  self.assertEqual(self.evidence['oracle_queries'],0)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
