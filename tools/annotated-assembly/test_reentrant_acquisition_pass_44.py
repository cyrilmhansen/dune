#!/usr/bin/env python3
"""Targeted development proof. This deliberately does not claim Pass44 completion."""
import argparse,json,subprocess,tempfile,unittest
from pathlib import Path
from check_6223_pass_32 import ROOT
class ReentrantDevelopmentTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='pass44-',dir=ROOT/'_build')as directory:
   path=Path(directory)/'proof.json'
   p=subprocess.run(['dune','exec','pli80-native-reentrant-acquisition','--','--toolchain',str(IMAGES),'--output',str(path)],cwd=ROOT,capture_output=True,text=True)
   if p.returncode:raise AssertionError(p.stderr[-1600:]+p.stdout[-400:])
   cls.proof=json.loads(path.read_text());(ROOT/'_build/host-compiler-pass-44/route-b-proof.json').write_bytes(path.read_bytes())
  cls.packet=json.loads((ROOT/'research/host-compiler/pass-44/implementation-packet.json').read_text())
 def test_corrected_21_logical_15_outer_six_nested_topology(self):
  self.assertEqual([(s['logical_count'],s['outer_count'],s['nested_count'],s['maximum_depth'])for s in self.packet['sources']],[(1,1,0,1),(18,12,6,2),(2,2,0,1)])
  nested=[r for s in self.packet['sources']for r in s['invocations']if r['window_depth']>1]
  self.assertEqual(sum(r['route']=='B_5929_2511'for r in nested),3)
  self.assertEqual(sum(r['route']=='A_01E8_256C'for r in nested),3)
 def test_all_thirteen_route_B_windows_are_independent_shadows(self):
  self.assertEqual([s['matched_route_B']for s in self.proof['sources']],[1,11,1])
  for source,actual in zip(self.packet['sources'],self.proof['sources']):
   expected=[r for r in source['invocations']if r['route']=='B_5929_2511']
   self.assertEqual([r['entry_step']for r in expected],[r['entry_step']for r in actual['cases']if r['route']=='B_5929_2511'])
   for e,a in zip(expected,[r for r in actual['cases']if r['route']=='B_5929_2511']):
    self.assertEqual((e['caller'],e['entry'],e['output'],e['return_step']),(a['caller'],a['input'],a['output'],a['return_step']))
    self.assertEqual(len(a['post_memory_sha256']),64);self.assertGreater(a['stack_cells'],0);self.assertGreater(a['logical_writes'],0)
 def test_all_route_A_paths_are_state_selected_and_complete(self):
  self.assertEqual([s['pending_route_A']for s in self.proof['sources']],[0,0,0])
  self.assertEqual([sum(r['route']=='A_01E8_256C'for r in s['cases'])for s in self.proof['sources']],[0,4,1])
  self.assertIn('no hybrid controller enabled',self.proof['status'])
  for module in ['reentrant_acquisition','classifier']:
   code=(ROOT/f'lib/pli80_host/{module}.ml').read_text()
   for forbidden in ['Runner.','Cpm.','I8080.','sha256','entry_step','source_name']:self.assertNotIn(forbidden,code)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
