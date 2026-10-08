"""Bounded +6619 roots, hierarchy, external state and actual-counter regressions."""
import argparse,json,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
class WrapperTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='pass45-wrappers-',dir=ROOT/'_build')as d:
   out=Path(d)/'proof'
   p=subprocess.run(['dune','exec','pli80-native-wrapper-hybrids','--','--toolchain',str(IMAGES),'--output-dir',str(out)],cwd=ROOT,capture_output=True,text=True)
   if p.returncode:raise AssertionError(p.stderr[-1600:]+p.stdout[-400:])
   cls.proofs={n:json.loads((out/(n+'.json')).read_text())for n in ['natural-cases','shadow-summary','single-hybrid-summary','cumulative-hybrid-summary']}
   target=ROOT/'_build/host-compiler-pass-45/validated-hybrids';target.mkdir(exist_ok=True)
   for n,v in cls.proofs.items():(target/(n+'.json')).write_text(json.dumps(v)+'\n')
 def test_every_external_root_full_state(self):
  groups=self.proofs['natural-cases']['sources']
  self.assertEqual([len(g['members'])for g in groups],[1,9,2])
  self.assertEqual([sum(c['result']['route']=='repeat'for c in g['members'])for g in groups],[0,3,0])
  for g in groups:
   for c in g['members']:
    self.assertEqual(c['caller'],'PLI1.OVL+663E');self.assertEqual(c['output']['sp'],c['input']['sp']+2)
    self.assertEqual(len(c['post_memory_sha256']),64);self.assertGreater(len(c['journal']),0)
 def test_hierarchy_and_whole_run_counters(self):
  groups=self.proofs['cumulative-hybrid-summary']['sources']
  self.assertEqual([g['pre_guest_instructions']for g in groups],[425324,1005906,496062])
  self.assertEqual([g['result']['actual_guest_instructions']for g in groups],[424898,995583,495210])
  self.assertEqual([g['transition_vector'][:2]for g in groups],[[1,0],[9,0],[2,0]])
  self.assertEqual([g['result']['host_transitions']for g in groups],[125,388,148])
  self.assertEqual([g['host_bdos_services']for g in groups],[2,6,2])
 def test_compiler_goldens_and_external_identity(self):
  for key in ['single-hybrid-summary','cumulative-hybrid-summary']:
   for g in self.proofs[key]['sources']:
    r=g.get('result',g)
    self.assertTrue(r['PASS1']and r['PASS2']and r['END_COMPILATION']);self.assertEqual(r['termination'],'warm_boot')
  code=(ROOT/'lib/pli80_host/acquisition_family.ml').read_text()
  for forbidden in ['Runner.','Cpm.','sha256','source_name','entry_step']:self.assertNotIn(forbidden,code)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
