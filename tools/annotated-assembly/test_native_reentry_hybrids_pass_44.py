"""Whole compiler identity and actual hierarchy counters for the reentrant root."""
import argparse,json,subprocess,tempfile,unittest
from pathlib import Path
from check_6223_pass_32 import ROOT
class ReentryHybridTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='pass44-hybrids-',dir=ROOT/'_build')as directory:
   out=Path(directory)/'results'
   q=subprocess.run(['dune','exec','pli80-native-reentrant-hybrids','--','--toolchain',str(IMAGES),'--output-dir',str(out)],cwd=ROOT,capture_output=True,text=True)
   if q.returncode:raise AssertionError(q.stdout[-600:]+q.stderr[-1600:])
   cls.reports={p.stem:json.loads(p.read_text())for p in out.glob('*.json')}
   proof=ROOT/'_build/host-compiler-pass-44/latest-hybrids';proof.mkdir(parents=True,exist_ok=True)
   for p in out.glob('*.json'):(proof/p.name).write_bytes(p.read_bytes())
 def test_all_outer_roots_and_logical_windows(self):
  self.assertEqual([len(s['members'])for s in self.reports['natural-cases']['sources']],[1,12,2])
  self.assertEqual([s['invocations']for s in self.reports['shadow-summary']['sources']],[1,18,2])
 def test_single_and_cumulative_goldens_and_markers(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for group in [self.reports['single-hybrid-summary']['sources'],[q['result']for q in self.reports['cumulative-hybrid-summary']['sources']]]:
   self.assertEqual([q['REL_sha256']for q in group],hashes)
   self.assertEqual([q['REL_size']for q in group],[256,768,256])
   for q in group:self.assertTrue(q['PASS1']and q['PASS2']and q['END_COMPILATION']);self.assertEqual(q['termination'],'warm_boot')
 def test_actual_counters_not_overlapping_interval_sums(self):
  sources=self.reports['cumulative-hybrid-summary']['sources']
  self.assertEqual([q['pre_guest_instructions']for q in sources],[425454,1029607,498198])
  self.assertEqual([q['result']['actual_guest_instructions']for q in sources],[425324,1005906,496062])
  self.assertEqual([q['guest_instructions_removed']for q in sources],[130,23701,2136])
  self.assertEqual([q['transition_vector'][0]for q in sources],[1,12,2])
  for q in sources:self.assertEqual(sum(q['transition_vector']),q['result']['host_transitions'])
 def test_live_service_and_output_identity(self):
  sources=self.reports['cumulative-hybrid-summary']['sources']
  self.assertEqual([q['host_bdos_services']for q in sources],[2,6,2])
  for single,cumulative in zip(self.reports['single-hybrid-summary']['sources'],sources):
   self.assertEqual(single['INT_sha256'],cumulative['result']['INT_sha256'])
   self.assertEqual(single['filesystem_sha256'],cumulative['result']['filesystem_sha256'])
   self.assertGreaterEqual(len(cumulative['record_sha256_sequence']),3)
 def test_continuations_have_derived_stack_writers(self):
  fizz=self.reports['natural-cases']['sources'][1]['members']
  early=next(c for c in fizz if c['result']['route']=='A_early')
  writers={w for a,v,w,d,k in early['journal']}
  for site in [0x891f,0x8473,0x7231,0x8308,0x82f0]:self.assertIn(site,writers)
  for c in fizz:self.assertEqual(c['output']['sp'],c['input']['sp']+2)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
