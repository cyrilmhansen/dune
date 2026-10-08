"""Independent bounded2259/345E shadows and retained archaeological scope."""
import argparse,json,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
class LocalGatesTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.proofs={}
  with tempfile.TemporaryDirectory(prefix='pass45-gates-',dir=ROOT/'_build')as directory:
   for operation in ('2259','345E','25A9','654E'):
    path=Path(directory)/operation
    cmd=['dune','exec','pli80-native-acquisition-family','--','--toolchain',str(IMAGES),'--operation',operation,'--output',str(path)]
    if operation in ('345E','25A9','654E'):cmd.append('--spine')
    q=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True)
    if q.returncode:raise AssertionError(q.stderr[-1400:]+q.stdout[-500:])
    cls.proofs[operation]=json.loads(path.read_text())
 def test_every_natural_case_full_state(self):
  self.assertEqual([s['field15_matched']for s in self.proofs['2259']['sources']],[5,1])
  self.assertEqual([s['field15_matched']for s in self.proofs['345E']['sources']],[3,0])
  self.assertEqual([s['field15_matched']for s in self.proofs['25A9']['sources']],[0,3,0])
  self.assertEqual([s['field15_matched']for s in self.proofs['654E']['sources']],[1,15,2])
  for p in self.proofs.values():
   for s in p['sources']:
    for c in s['cases']:
     self.assertEqual(len(c['memory_sha256']),64);self.assertGreater(c['final_writer_cells'],0)
 def test_global_partial_status_and_first_next_gap(self):
  cat=json.loads((ROOT/'research/annotated-assembly/procedures.json').read_text())['procedures']
  for key in ('2259','345E'):
   p=next(p for p in cat if p['id']=='PLI1.OVL+'+key)
   self.assertEqual(p['completeness'],dict(bounds='provisional',control_flow='partial',contract='partial'))
  m=json.loads((ROOT/'research/host-compiler/pass-45/first-missing-causal-operation.json').read_text())
  self.assertIsNone(m['current_missing_operation'])
  table=next(p for p in cat if p['id']=='PLI1.OVL+25A9')
  self.assertEqual(table['completeness'],dict(bounds='stable',control_flow='complete',contract='complete'))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
