"""Independent natural shadows, parent hierarchy and bounded Pass46 contracts."""
import argparse,hashlib,json,unittest
from pathlib import Path
from run_parent_pass_46 import prove
ROOT=Path(__file__).resolve().parents[2]
REPORT=ROOT/'research/host-compiler/pass-46'
def load(p):return json.loads(p.read_text())
class ParentTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.output=prove(IMAGES)
  cls.groups=load(cls.output/'natural-cases.json')['sources']
 def test_independent_components(self):
  expected={'6708-E05':[2,6,0],'46ED':[2,6,0],'4738':[1,3,0],'666E':[1,3,0],'28AA-I1':[1,7,2],'19F0':[1,4,1]}
  for operation,counts in expected.items():
   p=load(self.output/(operation+'.json'))
   self.assertEqual([g['field15_matched']for g in p['sources']],counts)
   self.assertTrue(all(g['field80_boundary_matched']==0 for g in p['sources']))
 def test_six_root_windows_and_private_frame(self):
  self.assertEqual([len(g['members'])for g in self.groups],[1,4,1])
  self.assertEqual([sum(c['result']['route']=='selector05_construct'for c in g['members'])for g in self.groups],[1,3,0])
  for g in self.groups:
   for c in g['members']:
    self.assertEqual(c['caller'],'PLI1.OVL+1B7B')
    self.assertEqual((c['output']['sp'],c['output']['pc']),(c['input']['sp']+2,0x3d7e))
    writes=c['journal'];frame=c['input']['sp']-2
    self.assertIn([frame,c['input']['c'],0x3bf2,0,'compatibility'],writes)
    self.assertTrue(any(a==frame+1 and w==0x3bfb and k=='logical'for a,v,w,d,k in writes))
    self.assertEqual(c['output']['l'],c['input']['c'])
    self.assertEqual(c['output']['a'],0)
 def test_N2_N8_and_internal_wrapper_correlation(self):
  for g in self.groups:
   for c in g['members']:
    writes=c['journal'];sp=c['input']['sp']
    self.assertEqual(sum(w==0x883e and k=='compatibility'for a,v,w,d,k in writes),2)
    self.assertEqual(sum(w==0x8473 and k=='compatibility'for a,v,w,d,k in writes),2)
    if c['result']['route']=='selector05_construct':
     self.assertEqual(sum(w==0x891f and k=='compatibility'for a,v,w,d,k in writes),4)
     self.assertTrue(any(w==0x6674 for a,v,w,d,k in writes))
    self.assertTrue(all(0<=a<65536 and 0<=v<256 for a,v,w,d,k in writes))
 def test_actual_whole_run_counters_and_absorption(self):
  p=load(self.output/'cumulative-hybrid-summary.json')['sources']
  self.assertEqual([g['pre_guest_instructions']for g in p],[424898,995583,495210])
  self.assertEqual([g['result']['actual_guest_instructions']for g in p],[414704,967554,494793])
  self.assertEqual([g['guest_instructions_removed']for g in p],[10194,28029,417])
  self.assertEqual([sum(g['pre_transition_vector'])for g in p],[125,388,148])
  self.assertEqual([g['result']['host_transitions']for g in p],[112,340,139])
  self.assertEqual([g['transition_vector'][:2]for g in p],[[1,0],[4,5],[1,1]])
  self.assertEqual([g['host_bdos_services']for g in p],[2,6,2])
 def test_compiler_goldens_and_external_identity(self):
  golden={'MINIMAL':(256,'7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119'),'FIZZBUZ':(768,'68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203'),'PICTURE':(256,'c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1')}
  for filename in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   for g in load(self.output/filename)['sources']:
    q=g.get('result',g);self.assertEqual((q['REL_size'],q['REL_sha256']),golden[q['source']]);self.assertTrue(q['PASS1']and q['PASS2']and q['END_COMPILATION']);self.assertEqual(q['termination'],'warm_boot')
 def test_compact_packet_contract_identity_and_scoped_catalog(self):
  raw=(REPORT/'implementation-packet.json').read_bytes();self.assertLessEqual(len(raw),32768)
  p=json.loads(raw);self.assertEqual(p['selected_root'],'PLI1.OVL+19F0');self.assertEqual(p['oracle_queries'],0)
  catalog={q['id']:q for q in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
  for ref in p['reused_contracts']+p['new_contract_references']:
   self.assertEqual(hashlib.sha256(json.dumps(catalog[ref['coordinate']],sort_keys=True,separators=(',',':')).encode()).hexdigest(),ref['procedure_sha256'])
  for key in ['19F0','28AA','6708','46ED','4738','666E']:
   self.assertEqual(catalog['PLI1.OVL+'+key]['completeness']['contract'],'partial')
 def test_host_has_no_fixture_or_emulator_dispatch(self):
  code=(ROOT/'lib/pli80_host/acquisition_family.ml').read_text()
  for forbidden in ['Runner.','Cpm.','Cpu8080','Cpu.step','source_name','entry_step','sha256']:
   self.assertNotIn(forbidden,code)
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--images',required=True,type=Path)
 args,rest=parser.parse_known_args();IMAGES=args.images
 unittest.main(argv=[__file__]+rest)
