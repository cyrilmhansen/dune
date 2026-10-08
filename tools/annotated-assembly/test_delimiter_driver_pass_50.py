#!/usr/bin/env python3
"""Fresh full-state delimiter driver shadows, hierarchy and compiler hybrids."""
import argparse,json,unittest
from pathlib import Path
from run_delimiter_driver_pass_50 import prove
REPORT=Path('research/host-compiler/pass-50')
class DelimiterDriver(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.proof=prove(IMAGES,persist=True)
  cls.packet=json.loads((REPORT/'implementation-packet.json').read_text())
  cls.roots=json.loads((cls.proof/'natural-cases.json').read_text())['sources']
  cls.post=json.loads((cls.proof/'cumulative-hybrid-summary.json').read_text())['sources']
 def test_topology(self):
  self.assertEqual(self.packet['selected_root'],'PLI1.OVL+0C75')
  self.assertEqual([len(r['members'])for r in self.roots],[1,1,1])
  for group in self.packet['cases'].values():
   self.assertEqual(group['PLI1.OVL+0C75'][0]['caller'],'PLI1.OVL+011E')
 def test_visible_lifetime_and_pointer_publication(self):
  for row in self.roots:
   c=row['members'][0];j=c['journal'];own=[w for w in j if w[3]==0 and w[4]=='logical']
   self.assertEqual([w[0]for w in own],[0xa5d9,0xa5da,0xa5db,0xa5d9])
   self.assertEqual([w[2]for w in own],[0x2e78,0x2e91,0x2e91,0x2f06])
   self.assertEqual([own[0][1],own[-1][1]],[1,0])
   self.assertEqual(c['output']['sp'],c['input']['sp']+2);self.assertEqual(c['output']['pc'],0x2321)
 def test_direct_child_chronology_and_scan(self):
  wanted=[0x2e81,0x2e88,0x2e8b,0x2e94,0x2e99,0x2ea2,0x2ea9,0x2eae,0x2ec1]+[0x2ecc]*4+[0x2ed7,0x2ee3,0x2ef2]
  for row in self.roots:
   j=row['members'][0]['journal'];calls=[w[2]for i,w in enumerate(j[:-1])if w[3]==0 and w[4]=='compatibility'and w[2]in wanted and j[i+1][2]==w[2]and w[0]==j[i+1][0]+1]
   self.assertEqual(calls,wanted)
 def test_return_channels_and_full_state(self):
  for row in self.roots:
   c=row['members'][0];q=c['output'];self.assertEqual(c['result']['route'],'delimiter_EOF_driver');self.assertTrue(c['post_memory_sha256'])
   self.assertEqual([q[k]for k in ['a','b','c','d','e','h','l']],[0,0x1d,0x8c,0xaa,0xaa,0xa5,0xd9])
   self.assertEqual(q['flags'],dict(sign=False,zero=True,auxiliary_carry=True,parity=True,carry=False))
 def test_internal_initialization_and_recursive_frames(self):
  for row in self.roots:
   c=row['members'][0];j=c['journal'];S=c['input']['sp']-2
   self.assertIn([S,0xda,0x2ed7,0,'compatibility'],j);self.assertIn([S+1,0x2e,0x2ed7,0,'compatibility'],j)
   self.assertTrue(any(w[2]==0x2e61 for w in j));self.assertTrue(any(w[2]==0x2c38 for w in j))
 def test_whole_run_counters_and_absorption(self):
  self.assertEqual([r['pre_guest_instructions']for r in self.post],[391255,849221,439060])
  self.assertEqual([sum(r['pre_transition_vector'])for r in self.post],[80,103,64])
  for r in self.post:
   self.assertEqual(r['transition_vector'][:8],[1,0,0,0,0,0,0,0]);self.assertEqual(r['pre_transition_vector'][0],1)
   self.assertEqual(r['guest_instructions_removed'],r['pre_guest_instructions']-r['result']['actual_guest_instructions'])
   self.assertGreater(r['guest_instructions_removed'],10000)
 def test_hybrid_goldens(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for file in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   rows=[r.get('result',r)for r in json.loads((self.proof/file).read_text())['sources']];self.assertEqual([r['REL_sha256']for r in rows],hashes)
   self.assertTrue(all(r['PASS1']and r['PASS2']and r['END_COMPILATION']and r['termination']=='warm_boot'for r in rows))
 def test_bounded_catalog_and_packet(self):
  p=next(p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']if p['id']=='PLI1.OVL+0C75')
  self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='partial',contract='partial'));self.assertEqual(p['observed_paths']['represented_bytes'],142)
  self.assertLessEqual((REPORT/'implementation-packet.json').stat().st_size,28672)
  host=Path('lib/pli80_host/initialization_parent.ml').read_text()
  for name in ['source_name','entry_step','sha256','Runner.','Cpu8080','invocation']:self.assertNotIn(name,host)
  self.assertIn('let rec delimiter()',host);self.assertIn('let rec drive()',host)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
