#!/usr/bin/env python3
"""Independent resident output family shadows and complete compiler hybrids."""
import argparse,json,unittest
from pathlib import Path
from run_output_termination_pass_51 import prove
REPORT=Path('research/host-compiler/pass-51')
class OutputFinalization(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.proof=prove(IMAGES,persist=True)
  cls.roots=json.loads((cls.proof/'natural-cases.json').read_text())['sources']
  cls.packet=json.loads((REPORT/'implementation-packet.json').read_text())
  cls.post=json.loads((cls.proof/'cumulative-hybrid-summary.json').read_text())['sources']
 def test_phase_boundary_and_root(self):
  self.assertEqual(self.packet['selected_root'],'PLI.COM+1272')
  self.assertEqual([len(r['members'])for r in self.roots],[1,1,1])
  self.assertEqual([r['members'][0]['caller']for r in self.roots],['PLI.COM+02E3']*3)
  for v in self.packet['cases'].values():self.assertGreater(v['padding_calls'],0)
 def test_fresh_indices_and_padding_law(self):
  self.assertEqual([v['indices']for v in self.packet['cases'].values()],[[44,7],[7,7],[51,7]])
  for row,case in zip(self.roots,self.packet['cases'].values()):
   j=row['members'][0]['journal']
   self.assertEqual(sum(w[2]==0x1269 for w in j),(128-case['indices'][0])*8-case['indices'][1])
   self.assertEqual(sum(w[2]==0x129b for w in j),1)
   self.assertIn([0x1d8a,0,0x129b,1,'logical'],j)
 def test_return_flags_channels_and_continuation(self):
  for row in self.roots:
   c=row['members'][0];q=c['output']
   self.assertEqual([q[k]for k in ['a','b','c','d','e','h','l']],[0,0,16,0x1c,0xe4,0x1c,0xe4])
   self.assertEqual(q['flags'],dict(sign=False,zero=False,auxiliary_carry=False,parity=False,carry=True))
   self.assertEqual(q['pc'],0x03e6);self.assertEqual(q['sp'],c['input']['sp']+2)
 def test_hardware_stack_and_direct_children(self):
  for row,case in zip(self.roots,self.packet['cases'].values()):
   c=row['members'][0];j=c['journal'];S=c['input']['sp']
   self.assertFalse(any(w[0]in[S,S+1]for w in j))
   owncalls=[w[2]for i,w in enumerate(j[:-1])if w[3]==0 and w[4]=='compatibility'and w[2]in[0x13a1,0x13aa]and w[0]==j[i+1][0]+1 and w[2]==j[i+1][2]]
   self.assertEqual(owncalls,[0x13a1]*case['padding_calls']+[0x13aa])
   self.assertTrue(any(w[2]==0x074c and w[0]==S-3 for w in j))
   self.assertTrue(any(w[2]==0x0759 for w in j))
 def test_services_dma_and_last_record(self):
  for row in self.roots:
   c=row['members'][0];v=c['service_details']
   self.assertEqual([s['function']for s in v],[26,21,26,16])
   self.assertEqual(c['post_dma'],0x80)
   self.assertEqual([s['dma_after']for s in v],[0x1d0a,0x1d0a,0x80,0x80])
   self.assertEqual(len(v[1]['records']),1)
 def test_independent_component_proofs(self):
  rows=json.loads((self.proof/'component-shadows.json').read_text())['sources']
  self.assertEqual([r['bit_writer_required_shadows']for r in rows],[665,961,609])
  self.assertEqual([[n for _,n in r['service_wrapper_shadows']]for r in rows],[[5,3,20],[5,9,20],[5,3,20]])
 def test_whole_run_counters_and_hierarchy(self):
  self.assertEqual([r['pre_guest_instructions']for r in self.post],[380445,838187,428026])
  self.assertEqual([sum(r['pre_transition_vector'])for r in self.post],[72,95,56])
  self.assertEqual([r['guest_instructions_removed']for r in self.post],[31192,44993,28581])
  for r in self.post:
   self.assertEqual(r['transition_vector'],[1]+r['pre_transition_vector'])
   self.assertEqual(r['guest_instructions_removed'],r['pre_guest_instructions']-r['result']['actual_guest_instructions'])
 def test_hybrids_goldens_and_scope(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for file in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   rows=[r.get('result',r)for r in json.loads((self.proof/file).read_text())['sources']]
   self.assertEqual([r['REL_sha256']for r in rows],hashes)
   self.assertTrue(all(r['PASS1']and r['PASS2']and r['END_COMPILATION']and r['termination']=='warm_boot'for r in rows))
  self.assertLess((REPORT/'implementation-packet.json').stat().st_size,28672)
  counts=json.loads((REPORT/'archaeology-summary-PLI.COM.json').read_text())
  self.assertEqual(counts['raw_to_understood'],83)
  cat={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
  self.assertEqual(cat['PLI.COM+1272']['completeness'],dict(bounds='stable',control_flow='partial',contract='partial'))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
