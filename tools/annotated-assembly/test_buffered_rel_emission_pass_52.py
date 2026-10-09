#!/usr/bin/env python3
"""Cross-phase natural proofs for the canonical resident tagged-word family."""
import argparse,json,unittest
from pathlib import Path
from run_buffered_rel_emission_pass_52 import prove,OUT,REPORT
class BufferedRelEmission(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  prove(IMAGES)
  cls.roots=json.loads((OUT/'natural-cases.json').read_text())['sources']
  cls.post=json.loads((OUT/'cumulative-hybrid-summary.json').read_text())['sources']
  cls.packet=json.loads((REPORT/'implementation-packet.json').read_text())
 def test_natural_inventory_and_family_boundary(self):
  top=json.loads((REPORT/'topology-summary.json').read_text())
  self.assertEqual([g['total_serializer']for g in top.values()],[189,703,197])
  self.assertEqual([[len(e['members'])for e in r['entries']]for r in self.roots],[[1,14,2],[1,63,14],[1,14,4]])
  self.assertEqual([e['coordinate']for e in self.packet['accepted_entries']],['PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207'])
  self.assertEqual(self.packet['unobserved_member']['status'],'STATIC / UNOBSERVED; not promoted or intercepted')
 def test_tags_cache_writers_and_fresh_word_channels(self):
  for r in self.roots:
   for e in r['entries']:
    offset=e['offset'];cache={0x11c3:0x20b9,0x11e5:0x20bb,0x1207:0x20bd}[offset]
    for c in e['members']:
     j=c['journal'];own=[w for w in j if w[3]==0 and w[4]=='logical']
     self.assertEqual(own,[[cache+1,c['input']['b'],offset+0x103,0,'logical'],[cache,c['input']['c'],offset+0x105,0,'logical']])
     count_writes=[w[1]for w in j if w[2]==0x12a1]
     self.assertEqual(count_writes,[2,8,8])
 def test_final_child_return_channels(self):
  for r in self.roots:
   for e in r['entries']:
    for c in e['members']:
     q=c['output'];self.assertEqual(q['a'],0);self.assertEqual([q['h'],q['l']],[0x20,0xb8]);self.assertEqual(q['e'],8)
     self.assertEqual(q['flags'],dict(sign=False,zero=True,auxiliary_carry=True,parity=True,carry=False))
     self.assertEqual(q['sp'],c['input']['sp']+2)
 def test_hardware_calls_and_stack_writers(self):
  for r in self.roots:
   for e in r['entries']:
    for c in e['members']:
     j=c['journal'];S=c['input']['sp'];offset=e['offset']
     self.assertFalse(any(w[0]in [S,S+1]for w in j))
     calls=[w[2]for i,w in enumerate(j[:-1])if w[3]==0 and w[4]=='compatibility'and w[0]==j[i+1][0]+1 and w[2]==j[i+1][2]]
     self.assertEqual(calls,[offset+0x10a,offset+0x114,offset+0x11e])
     self.assertEqual(sum(w[2]==0x12b5 and w[0]==S-3 for w in j),18)
 def test_independent_serializer_and_writer_cases(self):
  rows=json.loads((OUT/'component-shadows.json').read_text())['sources']
  self.assertEqual([r['serializer_shadows']for r in rows],[189,703,197])
  self.assertEqual([r['bit_writer_shadows']for r in rows],[306,1404,342])
  writer=json.loads((REPORT/'writer-route-summary.json').read_text())
  self.assertEqual([sum(q['flushes']for q in g['PLI.COM+119E'].values())for g in writer.values()],[1,5,1])
 def test_hierarchy_and_actual_counters(self):
  self.assertEqual([r['pre_guest_instructions']for r in self.post],[349253,793194,399445])
  self.assertEqual([r['result']['actual_guest_instructions']for r in self.post],[336252,732279,384016])
  self.assertEqual([r['family_roots']for r in self.post],[16,75,19])
  self.assertEqual([sum(r['pre_transition_vector'])for r in self.post],[73,96,57])
  self.assertEqual([r['result']['host_transitions']for r in self.post],[89,171,76])
  for r in self.post:
   self.assertEqual(r['transition_vector'][3:],r['pre_transition_vector'])
   self.assertEqual(r['guest_instructions_removed'],r['pre_guest_instructions']-r['result']['actual_guest_instructions'])
 def test_external_serializer_remainder_and_economics(self):
  top=json.loads((REPORT/'topology-summary.json').read_text())
  self.assertEqual([g['remaining_external_serializer']for g in top.values()],[130,450,140])
  self.assertEqual([3*sum(q['external']for q in g['members'].values())for g in top.values()],[48,225,57])
  self.assertLess(sum(r['family_roots']for r in self.post),sum(g['total_serializer']for g in top.values()))
 def test_goldens_and_bounded_catalog(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for f in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   rows=[r['result']for r in json.loads((OUT/f).read_text())['sources']]
   self.assertEqual([r['REL_sha256']for r in rows],hashes)
   self.assertTrue(all(r['PASS1']and r['PASS2']and r['END_COMPILATION']and r['termination']=='warm_boot'for r in rows))
  self.assertLess((REPORT/'implementation-packet.json').stat().st_size,28672)
  cat={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
  for x in [0x11c3,0x11e5,0x1207]:self.assertEqual(cat[f'PLI.COM+{x:04X}']['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'))
  self.assertEqual(json.loads((REPORT/'archaeology-summary-PLI.COM.json').read_text())['raw_to_understood'],68)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
