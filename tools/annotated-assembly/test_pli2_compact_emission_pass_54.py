#!/usr/bin/env python3
"""Independent historical full-state shadows, bit equations and compact hierarchy."""
import argparse,json,unittest
from pathlib import Path
from run_pli2_compact_emission_pass_54 import prove,OUT,REPORT,ENTRIES
class CompactEmission(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  prove(IMAGES)
  cls.rows=json.loads((OUT/'natural-cases.json').read_text())['sources']
  cls.post=json.loads((OUT/'cumulative-hybrid-summary.json').read_text())['sources']
 def test_valid_entrypoints(self):
  cfg=json.loads((OUT/'cfg.json').read_text())
  self.assertEqual(sorted(k for k in cfg if 0x7557<=int(k.split('+')[1],16)<0x7630),[f'PLI2.OVL+{x:04X}'for x in ENTRIES])
  self.assertEqual(next(r for r in cfg['PLI2.OVL+75CE']if r[0]==0x75ce)[1],'21D7AD')
  self.assertFalse(any(r[0]==0x75d0 for rs in cfg.values()for r in rs))
 def test_all_natural_cross_cases(self):
  self.assertEqual([[len(e['members'])for e in r['entries'][:9]]for r in self.rows],[[13,7,2,6,10,3,13,6,3],[94,33,11,33,43,18,94,63,19],[15,7,1,6,11,4,15,6,4]])
 def test_literal_bit_counts_and_position_steps(self):
  for r in self.rows:
   for e in r['entries'][:6]:
    for c in e['members']:
     n=2 if e['offset']in[0x75f1,0x7619]else 1
     self.assertEqual([w[1]for w in c['journal']if w[2]==0x12a1],[8]*n)
     self.assertEqual(len([w for w in c['journal']if w[2]==0x9740]),2*n)
     q=c['output'];self.assertEqual(q['d']*256+q['e'],0)
     self.assertEqual(q['a'],q['h']|q['l']);self.assertFalse(q['flags']['carry'])
 def test_field_normalization_from_state(self):
  for r in self.rows:
   for e in r['entries']:
    if e['offset']not in[0x756d,0x75ce]:continue
    for c in e['members']:
     v=c['input']['c'];f=c['input']['e'];q=c['journal'];emitted=[w[1]for w in q if w[2]==0x975a]
     expected=(v|(1 if v==0xc2 and f==9 else f))if e['offset']==0x756d else v|((f<<3)&255)
     self.assertEqual(emitted,[expected])
     if e['offset']==0x756d:self.assertEqual([w[1]for w in q if w[2]==0x978e],[1]if v==0xc2 and f==9 else[])
 def test_two_independent_word_reads(self):
  for r in self.rows:
   e=next(e for e in r['entries']if e['offset']==0x75f1)
   for c in e['members']:
    self.assertEqual([w[1]for w in c['journal']if w[2]==0x12a3],[c['input']['c'],c['input']['b']])
 def test_carrier_gate_return_flags_and_publications(self):
  caches={0x746f:0xadcc,0x74c7:0xadcf,0x7510:0xadd0}
  for r in self.rows:
   for e in r['entries'][6:9]:
    for c in e['members']:
     q=c['output'];cache=caches[e['offset']]
     self.assertEqual(q['h']*256+q['l'],cache)
     self.assertEqual(q['flags'],{**c['input']['flags'],'carry':False})
     self.assertEqual(q['b'],c['input']['b']);self.assertEqual(q['c'],c['input']['c'])
     own=[w for w in c['journal']if w[4]=='logical']
     self.assertEqual([(w[0],w[1])for w in own],([(cache+1,c['input']['b'])]if e['offset']==0x7510 else[])+[(cache,c['input']['c'])])
 def test_stack_and_continuation(self):
  for r in self.rows:
   for e in r['entries']:
    for c in e['members']:
     S=c['input']['sp'];self.assertEqual(c['output']['sp'],S+2)
     self.assertFalse(any(w[0]in[S,S+1]for w in c['journal']))
 def test_hierarchy_and_transition_economics(self):
  top=json.loads((REPORT/'topology-summary.json').read_text())
  self.assertEqual([g['roots']for g in top.values()],[25,148,27])
  self.assertEqual([g['serializer_absorbed']for g in top.values()],[35,191,38])
  self.assertEqual([g['serializer_remaining']for g in top.values()],[92,236,99])
  for g,r in zip(top.values(),self.post):
   self.assertEqual(r['family_roots'],g['roots']);self.assertEqual(r['result']['host_transitions']-sum(r['pre_transition_vector']),g['net_new_transitions'])
 def test_component_proofs(self):
  c=json.loads((OUT/'component-shadows.json').read_text())['sources']
  self.assertEqual([r['serializer_shadows']for r in c],[35,191,38]);self.assertEqual([r['bit_writer_shadows']for r in c],[315,1719,342])
 def test_whole_run_baseline_and_exact_output(self):
  self.assertEqual([r['pre_guest_instructions']for r in self.post],[335133,723107,382741])
  self.assertEqual([r['result']['actual_guest_instructions']for r in self.post],[320378,642630,366662])
  self.assertEqual([r['guest_instructions_removed']for r in self.post],[14755,80477,16079])
  self.assertEqual([r['result']['host_transitions']for r in self.post],[114,319,103])
  golden=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for file in['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   rows=[r['result']for r in json.loads((OUT/file).read_text())['sources']]
   self.assertEqual([r['REL_sha256']for r in rows],golden)
   self.assertTrue(all(r['PASS1']and r['PASS2']and r['END_COMPILATION']and r['termination']=='warm_boot'for r in rows))
 def test_annotation_scope_and_historical_totals(self):
  cat={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
  for x in ENTRIES:self.assertEqual(cat[f'PLI2.OVL+{x:04X}']['completeness']['contract'],'partial')
  p=cat['PLI2.OVL+7557'];self.assertEqual(p['observed_paths']['invocations_by_run']['FACTOR'],50);self.assertEqual(p['observed_paths']['invocations_by_run']['OPTIMIST'],169)
  self.assertEqual(json.loads((REPORT/'archaeology-summary-PLI2.OVL.json').read_text())['raw_to_understood'],223)
  self.assertLess((REPORT/'implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
