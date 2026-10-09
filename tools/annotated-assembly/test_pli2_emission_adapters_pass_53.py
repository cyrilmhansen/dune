#!/usr/bin/env python3
"""Independent natural, cross-caller and synthetic proofs for compact PLI2 adapters."""
import argparse,json,unittest
from pathlib import Path
from run_pli2_emission_adapters_pass_53 import prove,OUT,REPORT
class Pli2EmissionAdapters(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  prove(IMAGES)
  cls.rows=json.loads((OUT/'natural-cases.json').read_text())['sources']
  cls.post=json.loads((OUT/'cumulative-hybrid-summary.json').read_text())['sources']
 def test_inventory_and_component_cross_cases(self):
  self.assertEqual([[len(e['members'])for e in r['entries'][:5]]for r in self.rows],[[3,1,1,12,39],[23,12,11,66,237],[3,1,3,15,46]])
  self.assertTrue(all(len(r['entries'][5]['members'])>=len(r['entries'][4]['members'])for r in self.rows))
 def test_entry_specific_cache_and_output_parameters(self):
  for r in self.rows:
   for e in r['entries'][:3]:
    offset=e['offset'];cache={0x7434:0xadc6,0x7630:0xaddc,0x765e:0xade0}[offset]
    for c in e['members']:
     own=[w for w in c['journal']if w[3]==0 and w[4]=='logical']
     self.assertEqual(own[:2],[[cache+1,c['input']['b'],offset+0x2203,0,'logical'],[cache,c['input']['c'],offset+0x2205,0,'logical']])
     count=[w[1]for w in c['journal']if w[2]==0x12a1]
     self.assertEqual(count,([7]if offset==0x7434 else[])+[2,8,8])
     if offset==0x7434:self.assertEqual(own[2:],[[0x1c2c,c['input']['c'],0x9644,0,'logical'],[0x1c2d,c['input']['b'],0x9644,0,'logical']])
 def test_position_fresh_publications_and_return_provenance(self):
  for r in self.rows:
   for e in r['entries']:
    if e['offset']not in[0x7550,0x753c,0x7630,0x765e]:continue
    count=1 if e['offset']==0x753c else 2
    for c in e['members']:
     writes=[w for w in c['journal']if w[2]==0x9740]
     self.assertEqual(len(writes),count*2)
     words=[writes[i][1]+256*writes[i+1][1]for i in range(0,len(writes),2)]
     if count==2:self.assertEqual(words[1],(words[0]+1)&65535)
     q=c['output'];neg=(-words[-1])&65535
     self.assertEqual(q['h']*256+q['l'],neg);self.assertEqual(q['a'],(neg>>8)|(neg&255));self.assertEqual(q['d']*256+q['e'],0)
     self.assertEqual(q['flags'],dict(sign=q['a']>=128,zero=False,auxiliary_carry=False,parity=q['a'].bit_count()%2==0,carry=False))
 def test_call_words_and_continuation_lifetime(self):
  for r in self.rows:
   for e in r['entries'][:5]:
    for c in e['members']:
     S=c['input']['sp'];j=c['journal'];self.assertFalse(any(w[0]in[S,S+1]for w in j));self.assertEqual(c['output']['sp'],S+2)
     words=[(j[i][2],j[i+1][1]+256*j[i][1])for i in range(len(j)-1)if j[i][3]==0 and j[i][4]=='compatibility'and j[i][0]==S-1 and j[i+1][0]==S-2]
     sites={0x7434:[0x963e,0x9649],0x7630:[0x9838,0x9840,0x9843],0x765e:[0x9866,0x986e,0x9871],0x7550:[0x9750,0x9753],0x753c:[0x9745]}[e['offset']]
     self.assertEqual(words,[(site,site+3)for site in sites])
 def test_independent_serializer_and_writer_shadows(self):
  c=json.loads((OUT/'component-shadows.json').read_text())['sources']
  self.assertEqual([r['serializer_shadows']for r in c],[18,161,24]);self.assertEqual([r['bit_writer_shadows']for r in c],[113,1012,151])
 def test_exact_hierarchy_and_remaining_serializer_map(self):
  top=json.loads((REPORT/'topology-summary.json').read_text())
  self.assertEqual([g['adapter_roots']for g in top.values()],[5,46,7]);self.assertEqual([g['resident_roots_absorbed']for g in top.values()],[5,46,7])
  self.assertEqual([g['serializer_remaining_post']for g in top.values()],[127,427,137])
  for r in self.post:self.assertEqual(sum(r['transition_vector']),sum(r['pre_transition_vector']));self.assertEqual(r['family_roots'],sum(r['transition_vector'][:3]))
 def test_actual_whole_run_counters(self):
  self.assertEqual([r['pre_guest_instructions']for r in self.post],[336252,732279,384016])
  self.assertEqual([r['result']['actual_guest_instructions']for r in self.post],[335133,723107,382741])
  self.assertEqual([r['guest_instructions_removed']for r in self.post],[1119,9172,1275])
  self.assertEqual([r['result']['host_transitions']for r in self.post],[89,171,76])
 def test_catalog_completeness_and_raw_boundary(self):
  cat={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
  for offset in[0x7434,0x7630,0x765e,0x7550]:self.assertEqual(cat[f'PLI2.OVL+{offset:04X}']['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'))
  self.assertEqual(cat['PLI2.OVL+753C']['completeness'],dict(bounds='stable',control_flow='partial',contract='partial'))
  self.assertEqual(json.loads((REPORT/'archaeology-summary-PLI2.OVL.json').read_text())['raw_to_understood'],95)
  self.assertLess((REPORT/'implementation-packet.json').stat().st_size,28672)
 def test_external_and_record_oracles(self):
  expected=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for file in['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   rows=[r['result']for r in json.loads((OUT/file).read_text())['sources']];self.assertEqual([r['REL_sha256']for r in rows],expected)
   self.assertTrue(all(r['PASS1']and r['PASS2']and r['END_COMPILATION']and r['termination']=='warm_boot'for r in rows))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
