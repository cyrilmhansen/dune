#!/usr/bin/env python3
"""Independent classification, carrier and field equations over exact shadows."""
import argparse,collections,json,unittest
from pathlib import Path
from run_carrier_clear_emission_pass_59 import prove,OUT,REPORT

class CarrierClear(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  prove(IMAGES)
  cls.raw=json.loads((OUT/'rows.json').read_text());cls.nat=json.loads((OUT/'proof/natural-cases.json').read_text())['sources'];cls.hierarchy=json.loads((REPORT/'hierarchy-summary.json').read_text())['sources']
 def test_fresh_topology_and_pairs(self):
  self.assertEqual([len(r['PLI2.OVL+7B1B'])for r in self.raw.values()],[0,10,0])
  roots=self.raw['FIZZBUZ']['PLI2.OVL+7B1B']
  self.assertEqual(collections.Counter((r['entry']['before']['c'],r['entry']['before']['e'])for r in roots),{(0xb0,7):1,(0x80,7):3,(0x98,7):3,(0xb0,5):3})
  self.assertEqual(collections.Counter(r['call']['origin']['offset']for r in roots),{0x31e7:1,0x36fa:3,0x3701:3,0x420c:3})
 def test_equality_masks_and_psw_transport(self):
  for r in self.raw['FIZZBUZ']['PLI2.OVL+7B1B']:
   own={w['origin']['offset']:w for w in r['own_witnesses']};q=r['entry']['before'];second=255 if q['e']==7 else 0
   self.assertEqual(own[0x7b28]['after']['a'],0);self.assertEqual(own[0x7b31]['after']['a'],second)
   self.assertEqual([(w['address'],w['new_value'])for w in own[0x7b29]['writes']],[(q['sp']-1,0),(q['sp']-2,0x56)])
   pop=own[0x7b32]['after'];self.assertEqual((pop['b'],pop['c']),(0,0x56));self.assertEqual(pop['flags'],own[0x7b31]['after']['flags'])
   self.assertEqual(own[0x7b34]['after']['a'],0);self.assertFalse(own[0x7b35]['after']['flags']['carry']);self.assertEqual(own[0x7b36]['after']['pc'],0x9d52)
 def test_carrier_save_and_fresh_tail_arguments(self):
  for r in self.raw['FIZZBUZ']['PLI2.OVL+7B1B']:
   own={w['origin']['offset']:w for w in r['own_witnesses']};q=r['entry']['before']
   self.assertEqual([(own[s]['writes'][0]['address'],own[s]['writes'][0]['new_value'])for s in [0x7b1e,0x7b20]],[(0xae0d,q['e']),(0xae0c,q['c'])])
   self.assertEqual([own[s]['before']['c']for s in [0x7b5c,0x7b63,0x7b6a,0x7b75]],[7,q['c'],q['e'],q['c']|q['e']])
   for site,addresses in [(0x7b21,[0xae0c]),(0x7b2a,[0xae0d]),(0x7b52,[0xae0c]),(0x7b5f,[0xae0c,0xae0d]),(0x7b66,[0xae0d,0xae0e]),(0x7b6d,[0xae0d]),(0x7b73,[0xae0c])]:self.assertEqual([w['address']for w in own[site]['reads']],addresses)
   self.assertEqual(own[0x7b73]['after']['flags'],dict(sign=True,zero=False,parity=(q['c']|q['e']).bit_count()%2==0,auxiliary_carry=False,carry=False))
 def test_independent_7314_publications_and_stack_carrier(self):
  self.assertEqual([len(r['PLI2.OVL+7314'])for r in self.raw.values()],[8,33,9])
  for g in self.raw.values():
   for r in g['PLI2.OVL+7314']:
    own={w['origin']['offset']:w for w in r['own_witnesses']};q=r['entry']['before']
    writes=[(w['address'],w['new_value'])for s in [0x7317,0x7319,0x731d,0x7328,0x7336]for w in own[s]['writes']]
    self.assertEqual(writes,[(0xadbc,q['e']),(0xadbb,q['c']),(0xadaa,1),(0xadab+q['c'],1),(0xadb3+q['c'],q['e'])])
    self.assertEqual([w['new_value']for w in own[0x731f]['writes']],[0xad,0xaa]);self.assertEqual(own[0x7326]['after']['b']*256+own[0x7326]['after']['c'],0xadab)
 def test_independent_7365_routes(self):
  rs=self.raw['PICTURE']['PLI2.OVL+7365'];self.assertEqual(len(rs),16);self.assertEqual(collections.Counter(r['ret']['origin']['offset']for r in rs),{0x7385:12,0x7396:4})
  for r in rs:
   own={w['origin']['offset']:w for w in r['own_witnesses']}
   if 0x7395 in own:
    value=own[0x7392]['reads'][0]['value'];mask=255 if r['entry']['before']['e']==value else 0
    self.assertEqual(own[0x7395]['after']['a'],mask)
   else:self.assertEqual(r['ret']['before']['a'],0);self.assertEqual(r['ret']['before']['flags'],own[0x737f]['after']['flags'])
 def test_shadow_stack_and_unobserved_scope(self):
  self.assertEqual([[len(e['members'])for e in r['entries']]for r in self.nat],[[0,8,0,2],[10,33,0,36],[0,9,16,4]])
  for r in self.nat:
   for e in r['entries']:
    for c in e['members']:
     self.assertEqual(c['output']['sp'],c['input']['sp']+2);self.assertFalse(any(w[0]in[c['input']['sp'],c['input']['sp']+1]for w in c['journal']))
  s=json.loads((REPORT/'shadow-summary.json').read_text());self.assertTrue(s['all_passed']);self.assertEqual(s['natural_special_cases'],0);self.assertEqual(s['natural_B8_cases'],0)
 def test_cross_evidence_is_not_fabricated(self):
  c=json.loads((REPORT/'cross-evidence.json').read_text());self.assertEqual(c['FACTOR']['PLI2.OVL+7B1B']['pairs'],{'B0/06':1});self.assertEqual(c['FACTOR']['PLI2.OVL+7314']['calls'],12);self.assertFalse(c['OPTIMIST']['full_state_shadow'])
 def test_hierarchy_and_actual_counters(self):
  h=self.hierarchy;self.assertEqual([r['pre_guest']for r in h],[300443,569925,346935]);self.assertEqual([r['roots']for r in h],[0,10,0]);self.assertEqual([r['net_host_delta']for r in h],[0,0,0]);self.assertEqual(h[1]['absorbed'],{'PLI2.OVL+7557':10})
  live=json.loads((OUT/'proof/cumulative-hybrid-summary.json').read_text())['sources']
  self.assertEqual([r['result']['actual_guest_instructions']for r in live],[300443,569375,346935]);self.assertEqual([r['result']['host_transitions']for r in live],[102,277,90])
  self.assertEqual([r['remaining']['PLI.COM+119E']['calls']for r in h],[36,36,43]);self.assertEqual([r['remaining']['PLI2.OVL+7B1B']['calls']for r in h],[0,0,0])
  for r in h:self.assertEqual(r['saved'],r['pre_guest']-r['post_guest']);self.assertGreaterEqual(r['saved'],0)
 def test_hybrids_catalog_and_documentation(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   q=json.loads((OUT/'proof'/name).read_text());self.assertTrue(q['all_passed']);self.assertEqual([p['result']['REL_sha256']for p in q['sources']],hashes)
  catalog={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
  for key,length in [('PLI2.OVL+7B1B',94),('PLI2.OVL+7314',36),('PLI2.OVL+7365',50)]:self.assertEqual(catalog[key]['length'],length);self.assertEqual(catalog[key]['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'))
  self.assertEqual(json.loads((REPORT/'fidelity.json').read_text())['promotions'],{'RAW':180});self.assertLessEqual((REPORT/'implementation-packet.json').stat().st_size,28672)
  s=json.loads((REPORT/'semantic-extraction.json').read_text());self.assertEqual(s['historical_root'],'PLI2.OVL+7B1B');self.assertEqual(set(s),{'historical_root','semantic_inputs','semantic_outputs','shared_historical_state','historical_mechanism','candidate_modern_operation','confidence','mir_relevance'})
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=[__file__]+rest)
