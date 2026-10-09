#!/usr/bin/env python3
"""Independent carrier/address equations over natural and transactional proofs."""
import argparse, collections, json, unittest
from pathlib import Path
from run_indexed_carrier_transfer_pass_58 import prove, OUT, REPORT

class IndexedCarrier(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  prove(IMAGES)
  cls.rows=json.loads((OUT/'rows.json').read_text())
  cls.natural=json.loads((OUT/'proof/natural-cases.json').read_text())['sources']
  cls.hierarchy=json.loads((REPORT/'hierarchy-summary.json').read_text())['sources']
 def test_natural_topology_and_domains(self):
  for entry in ['PLI2.OVL+7B99','PLI2.OVL+793C']:
   self.assertEqual([len(r[entry]) for r in self.rows.values()],[0,10,0])
   pairs=collections.Counter((r['entry']['before']['c'],r['entry']['before']['e']) for r in self.rows['FIZZBUZ'][entry])
   self.assertEqual(pairs,{(7,4):4,(5,7):3,(4,7):3})
  roots=self.rows['FIZZBUZ']['PLI2.OVL+7B99']
  self.assertEqual(collections.Counter(r['call']['origin']['offset'] for r in roots),{0x3ae8:1,0x36f3:3,0x3708:3,0x4205:3})
  self.assertEqual({r['call']['origin']['offset'] for r in self.rows['FIZZBUZ']['PLI2.OVL+793C']},{0x7bae})
 def test_root_carrier_writes_and_fresh_reads(self):
  for r in self.rows['FIZZBUZ']['PLI2.OVL+7B99']:
   own={w['origin']['offset']:w for w in r['own_witnesses']};q=r['entry']['before']
   self.assertEqual([(own[s]['writes'][0]['address'],own[s]['writes'][0]['new_value']) for s in [0x7b9c,0x7b9e]],[(0xae11,q['e']),(0xae10,q['c'])])
   for s,addresses in [(0x7b9f,[0xae10,0xae11]),(0x7ba6,[0xae10,0xae11]),(0x7baa,[0xae11,0xae12])]:
    self.assertEqual([x['address'] for x in own[s]['reads']],addresses)
   child=own[0x7bae]['before'];self.assertEqual(child['c'],q['c']);self.assertEqual(child['e'],q['e'])
   self.assertEqual(child['d'],own[0x7baa]['reads'][1]['value'])
 def test_independent_transfer_address_and_value_equations(self):
  for r in self.rows['FIZZBUZ']['PLI2.OVL+793C']:
   own={w['origin']['offset']:w for w in r['own_witnesses']};q=r['entry']['before']
   for base,push,read,write in [(0xadab,0x7961,0x7969,0x796a),(0xadb3,0x7974,0x797c,0x797d)]:
    source=base+q['e'];dest=base+q['c'];p=own[push];sp=p['before']['sp']
    self.assertEqual([(w['address'],w['new_value']) for w in p['writes']],[(sp-1,source>>8),(sp-2,source&255)])
    self.assertEqual(own[read]['reads'][0]['address'],source)
    self.assertEqual([(w['address'],w['new_value']) for w in own[write]['writes']],[(dest,own[read]['reads'][0]['value'])])
 def test_field_arithmetic_and_emission_abi(self):
  for r in self.rows['FIZZBUZ']['PLI2.OVL+793C']:
   own={w['origin']['offset']:w for w in r['own_witnesses']};q=r['entry']['before']
   self.assertEqual([own[s]['before']['c'] for s in [0x7980,0x7987,0x798e,0x799e]],[0x40,q['c'],q['e'],((q['c']*8)&255)|0x40|q['e']])
   for s in [0x7994,0x7995,0x7996]:
    w=own[s];old=w['before']['a'];v=old*2&255
    self.assertEqual(w['bytes'],'87');self.assertEqual(w['after']['a'],v)
    self.assertEqual(w['after']['flags'],dict(sign=v>=128,zero=v==0,parity=v.bit_count()%2==0,auxiliary_carry=(old&15)*2>15,carry=old*2>255))
 def test_stack_and_natural_component_proofs(self):
  self.assertEqual([[len(e['members']) for e in r['entries']] for r in self.natural],[[0,0,2],[10,10,21],[0,0,1]])
  for r in self.natural:
   for entry in r['entries']:
    for c in entry['members']:
     self.assertEqual(c['output']['sp'],c['input']['sp']+2)
     self.assertFalse(any(w[0] in [c['input']['sp'],c['input']['sp']+1] for w in c['journal']))
  s=json.loads((REPORT/'shadow-summary.json').read_text());self.assertTrue(s['all_passed']);self.assertEqual(s['natural_E6_cases'],0)
 def test_actual_counters_and_exact_hierarchy(self):
  h=self.hierarchy
  self.assertEqual([r['post_guest'] for r in h],[300443,569925,346935])
  self.assertEqual([r['saved'] for r in h],[0,780,0])
  self.assertEqual([r['post_host'] for r in h],[102,277,90])
  self.assertEqual(h[1]['absorbed'],{'PLI2.OVL+7AE4':10,'PLI2.OVL+7557':10})
  self.assertEqual([r['remaining']['PLI.COM+119E']['calls'] for r in h],[36,36,43])
 def test_hybrids_and_record_goldens(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   q=json.loads((OUT/'proof'/name).read_text());self.assertTrue(q['all_passed']);self.assertEqual([r['result']['REL_sha256'] for r in q['sources']],hashes)
 def test_catalog_scope_and_documentation(self):
  catalog={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
  for key,length in [('PLI2.OVL+793C',102),('PLI2.OVL+7B99',25)]:
   self.assertEqual(catalog[key]['length'],length)
   self.assertEqual(catalog[key]['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'))
  fidelity=json.loads((REPORT/'fidelity.json').read_text());self.assertEqual(fidelity['promotions'],{'RAW':127});self.assertEqual(fidelity['oracle_queries'],0)
  self.assertLessEqual((REPORT/'implementation-packet.json').stat().st_size,28672)
  s=json.loads((REPORT/'semantic-extraction.json').read_text());self.assertEqual(s['historical_root'],'PLI2.OVL+7B99')
  self.assertEqual(set(s),{'historical_root','semantic_inputs','semantic_outputs','shared_historical_state','historical_mechanism','candidate_modern_operation','confidence','mir_relevance'})

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=[__file__]+rest)
