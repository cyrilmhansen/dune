#!/usr/bin/env python3
"""Independent gate equations, fresh channels and instruction-level discriminants."""
import argparse,collections,json,unittest
from pathlib import Path
from run_carrier_generation_pass_60 import prove,OUT,REPORT

def load(path):return json.loads(Path(path).read_text())
class CarrierGeneration(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  prove(IMAGES);cls.raw=load(OUT/'rows.json');cls.nat=load(OUT/'proof/natural-cases.json')['sources'];cls.synthetic=load(OUT/'proof/synthetic-checkpoints.json')['cases']
 def roots(self):return[r for g in self.raw.values()for r in g['PLI2.OVL+7E05']]
 def test_corrected_entries_counts_and_returns(self):
  self.assertEqual([len(g['PLI2.OVL+7E05'])for g in self.raw.values()],[2,11,1])
  for g in self.raw.values():
   self.assertFalse(g['PLI2.OVL+7DC3']);self.assertFalse(g['PLI2.OVL+7DE4'])
  self.assertEqual(collections.Counter((r['entry']['before']['c'],r['entry']['before']['e'])for r in self.roots()),{(7,1):5,(7,7):1,(7,15):1,(7,8):1,(7,3):1,(7,4):2,(7,5):1,(7,9):2})
  self.assertTrue(all(r['ret']['origin']['offset']==0x7ed5 for r in self.roots()))
 def test_mask_flags_and_psw_carrier(self):
  for r in self.roots():
   w={w['origin']['offset']:w for w in r['own_witnesses']}
   self.assertEqual(w[0x7e15]['after']['a'],1)
   self.assertEqual(w[0x7e17]['after']['a'],0);self.assertTrue(w[0x7e17]['after']['flags']['carry'])
   self.assertEqual(w[0x7e19]['after']['a'],255)
   self.assertEqual(w[0x7e19]['after']['flags'],dict(sign=True,zero=False,parity=True,auxiliary_carry=False,carry=True))
   self.assertEqual(w[0x7e1d]['reads'],[dict(address=0xadaa,value=0)])
   self.assertEqual(w[0x7e1f]['reads'],[dict(address=0x202b,value=0)])
   self.assertEqual([v['new_value']for v in w[0x7e1e]['writes']],[0,0x56])
   self.assertEqual((w[0x7e23]['after']['b'],w[0x7e23]['after']['c']),(0,0x56))
   self.assertEqual(w[0x7e23]['after']['flags'],w[0x7e1f]['after']['flags'])
   self.assertFalse(w[0x7e26]['after']['flags']['carry']);self.assertEqual(w[0x7e27]['after']['pc'],0xa0ba)
 def test_visible_saves_and_independent_rereads(self):
  for r in self.roots():
   w={w['origin']['offset']:w for w in r['own_witnesses']};C=r['entry']['before']['c'];E=r['entry']['before']['e']
   self.assertEqual([(w[s]['writes'][0]['address'],w[s]['writes'][0]['new_value'])for s in [0x7e08,0x7e0a]],[(0xae37,E),(0xae36,C)])
   for site,addresses in [(0x7e0b,[0xae36,0xae37]),(0x7e12,[0xae36]),(0x7eba,[0xae36,0xae37]),(0x7ebe,[0xae37,0xae38]),(0x7ec5,[0xae36,0xae37]),(0x7ece,[0xae37,0xae38])]:self.assertEqual([v['address']for v in w[site]['reads']],addresses)
   self.assertEqual([(w[s]['before']['c'],w[s]['before']['e'])for s in [0x7ec2,0x7ecb,0x7ed2]],[(C,E),(6,C),(E,0)])
 def test_natural_children_do_not_mutate_carriers(self):
  for r in self.roots():
   for child in r['nested_returns'].values():
    self.assertFalse(any(v['address']in[0xae36,0xae37,0xae38]for w in child['memory_witnesses']for v in w['writes']))
 def test_static_routes_independently_execute_binary(self):
  expected={'disabled','global_gate','C6','same','plus','minus','inactive_no_match','active_no_match','match0','match5','skip6','match7','plus_wrap','minus_wrap'}
  self.assertEqual(len(self.synthetic),14*14)
  self.assertEqual(set(r['route']for r in self.synthetic),expected)
  for r in self.synthetic:
   self.assertTrue(r['all_passed']);self.assertEqual(len(r['full_RAM_sha256']),64)
   pcs=[p['pc']-0x2200 for p in r['checkpoints']]
   self.assertEqual(0x7eaf in pcs,r['route']in['match0','match5','match7'])
   self.assertEqual(0x7e5c in pcs,r['route']in['plus','plus_wrap'])
   self.assertEqual(0x7e6f in pcs,r['route']in['minus','minus_wrap'])
   if r['route']=='same':self.assertIn(0x7e4c,pcs);self.assertNotIn(0x7ec2,pcs)
 def test_search_order_and_index6_exclusion(self):
  for r in self.synthetic:
   index=[p['index']for p in r['checkpoints']if p['pc']==0xa07d]
   n={'match0':1,'match5':6,'match7':8,'skip6':9,'inactive_no_match':9,'active_no_match':9}.get(r['route'],0)
   self.assertEqual(index,list(range(n)))
   if r['route']=='skip6':
    candidates=[p['index']for p in r['checkpoints']if p['pc']==0xa0a3]
    self.assertNotIn(6,candidates)
 def test_static_helper_call_return_ancestry(self):
  ps=load(OUT/'proof/synthetic-helper-pairs.json');self.assertEqual({p['coordinate']for p in ps},{'PLI2.OVL+7DC3','PLI2.OVL+7DE4'})
  for p in ps:
   self.assertIn('STATIC UNOBSERVED',p['relation']);call=p['call'];ret=p['ret']
   self.assertEqual(call['sp_after'],ret['sp_before']);self.assertEqual(call['pc']+3,ret['pc_after'])
   self.assertEqual({v['address']:v['new_value']for v in call['writes']},{v['address']:v['value']for v in ret['reads']})
 def test_full_root_stack_and_child_shadows(self):
  self.assertEqual([len(r['entries'][0]['members'])for r in self.nat],[2,11,1])
  for source in self.nat:
   for e in source['entries']:
    for r in e['members']:
     self.assertEqual(r['output']['sp'],r['input']['sp']+2)
     self.assertFalse(any(w[0]in[r['input']['sp'],r['input']['sp']+1]for w in r['journal']))
  self.assertEqual([r['serializer_shadows']for r in load(OUT/'proof/component-shadows.json')['sources']],[4,22,2])
 def test_actual_leverage_and_remaining_map(self):
  live=load(OUT/'proof/cumulative-hybrid-summary.json')['sources'];h=load(REPORT/'hierarchy-summary.json')['sources']
  self.assertEqual([r['pre_guest_instructions']for r in live],[300443,569375,346935])
  self.assertEqual([r['result']['actual_guest_instructions']for r in live],[300335,568781,346881]);self.assertEqual([r['result']['host_transitions']for r in live],[98,255,88])
  for r,n in zip(h,[2,11,1]):
   self.assertEqual(r['absorbed'],{'PLI2.OVL+7AE4':n,'PLI2.OVL+75CE':n,'PLI2.OVL+75A7':n});self.assertEqual(r['net_host_delta'],-2*n)
   self.assertEqual(r['remaining']['PLI2.OVL+7AE4']['calls'],0)
  self.assertEqual([r['remaining']['PLI.COM+119E']['calls']for r in h],[36,36,43])
 def test_hybrids_and_evidence_classification(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   v=load(OUT/'proof'/name);self.assertTrue(v['all_passed']);self.assertEqual([r['result']['REL_sha256']for r in v['sources']],hashes)
  f=load(REPORT/'fidelity.json');self.assertEqual(f['promotions'],{'RAW':275});self.assertEqual((f['OBSERVED_natural_bytes'],f['DEDUCED_STATIC_UNOBSERVED_bytes']),(65,210))
  cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']}
  for key,n in [('PLI2.OVL+7E05',209),('PLI2.OVL+7DC3',33),('PLI2.OVL+7DE4',33)]:
   p=cat[key];self.assertEqual(p['length'],n);self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'))
   if key!='PLI2.OVL+7E05':self.assertTrue(all(n==0 for n in p['observed_paths']['invocations_by_run'].values()))
  self.assertLessEqual((REPORT/'implementation-packet.json').stat().st_size,28672)
  self.assertEqual(set(load(REPORT/'semantic-extraction.json')),{'historical_root','semantic_inputs','semantic_outputs','shared_historical_state','historical_mechanism','candidate_modern_operation','confidence','mir_relevance'})
  self.assertEqual(load(REPORT/'cross-evidence.json')['FACTOR']['PLI2.OVL+7E05']['calls'],2)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=[__file__]+rest)
