#!/usr/bin/env python3
"""Exhaustive Pass70 discovery proof: no native arm/full certificate claimed."""
import argparse,os,unittest
from run_indexed_policy_pass_70 import OUT,REPORT,SOURCES,GOLDENS,load,discovery
from check_selector02_pass_40 import coord
class IndexedPolicyDiscovery(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  discovery(IMAGES)
  cls.roots=load(OUT/'roots.json');cls.inventory=load(OUT/'inventory.json')
 def test_five_source_roots_and_exact_goldens(self):
  self.assertEqual([self.inventory[s]['roots']for s in SOURCES],[0,1,0,0,1])
  for s,sha in zip(SOURCES,GOLDENS):self.assertEqual(self.inventory[s]['REL_sha256'],sha)
  for r in self.roots:self.assertEqual(self.inventory[r['source']]['callsite_counts']['PLI2.OVL+4257->PLI2.OVL+397F'],1)
 def test_hardware_entry_and_final_RET_word(self):
  for r in self.roots:
   e=r['entry'];s=e['entry']['sp'];lo=e['low_writer'];hi=e['high_writer']
   self.assertEqual(lo['instruction'],hi['instruction']);w=lo['instruction'];self.assertEqual(w['bytes'],'CD7F5B');self.assertEqual(w['before']['pc'],0x6457);self.assertEqual(w['after'],e['entry']);self.assertEqual(lo['value'],0x5a);self.assertEqual(hi['value'],0x64)
   self.assertEqual(w['before']['sp'],s+2);self.assertEqual(e['continuation'],0x645a)
   ret=r['ret'];self.assertEqual(ret['origin']['offset'],0x3b6f);self.assertEqual(ret['reads'],[dict(address=s,value=0x5a),dict(address=s+1,value=0x64)]);self.assertEqual(ret['after']['sp'],s+2);self.assertEqual(ret['after']['pc'],0x645a)
   self.assertNotIn(str(s),r['stack_last_writers']);self.assertNotIn(str(s+1),r['stack_last_writers'])
 def test_natural_frontend_freshness_and_table_byte_order(self):
  for r in self.roots:
   w={q['origin']['offset']:q for q in r['own']};s=r['entry']['entry']['sp'];self.assertEqual(r['selector'],15)
   self.assertEqual([v['address']for v in w[0x397f]['reads']],[0xad0a,0xad0b]);self.assertEqual(w[0x3983]['after']['b'],0)
   self.assertEqual(w[0x3988]['after']['h']*256+w[0x3988]['after']['l'],0x5d3c+15)
   self.assertEqual(w[0x398a]['reads'],[dict(address=0x5d5a,value=0xcc)]);self.assertEqual(w[0x398c]['reads'],[dict(address=0x5d5b,value=0x5c)])
   self.assertEqual(w[0x398e]['after']['pc'],0x5ccc);self.assertEqual(w[0x398e]['before']['sp'],s);self.assertEqual(w[0x398e]['after']['sp'],s)
  self.assertNotEqual(self.roots[0]['own'][0]['reads'][1]['value'],self.roots[1]['own'][0]['reads'][1]['value'])
 def test_natural_child_graph_and_substantive_gateway(self):
  for r in self.roots:
   self.assertEqual([c['target']for c in r['children']],['PLI2.OVL+'+s for s in ['373C','3790','8386','382E','7B99']])
   self.assertEqual(r['gateway_calls'][0]['callsite'],'PLI2.OVL+3740')
   self.assertEqual([c['callsite']for c in r['children']],['PLI2.OVL+'+s for s in ['3ACC','3AD6','3ADA','3AE1','3AE8']])
 def test_independent_mapped_value_provenance(self):
  self.assertEqual([r['children'][1]['call']['after']['c']for r in self.roots],[11,91])
  self.assertEqual([r['children'][1]['ret']['after']['l']for r in self.roots],[15,6])
  for r in self.roots:
   w={q['origin']['offset']:q for q in r['own']};self.assertEqual([v['address']for v in w[0x3ad2]['reads']],[0xad0d,0xad0e]);self.assertEqual(w[0x3ad5]['after']['c'],w[0x3ad2]['reads'][0]['value']);q=r['children'][2];before=q['call']['after'];after=q['ret']['after'];old=before['h']*256+before['l'];self.assertEqual(after['h']*256+after['l'],(-old)&65535)
 def test_caller_argument_consumption_and_relocated_return(self):
  for r in self.roots:
   s=r['entry']['entry']['sp'];w={q['origin']['offset']:q for q in r['own']};self.assertEqual(w[0x3ad1]['after']['sp'],s-2)
   push=w[0x3ad1];self.assertEqual(push['writes'][1]['address'],s-2);self.assertEqual(push['writes'][1]['new_value'],1)
   child=r['children'][3];self.assertEqual(child['call']['after']['sp'],s-4);self.assertEqual(child['ret']['before']['sp'],s-2);self.assertEqual(child['ret']['after']['sp'],s);self.assertEqual(child['ret']['reads'],[dict(address=s-2,value=0xe4),dict(address=s-1,value=0x5c)])
   for c in r['children']:
    self.assertEqual(c['ret']['after']['pc'],c['call']['pc']+3)
    if c['target']!='PLI2.OVL+382E':self.assertEqual(c['ret']['after']['sp'],c['call']['before']['sp'])
 def test_common_tail_fresh_selector_vector_and_flags(self):
  for r in self.roots:
   w={q['origin']['offset']:q for q in r['own']};self.assertEqual([v['address']for v in w[0x3b62]['reads']],[0xad0a,0xad0b]);index=w[0x3b62]['reads'][0]['value'];self.assertEqual(w[0x3b6b]['reads'][0]['address'],0x579b+index);value=w[0x3b6b]['reads'][0]['value'];self.assertEqual(w[0x3b6c]['writes'][0]['address'],0xad06);self.assertEqual(w[0x3b6c]['writes'][0]['new_value'],value)
   final=r['ret']['after']['flags'];child=r['children'][-1]['ret']['after']['flags'];self.assertEqual({k:v for k,v in final.items()if k!='carry'},{k:v for k,v in child.items()if k!='carry'});self.assertFalse(final['carry'])
 def test_static_extent_table_not_instructions(self):
  cfg=load(REPORT/'cfg.json');offsets={q['offset']for q in cfg};law=load(REPORT/'dispatch-law.json');self.assertEqual(law['table_entries'],19);self.assertEqual(sum(len(bytes.fromhex(q['bytes']))for q in cfg),459)
  self.assertFalse(any(0x3b3c<=o<0x3b62 for o in offsets));self.assertEqual([q['offset']for q in cfg if q['decoded']=='RET'],[0x3b6f]);self.assertTrue(all(int(t,16)in offsets for t in law['targets']))
  for source in SOURCES:self.assertTrue(set(load(REPORT/'natural-inventory.json')[source]['overlapping_hardware_entries'])<= {'PLI2.OVL+397F'})
 def test_synthetic_scope_frontend_and_tail(self):
  q=load(OUT/'frontend-proof.json');self.assertTrue(q['all_passed']);self.assertEqual(len(q['cases']),240);self.assertEqual(q['tail_cases'],18)
  for c in q['cases']:self.assertTrue(c['RAM_unchanged']);self.assertEqual(c['supported_table_domain'],c['selector']<19);self.assertEqual(len(c['steps']),11)
 def test_canonical_components_full_state_independently_shadow(self):
  q=load(OUT/'component-shadows.json');self.assertTrue(q['all_passed']);self.assertEqual(len(q['components']),4)
  for c in q['components']:self.assertEqual(c['count'],1);self.assertTrue(c['full_registers_flags_RAM_ordered_writes_stack_services_compared'])
 def test_discovery_scope_no_false_promotion_or_certificate(self):
  q=load(REPORT/'implementation-packet.json');self.assertFalse(q['runtime_changes']);self.assertEqual(q['oracle_queries'],0);self.assertEqual(q['current_full'],'Pass67');self.assertTrue(all(v==0 for v in q['promotions'].values()))
  self.assertFalse(load(REPORT/'historical-full-selection-proof.json')['executed'])
if __name__=='__main__':
 p=argparse.ArgumentParser(add_help=False);p.add_argument('--images',default='/home/john/pli/cpm/pli80/DISK1');a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=[__file__]+rest)
