#!/usr/bin/env python3
"""Instruction-owned stack/predicate proofs and independent native/CPU shadows."""
import argparse,json,os,unittest
from pathlib import Path
from run_predicate_generation_pass_68 import OUT,REPORT,BOUNDS,prove,discovery
from check_selector02_pass_40 import children_any

def load(p):return json.loads(Path(p).read_text())
class PredicateGeneration(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if os.environ.get('RUNES_PASS68_REUSE_PROOF')!='1':prove(IMAGES)
  cls.rows=load(OUT/'rows.json');cls.paths=load(REPORT/'natural-paths.json')
  for g in cls.rows.values():
   for rs in g.values():
    for r in rs:r['nested_returns']={int(k):v for k,v in r['nested_returns'].items()}
 def roots(self):return [r for g in self.rows.values()for r in g['PLI2.OVL+3D10']]
 def test_natural_entry_extent_and_cross_sources(self):
  self.assertEqual([len(self.rows[s]['PLI2.OVL+3D10'])for s in ['MINIMAL','FIZZBUZ','PICTURE','FACTOR','OPTIMIST']],[0,1,1,0,1])
  for r in self.roots():
   self.assertEqual(r['call']['origin']['offset'],0x3e0d);self.assertEqual(r['call']['bytes'],'CD105F');self.assertEqual(r['ret']['origin']['offset'],0x3de3)
   self.assertEqual(r['ret']['after']['sp'],r['entry']['sp_before']+2)
 def test_every_actual_direct_child_and_register_result(self):
  for r in self.roots():
   cs=children_any(r);self.assertEqual([q['target']for q in cs],['PLI2.OVL+3BFB','PLI2.OVL+3660','PLI2.OVL+3790','PLI2.OVL+3BFB','PLI2.OVL+8072','PLI2.OVL+7C22'])
   self.assertEqual([q['output']['a']for q in cs[:2]],[255,0]);self.assertEqual(cs[3]['output']['a'],255)
   self.assertEqual(cs[4]['entry']['c'],4);self.assertEqual([cs[4]['entry'][k]for k in ['e','d']],[cs[2]['output'][k]for k in ['l','h']])
 def test_all_hardware_continuations_and_last_writers(self):
  for g in self.rows.values():
   for rs in g.values():
    for r in rs:
     for c in children_any(r):
      w=next(w for w in r['own_witnesses']if w['step_index']==c['call_step']);ret=r['nested_returns'][c['call_step']]['ret'];sp=w['sp_after'];pc=w['pc']+3
      self.assertEqual([(q['address'],q['new_value'])for q in w['writes']],[(sp+1,pc>>8),(sp,pc&255)]);self.assertEqual(ret['after']['pc'],pc);self.assertEqual(ret['after']['sp'],sp+2)
 def test_stack_is_mutated_storage_not_HL_restore(self):
  for rs in load(REPORT/'stack-proof.json').values():
   for r in rs:
    s=r['entry_SP'];push=r['PUSH_H'];self.assertEqual(push['sp_before'],s-1);self.assertEqual(push['sp_after'],s-3)
    self.assertEqual([q['address']for q in push['writes']],[s-2,s-3]);self.assertEqual([q['address']for q in r['POP_H']['reads']],[s-2,s-1]);self.assertEqual(r['POP_H']['after']['sp'],s)
    self.assertEqual([w['writes'][0]['address']for w in r['local_stores']],[s-2,s-1]);self.assertEqual(r['last_writers'][str(s-2)]['writer'],'PLI2.OVL+3D7B');self.assertEqual(r['last_writers'][str(s-1)]['writer'],'PLI2.OVL+3D7D')
 def test_actual_RAR_predicates_and_unsupported_gateway(self):
  for r in self.roots():
   w={q['origin']['offset']:q for q in r['own_witnesses']}
   for o in [0x3d15,0x3d23,0x3d81]:
    a=w[o]['before'];b=w[o]['after'];self.assertEqual(b['a'],(a['a']>>1)|(int(a['flags']['carry'])<<7));self.assertEqual(b['flags'],dict(a['flags'],carry=bool(a['a']&1)))
   self.assertTrue(w[0x3d16]['control']['taken']);self.assertTrue(w[0x3d24]['control']['taken']);self.assertFalse(w[0x3d82]['control']['taken']);self.assertNotIn(0x3d1d,w)
 def test_local_word_fresh_reads_before_8072(self):
  for r in self.roots():
   w={q['origin']['offset']:q for q in r['own_witnesses']};s=r['entry']['sp_before']
   self.assertEqual(w[0x3d89]['reads'],[dict(address=s-2,value=w[0x3d7b]['writes'][0]['new_value'])]);self.assertEqual(w[0x3d8b]['reads'],[dict(address=s-1,value=w[0x3d7d]['writes'][0]['new_value'])]);self.assertEqual([q['address']for q in w[0x3d91]['reads']],[0xad0c,0xad0d])
 def test_mapped_predicates_derive_from_actual_fresh_tables(self):
  for g in self.rows.values():
   for key,table in [('PLI2.OVL+047D',0xa609),('PLI2.OVL+059E',0xa9e7)]:
    for r in g[key]:
     rs=[q for w in r['own_witnesses']for q in w['reads']];selector=r['entry']['before']['c'];j=next(q['value']for q in rs if q['address']==0xaab0+selector);value=next(q['value']for q in rs if q['address']==table+j)
     self.assertEqual(r['ret']['after']['a'],value);self.assertEqual(r['ret']['after']['c'],j);self.assertEqual(r['ret']['after']['b'],0)
 def test_scan_state_driven_bounds_and_fresh_rereads(self):
  for g in self.rows.values():
   for r in g['PLI2.OVL+7897']:
    increments=[w for w in r['own_witnesses']if w['origin']['offset']==0x78e4]
    self.assertEqual([w['reads'][0]['value']for w in increments],list(range(8)));self.assertEqual([w['writes'][0]['new_value']for w in increments],list(range(1,9)));self.assertEqual(r['ret']['origin']['offset'],0x78e8)
 def test_structure_sum_and_type_emission_provenance(self):
  for g in self.rows.values():
   for r in g['PLI2.OVL+77CC']:
    w={q['origin']['offset']:q for q in r['own_witnesses']};ptr=w[0x77d2]['after']['h']*256+w[0x77d2]['after']['l'];self.assertEqual(w[0x77da]['reads'][0]['address'],ptr+2);self.assertEqual(w[0x77e5]['reads'][0]['address'],ptr+3)
    self.assertEqual([q['address']for q in w[0x77ec]['reads']],[0xac9f,0xaca0]);self.assertEqual([c['target']for c in children_any(r)],['PLI2.OVL+8342','PLI2.OVL+765E']);self.assertEqual([(q['address'],q['new_value'])for q in w[0x7858]['writes']],[(0xadef,0),(0xadf0,0)])
 def test_CPU_synthetic_routes_and_full_state_journals(self):
  cases=[q for q in load(OUT/'proof/synthetic-checkpoints.json')['cases']if q['route'].startswith('3D10_')];self.assertEqual(len(cases),48);self.assertTrue(all(q['all_passed']for q in cases));labels={q['route']for q in cases}
  for gate in [0,1]:
   for value in [0,1,7,127]:
    for carry in ['true','false']:self.assertIn(f'3D10_gate{gate}_value{value}_kind76_CY{carry}',labels)
 def test_independent_natural_component_and_root_shadows(self):
  primary=load(OUT/'proof/natural-cases.json')['sources'];self.assertEqual([len(next(e for e in s['entries']if e['offset']==0x3d10)['members'])for s in primary],[0,1,1])
  cross=load(OUT/'proof/OPTIMIST-natural-cases.json')['sources'][0];self.assertEqual(len(next(e for e in cross['entries']if e['offset']==0x3d10)['members']),1)
  self.assertTrue(load(OUT/'proof/component-shadows.json')['all_passed'])
 def test_hybrids_exact_goldens_and_actual_economics(self):
  post=load(OUT/'proof/cumulative-hybrid-summary.json')['sources'];self.assertEqual([s['pre_guest_instructions']for s in post],[294445,560647,340310]);self.assertEqual([sum(s['pre_transition_vector'])for s in post],[92,223,81]);self.assertLess(post[1]['result']['host_transitions'],223);self.assertTrue(load(OUT/'proof/single-hybrid-summary.json')['all_passed'])
 def test_knowledge_scope_and_FULL_epoch_preservation(self):
  cfg=load(REPORT/'cfg.json');by={w['offset']:w for w in cfg if w['owner']=='PLI2.OVL+3D10'};self.assertEqual(by[0x3d1d]['evidence'],'STATIC UNOBSERVED unsupported');self.assertNotIn(0x3de4,by)
  policy=load('research/host-compiler/validation-policy.json');self.assertEqual(policy['current_full_epoch']['name'],'Pass67')
if __name__=='__main__':
 p=argparse.ArgumentParser(add_help=False);p.add_argument('--images',default='/home/john/pli/cpm/pli80/DISK1');a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=[__file__]+rest)
