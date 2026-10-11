#!/usr/bin/env python3
"""Fresh five-source component/CPU proofs; scoped predicate and software ABI."""
import argparse, collections, copy, json, os, subprocess, unittest
from pathlib import Path
import run_k23_handler_pass_72 as driver
from software_gateway_pass_72 import prove_gateway

class K23(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if not os.environ.get('RUNES_PASS72_REUSE_PROOF'): driver.prove(str(IMAGES))
  cls.hs=driver.load(driver.OUT/'handlers.json');cls.ps=driver.load(driver.OUT/'predicates.json')
 def test_five_source_independent_inventory(self):
  self.assertEqual([sum(h['source']==s for h in self.hs)for s in driver.SOURCES],[1,13,1,4,9])
  self.assertEqual([sum(p['source']==s for p in self.ps)for s in driver.SOURCES],[3,27,1,6,13])
  self.assertFalse(any(h['nested_gateways']for h in self.hs))
 def test_actual_software_stack_writer_and_consumer(self):
  for h in self.hs:
   e=h['entry'];r=h['ret'];slot=e['state']['sp']
   self.assertEqual(e['previous']['offset'],0x20b3);self.assertEqual(e['previous']['bytes'],'E9')
   self.assertEqual([w['offset']for w in h['stack_last_writers']],[0x20af]*2)
   self.assertEqual([w['value']for w in h['stack_last_writers']],[0xb4,0x42])
   self.assertEqual(r['offset'],0x3ef5);self.assertEqual(r['after']['pc'],0x42b4)
   self.assertEqual(r['before']['sp'],slot);self.assertEqual(r['after']['sp'],slot+2)
   self.assertEqual([(a['address'],a['value'])for a in driver.accesses(r,'read')],[(slot,0xb4),(slot+1,0x42)])
 def test_handler_actual_result_gate_and_fresh_reads(self):
  self.assertEqual(collections.Counter(h['entry']['AD_state'][0]for h in self.hs),{0:11,1:17})
  for h in self.hs:
   own=h['own'];children=h['children'];targets=[c['call']['target_origin']['offset']for c in children]
   self.assertIn(0x3660,targets)
   for q in own:
    if q['decoded']=='RAR':
     b,a=q['before'],q['after'];self.assertEqual(a['CY'],bool(b['a']&1))
     self.assertEqual(a['a'],(b['a']>>1)|(int(b['CY'])<<7))
     for flag in ['S','Z','AC','P']:self.assertEqual(a[flag],b[flag])
   if h['entry']['AD_state'][0]==0:
    self.assertEqual(targets,[0x047d,0x3660,0x04ff,0x04ff,0x7e05])
    mapped=[c for c in children if c['call']['target_origin']['offset']==0x04ff]
    last=children[-1]['call']['before'];self.assertEqual(last['e'],mapped[-1]['ret']['after']['a']);self.assertEqual(last['c'],7)
   else:
    self.assertEqual(targets,[0x3660,0x7bcc])
    writes=[a for q in own for a in driver.accesses(q,'write')if a['address']==0xad58]
    self.assertEqual(len(writes),1)
    fresh=[a for q in own for a in driver.accesses(q,'read')if a['address']==0xad58]
    self.assertEqual([a['value']for a in fresh],[writes[0]['value']])
 def test_descriptor_state_defined_scope_and_actual_returns(self):
  self.assertEqual(collections.Counter(tuple(p['tokens'])for p in self.ps),{(5,):28,(0x69,):11,(0xfb,):11})
  self.assertEqual(collections.Counter(p['ret']['after']['a']for p in self.ps),{0:22,1:28})
  for p in self.ps:
   ptr=p['event']['descriptor_pointer'];tokens=p['tokens'];self.assertFalse(p['cached_reuse'])
   self.assertEqual(ptr,{5:0x57c7,0x69:0x57c9,0xfb:0x3bf3}[tokens[0]])
   targets=[c['call']['target_origin']['offset']for c in p['direct_children']]
   self.assertEqual(targets,[0x0992]if tokens==[0xfb]else[0x047d])
   if tokens==[0xfb]:
    writes=[w for w in p['writes']if w['address']==0xad15]
    self.assertEqual([w['value']for w in writes],[255,1])
   else:
    child=p['direct_children'][0];expected=(p['event']['state']['c']-1)&255
    self.assertEqual(child['call']['before']['c'],expected)
    self.assertEqual(p['ret']['after']['a'],int(child['ret']['after']['a']==tokens[0]))
 def test_all_components_and_independent_cpu_discriminants(self):
  q=driver.load(driver.OUT/'predicate-component-shadows.json');self.assertTrue(q['all_passed'])
  self.assertEqual(sum(c['count']for c in q['components']if c['offset']==0x1dff),50)
  self.assertTrue(all(c['full_registers_flags_RAM_ordered_writes_stack_services_compared']for c in q['components']))
  s=driver.load(driver.OUT/'proof/synthetic-checkpoints.json')['cases'];self.assertEqual(len(s),330)
  self.assertEqual(len(q['synthetic_cases']),300);self.assertTrue(all(c['all_passed']for c in s+q['synthetic_cases']))
  for name in ['proof','cross-FACTOR','cross-OPTIMIST']:
   self.assertTrue(driver.load(driver.OUT/name/'component-shadows.json')['all_passed'])
 def test_hybrid_goldens_and_measured_hierarchy(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for name in ['single','cumulative']:
   q=driver.load(driver.OUT/'proof'/f'{name}-hybrid-summary.json');self.assertTrue(q['all_passed'])
   self.assertEqual([r['result']['REL_sha256']for r in q['sources']],hashes)
  q=driver.load(driver.OUT/'proof/cumulative-hybrid-summary.json')['sources']
  self.assertEqual([r['result']['actual_guest_instructions']for r in q],[294362,557928,339572])
  self.assertEqual([r['result']['host_transitions']for r in q],[92,215,78])
 def test_partial_catalog_and_no_bulk_promotion(self):
  cat={p['id']:p for p in driver.load('research/annotated-assembly/procedures.json')['procedures']}
  for o,e in driver.BOUNDS.items():self.assertEqual(cat[f'PLI2.OVL+{o:04X}']['length'],e-o)
  for o in [0x1dff,0x3e36]:self.assertEqual(cat[f'PLI2.OVL+{o:04X}']['completeness']['contract'],'partial')
  baseline=json.loads(subprocess.check_output(['git','show',driver.BASE+':research/annotated-assembly/procedures.json']))
  old={p['id']:p for p in baseline['procedures']};self.assertEqual(cat['PLI2.OVL+047D'],old['PLI2.OVL+047D'])
  current=driver.load('research/annotated-assembly/manifest.json');oldmanifest=json.loads(subprocess.check_output(['git','show',driver.BASE+':research/annotated-assembly/manifest.json']))
  def statuses(m):return {a:s['status']for i in m['images']if i['name']=='PLI2.OVL'for s in i['sections']for a in range(s['start_offset'],s['end_offset'])}
  before,after=statuses(oldmanifest),statuses(current)
  allowed={a for q in driver.load(driver.REPORT/'cfg.json')if q['evidence']!='STATIC UNOBSERVED unsupported'for a in range(q['offset'],q['offset']+len(bytes.fromhex(q['bytes'])))}
  self.assertTrue({a for a in before if before[a]!='UNDERSTOOD'and after[a]=='UNDERSTOOD'}<=allowed)
 def test_exact_software_witness_and_corruption(self):
  proof=driver.load(driver.OUT/'software-return-sample.json');seed=dict(id='PLI2.OVL+3E36',image='PLI2.OVL',start_offset=0x3e36,end_offset=0x3ef6,software_return_sample=proof)
  images={'PLI2.OVL':dict(runtime_base=0x2200)};originals={'PLI2.OVL':(IMAGES/'PLI2.OVL').read_bytes()}
  self.assertEqual(prove_gateway(seed,images,originals)['continuation'],0x42b4)
  for field in ['continuation','original_slot']:
   bad=copy.deepcopy(seed);bad['software_return_sample'][field]^=1
   with self.assertRaises(ValueError):prove_gateway(bad,images,originals)
 def test_historical_assertion_preserved_at_its_epoch(self):
  from test_pending_generation_pass_57 import Pending
  Pending('test_catalog_scope_and_packet').test_catalog_scope_and_packet()
 def test_full_selection_pending_and_packet(self):
  q=driver.load(driver.OUT/'historical-full-selection.json');cert=driver.load('research/host-compiler/pass-67/validation-full-initial.json')
  self.assertEqual(len(q['selected_categories']),103);self.assertTrue(set(cert['selected_categories'])<=set(q['selected_categories']))
  handoff=driver.load(driver.REPORT/'full-checkpoint-handoff.json');self.assertEqual(handoff['status'],'pending_external_execution');self.assertEqual(handoff['last_certified_full'],'Pass67')
  self.assertLess((driver.REPORT/'implementation-packet.json').stat().st_size,28672)
  self.assertEqual(set(driver.load(driver.REPORT/'semantic-extraction.json')),{'historical_root','semantic_inputs','semantic_outputs','shared_historical_state','historical_mechanism','candidate_modern_operation','confidence','mir_relevance'})
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
