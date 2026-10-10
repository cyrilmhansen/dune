#!/usr/bin/env python3
"""Independent publication, capture/reread and hierarchy invariants."""
import argparse,collections,json,unittest
from pathlib import Path
from run_73d0_parent_family_pass_61 import prove,OUT,REPORT

def load(p):return json.loads(Path(p).read_text())
def own(r):return{w['origin']['offset']:w for w in r['own_witnesses']}
def written(w):return[(v['address'],v['new_value'])for v in w['writes']]
def paired(w):return sum(v['value']<<(8*i)for i,v in enumerate(w['reads']))
class TrueParents(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  prove(IMAGES);cls.raw=load(OUT/'rows.json');cls.nat=load(OUT/'proof/natural-cases.json')['sources']
 def rows(self,k):return[r for g in self.raw.values()for r in g['PLI2.OVL+'+k]]
 def test_actual_entries_counts_bounds_and_no_callsite_roots(self):
  counts={'742A':[3,14,3],'8258':[1,11,1],'82B5':[1,1,1],'7423':[5,26,5],'79A2':[1,1,1]}
  cfg=load(OUT/'cfg.json');ends={'742A':0x7434,'8258':0x829c,'82B5':0x82dd,'7423':0x742a,'79A2':0x79ae}
  for k,ns in counts.items():
   self.assertEqual([len(g['PLI2.OVL+'+k])for g in self.raw.values()],ns)
   self.assertEqual(max(o+len(bytes.fromhex(b))for o,b,_ in cfg['PLI2.OVL+'+k]),ends[k])
   for r in self.rows(k):self.assertEqual(r['entry']['origin']['offset'],int(k,16));self.assertEqual(r['ret']['origin']['offset'],ends[k]-1)
  cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']}
  self.assertNotIn('PLI2.OVL+825E',cat);self.assertNotIn('PLI2.OVL+82BA',cat)
 def test_literal_publication_flags_and_all_nonHL_channels(self):
  for r in self.rows('7423'):
   w=own(r);self.assertEqual(written(w[0x7426]),[(0xada6,255),(0xada7,255)])
   before=r['entry']['before'];after=r['ret']['after']
   self.assertEqual((after['h'],after['l']),(255,255))
   for k in ['a','b','c','d','e','flags']:self.assertEqual(before[k],after[k])
 def test_three_zero_publications_preserve_flags(self):
  for r in self.rows('79A2'):
   w=own(r);self.assertEqual([written(w[s])for s in [0x79a5,0x79a8,0x79ab]],[[(0xae04,0)],[(0xae05,0)],[(0xae06,0)]])
   after=r['ret']['after'];self.assertEqual((after['h'],after['l']),(0xae,6))
   for k in ['a','b','c','d','e','flags']:self.assertEqual(r['entry']['before'][k],after[k])
 def test_742A_fresh_position_and_child_flags(self):
  for r in self.rows('742A'):
   w=own(r);self.assertEqual([v['address']for v in w[0x7430]['reads']],[0x1c2c,0x1c2d]);after=r['ret']['after']
   self.assertEqual(after['h']*256+after['l'],paired(w[0x7430]))
   child=r['nested_returns'][str(w[0x742a]['step_index'])]['ret']['after'];self.assertEqual(after['flags'],child['flags'])
 def test_8258_save_capture_independent_reads_and_increment(self):
  for r in self.rows('8258'):
   w=own(r);entry=r['entry']['before'];self.assertEqual(written(w[0x825b]),[(0xae67,entry['b'])]);self.assertEqual(written(w[0x825d]),[(0xae66,entry['c'])])
   value=paired(w[0x8261]);self.assertEqual(written(w[0x8264]),[(0xae68,value&255),(0xae69,value>>8)])
   self.assertEqual(paired(w[0x8267]),entry['b']*256+entry['c'])
   c=w[0x826d]['before'];self.assertEqual(c['b']*256+c['c'],(entry['b']*256+entry['c']+1)&65535)
   for site in [0x8288,0x8290]:
    self.assertEqual([v['address']for v in w[site]['reads']],[0xae68,0xae69]);self.assertEqual(paired(w[site]),value)
   for site in [0x828d,0x8295]:c=w[site]['before'];self.assertEqual(c['b']*256+c['c'],value)
   self.assertEqual(w[0x8270]['reads'],[dict(address=0x201d,value=0)]);self.assertFalse(w[0x8273]['after']['flags']['carry']);self.assertEqual(w[0x8274]['after']['pc'],0xa488)
 def test_8258_child_publication_and_saved_channels(self):
  for r in self.rows('8258'):
   w=own(r);snapshot=paired(w[0x8261]);children=r['nested_returns'];last=children[str(w[0x8295]['step_index'])]
   writes=[v for q in last['memory_witnesses']for v in q['writes']if v['address']in[0x1c2c,0x1c2d]]
   self.assertEqual([(v['address'],v['new_value'])for v in writes],[(0x1c2c,snapshot&255),(0x1c2d,snapshot>>8)])
   for child in children.values():self.assertFalse(any(v['address']in range(0xae66,0xae6a)for q in child['memory_witnesses']for v in q['writes']))
 def test_82B5_exact_reset_and_output_arguments(self):
  for r in self.rows('82B5'):
   w=own(r);self.assertEqual(written(w[0x82b8]),[(0xadaa,1)]);self.assertEqual(written(w[0x82c0]),[(0xada8,0),(0xada9,0)])
   self.assertEqual((w[0x82c6]['before']['b'],w[0x82c6]['before']['c']),(0,0))
   self.assertEqual([written(w[s])for s in [0x82cf,0x82d2,0x82d7]],[[(0xadc9,0)],[(0xadca,0)],[(0xae6a,0)]])
   self.assertEqual((r['ret']['after']['h'],r['ret']['after']['l']),(0xae,6))
 def test_hardware_stack_and_complete_child_sequences(self):
  expected={'742A':[0x73d0,0x7423],'8258':[0x73d0,0x7434,0x7630,0x7434,0x7423],'82B5':[0x73d0,0x7434,0x7423,0x79a2]}
  for k,targets in expected.items():
   for r in self.rows(k):
    sp=r['entry']['before']['sp'];calls=[w for w in r['own_witnesses']if w['control']['kind']=='call']
    self.assertEqual([w['target_origin']['offset']for w in calls],targets)
    for w in calls:
     resume=w['before']['pc']+3;self.assertEqual(written(w),[(sp-1,resume>>8),(sp-2,resume&255)])
     ret=r['nested_returns'][str(w['step_index'])]['ret'];self.assertEqual(ret['after']['sp'],sp);self.assertEqual(ret['after']['pc'],resume)
    self.assertEqual([v['address']for v in r['ret']['reads']],[sp,sp+1]);self.assertEqual(r['ret']['after']['sp'],sp+2);self.assertEqual(r['ret']['after']['pc'],r['call']['call_return_address'])
 def test_targeted_wrap_and_distinct_position_cpu_discriminants(self):
  synth=[v for v in load(OUT/'proof/synthetic-checkpoints.json')['cases']if v['route'].startswith('8258_')]
  self.assertEqual(len(synth),26);self.assertEqual(collections.Counter(v['route']for v in synth),{'8258_input_wrap':13,'8258_distinct_word_position':13});self.assertTrue(all(v['all_passed']for v in synth))
 def test_hierarchy_actual_counters_and_remaining(self):
  hs=load(REPORT/'hierarchy-summary.json')['sources'];live=load(OUT/'proof/cumulative-hybrid-summary.json')['sources']
  self.assertEqual([v['pre_guest_instructions']for v in live],[300335,568781,346881]);self.assertEqual([v['result']['actual_guest_instructions']for v in live],[300032,567517,346578]);self.assertEqual([v['result']['host_transitions']for v in live],[99,247,89])
  for h,n,delta in zip(hs,[1,11,1],[1,-8,1]):
   self.assertEqual(h['absorbed'],{'PLI2.OVL+7434':2*n+1,'PLI2.OVL+7630':n});self.assertEqual(h['net_host_delta'],delta);self.assertEqual(h['remaining']['PLI2.OVL+73D0']['calls'],0)
  self.assertEqual([h['remaining']['PLI.COM+119E']['calls']for h in hs],[36,36,43])
 def test_hybrids_metadata_scope_and_coverage_preservation(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   v=load(OUT/'proof'/name);self.assertTrue(v['all_passed']);self.assertEqual([r['result']['REL_sha256']for r in v['sources']],hashes)
  f=load(REPORT/'fidelity.json');self.assertEqual(f['promotions'],{'RAW':120});self.assertEqual(f['DEDUCED_STATIC_UNOBSERVED_bytes'],0)
  cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};self.assertEqual(cat['PLI2.OVL+8258']['observed_paths']['represented_bytes'],51);self.assertEqual(cat['PLI2.OVL+8258']['completeness']['control_flow'],'partial')
  self.assertLessEqual((REPORT/'implementation-packet.json').stat().st_size,28672)
  self.assertEqual(set(load(REPORT/'semantic-extraction.json')),{'historical_roots','semantic_inputs','semantic_outputs','shared_historical_state','historical_mechanism','candidate_modern_operation','confidence','mir_relevance'})
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=[__file__]+rest)
