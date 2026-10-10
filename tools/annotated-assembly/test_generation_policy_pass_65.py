#!/usr/bin/env python3
"""Pass65 independent natural/synthetic policy, hierarchy and integrity proofs."""
import argparse,json,unittest,os
from pathlib import Path
from run_generation_policy_pass_65 import prove,OUT,REPORT,BASE,BOUNDS
from check_selector02_pass_40 import children_any

def load(p):return json.loads(Path(p).read_text())
def own(r):return{w['origin']['offset']:w for w in r['own_witnesses']}
class GenerationPolicy(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if os.environ.get('RUNES_PASS65_REUSE_PROOF')!='1':prove(IMAGES)
  cls.rows=load(OUT/'rows.json');cls.proof=load(OUT/'proof/natural-cases.json');cls.synthetic=load(OUT/'proof/synthetic-checkpoints.json')['cases']
 def parents(self):return[r for g in self.rows.values()for r in g['PLI2.OVL+7ED6']]
 def test_true_entry_extent_and_calls(self):
  self.assertEqual([len(g['PLI2.OVL+7ED6'])for g in self.rows.values()],[3,11,4])
  for r in self.parents():
   self.assertEqual(r['call']['origin']['offset'],0x808d);self.assertIn(r['ret']['origin']['offset'],[0x7ef1,0x8071]);self.assertEqual(r['ret']['after']['sp'],r['entry']['before']['sp']+2)
 def test_ordered_three_carrier_saves(self):
  for r in self.parents():
   w=own(r);inp=r['entry']['before'];self.assertEqual([(q['address'],q['new_value'])for o in[0x7ed9,0x7edb,0x7edd]for q in w[o]['writes']],[(0xae3c,inp['d']),(0xae3b,inp['e']),(0xae3a,inp['c'])])
   self.assertEqual([w[o]['before']['h']*256+w[o]['before']['l']for o in[0x7ed9,0x7edb,0x7edd]],[0xae3c,0xae3b,0xae3a])
 def test_gate_reads_flag_producers_and_returns(self):
  early=0
  for r in self.parents():
   w=own(r)
   for lda,rar,addr in[(0x7ede,0x7ee1,0x202b),(0x7ee8,0x7eeb,0xadaa)]:
    self.assertEqual(w[lda]['reads'][0]['address'],addr);self.assertEqual(w[rar]['after']['flags']['carry'],bool(w[lda]['reads'][0]['value']&1))
   if r['ret']['origin']['offset']==0x7ef1:early+=1;self.assertEqual(r['ret']['after']['a'],0);self.assertFalse(w[0x7eec]['control']['taken'])
  self.assertEqual(early,17)
 def test_independent_activity_address_reads_and_stack(self):
  r=next(r for r in self.parents()if r['ret']['origin']['offset']==0x8071);w=own(r);c=r['entry']['before']['c']
  self.assertEqual([q['address']for q in w[0x7efd]['reads']],[0xae3a,0xae3b]);self.assertEqual([q['address']for q in w[0x7f07]['reads']],[0xae3a,0xae3b]);self.assertEqual(w[0x7f0e]['reads'][0]['address'],0xadab+c+1);self.assertEqual(w[0x7f10]['reads'][0]['address'],0xadab+c)
  self.assertEqual(w[0x7f06]['after']['sp'],w[0x7f06]['before']['sp']-2);self.assertEqual(w[0x7f0f]['after']['sp'],w[0x7f06]['before']['sp'])
 def test_four_predicate_callsites_and_argument_provenance(self):
  r=next(r for r in self.parents()if r['ret']['origin']['offset']==0x8071);ws=r['own_witnesses'];counts={o:sum(w['origin']['offset']==o for w in ws)for o in[0x7fba,0x7fd9,0x8015,0x802b]};self.assertEqual(counts,{0x7fba:1,0x7fd9:1,0x8015:7,0x802b:7})
  for o,key in[(0x8015,'d'),(0x802b,'e')]:
   hits=[w['before']for w in ws if w['origin']['offset']==o];self.assertEqual([q['c']for q in hits],[0,1,2,3,4,5,7]);self.assertEqual([q['e']for q in hits],[r['entry']['before'][key]]*7)
 def test_scan_state_lifetime_and_termination(self):
  r=next(r for r in self.parents()if r['ret']['origin']['offset']==0x8071);ws=r['own_witnesses'];self.assertEqual([w['reads'][0]['value']for w in ws if w['origin']['offset']==0x8004],list(range(8)))
  self.assertEqual([q['new_value']for w in ws if w['origin']['offset']==0x806b for q in w['writes']],list(range(1,9)));self.assertEqual(r['ret']['after']['a'],0);self.assertTrue(r['ret']['after']['flags']['carry'])
 def test_independent_natural_component_shadows(self):
  self.assertEqual([len(s['entries'][0]['members'])for s in self.proof['sources']],[3,11,4]);self.assertEqual([len(next(e for e in s['entries']if e['offset']==0x7365)['members'])for s in self.proof['sources']],[0,0,16])
  for s in self.proof['sources']:
   for r in s['entries'][0]['members']:
    self.assertEqual(r['output']['sp'],r['input']['sp']+2);self.assertEqual(r['entry_dma'],r['post_dma']);self.assertNotIn(r['input']['sp'],[q[0]for q in r['journal']]);self.assertNotIn(r['input']['sp']+1,[q[0]for q in r['journal']])
 def test_synthetic_gates_search_match_and_adjacent_distance(self):
  labels={q['route']for q in self.synthetic};self.assertTrue(all(q['all_passed']for q in self.synthetic));self.assertGreaterEqual(len(self.synthetic),504)
  self.assertTrue({'7ED6_gate202B','7ED6_gateADAA','7ED6_reserved6','7ED6_pair_equal','7ED6_pair_plus1','7ED6_pair_plus2','7ED6_pair_minus1','7ED6_pair_minus2','7ED6_pair_far','7ED6_match_first','7ED6_match_second','7ED6_search_pair','7ED6_search_index7','7ED6_skip_index6','7ED6_same_destination','7ED6_equal_values'}<=labels)
 def test_helpers_independently_synthetic_proved(self):
  labels={q['route']for q in self.synthetic}
  for off in[0x7d47,0x7d85,0x8398,0x83b4,0x83d2]:self.assertTrue(any(f'helper_{off:04X}'in s for s in labels))
  pairs=load(OUT/'proof/synthetic-helper-pairs.json');self.assertTrue({f'PLI2.OVL+{x:04X}'for x in[0x7d47,0x7d85,0x8398,0x83b4,0x83d2]}<={q['coordinate']for q in pairs})
 def test_factor_optimist_independent_natural_cases(self):
  for s,n in [('FACTOR',5),('OPTIMIST',14)]:self.assertEqual(len(load(OUT/(s+'-natural-cases.json'))['sources'][0]['entries'][0]['members']),n)
 def test_hybrids_exact_goldens_chronology_and_counters(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for file in['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   d=load(OUT/'proof'/file);self.assertTrue(d['all_passed']);self.assertEqual([s['result']['REL_sha256']for s in d['sources']],hashes)
  rows=load(OUT/'proof/cumulative-hybrid-summary.json')['sources'];self.assertEqual([s['pre_guest_instructions']for s in rows],[294735,561768,341214]);self.assertTrue(all(s['guest_instructions_removed']>0 for s in rows))
 def test_catalog_byte_status_and_historical_totals(self):
  from historical_catalog_epoch import _checkpoint
  cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']}
  for off,end in BOUNDS.items():self.assertEqual(cat[f'PLI2.OVL+{off:04X}']['end_offset'],end)
  for k,p in _checkpoint(BASE).items():
   for s,n in p['observed_paths']['invocations_by_run'].items():self.assertGreaterEqual(cat[k]['observed_paths']['invocations_by_run'].get(s,0),n)
  self.assertLess((REPORT/'implementation-packet.json').stat().st_size,32768)
 def test_static_evidence_separate_from_natural(self):
  cfg=load(REPORT/'cfg.json');self.assertEqual(sum(len(bytes.fromhex(w['bytes']))for w in cfg if w['evidence']=='OBSERVED'),297);self.assertEqual(sum(len(bytes.fromhex(w['bytes']))for w in cfg if w['evidence']=='DEDUCED STATIC UNOBSERVED'),265)
 def test_historical_full_selection_only(self):
  import run_host_compiler_regressions as r
  _,selected,_=r.select_categories(r.commands(str(IMAGES),OUT),load('research/host-compiler/validation-policy.json'),'historical-full');self.assertTrue(set(load('research/host-compiler/pass-62/validation.json')['categories'])<=set(selected));self.assertTrue({'pass63','pass64','pass65','validation-runner-tests'}<=set(selected));self.assertGreaterEqual(len(selected),96)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=[__file__]+rest)
