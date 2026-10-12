#!/usr/bin/env python3
import argparse,json,os,subprocess,unittest
from pathlib import Path
import run_partial_k23_gateway_pass_74 as d
class Mixed(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if not os.environ.get('RUNES_PASS74_REUSE_PROOF'):d.prove(IMAGES)
  cls.single=d.load(d.OUT/'proof/single-hybrid-summary.json');cls.post=d.load(d.OUT/'proof/cumulative-hybrid-summary.json')
 def test_all_five_sources_accept_and_decline_statefully(self):
  self.assertTrue(self.single['all_passed']);self.assertEqual([r['result']['invocations']for r in self.single['sources']],[1,13,1,4,9]);self.assertEqual([r['declined_gateway_roots']for r in self.single['sources']],[10,48,11,29,111])
 def test_primary_cumulative_counts_and_old_native_hierarchy(self):
  self.assertTrue(self.post['all_passed']);self.assertEqual([r['family_roots']for r in self.post['sources']],[1,13,1]);self.assertEqual([r['declined_gateway_roots']for r in self.post['sources']],[10,48,11])
  self.assertEqual([r['pre_guest_instructions']for r in self.post['sources']],[294362,557928,339572]);self.assertEqual([sum(r['pre_transition_vector'])for r in self.post['sources']],[92,215,78])
  for r in self.post['sources']:self.assertLess(r['result']['actual_guest_instructions'],r['pre_guest_instructions'])
 def test_goldens_and_whole_run_observables(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for q in [self.single,self.post]:self.assertEqual([r['result']['REL_sha256']for r in q['sources'][:3]],hashes)
 def test_all_accepted_root_shadows_and_frames(self):
  rows=d.load(d.OUT/'proof/natural-cases.json')['sources'];self.assertEqual([len(r['entries'][0]['members'])for r in rows],[1,13,1,4,9])
  for r in rows:
   for c in r['entries'][0]['members']:
    self.assertEqual(c['output']['sp'],c['input']['sp']+2);self.assertFalse(any(w[0]in[c['input']['sp'],c['input']['sp']+1]for w in c['journal']))
 def test_no_knowledge_or_faithful_law_change(self):
  semantic='878544acb368b5635c4fa242a03508103eaf30aa'
  for file in ['lib/pli80_host/acquisition_family.ml','research/annotated-assembly/manifest.json','research/host-compiler/pass-72/validation-full.json']:
   original=subprocess.check_output(['git','show',d.BASE+':'+file])
   self.assertEqual(subprocess.check_output(['git','show',semantic+':'+file]),original)
  certificate='research/host-compiler/pass-72/validation-full.json'
  self.assertEqual(Path(certificate).read_bytes(),subprocess.check_output(['git','show',semantic+':'+certificate]))
  policy_file='research/host-compiler/validation-policy.json'
  baseline=json.loads(subprocess.check_output(['git','show',d.BASE+':'+policy_file]))
  published=json.loads(subprocess.check_output(['git','show',semantic+':'+policy_file]))
  self.assertEqual(published,baseline)
  live=d.load(policy_file);epochs=[*live['previous_full_epochs'],live['current_full_epoch']]
  self.assertEqual(next(e for e in epochs if e['name']=='Pass72'),baseline['current_full_epoch'])
  m=d.load('research/annotated-assembly/manifest.json');self.assertEqual(sum(i['length']for i in m['images']),94720)
 def test_full_selection_trigger_handoff(self):
  import run_host_compiler_regressions as r
  _,names,_=r.select_categories(r.commands(IMAGES,d.OUT/'listing'),d.load(r.POLICY),profile='historical-full')
  archived=d.load('research/host-compiler/pass-74/historical-full-selection-proof.json')
  selected=archived['selected_categories'];self.assertEqual(archived['selected_category_count'],105)
  self.assertEqual(len(selected),105);self.assertEqual(len(selected),len(set(selected)))
  self.assertTrue(set(d.load('research/host-compiler/pass-72/validation-full.json')['selected_categories'])<=set(selected))
  self.assertEqual(len(names),len(set(names)));self.assertTrue(set(selected)<=set(names))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True);a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=[__file__]+rest)
