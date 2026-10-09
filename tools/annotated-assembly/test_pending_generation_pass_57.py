#!/usr/bin/env python3
"""Independent pending-selector ABI/state equations over full natural shadows."""
import argparse,json,unittest
from pathlib import Path
from run_pending_generation_pass_57 import prove,OUT,REPORT
class Pending(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  prove(IMAGES);cls.rows=json.loads((OUT/'proof/natural-cases.json').read_text())['sources'];cls.post=json.loads((OUT/'proof/cumulative-hybrid-summary.json').read_text())['sources']
 def test_entries_and_topology(self):
  self.assertEqual([len(r['entries'][0]['members'])for r in self.rows],[2,21,1]);top=json.loads((REPORT/'topology-summary.json').read_text());self.assertEqual([g['external']for g in top.values()],[2,21,1]);self.assertEqual([g['net_host_delta']for g in top.values()],[2,18,1])
 def test_selector_fresh_publications(self):
  for r in self.rows:
   for c in r['entries'][0]['members']:
    selector=c['input']['c'];self.assertEqual([(w[0],w[1])for w in c['journal']if w[2]in[0x9ce7,0x9cc7,0x9cd7]],[(0xae0a,selector),(0xae08,selector),(0xae09,selector)])
    self.assertEqual(c['output']['sp'],c['input']['sp']+2)
 def test_nonzero_gate_chronology(self):
  cases=[c for r in self.rows for e in r['entries']if e['offset']==0x7a17 for c in e['members']]
  nonzero=[c for c in cases if any(w[2]==0x9c3b for w in c['journal'])];self.assertEqual(len(nonzero),3)
  for c in nonzero:
   writes=[w for w in c['journal']if w[4]=='logical'];tail=writes[-2:];self.assertEqual([(w[0],w[1],w[2])for w in tail],[(0xae04,0,0x9c3b),(0xae06,0,0x9c40)])
   self.assertEqual(c['output']['a'],0);self.assertEqual(c['output']['h']*256+c['output']['l'],0xae06);self.assertTrue(c['output']['flags']['zero'])
 def test_cross_caller_components(self):
  self.assertEqual([[len(e['members'])for e in r['entries'][1:]]for r in self.rows],[[2,1,2,2,8,0,0,9],[36,13,21,21,41,3,6,40],[4,2,1,1,10,0,0,8]])
  for r in self.rows:
   for e in r['entries']:
    for c in e['members']:self.assertFalse(any(w[0]in[c['input']['sp'],c['input']['sp']+1]for w in c['journal']))
 def test_actual_counters_and_hierarchy(self):
  self.assertEqual([p['pre_guest_instructions']for p in self.post],[300501,571416,346964]);self.assertEqual([p['result']['actual_guest_instructions']for p in self.post],[300443,570705,346935]);self.assertEqual([p['result']['host_transitions']for p in self.post],[102,287,90]);self.assertEqual([p['guest_instructions_removed']for p in self.post],[58,711,29])
 def test_hybrid_goldens_and_chronology(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   q=json.loads((OUT/'proof'/name).read_text());self.assertTrue(q['all_passed']);self.assertEqual([p['result']['REL_sha256']for p in q['sources']],hashes)
 def test_catalog_scope_and_packet(self):
  c={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']};self.assertEqual(c['PLI2.OVL+7AE4']['length'],30);self.assertEqual(c['PLI2.OVL+7A17']['completeness']['contract'],'partial');self.assertEqual(c['PLI2.OVL+7397']['completeness']['contract'],'complete');self.assertLess((REPORT/'implementation-packet.json').stat().st_size,28672)
 def test_semantic_extraction_is_documentation_only(self):
  s=json.loads((REPORT/'semantic-extraction.json').read_text());self.assertEqual(s['historical_root'],'PLI2.OVL+7AE4');self.assertEqual(set(s),{'historical_root','semantic_inputs','semantic_outputs','shared_historical_state','historical_mechanism','candidate_modern_operation','confidence','mir_relevance'})
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=[__file__]+rest)
