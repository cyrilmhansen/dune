#!/usr/bin/env python3
"""Pass66 independent CPU/natural composition and transactional proofs."""
import argparse,collections,json,os,unittest
from pathlib import Path
from run_generation_composition_pass_66 import BASE,OUT,REPORT,prove
from check_selector02_pass_40 import children_any

def load(p):return json.loads(Path(p).read_text())
def own(r):return{w['origin']['offset']:w for w in r['own_witnesses']}
class GenerationComposition(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if os.environ.get('RUNES_PASS66_REUSE_PROOF')!='1':prove(IMAGES)
  cls.rows=load(OUT/'rows.json');cls.proof=load(OUT/'proof/natural-cases.json');cls.syn=[c for c in load(OUT/'proof/synthetic-checkpoints.json')['cases']if c['route'].startswith('8072_')]
  for g in cls.rows.values():
   for r in g['PLI2.OVL+8072']:r['nested_returns']={int(k):v for k,v in r['nested_returns'].items()}
 def parents(self):return[r for g in self.rows.values()for r in g['PLI2.OVL+8072']]
 def test_true_entry_bounds_and_returns(self):
  self.assertEqual([len(g['PLI2.OVL+8072'])for g in self.rows.values()],[3,11,4])
  for r in self.parents():
   w=own(r);self.assertEqual(min(w),0x8072);self.assertEqual(r['ret']['origin']['offset'],0x80b1);self.assertEqual(r['ret']['after']['sp'],r['entry']['before']['sp']+2)
  cfg=load(REPORT/'cfg.json');self.assertEqual(cfg[-1]['offset'],0x80b1);self.assertEqual(sum(len(bytes.fromhex(w['bytes']))for w in cfg),64)
 def test_saved_triple_order_flags_and_addresses(self):
  for r in self.parents():
   w=own(r);e=r['entry']['before'];self.assertEqual([(q['address'],q['new_value'])for o in[0x8075,0x8077,0x8079]for q in w[o]['writes']],[(0xae46,e['d']),(0xae45,e['e']),(0xae44,e['c'])])
   for o in[0x8075,0x8077,0x8079]:self.assertEqual(w[o]['before']['flags'],w[o]['after']['flags'])
 def test_selector4_preparation_and_complete_child_sequence(self):
  counts=[]
  for g in self.rows.values():
   n=0
   for r in g['PLI2.OVL+8072']:
    w=own(r);cs=children_any(r);selector=w[0x807a]['reads'][0];self.assertEqual(selector,dict(address=0xae44,value=r['entry']['before']['c']))
    selected=selector['value']==4;n+=selected;self.assertEqual(w[0x807f]['control']['taken'],not selected)
    self.assertEqual([c['target']for c in cs],(['PLI2.OVL+7A17']if selected else[])+['PLI2.OVL+7ED6','PLI2.OVL+7338','PLI2.OVL+75CE','PLI2.OVL+7619'])
   counts.append(n)
  self.assertEqual(counts,[0,1,1])
 def test_all_independent_paired_read_provenance(self):
  for r in self.parents():
   w=own(r)
   for o,a in[(0x8085,0xae44),(0x8089,0xae45),(0x8095,0xae44),(0x8099,0xae45),(0x80a0,0xae44),(0x80a9,0xae45)]:self.assertEqual([q['address']for q in w[o]['reads']],[a,a+1])
 def test_7ed6_and_fallback_7338_channels(self):
  for r in self.parents():
   e=r['entry']['before'];cs=children_any(r)
   for target in ['PLI2.OVL+7ED6','PLI2.OVL+7338']:
    c=next(c for c in cs if c['target']==target);self.assertEqual([c['entry'][k]for k in['c','d','e']],[e[k]for k in['c','d','e']])
 def test_actual_7ed6_result_and_rar_flags(self):
  carries=[]
  for r in self.parents():
   w=own(r);child=next(c for c in children_any(r)if c['target']=='PLI2.OVL+7ED6');old=child['output'];before=w[0x8090]['before'];after=w[0x8090]['after'];self.assertEqual(before,old);self.assertEqual(after['a'],(128 if old['flags']['carry']else 0)|(old['a']>>1));self.assertEqual(after['flags'],dict(old['flags'],carry=bool(old['a']&1)));self.assertTrue(w[0x8091]['control']['taken']);carries.append(old['flags']['carry'])
  self.assertEqual(collections.Counter(carries),{False:17,True:1})
 def test_75ce_not_original_relation_and_7619_word(self):
  for r in self.parents():
   e=r['entry']['before'];cs=children_any(r);field=next(c for c in cs if c['target']=='PLI2.OVL+75CE');word=next(c for c in cs if c['target']=='PLI2.OVL+7619');self.assertEqual([field['entry'][k]for k in['c','d','e']],[1,e['e'],e['c']]);self.assertEqual([word['entry'][k]for k in['b','c']],[e['d'],e['e']])
   self.assertEqual(r['ret']['after']['flags'],word['output']['flags'])
 def test_component_shadows_and_exact_continuations(self):
  for s,counts in zip(self.proof['sources'],[3,11,4]):
   entries={e['offset']:e['members']for e in s['entries']};self.assertEqual(len(entries[0x8072]),counts)
   for o in[0x7ed6,0x7338,0x75ce,0x7619]:self.assertEqual(len(entries[o]),counts)
   for r in entries[0x8072]:
    self.assertEqual(r['output']['sp'],r['input']['sp']+2);self.assertEqual(r['entry_dma'],r['post_dma']);self.assertNotIn(r['input']['sp'],[q[0]for q in r['journal']]);self.assertNotIn(r['input']['sp']+1,[q[0]for q in r['journal']])
 def test_cpu_synthetic_paths_saves_and_result_gate(self):
  self.assertEqual(len(self.syn),432);self.assertTrue(all(c['all_passed']for c in self.syn));labels={c['route']for c in self.syn}
  for name in ['fallback_C0','fallback_C4','fallback_C5','reserved_C6','gate202B','scan_failed','selector4_pending','success_equal','success_C4','success_plus1','success_first','success_search']:
   for cy in [0,1]:self.assertIn(f'8072_{name}_CY{cy}',labels)
  for r in self.syn:
   ws={w['pc']-0x2200:w for w in r['checkpoints']};self.assertEqual(ws[0x8079]['HL'],0xae44)
   success='_success_'in r['route'];self.assertEqual(ws[0x8090]['PSW']&1,int(success));self.assertEqual(0x8094 in ws,success);self.assertEqual(0x809d in ws,not success)
   if success:self.assertNotIn(0x80a6,ws);self.assertNotIn(0x80ae,ws)
 def test_cross_sources_independent_children_and_saves(self):
  for s in ['FACTOR','OPTIMIST']:
   es=load(OUT/(s+'-natural-cases.json'))['sources'][0]['entries'];roots=es[0]['members'];self.assertGreater(len(roots),0)
   for r in roots:self.assertEqual(r['output']['sp'],r['input']['sp']+2);self.assertEqual(r['entry_dma'],r['post_dma'])
 def test_standalone_and_cumulative_exact_goldens(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for n in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   d=load(OUT/'proof'/n);self.assertTrue(d['all_passed']);self.assertEqual([r['result']['REL_sha256']for r in d['sources']],hashes)
  d=load(OUT/'proof/cumulative-hybrid-summary.json');self.assertEqual([r['pre_guest_instructions']for r in d['sources']],[294693,561614,340593]);self.assertEqual([sum(r['pre_transition_vector'])for r in d['sources']],[104,268,96])
 def test_epoch_and_historical_totals_preserved(self):
  from historical_catalog_epoch import _checkpoint
  cur={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']}
  for key,p in _checkpoint(BASE).items():
   for s,n in p['observed_paths']['invocations_by_run'].items():self.assertGreaterEqual(cur[key]['observed_paths']['invocations_by_run'].get(s,0),n)
  self.assertEqual(cur['PLI2.OVL+8072']['end_offset'],0x80b2);self.assertLess((REPORT/'implementation-packet.json').stat().st_size,32768)
 def test_historical_full_selection_only_active_not_accumulated(self):
  import run_host_compiler_regressions as r
  policy=load('research/host-compiler/validation-policy.json');_,full,_=r.select_categories(r.commands(str(IMAGES),OUT),policy,'historical-full');self.assertTrue(set(load('research/host-compiler/pass-62/validation.json')['categories'])<=set(full));self.assertTrue({'pass63','pass64','pass65','pass66','validation-runner-tests'}<=set(full));self.assertGreaterEqual(len(full),97)
  _,active,_=r.select_categories(r.commands(str(IMAGES),OUT),policy,'active',extras='pass66,pass65');self.assertTrue({'pass66','pass65'}<=set(active));self.assertTrue({'pass54','pass57','pass62'}.isdisjoint(active))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=[__file__]+rest)
