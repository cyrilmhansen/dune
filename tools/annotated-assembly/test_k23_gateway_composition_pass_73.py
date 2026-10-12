#!/usr/bin/env python3
"""Whole-chain concrete shadows, nested frames and state-defined acceptance."""
import argparse,collections,json,os,subprocess,unittest
from pathlib import Path
import run_k23_gateway_composition_pass_73 as d
class Gateway(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if not os.environ.get('RUNES_PASS73_REUSE_PROOF'):d.prove(IMAGES)
  _,cls.roots,cls.rs=d.extract();cls.components=d.load(d.OUT/'components.json')
 def test_natural_counts_and_scope_audit(self):
  self.assertEqual([sum(r['source']==s for r in self.rs)for s in d.g.SOURCES],[1,13,1,4,9])
  self.assertEqual([sum(r['source']==s for r in self.roots)for s in d.g.SOURCES],[11,61,12,33,120])
  self.assertEqual([q['roots']for q in self.components['sources']],[1,13,1,4,9])
  self.assertEqual([q['rejected_other_gateway_roots']for q in self.components['sources']],[10,48,11,29,111])
 def test_table_provenance_and_real_child_results(self):
  for r in self.rs:
   self.assertEqual(r['lookup']['call']['after']['c'],r['entry_C']);self.assertEqual(r['lookup']['ret']['after']['a'],23)
   own={w['offset']:w for w in r['own']}
   for off,address,value in [(0x1fec,0x3c4f,0xc6),(0x1fee,0x3c50,0x57),(0x2009,0x3e0b,0x36),(0x200b,0x3e0c,0x60)]:
    self.assertEqual([(q['address'],q['value'])for q in d.g.accesses(own[off],'read')],[(address,value)])
   self.assertEqual(r['descriptor'],0x57c6);self.assertEqual(r['handler'],0x6036)
 def test_candidate_success_and_fallback_chronology(self):
  self.assertEqual(collections.Counter(r['success']for r in self.rs),{True:17,False:11})
  self.assertEqual(sum(len(r['predicates'])for r in self.rs),50)
  for r in self.rs:
   self.assertEqual(r['scan_calls'],1 if r['success']else 2)
   self.assertEqual(r['predicate_tokens'],[5]if r['success']else[5,0x69,0xfb])
   if r['fallback']:self.assertEqual((r['fallback_index'],r['fallback_pointer']),(1,0x3bf3))
   for w in r['own']:
    if w['decoded']=='RAR':
     b,a=w['before'],w['after'];self.assertEqual(a['CY'],bool(b['a']&1));self.assertEqual(a['a'],(b['a']>>1)|(int(b['CY'])<<7))
     for flag in ['S','Z','AC','P']:self.assertEqual(a[flag],b[flag])
 def test_nested_frame_and_both_continuations(self):
  for r in self.rs:
   e=r['entry'];s=e['entry']['sp'];self.assertNotEqual(e['parent'],0)
   self.assertFalse(r['original_slot_writes']);self.assertFalse(r['descendant_original_slot_writes'])
   words=[w for w in r['own']if w['offset']==0x20af];self.assertEqual(len(words),1)
   self.assertEqual([(q['address'],q['value'])for q in d.g.accesses(words[0],'write')],[(s-13,0x42),(s-14,0xb4)])
   ret=r['handler_ret'];self.assertEqual(ret['offset'],0x3ef5);self.assertEqual(ret['after']['pc'],0x42b4);self.assertEqual(ret['after']['sp'],s-12)
   self.assertEqual([w['offset']for w in r['software_last_writers']],[0x20af,0x20af])
   saved=[q for w in r['own']if w['offset']==0x1fca for q in d.g.accesses(w,'write')]
   self.assertEqual([q['address']for q in saved],list(range(s-11,s-1)))
   self.assertEqual([q['value']for q in saved],e['saved_state'][1:])
 def test_instruction_derived_restore_registers_and_flags(self):
  for r in self.rs:
   s=r['entry']['entry']['sp'];x=r['exit']['exit']
   self.assertEqual((x['a'],x['b']*256+x['c'],x['d']*256+x['e'],x['h']*256+x['l'],x['sp']),(r['entry']['saved_state'][0],s-1,0xad15,s,s+2))
   self.assertEqual([x[k]for k in ['S','Z','AC','P','CY']],[False,True,True,True,False])
   restored=[q for w in r['own']if w['offset']==0x20d6 for q in d.g.accesses(w,'write')]
   self.assertEqual([q['value']for q in restored],r['entry']['saved_state'][1:])
 def test_independent_components_and_synthetic_domain(self):
  q=self.components;self.assertTrue(q['all_passed']);self.assertFalse(q['native_gateway_installed'])
  self.assertEqual(len(q['synthetic_cases']),196);self.assertTrue(all(c['all_passed']for c in q['synthetic_cases']))
  self.assertTrue(any('other_tabletrue'in c['route']for c in q['synthetic_cases']))
  for r in q['sources']:self.assertTrue(r['full_state_RAM_writes_stack_calls_services'])
  self.assertEqual(sum(c['count']for r in q['sources']for c in r['components']if c['offset']==0x1dff),50)
  self.assertEqual(sum(c['count']for r in q['sources']for c in r['components']if c['offset']==0x3e36),28)
 def test_goldens_and_certified_epoch_preserved(self):
  for name,sha in zip(d.g.SOURCES[:3],d.g.GOLDENS):self.assertEqual(d.load(d.OUT/'capture'/f'{name}-summary.json')['REL_sha256'],sha)
  policy=d.load('research/host-compiler/validation-policy.json');self.assertEqual(policy['current_full_epoch']['name'],'Pass72')
  original=subprocess.check_output(['git','show',d.BASE+':research/host-compiler/validation-policy.json']);self.assertEqual(Path('research/host-compiler/validation-policy.json').read_bytes(),original)
 def test_only_gateway_catalog_and_scoped_bytes_change(self):
  old=json.loads(subprocess.check_output(['git','show',d.BASE+':research/annotated-assembly/procedures.json']))
  current=d.load('research/annotated-assembly/procedures.json');old={p['id']:p for p in old['procedures']};new={p['id']:p for p in current['procedures']}
  self.assertEqual({k for k in old if old[k]!=new[k]},{'PLI2.OVL+1FB5'})
  p=new['PLI2.OVL+1FB5'];self.assertEqual(p['completeness']['contract'],'partial');self.assertEqual(p['observed_paths']['represented_bytes'],271)
  def mapping(m):return {a:s['status']for i in m['images']if i['name']=='PLI2.OVL'for s in i['sections']for a in range(s['start_offset'],s['end_offset'])}
  before=mapping(json.loads(subprocess.check_output(['git','show',d.BASE+':research/annotated-assembly/manifest.json'])));after=mapping(d.load('research/annotated-assembly/manifest.json'))
  changed={a for a in before if before[a]!=after[a]};self.assertEqual(len(changed),263)
  represented={a for q in d.load(d.REPORT/'cfg.json')if q['evidence']=='OBSERVED'for a in range(q['offset'],q['offset']+len(bytes.fromhex(q['bytes'])))}
  self.assertTrue(changed<=represented);self.assertTrue(all(before[a]=='STRUCTURED'and after[a]=='UNDERSTOOD'for a in changed))
 def test_historical_full_list_preservation_and_packet(self):
  import run_host_compiler_regressions as r
  available=r.commands(IMAGES,d.OUT/'list-test');policy=d.load(r.POLICY);_,names,_=r.select_categories(available,policy,profile='historical-full')
  self.assertEqual(len(names),104);self.assertTrue(set(d.load('research/host-compiler/pass-72/validation-full.json')['selected_categories'])<=set(names))
  self.assertLess((d.REPORT/'implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True);a,rest=p.parse_known_args();IMAGES=a.images
 unittest.main(argv=[__file__]+rest)
