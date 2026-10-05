#!/usr/bin/env python3
"""Fresh native proofs and independently corrected natural CALL/RET evidence."""
import argparse,json,subprocess,tempfile,unittest
from pathlib import Path
from check_native_2511_pass_31 import *
from check_240a_pass_30 import minimum,publication
from procedure_evidence_packet import verify_return
class NativeTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='pass31-',dir=ROOT/'_build')as temp:
   out=Path(temp)/'results'
   p=subprocess.run(['dune','exec','pli80-native-state-adaptation','--','--toolchain',str(IMAGES),'--output-dir',str(out)],cwd=ROOT,capture_output=True,text=True)
   if p.returncode:raise RuntimeError(p.stdout+p.stderr)
   cls.raw=json.loads((out/'natural-cases.json').read_text())
   cls.summaries={n:json.loads((out/(n+'.json')).read_text())for n in ['shadow-summary','single-hybrid-summary','cumulative-hybrid-summary']}
  for source,capture in CAPTURES.items():
   if not load(capture/'event-witnesses.json')['run_id'].startswith(source+':'):raise ValueError('Selected-run identity mismatch')
  cls.rows={s:gather(p,BOUNDS|EXTRA,include_nested_returns=True)for s,p in CAPTURES.items()}
  cls.image=(IMAGES/'PLI1.OVL').read_bytes()
 def test_fresh_shadows_and_complete_hybrids_are_deterministic(self):
  self.assertEqual(compact(self.raw),json.loads((REPORT/'natural-cases.json').read_text()))
  for n,r in self.summaries.items():self.assertEqual(r,json.loads((REPORT/(n+'.json')).read_text()))
 def test_corrected_natural_counts_callers_registers_and_all_logical_writers(self):
  for group in self.raw['sources']:
   rs=self.rows[group['source']][ENTRIES[group['operation']]];cs=group['members'];self.assertEqual(len(rs),len(cs))
   bystep={r['entry']['step_index']:r for r in rs}
   self.assertEqual(Counter(coord(r['call']['origin'])for r in rs),Counter(c['caller']for c in cs))
   for c in cs:
    r=bystep[c['entry_step']];verify_return(r['call'],r['ret'],r['relation'])
    self.assertEqual(c['input'],r['entry']['before']);self.assertEqual(c['output'],r['ret']['after']);self.assertEqual(c['return_step'],r['ret']['step_index'])
    inclusive=r['own_witnesses']+sum((q['memory_witnesses']for q in r['nested_returns'].values()),[]);inclusive.sort(key=lambda w:w['step_index'])
    actual=[(q['address'],q['new_value'],w['pc'])for w in inclusive for q in w['writes']]
    self.assertEqual({a:(v,w)for a,v,w in actual},{a:(v,w)for a,v,w,d,k in c['journal']})
    def logical(w,q):
     if w['control']['kind']=='call'or w['pc']in[0x9e48,0x9ddf,0x9de3,0x9f82,0x1abb,0x1abc,0x9d09]:return False
     if w['pc']==0x9e1e:return q['address']==((w['before']['sp']-1)&65535)
     if w['pc']==0x4712:return q['address']==c['input']['sp']-1
     return True
    self.assertEqual([(q['address'],q['new_value'],w['pc'])for w in inclusive for q in w['writes']if logical(w,q)],[(a,v,w)for a,v,w,d,k in c['journal']if k=='logical'])
    own={w['origin']['offset']:w for w in r['own_witnesses']}
    for q in c['children']:
     call=own[q['site']];child=r['nested_returns'][call['step_index']];verify_return(call,child['ret'],child['relation']);self.assertEqual(call['after'],q['input']);self.assertEqual(child['ret']['after'],q['output'])
 def test_cached_minimum_both_branches_flags_independent_of_A(self):
  cases=[minimum(r,self.image)for rs in self.rows.values()for r in rs['PLI1.OVL+23A0']]
  self.assertEqual(Counter(c['path']for c in cases),{'C>=E':59,'C<E':9})
 def test_three_fresh_publication_channels(self):
  for rs in self.rows.values():
   for r in rs['PLI1.OVL+23D2']:publication(r)
 def test_bounded_adapter_routes_and_no_selector_whitelist_by_index(self):
  for group in self.raw['sources']:
   if group['operation']!='adapt':continue
   for c in group['members']:
    ws=next(r for r in self.rows[group['source']]['PLI1.OVL+240A']if r['entry']['step_index']==c['entry_step'])['own_witnesses']
    selector=next(w for w in ws if w['origin']['offset']==0x2417)['after']['a']
    self.assertEqual(selector,c['result']['selector']);self.assertNotIn(selector,[0x16,0x19])
    if selector==0x15:self.assertEqual(next(w for w in ws if w['origin']['offset']==0x2442)['before']['a'],0)
    self.assertEqual([q['site']for q in c['children']],([0x242b]if selector==0x15 else[])+[0x24e6,0x24ed])
 def test_private_frame_exact_writes_fresh_reloads_and_stack_ancestry(self):
  self.assertEqual(self.image[0x2511:0x2514],bytes.fromhex('41C533'))
  self.assertEqual(self.image[0x7b09],0xe5);self.assertEqual(self.image[0x7b0e],0xe1)
  self.assertEqual(self.image[0x24ed:0x24f0],bytes.fromhex('CDD245'))
  for group in self.raw['sources']:
   if group['operation']=='adapt':
    for c in group['members']:
     s=c['input']['sp'];last={a:(v,w)for a,v,w,d,k in c['journal']}
     self.assertEqual([last[s-i]for i in range(1,5)],[(0x46,0x46ed),(0xf0,0x46ed),(0x46,0x4606),(9,0x4606)])
   if group['operation']!='saved':continue
   for c in group['members']:
    r=next(r for r in self.rows[group['source']]['PLI1.OVL+2511']if r['entry']['step_index']==c['entry_step']);ws={w['origin']['offset']:w for w in r['own_witnesses']};s=c['input']['sp']
    self.assertEqual([(q['address'],q['new_value'])for q in ws[0x2512]['writes']],[(s-1,c['input']['c']),(s-2,c['input']['c'])])
    for off in[0x2518,0x2525]:self.assertEqual(ws[off]['reads'],[dict(address=s-1,value=c['input']['c'])])
    self.assertEqual([q['site']for q in c['children']],[0x2519,0x251e,0x2526]);self.assertEqual(c['children'][1]['input']['c'],0)
    self.assertEqual([c['children'][i]['input']['c']for i in[0,2]],[c['input']['c']]*2)
    last={a:(v,w)for a,v,w,d,k in c['journal']};self.assertEqual(last[s-1],(c['input']['c'],0x4712))
    self.assertEqual(last[s-2],(0x47,0x4726));self.assertEqual(last[s-3],(0x29,0x4726))
 def test_cumulative_hierarchy_services_outputs_and_body_isolation(self):
  groups={(g['source'],g['operation']):g['members']for g in self.raw['sources']}
  for q in self.summaries['cumulative-hybrid-summary']['sources']:
   s=q['result']['source'];windows=[];expected=[]
   for op in['saved','adapt','publish','minimum']:
    cs=groups[s,op];expected.append(sum(not any(a<c['entry_step']<b for a,b in windows)for c in cs));windows.extend((c['entry_step'],c['return_step'])for c in cs)
   self.assertEqual(q['transition_vector'][:4],expected);self.assertEqual(q['host_bdos_services'],{'MINIMAL':2,'FIZZBUZ':6,'PICTURE':2}[s])
   for result in[q['result']]+[q['result']for q in self.summaries['single-hybrid-summary']['sources']if q['result']['source']==s]:self.assertTrue(result['PASS1']and result['PASS2']and result['END_COMPILATION']);self.assertEqual(result['termination'],'warm_boot')
 def test_next_boundary_ownership_is_mechanically_counted(self):
  audit=json.loads((REPORT/'boundary-assessment.json').read_text())
  self.assertEqual(boundary(self.rows),audit['corrected_observations'])
  for source,capture in CAPTURES.items():
   roots=next(g['members']for g in self.raw['sources']if g['source']==source and g['operation']=='saved')
   self.assertEqual(enclosing_parents(capture,roots),audit['newly_exposed_enclosing_ordinary_windows'][source])
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);args,rest=p.parse_known_args();IMAGES=args.images
 unittest.main(argv=[__file__]+rest)
