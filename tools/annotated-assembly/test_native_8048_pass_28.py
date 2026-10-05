#!/usr/bin/env python3
"""Fresh native proofs plus corrected, independently selected capture windows."""
import argparse,json,subprocess,tempfile,unittest
from collections import Counter
from pathlib import Path
from check_minimal_pass_2 import coord
from check_minimal_pass_3 import gather
from procedure_evidence_packet import ROOT,verify_return
REPORT=ROOT/'research/host-compiler/pass-28'
CAPTURES={'MINIMAL':ROOT/'_build/minimal-baseline/capture','FIZZBUZ':ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture','PICTURE':ROOT/'_build/discriminator-pass-15/selected-capture'}
BOUNDS={'PLI1.OVL+8048':(0x8048,0x80b1),'PLI1.OVL+7A93':(0x7a93,0x7aa9),'PLI1.OVL+7B13':(0x7b13,0x7b2e),'PLI1.OVL+7EC0':(0x7ec0,0x7ed7),'PLI1.OVL+80B7':(0x80b7,0x80ca)}
FILES=['natural-cases','control-cases','shadow-summary','control-single-hybrid-summary','single-hybrid-summary','cumulative-hybrid-summary']
class InputTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='pass28-',dir=ROOT/'_build')as temp:
   out=Path(temp)/'results'
   p=subprocess.run(['dune','exec','pli80-native-input-processing','--','--toolchain',str(IMAGES),'--output-dir',str(out)],cwd=ROOT,capture_output=True,text=True)
   if p.returncode:raise RuntimeError(p.stdout+p.stderr)
   cls.reports={n:json.loads((out/(n+'.json')).read_text())for n in FILES}
  cls.rows={s:gather(p,BOUNDS,include_nested_returns=True)for s,p in CAPTURES.items()}
  cls.roots={s['source']:s['members']for s in cls.reports['natural-cases']['sources']}
  cls.controls={s['source']:s['members']for s in cls.reports['control-cases']['sources']}
 def test_fresh_shadows_and_hybrids_durable(self):
  for n,r in self.reports.items():self.assertEqual(r,json.loads((REPORT/(n+'.json')).read_text()))
 def test_root_counts_return_ancestry_all_writes_and_stack_writers(self):
  for source,cs in self.roots.items():
   rows=self.rows[source]['PLI1.OVL+8048'];self.assertEqual(len(rows),len(cs))
   self.assertEqual(Counter(c['caller']for c in cs),Counter(coord(r['call']['origin'])for r in rows))
   bystep={r['entry']['step_index']:r for r in rows}
   for c in cs:
    r=bystep[c['entry_step']];verify_return(r['call'],r['ret'],r['relation'])
    self.assertEqual(c['input'],r['entry']['before']);self.assertEqual(c['output'],r['ret']['after']);self.assertEqual(c['return_step'],r['ret']['step_index'])
    inclusive=r['own_witnesses']+sum((q['memory_witnesses']for q in r['nested_returns'].values()),[]);inclusive.sort(key=lambda w:w['step_index'])
    actual=[(q['address'],q['new_value'],w['pc'])for w in inclusive for q in w['writes']]
    planned=[(w['address'],w['value'],w['writer'])for w in c['journal']]
    self.assertEqual(actual,planned)
    self.assertEqual({a:(v,writer)for a,v,writer in actual},{a:(v,writer)for a,v,writer in planned})
 def test_low_independent_predecessors_and_child_machine_states(self):
  for source,cs in self.roots.items():
   rs={r['entry']['step_index']:r for r in self.rows[source]['PLI1.OVL+8048']}
   for c in cs:
    r=rs[c['entry_step']];ws={w['origin']['offset']:w for w in r['own_witnesses']};low=c['result']['route']=='low'
    self.assertEqual(low,c['input']['c']<=0xdd);self.assertEqual(ws[0x8051]['after']['flags']['carry'],not low)
    self.assertEqual(ws[0x8052]['control']['taken'],low)
    if not low:continue
    self.assertEqual([w['origin']['offset']for w in r['own_witnesses']if w['control']['kind']=='call'],[0x807d,0x8085,0x808d,0x8095,0x809d,0x80a5,0x80ad])
    for channel,read,dcr,pair,call in zip(c['result']['channels'],[0x8080,0x8090,0x80a0],[0x8083,0x8093,0x80a3],[0x8088,0x8098,0x80a8],[0x8085,0x8095,0x80a5]):
     old=ws[read]['reads'][0]['value'];self.assertEqual(channel['predecessor'],(old-1)&255)
     self.assertEqual(ws[dcr]['after']['a'],channel['predecessor'])
     self.assertEqual(ws[pair]['reads'][0]['address'],0xae32);self.assertEqual(ws[pair]['reads'][1]['address'],0xae33)
     self.assertEqual(channel['position'],ws[pair]['reads'][0]['value'])
     self.assertEqual(channel['value'],r['nested_returns'][ws[call]['step_index']]['ret']['after']['a'])
    self.assertEqual(c['output']['flags'],ws[0x80a3]['after']['flags'])
    s=c['input']['sp'];last={w['address']:w for w in c['journal']}
    self.assertEqual((last[s-2]['value'],last[s-1]['value'],last[s-2]['writer']),(0xb0,0xa2,0xa2ad))
    self.assertEqual(last[s-4]['writer'],0xa0b2);self.assertEqual(last[s-3]['writer'],0xa0b2)
    self.assertEqual(last[s-6]['writer'],0x9d09);self.assertEqual(last[s-5]['writer'],0x9d09)
    for child in c['children']:
     w=ws[child['site']];nested=r['nested_returns'][w['step_index']];verify_return(w,nested['ret'],nested['relation'])
     self.assertEqual(child['input'],w['after']);self.assertEqual(child['output'],nested['ret']['after'])
 def test_high_gate_RAR_fresh_saved_byte_and_emitter_result(self):
  for source,cs in self.roots.items():
   rs={r['entry']['step_index']:r for r in self.rows[source]['PLI1.OVL+8048']}
   for c in cs:
    if c['result']['route']!='high':continue
    r=rs[c['entry_step']];ws={w['origin']['offset']:w for w in r['own_witnesses']}
    self.assertGreater(c['input']['c'],0xdd);self.assertFalse(c['result']['gate']&1)
    self.assertEqual(ws[0x8058]['before']['flags']['carry'],True)
    self.assertEqual(ws[0x8058]['after']['a'],(c['result']['gate']>>1)|128)
    self.assertFalse(ws[0x8058]['after']['flags']['carry']);self.assertTrue(ws[0x8059]['control']['taken'])
    for key in ['sign','zero','auxiliary_carry','parity']:self.assertEqual(ws[0x8058]['after']['flags'][key],ws[0x8051]['after']['flags'][key])
    self.assertFalse(any(0x805c<=o<=0x8068 for o in ws))
    self.assertEqual([w['origin']['offset']for w in r['own_witnesses']if w['control']['kind']=='call'],[0x8069,0x8070])
    self.assertEqual([q['address']for q in ws[0x806c]['reads']],[0xae6a,0xae6b])
    emitted=ws[0x806c]['reads'][0]['value'];self.assertEqual(c['result']['emitted'],emitted)
    self.assertEqual(ws[0x8070]['before']['c'],emitted)
    for child in c['children']:
     w=ws[child['site']];nested=r['nested_returns'][w['step_index']];verify_return(w,nested['ret'],nested['relation'])
     self.assertEqual(child['input'],w['after']);self.assertEqual(child['output'],nested['ret']['after'])
    self.assertEqual(c['output'],{**r['nested_returns'][ws[0x8070]['step_index']]['ret']['after'],'pc':c['output']['pc'],'sp':c['output']['sp']})
 def test_control_leaf_counts_pair_reads_publications_flags(self):
  for source,cs in self.controls.items():
   for op,key,pair,mapsite,readsite in [('read','PLI1.OVL+7A93',0x7a97,0x7aa0,0x7aa7),('publish','PLI1.OVL+7B13',0x7b19,0x7b22,0x7b29)]:
    members=[c for c in cs if c['operation']==op];rows=self.rows[source][key];self.assertEqual(len(members),len(rows))
    self.assertEqual(Counter(c['caller']for c in members),Counter(coord(r['call']['origin'])for r in rows))
    bystep={r['entry']['step_index']:r for r in rows}
    for c in members:
     r=bystep[c['entry_step']];verify_return(r['call'],r['ret'],r['relation']);ws={w['origin']['offset']:w for w in r['own_witnesses']}
     self.assertEqual(c['input'],r['entry']['before']);self.assertEqual(c['output'],r['ret']['after'])
     self.assertEqual(ws[pair]['reads'][1]['value'],c['discarded_high'])
     self.assertEqual(ws[mapsite]['reads'],[dict(address=0xaa1f+c['position'],value=c['index'])])
     self.assertEqual(c['address'],0xac73+c['index'])
     writes=[(q['address'],q['new_value'])for w in r['own_witnesses']for q in w['writes']]
     self.assertEqual(writes,[(w['address'],w['value'])for w in c['writes']])
     if op=='read':self.assertEqual(ws[readsite]['reads'],[dict(address=c['address'],value=c['value'])])
     else:self.assertEqual(writes,[(0xae42,c['input']['e']),(0xae41,c['input']['c']),(c['address'],c['input']['e'])])
     expected={**c['input']['flags'],'carry':False};self.assertEqual(c['output']['flags'],expected)
     self.assertEqual((c['output']['d'],c['output']['e']),(c['input']['d'],c['input']['e']))
 def test_aggregate_hierarchy_and_next_boundary_capture_counts(self):
  audit=json.loads((REPORT/'hierarchy-summary.json').read_text())
  for row in audit['sources']:
   source=row['source'];cs=self.roots[source];low=sum(c['result']['route']=='low'for c in cs);high=len(cs)-low
   self.assertEqual((row['roots'],row['low'],row['high']),(len(cs),low,high))
   n=row['nested_logical_operations'];self.assertEqual((n['7E5F'],n['7D53'],n['Int_emitter']),(low,high,high))
   self.assertEqual(n['BDOS26'],sum(c['service_functions'].count(26)for c in cs));self.assertEqual(n['BDOS21'],n['BDOS26'])
  selected=json.loads((REPORT/'next-boundary-assessment.json').read_text())['corrected_capture_observations']
  for source,observations in selected.items():
   for key,record in observations.items():
    rs=self.rows[source][key];self.assertEqual(record['calls'],len(rs))
    self.assertEqual(record['callers'],dict(Counter(coord(r['call']['origin'])for r in rs)))
    targets=Counter()
    for r in rs:
     for w in r['own_witnesses']:
      if w['control']['kind']=='call':
       first=min(r['nested_returns'][w['step_index']]['memory_witnesses'],key=lambda q:q['step_index'])
       self.assertEqual(first['origin']['image']['name'],'PLI1.OVL')
       off=first['origin']['offset']-(first['pc']-w['control']['target']);targets[f'PLI1.OVL+{off:04X}']+=1
    self.assertEqual(record['direct_callees'],dict(targets))
 def test_unchanged_8048_archaeology_and_canonical_code(self):
  # No RAW gate bytes or partial contract are promoted by the native scope.
  text=(ROOT/'research/annotated-assembly/PLI1.asm').read_text()
  self.assertIn('PLI1_805C: DB',text)
  image=(IMAGES/'PLI1.OVL').read_bytes()
  self.assertEqual(image[0x8055:0x805c],bytes.fromhex('3a1aaa1fd269a2'))
  for site,target in [(0x8069,0x9f53),(0x8070,0xff6),(0x807d,0xa05f),(0x8085,0x9c93),(0x808d,0x9d13)]:self.assertEqual(image[site:site+3],bytes([0xcd,target&255,target>>8]))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);args,rest=p.parse_known_args();IMAGES=args.images;unittest.main(argv=[__file__]+rest)
