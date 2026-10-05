#!/usr/bin/env python3
"""Corrected root windows, child chronology and independently derived stack writers."""
import argparse,json,subprocess,tempfile,unittest
from collections import Counter
from pathlib import Path
from check_minimal_pass_2 import coord
from check_minimal_pass_3 import gather
from procedure_evidence_packet import ROOT,verify_return
REPORT=ROOT/'research/host-compiler/pass-27'
CAPTURES={'MINIMAL':ROOT/'_build/minimal-baseline/capture','FIZZBUZ':ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture','PICTURE':ROOT/'_build/discriminator-pass-15/selected-capture'}
KEY='PLI1.OVL+7E5F';BOUNDS={KEY:(0x7e5f,0x7ec0)}
FILES=['natural-cases','shadow-summary','single-hybrid-summary','cumulative-hybrid-summary']
class PublicationTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='pass27-',dir=ROOT/'_build')as temp:
   out=Path(temp)/'results'
   p=subprocess.run(['dune','exec','pli80-native-range-publication','--','--toolchain',str(IMAGES),'--output-dir',str(out)],cwd=ROOT,capture_output=True,text=True)
   if p.returncode:raise RuntimeError(p.stdout+p.stderr)
   cls.reports={n:json.loads((out/(n+'.json')).read_text())for n in FILES}
  cls.rows={s:gather(p,BOUNDS,include_nested_returns=True)[KEY]for s,p in CAPTURES.items()}
  cls.cases={s['source']:s['members']for s in cls.reports['natural-cases']['sources']}
 def test_fresh_shadows_and_hybrids_durable(self):
  for n,r in self.reports.items():self.assertEqual(r,json.loads((REPORT/(n+'.json')).read_text()))
 def test_corrected_invocations_returns_callers_and_all_writers(self):
  for source,cs in self.cases.items():
   rows=self.rows[source];self.assertEqual(len(cs),len(rows));self.assertEqual(Counter(c['caller']for c in cs),Counter(coord(r['call']['origin'])for r in rows))
   bystep={r['entry']['step_index']:r for r in rows}
   for c in cs:
    r=bystep[c['entry_step']];verify_return(r['call'],r['ret'],r['relation'])
    self.assertEqual(c['input'],r['entry']['before']);self.assertEqual(c['output'],r['ret']['after'])
    self.assertEqual(c['return_step'],r['ret']['step_index'])
    inclusive=r['own_witnesses']+sum((q['memory_witnesses']for q in r['nested_returns'].values()),[])
    inclusive.sort(key=lambda w:w['step_index'])
    self.assertEqual([(q['address'],q['new_value'],w['pc'])for w in inclusive for q in w['writes']],[(w['address'],w['value'],w['writer'])for w in c['journal']])
    self.assertEqual([(w['address'],w['value'])for w in c['writes']],[(w['address'],w['value'])for w in c['journal']if w['kind']=='logical'])
 def test_normal_gate_fresh_parent_reads_and_child_order(self):
  for source,cs in self.cases.items():
   rs={r['entry']['step_index']:r for r in self.rows[source]}
   for c in cs:
    r=rs[c['entry_step']];q=c['result'];at=lambda o:next(w for w in r['own_witnesses']if w['origin']['offset']==o)
    self.assertLessEqual(q['end'],0x94);self.assertFalse(at(0x7e6c)['after']['flags']['carry']);self.assertTrue(at(0x7e6d)['control']['taken'])
    self.assertFalse(any(w['origin']['offset']==0x7e70 for w in r['own_witnesses']))
    self.assertEqual(at(0x7e7c)['reads'],[dict(address=0xae33,value=q['old_index'])])
    self.assertEqual(at(0x7e7f)['writes'][0]['address'],0xaa1f+q['end']);self.assertEqual(at(0x7e7f)['writes'][0]['new_value'],q['old_index'])
    self.assertEqual(at(0x7e89)['reads'],[dict(address=0xaab4+q['old_index'],value=q['displaced'])])
    calls=[w for w in r['own_witnesses']if w['control']['kind']=='call']
    self.assertEqual([w['origin']['offset']for w in calls],[0x7e95,0x7ea0,0x7ea9,0x7eb2])
    self.assertEqual([w['control']['target']for w in calls],[0x9cd5,0x9cf0,0x9d2e,0x9d49])
    for w in calls:
     child=r['nested_returns'][w['step_index']];verify_return(w,child['ret'],child['relation'])
    for site in [0x7e73,0x7e8d,0x7e98,0x7ea3,0x7eac]:
     self.assertEqual(at(site)['reads'],[dict(address=0xae35,value=q['end']),dict(address=0xae36,value=dict(c['entry_scratch'])[0xae36])])
 def test_stack_last_writers_and_final_INR_ABI(self):
  for source,cs in self.cases.items():
   rs={r['entry']['step_index']:r for r in self.rows[source]}
   for c in cs:
    q=c['result'];s=c['input']['sp'];expected={s-4:q['word_address']&255,s-3:q['word_address']>>8,s-2:0xb5,s-1:0xa0}
    self.assertEqual(dict(c['compatibility_writes']),expected)
    latest={w['address']:w for w in c['journal']}
    for a,v in expected.items():
     self.assertEqual(latest[a]['value'],v);self.assertEqual(latest[a]['writer'],0x9d09 if a<s-2 else 0xa0b2);self.assertEqual(latest[a]['depth'],1 if a<s-2 else 0)
    inc=next(w for w in rs[c['entry_step']]['own_witnesses']if w['origin']['offset']==0x7ebe)
    self.assertEqual(c['output']['flags'],inc['after']['flags']);self.assertFalse(c['output']['flags']['carry'])
    self.assertEqual((c['output']['a'],c['output']['b']*256+c['output']['c'],c['output']['d']*256+c['output']['e'],c['output']['h']*256+c['output']['l']),(q['end'],q['secondary_index'],q['word']&0xff00,0xae35))
    self.assertEqual(q['end_after'],q['end']+1)
 def test_immutable_calls_push_pop_and_comparison(self):
  b=(IMAGES/'PLI1.OVL').read_bytes();self.assertEqual(b[0x7e67:0x7e70].hex(),'3e942135aebe d273a0'.replace(' ',''))
  for site,target in [(0x7e95,0x9cd5),(0x7ea0,0x9cf0),(0x7ea9,0x9d2e),(0x7eb2,0x9d49)]:self.assertEqual(b[site:site+3],bytes([0xcd,target&255,target>>8]))
  self.assertEqual((b[0x7b09],b[0x7b0e]),(0xe5,0xe1))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);args,rest=p.parse_known_args();IMAGES=args.images;unittest.main(argv=[__file__]+rest)
