#!/usr/bin/env python3
"""Corrected natural return windows, write chronology and independent ABI proof."""
import argparse,json,subprocess,tempfile,unittest
from collections import Counter
from pathlib import Path
from check_minimal_pass_2 import coord
from check_minimal_pass_3 import gather
from procedure_evidence_packet import ROOT,verify_return
REPORT=ROOT/'research/host-compiler/pass-26'
CAPTURES={'MINIMAL':ROOT/'_build/minimal-baseline/capture','FIZZBUZ':ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture','PICTURE':ROOT/'_build/discriminator-pass-15/selected-capture'}
BOUNDS={'PLI1.OVL+7AF0':(0x7af0,0x7b13),'PLI1.OVL+7B49':(0x7b49,0x7b64)}
FILES=['mapped-word-publication-cases','secondary-publication-cases','shadow-summary','single-hybrid-summary','cumulative-hybrid-summary']
class PublicationTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='pass26-',dir=ROOT/'_build')as temp:
   out=Path(temp)/'results'
   p=subprocess.run(['dune','exec','pli80-native-publication-primitives','--','--toolchain',str(IMAGES),'--output-dir',str(out)],cwd=ROOT,capture_output=True,text=True)
   if p.returncode:raise RuntimeError(p.stdout+p.stderr)
   cls.reports={n:json.loads((out/(n+'.json')).read_text())for n in FILES}
  cls.rows={s:gather(p,BOUNDS,include_nested_returns=True)for s,p in CAPTURES.items()}
  cls.cases={k:{s['source']:s['members']for s in cls.reports[f]['sources']}for k,f in zip(BOUNDS,FILES)}
 def test_fresh_shadows_hybrids_durable(self):
  for n,r in self.reports.items():self.assertEqual(r,json.loads((REPORT/(n+'.json')).read_text()))
 def test_all_corrected_calls_returns_and_logical_writes(self):
  for key,sources in self.cases.items():
   for source,cs in sources.items():
    rows=self.rows[source][key];self.assertEqual(len(cs),len(rows))
    self.assertEqual(Counter(c['caller']for c in cs),Counter(coord(r['call']['origin'])for r in rows))
    bystep={r['entry']['step_index']:r for r in rows}
    for c in cs:
     r=bystep[c['entry_step']];verify_return(r['call'],r['ret'],r['relation'])
     self.assertEqual(c['input'],r['entry']['before']);self.assertEqual(c['output'],r['ret']['after'])
     self.assertEqual(c['return_step'],r['ret']['step_index']);self.assertFalse(r['nested_returns'])
     self.assertEqual([(w['address'],w['value'])for w in c['writes']],[(q['address'],q['new_value'])for w in r['own_witnesses']if w['pc']!=0x9d09 for q in w['writes']])
     flags=c['input']['flags'].copy();flags['carry']=False;self.assertEqual(flags,c['output']['flags'])
     self.assertEqual((c['output']['d'],c['output']['e']),(c['input']['d'],c['input']['e']))
 def test_word_fresh_reads_two_additions_push_pop_and_low_high(self):
  for source,cs in self.cases['PLI1.OVL+7AF0'].items():
   rs={r['entry']['step_index']:r for r in self.rows[source]['PLI1.OVL+7AF0']}
   for c in cs:
    q=c['result'];ws=rs[c['entry_step']]['own_witnesses'];at=lambda o:next(w for w in ws if w['origin']['offset']==o)
    self.assertEqual(at(0x7af8)['reads'],[dict(address=0xae3e,value=q['position']),dict(address=0xae3f,value=q['discarded_ae3f'])])
    self.assertEqual(at(0x7b01)['reads'],[dict(address=0xaa1f+q['position'],value=q['index'])])
    self.assertEqual(at(0x7b07)['after']['h']*256+at(0x7b07)['after']['l'],q['first_address'])
    self.assertEqual(at(0x7b08)['after']['h']*256+at(0x7b08)['after']['l'],q['low_address'])
    self.assertEqual(at(0x7b0a)['reads'],[dict(address=0xae3f,value=c['input']['e']),dict(address=0xae40,value=c['input']['d'])])
    self.assertEqual(c['compatibility_writes'],[[c['input']['sp']-1,q['low_address']>>8],[c['input']['sp']-2,q['low_address']&255]])
    self.assertEqual(c['compatibility_writes'],[[v['address'],v['new_value']]for v in at(0x7b09)['writes']])
    self.assertEqual(at(0x7b0e)['reads'],[dict(address=c['input']['sp']-2,value=q['low_address']&255),dict(address=c['input']['sp']-1,value=q['low_address']>>8)])
    self.assertEqual(c['output']['a'],c['input']['a']);self.assertEqual(q['word'],c['input']['d']*256+c['input']['e'])
    self.assertEqual((c['output']['b']*256+c['output']['c'],c['output']['h']*256+c['output']['l']),(q['index'],q['high_address']))
 def test_secondary_saved_value_and_unconditional_distinct_publication(self):
  for source,cs in self.cases['PLI1.OVL+7B49'].items():
   rs={r['entry']['step_index']:r for r in self.rows[source]['PLI1.OVL+7B49']}
   for c in cs:
    q=c['result'];at=lambda o:next(w for w in rs[c['entry_step']]['own_witnesses']if w['origin']['offset']==o)
    self.assertEqual(at(0x7b4f)['reads'],[dict(address=0xae45,value=q['position']),dict(address=0xae46,value=q['discarded_high'])])
    self.assertEqual(at(0x7b58)['reads'],[dict(address=0xaa1f+q['position'],value=q['index'])])
    self.assertEqual(at(0x7b5f)['reads'],[dict(address=0xae46,value=c['input']['e'])])
    self.assertEqual(q['address'],0xad9d+q['index']);self.assertEqual(q['value'],c['input']['e'])
    self.assertEqual(c['output']['a'],q['value']);self.assertEqual(c['compatibility_writes'],[])
 def test_exact_immutable_encodings(self):
  b=(IMAGES/'PLI1.OVL').read_bytes()
  self.assertEqual(b[0x7af0:0x7b13].hex(),'2140ae722b732b71 2a3eae2600011faa094e06002149ab0909e52a3faeebe1732372c9'.replace(' ',''))
  self.assertEqual(b[0x7b49:0x7b64].hex(),'2146ae732b712a45ae2600011faa094e0600219dad093a46ae77c9')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);args,rest=p.parse_known_args();IMAGES=args.images;unittest.main(argv=[__file__]+rest)
