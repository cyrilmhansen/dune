#!/usr/bin/env python3
"""All natural7B7A oracles, actual helper reads, write/flag ancestry and cumulative migration."""
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from check_minimal_pass_2 import coord
from check_minimal_pass_3 import gather
from minimal_baseline import load
from procedure_evidence_packet import ROOT,verify_return

REPORT=ROOT/'research/host-compiler/pass-18'
CAPTURES={'MINIMAL':ROOT/'_build/minimal-baseline/capture','FIZZBUZ':ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture','PICTURE':ROOT/'_build/discriminator-pass-15/selected-capture'}

class NativeBalancePassEighteenTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='atlas-native7b7a-',dir='/tmp')as temp:
   out=Path(temp)/'experiment'
   r=subprocess.run(['dune','exec','pli80-native-7b7a','--','--toolchain',str(IMAGES),'--output-dir',str(out)],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
   if r.returncode:raise RuntimeError(r.stdout+r.stderr)
   cls.reports={n:json.loads((out/(n+'.json')).read_text())for n in ['balance-scan-cases','shadow-summary','single-hybrid-summary','cumulative-hybrid-summary']}
  cls.records={n:gather(p,{'PLI1.OVL+7B7A':(0x7B7A,0x7BA2)},include_nested_returns=True)['PLI1.OVL+7B7A']for n,p in CAPTURES.items()}

 def test_live_reports_and_all_corrected_invocations(self):
  for name,value in self.reports.items():self.assertEqual(value,json.loads((REPORT/(name+'.json')).read_text()))
  for run in self.reports['balance-scan-cases']['sources']:
   rs=self.records[run['source']];self.assertEqual(len(rs),len(run['members']));self.assertEqual(len(rs),{'MINIMAL':21,'FIZZBUZ':136,'PICTURE':27}[run['source']])
   self.assertEqual(Counter(coord(r['call']['origin'])for r in rs),Counter(c['caller']for c in run['members']))
   rows={r['entry']['step_index']:r for r in rs}
   for c in run['members']:
    r=rows[c['entry_step']];verify_return(r['call'],r['ret'],r['relation']);self.assertEqual(c['return_step'],r['ret']['step_index']);self.assertEqual(c['input'],r['entry']['before']);self.assertEqual(c['output'],r['ret']['after']);self.assertEqual(c['output']['pc'],r['call']['pc']+3)
    self.assertEqual(c['output']['flags'],dict(sign=False,zero=True,auxiliary_carry=True,parity=True,carry=False))
    self.assertEqual((c['output']['d'],c['output']['e']),(c['input']['d'],c['input']['e']))

 def test_each_iteration_uses_actual_mapper_table_reads_and_cmp_producer(self):
  for run in self.reports['balance-scan-cases']['sources']:
   rows={r['entry']['step_index']:r for r in self.records[run['source']]}
   for c in run['members']:
    r=rows[c['entry_step']];ws=r['own_witnesses'];calls=[w for w in ws if w['origin']['offset']==0x7B87];self.assertEqual(len(calls),len(c['iterations']))
    for k,(call,i)in enumerate(zip(calls,c['iterations'])):
     child=r['nested_returns'][call['step_index']];effects=child['memory_witnesses']
     read=lambda o:next(w for w in effects if w['origin']['offset']==o)['reads']
     self.assertEqual(call['before']['c'],i['cursor'])
     self.assertEqual((read(0x7A5A)[0]['address'],read(0x7A5A)[0]['value']),(0xAA1F+i['cursor'],i['index']))
     self.assertEqual((read(0x7A61)[0]['address'],read(0x7A61)[0]['value']),(0xAAB4+i['index'],i['mapped_byte']))
     self.assertEqual((read(0x7A77)[0]['address'],read(0x7A77)[0]['value']),(0x1B4B+i['mapped_byte'],i['packed_byte']))
     self.assertEqual(i['attribute'],i['packed_byte']&7);self.assertEqual(i['discarded_AE38'],read(0x7A67)[1]['value']);self.assertEqual(i['discarded_AE37'],read(0x7A51)[1]['value'])
     end=calls[k+1]['step_index']if k+1<len(calls)else c['return_step'];group=[w for w in ws if call['step_index']<w['step_index']<end];at=lambda o:next(w for w in group if w['origin']['offset']==o)
     self.assertEqual(at(0x7B8D)['reads'][0]['value'],i['balance_before']);self.assertEqual(at(0x7B8D)['after']['a'],i['temporary_sum']);self.assertEqual(at(0x7B8F)['writes'][0]['new_value'],i['balance_after'])
     cmp=at(0x7B93);branch=at(0x7B94);self.assertEqual((cmp['before']['a'],cmp['before']['c']),(0,i['balance_after']));self.assertEqual(branch['before']['flags'],cmp['after']['flags']);self.assertEqual(branch['control']['taken'],i['balance_after']==0)
     dec=[w for w in group if w['origin']['offset']==0x7B9A];self.assertEqual(bool(dec),i['balance_after']!=0)
     if dec:self.assertEqual(dec[0]['writes'][0]['new_value'],(i['cursor']-1)&255)
     self.assertEqual(i['cursor_wrapped'],bool(dec)and i['cursor']==0)

 def test_logical_write_order_and_final_stack_writers(self):
  for run in self.reports['balance-scan-cases']['sources']:
   rows={r['entry']['step_index']:r for r in self.records[run['source']]}
   for c in run['members']:
    r=rows[c['entry_step']];F=c['input']['sp'];stack={(F-i)&65535 for i in range(1,5)};logical=[];latest={}
    ws=r['own_witnesses']+[w for child in r['nested_returns'].values()for w in child['memory_witnesses']]
    for w in sorted(ws,key=lambda w:w['step_index']):
     for q in w['writes']:
      if q['address']in stack:latest[q['address']]=(w,q['new_value'])
      else:logical.append((q['address'],q['new_value']))
    self.assertEqual(logical,[(w['address'],w['value'])for w in c['writes']]);self.assertEqual(len(logical),4*len(c['iterations'])+1)
    digest=hashlib.sha256(';'.join(f'{a:04X}:{v:02X}'for a,v in logical).encode()).hexdigest();self.assertEqual(digest,c['logical_writes_sha256'])
    for a,value in c['compatibility_writes']:
     w,v=latest[a];depth=4 if a in {(F-4)&65535,(F-3)&65535}else 2;site=0x7A6B if depth==4 else 0x7B87
     self.assertEqual(coord(w['origin']),f'PLI1.OVL+{site:04X}');self.assertEqual(v,value);self.assertEqual(w['control']['kind'],'call');pc=w['pc']+3;self.assertEqual(value,pc&255 if a==(F-depth)&65535 else pc>>8)

 def test_single_and_cumulative_oracles_and_real_guest_accounting(self):
  shadows={r['source']:r for r in self.reports['shadow-summary']['sources']};single={r['source']:r for r in self.reports['single-hybrid-summary']['sources']}
  for row in self.reports['cumulative-hybrid-summary']['sources']:
   r=row['result'];name=r['source'];self.assertEqual((row['native_7BBF'],row['native_7B7A']),({'MINIMAL':3,'FIZZBUZ':21,'PICTURE':3}[name],{'MINIMAL':21,'FIZZBUZ':136,'PICTURE':27}[name]));self.assertEqual(r['host_transitions'],row['native_7BBF']+row['native_7B7A'])
   self.assertEqual(single[name]['host_transitions'],row['native_7B7A']);self.assertLess(r['actual_guest_instructions'],single[name]['actual_guest_instructions']);self.assertLess(single[name]['actual_guest_instructions'],shadows[name]['actual_guest_instructions'])
   for k in ['REL_size','REL_sha256','PASS1','PASS2','END_COMPILATION','termination']:self.assertEqual(r[k],single[name][k]);self.assertEqual(r[k],shadows[name][k])
   expected=[];p=CAPTURES[name]
   for chunk in load(p/'event-witnesses.json')['chunks']:
    for e in load(p/'event-witnesses/chunks'/f"{chunk['id']:06d}.json")['events']:
     if e['type']=='bdos_record'and e['operation']=='write_record':expected.append(dict(file=e['file']['name'],record=e['record'],sha256=hashlib.sha256(bytes.fromhex(e['data'])).hexdigest()))
   self.assertEqual(row['record_oracles'],expected);self.assertTrue(row['all_entry_resume_memory_states_match']);self.assertTrue(row['no_historical_replaced_body_execution'])

 def test_parent_scope_audit_uses_existing_predicates_only(self):
  audit=json.loads((REPORT/'parent-scope-audit.json').read_text())
  for row in audit:
   rs=gather(CAPTURES[row['source']],{'PLI1.OVL+7C1B':(0x7C1B,0x7D53)})['PLI1.OVL+7C1B'];actual=[]
   for r in rs:
    ws=r['own_witnesses'];mapped=next(w['writes'][0]['new_value']for w in ws if w['origin']['offset']==0x7C2C)
    offsets={w['origin']['offset']for w in ws};path='mapped0A'if mapped==10 else 'special'if 0x7C56 in offsets else 'predecessor_fallback'if 0x7CD0 in offsets else 'mapped17_predecessor0A'if mapped==23 else 'default'
    actual.append(dict(call_step=r['call']['step_index'],caller=coord(r['call']['origin']),mapped=mapped,path=path))
   self.assertEqual(actual,row['cases']);self.assertEqual(len(actual),row['calls']);self.assertEqual(dict(Counter(c['path']for c in actual)),row['path_counts']);self.assertNotIn(33,row['special_mapped_bytes'])

 def test_observed_termination_scope_and_fidelity(self):
  runs=self.reports['balance-scan-cases']['sources'];self.assertEqual(sum(len(c['iterations'])for r in runs for c in r['members']),440);self.assertFalse(any(i['cursor_wrapped']for r in runs for c in r['members']for i in c['iterations']))
  f=load(REPORT/'fidelity.json');self.assertEqual(f['fidelity_debt'],[]);self.assertEqual(f['divergences'],[]);self.assertTrue(f['cumulative_replacement_verified'])
  text=(ROOT/'lib/pli80_host/balance_scan.ml').read_text();self.assertNotIn('max_iterations',text);self.assertNotIn('Hashtbl',text)
  self.assertEqual(len({c['caller']for r in runs for c in r['members']}),10)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images.resolve();unittest.main(argv=[sys.argv[0],*rest])
