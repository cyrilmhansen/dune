#!/usr/bin/env python3
"""Fresh native/real-CPM proofs against independent Pass22 corrected evidence."""
import argparse
import hashlib
import json
import subprocess
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
REPORT=ROOT/'research/host-compiler/pass-23'
OLD=ROOT/'research/host-compiler/pass-22'
FILES=['emitter-native-cases','single-hybrid-summary','cumulative-hybrid-summary']
COUNTS={'MINIMAL':128,'FIZZBUZ':384,'PICTURE':128}

class NativeIntEmitterPassTwentyThreeTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='pass23-native-',dir=ROOT/'_build') as directory:
   out=Path(directory)/'proofs'
   run=subprocess.run(['dune','exec','pli80-native-int-emitter','--','--toolchain',str(IMAGES),'--output-dir',str(out)],cwd=ROOT,capture_output=True,text=True)
   if run.returncode:raise RuntimeError(run.stdout+run.stderr)
   cls.reports={n:json.loads((out/(n+'.json')).read_text())for n in FILES}
  cls.cases={s['source']:s['cases']for s in cls.reports['emitter-native-cases']['sources']}
  cls.old={s['source']:{c['entry_step']:c for c in s['members']}for s in json.loads((OLD/'emitter-cases.json').read_text())['sources']}
  cls.flushes={(c['source'],c['entry_step']):c for c in json.loads((OLD/'bdos-chronology.json').read_text())['flushes']}

 def test_fresh_complete_shadow_and_hybrid_reports(self):
  for n,r in self.reports.items():self.assertEqual(r,json.loads((REPORT/(n+'.json')).read_text()))
  for name,cs in self.cases.items():
   self.assertEqual(len(cs),COUNTS[name]);self.assertEqual(len(cs),len(self.old[name]))
   self.assertEqual(Counter(c['caller']for c in cs),Counter(c['caller']for c in self.old[name].values()))
   for c in cs:
    old=self.old[name][c['entry_step']]
    for key in ['entry_step','return_step','caller','input','output','entry_memory_sha256','post_memory_sha256']:self.assertEqual(c[key],old[key])
    self.assertEqual((c['index'],c['neighbor'],c['destination']),(old['entry_index'],old['neighbor_1E0D'],old['buffer_address']))
    self.assertEqual(c['output']['sp'],(c['input']['sp']+2)&65535)

 def test_nonflush_order_and_CPI80_state(self):
  count=0
  for cs in self.cases.values():
   for c in cs:
    i=c['index'];self.assertLess(i,128)
    self.assertEqual(c['fresh_scratch'],c['input']['c']);self.assertEqual(c['reloaded_index'],i);self.assertEqual(c['incremented_index'],i+1)
    if c['flush']:continue
    count+=1
    self.assertEqual(c['logical_writes'],[[0x20b0,c['input']['c']],[0x1d8c+i,c['input']['c']],[0x1e0c,i+1]])
    self.assertEqual(c['compatibility_writes'],[]);self.assertEqual(c['services'],[])
    q=i+1;v=(q-128)&255;o=c['output']
    self.assertEqual(o['flags'],dict(sign=bool(v&128),zero=v==0,auxiliary_carry=True,parity=v.bit_count()%2==0,carry=q<128))
    self.assertEqual((o['a'],o['b']*256+o['c'],o['h']*256+o['l']),(q,0x1d8c,0x1d8c+i))
    self.assertEqual((o['d'],o['e']),(c['input']['d'],c['input']['e']))
  self.assertEqual(count,635)

 def test_real_services_chronology_and_exact_INT_data(self):
  count=0
  for name,cs in self.cases.items():
   for c in cs:
    if not c['flush']:continue
    count+=1;old=self.flushes[name,c['entry_step']]
    self.assertEqual(c['index'],127)
    self.assertEqual(c['logical_writes'],[[0x20b0,c['input']['c']],[0x1e0b,c['input']['c']],[0x1e0c,128],[0x2060,0x1d],[0x205f,0x8c],[0x1e0c,0],[0x2066,0x1c],[0x2065,0xa2]])
    self.assertEqual([s['call_state']['c']for s in c['services']],[26,21])
    dma,write=c['services'];self.assertEqual(dma['dma_after'],0x1d8c);self.assertEqual(write['dma_before'],0x1d8c);self.assertEqual(write['dma_after'],0x1d8c)
    self.assertEqual(c['post_dma'],0x1d8c)
    self.assertEqual((dma['call_state']['d']*256+dma['call_state']['e'],write['call_state']['d']*256+write['call_state']['e']),(0x1d8c,0x1ca2))
    self.assertEqual(dma['records'],[]);self.assertEqual(len(write['records']),1)
    r=write['records'][0];self.assertEqual(len(bytes.fromhex(r['data_hex'])),128);self.assertEqual(hashlib.sha256(bytes.fromhex(r['data_hex'])).hexdigest(),r['sha256'])
    # Independent record producer/window from corrected Pass22 witnesses.
    historical=old['record']
    self.assertEqual(r['data_hex'].upper(),historical['data'].upper())
    self.assertEqual((r['file'],r['record'],r['dma']),(historical['file']['name'],historical['record'],historical['dma']))
  self.assertEqual(count,5)

 def test_flush_return_state_and_derived_stack_last_writers(self):
  raw=(IMAGES/'PLI.COM').read_bytes()
  sites=[(2,0xf21,0x428),(4,0x334,0x1abb),(10,0x19c3,0x1b0f)]
  for depth,site,target in sites:self.assertEqual(raw[site:site+3],bytes([0xcd,target&255,target>>8]))
  self.assertEqual(raw[0x19bb:0x19bd],bytes([0xc5,0xd5]))
  for cs in self.cases.values():
   for c in cs:
    if not c['flush']:continue
    o=c['output'];self.assertEqual((o['a'],o['b']*256+o['c'],o['d']*256+o['e'],o['h']*256+o['l']),(0,21,0x1ca2,0))
    self.assertEqual(o['flags'],dict(sign=False,zero=True,auxiliary_carry=True,parity=True,carry=False))
    final=dict(c['compatibility_writes']);S=c['input']['sp']
    words={d:0x100+site+3 for d,site,_ in sites}|{6:0x1c15,8:0x1ca2}
    for depth,v in words.items():self.assertEqual(final[(S-depth)&65535]|(final[(S-depth+1)&65535]<<8),v)

 def test_external_records_filesystem_accounting_and_hierarchy(self):
  singles=self.reports['single-hybrid-summary']['sources'];cum=self.reports['cumulative-hybrid-summary']['sources']
  for s in singles:
   n=COUNTS[s['source']];self.assertEqual((s['invocations'],s['host_transitions'],s['host_bdos_services']),(n,n,2*(n//128)))
   self.assertTrue(s['full_filesystem_identity']);self.assertTrue(s['file_events_identity']);self.assertEqual(s['termination'],'warm_boot')
  expected={'MINIMAL':[9,0,16,16,18,16,14,128],'FIZZBUZ':[35,0,93,107,140,109,113,384],'PICTURE':[11,0,19,22,28,25,19,128]}
  for c in cum:
   r=c['result'];counts=c['transition_counts_7C1B_7BBF_7B7A_7BA2_7AD5_7B64_7ABF_0EF6']
   self.assertEqual(counts,expected[r['source']]);self.assertEqual(sum(counts),r['host_transitions']);self.assertEqual(r['host_bdos_services'],2*(COUNTS[r['source']]//128))
   self.assertTrue(c['no_replaced_guest_bodies']);self.assertTrue(c['all_entry_resume_states_and_external_state_exact'])

 def test_dependency_separation_and_scope_unchanged(self):
  host=(ROOT/'lib/pli80_host/int_emitter.ml').read_text()
  for name in ['I8080','Runner','Cpm.','Cpu.']:self.assertNotIn(name,host)
  catalog=json.loads((ROOT/'research/annotated-assembly/procedures.json').read_text())
  p=next(p for p in catalog['procedures']if p['id']=='PLI.COM+0EF6')
  self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'))
  self.assertFalse(json.loads((REPORT/'fidelity.json').read_text())['contract_completeness_changed'])

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--images',type=Path,required=True)
 args,rest=parser.parse_known_args();IMAGES=args.images
 unittest.main(argv=[__file__]+rest)
