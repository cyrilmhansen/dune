#!/usr/bin/env python3
"""Independent corrected leaf witnesses, complete live shadows and seven-operation hybrids."""
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
from procedure_evidence_packet import ROOT, verify_return

REPORT=ROOT/'research/host-compiler/pass-21'
CAPTURES={'MINIMAL':ROOT/'_build/minimal-baseline/capture','FIZZBUZ':ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture','PICTURE':ROOT/'_build/discriminator-pass-15/selected-capture'}
BOUNDS={'PLI1.OVL+7B64':(0x7B64,0x7B7A),'PLI1.OVL+7ABF':(0x7ABF,0x7AD5),'PLI1.OVL+7AD5':(0x7AD5,0x7AF0),'PLI1.OVL+7BA2':(0x7BA2,0x7BBF),'PLI1.OVL+7C1B':(0x7C1B,0x7D53),'PLI1.OVL+7BBF':(0x7BBF,0x7C1B),'PLI1.OVL+7B7A':(0x7B7A,0x7BA2)}
FILES=['high-attribute-cases','second-auxiliary-cases','shadow-summary','single-hybrid-summary','cumulative-hybrid-summary']
COUNTS={'PLI1.OVL+7B64':dict(MINIMAL=16,FIZZBUZ=109,PICTURE=25),'PLI1.OVL+7ABF':dict(MINIMAL=14,FIZZBUZ=113,PICTURE=19)}

class NativeAttributeAuxiliaryPassTwentyOneTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='atlas-native-attribute-',dir='/tmp')as temp:
   out=Path(temp)/'experiment'
   run=subprocess.run(['dune','exec','pli80-native-attribute-auxiliary','--','--toolchain',str(IMAGES),'--output-dir',str(out)],cwd=ROOT,capture_output=True,text=True)
   if run.returncode:raise RuntimeError(run.stdout+run.stderr)
   cls.reports={n:json.loads((out/(n+'.json')).read_text())for n in FILES}
  cls.records={name:gather(path,BOUNDS,include_nested_returns=True)for name,path in CAPTURES.items()}
  cls.cases={key:{s['source']:s['members']for s in cls.reports[file]['sources']}for key,file in [('PLI1.OVL+7B64','high-attribute-cases'),('PLI1.OVL+7ABF','second-auxiliary-cases')]}
  cls.rows={name:{key:{r['entry']['step_index']:r for r in rs}for key,rs in groups.items()}for name,groups in cls.records.items()}
  cls.output_records={};cls.entry_scratch={};cls.collisions={}
  for name,path in CAPTURES.items():
   entries={c['entry_step']for key in cls.cases for c in cls.cases[key][name]}
   scratch={a:0 for a in (0xae47,0xae48,0xae3b,0xae3c)}
   cls.entry_scratch[name]={};cls.output_records[name]=[];cls.collisions[name]=Counter()
   for chunk in load(path/'event-witnesses.json')['chunks']:
    for event in load(path/'event-witnesses/chunks'/f"{chunk['id']:06d}.json")['events']:
     if event['type']=='instruction':
      w=event['witness']
      if w['step_index']in entries:cls.entry_scratch[name][w['step_index']]=scratch.copy()
      if w['pc']in (0x9d64,0x9cbf)and coord(w['origin'])not in cls.cases:cls.collisions[name][coord(w['origin'])]+=1
      for q in w['writes']:
       if q['address']in scratch:scratch[q['address']]=q['new_value']
     elif event['type']=='bdos_record'and event['operation']=='write_record':
      cls.output_records[name].append(dict(file=event['file']['name'],record=event['record'],sha256=hashlib.sha256(bytes.fromhex(event['data'])).hexdigest()))

 def test_live_reports_exact_all_invocations_and_original_returns(self):
  for name,report in self.reports.items():self.assertEqual(report,json.loads((REPORT/(name+'.json')).read_text()))
  for key,by_source in self.cases.items():
   for name,cs in by_source.items():
    rows=self.rows[name][key];self.assertEqual(len(cs),len(rows));self.assertEqual(len(cs),COUNTS[key][name])
    self.assertEqual(Counter(c['caller']for c in cs),Counter(coord(r['call']['origin'])for r in rows.values()))
    for c in cs:
     r=rows[c['entry_step']];verify_return(r['call'],r['ret'],r['relation'])
     self.assertEqual(c['input'],r['entry']['before']);self.assertEqual(c['output'],r['ret']['after']);self.assertEqual(c['return_step'],r['ret']['step_index'])
     self.assertEqual(c['output']['sp'],(c['input']['sp']+2)&65535);self.assertEqual(c['output']['pc'],r['call']['pc']+3)
     self.assertEqual(dict(c['entry_scratch']),self.entry_scratch[name][c['entry_step']]);self.assertIsNone(c['parent_entry_step'])
     self.assertEqual(c['compatibility_writes'],[])
     ws=r['own_witnesses'];self.assertFalse(r['nested_returns']);self.assertFalse(any(w['control']['kind']=='call'for w in ws))
     self.assertEqual({q['address']:q['new_value']for q in r['call']['writes']},{q['address']:q['value']for q in r['ret']['reads']})
     self.assertFalse({c['input']['sp'],(c['input']['sp']+1)&65535}&{q['address']for w in ws for q in w['writes']})

 def test_high_attribute_actual_reads_masks_three_rotates_final_flags(self):
  for name,cs in self.cases['PLI1.OVL+7B64'].items():
   for c in cs:
    r=self.rows[name]['PLI1.OVL+7B64'][c['entry_step']];q=c['result'];at=lambda o:next(w for w in r['own_witnesses']if w['origin']['offset']==o)
    self.assertEqual(q['byte_index'],c['input']['c']);self.assertEqual(q['address'],0x1b4b+q['byte_index'])
    self.assertEqual(at(0x7B68)['reads'],[dict(address=0xae47,value=q['byte_index']),dict(address=0xae48,value=q['discarded_ae48'])])
    self.assertEqual(q['discarded_ae48'],dict(c['entry_scratch'])[0xae48])
    self.assertEqual(at(0x7B71)['reads'],[dict(address=q['address'],value=q['packed_byte'])])
    self.assertEqual(at(0x7B72)['before']['a'],q['packed_byte']);self.assertEqual(at(0x7B72)['after']['a'],q['after_mask']);self.assertEqual(q['after_mask'],q['packed_byte']&252)
    self.assertFalse(at(0x7B72)['after']['flags']['carry'])
    value=q['after_mask'];carry=False
    for n,site in enumerate([0x7B74,0x7B75,0x7B76]):
     w=at(site);self.assertEqual((w['before']['a'],w['before']['flags']['carry']),(value,carry))
     value,carry=(value>>1)|(128 if carry else 0),bool(value&1)
     self.assertEqual((w['after']['a'],w['after']['flags']['carry']),(value,carry))
     self.assertEqual((q['shifts'][n],q['shift_carries'][n]),(value,carry))
    final=at(0x7B77);self.assertEqual(final['before']['a'],value);self.assertEqual(q['high3'],value&7)
    self.assertEqual(c['output']['flags'],final['after']['flags'])
    self.assertEqual(c['output']['flags'],dict(sign=False,zero=q['high3']==0,parity=q['high3'].bit_count()%2==0,auxiliary_carry=bool(value&8),carry=False))
    self.assertEqual(c['output']['flags']['auxiliary_carry'],bool(q['packed_byte']&64))
    self.assertEqual((c['output']['a'],c['output']['b']*256+c['output']['c'],c['output']['h']*256+c['output']['l']),(q['high3'],0x1b4b,q['address']))
    self.assertEqual((c['output']['d'],c['output']['e']),(c['input']['d'],c['input']['e']))

 def test_second_auxiliary_fresh_map_neighbor_and_table_flags_preserved(self):
  for name,cs in self.cases['PLI1.OVL+7ABF'].items():
   for c in cs:
    r=self.rows[name]['PLI1.OVL+7ABF'][c['entry_step']];q=c['result'];at=lambda o:next(w for w in r['own_witnesses']if w['origin']['offset']==o)
    self.assertEqual(q['position'],c['input']['c']);self.assertEqual(q['address'],0xad9d+q['index'])
    self.assertEqual(q['discarded_high'],dict(c['entry_scratch'])[0xae3c])
    self.assertEqual(at(0x7AC3)['reads'],[dict(address=0xae3b,value=q['position']),dict(address=0xae3c,value=q['discarded_high'])])
    self.assertEqual(at(0x7ACC)['reads'],[dict(address=0xaa1f+q['position'],value=q['index'])])
    self.assertEqual(at(0x7AD3)['reads'],[dict(address=q['address'],value=q['value'])])
    self.assertLess(at(0x7ACC)['step_index'],at(0x7AD3)['step_index'])
    expected=c['input']['flags'].copy();expected['carry']=False
    self.assertEqual(c['output']['flags'],expected);self.assertEqual(at(0x7AD2)['after']['flags'],expected)
    self.assertEqual(at(0x7AD3)['after']['flags'],expected) # Returned data does not produce NZPA.
    o=c['output'];self.assertEqual((o['a'],o['b']*256+o['c'],o['h']*256+o['l']),(q['value'],q['index'],q['address']))
    self.assertEqual((o['d'],o['e']),(c['input']['d'],c['input']['e']))

 def test_write_chronology_full_memory_proofs_and_distributions(self):
  audit=load(REPORT/'characterization.json')
  for key,by_source in self.cases.items():
   for name,cs in by_source.items():
    fields=['packed_byte','high3']if key.endswith('7B64')else ['index','value']
    summary=audit[key][name];self.assertEqual(summary['calls'],len(cs))
    self.assertEqual(summary['callers'],dict(Counter(c['caller']for c in cs)))
    for field in fields:self.assertEqual(summary[field],{str(k):v for k,v in sorted(Counter(c['result'][field]for c in cs).items())})
    for c in cs:
     ws=self.rows[name][key][c['entry_step']]['own_witnesses']
     actual=[(q['address'],q['new_value'])for w in ws for q in w['writes']]
     self.assertEqual(actual,[(w['address'],w['value'])for w in c['writes']]);self.assertEqual(len(actual),1)
     self.assertEqual(actual[0],(0xae47,c['input']['c'])if key.endswith('7B64')else(0xae3b,c['input']['c']))
     self.assertEqual(hashlib.sha256(';'.join(f'{a:04X}:{v:02X}'for a,v in actual).encode()).hexdigest(),c['logical_writes_sha256'])
     for field in ['entry_memory_sha256','final_memory_sha256']:self.assertEqual(len(c[field]),64)
  self.assertTrue(self.reports['shadow-summary']['all_passed'])

 def test_six_singles_and_cumulative_exact_hierarchy_records_and_outputs(self):
  singles={s['source']:s for s in self.reports['single-hybrid-summary']['sources']}
  for row in self.reports['cumulative-hybrid-summary']['sources']:
   name=row['result']['source'];rs=self.records[name]
   roots=[r for r in rs['PLI1.OVL+7C1B']if coord(r['call']['origin'])=='PLI1.OVL+7D9D']
   parents=rs['PLI1.OVL+7BA2'];windows=[(r['entry']['step_index'],r['ret']['step_index'])for r in roots+parents]
   outside=lambda r:not any(a<r['entry']['step_index']<b for a,b in windows)
   self.assertEqual(row['native_7C1B_roots'],len(roots));self.assertEqual(row['native_7BA2'],len(parents));self.assertEqual(row['logical_7AD5_inside_7BA2'],len(parents))
   for entry,key in [('7BBF','external_native_7BBF'),('7B7A','external_native_7B7A'),('7AD5','external_native_7AD5'),('7B64','native_7B64'),('7ABF','native_7ABF')]:
    self.assertEqual(row[key],len([r for r in rs['PLI1.OVL+'+entry]if outside(r)]))
   self.assertEqual(row['logical_7C1B_nodes'],len(rs['PLI1.OVL+7C1B']));self.assertEqual(row['logical_Packed_inside_7C1B'],len(rs['PLI1.OVL+7BBF']))
   self.assertEqual(row['logical_Balance_inside_7C1B'],len(rs['PLI1.OVL+7B7A'])-row['external_native_7B7A'])
   keys=['native_7C1B_roots','external_native_7BBF','external_native_7B7A','native_7BA2','external_native_7AD5','native_7B64','native_7ABF']
   self.assertEqual(row['result']['host_transitions'],sum(row[k]for k in keys))
   self.assertEqual(row['record_oracles'],self.output_records[name]);self.assertTrue(row['INT_REL_records_match']);self.assertTrue(row['all_entry_resume_memory_states_match']);self.assertTrue(row['no_historical_replaced_body_execution'])
   for label,entry in [('high_attribute','7B64'),('second_auxiliary','7ABF')]:
    single=singles[name][label];self.assertEqual(single['host_transitions'],len(rs['PLI1.OVL+'+entry]))
    for k in ['REL_size','REL_sha256','PASS1','PASS2','END_COMPILATION','termination']:self.assertEqual(single[k],row['result'][k])
  self.assertTrue(self.reports['single-hybrid-summary']['no_fallback']);self.assertTrue(self.reports['cumulative-hybrid-summary']['no_fallback'])

 def test_scope_separation_and_next_boundary_remains_explicit(self):
  fidelity=load(REPORT/'fidelity.json');self.assertEqual(fidelity['divergences'],[]);self.assertEqual(fidelity['fidelity_debt'],[]);self.assertFalse(fidelity['Runner_changed']);self.assertFalse(fidelity['Native_dispatch_changed'])
  for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']:
   if p['id']in self.cases:self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract='complete'))
  for filename in ['mapped_lookup.ml','auxiliary.ml']:
   source=(ROOT/'lib/pli80_host'/filename).read_text()
   for forbidden in ['Cpu','Runner','Decode','sha256','entry_step','source_name']:self.assertNotIn(forbidden,source)
  assessment=load(REPORT/'emission-boundary-assessment.json');self.assertEqual(assessment['recommended_pass_22'],'B: focused resident PLI.COM+0EF6 archaeology')
  self.assertFalse(assessment['implements_emitters']);self.assertFalse(assessment['pragmatic_divergence_authorized'])

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images.resolve();unittest.main(argv=[sys.argv[0],*rest])
