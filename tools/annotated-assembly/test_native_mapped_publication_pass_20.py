#!/usr/bin/env python3
"""All natural mapped-publication shadows, independent corrected witnesses and hybrids."""
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

REPORT=ROOT/'research/host-compiler/pass-20'
CAPTURES={'MINIMAL':ROOT/'_build/minimal-baseline/capture','FIZZBUZ':ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture','PICTURE':ROOT/'_build/discriminator-pass-15/selected-capture'}
BOUNDS={'PLI1.OVL+7AD5':(0x7AD5,0x7AF0),'PLI1.OVL+7BA2':(0x7BA2,0x7BBF),'PLI1.OVL+7C1B':(0x7C1B,0x7D53),'PLI1.OVL+7BBF':(0x7BBF,0x7C1B),'PLI1.OVL+7B7A':(0x7B7A,0x7BA2)}
FILES=['mapped-publication-cases','recycle-cases','shadow-summary','single-hybrid-summary','hierarchical-hybrid-summary','cumulative-hybrid-summary']

def effects(r):
 rows={w['step_index']:w for w in r['own_witnesses']}
 for child in r['nested_returns'].values():rows.update({w['step_index']:w for w in child['memory_witnesses']})
 return [rows[k]for k in sorted(rows)]

class NativeMappedPublicationPassTwentyTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='atlas-native-mapped-',dir='/tmp')as temp:
   out=Path(temp)/'experiment'
   run=subprocess.run(['dune','exec','pli80-native-mapped-publication','--','--toolchain',str(IMAGES),'--output-dir',str(out)],cwd=ROOT,capture_output=True,text=True)
   if run.returncode:raise RuntimeError(run.stdout+run.stderr)
   cls.reports={n:json.loads((out/(n+'.json')).read_text())for n in FILES}
  cls.records={name:gather(path,BOUNDS,include_nested_returns=True)for name,path in CAPTURES.items()}
  cls.cases={key:{s['source']:s['members']for s in cls.reports[file]['sources']}for key,file in [('PLI1.OVL+7AD5','mapped-publication-cases'),('PLI1.OVL+7BA2','recycle-cases')]}
  cls.rows={name:{key:{r['entry']['step_index']:r for r in rs}for key,rs in groups.items()}for name,groups in cls.records.items()}
  cls.output_records={};cls.entry_scratch={};cls.collisions={};cls.old_destinations={}
  for name,path in CAPTURES.items():
   entry_cases={c['entry_step']:c for key in cls.cases for c in cls.cases[key][name]}
   entries=set(entry_cases);table={};cls.old_destinations[name]={}
   scratch={a:0 for a in (0xae33,0xae34,0xae3c,0xae3d,0xae4a,0xae4b)}
   cls.entry_scratch[name]={};cls.output_records[name]=[];cls.collisions[name]=Counter()
   for chunk in load(path/'event-witnesses.json')['chunks']:
    for event in load(path/'event-witnesses/chunks'/f"{chunk['id']:06d}.json")['events']:
     if event['type']=='instruction':
      event=event['witness']
      if event['step_index']in entries:
       step=event['step_index'];cls.entry_scratch[name][step]=scratch.copy()
       q=entry_cases[step]['result'];address=q.get('child',q)['address'];cls.old_destinations[name][step]=table.get(address)
      if event['pc']in (0x9cd5,0x9da2)and coord(event['origin'])not in cls.cases:cls.collisions[name][coord(event['origin'])]+=1
      for w in event['writes']:
       if w['address']in scratch:scratch[w['address']]=w['new_value']
       if 0xaab4<=w['address']<=0xabb3:table[w['address']]=w['new_value']
     elif event['type']=='bdos_record'and event['operation']=='write_record':
      cls.output_records[name].append(dict(file=event['file']['name'],record=event['record'],sha256=hashlib.sha256(bytes.fromhex(event['data'])).hexdigest()))

 def test_live_reports_exact_and_all_corrected_invocations_retained(self):
  for name,report in self.reports.items():self.assertEqual(report,json.loads((REPORT/(name+'.json')).read_text()))
  expected={'PLI1.OVL+7AD5':dict(MINIMAL=34,FIZZBUZ=247,PICTURE=50),'PLI1.OVL+7BA2':dict(MINIMAL=16,FIZZBUZ=107,PICTURE=22)}
  for key,by_source in self.cases.items():
   for name,cs in by_source.items():
    rows=self.rows[name][key];self.assertEqual(len(cs),len(rows));self.assertEqual(len(cs),expected[key][name])
    self.assertEqual(Counter(c['caller']for c in cs),Counter(coord(r['call']['origin'])for r in rows.values()))
    for c in cs:
     r=rows[c['entry_step']];verify_return(r['call'],r['ret'],r['relation'])
     self.assertEqual(c['input'],r['entry']['before']);self.assertEqual(c['output'],r['ret']['after']);self.assertEqual(c['return_step'],r['ret']['step_index'])
     self.assertEqual(c['output']['sp'],(c['input']['sp']+2)&65535);self.assertEqual(c['output']['pc'],r['call']['pc']+3)
     self.assertEqual(dict(c['entry_scratch']),self.entry_scratch[name][c['entry_step']])

 def test_standalone_publication_order_and_fresh_lookup(self):
  for name,cs in self.cases['PLI1.OVL+7AD5'].items():
   for c in cs:
    r=self.rows[name]['PLI1.OVL+7AD5'][c['entry_step']];q=c['result'];at=lambda o:next(w for w in r['own_witnesses']if w['origin']['offset']==o)
    self.assertEqual(q['position'],c['input']['c']);self.assertEqual(q['value'],c['input']['e'])
    self.assertEqual(at(0x7ADB)['reads'],[dict(address=0xae3c,value=q['position']),dict(address=0xae3d,value=q['discarded_high'])])
    self.assertEqual(at(0x7AE4)['reads'],[dict(address=0xaa1f+q['position'],value=q['index'])])
    self.assertEqual(q['address'],0xaab4+q['index']);self.assertNotEqual(q['address'],0xaa1f+q['position'])
    w=at(0x7AEE)['writes'][0];self.assertEqual((w['address'],w['new_value']),(q['address'],q['value']));self.assertEqual(cls_old:=self.old_destinations[name][c['entry_step']],q['old_value']);self.assertIsNotNone(cls_old)
    self.assertEqual([(w['address'],w['value'])for w in c['writes']],[(0xae3d,q['value']),(0xae3c,q['position']),(q['address'],q['value'])])
    self.assertEqual([w['origin']['offset']for w in r['own_witnesses']if w['writes']],[0x7AD8,0x7ADA,0x7AEE])

 def test_recycle_neighbor_read_then_independent_second_map_read(self):
  for name,cs in self.cases['PLI1.OVL+7BA2'].items():
   for c in cs:
    r=self.rows[name]['PLI1.OVL+7BA2'][c['entry_step']];q=c['result'];at=lambda o:next(w for w in r['own_witnesses']if w['origin']['offset']==o)
    self.assertEqual(q['position'],c['input']['c']);self.assertEqual(q['old_word'],dict(c['entry_scratch'])[0xae33]+256*dict(c['entry_scratch'])[0xae34])
    self.assertEqual(at(0x7BAA)['reads'],[dict(address=0xae33,value=q['old_word']&255),dict(address=0xae34,value=q['old_word']>>8)])
    for site,carrier in [(0x7BA6,q['initial_carrier']),(0x7BB1,q['fresh_carrier'])]:
     self.assertEqual(at(site)['reads'],[dict(address=0xae4a,value=carrier&255),dict(address=0xae4b,value=carrier>>8)])
    calls=[w for w in r['own_witnesses']if w['control']['kind']=='call'];self.assertEqual([w['origin']['offset']for w in calls],[0x7BAE])
    call=calls[0];self.assertEqual((call['before']['c'],call['before']['d'],call['before']['e']),(q['position'],q['old_word']>>8,q['old_word']&255))
    child=r['nested_returns'][call['step_index']];verify_return(call,child['ret'],child['relation'])
    child_case=next(m for m in self.cases['PLI1.OVL+7AD5'][name]if m['entry_step']==call['step_index']+1)
    self.assertEqual(child_case['parent_entry_step'],c['entry_step']);self.assertEqual(child_case['result'],q['child'])
    pub=next(w for w in child['memory_witnesses']if w['origin']['offset']==0x7AEE)
    self.assertLess(pub['step_index'],at(0x7BB1)['step_index']);self.assertLess(at(0x7BB1)['step_index'],at(0x7BBA)['step_index'])
    self.assertEqual(at(0x7BBA)['reads'],[dict(address=0xaa1f+(q['fresh_carrier']&255),value=q['fresh_index'])])
    self.assertEqual(at(0x7BBB)['writes'][0]['new_value'],q['fresh_index']);self.assertEqual(q['child']['value'],q['old_word']&255)
    # Equal observed indices are a consequence at this scope, not a cached read.
    self.assertEqual(q['child']['index'],q['fresh_index'])
    self.assertEqual([w['phase']for w in c['writes']],['recycle_position','mapped_write_value','mapped_write_position','mapped_publication','recycle_cached_index'])

 def test_all_logical_writes_and_return_flag_producers(self):
  for key,by_source in self.cases.items():
   for name,cs in by_source.items():
    for c in cs:
     r=self.rows[name][key][c['entry_step']];ws=effects(r)
     actual=[(q['address'],q['new_value'])for w in ws if w['control']['kind']!='call'for q in w['writes']]
     logical=[(w['address'],w['value'])for w in c['writes']];self.assertEqual(actual,logical)
     self.assertEqual(hashlib.sha256(';'.join(f'{a:04X}:{v:02X}'for a,v in actual).encode()).hexdigest(),c['logical_writes_sha256'])
     expected=c['input']['flags'].copy();expected['carry']=False;self.assertEqual(c['output']['flags'],expected)
     producer=next(w for w in r['own_witnesses']if w['origin']['offset']==(0x7AEA if key.endswith('7AD5')else 0x7BB9))
     self.assertEqual(producer['after']['flags'],c['output']['flags'])
     q=c['result'];o=c['output'];i=c['input']
     if key.endswith('7AD5'):
      self.assertEqual((o['a'],o['b']*256+o['c'],o['d']*256+o['e'],o['h']*256+o['l']),(q['value'],q['index'],i['d']*256+i['e'],q['address']))
     else:self.assertEqual((o['a'],o['b']*256+o['c'],o['d']*256+o['e'],o['h']*256+o['l']),(q['fresh_index'],0xaa1f,q['old_word'],0xaa1f+(q['fresh_carrier']&255)))

 def test_exact_abi_residue_and_original_return_writer_consumer(self):
  for key,by_source in self.cases.items():
   for name,cs in by_source.items():
    for c in cs:
     r=self.rows[name][key][c['entry_step']];ws=effects(r);s=c['input']['sp']
     if key.endswith('7AD5'):self.assertEqual(c['compatibility_writes'],[]);self.assertFalse(any(w['control']['kind']=='call'for w in ws))
     else:
      self.assertEqual(c['compatibility_writes'],[[(s-2)&65535,0xb1],[(s-1)&65535,0x9d]])
      call=next(w for w in ws if w['origin']['offset']==0x7BAE);self.assertEqual(bytes.fromhex(call['bytes']),bytes.fromhex('CDD59C'))
      latest={q['address']:(w,q['new_value'])for w in ws for q in w['writes']}
      for a,v in c['compatibility_writes']:
       w,value=latest[a];self.assertEqual((w['origin']['offset'],value),(0x7BAE,v));self.assertEqual(call['sp_after'],(s-2)&65535)
     self.assertEqual({q['address']:q['new_value']for q in r['call']['writes']},{q['address']:q['value']for q in r['ret']['reads']})
     self.assertFalse({s,(s+1)&65535}&{q['address']for w in ws for q in w['writes']})

 def test_standalone_hierarchical_cumulative_counts_and_records(self):
  singles={s['source']:s for s in self.reports['single-hybrid-summary']['sources']}
  hierarchy={s['result']['source']:s for s in self.reports['hierarchical-hybrid-summary']['sources']}
  for row in self.reports['cumulative-hybrid-summary']['sources']:
   name=row['result']['source'];rs=self.records[name]
   roots=[r for r in rs['PLI1.OVL+7C1B']if coord(r['call']['origin'])=='PLI1.OVL+7D9D']
   parents=rs['PLI1.OVL+7BA2'];windows=[(r['entry']['step_index'],r['ret']['step_index'])for r in roots+parents]
   outside=lambda r:not any(a<r['entry']['step_index']<b for a,b in windows)
   self.assertEqual(row['native_7C1B_roots'],len(roots));self.assertEqual(row['external_native_7BBF'],len([r for r in rs['PLI1.OVL+7BBF']if outside(r)]))
   self.assertEqual(row['external_native_7B7A'],len([r for r in rs['PLI1.OVL+7B7A']if outside(r)]))
   self.assertEqual(row['external_native_7AD5'],len([r for r in rs['PLI1.OVL+7AD5']if outside(r)]));self.assertEqual(row['native_7BA2'],len(parents));self.assertEqual(row['logical_7AD5_inside_7BA2'],len(parents))
   self.assertEqual(singles[name]['host_transitions'],len(rs['PLI1.OVL+7AD5']))
   self.assertEqual(hierarchy[name]['result']['host_transitions'],len(rs['PLI1.OVL+7AD5']));self.assertEqual(hierarchy[name]['native_7BA2'],len(parents))
   self.assertEqual(row['result']['host_transitions'],sum(row[k]for k in ['native_7C1B_roots','external_native_7BBF','external_native_7B7A','native_7BA2','external_native_7AD5']))
   self.assertEqual(row['record_oracles'],self.output_records[name]);self.assertTrue(row['INT_REL_records_match']);self.assertTrue(row['no_historical_replaced_body_execution'])
   self.assertEqual(row['logical_7C1B_nodes'],len(rs['PLI1.OVL+7C1B']));self.assertEqual(row['logical_Packed_inside_7C1B'],len(rs['PLI1.OVL+7BBF']))
   self.assertEqual(row['logical_Balance_inside_7C1B'],len(rs['PLI1.OVL+7B7A'])-row['external_native_7B7A'])
   for k in ['REL_size','REL_sha256','PASS1','PASS2','END_COMPILATION','termination']:self.assertEqual(row['result'][k],singles[name][k]);self.assertEqual(row['result'][k],hierarchy[name]['result'][k])

 def test_canonical_dispatch_collision_and_scope_unchanged(self):
  self.assertGreater(sum(self.collisions['FIZZBUZ'].values()),0)
  fidelity=load(REPORT/'fidelity.json');self.assertEqual(fidelity['divergences'],[]);self.assertEqual(fidelity['fidelity_debt'],[]);self.assertFalse(fidelity['Runner_changed'])
  for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']:
   if p['id']in self.cases:self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract='complete'))
  source=(ROOT/'lib/pli80_host/mapped_publication.ml').read_text()
  for forbidden in ['Cpu','Runner','Decode','sha256','entry_step','source_name']:self.assertNotIn(forbidden,source)
  self.assertIn('fresh_carrier=State.word memory 0xae4a',source);self.assertIn('fresh_index=State.read memory',source)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images.resolve();unittest.main(argv=[sys.argv[0],*rest])
