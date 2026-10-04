#!/usr/bin/env python3
"""Bounded recursive composition checked against all corrected natural CALL windows."""
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

REPORT=ROOT/'research/host-compiler/pass-19'
CAPTURES={'MINIMAL':ROOT/'_build/minimal-baseline/capture','FIZZBUZ':ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture','PICTURE':ROOT/'_build/discriminator-pass-15/selected-capture'}
BOUNDS={'PLI1.OVL+7C1B':(0x7C1B,0x7D53),'PLI1.OVL+7BBF':(0x7BBF,0x7C1B),'PLI1.OVL+7B7A':(0x7B7A,0x7BA2)}

def effects(r):
 rows={w['step_index']:w for w in r['own_witnesses']}
 for child in r['nested_returns'].values():rows.update({w['step_index']:w for w in child['memory_witnesses']})
 return [rows[k]for k in sorted(rows)]

class NativeRecursivePassNineteenTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='atlas-native7c1b-',dir='/tmp')as temp:
   out=Path(temp)/'experiment'
   run=subprocess.run(['dune','exec','pli80-native-7c1b','--','--toolchain',str(IMAGES),'--output-dir',str(out)],cwd=ROOT,capture_output=True,text=True)
   if run.returncode:raise RuntimeError(run.stdout+run.stderr)
   cls.reports={n:json.loads((out/(n+'.json')).read_text())for n in ['recursive-cases','shadow-summary','single-hybrid-summary','cumulative-hybrid-summary']}
  cls.records={name:gather(path,BOUNDS,include_nested_returns=True)for name,path in CAPTURES.items()}
  cls.cases={s['source']:s['members']for s in cls.reports['recursive-cases']['sources']}
  cls.rows={name:{r['entry']['step_index']:r for r in rs['PLI1.OVL+7C1B']}for name,rs in cls.records.items()}

 def test_all_live_reports_and_independent_natural_returns(self):
  for name,value in self.reports.items():self.assertEqual(value,json.loads((REPORT/(name+'.json')).read_text()))
  for name,cs in self.cases.items():
   rows=self.rows[name];self.assertEqual(len(cs),len(rows));self.assertEqual(len(cs),{'MINIMAL':16,'FIZZBUZ':96,'PICTURE':21}[name])
   self.assertEqual(Counter(c['caller']for c in cs),Counter(coord(r['call']['origin'])for r in rows.values()))
   for c in cs:
    r=rows[c['entry_step']];verify_return(r['call'],r['ret'],r['relation'])
    self.assertEqual(c['input'],r['entry']['before']);self.assertEqual(c['output'],r['ret']['after']);self.assertEqual(c['return_step'],r['ret']['step_index'])
    self.assertEqual(c['output']['sp'],(c['input']['sp']+2)&65535);self.assertEqual(c['output']['pc'],r['call']['pc']+3)

 def test_actual_invocation_forest_and_ordered_native_subtrees(self):
  forest=load(REPORT/'invocation-forest.json')
  for name,cs in self.cases.items():
   rows=self.rows[name];by_entry={c['entry_step']:c for c in cs};parents={}
   for step,r in rows.items():
    calls=[w for w in r['own_witnesses']if coord(w.get('target_origin'))=='PLI1.OVL+7C1B']
    for w in calls:parents[w['step_index']+1]=step
   self.assertEqual(len(cs)-len(parents),{'MINIMAL':9,'FIZZBUZ':35,'PICTURE':11}[name])
   def check(t,step):
    r=rows[step];c=by_entry[step];s=r['entry']['before']
    self.assertEqual((t['position'],t['entry_SP'],t['entry_HL'],t['entry_DE']),(s['c'],s['sp'],s['h']*256+s['l'],s['d']*256+s['e']))
    self.assertEqual(t['returned_A'],r['ret']['after']['a']);self.assertEqual(t['final_frame'],c['tree']['final_frame'])
    self.assertEqual(t['return_site'],r['ret']['origin']['offset'])
    calls=[w for w in r['own_witnesses']if coord(w.get('target_origin'))=='PLI1.OVL+7C1B']
    self.assertEqual(len(t['children']),len(calls))
    for child,w in zip(t['children'],calls):
     self.assertEqual(child['depth'],t['depth']+1);check(child,w['step_index']+1)
   for c in cs:
    self.assertEqual(c['parent_entry_step'],parents.get(c['entry_step']))
    check(c['tree'],c['entry_step'])
   expected=next(r for r in forest['sources']if r['source']==name)
   self.assertEqual(expected['roots'],len(cs)-len(parents));self.assertEqual(expected['callers'],dict(Counter(c['caller']for c in cs)))
   self.assertEqual([m['parent_entry_step']for m in expected['members']],[c['parent_entry_step']for c in cs])

 def test_inherited_frame_bytes_and_full_logical_write_chronology(self):
  for name,cs in self.cases.items():
   for c in cs:
    r=self.rows[name][c['entry_step']];s=c['input'];f=(s['sp']-5)&65535;t=c['tree']
    self.assertEqual(t['initial_frame'],[s['c'],s['l'],s['h'],s['l'],s['h']]);self.assertEqual(t['frame'],f)
    logical=[];latest={}
    for w in effects(r):
     site=w['origin']['offset']
     for q in w['writes']:
      latest[q['address']]=(site,q['new_value'])
      if w['control']['kind']=='call' or site in (0x7C48,0x7BDF,0x7BE3):continue
      if site==0x7C1E and q['address']!=(w['before']['sp']-1)&65535:continue
      logical.append((q['address'],q['new_value'],site))
    self.assertEqual(logical,[(w['address'],w['value'],w['writer'])for w in c['writes']])
    digest=hashlib.sha256(';'.join(f'{a:04X}:{v:02X}'for a,v,_ in logical).encode()).hexdigest();self.assertEqual(digest,c['logical_writes_sha256'])
    self.assertEqual(t['final_frame'],[latest[(f+i)&65535][1]for i in range(5)])
    self.assertEqual(c['output']['h']*256+c['output']['l'],t['final_frame'][3]+256*t['final_frame'][4])

 def test_every_recursive_stack_cell_has_exact_last_writer(self):
  report=load(REPORT/'stack-compatibility.json')
  for name,cs in self.cases.items():
   retain=next(r for r in report['sources']if r['source']==name)
   for c,member in zip(cs,retain['members']):
    r=self.rows[name][c['entry_step']];latest={q['address']:(w,q['new_value'])for w in effects(r)for q in w['writes']}
    self.assertEqual(set(latest),{q['address']for q in c['final_writers']})
    self.assertEqual(member['cells'],[q for q in c['final_writers']if q['address']>0xAE50])
    for q in c['final_writers']:
     w,value=latest[q['address']];self.assertEqual((q['writer'],q['value']),(w['origin']['offset'],value))
     depth=sum(other['entry']['step_index']<=w['step_index']<=other['ret']['step_index']
       for other in self.rows[name].values()if c['entry_step']<=other['entry']['step_index']<=c['return_step'])-1
     self.assertEqual(q['depth'],depth)
     if q['kind']=='compatibility' and w['control']['kind']=='call':
      self.assertEqual(q['value'],(w['pc']+3)&255 if q['address']==w['sp_after']else(w['pc']+3)>>8)
    original={q['address']:q['new_value']for q in r['call']['writes']}
    self.assertFalse(set(original)&set(latest));self.assertEqual(original,{q['address']:q['value']for q in r['ret']['reads']})

 def test_each_path_exact_helper_and_recursive_call_order(self):
  for name,cs in self.cases.items():
   for c in cs:
    r=self.rows[name][c['entry_step']];t=c['tree'];path=t['path']
    expected={'mapped0A':[0x7C25,0x7C37],'mapped17_predecessor0A':[0x7C25,0x7CC8,0x7CE3,0x7CF5],
     'mapped17_fallback':[0x7C25,0x7CC8,0x7CD5],'mapped1E':[0x7C25,0x7C5D,0x7C6C,0x7C71,0x7CAB],
     'default':[0x7C25,0x7D06,0x7D13]+[s for _ in t['children']for s in (0x7D2D,0x7D3A)]}[path]
    calls=[w for w in r['own_witnesses']if w['control']['kind']=='call'];self.assertEqual([w['origin']['offset']for w in calls],expected)
    helpers={h['site']:h for h in t['helpers']if h['kind']not in ('balance',)}
    for call in calls:
     site=call['origin']['offset'];child=r['nested_returns'][call['step_index']];verify_return(call,child['ret'],child['relation'])
     if site not in helpers:continue
     h=helpers[site];ws=child['memory_witnesses'];read=lambda o:next(w for w in ws if w['origin']['offset']==o)['reads']
     self.assertEqual(h['position'],call['before']['c'])
     if h['kind']=='mapping':
      self.assertEqual((read(0x7A5A)[0]['address'],read(0x7A5A)[0]['value']),(0xAA1F+h['position'],h['index']));self.assertEqual(read(0x7A61)[0]['value'],h['mapped'])
     if h['kind']=='auxiliary_read':
      self.assertEqual(read(0x7AB6)[0]['value'],h['index']);self.assertEqual((read(0x7ABD)[0]['address'],read(0x7ABD)[0]['value']),(h['address'],h['value']));self.assertEqual(read(0x7AAD)[1]['value'],h['discarded_high'])
     if h['kind']=='auxiliary_write':
      self.assertEqual(read(0x7B3D)[0]['value'],h['index']);self.assertEqual(read(0x7B34)[1]['value'],h['discarded_high']);q=next(w for w in ws if w['origin']['offset']==0x7B47)['writes'][0];self.assertEqual((q['address'],q['new_value']),(h['address'],h['value']))
    if path=='default':
     attr=next(h for h in t['helpers']if h['kind']=='attribute');aux=next(h for h in t['helpers']if h['kind']=='auxiliary_read')
     self.assertEqual(len(t['children']),attr['low3']);self.assertEqual(t['returned_A'],aux['value']);self.assertEqual(t['final_frame'][1],0)
    if path=='mapped17_fallback':
     self.assertEqual(next(h for h in t['helpers']if h['site']==0x7CC8)['mapped'],5)
     self.assertFalse(t['children']);self.assertFalse(any(h['kind']=='auxiliary_write'for h in t['helpers']));self.assertEqual(t['final_frame'][4],c['input']['h'])

 def test_flag_producers_special_wrap_and_clamp_scope(self):
  special=[]
  for name,cs in self.cases.items():
   for c in cs:
    r=self.rows[name][c['entry_step']];ws=r['own_witnesses'];offsets={w['origin']['offset']for w in ws}
    for producer,branch in [(0x7C2D,0x7C2F),(0x7C52,0x7C53),(0x7CBC,0x7CBE),(0x7CCB,0x7CCD),(0x7C82,0x7C83),(0x7C97,0x7C98)]:
     if branch in offsets:
      p=next(w for w in ws if w['origin']['offset']==producer);b=next(w for w in ws if w['origin']['offset']==branch);self.assertEqual(p['after']['flags'],b['before']['flags'])
    for b in [w for w in ws if w['origin']['offset']==0x7D22]:
     p=ws[ws.index(b)-1];self.assertEqual(p['origin']['offset'],0x7D21);self.assertEqual(p['after']['flags'],b['before']['flags']);self.assertEqual(b['control']['taken'],p['reads'][0]['value']==0)
    if c['tree']['path']=='mapped1E':
     special.append(c);at=lambda o:next(w for w in ws if w['origin']['offset']==o)
     self.assertEqual([n['returned_A']for n in c['tree']['children']],[1,15]);self.assertFalse(at(0x7C83)['control']['taken']);self.assertFalse(at(0x7C98)['control']['taken'])
     self.assertEqual(at(0x7C94)['writes'][0]['new_value'],16);self.assertEqual(at(0x7C9F)['writes'][0]['new_value'],15)
     expected=at(0x7C97)['after']['flags'].copy();expected['carry']=False;self.assertEqual(c['output']['flags'],expected)
  self.assertEqual(len(special),1);self.assertEqual(special[0]['tree']['mapped'],30)

 def test_hierarchical_counts_no_double_count_and_record_identity(self):
  singles={s['source']:s for s in self.reports['single-hybrid-summary']['sources']}
  for row in self.reports['cumulative-hybrid-summary']['sources']:
   name=row['result']['source'];cs=self.cases[name];roots=[c for c in cs if c['parent_entry_step']is None]
   external={}
   for key in ('PLI1.OVL+7BBF','PLI1.OVL+7B7A'):
    rs=self.records[name][key]
    external[key]=[r for r in rs if not any(c['entry_step']<r['entry']['step_index']<c['return_step']for c in roots)]
   self.assertEqual(row['native_7C1B_roots'],len(roots));self.assertEqual(row['external_native_7BBF'],len(external['PLI1.OVL+7BBF']));self.assertEqual(row['external_native_7B7A'],len(external['PLI1.OVL+7B7A']))
   self.assertEqual(row['external_native_7BBF'],0);self.assertEqual(row['external_native_7B7A'],{'MINIMAL':16,'FIZZBUZ':93,'PICTURE':19}[name]);self.assertEqual(row['result']['host_transitions'],len(roots)+row['external_native_7B7A'])
   self.assertEqual(singles[name]['host_transitions'],len(roots));self.assertTrue(row['INT_REL_records_match']);self.assertTrue(row['no_historical_replaced_body_execution'])
   expected=[];path=CAPTURES[name]
   for chunk in load(path/'event-witnesses.json')['chunks']:
    for e in load(path/'event-witnesses/chunks'/f"{chunk['id']:06d}.json")['events']:
     if e['type']=='bdos_record'and e['operation']=='write_record':expected.append(dict(file=e['file']['name'],record=e['record'],sha256=hashlib.sha256(bytes.fromhex(e['data'])).hexdigest()))
   self.assertEqual(row['record_oracles'],expected)
   for k in ['REL_size','REL_sha256','PASS1','PASS2','END_COMPILATION','termination']:self.assertEqual(row['result'][k],singles[name][k])

 def test_characterization_depth_counts_and_actual_stack_footprint(self):
  audit=load(REPORT/'path-characterization.json')
  for name,cs in self.cases.items():
   report=next(s for s in audit['sources']if s['source']==name);self.assertEqual(report['path_classes'],dict(Counter(c['tree']['path']for c in cs)))
   def walk(t):return [t]+[n for child in t['children']for n in walk(child)]
   roots=[c for c in cs if c['parent_entry_step']is None];nodes=[n for c in roots for n in walk(c['tree'])]
   self.assertEqual(len(nodes),len(cs));self.assertEqual(report['maximum_recursive_edges'],max(n['depth']for n in nodes));self.assertEqual(report['helpers_inside_native_roots'],dict(Counter(h['kind']for n in nodes for h in n['helpers'])))
   actual=max(c['input']['sp']-q['address']for c in roots for w in effects(self.rows[name][c['entry_step']])for q in w['writes']if 0xAE50<q['address']<c['input']['sp'])
   self.assertEqual(report['maximum_stack_bytes_below_root_entry'],actual)

 def test_scope_remains_partial_and_host_is_not_a_cpu(self):
  fidelity=load(REPORT/'fidelity.json');self.assertEqual(fidelity['divergences'],[]);self.assertEqual(fidelity['fidelity_debt'],[]);self.assertFalse(fidelity['Runner_changed']);self.assertTrue(fidelity['hierarchical_cumulative_replacement_verified'])
  text=(ROOT/'lib/pli80_host/recursive_mapped.ml').read_text()
  for forbidden in ['Cpu.step','Decode.','source_name','entry_step','sha256','max_depth','max_nodes','Hashtbl']:self.assertNotIn(forbidden,text)
  procedures=load(ROOT/'research/annotated-assembly/procedures.json')
  # The catalog is independently authoritative; the host scope does not promote it.
  p=next(p for p in procedures['procedures']if p['id']=='PLI1.OVL+7C1B')
  self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images.resolve();unittest.main(argv=[sys.argv[0],*rest])
