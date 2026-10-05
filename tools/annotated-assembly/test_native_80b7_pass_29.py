#!/usr/bin/env python3
"""Independent corrected return windows for the native packed gate/saved parent."""
import argparse,json,subprocess,tempfile,unittest
from collections import Counter
from pathlib import Path
from check_minimal_pass_2 import coord
from check_minimal_pass_3 import gather
from procedure_evidence_packet import ROOT,verify_return
REPORT=ROOT/'research/host-compiler/pass-29'
CAPTURES={'MINIMAL':ROOT/'_build/minimal-baseline/capture','FIZZBUZ':ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture','PICTURE':ROOT/'_build/discriminator-pass-15/selected-capture'}
BOUNDS={'PLI1.OVL+7EC0':(0x7ec0,0x7ed7),'PLI1.OVL+80B7':(0x80b7,0x80ca),'PLI1.OVL+2511':(0x2511,0x252b),'PLI1.OVL+240A':(0x240a,0x24f1),'PLI1.OVL+80EF':(0x80ef,0x810b),'PLI1.OVL+80CA':(0x80ca,0x80ef)}
FILES=['gate-cases','natural-cases','shadow-summary','single-hybrid-summary','cumulative-hybrid-summary']
class NativeTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='pass29-',dir=ROOT/'_build')as temp:
   out=Path(temp)/'results'
   p=subprocess.run(['dune','exec','pli80-native-attribute-gate','--','--toolchain',str(IMAGES),'--output-dir',str(out)],cwd=ROOT,capture_output=True,text=True)
   if p.returncode:raise RuntimeError(p.stdout+p.stderr)
   cls.reports={n:json.loads((out/(n+'.json')).read_text())for n in FILES}
  cls.rows={s:gather(p,BOUNDS,include_nested_returns=True)for s,p in CAPTURES.items()}
  cls.gates={s['source']:s['members']for s in cls.reports['gate-cases']['sources']}
  cls.roots={s['source']:s['members']for s in cls.reports['natural-cases']['sources']}
 def test_fresh_shadows_hybrids_and_proof_count_rejections(self):
  for n,r in self.reports.items():self.assertEqual(r,json.loads((REPORT/(n+'.json')).read_text()))
 def test_all_corrected_calls_states_and_exact_ordered_writers(self):
  for key,members in [('PLI1.OVL+7EC0',self.gates),('PLI1.OVL+80B7',self.roots)]:
   for source,cs in members.items():
    rows=self.rows[source][key];self.assertEqual(len(rows),len(cs))
    self.assertEqual(Counter(c['caller']for c in cs),Counter(coord(r['call']['origin'])for r in rows))
    bystep={r['entry']['step_index']:r for r in rows}
    for c in cs:
     r=bystep[c['entry_step']];verify_return(r['call'],r['ret'],r['relation'])
     self.assertEqual(c['input'],r['entry']['before']);self.assertEqual(c['output'],r['ret']['after']);self.assertEqual(c['return_step'],r['ret']['step_index'])
     inclusive=r['own_witnesses']+sum((q['memory_witnesses']for q in r['nested_returns'].values()),[]);inclusive.sort(key=lambda w:w['step_index'])
     actual=[(q['address'],q['new_value'],w['pc'])for w in inclusive for q in w['writes']]
     self.assertEqual({a:(v,w)for a,v,w in actual},{w['address']:(w['value'],w['writer'])for w in c['journal']})
     def logical(w,q):
      if w['control']['kind']=='call':return False
      pc=w['pc']
      if pc in [0x9e48,0x9ddf,0x9de3,0x9f82,0x1abb,0x1abc,0x9d09]:return False
      return pc!=0x9e1e or q['address']==((w['before']['sp']-1)&65535)
     actual_logical=[(q['address'],q['new_value'],w['pc'])for w in inclusive for q in w['writes']if logical(w,q)]
     self.assertEqual(actual_logical,[(w['address'],w['value'],w['writer'])for w in c['journal']if w['kind']=='logical'])
     ws={w['origin']['offset']:w for w in r['own_witnesses']}
     for child in c['children']:
      call=ws[child['site']];nested=r['nested_returns'][call['step_index']];verify_return(call,nested['ret'],nested['relation'])
      self.assertEqual(child['input'],call['after']);self.assertEqual(child['output'],nested['ret']['after'])
 def test_gate_direct_table_pair_rotates_flags_and_JNC(self):
  for source,cs in self.gates.items():
   rs={r['entry']['step_index']:r for r in self.rows[source]['PLI1.OVL+7EC0']}
   for c in cs:
    ws={w['origin']['offset']:w for w in rs[c['entry_step']]['own_witnesses']};q=c['result'];packed=q['packed'];call=bool(packed&128)
    self.assertEqual(ws[0x7ec4]['reads'],[dict(address=0xae57,value=c['input']['c']),dict(address=0xae58,value=q['discarded_high'])])
    self.assertEqual(ws[0x7ecd]['reads'],[dict(address=0x1b4b+c['input']['c'],value=packed)])
    self.assertEqual(ws[0x7ece]['after']['a'],q['rotated']);self.assertEqual(q['rotated'],((packed<<1)&255)|(packed>>7))
    self.assertEqual(ws[0x7ece]['after']['flags']['carry'],call)
    self.assertEqual(ws[0x7ecf]['after']['a'],packed);self.assertEqual(ws[0x7ecf]['after']['flags']['carry'],call)
    for name in ['sign','zero','auxiliary_carry','parity']:
     self.assertEqual(ws[0x7ece]['after']['flags'][name],c['input']['flags'][name]);self.assertEqual(ws[0x7ecf]['after']['flags'][name],c['input']['flags'][name])
    self.assertEqual(ws[0x7ed0]['control']['taken'],not call);self.assertEqual(q['route'],'call'if call else'skip')
    self.assertEqual([w['origin']['offset']for w in rs[c['entry_step']]['own_witnesses']if w['control']['kind']=='call'],[0x7ed3]if call else[])
    if not call:
     self.assertEqual((c['output']['a'],c['output']['b'],c['output']['c'],c['output']['h']*256+c['output']['l']),(packed,0x1b,0x4b,0x1b4b+c['input']['c']))
     self.assertEqual((c['output']['d'],c['output']['e']),(c['input']['d'],c['input']['e']))
     self.assertEqual(c['output']['flags'],{**c['input']['flags'],'carry':False})
    else:
     child=c['children'][0];self.assertEqual(child['input']['a'],packed);self.assertEqual((child['input']['b'],child['input']['c']),(0x1b,0x4b))
     self.assertEqual(c['output'],{**child['output'],'sp':c['output']['sp'],'pc':c['output']['pc']})
 def test_saved_pair_fresh_read_and_final_child_channel(self):
  for source,cs in self.roots.items():
   rs={r['entry']['step_index']:r for r in self.rows[source]['PLI1.OVL+80B7']}
   for c in cs:
    r=rs[c['entry_step']];ws={w['origin']['offset']:w for w in r['own_witnesses']}
    self.assertEqual([w['origin']['offset']for w in r['own_witnesses']if w['control']['kind']=='call'],[0x80bf,0x80c6])
    for pair in [0x80bb,0x80c2]:self.assertEqual([q['address']for q in ws[pair]['reads']],[0xae6b,0xae6c])
    self.assertGreater(ws[0x80c2]['step_index'],r['nested_returns'][ws[0x80bf]['step_index']]['ret']['step_index'])
    fresh=ws[0x80c2]['reads'][0]['value'];self.assertEqual(fresh,c['result']['fresh_input']);self.assertEqual(c['children'][1]['input']['c'],fresh)
    self.assertEqual(c['children'][1]['input']['b'],c['children'][0]['output']['b'])
    self.assertEqual(c['output'],{**c['children'][1]['output'],'pc':c['output']['pc'],'sp':c['output']['sp']})
 def test_nested_operation_accounting_is_actual_capture_chronology(self):
  for source,cs in self.roots.items():
   rs={r['entry']['step_index']:r for r in self.rows[source]['PLI1.OVL+80B7']}
   for c in cs:
    r=rs[c['entry_step']];inclusive=r['own_witnesses']+sum((q['memory_witnesses']for q in r['nested_returns'].values()),[])
    calls=[w for w in inclusive if w['control']['kind']=='call'and w['control']['taken']and w['origin'].get('image',{}).get('name')=='PLI1.OVL']
    for key,target in [('8048',0xa248),('7EC0',0xa0c0),('7D53',0x9f53),('7E5F',0xa05f)]:
     self.assertEqual(c['nested'][key],sum(w['control']['target']==target for w in calls))
    self.assertEqual(c['nested']['recursive_nodes'],sum(w['control']['target']==0x9e1b for w in calls))
    self.assertEqual(c['nested']['emitters'],sum(w['control']['target']==0xff6 for w in calls))
 def test_static_CALL_and_surviving_stack_residue_are_derived(self):
  image=(IMAGES/'PLI1.OVL').read_bytes()
  self.assertEqual(image[0x7ed3:0x7ed6],bytes.fromhex('CD539F'))
  self.assertEqual(image[0x80bf:0x80c2],bytes.fromhex('CD48A2'));self.assertEqual(image[0x80c6:0x80c9],bytes.fromhex('CDC0A0'))
  for source,cs in self.roots.items():
   for c in cs:
    last={w['address']:w for w in c['journal']};s=c['input']['sp']
    self.assertEqual((last[s-2]['value'],last[s-1]['value'],last[s-2]['writer']),(0xc9,0xa2,0xa2c6))
  for source,cs in self.gates.items():
   for c in cs:
    if c['result']['route']=='skip':self.assertFalse(any(w['kind']=='compatibility'for w in c['journal']))
    else:
     last={w['address']:w for w in c['journal']};s=c['input']['sp']
     self.assertEqual((last[s-2]['value'],last[s-1]['value'],last[s-2]['writer']),(0xd6,0xa0,0xa0d3))
 def test_hierarchy_counts_services_and_golden_results(self):
  details=[]
  for operation,members in [('gate',self.gates),('saved',self.roots)]:
   for source,cs in members.items():
    for c in cs:
     if c['service_details']:
      details.append(dict(operation=operation,source=source,caller=c['caller'],entry_step=c['entry_step'],return_step=c['return_step'],services=c['service_details']))
  self.assertEqual(details,json.loads((REPORT/'host-service-summary.json').read_text())['nested_services'])
  for source,cs in self.roots.items():
   cumulative=next(s for s in self.reports['cumulative-hybrid-summary']['sources']if s['result']['source']==source)
   gates=self.gates[source];inside=lambda step:any(c['entry_step']<step<c['return_step']for c in cs)
   self.assertEqual(cumulative['transition_vector'][:2],[len(cs),sum(not inside(c['entry_step'])for c in gates)])
   self.assertEqual(cumulative['host_bdos_services'],{'MINIMAL':2,'FIZZBUZ':6,'PICTURE':2}[source])
   for summary in [cumulative['result']]+[q['result']for q in self.reports['single-hybrid-summary']['sources']if q['result']['source']==source]:
    self.assertTrue(summary['PASS1']and summary['PASS2']and summary['END_COMPILATION']);self.assertEqual(summary['termination'],'warm_boot')
 def test_next_boundary_audit_uses_corrected_local_ownership(self):
  audit=json.loads((REPORT/'boundary-assessment.json').read_text())
  for source,rows in self.rows.items():
   for key in ['PLI1.OVL+2511','PLI1.OVL+240A','PLI1.OVL+80EF','PLI1.OVL+80CA']:
    q=audit['corrected_observations'][source][key];rs=rows[key]
    self.assertEqual(q['calls'],len(rs));self.assertEqual(q['own_occurrences'],sum(len(r['own_witnesses'])for r in rs))
    self.assertEqual(q['callers'],dict(Counter(coord(r['call']['origin'])for r in rs)))
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--images',type=Path,required=True);args,rest=parser.parse_known_args();IMAGES=args.images
 unittest.main(argv=[__file__]+rest)
