#!/usr/bin/env python3
"""Fresh native proofs against corrected ordinary roots and exact witnesses."""
import argparse, hashlib, json, subprocess, tempfile, unittest
from collections import Counter
from pathlib import Path
from check_minimal_pass_3 import gather
from check_minimal_pass_2 import coord
from procedure_evidence_packet import verify_return
from check_fizzbuz_pass_14 import checker_input
from check_minimal_pass_7 import validate_d53
from check_native_7d53_pass_25 import derive, FILES
ROOT=Path(__file__).resolve().parents[2]
REPORT=ROOT/'research/host-compiler/pass-25'
CAPTURES={'MINIMAL':ROOT/'_build/minimal-baseline/capture','FIZZBUZ':ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture','PICTURE':ROOT/'_build/discriminator-pass-15/selected-capture'}
KEY='PLI1.OVL+7D53';BOUNDS={KEY:(0x7d53,0x7e46)}
class NativeRangePassTwentyFiveTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='pass25-native-',dir=ROOT/'_build')as d:
   out=Path(d)/'proofs'
   p=subprocess.run(['dune','exec','pli80-native-range-processing','--','--toolchain',str(IMAGES),'--output-dir',str(out)],cwd=ROOT,capture_output=True,text=True)
   if p.returncode:raise RuntimeError(p.stdout+p.stderr)
   cls.raw=json.loads((out/'root-cases.json').read_text())
   cls.reports=derive(cls.raw,*[json.loads((out/(n+'.json')).read_text())for n in ['shadow-summary','single-hybrid-summary','cumulative-hybrid-summary']])
  cls.rows={name:gather(capture,BOUNDS,include_nested_returns=True)[KEY]for name,capture in CAPTURES.items()}
  cls.cases={s['source']:s['cases']for s in cls.raw['sources']}
 def test_fresh_durable_proofs(self):
  for n in FILES:self.assertEqual(self.reports[n],json.loads((REPORT/(n+'.json')).read_text()))
  self.assertEqual(sum(map(len,self.cases.values())),121)
  for name,cs in self.cases.items():
   rows={r['entry']['step_index']:r for r in self.rows[name]}
   self.assertEqual(set(rows),{c['entry_step']for c in cs})
   self.assertEqual(Counter(coord(r['call']['origin'])for r in rows.values()),Counter(c['caller']for c in cs))
   for c in cs:
    r=rows[c['entry_step']];verify_return(r['call'],r['ret'],r['relation'])
    self.assertEqual((c['input'],c['output'],c['return_step']),(r['entry']['before'],r['ret']['after'],r['ret']['step_index']))
    self.assertEqual(c['output']['sp'],c['input']['sp']+2)
    self.assertEqual(c['output']['pc'],r['call']['pc']+3)
 def test_early_ABI_and_immediate_flag_producers(self):
  for name,cs in self.cases.items():
   rows={r['entry']['step_index']:r for r in self.rows[name]}
   for c in cs:
    r=rows[c['entry_step']];own=r['own_witnesses'];at=lambda x:next(w for w in own if coord(w['origin'])==f'PLI1.OVL+{x:04X}')
    cells=dict(c['entry_cells']);begin,end=cells[0xae34],cells[0xae35]
    expected='equal'if begin==end else'gate'if cells[0xaa1a]&1 else'work'
    self.assertEqual(c['path'],expected)
    if expected=='equal':
     self.assertEqual(c['output']['a'],end);self.assertEqual(c['output']['flags'],at(0x7d59)['after']['flags']);self.assertEqual(c['journal'],[])
    if expected=='gate':
     cmp=at(0x7d59)['after']['flags'];gate=cells[0xaa1a]
     self.assertEqual(c['output']['a'],(gate>>1)|(int(cmp['carry'])<<7))
     self.assertEqual(c['output']['flags'],cmp|dict(carry=bool(gate&1)))
     self.assertEqual(c['journal'],[])
    if expected!='work':
     for register in 'bcde':self.assertEqual(c['output'][register],c['input'][register])
     self.assertEqual(c['output']['h']*256+c['output']['l'],0xae34)
 def test_reverse_PSW_sentinel_and_child_composition(self):
  for name,cs in self.cases.items():
   rows={r['entry']['step_index']:r for r in self.rows[name]}
   for c in cs:
    r=rows[c['entry_step']];own=r['own_witnesses']
    pushes=[w for w in own if coord(w['origin'])=='PLI1.OVL+7D82']
    self.assertEqual(len(pushes),len(c['reverse']))
    for w,it in zip(pushes,c['reverse']):
     f=w['before']['flags'];psw=int(f['sign'])*128+int(f['zero'])*64+int(f['auxiliary_carry'])*16+int(f['parity'])*4+2+int(f['carry'])
     self.assertEqual((it['cursor'],it['psw']),(w['before']['a'],psw))
     self.assertEqual([(a['address'],a['new_value'])for a in w['writes']],[(c['input']['sp']-1,it['cursor']),(c['input']['sp']-2,psw)])
    directs=[w for w in own if coord(w['origin'])=='PLI1.OVL+7D9D']
    native=[n for n in c['children']if n['operation']=='recursive']
    self.assertEqual(len(directs),len(native))
    for w,n in zip(directs,native):
     child=r['nested_returns'].get(w['step_index'],r['nested_returns'].get(str(w['step_index'])))
     self.assertEqual(n['input'],{**w['after']})
     self.assertEqual(n['output'],child['ret']['after'])
    if c['path']=='work':
     self.assertIsNone(c['reverse'][-1]['direct_result']);self.assertEqual(c['reverse'][-1]['cursor'],c['reverse'][-1]['sentinel'])
 def test_forward_attribute_channels_and_emission_order(self):
  expected={2:['mapped_byte','mapped_word_low','mapped_word_high'],3:['mapped_byte','secondary_auxiliary','primary_auxiliary'],4:['mapped_byte','primary_auxiliary'],6:['mapped_byte','mapped_word_low','mapped_word_high']}
  for name,cs in self.cases.items():
   rows={r['entry']['step_index']:r for r in self.rows[name]}
   for c in cs:
    r=rows[c['entry_step']];view,iv=checker_input(r)
    validate_d53(view,iv) # Preserve the established Pass7 correlation checker.
    own=r['own_witnesses'];attrs=[w for w in own if coord(w['origin'])=='PLI1.OVL+7DDE']
    self.assertEqual([w['before']['a']for w in attrs],[f['attribute']for f in c['forward']])
    emitted=[]
    calls=[w for w in own if w['control']['kind']=='call'and w['control']['taken']]
    self.assertEqual(len(calls),len(c['children']))
    for n,w in zip(c['children'],calls):
     self.assertEqual(w['pc'],n['site']+0x2200)
     self.assertEqual(w['after'],n['input'])
     if n['operation']=='emitter':emitted.append(n['input']['c'])
     if n['operation']in('word_low','word_high'):
      # Bind a wrapper's suppressed nested emitter to its actual corrected child.
      # Exact ordinal CALL ancestry, never equal-valued register matching.
      child=r['nested_returns'].get(w['step_index'],r['nested_returns'].get(str(w['step_index'])))
      site=0xa052 if n['operation']=='word_low'else 0xa05b
      emitted.append(next(q for q in child['memory_witnesses']if q['pc']==site)['before']['c'])
    self.assertEqual(emitted,[v for f in c['forward']for _,v in f['channels']])
    for f in c['forward']:self.assertEqual([n for n,_ in f['channels']],expected[f['attribute']])
    if c['path']=='work':
     self.assertEqual(c['output']['a'],dict(c['entry_cells'])[0xae34])
     self.assertEqual(c['output']['flags'],[w for w in own if coord(w['origin'])=='PLI1.OVL+7DBD'][-1]['after']['flags'])
 def test_external_services_hierarchy_and_goldens(self):
  totals={'MINIMAL':(21,1),'FIZZBUZ':(77,3),'PICTURE':(23,1)}
  for s in self.reports['cumulative-hybrid-summary']['sources']:
   r=s['result'];name=r['source'];vector=s['transition_vector']
   self.assertEqual(vector[0],totals[name][0]);self.assertEqual(r['host_bdos_services'],totals[name][1]*2)
   self.assertEqual(vector[1:3],[0,0]);self.assertEqual(vector[-2:],[0,0])
   self.assertTrue(r['PASS1']and r['PASS2']and r['END_COMPILATION']);self.assertEqual(r['termination'],'warm_boot')
  services=self.reports['host-service-summary']['internal_roots'];self.assertEqual(len(services),1)
  root=services[0];self.assertEqual(root['source'],'FIZZBUZ');dma,write=root['services']
  self.assertEqual((dma['call_state']['c'],write['call_state']['c']),(26,21))
  self.assertEqual((dma['dma_after'],write['dma_before']),(0x1d8c,0x1d8c));self.assertEqual(write['call_state']['d']*256+write['call_state']['e'],0x1ca2)
  record=write['records'][0];self.assertEqual(hashlib.sha256(bytes.fromhex(record['data_hex'])).hexdigest(),record['sha256'])
 def test_fidelity_scope_and_isolation(self):
  core=(ROOT/'lib/pli80_host/range_processing.ml').read_text()
  for forbidden in ['Runner','I8080','Cpm.','Cpu.step','source_name','sha256','max_iterations','cycle_detector']:self.assertNotIn(forbidden,core)
  p=next(p for p in json.loads((ROOT/'research/annotated-assembly/procedures.json').read_text())['procedures']if p['id']==KEY)
  self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'))
  f=json.loads((REPORT/'fidelity.json').read_text());self.assertIsNone(f['fidelity_debt']);self.assertIsNone(f['pragmatic_divergence'])
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);args,rest=p.parse_known_args();IMAGES=args.images
 unittest.main(argv=[__file__]+rest)
