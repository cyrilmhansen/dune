#!/usr/bin/env python3
"""Native root versus independently corrected Pass42 windows, not snapshot semantics."""
import argparse,json,subprocess,tempfile,unittest,hashlib
from pathlib import Path
from collections import Counter
from check_causal_5929_pass_42 import ROOT,BOUNDS,CAPTURES,gather_selected,SOFTWARE,analyze,acquisition_compatibility
class NativeAcquisitionTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='pass43-',dir=ROOT/'_build')as temp:
   out=Path(temp)/'results'
   p=subprocess.run(['dune','exec','pli80-native-acquisition-parent','--','--toolchain',str(IMAGES),'--output-dir',str(out)],cwd=ROOT,capture_output=True,text=True)
   if p.returncode:raise AssertionError(p.stdout[-1000:]+p.stderr[-2000:])
   cls.reports={p.stem:json.loads(p.read_text())for p in out.glob('*.json')}
   proof=ROOT/'_build/host-compiler-pass-43/latest-proof';proof.mkdir(parents=True,exist_ok=True)
   for p in out.glob('*.json'):(proof/p.name).write_bytes(p.read_bytes())
  cls.rows={s:gather_selected(c,BOUNDS,include_nested_returns=True,software_callees=SOFTWARE)for s,c in CAPTURES.items()};cls.proof=analyze(cls.rows,IMAGES)
  cls.image=(IMAGES/'PLI1.OVL').read_bytes()
 def groups(self):return self.reports['natural-cases']['sources']
 def test_all_thirteen_independent_corrected_windows(self):
  self.assertEqual({g['source']:len(g['members'])for g in self.groups()},{'MINIMAL':1,'FIZZBUZ':11,'PICTURE':1})
  for g in self.groups():
   expected=self.rows[g['source']]['PLI1.OVL+5929']
   self.assertEqual([c['entry_step']for c in g['members']],[r['entry']['step_index']for r in expected])
   for c,r in zip(g['members'],expected):
    self.assertEqual(c['input'],r['entry']['before']);self.assertEqual(c['output'],r['ret']['after']);self.assertEqual(c['return_step'],r['ret']['step_index']);self.assertEqual(c['caller'],'PLI1.OVL+6240')
 def test_selection_constructor_and_reuse_routes(self):
  routes=Counter(c['result']['selection']for g in self.groups()for c in g['members']);self.assertEqual(routes,{'null':10,'reuse':3})
  for g in self.groups():
   for c in g['members']:
    writers={w for a,v,w,d,k in c['journal']}
    self.assertEqual(0x6674 in writers,c['result']['selection']=='null')
    if c['result']['selection']=='null':self.assertIn(0x689a,writers)
 def test_final_full_memory_flags_and_external_state_proof(self):
  for g in self.groups():
   for c in g['members']:
    for k in ['entry_memory_sha256','post_memory_sha256','entry_filesystem_sha256','post_filesystem_sha256']:self.assertEqual(len(c[k]),64)
    self.assertEqual(c['output']['sp'],c['input']['sp']+2);self.assertEqual(c['output']['pc'],0x8443)
    self.assertEqual(set(c['output']['flags']),{'sign','zero','parity','auxiliary_carry','carry'})
 def test_constructor_N2_and_stack_last_writer_ancestry(self):
  for g in self.groups():
   expected=self.proof[g['source']]['PLI1.OVL+5929']
   for c,q in zip(g['members'],expected):
    # Pass42 independently derives every surviving byte from instruction operands,
    # register sources and actual stack depth. Compare native derivation directly.
    last={a:(v,w)for a,v,w,d,k in c['journal']}
    for x in q['stack']:
     self.assertEqual(last[c['input']['sp']+x['relative_address']],(x['value'],int(x['writer'].split('+')[1],16)+0x2200 if x['writer'].startswith('PLI1')else int(x['writer'].split('+')[1],16)+0x100))
 def test_fresh_selector_is_not_gate_return(self):
  for g in self.groups():
   for c in g['members']:
    values=[v for a,v,w,d,k in c['journal']if a==0xa628 and w==0x7b4b];self.assertEqual(len(values),1);self.assertIn(values[0],[2,5]);self.assertNotIn(values[0],[0,255])
 def test_required_resident_contract_matches_Pass41(self):
  self.assertEqual(len(acquisition_compatibility(self.rows)),13)
  self.assertEqual(Counter(c['result']['acquisition']for g in self.groups()for c in g['members']),{'literal_first_byte':9,'descriptor_match':4})
 def test_single_and_cumulative_goldens_with_factual_accounting(self):
  golden={'MINIMAL':(256,'7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119'),'FIZZBUZ':(768,'68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203'),'PICTURE':(256,'c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1')}
  for c in self.reports['single-hybrid-summary']['sources']+[q['result']for q in self.reports['cumulative-hybrid-summary']['sources']]:
   self.assertEqual((c['REL_size'],c['REL_sha256']),golden[c['source']]);self.assertTrue(c['PASS1']and c['PASS2']and c['END_COMPILATION']);self.assertEqual(c['termination'],'warm_boot')
  for q in self.reports['cumulative-hybrid-summary']['sources']:
   self.assertEqual(sum(q['transition_vector']),q['result']['host_transitions']);self.assertEqual(q['transition_vector'][0],{'MINIMAL':1,'FIZZBUZ':11,'PICTURE':1}[q['result']['source']]);self.assertEqual(q['guest_instructions_removed'],q['pre_guest_instructions']-q['result']['actual_guest_instructions']);self.assertGreater(q['guest_instructions_removed'],0)
 def test_host_remains_algorithmic_and_archaeology_unchanged(self):
  text=(ROOT/'lib/pli80_host/acquisition_parent.ml').read_text()
  for forbidden in ['Cpu.step','Cpu8080','Runner.','Cpm.','source_name','entry_step','sha256']:self.assertNotIn(forbidden,text)
  base=subprocess.check_output(['git','show','6e267e64bdfea5b9418e69952d43e9c4bea996ed:research/annotated-assembly/procedures.json'])
  self.assertEqual(json.loads(base),json.loads((ROOT/'research/annotated-assembly/procedures.json').read_text()))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',required=True,type=Path);args,rest=p.parse_known_args();IMAGES=args.images
 unittest.main(argv=[__file__]+rest)
