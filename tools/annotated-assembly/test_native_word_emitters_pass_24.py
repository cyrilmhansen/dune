#!/usr/bin/env python3
"""Fresh host proofs joined to independently corrected natural CALL/RET captures."""
import argparse
import hashlib
import json
import subprocess
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from check_minimal_pass_3 import gather
from check_minimal_pass_2 import coord
from procedure_evidence_packet import verify_return

ROOT=Path(__file__).resolve().parents[2]
REPORT=ROOT/'research/host-compiler/pass-24'
CAPTURES={'MINIMAL':ROOT/'_build/minimal-baseline/capture',
 'FIZZBUZ':ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture',
 'PICTURE':ROOT/'_build/discriminator-pass-15/selected-capture'}
FILES=['mapped-word-cases','low-word-emitter-cases','high-word-emitter-cases',
 'shadow-summary','single-hybrid-summary','hierarchical-summary','cumulative-hybrid-summary']
COUNTS={'MINIMAL':(11,7,7),'FIZZBUZ':(91,42,42),'PICTURE':(18,12,12)}
BOUNDS={'PLI1.OVL+7A79':(0x7a79,0x7a93),'PLI1.OVL+7E46':(0x7e46,0x7e56),'PLI1.OVL+7E56':(0x7e56,0x7e5f)}

def at(r,offset):return next(w for w in r['own_witnesses']if coord(w['origin'])==f'PLI1.OVL+{offset:04X}')
def pair(s,h,l):return s[h]*256+s[l]

class NativeWordEmittersPassTwentyFourTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  with tempfile.TemporaryDirectory(prefix='pass24-native-',dir=ROOT/'_build')as directory:
   out=Path(directory)/'proofs'
   p=subprocess.run(['dune','exec','pli80-native-word-emitters','--','--toolchain',str(IMAGES),'--output-dir',str(out)],cwd=ROOT,capture_output=True,text=True)
   if p.returncode:raise RuntimeError(p.stdout+p.stderr)
   cls.reports={n:json.loads((out/(n+'.json')).read_text())for n in FILES}
  cls.cases={n:{s['source']:s['cases']for s in cls.reports[n]['sources']}for n in FILES[:3]}
  cls.corrected={name:gather(capture,BOUNDS,include_nested_returns=True)for name,capture in CAPTURES.items()}
  cls.emitter={s['source']:s['cases']for s in json.loads((ROOT/'research/host-compiler/pass-23/emitter-native-cases.json').read_text())['sources']}

 def test_fresh_reports_match_durable_facts(self):
  for n,r in self.reports.items():self.assertEqual(r,json.loads((REPORT/(n+'.json')).read_text()))
  for i,n in enumerate(FILES[:3]):
   for name,cs in self.cases[n].items():
    self.assertEqual(len(cs),COUNTS[name][i]);key=list(BOUNDS)[i]
    rows={r['entry']['step_index']:r for r in self.corrected[name][key]}
    self.assertEqual(set(rows),{c['entry_step']for c in cs})
    self.assertEqual(Counter(c['caller']for c in cs),Counter(coord(r['call']['origin'])for r in rows.values()))
    for c in cs:
     r=rows[c['entry_step']];verify_return(r['call'],r['ret'],r['relation'])
     self.assertEqual((c['input'],c['output'],c['return_step']),(r['entry']['before'],r['ret']['after'],r['ret']['step_index']))
     self.assertEqual(c['output']['pc'],r['call']['pc']+3)
     self.assertEqual(c['output']['sp'],(c['input']['sp']+2)&65535)

 def test_mapped_word_exact_neighbor_reads_addresses_and_ABI(self):
  for name,cs in self.cases['mapped-word-cases'].items():
   rows={r['entry']['step_index']:r for r in self.corrected[name]['PLI1.OVL+7A79']}
   for c in cs:
    r=rows[c['entry_step']];q=c['result']['lookup'];i=c['input'];o=c['output']
    self.assertEqual(q['discarded_AE39'],dict(c['entry_cells'])[0xae39]);
    self.assertEqual(q['position'],i['c']);self.assertEqual(q['doubled_offset'],2*q['index'])
    self.assertEqual(at(r,0x7a7d)['reads'],[dict(address=0xae38,value=i['c']),dict(address=0xae39,value=q['discarded_AE39'])])
    self.assertEqual(at(r,0x7a86)['reads'],[dict(address=0xaa1f+i['c'],value=q['index'])])
    self.assertEqual(at(r,0x7a8e)['reads'],[dict(address=q['low_address'],value=q['low'])])
    self.assertEqual(at(r,0x7a90)['reads'],[dict(address=q['high_address'],value=q['high'])])
    self.assertEqual((q['low_address'],q['high_address']),(0xab49+2*q['index'],0xab4a+2*q['index']))
    self.assertEqual(q['word'],q['low']+256*q['high'])
    self.assertEqual(c['logical_writes'],[[0xae38,i['c']]])
    self.assertEqual(c['compatibility_writes'],[]);self.assertEqual(c['services'],[])
    self.assertEqual((o['a'],pair(o,'b','c'),pair(o,'d','e'),pair(o,'h','l')),(i['a'],q['index'],q['high_address'],q['word']))
    self.assertEqual(o['flags'],i['flags']|dict(carry=False))

 def test_low_wrapper_cache_before_emitter_and_child_ownership(self):
  for name,cs in self.cases['low-word-emitter-cases'].items():
   rows={r['entry']['step_index']:r for r in self.corrected[name]['PLI1.OVL+7E46']}
   for c in cs:
    r=rows[c['entry_step']];q=c['result'];lookup=q['lookup'];word=q['selected_word']
    self.assertEqual(at(r,0x7e46)['reads'],[dict(address=0xae4f,value=q['paired_word']&255),dict(address=0xae50,value=q['discarded_neighbor'])])
    self.assertEqual(lookup['position'],q['paired_word']&255)
    calls=[w for w in r['own_witnesses']if w['control']['kind']=='call']
    self.assertEqual([coord(w['target_origin'])for w in calls],['PLI1.OVL+7A79','PLI.COM+0EF6'])
    child=next(x for x in self.cases['mapped-word-cases'][name]if calls[0]['step_index']<x['entry_step']<calls[1]['step_index'])
    self.assertEqual(child['parent_entry_step'],c['entry_step']);self.assertEqual(child['result']['lookup'],lookup)
    self.assertEqual([(x['address'],x['new_value'])for x in at(r,0x7e4d)['writes']],[(0xae52,word&255),(0xae53,word>>8)])
    self.assertLess(child['return_step'],at(r,0x7e4d)['step_index']);self.assertLess(at(r,0x7e4d)['step_index'],calls[1]['step_index'])
    self.assertEqual(c['logical_writes'][:3],[[0xae38,lookup['position']],[0xae52,word&255],[0xae53,word>>8]])
    self.assertEqual(calls[1]['before']['c'],word&255);self.assertEqual(calls[1]['before']['a'],word&255)

 def test_high_wrapper_fresh_paired_cache_read(self):
  for name,cs in self.cases['high-word-emitter-cases'].items():
   rows={r['entry']['step_index']:r for r in self.corrected[name]['PLI1.OVL+7E56']}
   for c in cs:
    r=rows[c['entry_step']];q=c['result'];word=q['selected_word']
    self.assertEqual(at(r,0x7e56)['reads'],[dict(address=0xae52,value=word&255),dict(address=0xae53,value=word>>8)])
    self.assertEqual(q['discarded_neighbor'],word&255);self.assertEqual(q['emitted_byte'],word>>8)
    calls=[w for w in r['own_witnesses']if w['control']['kind']=='call']
    self.assertEqual([coord(w['target_origin'])for w in calls],['PLI.COM+0EF6'])
    self.assertEqual(calls[0]['before']['c'],word>>8);self.assertEqual(calls[0]['before']['a'],word>>8)
    self.assertEqual(q['lookup'],None)

 def test_emitter_result_is_wrapper_return_and_stack_writer_is_exact(self):
  raw=(IMAGES/'PLI1.OVL').read_bytes()
  for file,site in [('low-word-emitter-cases',0x7e52),('high-word-emitter-cases',0x7e5b)]:
   self.assertEqual(raw[site:site+3],bytes.fromhex('CD F6 0F'))
   for name,cs in self.cases[file].items():
    for c in cs:
     children=[e for e in self.emitter[name]if c['entry_step']<e['entry_step']<e['return_step']<c['return_step']]
     self.assertEqual(len(children),1);child=children[0];q=c['result'];S=c['input']['sp']
     self.assertEqual(child['caller'],f'PLI1.OVL+{site:04X}');self.assertEqual(child['input']['c'],q['emitted_byte'])
     self.assertEqual(child['index'],q['emitter_index']);self.assertEqual(q['flush'],False)
     self.assertEqual(c['output'],child['output']|dict(sp=S+2,pc=c['output']['pc']))
     self.assertEqual(c['logical_writes'][-3:],child['logical_writes']);self.assertEqual(c['services'],[])
     final={a:(v,w)for a,v,w in c['residue_writers']}
     self.assertEqual(set(final),{S-2,S-1})
     self.assertEqual(final[S-2],((site+0x2203)&255,site+0x2200))
     self.assertEqual(final[S-1],((site+0x2203)>>8,site+0x2200))

 def test_hierarchy_residual_counts_and_external_records(self):
  for h in self.reports['hierarchical-summary']['sources']:
   name=h['result']['source'];low,high=COUNTS[name][1:]
   self.assertEqual(h['transition_counts_7E46_7E56'],[low,high]);self.assertEqual(h['logical_emitters_inside_wrappers'],low+high)
   self.assertEqual(h['result']['host_bdos_services'],0)
  expected={'MINIMAL':[9,0,16,16,18,16,14,114,1,7,7],
   'FIZZBUZ':[35,0,93,107,140,109,113,300,28,42,42],
   'PICTURE':[11,0,19,22,28,25,19,104,3,12,12]}
  old={s['source']:s for s in json.loads((ROOT/'research/host-compiler/pass-23/single-hybrid-summary.json').read_text())['sources']}
  for h in self.reports['cumulative-hybrid-summary']['sources']:
   r=h['result'];name=r['source'];counts=h['transition_counts_7C1B_7BBF_7B7A_7BA2_7AD5_7B64_7ABF_0EF6_7A79_7E46_7E56']
   self.assertEqual(counts,expected[name]);self.assertEqual(sum(counts),r['host_transitions'])
   self.assertEqual(r['host_bdos_services'],old[name]['host_bdos_services'])
   self.assertEqual(counts[7]+counts[9]+counts[10],old[name]['invocations'])
   for key in ['REL_size','REL_sha256','PASS1','PASS2','END_COMPILATION','termination','full_filesystem_identity','file_events_identity']:self.assertEqual(r[key],old[name][key])
  for s in self.reports['shadow-summary']['sources']:
   records=s['record_sha256_sequence'];name=s['result']['source']
   self.assertEqual(len([q for q in records if q[0]==name+'.INT']),{'MINIMAL':1,'FIZZBUZ':3,'PICTURE':1}[name])
   for q in records:self.assertEqual(len(q[2]),64)

 def test_scope_dependency_and_single_lookup_implementation(self):
  core=(ROOT/'lib/pli80_host/mapped_word.ml').read_text();packed=(ROOT/'lib/pli80_host/packed_scan.ml').read_text()
  self.assertIn('Mapped_word.lookup',packed);self.assertNotIn('0xab49',packed)
  for file in ['mapped_word.ml','word_emitter.ml']:
   for forbidden in ['I8080','Runner','Cpm.','Cpu.']:self.assertNotIn(forbidden,(ROOT/'lib/pli80_host'/file).read_text())
  self.assertIn('State.word state 0xae52',(ROOT/'lib/pli80_host/word_emitter.ml').read_text())
  catalog=json.loads((ROOT/'research/annotated-assembly/procedures.json').read_text())
  for entry,contract in [('7A79','complete'),('7E46','partial'),('7E56','partial')]:
   p=next(p for p in catalog['procedures']if p['id']=='PLI1.OVL+'+entry)
   self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract=contract))
  fidelity=json.loads((REPORT/'fidelity.json').read_text());self.assertEqual(fidelity['fidelity_debt'],None);self.assertFalse(fidelity['contracts_changed'])

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True)
 args,rest=p.parse_known_args();IMAGES=args.images
 unittest.main(argv=[__file__]+rest)
