#!/usr/bin/env python3
"""Live native shadow/hybrid regression against all retained ordinary-return windows."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from collections import Counter
from minimal_baseline import load
from check_minimal_pass_2 import coord
from check_minimal_pass_3 import gather
from procedure_evidence_packet import ROOT

REPORT=ROOT/'research/host-compiler/pass-17'
CAPTURES={'MINIMAL':ROOT/'_build/minimal-baseline/capture','FIZZBUZ':ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture','PICTURE':ROOT/'_build/discriminator-pass-15/selected-capture'}

class NativePassSeventeenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory(prefix='atlas-native7bbf-',dir='/tmp') as temp:
            output=Path(temp)/'experiment'
            subprocess.run(['dune','exec','pli80-native-7bbf','--','--toolchain',str(IMAGES),'--output-dir',str(output)],cwd=ROOT,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            cls.cases=json.loads((output/'native-cases.json').read_text());cls.shadow=json.loads((output/'shadow-summary.json').read_text());cls.hybrid=json.loads((output/'hybrid-summary.json').read_text())
        cls.records={name:gather(cap,{'PLI1.OVL+7BBF':(0x7BBF,0x7C1B)},include_nested_returns=True)['PLI1.OVL+7BBF'] for name,cap in CAPTURES.items()}

    def test_live_outputs_equal_durable_reports(self):
        for file,value in [('native-cases',self.cases),('shadow-summary',self.shadow),('hybrid-summary',self.hybrid)]:self.assertEqual(value,json.loads((REPORT/(file+'.json')).read_text()))
        self.assertEqual(self.shadow['total'],27);self.assertEqual(self.hybrid['total_native_replacements'],27);self.assertTrue(self.hybrid['no_fallback'])

    def test_all_27_entry_return_and_discrete_cases_match_original_witnesses(self):
        old={r['run_id'].split(':')[0]:r for r in json.loads((ROOT/'research/host-compiler/pass-16/operation-captures.json').read_text())}
        for run in self.cases['sources']:
            name=run['source'];members=run['members'];self.assertEqual(len(members),old[name]['invocations'])
            recorded={m['entry_step']:m for m in old[name]['members']}
            for case in members:
                m=recorded[case['entry_step']];self.assertEqual(case['input'],m['input_state']);self.assertEqual(case['output'],m['post_state']);self.assertEqual(case['return_step'],m['return_step'])
                for a,b in [('initial_word','initial_word'),('shifted_word','shifted_word'),('shifts','shifts'),('counter','returned_counter'),('auxiliary_address','auxiliary_address')]:self.assertEqual(case[a],m[b])
                self.assertTrue(all(case[k] for k in ['all_registers_flags_match','full_memory_match','logical_order_match','residue_latest_writers_match']))
        self.assertEqual(Counter(c['initial_word'] for r in self.cases['sources'] for c in r['members']),{1:13,594:6,0:3,15:2,3:1,5:1,7:1})

    def test_logical_write_order_and_residue_ancestry_are_exact(self):
        for run in self.cases['sources']:
            rows={r['entry']['step_index']:r for r in self.records[run['source']]}
            for c in run['members']:
                r=rows[c['entry_step']];F=c['input']['sp'];stack={(F-i)&65535 for i in range(1,7)}
                ws=r['own_witnesses']+[w for child in r['nested_returns'].values() for w in child['memory_witnesses']]
                logical=[];latest={}
                for w in sorted(ws,key=lambda w:w['step_index']):
                    for q in w['writes']:
                        if q['address'] in stack:latest[q['address']]=(w,q['new_value'])
                        else:logical.append((q['address'],q['new_value']))
                native=[(w['address'],w['value']) for w in c['writes']];self.assertEqual(native,logical)
                text=';'.join(f'{a:04X}:{v:02X}' for a,v in logical).encode();self.assertEqual(hashlib.sha256(text).hexdigest(),c['logical_writes_sha256'])
                for a,value in c['compatibility_writes']:
                    w,v=latest[a];depth=6 if a in {(F-6)&65535,(F-5)&65535} else 4 if a in {(F-4)&65535,(F-3)&65535} else 2
                    expected={6:0x7BF3,4:0x7BF7,2:0x7C14}[depth];self.assertEqual(coord(w['origin']),f'PLI1.OVL+{expected:04X}');self.assertEqual(w['control']['kind'],'call');self.assertEqual(v,value)
                    pc=w['pc']+3;self.assertEqual(value,(pc&255) if a==(F-depth)&65535 else pc>>8)

    def test_hybrid_real_metrics_and_record_oracles(self):
        normal={r['source']:r for r in self.shadow['sources']}
        for row in self.hybrid['sources']:
            r=row['result'];name=r['source'];self.assertEqual(r['native_interceptions'],{'MINIMAL':3,'FIZZBUZ':21,'PICTURE':3}[name])
            for k in ['REL_size','REL_sha256','PASS1','PASS2','END_COMPILATION','termination']:self.assertEqual(r[k],normal[name][k])
            self.assertLess(r['actual_guest_instructions'],normal[name]['actual_guest_instructions']);self.assertLess(r['actual_guest_t_states'],normal[name]['actual_guest_t_states'])
            summary=load(CAPTURES[name]/'run-summary.json');self.assertEqual(normal[name]['actual_guest_instructions'],summary['steps']);self.assertEqual(normal[name]['REL_sha256'],summary['rel']['sha256'])
            self.assertTrue(row['all_entry_and_resume_states_match']);self.assertTrue(row['all_record_bytes_match'])
            index=load(CAPTURES[name]/'event-witnesses.json');expected=[]
            for chunk in index['chunks']:
                for e in load(CAPTURES[name]/'event-witnesses/chunks'/f"{chunk['id']:06d}.json")['events']:
                    if e['type']=='bdos_record' and e['operation']=='write_record':expected.append(dict(file=e['file']['name'],record=e['record'],sha256=hashlib.sha256(bytes.fromhex(e['data'])).hexdigest()))
            self.assertEqual(row['record_oracles'],expected)

    def test_module_boundary_and_historical_images_unchanged(self):
        dune=(ROOT/'lib/pli80_host/dune').read_text();self.assertNotIn('i8080',dune);self.assertNotIn('runner',dune)
        for p in (ROOT/'lib/pli80_host').glob('*.ml'):
            text=p.read_text();self.assertNotIn('Cpu.step',text);self.assertNotIn('Decode.',text)
        for m in load(ROOT/'research/annotated-assembly/manifest.json')['images']:self.assertEqual(hashlib.sha256((IMAGES/m['name']).read_bytes()).hexdigest(),m['sha256'])
        fidelity=load(REPORT/'fidelity.json');self.assertEqual(fidelity['unresolved_differences'],[]);self.assertEqual(fidelity['fidelity_debt'],[]);self.assertTrue(fidelity['final_guest_visible_memory_identity'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images.resolve();unittest.main(argv=[sys.argv[0],*rest])
