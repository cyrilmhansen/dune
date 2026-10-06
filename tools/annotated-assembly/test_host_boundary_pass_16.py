#!/usr/bin/env python3
"""Pass-16 cut dependencies, exact output chronology and closed uncertainty."""
import argparse
import hashlib
import json
import sys
import unittest
from pathlib import Path
from check_host_boundary_pass_16 import (ROOT,REPORT,FIZZ,scan,operation_capture,
                                         dependency_inputs,check_snapshot_inputs,rel_audit,timeline_projection)
from minimal_baseline import load

class HostBoundaryPassSixteenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest=load(ROOT/'research/annotated-assembly/manifest.json')
        cls.images={x['name']:(IMAGES/x['name']).read_bytes() for x in cls.manifest['images']}
        cls.timeline=scan(FIZZ,cls.images)
        cls.operations=[operation_capture(ROOT/r) for r in ['_build/minimal-baseline/capture','_build/evidence-packet-cross-run/fizzbuz-capture','_build/discriminator-pass-15/selected-capture']]
        cls.cut=load(REPORT/'recommended-cut.json');cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}

    def test_identity_and_durable_mechanical_facts(self):
        self.assertEqual(sum(len(x) for x in self.images.values()),94720)
        for i in self.manifest['images']:self.assertEqual(hashlib.sha256(self.images[i['name']]).hexdigest(),i['sha256'])
        t=load(REPORT/'fizzbuz-timeline.json');self.assertEqual(t['facts'],timeline_projection(self.timeline))
        self.assertEqual(json.loads((REPORT/'operation-captures.json').read_text()),self.operations)
        self.assertEqual((self.timeline['rel']['size'],self.timeline['rel']['sha256']),(768,'68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203'))
        summary=load(FIZZ/'run-summary.json');self.assertTrue(all(summary[k] for k in ['pass1_success','pass2_success','end_compilation']))
        for n,key in [('0','PLI.COM+0000'),('14310','PLI0.OVL+0000'),('319757','PLI1.OVL+0000'),('664916','PLI2.OVL+0000'),('1145516','PLI.COM+19E0')]:self.assertEqual(self.timeline['markers'][n]['coordinate'],key)

    def test_REL_item_bit_record_and_padding_oracles(self):
        r=self.timeline['rel'];self.assertTrue(r['all_writer_bits_reproduce_file']);self.assertEqual(r['bit_writer_calls'],6144)
        self.assertEqual(r['bits_by_epoch'],dict(before_PLI2=469,PLI2_onward=5675));self.assertEqual(r['gate_values'],{'0':6144})
        self.assertEqual((r['logical_items'],r['kind_counts']),(289,dict(special=59,absolute_byte=207,relative_word=23)))
        self.assertEqual(bytes.fromhex(r['first_items'][0]['name_hex']),b'FIZZBU');self.assertEqual(bytes.fromhex(r['first_items'][1]['name_hex']),b'PLILIB')
        self.assertEqual((r['last_items'][-1]['control'],r['end_file_bit'],r['trailing_bit_count']),(15,5183,961));self.assertTrue(r['trailing_all_zero'])
        self.assertEqual(r['module_alignment'],[dict(start_bit=5175,bits='0')])
        for i,record in enumerate(self.timeline['REL_records']):self.assertEqual((record['record'],record['dma']),(i,0x1D0A))
        ints=self.timeline['INT_records'];writes={r['record']:r['sha256'] for r in ints if r['operation']=='write_record'}
        self.assertEqual(writes,{r['record']:r['sha256'] for r in ints if r['operation']=='read_record'})
        state=self.timeline['markers']['664916']['observed_prior_state_writes'];self.assertEqual((state['1D8A']['value'],state['1D8B']['value']),(58,5))

    def test_bounded_reader_independent_fields_and_rejection(self):
        # Synthetic REL format unit input, never a synthesized PL/I source.
        bits='0'+'01000001'+'101'+'00110100'+'00010010'+'1001110'+'00'+'0'*16
        bits+='0'*((-len(bits))%8);bits+='1001111';bits+='0'*((-len(bits))%8)
        raw=bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8));r=rel_audit(raw)
        self.assertEqual(r['logical_items'],4);self.assertEqual(r['first_items'][0]['value'],65)
        self.assertEqual((r['first_items'][1]['address_type'],r['first_items'][1]['value']),(1,0x1234))
        for raw in [b'',bytes.fromhex('88'),bytes.fromhex('90')]:
            with self.assertRaises(ValueError):rel_audit(raw)

    def test_selected_operation_has_exact_inputs_outputs_and_order(self):
        self.assertEqual([r['invocations'] for r in self.operations],[3,21,3])
        for run in self.operations:
            for m in run['members']:
                F=m['input_state']['sp'];j=m['map_index'];inp={int(a,16):v for a,v in m['input_memory'].items()}
                self.assertEqual(set(inp),{0xAE39,0xAA1F+m['position'],0xAB49+2*j,0xAB4A+2*j,F,F+1})
                self.assertEqual(inp[0xAB49+2*j]+256*inp[0xAB4A+2*j],m['initial_word'])
                # Independent stop oracle from adjacent original bits plus a final zero.
                bits=f"{m['initial_word']:016b}"+'0';expected=next((i for i in range(1,17) if bits[i]!=bits[i-1]),16)
                self.assertEqual(m['shifts'],expected);self.assertEqual(m['returned_counter'],16-expected)
                self.assertEqual(m['shifted_word'],(m['initial_word']<<expected)&65535)
                post={int(a,16):v for a,v in m['post_written_bytes'].items()}
                self.assertEqual(set(post),{0xAE38,0xAE43,0xAE44,*range(0xAE4B,0xAE4F),0xAD08+j,*range(F-6,F)})
                self.assertEqual(post[0xAD08+j],m['returned_counter']);self.assertEqual(m['post_state']['sp'],F+2)
                self.assertEqual((m['caller'],m['return_coordinate']),('PLI1.OVL+7C37','PLI1.OVL+7C1A'))
        zero=[m for m in self.operations[1]['members'] if m['initial_word']==0];self.assertEqual(len(zero),3);self.assertTrue(all(m['shifts']==16 and m['returned_counter']==0 for m in zero))

    def test_snapshot_cannot_drop_reads_or_use_value_equality_as_preservation(self):
        ws=[dict(step_index=1,reads=[dict(address=100,value=7)],writes=[]),
            dict(step_index=2,reads=[],writes=[dict(address=101,new_value=7)]),
            dict(step_index=3,reads=[dict(address=101,value=7),dict(address=102,value=0)],writes=[])]
        inputs,_,_=dependency_inputs(ws);self.assertEqual(inputs,{100:7,102:0});check_snapshot_inputs(ws,inputs)
        for bad in [{100:7},{100:7,102:1},{100:7,101:7,102:0}]:
            with self.assertRaisesRegex(ValueError,'Snapshot omits or alters'):check_snapshot_inputs(ws,bad)

    def test_all_ranked_ranges_are_observed_and_unknowns_remain_explicit(self):
        candidates=load(REPORT/'candidate-boundaries.json')['candidates'];self.assertGreaterEqual(len(candidates),3)
        deps=self.timeline['bounded_dependencies'];phase=self.timeline['phase_snapshot_dependencies']
        for c in candidates:
            if c['dependency_key'] in deps:actual=deps[c['dependency_key']]
            elif c['dependency_key'] in phase:actual=phase[c['dependency_key']]
            else:continue  # +7BBF individual correlated snapshots above, not a union.
            self.assertEqual(c['read_before_write_ranges'],actual['read_before_write_ranges']);self.assertTrue(c['unresolved_dependencies'])
        self.assertEqual(self.cut['entry'],'PLI1.OVL+7BBF');self.assertEqual(self.catalog[self.cut['entry']]['completeness'],dict(bounds='stable',control_flow='complete',contract='complete'))
        self.assertFalse(self.cut['checkpoint_resume_demonstrated']);self.assertFalse(self.cut['pragmatic_divergence_required'])
        self.assertIn('AE39',self.cut['validation_snapshot']['discarded_read'])
        audit=load(REPORT/'critical-path-audit.json');actual=self.timeline['call_inventory']
        # Pass16 is a frozen reconnaissance audit. Pass22 separately records the
        # later emitter refinement and newly cataloged sequential-write wrapper.
        # Pass30 records the later complete +23A0 contract; retain its prior state
        # when checking the frozen Pass16 classification, not the live catalog.
        later=load(ROOT/'research/host-compiler/pass-22/catalog-refinement.json')
        prior30=load(ROOT/'research/host-compiler/pass-30/before.json')
        self.assertEqual(later['new_entries'],['PLI.COM+0328'])
        # Pass32 adds bounded dispatcher/dependency hypotheses; the frozen Pass16
        # audit still compares its original catalog membership.
        prior32=load(ROOT/'research/host-compiler/pass-32/before.json')
        added32={k for k,v in prior32.items()if v is None}
        prior33=load(ROOT/'research/host-compiler/pass-33/before.json')
        added32|={k for k,v in prior33.items()if v is None}
        prior34=load(ROOT/'research/host-compiler/pass-34/before.json')
        added32|={k for k,v in prior34.items()if v is None}
        prior37=load(ROOT/'research/host-compiler/pass-37/before.json')
        prior38=load(ROOT/'research/host-compiler/pass-38/before.json')
        added32|={k for k,v in prior38.items()if v is None}
        added32|={k for k,v in prior37.items()if v is None}
        prior36=load(ROOT/'research/host-compiler/pass-36/before.json')
        added32|={k for k,v in prior36.items()if v is None}
        prior35=load(ROOT/'research/host-compiler/pass-35/before.json')
        added32|={k for k,v in prior35.items()if v is None}
        self.assertEqual({p['entry'] for p in audit['established']},{k for k in actual if k in self.catalog and k not in set(later['new_entries'])|added32})
        for p in audit['established']:
            self.assertEqual(p['FIZZBUZ_calls'],actual[p['entry']]['count'])
            previous=later['previous'].get(p['entry'],prior30.get(p['entry'],prior37.get(p['entry']) or self.catalog[p['entry']]))
            self.assertEqual(p['completeness'],previous['completeness'])
            if p['classification']=='READY FOR FAITHFUL HOST IMPLEMENTATION':self.assertEqual(p['completeness']['contract'],'complete')
            else:self.assertTrue(p['missing_scope'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images.resolve();unittest.main(argv=[sys.argv[0],*rest])
