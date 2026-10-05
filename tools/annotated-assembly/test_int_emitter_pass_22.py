#!/usr/bin/env python3
"""Fresh resident emitter snapshots joined to corrected returns and real BDOS effects."""
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from check_int_emitter_pass_22 import ROOT, REPORT, build
from minimal_baseline import load
from decompilation_annotations import header_lines

class IntEmitterPassTwentyTwoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory(prefix='atlas-emitter-pass22-', dir='/tmp') as directory:
            output = Path(directory)/'run'
            subprocess.run(['dune','exec','pli80-int-emitter-audit','--','--toolchain',str(IMAGES),
                            '--output-dir',str(output)],cwd=ROOT,check=True,stdout=subprocess.PIPE)
            cls.live=load(output/'snapshots.json')
        cls.actual=json.loads(json.dumps(build(cls.live)))
        cls.catalog={q['id']:q for q in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
        cls.cases=[c for s in cls.actual['emitter-cases']['sources'] for c in s['members']]
        cls.flushes=cls.actual['bdos-chronology']['flushes']

    def test_exact_images_and_local_bytes(self):
        manifest=load(ROOT/'research/annotated-assembly/manifest.json')
        self.assertEqual(sum(i['length'] for i in manifest['images']),94720)
        for i in manifest['images']:
            b=(IMAGES/i['name']).read_bytes()
            self.assertEqual(len(b),i['length']);self.assertEqual(hashlib.sha256(b).hexdigest(),i['sha256'])
        b=(IMAGES/'PLI.COM').read_bytes()
        error=load(REPORT/'error-path.json')
        for region in error['exact_regions']:
            self.assertEqual(b[region['start']:region['end']].hex().upper(),region['bytes'])
        self.assertEqual(b[0xf29:0xf2c],bytes.fromhex('CDA00F'))
        self.assertEqual(b[0x328:0x338],bytes.fromhex('216620702B712A6520EB0E15CDBB1AC9'))

    def test_all_durable_members_regenerate(self):
        for name,data in self.actual.items():self.assertEqual(data,load(REPORT/(name+'.json')),name)
        for source in self.live['sources']:
            self.assertTrue(source['PASS1_PASS2_END_warm_boot'])
            summary=next(s for s in self.actual['buffer-lifecycle']['sources'] if s['source']==source['source'])
            self.assertEqual((source['REL_size'],source['REL_sha256']),(summary['REL_size'],summary['REL_sha256']))

    def test_every_natural_invocation_and_catalog_count(self):
        for s in self.actual['buffer-lifecycle']['sources']:
            run=s['source'];p=self.catalog['PLI.COM+0EF6']
            self.assertEqual(s['calls'],p['observed_paths']['invocations_by_run'][run])
            self.assertEqual(s['callers'],{q['coordinate']:q['counts_by_run'][run] for q in p['callers'] if run in q['counts_by_run']})
            self.assertEqual(s['flush_error'],0);self.assertEqual(s['error_boundary_calls'],{})
            self.assertEqual(s['non_flush']+s['flush_success'],s['calls'])
        self.assertEqual(len(self.cases),640)
        self.assertEqual(len(self.flushes),5)

    def test_nonflush_registers_flags_and_address(self):
        for c in self.cases:
            i=c['entry_index'];q=(i+1)&255;o=c['output']
            self.assertEqual(c['buffer_address'],0x1d8c+i)
            self.assertEqual(c['new_buffer_byte'],c['input']['c'])
            self.assertEqual(o['sp'],c['input']['sp']+2)
            if c['path']=='non_flush':
                self.assertNotEqual(q,128);self.assertEqual(c['resulting_index'],q)
                self.assertEqual((o['a'],o['b']*256+o['c'],o['d']*256+o['e'],o['h']*256+o['l']),
                                 (q,0x1d8c,c['input']['d']*256+c['input']['e'],0x1d8c+i))
                # Independent bit/parity and 8080 subtraction/complement-carry oracle.
                v=(q-128)%256
                self.assertEqual(o['flags'],dict(sign=v>=128,zero=v==0,auxiliary_carry=True,
                                                 parity=bin(v).count('1')%2==0,carry=q<128))

    def test_flush_chronology_status_record_and_fcb(self):
        for q in self.flushes:
            steps=[q['append_step'],q['index80_step'],q['dma_wrapper_call_step'],q['bdos_calls'][0]['step_index'],q['index_reset_step'],q['write_wrapper_call_step'],q['bdos_calls'][1]['step_index'],q['status_compare_step'],q['return_step']]
            self.assertEqual(steps,sorted(set(steps)))
            a,b=q['bdos_calls'];self.assertEqual((a['function'],b['function']),(26,21))
            self.assertEqual((a['state']['d']*256+a['state']['e'],b['state']['d']*256+b['state']['e'],b['dma']),(0x1d8c,0x1ca2,0x1d8c))
            self.assertEqual(q['record']['step_index'],b['step_index'])
            self.assertEqual(q['file_events'][0]['record'],q['record']['record'])
            producers=q['buffer_writers']
            self.assertEqual([w[0] for w in producers],list(range(0x1d8c,0x1e0c)))
            self.assertTrue(all(w[1]<b['step_index'] for w in producers))
            self.assertEqual(bytes(w[3] for w in producers).hex().upper(),q['record']['data'])
            self.assertEqual(q['post_host_boundaries'][1]['buffer_hex'],q['record']['data'])
            before=bytearray.fromhex(b['fcb_bytes']);after=bytearray.fromhex(q['post_host_boundaries'][1]['FCB_hex'])
            for event in q['host_effects']:
                effect=event['effect']
                if effect['kind']=='memory_write':
                    self.assertEqual(before[effect['address']-0x1ca2],effect['old_value'])
                    before[effect['address']-0x1ca2]=effect['new_value']
            self.assertEqual(before,after)
            o=q['output'];self.assertEqual((o['a'],o['b'],o['c'],o['d'],o['e'],o['h'],o['l']),(0,0,21,0x1c,0xa2,0,0))
            self.assertEqual(o['flags'],dict(sign=False,zero=True,auxiliary_carry=True,parity=True,carry=False))

    def test_real_runtime0005_returns_and_final_stack_writers(self):
        for q in self.flushes:
            for r in q['bridge_returns']:
                self.assertIsNone(r['ret_origin']);self.assertEqual(r['ret_pc'],5)
                self.assertEqual({w['address']:w['new_value'] for w in r['call_slot_writes']},
                                 {w['address']:w['value'] for w in r['ret_slot_reads']})
                self.assertEqual(r['relation']['frame']['call_step'],r['call_step'])
            values=[w['value'] for w in q['final_stack_writers']]
            self.assertEqual(values,[0xc6,0x1a,0xa2,0x1c,0x15,0x1c,0x37,4,0x24,0x10])
            for call,resume in zip(q['bdos_calls'],q['bdos_resumes']):
                self.assertEqual(call['state']['flags'],resume['state']['flags'])
                self.assertEqual(resume['state']['a'],0)

    def test_buffer_lifecycle_and_complete_index_distribution(self):
        for s in self.actual['buffer-lifecycle']['sources']:
            copies=s['calls']//128
            self.assertEqual(s['entry_indices'],{str(i):copies for i in range(128)})
            self.assertEqual(s['neighbor_values'],{'0':s['calls']})
            self.assertEqual(s['records'],list(range(copies)))
            self.assertTrue(s['buffer_persists_after_reset']);self.assertTrue(s['flushes_on_every_128th_call'])
        for q in self.flushes:
            self.assertEqual([p['index'] for p in q['post_host_boundaries']],[128,0])

    def test_independent_generic_write_wrapper(self):
        p=self.catalog['PLI.COM+0328']
        self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'))
        for s in self.actual['bdos-write-wrapper']['sources']:
            self.assertEqual(s['calls'],p['observed_paths']['invocations_by_run'][s['source']])
            self.assertEqual(s['callers'],{q['coordinate']:q['counts_by_run'][s['source']] for q in p['callers']})
            self.assertEqual({q['argument'] for q in s['members']},{0x1ca2,0x1ce4})

    def test_static_error_scope_and_annotation_axes(self):
        p=self.catalog['PLI.COM+0EF6'];self.assertEqual(p['observed_paths']['represented_bytes'],55)
        self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'))
        e=next(s for s in load(ROOT/'research/annotated-assembly/evidence.json')['seeds'] if s['id']==p['id'])
        inst=next(i for i in e['instructions'] if i['offset']==0xf29)
        self.assertEqual(inst['runs'],[]);self.assertEqual(inst['decoded'],'CALL 0FA0H')
        manifest=load(ROOT/'research/annotated-assembly/manifest.json')
        com=next(i for i in manifest['images'] if i['name']=='PLI.COM')
        self.assertEqual(next(s['status'] for s in com['sections'] if s['start_offset']==0xf29),'DECODED')
        self.assertIn('STATIC / UNOBSERVED','\n'.join(header_lines(p)))
        self.assertEqual(load(REPORT/'error-path.json')['observed_write_errors'],0)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--images',type=Path,required=True)
    args,rest=parser.parse_known_args();IMAGES=args.images.resolve()
    unittest.main(argv=[sys.argv[0],*rest])
