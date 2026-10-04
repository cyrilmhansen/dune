#!/usr/bin/env python3
"""Exact initial table, golden corpus screening and two PICTURE attr6 word-pair paths."""
import argparse
import hashlib
import json
import re
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from check_minimal_pass_2 import coord
from check_attribute_discriminator_pass_15 import audit_table
from minimal_baseline import load
from procedure_evidence_packet import ROOT,build
from verify import assemble

REPORT=ROOT/'research/discriminator/pass-15'

def local(p,iv,o):return [(n,p['steps'][str(n)]) for n in iv['local_steps'] if p['steps'][str(n)]['coordinate']==f'PLI1.OVL+{o:04X}']

class AttributeDiscriminatorPassFifteenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table=load(REPORT/'table-classification.json');cls.screen=load(REPORT/'corpus-screen.json');cls.p=build(CAPTURE,IMAGES,'PLI1.OVL+7D53',0,(),run='PICTURE');cls.audit=audit_table(CAPTURE,bytes.fromhex(cls.table['table_hex']))
        cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}

    def test_historical_table_exact_initial_bits_and_candidates(self):
        raw=(IMAGES/'PLI.COM').read_bytes();table=raw[0x1A4B:0x1B4B];self.assertEqual(len(table),256);self.assertEqual(table.hex().upper(),self.table['table_hex']);self.assertEqual(hashlib.sha256(table).hexdigest(),self.table['table_sha256'])
        rebuilt=assemble(ROOT/'research/annotated-assembly/PLI.asm');self.assertEqual(len(rebuilt['sections']),1);self.assertEqual(rebuilt['sections'][0]['start'],256);self.assertEqual(bytes(rebuilt['sections'][0]['bytes'])[0x1A4B:0x1B4B],table)
        counts=Counter((v>>3)&7 for v in table);self.assertEqual([counts[i] for i in range(8)],[33,0,15,50,149,2,7,0]);self.assertEqual(self.table['high_distribution'],{str(i):counts[i] for i in range(8)})
        self.assertEqual({i for i,v in enumerate(table) if (v>>3)&7==5},{0x5F,0x67});self.assertEqual({i for i,v in enumerate(table) if (v>>3)&7==6},{0x10,0x18,0x75,0xB0,0xB3,0xB4,0xB8});self.assertFalse(counts[1]);self.assertFalse(counts[7])
        for i,row in enumerate(self.table['rows']):self.assertEqual((row['mapped_byte'],row['initial_byte'],row['low_attribute'],row['high_attribute']),(i,table[i],table[i]&7,(table[i]>>3)&7))
        code=(IMAGES/'PLI1.OVL').read_bytes();self.assertEqual(code[0x7A75:0x7A79],bytes.fromhex('3E07A6C9'));self.assertEqual(code[0x7B71:0x7B7A],bytes.fromhex('7EE6FC1F1F1FE607C9'))
        for value in range(256):
            shifted=value&252
            for _ in range(3):shifted>>=1
            expected=((value>>3)&1)+2*((value>>4)&1)+4*((value>>5)&1);self.assertEqual(shifted&7,expected)

    def test_all_screened_REL_goldens_and_canonical_coordinates(self):
        self.assertEqual(len(self.screen['sources']),10);doc=(ROOT/'docs/pli80-experiments.md').read_text();goldens={}
        for line in doc.splitlines():
            m=re.match(r'\| `([A-Z]+)\.PLI` \|.*?\| ([\d,]+) \| (\d+) \| `([a-f0-9]{64})` \|',line)
            if m:goldens[m[1]]=(int(m[2].replace(',','')),int(m[3]),m[4])
        goldens['OPTIMIST']=(2535509,1408,'5fca1ffe38d11c30d20cfb99a23fe2baf002c569790bda83e09151cf36032b15')
        positives=[]
        for row in self.screen['sources']:
            name=row['source'][:-4];path=Path(row['capture_path']);path=path if path.is_absolute() else ROOT/path;rel=(path/(name+'.REL')).read_bytes();self.assertEqual((row['guest_steps'],len(rel),hashlib.sha256(rel).hexdigest()),goldens[name]);self.assertEqual((row['REL_size'],row['REL_sha256']),(len(rel),hashlib.sha256(rel).hexdigest()))
            canonical=load(path/'canonical-code-blocks.json');facts={(i['image']['name'],i['offset']):i for i in canonical['instructions']}
            for o in [0x7D53,0x7E2B,0x7E2E]:
                fact=facts.get(('PLI1.OVL',o));cell=row['coordinates'][f'PLI1.OVL+{o:04X}'];self.assertEqual(cell['executed'],fact is not None);self.assertEqual(cell['execution_count'],fact['execution_count'] if fact else 0)
                if fact:self.assertEqual(bytes.fromhex(fact['bytes']),(IMAGES/'PLI1.OVL').read_bytes()[o:o+len(bytes.fromhex(fact['bytes']))])
            if row['coordinates']['PLI1.OVL+7E2B']['executed']:positives.append(row)
        self.assertEqual({r['source'] for r in positives},{'PICTURE.PLI','FACTOR.PLI','OPTIMIST.PLI'});self.assertEqual(min(positives,key=lambda r:r['guest_steps'])['source'],'PICTURE.PLI')

    def test_actual_table_reads_latest_writers_and_not_global_immutability(self):
        self.assertEqual(self.audit['run_id'],self.p['run_id']);self.assertTrue(self.audit['run_id'].startswith('PICTURE:'));self.assertEqual(self.audit['corrected_return_matches'],len(self.audit['high_attribute_reads']))
        self.assertGreater(self.audit['observed_table_write_count'],0);self.assertTrue(self.audit['changed_final_addresses']);self.assertEqual(self.audit['written_addresses'],list(range(0x1C2C,0x1C38)))
        for r in self.audit['high_attribute_reads']:
            self.assertIsNone(r['latest_writer']);self.assertEqual(r['table_address'],0x1B4B+r['input_C']);self.assertEqual(r['read_byte'],r['initial_byte']);self.assertEqual(r['returned_attribute'],(r['read_byte']>>3)&7)
        rows={r['call_step']:r for r in self.audit['high_attribute_reads']};self.assertEqual([(rows[n]['table_address'],rows[n]['read_byte'],rows[n]['returned_attribute']) for n in [326995,327173]],[(0x1B63,0x31,6),(0x1BFB,0xB1,6)])
        claimed=load(REPORT/'selected-table-reads.json');self.assertEqual(claimed['reads'],self.audit['high_attribute_reads'])

    def test_same_valued_table_write_replaces_initial_source(self):
        # Synthetic event-unit check only; not a PL/I fixture or compiler evidence.
        image={'name':'PLI1.OVL'}
        def instr(step,offset,reads=None,after=None,call=False):
            return dict(type='instruction',witness=dict(step_index=step,pc=0x2200+offset,
                origin=dict(image=image,offset=offset),control=dict(kind='call' if call else 'sequential',taken=True),
                target_origin=dict(image=image,offset=0x7B64) if call else None,
                before=dict(c=0x18),after=after or {},reads=reads or [],writes=[]))
        events=[instr(0,0x7DDB,call=True),
                dict(type='host_effect',step_index=1,effect=dict(kind='memory_write',address=0x1B63,new_value=0x31,cause='fcb_update')),
                instr(2,0x7B71,reads=[dict(address=0x1B63,value=0x31)]),
                instr(3,0x7B77,after=dict(a=6)),instr(4,0x7B79,after=dict(a=6,flags={})),
                dict(type='hardware_frame_return',step_index=4,frame=dict(call_step=0))]
        with tempfile.TemporaryDirectory(prefix='atlas-discriminator-test-',dir='/tmp') as temp:
            cap=Path(temp);(cap/'event-witnesses/chunks').mkdir(parents=True);identity='UNIT:'+('a'*64)
            (cap/'event-witnesses.json').write_text(json.dumps(dict(run_id=identity,chunks=[dict(id=0)],summary=dict(hardware_frame_returns=1))))
            (cap/'event-witnesses/chunks/000000.json').write_text(json.dumps(dict(run_id=identity,events=events)))
            report=audit_table(cap,bytes.fromhex(self.table['table_hex']));read=report['high_attribute_reads'][0]
            self.assertEqual(read['read_byte'],read['initial_byte']);self.assertEqual(read['latest_writer']['kind'],'host_effect');self.assertEqual(read['latest_writer']['step'],1)

    def test_positive_metadata_and_actual_return_to_AE50(self):
        p=self.p;cat=self.catalog[p['entry']];self.assertEqual(len(p['invocations']),23);self.assertEqual(cat['observed_paths']['invocations_by_run']['PICTURE'],23);self.assertEqual(cat['observed_paths']['invocations_by_run']['MINIMAL'],21);self.assertEqual(cat['observed_paths']['invocations_by_run']['FIZZBUZ'],77)
        self.assertEqual(Counter(iv['caller'] for iv in p['invocations']),Counter({c['coordinate']:c['counts_by_run']['PICTURE'] for c in cat['callers'] if 'PICTURE' in c['counts_by_run']}))
        iv=next(iv for iv in p['invocations'] if iv['call_step']==326116)
        self.assertEqual([n for n,w in local(p,iv,0x7E2B)],[327037,327215]);self.assertEqual([n for n,w in local(p,iv,0x7E2E)],[327076,327254])
        for n in [326995,327173]:
            c=p['calls'][str(n)];ret=p['steps'][str(c['post_return_state_step'])]['after'];nextwrite=next(w for step,w in local(p,iv,0x7DDE) if step>c['post_return_state_step']);self.assertEqual((ret['a'],nextwrite['before']['a'],nextwrite['writes'][0]['new_value']),(6,6,6))

    def test_attr6_suppression_pair_order_zero_channels_and_recycle(self):
        p=self.p;iv=next(iv for iv in p['invocations'] if iv['call_step']==326116);starts=[326960,327138];ends=[327098,327276]
        for cursor,start,end in zip([1,2],starts,ends):
            own=[(n,p['steps'][str(n)]) for n in iv['local_steps'] if start<=n<=end];at=lambda o:next((n,w) for n,w in own if w['coordinate']==f'PLI1.OVL+{o:04X}')
            cpi=at(0x7E17)[1];jump=at(0x7E19)[1];self.assertEqual(cpi['before']['a'],6);self.assertTrue(cpi['after']['flags']['zero']);self.assertEqual(jump['before']['flags'],cpi['after']['flags']);self.assertTrue(jump['control']['taken']);self.assertEqual(jump['control']['target'],0xA023)
            self.assertFalse(any(w['coordinate'] in ['PLI1.OVL+7E1C','PLI1.OVL+7E1F','PLI1.OVL+7E20'] for n,w in own));self.assertEqual(at(0x7DFE)[1]['writes'][0]['new_value'],0)
            cpi=at(0x7E26)[1];jump=at(0x7E28)[1];self.assertEqual(cpi['before']['a'],6);self.assertFalse(cpi['after']['flags']['carry']);self.assertEqual(jump['before']['flags'],cpi['after']['flags']);self.assertFalse(jump['control']['taken'])
            calls=[p['calls'][str(n)] for n in iv['nested_calls'] if start<=n<=end];targets=[c['target'] for c in calls];self.assertEqual(targets,['PLI1.OVL+7A4D','PLI.COM+0EF6','PLI1.OVL+7B64','PLI1.OVL+7AA9','PLI1.OVL+7E46','PLI1.OVL+7E56','PLI1.OVL+7BA2'])
            low,high=calls[-3:-1];self.assertEqual((low['callsite'],high['callsite']),('PLI1.OVL+7E2B','PLI1.OVL+7E2E'));self.assertLess(low['post_return_state_step'],high['pre_call_state_step'])
            effects=low['callee_memory_effects']['guest_instruction_accesses'];cache=[(e['step'],q['address'],q['new_value']) for e in effects if e['coordinate']=='PLI1.OVL+7E4D' for q in e['writes']];self.assertEqual([(a,v) for n,a,v in cache],[(0xAE52,0),(0xAE53,0)])
            source=[(q['address'],q['value']) for e in effects for q in e['reads'] if q['address'] in [0xAB49+2*cursor,0xAB4A+2*cursor]];self.assertEqual(source,[(0xAB49+2*cursor,0),(0xAB4A+2*cursor,0)])
            fresh=[(e['step'],q['address'],q['value']) for e in high['callee_memory_effects']['guest_instruction_accesses'] if e['coordinate']=='PLI1.OVL+7E56' for q in e['reads']];self.assertEqual([(a,v) for n,a,v in fresh],[(0xAE52,0),(0xAE53,0)]);self.assertLess(cache[0][0],fresh[0][0])
            for c in [low,high]:
                emitted=[q['new_value'] for e in c['callee_memory_effects']['guest_instruction_accesses'] if e['coordinate']=='PLI.COM+0EF9' for q in e['writes'] if q['address']==0x20B0];self.assertEqual(emitted,[0])
            all_effects=effects+high['callee_memory_effects']['guest_instruction_accesses']
            for address in [0xAE52,0xAE53]:
                last=max((e for e in all_effects if e['step']<fresh[0][0] and any(q['address']==address for q in e['writes'])),key=lambda e:e['step'])
                self.assertEqual(last['step'],cache[0][0])  # same-valued stores still define the cache source
            self.assertNotEqual(low['pre_call_state_step'],high['pre_call_state_step']);self.assertEqual(p['steps'][str(calls[-1]['pre_call_state_step'])]['before']['c'],cursor)
        # Primary zeros were read/cache-written but have no direct emitter CALL; emitted zeros are word channels.

    def test_promotion_is_six_observed_bytes_and_independent_completeness(self):
        p=self.catalog['PLI1.OVL+7D53'];self.assertEqual(p['observed_paths']['represented_bytes'],243);self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'))
        seed=next(s for s in load(ROOT/'research/annotated-assembly/evidence.json')['seeds'] if s['id']==p['id'])
        for o in [0x7E2B,0x7E2E]:self.assertEqual(next(i for i in seed['instructions'] if i['offset']==o)['runs'][0]['run'],'PICTURE')
        self.assertEqual(sum(len(bytes.fromhex(i['bytes'])) for i in seed['instructions']),243)
        progress=load(REPORT/'progress.json');self.assertEqual(progress['new_understood_bytes'],6);self.assertTrue(progress['MINIMAL_progress_unchanged'])

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--images',type=Path,required=True);parser.add_argument('--capture',type=Path,default=ROOT/'_build/discriminator-pass-15/selected-capture')
    args,remaining=parser.parse_known_args();IMAGES,CAPTURE=args.images,args.capture
    unittest.main(argv=[sys.argv[0],*remaining])
