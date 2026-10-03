#!/usr/bin/env python3
"""Scoped sum/traversal/word/bit contracts and exact image-coordinate regression."""
import argparse
import json
import sys
import unittest
from pathlib import Path

from check_minimal_pass_2 import at, coord, pair
from check_minimal_pass_3 import gather
from minimal_baseline import load, status_at
from minimal_dynamic_progress import calculate
from procedure_evidence_packet import ROOT, build, verify_return


def local(p, iv, offset):
    name = p['entry'].split('+')[0]
    return [p['steps'][str(n)] for n in iv['local_steps']
            if p['steps'][str(n)]['coordinate'] == f'{name}+{offset:04X}']


def bits(value, count):
    # Independent expectation for the observed rol8/low-bit writer interface.
    return [(value >> (7-i)) & 1 for i in range(count)]


class MinimalPassTenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packets = {k: build(CAPTURE, IMAGES, k, 0, ()) for k in
                       ['PLI1.OVL+452B','PLI1.OVL+4584','PLI.COM+1207',
                        'PLI1.OVL+46ED','PLI1.OVL+4738','PLI1.OVL+666E','PLI1.OVL+28AA']}
        keys=['PLI1.OVL+'+k for k in ['422F','4275','428E','22CB','66FA','230E']]
        cls.direct=gather(CAPTURE,{k:(0,0) for k in keys},include_nested_returns=True)
        cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}

    def test_sum_read_order_low_count_and_flags(self):
        p=self.packets['PLI1.OVL+452B']
        for iv in p['invocations']:
            entry=p['steps'][str(iv['entry_step'])]['before']; source=pair(entry,'b','c'); count=entry['e']
            reads=local(p,iv,0x4552)
            self.assertEqual([s['reads'][0]['address'] for s in reads],[(source+i)&65535 for i in reversed(range(count))])
            expected=sum(s['reads'][0]['value'] for s in reads)&127
            ret=p['steps'][str(iv['return_step'])]['after']
            self.assertEqual(ret['a'],expected)
            self.assertEqual(ret['flags']['carry'],False)
            self.assertEqual(ret['flags']['zero'],expected==0)
            self.assertEqual(ret['flags']['parity'],expected.bit_count()%2==0)
            self.assertEqual(pair(ret,'d','e'),pair(entry,'d','e'))
            self.assertEqual(pair(ret,'b','c'),0)
            self.assertEqual(pair(ret,'h','l'),0xA903)
            self.assertEqual([s['control']['taken'] for s in local(p,iv,0x453E)],[False]*count+[True])
            writes=[q['address'] for n in iv['local_steps'] for q in p['steps'][str(n)]['writes']]
            self.assertTrue(set(writes)<={0xA760,0xA901,0xA902,0xA903})
            self.assertFalse(set(writes)&{0xA947,0xA948})

    def test_slot_selection_and_successor_word(self):
        for r in self.direct['PLI1.OVL+422F']:
            ws=r['own_witnesses']; index=ws[0]['reads'][0]['value']; lo=at(ws,0x4239)[0]['reads'][0]; hi=at(ws,0x423B)[0]['reads'][0]
            self.assertEqual([lo['address'],hi['address']],[0xA761+2*index,0xA762+2*index])
            value=lo['value']+256*hi['value']; out=r['ret']['after']
            self.assertEqual(pair(out,'h','l'),value)
            self.assertEqual({q['address']:q['new_value'] for q in at(ws,0x423D)[0]['writes']},{0xA863:value&255,0xA864:value>>8})
            self.assertEqual(out['a'],r['entry']['before']['a'])
        for r in self.direct['PLI1.OVL+428E']:
            ws=r['own_witnesses']; pointer=at(ws,0x4291)[0]['reads']; pointer=pointer[0]['value']+256*pointer[1]['value']
            lo=at(ws,0x4295)[0]['reads'][0]; hi=at(ws,0x4297)[0]['reads'][0]
            self.assertEqual([lo['address'],hi['address']],[(pointer+8)&65535,(pointer+9)&65535])
            out=r['ret']['after']; self.assertEqual(pair(out,'h','l'),lo['value']+256*hi['value'])
            self.assertEqual(pair(out,'d','e'),(pointer+9)&65535)
            self.assertEqual(out['a'],r['entry']['before']['a'])
            self.assertEqual(out['flags']['carry'],pointer+8>65535)

    def test_complemented_borrow_is_value_not_returned_carry(self):
        for r in self.direct['PLI1.OVL+4275']:
            ws=r['own_witnesses']; child=r['nested_returns'][at(ws,0x427B)[0]['step_index']]
            reads={q['address']:q['value'] for w in child['memory_witnesses'] for q in w['reads']}
            pointer=reads[0xA863]+256*reads[0xA864]; reference=reads[0xA8AB]+256*reads[0xA8AC]
            borrow=pointer<reference; out=r['ret']['after']
            self.assertEqual(out['a'],0 if borrow else 255)
            self.assertEqual(out['flags']['carry'],borrow)
            self.assertEqual(out['flags']['zero'],not borrow)
            self.assertNotEqual(out['flags']['zero'],out['a']==0)
            self.assertEqual(out['flags'],at(ws,0x427E)[0]['after']['flags'])
            self.assertEqual(pair(out,'h','l'),(pointer-reference)&65535)
        p=self.packets['PLI1.OVL+46ED']
        for iv in p['invocations']:
            children=[p['calls'][str(n)] for n in iv['nested_calls'] if p['calls'][str(n)]['target']=='PLI1.OVL+4275']
            for c,branch in zip(children,local(p,iv,0x4702)):
                state=p['steps'][str(c['post_return_state_step'])]['after']
                self.assertEqual(branch['control']['taken'],not bool(state['a']&1))
            self.assertEqual([p['steps'][str(c['post_return_state_step'])]['after']['a'] for c in children],[255,0])

    def test_payload_comparison_and_return_are_not_a_boolean_mask(self):
        p=self.packets['PLI1.OVL+4584']
        for iv in p['invocations']:
            entry=p['steps'][str(iv['entry_step'])]['before']; source=pair(entry,'b','c'); n=entry['e']
            header=local(p,iv,0x459B)[0]['reads'][0]; pointer=header['address']
            self.assertEqual((header['value']-10)&255,n)
            child=next(c for c in p['calls'].values() if c['invocation']==iv['call_step'])
            reads={q['address']:q['value'] for w in child['callee_memory_effects']['guest_instruction_accesses'] for q in w['reads']}
            top=reads[0x1C36]+256*reads[0x1C37]
            self.assertEqual(pointer,reads[0xA863]+256*reads[0xA864])
            self.assertEqual(local(p,iv,0x4595)[0]['control']['taken'],pointer<=top)
            self.assertEqual(pair(p['steps'][str(child['post_return_state_step'])]['after'],'h','l'),(top-pointer)&65535)
            for k,a,b,branch in zip(reversed(range(n)),local(p,iv,0x45D0),local(p,iv,0x45D1),local(p,iv,0x45D2)):
                self.assertEqual(a['reads'][0]['address'],(source+k)&65535)
                self.assertEqual(b['reads'][0]['address'],(pointer+10+k)&65535)
                self.assertEqual(a['reads'][0]['value'],b['reads'][0]['value'])
                self.assertFalse(branch['control']['taken'])
            self.assertEqual([s['control']['taken'] for s in local(p,iv,0x45DA)],[True]*(n-1)+[False])
            out=p['steps'][str(iv['return_step'])]['after']
            self.assertEqual((out['a'],pair(out,'b','c'),pair(out,'d','e'),pair(out,'h','l')),(0,10,source,pointer+10))
            self.assertTrue(out['flags']['zero']);self.assertFalse(out['flags']['carry'])
            self.assertFalse(any(q['address'] in [0xA863,0xA864,0xA947,0xA948] for n in iv['local_steps'] for q in p['steps'][str(n)]['writes']))

    def test_actual_word_add_target_and_cached_operand_identity(self):
        self.assertNotIn('PLI1.OVL+84BB',self.catalog)
        for r in self.direct['PLI1.OVL+66FA']:
            call=at(r['own_witnesses'],0x6704)[0]
            self.assertEqual(coord(call['target_origin']),'PLI1.OVL+82BB')
            self.assertEqual(call['pc_after'],0x2200+0x82BB)
            child=r['nested_returns'][call['step_index']];reads={q['address']:q['value'] for w in child['memory_witnesses'] for q in w['reads']}
            first=pair(call['before'],'h','l'); second=pair(call['before'],'d','e')
            a=reads[first]+256*reads[(first+1)&65535];b=reads[second]+256*reads[(second+1)&65535]
            out=r['ret']['after']
            self.assertEqual(pair(out,'h','l'),(a+b)&65535)
            self.assertEqual(pair(out,'b','c'),a)
            self.assertEqual(pair(out,'d','e'),(second+1)&65535)
            self.assertEqual(out['flags']['carry'],a+b>65535)
            self.assertEqual(self.catalog['PLI1.OVL+82BB']['completeness']['contract'],'complete')

    def test_word_writer_and_full_processing_bit_order(self):
        p=self.packets['PLI.COM+1207']
        # Equal zero bytes cannot prove low/high source identity. The exact
        # moves and ordered little-endian loads do so independently of values.
        self.assertEqual(p['instructions']['PLI.COM+1217']['decoded'],'MOV A,L')
        self.assertEqual(p['instructions']['PLI.COM+1221']['decoded'],'MOV A,H')
        for iv in p['invocations']:
            entry=p['steps'][str(iv['entry_step'])]['before'];calls=[p['calls'][str(n)] for n in iv['nested_calls']]
            args=[(p['steps'][str(c['pre_call_state_step'])]['before']['c'],p['steps'][str(c['pre_call_state_step'])]['before']['e']) for c in calls]
            self.assertEqual(args,[(0x80,2),(entry['c'],8),(entry['b'],8)])
            for offset in (0x1214,0x121E):
                self.assertEqual([q['address'] for q in local(p,iv,offset)[0]['reads']],[0x20BD,0x20BE])
            for c,(value,count) in zip(calls,args):
                effects=c['callee_memory_effects']['guest_instruction_accesses']
                writer_inputs=[q['new_value']&1 for w in effects for q in w['writes'] if q['address']==0x20B6]
                self.assertEqual(writer_inputs,bits(value,count))
                self.assertFalse(any(q['address'] in [0x20BD,0x20BE,0xA863,0xA864,0xA947,0xA948] for w in effects for q in w['writes']))
        p=self.packets['PLI1.OVL+666E'];iv=p['invocations'][0]
        effects=[w for n in iv['nested_calls'] for w in p['calls'][str(n)]['callee_memory_effects']['guest_instruction_accesses']]
        actual=[q['new_value']&1 for w in effects for q in w['writes'] if q['address']==0x20B6]
        payload=[q['value'] for w in effects if w['coordinate']=='PLI1.OVL+66EC' for q in w['reads']]
        expected=bits(0x96,7)+[1,0]+[0]*16
        for byte in payload:expected += [0]+bits(byte,8)
        self.assertEqual(len(payload),7);self.assertEqual(len(actual),88);self.assertEqual(actual,expected)

    def test_default_literal_result_and_increments_keep_carry(self):
        for r in self.direct['PLI1.OVL+22CB']:
            ws=r['own_witnesses'];v=at(ws,0x22FC)[0]['reads'][0]['value'];out=r['ret']['after']
            self.assertEqual(v,5);self.assertEqual(out['a'],2)
            self.assertEqual(out['flags']['carry'],v<0x19)
            self.assertEqual(out['flags']['zero'],v==0x19)
            self.assertEqual(out['flags']['parity'],((v-0x19)&255).bit_count()%2==0)
        for r in self.direct['PLI1.OVL+230E']:
            ws=r['own_witnesses']
            if at(ws,0x2348):
                self.assertEqual([at(ws,o)[0]['after']['a'] for o in [0x234B,0x234C]],[3,4])
                self.assertTrue(r['ret']['after']['flags']['carry'])

    def test_promotions_keep_raw_gaps_and_continuation_scopes(self):
        for key in ['46ED','666E','28AA']:
            p=self.catalog['PLI1.OVL+'+key]
            self.assertEqual(p['byte_status_at_entry'],'UNDERSTOOD')
            self.assertEqual(p['completeness'],dict(bounds='provisional',control_flow='partial',contract='partial'))
        p=self.packets['PLI1.OVL+28AA'];iv=p['invocations'][0]
        self.assertEqual(len(iv['local_steps']),351)
        self.assertEqual([c['return_convention']['resumed_coordinate'] for c in p['calls'].values() if c['target']=='PLI1.OVL+6708'],['PLI1.OVL+2988','PLI1.OVL+2AB7'])
        manifest=load(ROOT/'research/annotated-assembly/manifest.json');image=next(i for i in manifest['images'] if i['name']=='PLI1.OVL')
        for a,b in [(0x45E1,0x45E6),(0x45E9,0x45F0)]:
            self.assertTrue(all(status_at(image,o)=='RAW' for o in range(a,b)))
        rows=[json.loads(s) for s in (ROOT/'research/minimal-baseline/instructions.jsonl').read_text().splitlines()]
        dynamic=calculate(manifest,rows)
        self.assertEqual(dynamic,load(ROOT/'research/minimal-baseline/dynamic-progress.json'))
        historical=load(ROOT/'research/minimal-baseline/pass-10/dynamic-progress.json')
        self.assertEqual(historical['total']['occurrences_by_status']['UNDERSTOOD'],210243)
        self.assertEqual(sum(i['length'] for i in manifest['images']),94720)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--images',type=Path,required=True)
    parser.add_argument('--capture',type=Path,default=ROOT/'_build/minimal-baseline/capture')
    args,remaining=parser.parse_known_args();IMAGES,CAPTURE=args.images,args.capture
    unittest.main(argv=[sys.argv[0],*remaining])
