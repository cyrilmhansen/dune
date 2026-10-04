#!/usr/bin/env python3
"""Bounded FIZZBUZ delta: correlated recursion, read-only fallback and N2 slot publication."""
import argparse
import copy
import hashlib
import json
import sys
import unittest
from collections import Counter
from pathlib import Path
from check_minimal_pass_2 import at,coord,pair,word
from check_minimal_pass_8 import gather as cleanup
from minimal_baseline import load,status_at
from minimal_dynamic_progress import calculate
from procedure_evidence_packet import ROOT,build
from software_continuation import prove


def local(packet,iv,offset):
    return [packet['steps'][str(n)] for n in iv['local_steps']
            if packet['steps'][str(n)]['coordinate']==f'PLI1.OVL+{offset:04X}']

class FizzbuzPassThirteenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
        cls.packets={key:build(CAPTURE,IMAGES,'PLI1.OVL+'+key,5 if key=='7C1B' else 0,(0,3) if key=='7C1B' else (),run='FIZZBUZ') for key in ['7C1B','4738','4693']}
        cls.constructors=cleanup(CAPTURE)['PLI1.OVL+4468']

    def test_selected_run_REL_and_exact_invocation_caller_metadata(self):
        summary=load(CAPTURE/'run-summary.json');self.assertTrue(all(summary[k] for k in ['pass1_success','pass2_success','end_compilation']))
        rel=(CAPTURE/'FIZZBUZ.REL').read_bytes();self.assertEqual(len(rel),768)
        self.assertEqual(hashlib.sha256(rel).hexdigest(),'68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203')
        for suffix,p in self.packets.items():
            key='PLI1.OVL+'+suffix;self.assertEqual(p['run_id'],load(CAPTURE/'event-witnesses.json')['run_id']);self.assertTrue(p['run_id'].startswith('FIZZBUZ:'))
            self.assertEqual(len(p['invocations']),self.catalog[key]['observed_paths']['invocations_by_run']['FIZZBUZ'])
            observed=Counter(iv['caller'] for iv in p['invocations']);expected=Counter({c['coordinate']:c['counts_by_run']['FIZZBUZ'] for c in self.catalog[key]['callers'] if 'FIZZBUZ' in c['counts_by_run']});self.assertEqual(observed,expected)
        self.assertEqual([len(self.packets[k]['invocations']) for k in ['7C1B','4738','4693']],[96,3,8])
        self.assertEqual(len(self.constructors),11);p=self.catalog['PLI1.OVL+4468'];self.assertEqual(p['observed_paths']['invocations_by_run']['FIZZBUZ'],11)
        self.assertEqual(Counter(coord(r['call']['origin']) for r in self.constructors),Counter({c['coordinate']:c['counts_by_run']['FIZZBUZ'] for c in p['callers']}))
        self.assertEqual(self.catalog['PLI1.OVL+7C1B']['observed_paths']['invocations_by_run']['MINIMAL'],16);self.assertEqual(p['observed_paths']['invocations_by_run']['MINIMAL'],2)

    def test_special_arm_exact_states_order_and_primary_publication(self):
        p=self.packets['7C1B'];members=[iv for iv in p['invocations'] if local(p,iv,0x7C56)]
        self.assertEqual([iv['call_step'] for iv in members],[618240])
        for iv in members:
            f=iv['F'];mapped=local(p,iv,0x7C2C)[0]['writes'][0]['new_value'];self.assertEqual(mapped,0x1E)
            self.assertEqual(p['steps'][str(iv['entry_step'])]['before']['c'],5)
            calls=[p['calls'][str(n)] for n in iv['nested_calls']]
            self.assertEqual([c['target'] for c in calls],['PLI1.OVL+'+s for s in ['7A4D','7C1B','7B7A','7C1B','7B2E']])
            args=[p['steps'][str(c['pre_call_state_step'])]['before'] for c in calls]
            outputs=[p['steps'][str(c['post_return_state_step'])]['after'] for c in calls]
            self.assertEqual([a['c'] for a in args],[5,4,4,2,5]);self.assertEqual([o['a'] for o in outputs],[30,1,3,15,15])
            first,second=outputs[1]['a'],outputs[3]['a'];value=min(15,(max(first,second)+1)&255)
            self.assertEqual(local(p,iv,0x7C64)[0]['writes'][0]['new_value'],first);self.assertEqual(local(p,iv,0x7C78)[0]['writes'][0]['new_value'],second)
            self.assertEqual(local(p,iv,0x7C8F)[0]['writes'][0]['new_value'],second);self.assertEqual(local(p,iv,0x7C94)[0]['writes'][0]['new_value'],16);self.assertEqual(local(p,iv,0x7C9F)[0]['writes'][0]['new_value'],value)
            self.assertEqual(args[-1]['e'],value)
            effect=calls[-1]['callee_memory_effects']['guest_instruction_accesses'];writes={q['address']:q['new_value'] for w in effect for q in w['writes']}
            self.assertEqual(writes,{0xAE44:value,0xAE43:5,0xAD0D:value})
            self.assertFalse(any(q['address']==f for w in [p['steps'][str(n)] for n in iv['local_steps']] if w['coordinate']!='PLI1.OVL+7C1E' for q in w['writes']))
            out=p['steps'][str(iv['return_step'])]['after'];self.assertEqual((out['a'],pair(out,'h','l')), (value,(second<<8)|mapped))
            for flag in ['sign','zero','parity','auxiliary_carry']:self.assertEqual(out['flags'][flag],local(p,iv,0x7C97)[0]['after']['flags'][flag])
            self.assertEqual(out['flags']['carry'],local(p,iv,0x7CB1)[0]['after']['flags']['carry'])
            self.assertNotEqual(out['flags'],outputs[3]['flags'])
        self.assertFalse(any(local(p,iv,0x7C2C)[0]['writes'][0]['new_value']==0x21 for iv in p['invocations']))

    def test_all_relevant_branch_polarities_have_actual_producers(self):
        p=self.packets['7C1B'];special=next(iv for iv in p['invocations'] if local(p,iv,0x7C56))
        for iv in p['invocations']:
            b=local(p,iv,0x7C53)
            if b:
                mapped=local(p,iv,0x7C2C)[0]['writes'][0]['new_value'];producer=local(p,iv,0x7C52)[0]
                self.assertEqual(b[0]['before']['flags'],producer['after']['flags']);self.assertEqual(producer['after']['flags']['carry'],mapped in [30,33]);self.assertEqual(b[0]['control']['taken'],mapped not in [30,33])
                self.assertEqual(producer['before']['a'],255 if mapped in [30,33] else 0)
            b=local(p,iv,0x7CCD)
            if b:
                cmp=local(p,iv,0x7CCB)[0];self.assertEqual(b[0]['before']['flags'],cmp['after']['flags']);self.assertEqual(b[0]['control']['taken'],cmp['before']['a']==10)
        cmp=local(p,special,0x7C82)[0];branch=local(p,special,0x7C83)[0]
        self.assertEqual(branch['before']['flags'],cmp['after']['flags']);self.assertEqual(branch['control']['taken'],cmp['before']['a']>=cmp['reads'][0]['value'])
        cmp=local(p,special,0x7C97)[0];branch=local(p,special,0x7C98)[0]
        self.assertEqual(branch['before']['flags'],cmp['after']['flags']);self.assertEqual(branch['control']['taken'],cmp['reads'][0]['value']<=15)
        self.assertFalse(branch['control']['taken'])

    def test_predecessor05_returns_current_auxiliary_without_publication(self):
        p=self.packets['7C1B'];members=[iv for iv in p['invocations'] if local(p,iv,0x7CD0)];self.assertEqual(len(members),6)
        self.assertEqual([iv['call_step'] for iv in members],[376381,406180,475962,542692,608347,619581])
        for iv in members:
            entry=p['steps'][str(iv['entry_step'])]['before'];position=entry['c'];self.assertEqual(local(p,iv,0x7C2C)[0]['writes'][0]['new_value'],23)
            self.assertEqual(local(p,iv,0x7CCB)[0]['before']['a'],5)
            calls=[p['calls'][str(n)] for n in iv['nested_calls']];self.assertEqual([c['target'] for c in calls],['PLI1.OVL+7A4D','PLI1.OVL+7A4D','PLI1.OVL+7AA9'])
            args=[p['steps'][str(c['pre_call_state_step'])]['before']['c'] for c in calls];self.assertEqual(args,[position,(position-1)&255,position])
            effects=calls[-1]['callee_memory_effects']['guest_instruction_accesses'];mapped=next(q['value'] for w in effects for q in w['reads'] if q['address']==0xAA1F+position)
            read=next(q for w in effects for q in w['reads'] if q['address']==0xAD08+mapped);self.assertEqual(read['value'],15)
            self.assertEqual([(q['address'],q['new_value']) for w in effects for q in w['writes']],[(0xAE3A,position)])
            out=p['steps'][str(iv['return_step'])]['after'];self.assertEqual(out['a'],read['value']);self.assertEqual(pair(out,'d','e'),pair(entry,'d','e'));self.assertEqual(pair(out,'h','l'),(entry['h']<<8)|23)
            for flag in ['sign','zero','parity','auxiliary_carry']:self.assertEqual(out['flags'][flag],local(p,iv,0x7CCB)[0]['after']['flags'][flag])
            self.assertFalse(out['flags']['carry']);self.assertFalse(local(p,iv,0x7CEA));self.assertFalse(local(p,iv,0x7CF5))

    def test_software_children_isolated_and_cleanup_ancestry_exact(self):
        children=0;empty=0;by={r['call']['step_index']:r for r in self.constructors}
        for suffix in ['4693','4738']:
            p=self.packets[suffix]
            for iv in p['invocations']:
                c=next(p['calls'][str(n)] for n in iv['nested_calls'] if p['calls'][str(n)]['target']=='PLI1.OVL+4468');children+=1
                proof=c['software_return_proof'];relation=prove(proof);r=by[relation['call_step']];is_empty=bool(at(r['own_witnesses'],0x44E7));empty+=is_empty
                self.assertEqual(is_empty,suffix=='4693');self.assertEqual(relation['consumed_caller_bytes'],2);self.assertEqual(relation['final_SP_minus_preCALL'],2);self.assertEqual(relation['relocated_return_slot'],(relation['original_return_slot']+2)&65535)
                self.assertEqual(c['return_convention']['resumed_coordinate'],'PLI1.OVL+'+('46A6' if suffix=='4693' else '4759'))
                self.assertFalse(any(relation['call_step']<n<=relation['software_ret_step'] for n in iv['local_steps']))
                resumed=next(p['steps'][str(n)] for n in iv['local_steps'] if n>relation['software_ret_step']);self.assertEqual(resumed['coordinate'],c['return_convention']['resumed_coordinate'])
                argument=next(w for w in proof['prefix'] if w['disassembly']=='POP B');push=local(p,iv,0x469A if suffix=='4693' else 0x474D)[0]
                self.assertEqual({q['address']:q['new_value'] for q in push['writes']},{q['address']:q['value'] for q in argument['reads']})
                # No intervening prefix writer may replace that caller argument.
                addresses={q['address'] for q in argument['reads']};self.assertFalse(any(q['address'] in addresses for w in proof['prefix'] if w['step_index']<argument['step_index'] for q in w['writes']))
                self.assertEqual(word(argument),0x20C6 if suffix=='4693' else 0xA948)
                if is_empty:
                    temp=at(r['own_witnesses'],0x44EB)[0];self.assertEqual(temp['sp_after'],relation['original_return_slot']);self.assertNotEqual(temp['sp_after'],relation['relocated_return_slot'])
        self.assertEqual((children,empty),(11,8))

    def test_empty_slot_exact_read_write_relationship_and_flags(self):
        by={r['call']['step_index']:r for r in self.constructors};p=self.packets['4693']
        for c in p['calls'].values():
            if c['target']!='PLI1.OVL+4468':continue
            r=by[c['pre_call_state_step']];ws=r['own_witnesses'];j=at(ws,0x44EC)[0]['reads'][0]['value'];slot=0xA761+2*j;newp=(word(at(ws,0x44E7)[0])+1)&65535
            effects=c['callee_memory_effects']['guest_instruction_accesses']
            reads=[q for w in effects if w['coordinate'] in ['PLI1.OVL+4239','PLI1.OVL+423B'] for q in w['reads']]
            self.assertEqual([(q['address'],q['value']) for q in reads],[(slot,0),(slot+1,0)])
            rar=at(ws,0x44E3)[0];branch=at(ws,0x44E4)[0];self.assertEqual(rar['before']['a'],0);self.assertEqual(branch['before']['flags'],rar['after']['flags']);self.assertEqual(branch['control']['taken'],bool(rar['before']['a']&1))
            for offset,address,value in [(0x44F7,slot,newp&255),(0x44F9,slot+1,newp>>8)]:
                q=at(ws,offset)[0]['writes'][0];self.assertEqual((q['address'],q['new_value']),(address,value))
                actual=next(e for e in effects if e['step']==at(ws,offset)[0]['step_index']);self.assertEqual([(q['address'],q['new_value']) for q in actual['writes']],[(address,value)])
            writes=at(ws,0x4527)[0]['writes'];self.assertEqual([(q['address'],q['new_value']) for q in writes],[(0xA863,newp&255),(0xA864,newp>>8)])
            self.assertFalse(at(ws,0x4506));self.assertFalse(at(ws,0x4520));out=r['ret']['after'];self.assertEqual((out['a'],pair(out,'b','c'),pair(out,'d','e'),pair(out,'h','l')),(0,newp,0xA864,newp))
            for flag in ['sign','zero','parity','auxiliary_carry']:self.assertEqual(out['flags'][flag],rar['before']['flags'][flag])
            self.assertEqual(out['flags']['carry'],at(ws,0x44F5)[0]['after']['flags']['carry'])

    def test_equal_return_value_does_not_replace_writer_identity(self):
        c=next(c for c in self.packets['4693']['calls'].values() if c['target']=='PLI1.OVL+4468');proof=copy.deepcopy(c['software_return_proof']);proof['relation']['low_byte_writer']['pc']+=1
        # Bytes/target stay identical; only the writer's identity is corrupted.
        with self.assertRaisesRegex(ValueError,'latest writer identity'):prove(proof)
        proof=copy.deepcopy(c['software_return_proof']);proof['relation']['stack_slot']-=2
        with self.assertRaisesRegex(ValueError,'relocated slot'):prove(proof)

    def test_byte_union_scope_and_MINIMAL_progress_unchanged(self):
        evidence=load(ROOT/'research/annotated-assembly/evidence.json');manifest=load(ROOT/'research/annotated-assembly/manifest.json');image=next(i for i in manifest['images'] if i['name']=='PLI1.OVL')
        for key,length in [('7C1B',312),('4468',195)]:
            p=self.catalog['PLI1.OVL+'+key];s=next(s for s in evidence['seeds'] if s['id']==p['id']);self.assertEqual(sum(len(bytes.fromhex(i['bytes'])) for i in s['instructions']),length);self.assertEqual(p['observed_paths']['represented_bytes'],length)
            self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'));self.assertEqual(p['byte_status_at_entry'],'UNDERSTOOD')
        report=load(ROOT/'research/fizzbuz-delta/pass-13/progress.json');self.assertEqual(report['new_understood_bytes'],131)
        rows=[json.loads(s) for s in (ROOT/'research/minimal-baseline/instructions.jsonl').read_text().splitlines()];self.assertEqual(calculate(manifest,rows),load(ROOT/'research/minimal-baseline/dynamic-progress.json'));self.assertEqual(sum(i['length'] for i in manifest['images']),94720)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--images',type=Path,required=True);parser.add_argument('--capture',type=Path,default=ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture')
    args,remaining=parser.parse_known_args();IMAGES,CAPTURE=args.images,args.capture
    unittest.main(argv=[sys.argv[0],*remaining])
