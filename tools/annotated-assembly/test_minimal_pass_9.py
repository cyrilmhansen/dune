#!/usr/bin/env python3
"""Pass-9 scoped equations, correlated publications and continuation ancestry."""
import argparse
import json
import sys
import unittest
from pathlib import Path

from check_minimal_pass_2 import at, coord, pair
from check_minimal_pass_3 import gather
from minimal_baseline import load
from minimal_dynamic_progress import calculate
from procedure_evidence_packet import ROOT, build, verify_return


def selected(packet, offset, invocation=None):
    return [packet['steps'][str(n)] for iv in packet['invocations']
            if invocation is None or iv['call_step'] == invocation
            for n in iv['local_steps']
            if packet['steps'][str(n)]['coordinate'] == f"PLI1.OVL+{offset:04X}"]


def stored(step):
    return {q['address']: q['new_value'] for q in step['writes']}


class MinimalPassNineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Complex procedures use fresh packets as their joined evidence interface.
        cls.packets = {k: build(CAPTURE, IMAGES, 'PLI1.OVL+'+k, 0, ())
                       for k in ('28AA', '46ED', '4738', '666E', '2355', '66C6')}
        keys = ['PLI1.OVL+'+k for k in
                ('213C', '2185', '21AD', '230E', '7AF0', '7B13', '7B49', '66FA', '4394', '429D')]
        cls.small = gather(CAPTURE, {k: (0, 0) for k in keys}, include_nested_returns=True)
        cls.catalog = {p['id']: p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}

    def test_small_returns_and_mapped_write_equations(self):
        for records in self.small.values():
            for r in records:
                verify_return(r['call'], r['ret'], r['relation'])
        for suffix, base, scratch, word in [
                 ('7AF0', 0xAB49, 0xAE3E, True), ('7B13', 0xAC73, 0xAE41, False),
                 ('7B49', 0xAD9D, 0xAE45, False)]:
            for r in self.small['PLI1.OVL+'+suffix]:
                ws = r['own_witnesses']; entry = r['entry']['before']; out = r['ret']['after']
                position, value = entry['c'], pair(entry, 'd', 'e') if word else entry['e']
                lookup = next(w for w in ws if w['disassembly'] == 'MOV C,M')
                self.assertEqual(lookup['reads'][0]['address'], 0xAA1F+position)
                j = lookup['reads'][0]['value']; destination = base+(2*j if word else j)
                writes = {q['address']: q['new_value'] for w in ws for q in w['writes']}
                self.assertEqual(writes[scratch], position)
                self.assertEqual(writes[scratch+1], value & 255)
                self.assertEqual(writes[destination], value & 255)
                if word:
                    self.assertEqual(writes[scratch+2], value >> 8)
                    self.assertEqual(writes[destination+1], value >> 8)
                    self.assertEqual(out['a'], entry['a'])
                else:
                    self.assertEqual(out['a'], entry['e'])
                self.assertEqual(pair(out, 'b', 'c'), j)
                self.assertEqual(pair(out, 'h', 'l'), destination+int(word))
                self.assertEqual(pair(out, 'd', 'e'), pair(entry, 'd', 'e'))
                self.assertFalse(out['flags']['carry'])
                for flag in ('zero', 'sign', 'parity', 'auxiliary_carry'):
                    self.assertEqual(out['flags'][flag], entry['flags'][flag])
                self.assertNotIn(0xAA1F+position, writes)
                self.assertNotIn(0x1B4B, writes)  # Fixed packed attributes are separate.

    def test_predicate_byte_and_flag_channels(self):
        self.assertEqual([(r['entry']['before']['c'], r['ret']['after']['a'])
                          for r in self.small['PLI1.OVL+213C']], [(0x40,0),(0x28,0)])
        for r in self.small['PLI1.OVL+213C']:
            c = r['entry']['before']['c']; out = r['ret']['after']
            self.assertNotIn(c, (0x0B, 0x0C, 0x0D, 2, 3, 4))
            self.assertEqual(out['a'], 0)
            self.assertEqual(out['flags']['carry'], c < 4)
            self.assertEqual(out['flags']['zero'], c == 4)
            self.assertEqual(out['flags']['parity'], ((c-4)&255).bit_count() % 2 == 0)
            self.assertEqual(pair(out, 'd', 'e'), pair(r['entry']['before'], 'd', 'e'))
        for r in self.small['PLI1.OVL+2185']:
            c = r['entry']['before']['c']; ws = r['own_witnesses']
            self.assertEqual(at(ws, 0x2190)[0]['control']['taken'], (c & 0xF0) != 0x10)
            child = r['nested_returns'][at(ws, 0x219A)[0]['step_index']]
            self.assertEqual(at(ws, 0x219E)[0]['control']['taken'], not (child['ret']['after']['a'] & 1))
            self.assertEqual(r['ret']['after']['a'], 255 if c == 0x31 else 0)
            self.assertEqual(r['ret']['after']['flags'], at(ws, 0x21AB)[0]['after']['flags'])
        for r in self.small['PLI1.OVL+21AD']:
            c = r['entry']['before']['c']; ws = r['own_witnesses']
            carry = ((c-0x30)&255)+255 > 255
            self.assertEqual(at(ws, 0x21B6)[0]['after']['flags']['carry'], carry)
            branch = at(ws, 0x21C6)[0]
            self.assertEqual(branch['control']['taken'], not (c != 0x30 and c <= 0x31))
            if not branch['control']['taken']:
                self.assertEqual(r['ret']['after']['a'], 1)
            else:
                call = at(ws, 0x21D0)[0]
                self.assertEqual(r['ret']['after']['a'], r['nested_returns'][call['step_index']]['ret']['after']['a'])
        for r in self.small['PLI1.OVL+230E']:
            ws = r['own_witnesses']; v = at(ws, 0x231B)[0]['reads'][0]['value']
            self.assertEqual(at(ws, 0x232C)[0]['control']['taken'], v not in (0x24, 0x25))
            self.assertEqual(at(ws, 0x233E)[0]['control']['taken'], v != 0x28)
            if v == 0x28:
                self.assertEqual(r['ret']['after']['a'], 1)
            else:
                child = r['nested_returns'][at(ws, 0x2348)[0]['step_index']]['ret']['after']
                self.assertEqual(r['ret']['after']['a'], (child['a']+2)&255)
                self.assertEqual(r['ret']['after']['flags']['carry'], child['flags']['carry'])
                self.assertEqual(r['ret']['after']['flags'], at(ws, 0x234C)[0]['after']['flags'])

    def test_saved_psw_is_a_proven_local_writer_not_an_extra_argument(self):
        p = self.packets['28AA']; save = selected(p, 0x2956)[0]; pop = selected(p, 0x2988)[0]
        call = next(c for c in p['calls'].values() if c['callsite'] == 'PLI1.OVL+2953')
        self.assertEqual(p['steps'][str(call['post_return_state_step'])]['after']['a'], 0)
        self.assertEqual({q['address']: q['value'] for q in pop['reads']}, stored(save))
        saved_addresses = set(stored(save)); child = next(c for c in p['calls'].values() if c['callsite'] == 'PLI1.OVL+2985')
        proof, relation = child['software_return_proof'], child['return_convention']
        arguments = {q['address'] for w in proof['prefix'] if w['step_index'] in relation['argument_pop_steps'] for q in w['reads']}
        self.assertFalse(saved_addresses & arguments)
        self.assertFalse(saved_addresses & {relation['relocated_return_slot'], relation['relocated_return_slot']+1})
        # Writer ancestry: every intervening parent/child guest write is checked,
        # not just equality between the two endpoint byte values. +6708's scoped
        # copy arm has no calls/host effects (established pass-8 contract).
        iv = p['invocations'][0]
        save_step = next(n for n in iv['local_steps'] if p['steps'][str(n)] is save)
        pop_step = next(n for n in iv['local_steps'] if p['steps'][str(n)] is pop)
        writes = [q['address'] for n in iv['local_steps'] if save_step < n < pop_step
                  for q in p['steps'][str(n)]['writes']]
        writes += [q['address'] for e in child['callee_memory_effects']['guest_instruction_accesses'] for q in e['writes']]
        self.assertFalse(saved_addresses & set(writes))
        self.assertFalse(any(p['instructions'][e['coordinate']]['decoded'].startswith('CALL')
                             for e in child['callee_memory_effects']['guest_instruction_accesses']))
        expected = not (save['before']['a'] & proof['ret']['after']['a'] & 1)
        self.assertEqual(selected(p, 0x298C)[0]['control']['taken'], expected)
        self.assertEqual(selected(p, 0x2AB8)[0]['control']['taken'], bool(next(c for c in p['calls'].values() if c['callsite']=='PLI1.OVL+2AB4')['software_return_proof']['ret']['after']['a'] & 1))

    def test_traversal_and_wrapper_preserve_correlated_pointer_roles(self):
        p = self.packets['46ED']
        for iv in p['invocations']:
            for offset, target, taken_bit in [(0x4702, 'PLI1.OVL+4275', False), (0x470F, 'PLI1.OVL+4281', False), (0x4720, 'PLI1.OVL+4281', True)]:
                site = {0x4702: 0x46FE, 0x470F: 0x470B, 0x4720: 0x471C}[offset]
                cs = [c for c in p['calls'].values() if c['invocation']==iv['call_step'] and c['callsite']==f'PLI1.OVL+{site:04X}']
                for c, branch in zip(cs, selected(p, offset, iv['call_step'])):
                    a = p['steps'][str(c['post_return_state_step'])]['after']['a']
                    self.assertEqual(c['target'], target)
                    self.assertEqual(branch['control']['taken'], bool(a&1) == taken_bit)
        p = self.packets['4738']; self.assertFalse(selected(p, 0x4747)[0]['control']['taken'])
        old = stored(selected(p, 0x4765)[0]); old_word = old[0xA917]+256*old[0xA918]
        self.assertEqual(old_word, 0)
        self.assertEqual(stored(selected(p, 0x4775)[0]), {0xFBE3: 7})
        self.assertEqual(stored(selected(p, 0x4777)[0]), {0xFBE4: 0})
        self.assertEqual(stored(selected(p, 0x4789)[0]), {0xFBBB: old_word & 255})
        self.assertEqual(stored(selected(p, 0x478B)[0]), {0xFBBC: old_word >> 8})
        child = next(c for c in p['calls'].values() if c['target']=='PLI1.OVL+4468')
        self.assertEqual(child['return_convention']['resumed_coordinate'], 'PLI1.OVL+4759')

    def test_processing_mask_and_buffer_call_order(self):
        p = self.packets['666E']; iv = p['invocations'][0]
        targets = [p['calls'][str(n)]['target'] for n in iv['nested_calls']]
        self.assertEqual(targets, ['PLI1.OVL+41A6', 'PLI.COM+119E', 'PLI1.OVL+66FA', 'PLI.COM+1207', 'PLI1.OVL+66C6'])
        self.assertEqual(selected(p, 0x6681)[0]['after']['a'], 0x29 & 31)
        self.assertFalse(selected(p, 0x668B)[0]['control']['taken'])
        p = self.packets['66C6']; iv = p['invocations'][0]
        self.assertEqual([p['calls'][str(n)]['target'] for n in iv['nested_calls']], ['PLI.COM+1140','PLI.COM+119E']*7)
        for c in p['calls'].values():
            before = p['steps'][str(c['pre_call_state_step'])]['before']
            if c['target']=='PLI.COM+1140': self.assertEqual(before['c'], 0)
            else: self.assertEqual(before['e'], 8)
        self.assertEqual([s['reads'][0]['address'] for s in selected(p, 0x66EC)], list(range(0xA948, 0xA94F)))
        self.assertEqual([s['reads'][0]['value'] for s in selected(p, 0x66DA)], list(range(8)))
        self.assertEqual([s['control']['taken'] for s in selected(p, 0x66DB)], [False]*7+[True])
        self.assertEqual(p['steps'][str(iv['return_step'])]['after']['a'], 6)

    def test_result_dispatch_and_distinct_parent_publications(self):
        p = self.packets['2355']
        members = []
        for iv in p['invocations']:
            c = next(c for c in p['calls'].values() if c['invocation']==iv['call_step'] and c['target']=='PLI1.OVL+21AD')
            a = p['steps'][str(c['post_return_state_step'])]['after']['a']
            self.assertEqual(selected(p, 0x2367, iv['call_step'])[0]['control']['taken'], bool(a&1))
            out = p['steps'][str(iv['return_step'])]['after']
            members.append((p['steps'][str(iv['entry_step'])]['before']['c'],
                            p['steps'][str(c['pre_call_state_step'])]['before']['c'], out['a']))
            if not (a&1): self.assertEqual(out['a'], 5)
            else:
                delegated = next(c for c in p['calls'].values() if c['invocation']==iv['call_step'] and c['target']=='PLI1.OVL+230E')
                delegated_out = p['steps'][str(delegated['post_return_state_step'])]['after']
                for field in ('a','b','c','d','e','h','l','flags'):
                    self.assertEqual(out[field], delegated_out[field])
        self.assertEqual(members, [(0,0x40,5),(0,5,4),(0,5,4),(2,0x28,1),(2,0x28,1)])
        p = self.packets['28AA']
        expected = {0x7AF0: [{0xAB4D:0xB5,0xAB4E:0xFB}], 0x7B13:[{0xAC75:0x28},{0xAC73:0x28}],
                    0x7B2E:[{0xAD0A:7},{0xAD08:7}], 0x7B49:[{0xAD9F:0},{0xAD9D:0}], 0x7AD5:[{0xAAB6:2},{0xAAB4:0x14}]}
        for target, groups in expected.items():
            cs = [c for c in p['calls'].values() if c['target']==f'PLI1.OVL+{target:04X}']
            for c, group in zip(cs, groups):
                writes = {q['address']:q['new_value'] for e in c['callee_memory_effects']['guest_instruction_accesses'] for q in e['writes']}
                self.assertEqual({a:writes[a] for a in group}, group)
            self.assertEqual(len(cs), len(groups))
        for offset, value in [(0x2B49,0x29),(0x2B5E,7),(0x2B72,0)]:
            self.assertEqual(next(iter(stored(selected(p,offset)[0]).values())), value)

    def test_partial_boundaries_secondary_gaps_and_live_progress(self):
        for key in ('28AA','4B69'):
            self.assertEqual(self.catalog['PLI1.OVL+'+key]['completeness'], {'bounds':'provisional','control_flow':'partial','contract':'partial'})
        historical = json.loads((ROOT/'research/minimal-baseline/pass-9/regions.json').read_text())
        self.assertEqual(next(p for p in historical if p['entry']=='PLI1.OVL+28AA')['byte_status'], 'STRUCTURED')
        for r in self.small['PLI1.OVL+4394']:
            self.assertTrue(at(r['own_witnesses'],0x43B5)[0]['control']['taken'])
        self.assertEqual(len(self.small['PLI1.OVL+429D']),1)
        self.assertEqual(at(self.small['PLI1.OVL+429D'][0]['own_witnesses'],0x42B4)[0]['after']['a'],0x30)
        manifest = load(ROOT/'research/annotated-assembly/manifest.json')
        self.assertEqual(sum(i['length'] for i in manifest['images']),94720)
        rows = [json.loads(s) for s in (ROOT/'research/minimal-baseline/instructions.jsonl').read_text().splitlines()]
        self.assertEqual(calculate(manifest,rows),load(ROOT/'research/minimal-baseline/dynamic-progress.json'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--images', type=Path, required=True)
    parser.add_argument('--capture', type=Path, default=ROOT/'_build/minimal-baseline/capture')
    args, remaining = parser.parse_known_args(); IMAGES, CAPTURE = args.images, args.capture
    unittest.main(argv=[sys.argv[0],*remaining])
