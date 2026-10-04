#!/usr/bin/env python3
"""Packet joins, failure detection, deterministic output and recursive isolation."""

import argparse
import copy
import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from check_minimal_pass_3 import gather
from minimal_baseline import load
from procedure_evidence_packet import ROOT, TARGET, CONTINUATIONS, build, child_return, render, role_matches, selected_run, validate_capture, validate_packet
from evidence_packet_local import call_contract, dependency_chain, derive_local, preserved_address
from software_continuation import prove


class ProjectionTests(unittest.TestCase):
    def test_recursive_children_and_nested_memory_stay_separate(self):
        # Both invocations execute the same coordinates. Extent filtering would
        # incorrectly put the child's instructions in the parent.
        origin = {"image": {"name": "PLI0.OVL"}, "offset": 0x24BC}

        def instruction(step, kind="sequential", writes=None):
            return {"type": "instruction", "witness": {
                "step_index": step, "origin": origin, "target_origin": origin,
                "control": {"kind": kind, "taken": True},
                "reads": [], "writes": writes or []}}

        def returned(step, call):
            return {"type": "hardware_frame_return", "step_index": step,
                    "frame": {"call_step": call}}

        events = [instruction(0, "call"), instruction(1), instruction(2), instruction(3, "call"),
                  instruction(4, writes=[{"address": 123, "new_value": 42}]), instruction(5, "return"),
                  returned(5, 3), instruction(6), instruction(7, "return"), returned(7, 0)]
        with tempfile.TemporaryDirectory(prefix="atlas-evidence-packet-test-", dir="/tmp") as temp:
            capture = Path(temp)
            chunks = capture / "event-witnesses/chunks"
            chunks.mkdir(parents=True)
            (capture / "event-witnesses.json").write_text(json.dumps({"chunks": [{"id": 0}]}))
            (chunks / "000000.json").write_text(json.dumps({"events": events}))
            rs = gather(capture, {TARGET: (0x24BC, 0x289B)}, include_nested_returns=True)[TARGET]
            parent = next(r for r in rs if r["call"]["step_index"] == 0)
            child = next(r for r in rs if r["call"]["step_index"] == 3)
            self.assertEqual([w["step_index"] for w in parent["own_witnesses"]], [1, 2, 3, 6, 7])
            self.assertEqual([w["step_index"] for w in child["own_witnesses"]], [4, 5])
            self.assertEqual([w["step_index"] for w in parent["nested_returns"][3]["memory_witnesses"]], [4])
            (chunks / "000000.json").unlink()
            with self.assertRaises(FileNotFoundError):
                gather(capture, {TARGET: (0x24BC, 0x289B)})

    def test_unknown_role_length_does_not_invent_table_bounds(self):
        role = {"id": "X:t", "name": "t", "runtime_address": 100, "width": None}
        self.assertEqual(role_matches(101, [role]), [])
        self.assertEqual(role_matches(100, [role])[0]["address"], 100)

    def test_preservation_requires_declaration_and_partial_scope(self):
        contract = {"outputs": "flags unchanged", "clobbers": "A,BC,DE,HL",
                    "contract": "No memory writes.", "contract_scope": "declared scope",
                    "completeness": {"contract": "complete"},
                    "returns": {"convention": "ordinary hardware CALL word"}}
        policy = call_contract(contract, "X+0000", "X+0001", [], {})
        self.assertEqual(set(policy['preserved_state']), {'carry', 'zero', 'sign', 'parity'})
        self.assertTrue(policy['all_memory_preserved'])
        guest_only = dict(contract, contract='No guest memory writes.')
        self.assertFalse(call_contract(guest_only, 'X+0000', 'X+0001', [], {})['all_memory_preserved'])
        call = {'contract_presentation': policy, 'pre_call_state_step': 1,
                'callee_memory_effects': {'guest_instruction_accesses': [{'writes': [{'address': 90, 'new_value': 7}]}]}}
        self.assertFalse(preserved_address(call, 90, 100, 0, {'1': {'before': {'sp': 100}}}))
        self.assertFalse(call_contract(None, "X+0000", "X+0001", [], {})['caller_storage_preserved'])
        partial = copy.deepcopy(contract)
        partial['completeness']['contract'] = 'partial'
        partial['contract_scope'] = '+0002 returns A bit0=0; remaining preconditions'
        catalog = {'X+0002': {'returns': {'observed_file_offsets': [3]}}}
        witness = {'step_index': 9, 'origin': {'image': {'name': 'X'}, 'offset': 3}, 'after': {'a': 1}}
        self.assertFalse(call_contract(partial, 'X+0000', 'X+0001', [witness], catalog)['all_memory_preserved'])
        witness['after']['a'] = 0
        supported = call_contract(partial, 'X+0000', 'X+0001', [witness], catalog)
        self.assertTrue(supported['all_memory_preserved'])
        self.assertEqual(supported['scope'], partial['contract_scope'])
        partial['clobbers'] += ',flags'
        self.assertEqual(call_contract(partial, 'X+0000', 'X+0001', [witness], catalog)['preserved_state'], [])

    def test_equal_register_value_does_not_connect_through_opaque_call(self):
        state = {r: 0 for r in 'abcdehl'}
        state['c'] = 1
        state['flags'] = dict(carry=False, zero=False, sign=False, parity=False)
        state['sp'] = 100
        def step(coordinate, before, after, control=None):
            return dict(coordinate=coordinate, before=before, after=after, reads=[], writes=[],
                        control=control or {'kind': 'sequential'})
        decoded = ['MVI C,01H', 'CALL 0009H', 'RET', 'MOV A,C', 'CMA', 'RAR', 'JNC 000AH']
        steps = {}
        previous = copy.deepcopy(state)
        for n, text in enumerate(decoded, 1):
            after = copy.deepcopy(previous)
            if n == 4: after['a'] = 1
            if n == 5: after['a'] = 0xFE
            if n == 6: after['a'] = 0x7F
            steps[str(n)] = step(f'X+{n:04X}', previous, after,
                                {'kind': 'jump', 'taken': True} if n == 7 else None)
            previous = after
        packet = {'entry': 'X+0001', 'instructions': {f'X+{n:04X}': {'decoded': text} for n, text in enumerate(decoded, 1)},
                  'steps': steps, 'calls': {'2': {'pre_call_state_step': 2, 'post_return_state_step': 3,
                    'callsite': 'X+0002', 'target': 'X+0009', 'recursive_child_invocation': None,
                    'contract_presentation': call_contract(None, 'X+0001', 'X+0009', [], {}),
                    'callee_memory_effects': {'guest_instruction_accesses': []}}},
                  'callsites': [], 'branches': {}, 'invocation_classes': [],
                  'invocations': [{'call_step': 0, 'F': 100, 'frame_relation': {'bytes': 0},
                                   'first_written_local_bytes': {}, 'local_steps': [1, 2, 4, 5, 6, 7]}],
                  'accumulated_knowledge': {'roles': [], 'procedure': {'memory_state': []}}}
        derive_local(packet)
        pred = packet['local_dependencies']['branches']['7']
        chain = dependency_chain(packet, pred)
        self.assertIn('2:returned:c', packet['local_dependencies']['nodes'])
        self.assertNotIn(1, [n['step'] for n in chain])
        returned = packet['local_dependencies']['nodes']['2:returned:c']
        self.assertEqual(returned['inputs'], [])
        self.assertEqual(returned['contract']['algorithmic_contract'], 'unavailable')


class SoftwareContinuationPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packets = {key: build(CAPTURE, IMAGES, key, 0, ()) for key in
                       ('PLI1.OVL+28AA', 'PLI1.OVL+4B69', 'PLI1.OVL+4693', 'PLI1.OVL+4738')}
        cls.instances = load(CONTINUATIONS)['instances']

    def test_all_three_families_keep_exact_cleanup_equations(self):
        seen = Counter()
        for p in self.packets.values():
            for c in p['calls'].values():
                if 'software_return_proof' not in c:
                    self.assertEqual(c['return_convention']['kind'], 'ORDINARY HARDWARE RETURN')
                    continue
                proof, r = c['software_return_proof'], c['return_convention']
                n = {'PLI1.OVL+4468': 2, 'PLI1.OVL+6708': 8, 'PLI1.OVL+43D5': 2}[c['target']]
                seen[c['target']] += 1
                self.assertNotIn('hardware_return_proof', c)
                self.assertEqual(r['consumed_caller_bytes'], n)
                self.assertEqual(r['relocated_return_slot'], (r['original_return_slot'] + n) & 65535)
                self.assertEqual(r['final_SP_minus_preCALL'], n)
                self.assertEqual(proof['ret']['sp_after'], (proof['call']['sp_before'] + n) & 65535)
                self.assertEqual(prove(proof), {k: r[k] for k in prove(proof)})
                self.assertEqual(c['contract_presentation']['kind'], 'PARTIAL')
        self.assertEqual(seen, {'PLI1.OVL+4468': 2, 'PLI1.OVL+6708': 2, 'PLI1.OVL+43D5': 1})

    def test_28aa_child_windows_psw_and_outer_return(self):
        p = self.packets['PLI1.OVL+28AA']; iv = p['invocations'][0]
        self.assertEqual(p['quality_checks']['local_instruction_occurrences'], 351)
        children = [c for c in p['calls'].values() if c['target'] == 'PLI1.OVL+6708']
        self.assertEqual([c['return_convention']['resumed_coordinate'] for c in children],
                         ['PLI1.OVL+2988', 'PLI1.OVL+2AB7'])
        for c in children:
            r = c['return_convention']; index = iv['local_steps'].index(r['call_step'])
            resumed = p['steps'][str(iv['local_steps'][index + 1])]
            self.assertEqual(resumed['coordinate'], r['resumed_coordinate'])
            self.assertFalse(any(r['call_step'] < s <= r['software_ret_step'] for s in iv['local_steps']))
            effects = c['callee_memory_effects']['guest_instruction_accesses']
            self.assertTrue(effects)
            self.assertTrue(all(r['call_step'] < e['step'] <= r['software_ret_step'] for e in effects))
        local = [p['steps'][str(s)] for s in iv['local_steps']]
        save = next(s for s in local if s['coordinate'] == 'PLI1.OVL+2956')
        pop = next(s for s in local if s['coordinate'] == 'PLI1.OVL+2988')
        self.assertEqual(p['instructions'][pop['coordinate']]['decoded'], 'POP B')
        self.assertEqual({q['address']: q['value'] for q in pop['reads']},
                         {q['address']: q['new_value'] for q in save['writes']})
        proof = children[0]['software_return_proof']; argument_steps = children[0]['return_convention']['argument_pop_steps']
        arguments = {q['address'] for w in proof['prefix'] if w['step_index'] in argument_steps for q in w['reads']}
        self.assertEqual(len(arguments), 8)
        self.assertFalse(arguments & {q['address'] for q in pop['reads']})
        self.assertIn('PLI1.OVL+2ABF', [s['coordinate'] for s in local])
        self.check_outer(p)

    def check_outer(self, p):
        iv = p['invocations'][0]
        call, ret = [p['steps'][str(iv[k])] for k in ('call_step', 'return_step')]
        self.assertEqual(ret['before']['sp'], call['after']['sp'])
        self.assertEqual(ret['after']['sp'], call['before']['sp'])
        self.assertEqual(iv['hardware_return_proof']['frame']['call_step'], iv['call_step'])
        self.assertEqual({q['address']: q['value'] for q in ret['reads']},
                         {q['address']: q['new_value'] for q in call['writes']})

    def test_4b69_loop_child_and_outer_return(self):
        p = self.packets['PLI1.OVL+4B69']; iv = p['invocations'][0]
        self.assertEqual(p['quality_checks']['local_instruction_occurrences'], 2088)
        c = next(c for c in p['calls'].values() if c['target'] == 'PLI1.OVL+43D5')
        r = c['return_convention']; index = iv['local_steps'].index(r['call_step'])
        self.assertEqual(p['steps'][str(iv['local_steps'][index + 1])]['coordinate'], 'PLI1.OVL+4BBD')
        self.assertFalse(any(r['call_step'] < s <= r['software_ret_step'] for s in iv['local_steps']))
        self.assertEqual(sum(p['steps'][str(s)]['coordinate'] == 'PLI1.OVL+4BB0' for s in iv['local_steps']), 128)
        self.check_outer(p)

    def test_consumed_words_cannot_survive_even_a_preservation_clause(self):
        p = self.packets['PLI1.OVL+28AA']
        c = copy.deepcopy(next(c for c in p['calls'].values() if c['target'] == 'PLI1.OVL+6708'))
        c['contract_presentation']['all_memory_preserved'] = True
        c['callee_memory_effects']['guest_instruction_accesses'] = []
        start = p['steps'][str(c['pre_call_state_step'])]['before']['sp']
        for a in range(start, start + 8):
            self.assertFalse(preserved_address(c, a, 0, 0, p['steps']))
        self.assertTrue(preserved_address(c, start + 8, 0, 0, p['steps']))
        self.assertEqual(c['contract_presentation']['preserved_state'], [])

    def test_corrupt_proofs_fail_in_packet_projection_and_stream_join(self):
        def corrupt(proof, case):
            pop = next(w for w in proof['prefix'] if w['disassembly'] == 'POP D')
            arg = next(w for w in proof['prefix'] if w['disassembly'] == 'POP B')
            event = proof['relation']
            if case == 'writer':
                event['low_byte_writer']['step'] = event['high_byte_writer']['step'] = arg['step_index']
            elif case == 'argument': arg['reads'][0]['address'] += 2
            elif case == 'DE': arg['disassembly'] = 'INX D'
            elif case == 'slot': event['stack_slot'] += 2
            elif case == 'same value wrong word': pop['reads'][0]['address'] += 2
            elif case == 'consumer writer': event['low_byte_writer']['pc'] += 1
            elif case == 'consumer read': proof['ret']['reads'][0]['address'] += 2
            elif case == 'nonunique POP': arg['disassembly'] = 'POP D'
            elif case == 'other register': pop['disassembly'] = 'POP H'
            elif case == 'PCHL': proof['ret']['disassembly'] = 'PCHL'
            elif case == 'declared count': proof['stack_argument_bytes'] += 2
        for instance in self.instances:
            for case in ('writer', 'argument', 'DE', 'slot', 'same value wrong word',
                         'consumer writer', 'consumer read', 'nonunique POP',
                         'other register', 'PCHL', 'declared count'):
                with self.subTest(entry=instance['entry'], case=case):
                    proof = copy.deepcopy(instance['proof']); corrupt(proof, case)
                    nested = {'ret': proof['ret'], 'relation': proof['relation'],
                              'software_proof': proof, 'software_relation': instance['relation']}
                    resumed = {'pc': proof['ret']['pc_after'], 'origin': proof['call']['origin']}
                    with self.assertRaises(ValueError): child_return(proof['call'], nested, resumed)
                    # Exercise gather's actual opt-in joining path, not just prove().
                    parent = copy.deepcopy(proof['call']); parent['step_index'] -= 1
                    parent['target_origin'] = {'image': {'name': 'P'}, 'offset': 0}
                    ret = copy.deepcopy(proof['ret']); ret['step_index'] += 1
                    events = [{'type': 'instruction', 'witness': w} for w in
                              [parent, proof['call'], *proof['prefix'], proof['ret']]]
                    events += [proof['relation'], {'type': 'instruction', 'witness': ret},
                               {'type': 'hardware_frame_return', 'step_index': ret['step_index'],
                                'frame': {'call_step': parent['step_index']}}]
                    with tempfile.TemporaryDirectory(prefix='atlas-software-packet-test-', dir='/tmp') as temp:
                        capture = Path(temp); chunks = capture / 'event-witnesses/chunks'; chunks.mkdir(parents=True)
                        (capture / 'event-witnesses.json').write_text(json.dumps({'chunks': [{'id': 0}]}))
                        (chunks / '000000.json').write_text(json.dumps({'events': events}))
                        with self.assertRaisesRegex(ValueError, 'Software child lacks'):
                            gather(capture, {'P+0000': (0, 1)}, include_nested_returns=True,
                                   software_callees={instance['entry']: proof['stack_argument_bytes']})

    def test_unsupported_outer_profile_and_resume_mismatch(self):
        with self.assertRaisesRegex(ValueError, 'Software outer returns'):
            build(CAPTURE, IMAGES, 'PLI1.OVL+6708', 0, ())
        instance = self.instances[0]; proof = instance['proof']
        with self.assertRaisesRegex(ValueError, 'resume coordinate'):
            child_return(proof['call'], {'ret': proof['ret']}, {'pc': proof['ret']['pc_after'] + 1})


class RunSelectionTests(unittest.TestCase):
    def fixture(self, capture):
        # Deliberately unrelated directory name: only content identifies the run.
        run_id = 'FIZZBUZ:' + 'a' * 64
        image = {'name': 'PLI.COM'}
        witness = dict(step_index=5, origin=dict(image=image, offset=0),
                       bytes='00', disassembly='NOP', pc=256)
        index = dict(run_id=run_id, chunks=[dict(id=0, event_count=1)],
                     summary=dict(instruction_witnesses=1))
        canonical = dict(instructions=[dict(image=image, offset=0, bytes='00', decoded='NOP',
                         execution_count=1, first_step=5, last_step=5,
                         contexts=[dict(runtime_pcs=[256])])])
        chunk = dict(run_id=run_id, chunk_id=0, events=[dict(type='instruction', witness=witness)])
        path = capture / 'event-witnesses/chunks'
        path.mkdir(parents=True)
        (path / '000000.json').write_text(json.dumps(chunk))
        (capture / 'run-summary.json').write_text(json.dumps(
            dict(module='FIZZBUZ', event_witnesses=dict(instruction_witnesses=1))))
        return index, canonical, chunk

    def test_requested_identity_comes_from_content(self):
        with tempfile.TemporaryDirectory(prefix='atlas-packet-run-test-', dir='/tmp') as temp:
            capture = Path(temp)
            index, canonical, _ = self.fixture(capture)
            self.assertEqual(selected_run(index, 'FIZZBUZ'), 'FIZZBUZ')
            validate_capture(capture, index, canonical, 'FIZZBUZ')
            for requested in ['MINIMAL', 'FIZZ', '']:
                with self.assertRaisesRegex(ValueError, 'does not match requested run'):
                    selected_run(index, requested)

    def test_mixed_chunk_summary_and_canonical_capture_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix='atlas-packet-run-test-', dir='/tmp') as temp:
            capture = Path(temp)
            index, canonical, chunk = self.fixture(capture)
            path = capture / 'event-witnesses/chunks/000000.json'
            for mutation, message in [('run', 'run identity/index'), ('slot', 'run identity/index'),
                                      ('bytes', 'bytes/runtime'), ('pc', 'bytes/runtime')]:
                bad = copy.deepcopy(chunk)
                if mutation == 'run': bad['run_id'] = 'MINIMAL:' + 'b' * 64
                elif mutation == 'slot': bad['chunk_id'] = 1
                elif mutation == 'bytes': bad['events'][0]['witness']['bytes'] = '01'
                else: bad['events'][0]['witness']['pc'] = 257
                path.write_text(json.dumps(bad))
                with self.assertRaisesRegex(ValueError, message):
                    validate_capture(capture, index, canonical, 'FIZZBUZ')
            path.write_text(json.dumps(chunk))
            for field in ['execution_count', 'first_step', 'last_step']:
                bad = copy.deepcopy(canonical); bad['instructions'][0][field] += 1
                with self.assertRaisesRegex(ValueError, 'selected capture chronology'):
                    validate_capture(capture, index, bad, 'FIZZBUZ')
            (capture / 'run-summary.json').write_text(json.dumps(dict(module='MINIMAL')))
            with self.assertRaisesRegex(ValueError, 'summary module/run'):
                validate_capture(capture, index, canonical, 'FIZZBUZ')

    def test_capture_mismatch_and_missing_run_metadata_are_explicit(self):
        with self.assertRaisesRegex(ValueError, 'does not match requested run'):
            build(CAPTURE, IMAGES, run='FIZZBUZ')
        from unittest.mock import patch
        original_load = load
        def selected_metadata(path):
            result = original_load(path)
            if path.name == 'event-witnesses.json':
                result['run_id'] = 'FIZZBUZ:' + 'c' * 64
            if path.name == 'procedures.json':
                # Missing-count fixture remains explicit after real FIZZBUZ metadata is added.
                for procedure in result['procedures']:
                    procedure['observed_paths']['invocations_by_run'].pop('FIZZBUZ', None)
            return result
        for target in ['PLI1.OVL+7C1B', 'PLI1.OVL+4468']:
            with patch('procedure_evidence_packet.load', side_effect=selected_metadata):
                with self.assertRaisesRegex(ValueError, "catalog lacks.*FIZZBUZ"):
                    build(CAPTURE, IMAGES, target, 0, (), run='FIZZBUZ')


class ExistingMinimalPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet = build(CAPTURE, IMAGES)
        cls.canonical = load(CAPTURE / "canonical-code-blocks.json")
        cls.dynamic = load(CAPTURE / "dynamic-blocks.json")
        cls.records = gather(CAPTURE, {TARGET: (0x24BC, 0x289B)}, include_nested_returns=True)[TARGET]
        cls.catalog = {p["id"]: p for p in load(ROOT / "research/annotated-assembly/procedures.json")["procedures"]}

    def check(self, packet):
        validate_packet(packet, self.canonical, self.dynamic, self.records, self.catalog)

    def test_source_counts_and_unchanged_accumulated_knowledge(self):
        self.assertEqual(self.packet["quality_checks"], {
            "invocations": 85, "local_instruction_occurrences": 11322,
            "local_instruction_coordinates": 371, "derived_blocks": 60,
            "invocation_path_classes": 13, "recursive_children": 20})
        source = json.loads((ROOT / "research/minimal-baseline/pass-3/regions.json").read_text())
        region = next(r for r in source if r["entry"] == TARGET)
        actual = Counter((self.packet["instructions"][k]["coordinate"]["offset"],
                          self.packet["steps"][str(s["step"])]["pc_after"], s["taken"])
                         for k, b in self.packet["branches"].items() for s in b["observations"])
        self.assertEqual(actual, Counter({(b["offset"], b["runtime_after"], b["taken"]): b["count"]
                                          for b in region["branches"]}))
        self.assertEqual(self.packet["accumulated_knowledge"]["procedure"], self.catalog[TARGET])
        self.assertEqual(len(self.packet["calls"]), 246)
        self.check(self.packet)

    def test_every_member_keeps_correlated_data_and_local_frame(self):
        invocations = {r["call_step"]: r for r in self.packet["invocations"]}
        for c in self.packet["invocation_classes"]:
            self.assertEqual(c["count"], len(c["invocations"]))
            for n in c["invocations"]:
                r = invocations[n]
                entry = self.packet["steps"][str(r["entry_step"])]["before"]
                self.assertEqual(entry["sp"] - 18, r["F"])
                self.assertEqual(entry["c"], c["distinguishing_observed_conditions"]["entry_C"])
                self.assertTrue(r["local_steps"])
                self.assertEqual(self.packet["steps"][str(r["return_step"])]["scope"], "local")
        # Different input counts within one path remain distinct, fully retained
        # records, rather than a cross product of independent sets.
        many = next(c for c in self.packet["invocation_classes"] if c["count"] == 54)
        self.assertGreater(len({invocations[n]["first_written_local_bytes"][11]["value"]
                                for n in many["invocations"]}), 1)

    def test_2798_recursion_selects_original_true_boolean(self):
        checked = 0
        for invocation in self.packet["invocations"]:
            owned = {self.packet["steps"][str(s)]["coordinate"]: self.packet["steps"][str(s)]
                     for s in invocation["local_steps"]}
            if "PLI0.OVL+2798" not in owned:
                continue
            with self.subTest(invocation=invocation["call_step"]):
                def at(offset):
                    return owned[f"PLI0.OVL+{offset:04X}"]

                calls = {self.packet["calls"][str(s)]["callsite"]: self.packet["calls"][str(s)]
                         for s in invocation["nested_calls"]}
                guard = self.packet["steps"][str(calls["PLI0.OVL+278A"]["post_return_state_step"])]["after"]
                field = self.packet["steps"][str(calls["PLI0.OVL+2790"]["post_return_state_step"])]["after"]
                self.assertEqual((guard["a"], field["a"]), (0x00, 0xFF))
                self.assertEqual(at(0x278D)["writes"][0]["new_value"], guard["a"])
                self.assertEqual(at(0x2793)["after"]["b"], guard["a"])
                self.assertEqual(at(0x2794)["after"]["c"], guard["a"])
                combined = field["a"] | guard["a"]
                complemented = combined ^ 0xFF
                self.assertEqual(at(0x2795)["after"]["a"], combined)
                self.assertFalse(at(0x2795)["after"]["flags"]["carry"])
                self.assertEqual(at(0x2796)["after"]["a"], complemented)
                self.assertEqual(at(0x2797)["after"]["a"], complemented >> 1)
                self.assertEqual(at(0x2797)["after"]["flags"]["carry"], bool(complemented & 1))
                branch = at(0x2798)
                pred = self.packet['local_dependencies']['branches'][str(next(s for s in invocation['local_steps']
                                          if self.packet['steps'][str(s)]['coordinate'] == 'PLI0.OVL+2798'))]
                self.assertEqual(pred['condition']['op'], 'or')
                sources = [self.packet['local_dependencies']['nodes'][arg['node']] for arg in pred['condition']['args']]
                self.assertEqual([s['coordinate'] for s in sources], ['PLI0.OVL+2790', 'PLI0.OVL+278A'])
                self.assertTrue(all(s['operation'] == 'call-output' and s['inputs'] == [] for s in sources))
                chain = dependency_chain(self.packet, pred)
                for offset in (0x278D, 0x2793, 0x2794, 0x2795, 0x2796, 0x2797):
                    self.assertIn(f'PLI0.OVL+{offset:04X}', [n['coordinate'] for n in chain])
                saved = next(n for n in chain if n['operation'] == 'call-preserved-storage')
                self.assertEqual(saved['contract']['kind'], 'PARTIAL')
                self.assertTrue(saved['contract']['scope_guard_evidence'])
                self.assertEqual(chain[-1]['inputs'][0]['kind'], 'value')
                self.assertEqual(branch["control"]["taken"], bool(combined & 1))
                self.assertEqual(branch["pc_after"], 0x49AC)
                self.assertIn("PLI0.OVL+27B4", calls)
                checked += 1
        self.assertEqual(checked, 10)

    def test_2601_patch_selects_clear_helper_a_bit_not_helper_carry(self):
        calls = [c for c in self.packet["calls"].values() if c["callsite"] == "PLI0.OVL+25FC"]
        self.assertEqual(len(calls), 1)
        call = calls[0]
        returned = self.packet["steps"][str(call["post_return_state_step"])]["after"]
        self.assertEqual((returned["a"], returned["flags"]["carry"]), (0x00, True))
        invocation = next(i for i in self.packet["invocations"] if i["call_step"] == call["invocation"])
        owned = {self.packet["steps"][str(s)]["coordinate"]: self.packet["steps"][str(s)]
                 for s in invocation["local_steps"]}

        def at(offset):
            return owned[f"PLI0.OVL+{offset:04X}"]

        complemented = returned["a"] ^ 0xFF
        self.assertEqual(at(0x25FF)["before"]["a"], returned["a"])
        self.assertEqual(at(0x25FF)["after"]["a"], complemented)
        self.assertEqual(at(0x25FF)["after"]["flags"], returned["flags"])
        self.assertEqual(at(0x2600)["after"]["flags"]["carry"], bool(complemented & 1))
        self.assertEqual(at(0x2601)["control"]["taken"], bool(returned["a"] & 1))
        self.assertEqual(at(0x2601)["pc_after"], 0x4804)
        pred = next(p for p in self.packet['local_dependencies']['branches'].values() if p['coordinate'] == 'PLI0.OVL+2601')
        self.assertEqual(pred['condition'], {'op': 'bit', 'node': f"{call['pre_call_state_step']}:returned:a", 'bit': 0})
        chain = dependency_chain(self.packet, pred)
        self.assertNotIn('returned:carry', [n['output'] for n in chain])
        source = self.packet['local_dependencies']['nodes'][pred['condition']['node']]
        self.assertEqual(source['contract']['algorithmic_contract'], 'unavailable')
        self.assertEqual(source['inputs'], [])
        # The fallthrough actually copies both bytes through the result-slot
        # pointer into working_record+6; it is not merely a branch-count claim.
        destination = at(0x260E)["after"]
        destination = (destination["h"] << 8) | destination["l"]
        for read_offset, write_offset, delta in [(0x2610, 0x2614, 0), (0x2612, 0x2616, 1)]:
            written = at(write_offset)["writes"][0]
            self.assertEqual(written["address"], (destination + delta) & 0xFFFF)
            self.assertEqual(written["new_value"], at(read_offset)["reads"][0]["value"])

    def test_correlated_recursion_frame_and_publication_navigation(self):
        for invocation in self.packet['invocations']:
            summary = self.packet['operational_summaries'][str(invocation['call_step'])]
            if invocation['class'] in ('C05', 'C06'):
                count = invocation['first_written_local_bytes'][11]['value']
                self.assertEqual(len(summary['frame_decrements']), count)
                self.assertEqual(len(summary['recursive_calls']), count + 2)
                self.assertEqual([c['mode_C'] for c in summary['recursive_calls']], [0, 4] + [0] * count)
                words = {w['coordinate']: w for w in summary['frame_word_writes']}
                first_child, second_child = [next(i for i in self.packet['invocations'] if i['call_step'] == c['child_invocation'])
                                             for c in summary['recursive_calls'][:2]]
                pointer = first_child['first_written_local_bytes'][14]['value'] + 256 * first_child['first_written_local_bytes'][15]['value']
                revisit = second_child['first_written_local_bytes'][14]['value'] + 256 * second_child['first_written_local_bytes'][15]['value']
                self.assertEqual(words['PLI0.OVL+2789']['F_offset'], 3)
                self.assertEqual(words['PLI0.OVL+2789']['value'], pointer)
                self.assertEqual(pointer, revisit)
                self.assertEqual(words['PLI0.OVL+27C1']['F_offset'], 5)
                self.assertNotEqual(words['PLI0.OVL+27C1']['value'], pointer)
            if invocation['class'] == 'C10':
                publications = [e for e in summary['events'] if e['channel'] in ('role-write', 'indirect-write')]
                by_coordinate = {e['coordinate']: e for e in publications}
                self.assertEqual(by_coordinate['PLI0.OVL+2861']['channel'], 'role-write')
                for offset in (0x2887, 0x2889, 0x2892, 0x2894):
                    self.assertEqual(by_coordinate[f'PLI0.OVL+{offset:04X}']['channel'], 'indirect-write')
                self.assertNotEqual(by_coordinate['PLI0.OVL+2887']['source_definition'], by_coordinate['PLI0.OVL+2892']['source_definition'])

    def test_opaque_effects_are_invocation_observations(self):
        checked = 0
        for c in self.packet['calls'].values():
            if c['target'] == 'PLI0.OVL+242B':
                self.assertEqual(c['contract_presentation']['algorithmic_contract'], 'unavailable')
                self.assertFalse(c['contract_presentation']['caller_storage_preserved'])
                self.assertEqual({a['address'] for a in c['observed_effects']['write_addresses']}, {0x6A97, 0x6A98})
                self.assertEqual(c['observed_effects']['caller_frame_written_offsets'], [])
                self.assertIn('PLI0.OVL:tested_pointer', c['observed_effects']['watched_word_roles_without_guest_writes'])
                checked += 1
        self.assertEqual(checked, 4)

    def test_call_aware_links_and_dependency_corruption(self):
        relations = self.packet['deduced']['local_write_read_relations']
        across = [r for r in relations if r['preserved_across_calls']]
        self.assertTrue(across)
        for relation in across:
            for step in relation['preserved_across_calls']:
                policy = self.packet['calls'][str(step)]['contract_presentation']
                self.assertNotEqual(policy['kind'], 'MISSING / OPAQUE')
                self.assertTrue(policy['caller_storage_preserved'] or policy['all_memory_preserved'])
        p = copy.deepcopy(self.packet)
        predicate = next(v for v in p['local_dependencies']['branches'].values() if v['coordinate'] == 'PLI0.OVL+2798')
        p['local_dependencies']['nodes'][predicate['flag_definition']]['value'] = True
        with self.assertRaisesRegex(AssertionError, 'Flag definition mismatch'):
            self.check(p)

    def test_conditions_reproduce_each_correlated_branch_outcome(self):
        nodes = self.packet['local_dependencies']['nodes']
        def evaluate(e):
            op = e['op']
            if op == 'not': return not evaluate(e['arg'])
            if op == 'or': return any(evaluate(a) for a in e['args'])
            if op == 'and': return all(evaluate(a) for a in e['args'])
            if op == 'xor': return sum(evaluate(a) for a in e['args']) % 2 == 1
            if op == 'bit': return bool(nodes[e['node']]['value'] & (1 << e['bit']))
            if op == 'flag': return bool(nodes[e['node']]['value'])
            if op == 'constant': return e['value']
            if op == 'zero': return nodes[e['node']]['value'] == 0
            values = [nodes[n]['value'] for n in e['nodes']]
            if op == 'equal': return values[0] == values[1]
            if op == 'borrow': return values[0] < sum(values[1:])
            self.fail(f'Unsupported condition in regression: {op}')
        predicates = self.packet['local_dependencies']['branches']
        for key, predicate in predicates.items():
            if 'condition' in predicate:
                with self.subTest(step=key):
                    self.assertEqual(evaluate(predicate['condition']), predicate['taken'])
        for branch in self.packet['branches'].values():
            self.assertEqual(sum(o['count'] for g in branch['polarity_summaries'] for o in g['outcomes']),
                             len(branch['dependency_steps']))

    def test_secondary_zero_frame_complete_procedure(self):
        p = build(CAPTURE, IMAGES, entry='PLI0.OVL+23C3', frame_bytes=0, class_slots=())
        self.assertEqual(p['quality_checks']['invocations'], 334)
        self.assertEqual(p['quality_checks']['recursive_children'], 0)
        self.assertEqual(p['accumulated_knowledge']['procedure']['completeness']['contract'], 'complete')
        self.assertTrue(all(i['first_written_local_bytes'] == {} for i in p['invocations']))

    def test_detects_corrupt_bytes_and_branch_counts(self):
        p = copy.deepcopy(self.packet)
        p["instructions"][TARGET]["bytes"] = "00"
        with self.assertRaisesRegex(ValueError, "Instruction coordinate/bytes/count"):
            self.check(p)
        p = copy.deepcopy(self.packet)
        next(iter(p["branches"].values()))["outcomes"][0]["count"] += 1
        with self.assertRaisesRegex(ValueError, "Branch outcome"):
            self.check(p)

    def test_detects_lost_recursive_ownership_and_frame_offsets(self):
        p = copy.deepcopy(self.packet)
        child = next(c["recursive_child_invocation"] for c in p["calls"].values()
                     if c["recursive_child_invocation"] is not None)
        invocation = next(r for r in p["invocations"] if r["call_step"] == child)
        p["steps"][str(invocation["return_step"])]["invocation"] = -1
        with self.assertRaisesRegex(ValueError, "Local ownership"):
            self.check(p)
        p = copy.deepcopy(self.packet)
        q = next(q for w in p["steps"].values() for q in w["writes"] if "deduced_frame_relation" in q)
        q["deduced_frame_relation"]["offset"] += 1
        with self.assertRaisesRegex(ValueError, "Frame offset"):
            self.check(p)

    def test_detects_role_address_and_call_join_corruption(self):
        p = copy.deepcopy(self.packet)
        role = next(role for w in p["steps"].values() for q in w["writes"]
                    for role in q.get("joined_roles", []))
        role["address"] += 1
        with self.assertRaisesRegex(ValueError, "Role erased"):
            self.check(p)
        p = copy.deepcopy(self.packet)
        next(iter(p["calls"].values()))["post_return_state_step"] += 1
        with self.assertRaisesRegex(ValueError, "Call return join"):
            self.check(p)

    def test_deterministic_regeneration(self):
        regenerated = build(CAPTURE, IMAGES, run='MINIMAL')
        self.assertEqual(json.dumps(self.packet, separators=(",", ":")),
                         json.dumps(regenerated, separators=(",", ":")))
        self.assertEqual(render(self.packet), render(regenerated))

    def test_caller_validation_uses_selected_run_counts(self):
        packet, catalog = copy.deepcopy(self.packet), copy.deepcopy(self.catalog)
        packet['run_id'] = 'FIZZBUZ:' + 'd' * 64
        for caller in catalog[TARGET]['callers']:
            caller['counts_by_run']['FIZZBUZ'] = caller['counts_by_run']['MINIMAL']
            caller['counts_by_run']['MINIMAL'] = 0
        validate_packet(packet, self.canonical, self.dynamic, self.records, catalog)
        catalog[TARGET]['callers'][0]['counts_by_run']['FIZZBUZ'] += 1
        with self.assertRaisesRegex(ValueError, 'FIZZBUZ caller counts mismatch'):
            validate_packet(packet, self.canonical, self.dynamic, self.records, catalog)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument("--capture", type=Path, default=ROOT / "_build/minimal-baseline/capture")
    args, rest = parser.parse_known_args()
    IMAGES, CAPTURE = args.images, args.capture
    unittest.main(argv=[sys.argv[0], *rest])
