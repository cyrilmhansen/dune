#!/usr/bin/env python3
"""MINIMAL pass 6: packet/witness-backed contracts and correlated publications."""
import argparse
import copy
import json
import sys
import unittest
from collections import Counter
from pathlib import Path

from check_minimal_pass_6 import ROOT, PACKETS, collect, validate_direct
from minimal_dynamic_progress import calculate
from procedure_evidence_packet import render

PASS = ROOT/'research/minimal-baseline/pass-6'


class MinimalPassSixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.regions,cls.direct,cls.packets = collect(CAPTURE,IMAGES)
        cls.by = {r['entry']:r for r in cls.regions}
        cls.catalog = {p['id']:p for p in json.loads((ROOT/'research/annotated-assembly/procedures.json').read_text())['procedures']}
        # Reproduce ignored factual packets after the accumulated contracts have
        # been updated; no fixture/compiler run or durable trace copy.
        output = ROOT/'_build/minimal-pass-6/packets';output.mkdir(parents=True,exist_ok=True)
        for k,p in cls.packets.items():
            stem = k.replace('.OVL','').replace('.COM','')
            (output/(stem+'.json')).write_text(json.dumps(p,separators=(',',':'))+'\n')
            (output/(stem+'.md')).write_text(render(p))

    def test_all_scoped_invocations(self):
        self.assertEqual(sum(r['invocations_checked'] for r in self.regions),863)
        self.assertEqual({k:self.by[k]['invocations_checked'] for k in PACKETS},
                         {'PLI.COM+1376':38,'PLI1.OVL+7C1B':16,'PLI1.OVL+7B7A':21,'PLI1.OVL+7BBF':3})

    def test_acquisition_streams_match_with_correlated_states(self):
        members = self.by['PLI.COM+1376']['members']
        groups = [[m for m in members if m['caller']==caller] for caller in ('PLI0.OVL+42D4','PLI1.OVL+784E')]
        project = lambda m:(m['context_entry'],m['selector'],m['width'],m['prefix'],m['following_context'],m['returned_A'])
        self.assertEqual([project(m) for m in groups[0]],[project(m) for m in groups[1]])
        self.assertEqual(Counter(m['selector'] for m in groups[1]),{1:9,10:9,5:1})
        self.assertEqual(sum(m['width'] for m in members),128)
        self.assertTrue(all(m['width']==1 for m in members if m['selector']==10))
        self.assertTrue(any(m['following_context'] != m['prefix'][-1] for m in members))
        self.assertEqual(json.loads((PASS/'host-effects.json').read_text())['file_events'],[])

    def test_supported_packet_polarities(self):
        acquisition = self.packets['PLI.COM+1376']['local_dependencies']['branches'].values()
        complements = [b for b in acquisition if b['coordinate']=='PLI.COM+145F']
        self.assertEqual((len(complements),sum(b['taken'] for b in complements)),(96,78))
        self.assertTrue(all(b['condition']['op']=='bit' and b['condition']['bit']==0 for b in complements))
        recursive = self.packets['PLI1.OVL+7C1B']['local_dependencies']['branches'].values()
        ors = [b for b in recursive if b['coordinate']=='PLI1.OVL+7C53']
        self.assertEqual(len(ors),13)
        self.assertTrue(all(b['taken'] and b['condition']['op']=='not' and b['condition']['arg']['op']=='or' for b in ors))

    def test_recursive_children_have_order_and_distinct_results(self):
        members = self.by['PLI1.OVL+7C1B']['members']
        self.assertEqual(sum(len(m['children']) for m in members),7)
        two = next(m for m in members if len(m['children'])==2)
        self.assertEqual([c['cursor'] for c in two['children']],[2,1])
        self.assertEqual([c['returned'] for c in two['children']],[10,1])
        self.assertEqual(two['returned'],0)  # cached auxiliary, not last child
        self.assertTrue(all(m['children'][0]['cursor']==m['input']-1 for m in members if m['mapped']==23))

    def test_packed_bits_and_scratch_write(self):
        # Independent exhaustive proof of the three RAR transformations; the
        # expected expression uses original bits, not the production extractor.
        for byte in range(256):
            a=byte & 252;carry=0
            for _ in range(3):a,carry=(carry<<7)|(a>>1),a & 1
            self.assertEqual(a & 7,(byte>>3)&7)
        bad=copy.deepcopy(self.direct['PLI1.OVL+7B64'][0])
        bad['ret']['after']['a'] ^= 1
        with self.assertRaisesRegex(ValueError,'bits3..5'):
            validate_direct(bad)

    def test_old_slot_value_and_fresh_map_cache_are_distinct_channels(self):
        members=self.by['PLI1.OVL+7BA2']['members']
        self.assertTrue(any(m['old_cached'] != m['new_cached'] for m in members))
        self.assertEqual({m['written_slot'] for m in members},set(range(0xAAB4,0xAABB)))
        bad=copy.deepcopy(self.direct['PLI1.OVL+7BA2'][0])
        child=next(iter(bad['nested_returns'].values()))
        store=next(w for w in child['memory_witnesses'] if w['origin']['offset']==0x7AEE)
        store['writes'][0]['new_value'] ^= 1
        with self.assertRaisesRegex(ValueError,'Old cached'):
            validate_direct(bad)

    def test_auxiliary_writes_are_read_later_in_the_parent(self):
        flow=json.loads((PASS/'table-flow.json').read_text())['relations']
        self.assertEqual(len(flow),2)
        witnesses={w['step_index']:w for k in ('PLI1.OVL+7B2E','PLI1.OVL+7AA9')
                   for r in self.direct[k] for w in r['own_witnesses']}
        for row in flow:
            writer=witnesses[row['writer']['step']];reader=witnesses[row['reader']['step']]
            self.assertLess(writer['step_index'],reader['step_index'])
            self.assertEqual(writer['writes'][0]['address'],row['address'])
            self.assertEqual(reader['reads'][0]['address'],row['address'])
            self.assertEqual(writer['writes'][0]['new_value'],reader['reads'][0]['value'])

    def test_partial_scopes_and_current_progress(self):
        partial={'bounds':'provisional','control_flow':'partial','contract':'partial'}
        for key in ('PLI.COM+1376','PLI1.OVL+7C1B','PLI1.OVL+784E','PLI1.OVL+7D53'):
            self.assertEqual(self.catalog[key]['completeness'],partial)
        historical={r['entry']:r for r in json.loads((PASS/'regions.json').read_text())}
        caller_history=next(r for r in json.loads((PASS.parent/'pass-5/regions.json').read_text()) if r['entry']=='PLI1.OVL+7D53')
        self.assertEqual(caller_history['byte_status'],'STRUCTURED')
        transitions=json.loads((PASS/'progress.json').read_text())['status_transitions']
        self.assertTrue(all(t['after']=='STRUCTURED' for t in transitions if t['before']=='STRUCTURED'))
        self.assertEqual(historical['PLI1.OVL+7BBF']['completeness']['contract'],'partial')
        self.assertIn('+82E1',' '.join(historical['PLI1.OVL+7BBF']['unresolved']))
        m=json.loads((ROOT/'research/annotated-assembly/manifest.json').read_text())
        rows=[json.loads(s) for s in (ROOT/'research/minimal-baseline/instructions.jsonl').read_text().splitlines()]
        current=calculate(m,rows)
        self.assertEqual(current,json.loads((ROOT/'research/minimal-baseline/dynamic-progress.json').read_text()))
        historical_dynamic=json.loads((PASS/'dynamic-progress.json').read_text())
        self.assertEqual(historical_dynamic['total']['occurrences_by_status']['UNDERSTOOD'],195878)
        self.assertEqual(next(i for i in historical_dynamic['per_image'] if i['image']=='PLI1.OVL')['occurrences_by_status']['UNDERSTOOD'],21687)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--images',type=Path,required=True)
    parser.add_argument('--capture',type=Path,default=ROOT/'_build/minimal-baseline/capture')
    args,remaining=parser.parse_known_args();IMAGES=args.images.resolve();CAPTURE=args.capture.resolve()
    unittest.main(argv=[sys.argv[0],*remaining])
