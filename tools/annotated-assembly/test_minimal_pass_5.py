#!/usr/bin/env python3
"""Pass-5 scoped contracts, packet use, immutable evidence and progress."""
import argparse
import copy
import json
import sys
import unittest
from collections import Counter
from pathlib import Path

from check_minimal_pass_5 import ROOT, BOUNDS, PACKET_TARGETS, extract, summarize, validate_direct, validate_packet_member, packet_local
from minimal_dynamic_progress import calculate

PASS=ROOT/'research/minimal-baseline/pass-5'


class MinimalPassFiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packets,cls.direct=extract(CAPTURE,IMAGES,ROOT/'_build/minimal-pass-5/packets')
        cls.regions=summarize(cls.packets,cls.direct)
        cls.progress=json.loads((PASS/'progress.json').read_text())
        cls.catalog={p['id']:p for p in json.loads((ROOT/'research/annotated-assembly/procedures.json').read_text())['procedures']}

    def test_all_concrete_invocations_and_counts(self):
        self.assertEqual(sum(r['invocations_checked'] for r in self.regions),130)
        self.assertEqual(sum(r['own_instruction_occurrences'] for r in self.regions),18936)
        self.assertEqual({r['entry']:r['invocations_checked'] for r in self.regions},
                         {'PLI0.OVL+1E0B':87,'PLI1.OVL+784E':19,'PLI1.OVL+4929':2,'PLI1.OVL+8273':1,'PLI1.OVL+7D53':21})

    def test_commit_count_is_global_byte_and_publications_ordered(self):
        rows=self.direct['PLI0.OVL+1E0B']
        self.assertTrue(any(validate_direct(r)['count'] != r['entry']['before']['c'] for r in rows))
        changed=copy.deepcopy(rows[0]);w=next(w for w in changed['own_witnesses'] if w['origin']['offset']==0x1E24)
        w['writes'][0]['new_value'] ^= 1
        with self.assertRaisesRegex(ValueError,'staging publication'):
            validate_direct(changed)

    def test_initializer_is_exactly_149_not_148_or_150(self):
        r=self.direct['PLI1.OVL+8273'][0];validate_direct(r)
        writes=[q for w in r['own_witnesses'] for q in w['writes'] if 0xAAB4<=q['address']<=0xAB48]
        self.assertEqual([q['address'] for q in writes],list(range(0xAAB4,0xAB49)))
        self.assertEqual([q['new_value'] for q in writes],list(range(1,150)))
        changed=copy.deepcopy(r);last=next(w for w in changed['own_witnesses'] if w['writes'] and w['writes'][0]['address']==0xAB48)
        last['writes'][0]['new_value']=148
        with self.assertRaisesRegex(ValueError,'initializer write order'):
            validate_direct(changed)

    def test_word_link_address_is_old_node_plus8_not_previous_slot(self):
        p=self.packets['PLI1.OVL+4929'];iv=next(i for i in p['invocations'] if any(p['steps'][str(s)]['coordinate']=='PLI1.OVL+4974' for s in i['local_steps']))
        bad=copy.deepcopy(p)
        read=next(bad['steps'][str(s)] for s in iv['local_steps'] if bad['steps'][str(s)]['coordinate']=='PLI1.OVL+4974')
        read['reads'][0]['address']=0xA76E
        with self.assertRaisesRegex(ValueError,'Old link address'):
            validate_packet_member(bad,iv)

    def test_primary_matches_exhaustions_and_zero_index_read(self):
        p=self.packets['PLI1.OVL+784E'];outcomes=Counter()
        for iv in p['invocations']:
            result=validate_packet_member(p,iv);outcomes[result['return']]+=1
        self.assertEqual(outcomes,{'PLI1.OVL+78BB':1,'PLI1.OVL+798B':9,'PLI1.OVL+7A0B':7,'PLI1.OVL+7A14':2})
        zeros=[]
        for iv in p['invocations']:
            ws=packet_local(p,iv)
            for n,w in enumerate(ws):
                if w['origin']['offset']==0x79C5 and w['reads'][0]['value']==0:
                    read=next(x for x in ws[n:] if x['origin']['offset']==0x79DA)
                    zeros.append(read['reads'][0]['address'])
        self.assertEqual(zeros,[0x21C5]*7)
        # Independent arithmetic check of the unsupported ADI-carry idiom.
        for byte in range(256):
            for k in (1,10):
                carry=((byte-k)%256)+255>255
                self.assertEqual(carry,byte!=k)

    def test_primary_packet_dependencies_support_combined_guard(self):
        p=self.packets['PLI1.OVL+784E']
        predicates=[v for v in p['local_dependencies']['branches'].values() if v['coordinate']=='PLI1.OVL+7872']
        self.assertEqual(len(predicates),19)
        self.assertTrue(all(v['condition']['op']=='not' and v['condition']['arg']['op']=='and' for v in predicates))
        self.assertTrue(all(v['taken'] for v in predicates))
        # No assertion that ADI ancestry is present when V0.1 stopped it.
        second=[v for v in p['local_dependencies']['branches'].values() if v['coordinate']=='PLI1.OVL+78B8']
        self.assertEqual(sum(v['taken'] for v in second),18)

    def test_emission_orchestration_stays_structured_and_partial(self):
        p=self.packets['PLI1.OVL+7D53'];returns=Counter(p['steps'][str(i['return_step'])]['coordinate'] for i in p['invocations'])
        self.assertEqual(returns,{'PLI1.OVL+7D5D':12,'PLI1.OVL+7D65':2,'PLI1.OVL+7E45':7})
        caller=self.catalog[p['entry']]
        self.assertEqual(caller['byte_status_at_entry'],'STRUCTURED')
        self.assertEqual(caller['completeness'],{'bounds':'provisional','control_flow':'partial','contract':'partial'})
        self.assertEqual(sum(validate_packet_member(p,i)['forward_iterations'] for i in p['invocations']),16)
        self.assertEqual(sum(len(validate_packet_member(p,i)['emission_C_bytes']) for i in p['invocations']),26)
        self.assertTrue(any(c['contract_presentation']['kind']=='MISSING / OPAQUE' for c in p['calls'].values()))

    def test_new_progress_and_caller_scope(self):
        after=self.progress['coverage_after']
        self.assertEqual({s:sum(i['executed_status_bytes'][s] for i in after) for s in ('RAW','DECODED','STRUCTURED','UNDERSTOOD')},
                         {'RAW':17077,'DECODED':304,'STRUCTURED':1760,'UNDERSTOOD':1871})
        self.assertEqual(self.progress['classification_after'],{'UNDERSTOOD':48,'STRUCTURED':11,'unresolved':332})
        manifest=json.loads((ROOT/'research/annotated-assembly/manifest.json').read_text())
        rows=[json.loads(s) for s in (ROOT/'research/minimal-baseline/instructions.jsonl').read_text().splitlines()]
        current=calculate(manifest,rows)
        self.assertEqual(current,json.loads((ROOT/'research/minimal-baseline/dynamic-progress.json').read_text()))
        self.assertEqual(current['total']['occurrences_by_status']['UNDERSTOOD'],178825)
        self.assertEqual(next(i for i in current['per_image'] if i['image']=='PLI1.OVL')['occurrences_by_status']['UNDERSTOOD'],17366)
        caller=self.catalog['PLI0.OVL+24BC']
        self.assertEqual(caller['completeness'],{'bounds':'provisional','control_flow':'partial','contract':'partial'})
        self.assertIn('commit_window1E0B',caller['pseudocode'])
        self.assertNotIn('+1E0B/', ' '.join(caller['unresolved_paths']))
        self.assertEqual(sum(i['length'] for i in manifest['images']),94720)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--images',type=Path,required=True)
    parser.add_argument('--capture',type=Path,default=ROOT/'_build/minimal-baseline/capture')
    args,rest=parser.parse_known_args();IMAGES,CAPTURE=args.images,args.capture
    unittest.main(argv=[sys.argv[0],*rest])
