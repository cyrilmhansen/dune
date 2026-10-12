#!/usr/bin/env python3
"""Post-052C +245D tail and Pass76 branch composition."""
import argparse
import unittest
from pathlib import Path
import run_k123_child_pass_78 as proof

class K123Child245D(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence=proof.prove(IMAGES)

    def test_actual_root_and_canonical_child_ownership(self):
        self.assertTrue(self.evidence['Pass75_trace_digest_verified'])
        self.assertEqual(self.evidence['canonical_052C_catalog_contract'],'complete')
        for case in self.evidence['cases']:
            self.assertEqual(case['root_entry']['pc'],0x465d)
            self.assertEqual(case['root_exit']['pc'],0x46bc)
            self.assertEqual(case['root_exit']['sp'],case['root_entry']['sp']+2)
            self.assertEqual(case['root_steps'],98)
            self.assertEqual(case['nested_CALL_count'],6)
            self.assertEqual(case['nested_calls'][0],
                             ['2465','272C','PLI2.OVL','052C'])
            self.assertEqual(case['BDOS_record_events'],0)

    def test_full_concrete_root_journal(self):
        for case in self.evidence['cases']:
            self.assertEqual(case['root_reads'],36)
            self.assertEqual(case['root_writes'],22)
            self.assertEqual(case['tail_steps'],10)
            self.assertEqual((case['tail_reads'],case['tail_writes']),(5,2))
            self.assertEqual(case['root_ADxx_writes'][0][3],0xad32)

    def test_tail_and_branch_cpu_composition(self):
        first,second=self.evidence['cases']
        self.assertEqual([c['tail_exit']['a'] for c in (first,second)],[0,255])
        self.assertEqual([c['branch_target'] for c in (first,second)],
                         [0xa5dc,0xa3aa])
        for case in (first,second):
            self.assertTrue(case['proof']['natural_tail'])
            self.assertTrue(case['proof']['natural_composed'])
            self.assertEqual((case['proof']['synthetic_tail'],
                              case['proof']['synthetic_composed']),(48,16))
        unresolved=proof.base.load(proof.REPORT/'unresolved-dependencies.json')
        self.assertEqual(unresolved['native_roots_installed'],0)
        self.assertLess((proof.REPORT/'implementation-packet.json').stat().st_size,28672)

    def test_historical_identity(self):
        self.assertEqual(self.evidence['FACTOR_REL_sha256'],proof.base.GOLDEN)
        manifest=proof.base.load('research/annotated-assembly/manifest.json')
        self.assertEqual(sum(image['length'] for image in manifest['images']),94720)

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--images',required=True,type=Path)
    options,remaining=parser.parse_known_args()
    IMAGES=options.images
    unittest.main(argv=[__file__]+remaining)
