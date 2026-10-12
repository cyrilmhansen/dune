#!/usr/bin/env python3
"""Complete +16B3 leaf against retained natural and independent CPU states."""
import argparse
import unittest
from pathlib import Path
import run_k123_child_pass_77 as proof

class K123Leaf(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence=proof.prove(IMAGES)

    def test_actual_hardware_boundary(self):
        for case in self.evidence['cases']:
            self.assertEqual((case['caller'],case['child'],case['hardware_return']),
                             ('PLI2.OVL+2492','PLI2.OVL+16B3','4695'))
            self.assertEqual(case['entry']['pc'],0x38b3)
            self.assertEqual(case['exit']['pc'],0x4695)
            self.assertEqual(case['exit']['sp'],case['entry']['sp']+2)
            self.assertEqual(case['nested_CALLs'],0)
            self.assertEqual(case['instruction_count'],14)
            self.assertEqual(case['BDOS_record_events'],0)
        self.assertTrue(self.evidence['Pass75_trace_digest_verified'])

    def test_ordered_carrier_and_return(self):
        for case in self.evidence['cases']:
            self.assertEqual(case['ordered_reads'],5)
            self.assertEqual(case['ordered_writes'],4)
            self.assertEqual(case['ACEE_after'],case['entry']['c'])
            self.assertEqual(case['ACEF_after'],case['entry']['b'])
            self.assertEqual(case['AC9F_after'],
                             [case['entry']['c'],case['entry']['b']])
            self.assertEqual(case['stack_continuation_last_writer'],
                             'PLI2.OVL+2492 CALL')

    def test_full_cpu_shadows_and_scope(self):
        for case in self.evidence['cases']:
            self.assertTrue(case['proof']['natural_passed'])
            self.assertTrue(case['proof']['all_passed'])
            self.assertEqual(case['proof']['synthetic_cases'],48)
        unresolved=proof.base.load(proof.REPORT/'unresolved-dependencies.json')
        self.assertFalse(unresolved['complete_247B'])
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
