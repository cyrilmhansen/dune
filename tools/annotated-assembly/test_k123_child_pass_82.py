#!/usr/bin/env python3
"""Pass82 actual +785C and scoped +7D05 composition."""
import argparse
import unittest
from pathlib import Path
import run_k123_child_pass_82 as proof

class K123FinalChildComposition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence=proof.prove(IMAGES)

    def test_actual_child_and_pointer_domain(self):
        self.assertTrue(self.evidence['capture_digests_match_Pass75'])
        for case in self.evidence['cases']:
            self.assertEqual((case['child_steps'],case['child_reads'],
                              case['child_writes'],case['child_hardware_calls']),
                             (963,347,224,31))
            self.assertEqual(case['fresh_type'],0x0c)
            self.assertGreaterEqual(case['actual_pointer'],0xae6d)
            self.assertTrue(case['child_proof']['natural_passed'])

    def test_full_scoped_handler_and_other_occurrence(self):
        for case in self.evidence['cases']:
            self.assertEqual((case['full_steps'],case['full_reads'],
                              case['full_writes'],case['full_hardware_calls']),
                             (1455,533,345,52))
            self.assertEqual(case['full_return']['pc'],0x9f46)
            self.assertEqual(case['full_return']['sp'],case['full_entry']['sp']+2)
            self.assertTrue(case['full_proof']['natural_passed'])
            self.assertEqual(case['full_proof']['synthetic_cases'],4)
            self.assertEqual(case['service_events'],0)
        self.assertEqual([c['total_785c_in_case'] for c in self.evidence['cases']],
                         [1,2])
        law=proof.base.load(proof.REPORT/'child-law.json')
        self.assertTrue(law['complete_7D05_natural'])
        self.assertFalse(law['complete_7D31'])
        self.assertIn('+77CC type 10h/11h',law['unsupported'])
        self.assertLess((proof.REPORT/'implementation-packet.json').stat().st_size,28672)

    def test_preserved_baselines(self):
        self.assertEqual(self.evidence['FACTOR_REL_sha256'],proof.base.GOLDEN)
        policy=proof.base.load('research/host-compiler/validation-policy.json')
        self.assertEqual((policy['current_full_epoch']['name'],
                          policy['current_full_epoch']['epoch']),('Pass74',3))
        manifest=proof.base.load('research/annotated-assembly/manifest.json')
        self.assertEqual(sum(image['length'] for image in manifest['images']),94720)

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--images',required=True,type=Path)
    options,remaining=parser.parse_known_args()
    IMAGES=options.images
    unittest.main(argv=[__file__]+remaining)
