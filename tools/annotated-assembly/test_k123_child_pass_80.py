#!/usr/bin/env python3
"""Pass80 bounded canonical carrier-clear composition."""
import argparse
import unittest
from pathlib import Path
import run_k123_child_pass_80 as proof

class K123ClearComposition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence=proof.prove(IMAGES)

    def test_verified_natural_calls_and_frames(self):
        self.assertTrue(self.evidence['capture_digests_match_Pass75'])
        for case in self.evidence['cases']:
            self.assertEqual(case['actual_index'],4)
            self.assertEqual(case['instructions'],46)
            self.assertEqual((case['ordered_reads'],case['ordered_writes']),(20,16))
            self.assertEqual([x['site'] for x in case['hardware_calls']],
                             ['7D15','7D1C','73B8','73C0'])
            self.assertEqual(case['return_state']['pc'],0x9f1f)
            self.assertEqual(case['return_state']['sp'],case['entry']['sp'])
            self.assertEqual(case['service_events'],0)

    def test_independent_cpu_shadows_and_bounds(self):
        for case in self.evidence['cases']:
            self.assertTrue(case['proof']['natural_passed'])
            self.assertEqual(case['proof']['synthetic_cases'],5)
        law=proof.base.load(proof.REPORT/'child-law.json')
        self.assertTrue(law['complete_73A7_natural'])
        self.assertFalse(law['complete_7D05'])
        self.assertIn('index6 early RET',law['unsupported'])
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
