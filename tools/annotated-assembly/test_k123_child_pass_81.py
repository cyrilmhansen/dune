#!/usr/bin/env python3
"""Pass81 bounded canonical field emission composition."""
import argparse
import unittest
from pathlib import Path
import run_k123_child_pass_81 as proof

class K123EmissionComposition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence=proof.prove(IMAGES)

    def test_actual_field_reads_and_output(self):
        self.assertTrue(self.evidence['capture_digests_match_Pass75'])
        for case in self.evidence['cases']:
            self.assertEqual((case['emit_entry']['c'],case['emit_entry']['e']),(1,4))
            self.assertEqual(case['emit_steps'],437)
            self.assertEqual(case['composed_steps'],487)
            self.assertEqual((case['ordered_reads'],case['ordered_writes']),(182,119))
            self.assertEqual(case['output_after']['position'],
                             case['output_before']['position']+1)
            self.assertEqual(case['return_state']['pc'],0x9f28)
            self.assertEqual(case['return_state']['sp'],case['entry']['sp'])
            self.assertEqual(case['BDOS_events'],0)

    def test_cpu_shadows_and_scope(self):
        for case in self.evidence['cases']:
            self.assertTrue(case['proof']['natural_passed'])
            self.assertEqual(case['proof']['synthetic_cases'],4)
        law=proof.base.load(proof.REPORT/'child-law.json')
        self.assertTrue(law['complete_75CE_natural'])
        self.assertFalse(law['complete_7D05'])
        self.assertIn('record flush',law['unsupported'])
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
