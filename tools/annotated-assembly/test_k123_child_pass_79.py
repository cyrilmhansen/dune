#!/usr/bin/env python3
"""Major +7D31 child boundary and faithful +7D05 front."""
import argparse
import unittest
from pathlib import Path
import run_k123_child_pass_79 as proof

class K123MajorChild(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence=proof.prove(IMAGES)

    def test_exact_root_and_descendant_ownership(self):
        self.assertTrue(self.evidence['Pass75_trace_digest_verified'])
        for case in self.evidence['cases']:
            self.assertEqual(case['root_entry']['pc'],0x9f31)
            self.assertEqual(case['root_exit']['pc'],0x46b5)
            self.assertEqual(case['root_exit']['sp'],case['root_entry']['sp']+2)
            self.assertEqual(case['root_instruction_steps'],1550)
            self.assertEqual(case['hardware_CALL_count'],59)
            self.assertEqual(case['child_7D05_steps'],1455)
            self.assertEqual([(e[2],e[5]) for e in case['direct_calls']],
                             [('7D3B','052C'),('7D43','7D05')])
            self.assertEqual(case['BDOS_record_events'],0)

    def test_complete_concrete_journals_and_shared_scratch(self):
        for case in self.evidence['cases']:
            self.assertEqual(case['root_ordered_reads'],568)
            self.assertEqual(case['root_ordered_writes'],368)
            self.assertEqual(len(case['root_ADxx_writes']),24)
            self.assertGreater(case['repeated_write_addresses'],20)
            self.assertEqual(len(case['child_7D05_direct_calls']),4)

    def test_executable_front_and_rejected_branch(self):
        for case in self.evidence['cases']:
            self.assertEqual(case['front_entry']['pc'],0x9f05)
            self.assertEqual(case['front_entry']['c'],4)
            self.assertEqual(case['front_next_child'],0x95a7)
            self.assertEqual(case['front_reads'],6)
            self.assertEqual(case['front_writes'],7)
            self.assertTrue(case['front_proof']['natural_passed'])
            self.assertTrue(case['front_proof']['unsupported_nonzero_AE04_rejected'])
            self.assertEqual(case['front_proof']['synthetic_cases'],21)
        unresolved=proof.base.load(proof.REPORT/'unresolved-dependencies.json')
        self.assertEqual(unresolved['first_uncomposed'],
                         'PLI2.OVL+73A7 after proved +7D05 front')
        self.assertFalse(unresolved['full_7D31'])
        self.assertEqual(unresolved['native_roots_installed'],0)
        self.assertLess((proof.REPORT/'implementation-packet.json').stat().st_size,28672)

    def test_historical_and_full_checkpoint_baseline(self):
        self.assertEqual(self.evidence['FACTOR_REL_sha256'],proof.base.GOLDEN)
        manifest=proof.base.load('research/annotated-assembly/manifest.json')
        self.assertEqual(sum(image['length'] for image in manifest['images']),94720)
        policy=proof.base.load('research/host-compiler/validation-policy.json')
        self.assertEqual((policy['current_full_epoch']['name'],
                          policy['current_full_epoch']['epoch']),('Pass74',3))
        handoff=proof.base.load(proof.REPORT/'full-checkpoint-handoff.json')
        self.assertEqual(handoff['certification_status'],'PENDING EXTERNAL MANUAL FULL')

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--images',required=True,type=Path)
    options,remaining=parser.parse_known_args()
    IMAGES=options.images
    unittest.main(argv=[__file__]+remaining)
