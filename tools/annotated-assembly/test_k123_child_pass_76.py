#!/usr/bin/env python3
"""Focused natural +247B boundaries and independently CPU-shadowed branch."""
import argparse
import unittest
from pathlib import Path
import run_k123_child_pass_76 as proof

class K123Child(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.boundary=proof.prove(IMAGES)

    def test_hardware_child_boundary_and_journal(self):
        for case in self.boundary['cases']:
            self.assertEqual(case['root_entry']['pc'],0x467b)
            self.assertEqual(case['root_exit']['pc'],0x4771)
            self.assertEqual(case['root_exit']['sp'],case['root_entry']['sp']+2)
            self.assertGreater(case['root_ordered_reads'],1000)
            self.assertGreater(case['root_ordered_writes'],700)
            self.assertGreater(len(case['root_ADxx_writes']),30)
            self.assertEqual(case['service_events'],0)
        self.assertEqual([c['root_instruction_steps'] for c in self.boundary['cases']],
                         [3238,3413])
        self.assertTrue(self.boundary['Pass75_trace_digest_verified'])

    def test_real_child_identities_and_divergence(self):
        first,second=self.boundary['cases']
        common=first['direct_children'][:7]
        self.assertEqual(common,second['direct_children'][:7])
        self.assertIn(['24A5','1B29','PLI.COM','1A29'],common)
        self.assertIn(['24B2','9F31','PLI2.OVL','7D31'],common)
        self.assertEqual(first['direct_children'][7][3],'83DC')
        self.assertEqual(second['direct_children'][7][3],'81AA')
        self.assertEqual([c['branch_next_child'] for c in (first,second)],
                         [0xa5dc,0xa3aa])
        self.assertEqual([c['branch_entry']['a'] for c in (first,second)],[0,255])

    def test_instruction_derived_branch_shadow(self):
        for case in self.boundary['cases']:
            self.assertTrue(case['branch_proof']['natural_passed'])
            self.assertTrue(case['branch_proof']['all_passed'])
            self.assertEqual(case['branch_proof']['synthetic_cases'],48)
            self.assertEqual(case['branch_reads'],2)
            self.assertEqual(case['branch_writes'],2)
            self.assertEqual(case['branch_next_child_state']['pc'],
                             case['branch_next_child'])
        unresolved=proof.load(proof.REPORT/'unresolved-dependencies.json')
        self.assertEqual(unresolved['native_roots_installed'],0)
        self.assertLess((proof.REPORT/'implementation-packet.json').stat().st_size,28672)

    def test_output_and_certification_baseline(self):
        self.assertEqual(self.boundary['FACTOR_REL_sha256'],proof.GOLDEN)
        policy=proof.load('research/host-compiler/validation-policy.json')
        epochs=[*policy['previous_full_epochs'],policy['current_full_epoch']]
        self.assertIn(('Pass74',3),[(e['name'],e['epoch']) for e in epochs])
        self.assertEqual(sum(image['length'] for image in
                             proof.load('research/annotated-assembly/manifest.json')['images']),
                         94720)

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--images',required=True,type=Path)
    options,remaining=parser.parse_known_args()
    IMAGES=options.images
    unittest.main(argv=[__file__]+remaining)
