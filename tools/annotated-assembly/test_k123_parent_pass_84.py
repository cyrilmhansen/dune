#!/usr/bin/env python3
import argparse
import unittest
import run_k123_parent_pass_84 as proof
class Common247B(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.evidence=proof.prove(IMAGES)
    def test_complete245d(self):
        for c in self.evidence['cases']:
            q=c['child245d'];self.assertEqual((q['instructions'],q['reads'],q['writes']),(98,36,22))
            self.assertEqual(q['returned']['pc'],0x46bc)
            self.assertTrue(q['fresh_CPU_accesses_match_capture'])
            self.assertEqual(q['proof']['synthetic_cases'],3)
    def test_common_prefix_and_branch_boundary(self):
        self.assertEqual([c['prefix']['returned']['pc'] for c in self.evidence['cases']],[0xa5dc,0xa3aa])
        for c in self.evidence['cases']:
            q=c['prefix'];self.assertTrue(q['proof']['natural_passed'])
            self.assertTrue(q['fresh_CPU_accesses_match_capture'])
            self.assertEqual(q['proof']['synthetic_cases'],2)
            self.assertEqual((q['reads'],q['writes']),(689,449))
        self.assertFalse(self.evidence['complete_247B'])
    def test_preservation(self):
        self.assertEqual(self.evidence['FACTOR_REL_sha256'],proof.base.GOLDEN)
        self.assertEqual(self.evidence['native_roots_installed'],0)
        self.assertLess((proof.REPORT/'implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
