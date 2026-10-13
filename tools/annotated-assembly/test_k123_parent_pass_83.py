#!/usr/bin/env python3
import argparse
import unittest
import run_k123_parent_pass_83 as proof

class Parent7D31(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.evidence=proof.prove(IMAGES)
    def test_natural_complete_shadow(self):
        for c in self.evidence['cases']:
            self.assertEqual((c['instructions'],c['reads'],c['writes']),(1550,568,368))
            self.assertEqual(c['returned']['pc'],0x46b5)
            self.assertEqual(c['returned']['sp'],c['entry']['sp']+2)
            self.assertTrue(c['fresh_CPU_accesses_match_capture'])
            self.assertTrue(c['proof']['natural_passed'])
    def test_synthetic_and_reused_child_domains(self):
        for c in self.evidence['cases']:
            self.assertEqual(c['proof']['synthetic_cases'],4)
            self.assertEqual(c['children'][1]['entry']['c'],4)
            self.assertEqual(c['BDOS_events'],0)
        self.assertEqual(self.evidence['native_roots_installed'],0)
    def test_preservation(self):
        self.assertEqual(self.evidence['FACTOR_REL_sha256'],proof.base.GOLDEN)
        m=proof.base.load('research/annotated-assembly/manifest.json')
        self.assertEqual(sum(i['length'] for i in m['images']),94720)
        self.assertLess((proof.REPORT/'implementation-packet.json').stat().st_size,28672)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True)
    opts,rest=p.parse_known_args();IMAGES=opts.images
    unittest.main(argv=[__file__]+rest)
