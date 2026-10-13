#!/usr/bin/env python3
import argparse
import unittest
import run_k123_completion_pass_85 as proof
class K123Completion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.evidence=proof.prove(IMAGES)
    def test_full_parent_and_software_handler(self):
        for c in self.evidence['cases']:
            parent=c['parent'];handler=c['handler']
            self.assertEqual(parent['returned']['pc'],0x4771)
            self.assertEqual(parent['returned']['sp'],parent['entry']['sp']+2)
            self.assertEqual(handler['returned']['pc'],0x42b4)
            self.assertEqual(handler['returned']['sp'],handler['entry']['sp']+2)
            self.assertTrue(parent['fresh_CPU_accesses_match_capture'])
            self.assertTrue(handler['fresh_CPU_accesses_match_capture'])
            self.assertTrue(handler['proof']['natural_passed'])
            self.assertEqual(handler['proof']['synthetic_cases'],2)
            self.assertEqual(c['service_events'],0)
    def test_independent_branches(self):
        first,second=self.evidence['cases']
        self.assertEqual(set(first['components']),{'83DC','81C0','742A'})
        self.assertEqual(set(second['components']),{'81AA','8187'})
        self.assertEqual(first['components']['83DC']['proof']['synthetic_cases'],10)
        self.assertEqual(second['extra_structure']['masked_type'],8)
        self.assertEqual(second['extra_structure']['required_child'],'canonical7630 via +7832')
        for c in self.evidence['cases']:
            for q in c['components'].values():
                self.assertTrue(q['fresh_CPU_accesses_match_capture'])
                self.assertTrue(q['proof']['natural_passed'])
    def test_scope_and_preservation(self):
        self.assertTrue(self.evidence['complete_natural_256E'])
        self.assertEqual(self.evidence['native_roots_installed'],0)
        self.assertEqual(self.evidence['FACTOR_REL_sha256'],proof.base.GOLDEN)
        packet=proof.base.load(proof.REPORT/'implementation-packet.json')
        self.assertIn('nonzero83DC route',packet['unsupported'])
        self.assertLess((proof.REPORT/'implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
