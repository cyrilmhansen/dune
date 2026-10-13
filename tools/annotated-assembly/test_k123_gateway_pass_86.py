#!/usr/bin/env python3
import argparse
import unittest
import run_k123_gateway_pass_86 as proof
class Gateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.evidence=proof.prove(IMAGES)
    def test_complete_transactions(self):
        for c in self.evidence['cases']:
            self.assertEqual(c['canonical_index'],123)
            self.assertEqual(c['descriptor'],0x4357)
            self.assertEqual(c['handler'],0x476e)
            self.assertEqual(c['fallback_pointer'],0x3bf6)
            self.assertEqual(c['predicate_tokens'],[0xfb,0xfc])
            self.assertTrue(c['proof']['natural_passed'])
            self.assertTrue(c['proof']['gateway_ordered_reads_match_CPU'])
            self.assertTrue(c['independent_CPU_accesses_match_capture'])
            self.assertEqual(c['proof']['synthetic_cases'],2)
            self.assertEqual(c['software_RET']['after']['pc'],0x42b4)
            self.assertEqual(c['returned']['state']['sp'],c['entry']['state']['sp']+2)
            self.assertEqual(c['returned']['service_events'],0)
    def test_readonly_scope_and_proof_errors(self):
        for c in self.evidence['cases']:
            self.assertTrue(c['proof']['input_unchanged'])
            self.assertTrue(c['proof']['preparation_error_propagates'])
            self.assertTrue({'invalid descriptor','invalid handler','corrupted hardware continuation',
                             'trace gate','unsupported predicate token','scratch pointer alias',
                             'stack pointer alias','output error domain'}<=set(c['proof']['rejections']))
    def test_mixed_single_entry_design(self):
        for s in self.evidence['mixed_inventory']:
            self.assertEqual(s['roots'],s['k23']+s['k123']+s['declined'])
        self.assertEqual(self.evidence['native_roots_installed'],0)
        self.assertEqual(self.evidence['knowledge_promotions'],0)
        self.assertEqual(self.evidence['oracle_queries'],0)
        self.assertEqual(self.evidence['FACTOR_REL_sha256'],proof.base.GOLDEN)
        self.assertTrue(self.evidence['capture_integrity_verified'])
    def test_publication_baseline_and_packet(self):
        import subprocess
        archived=proof.base.load(proof.REPORT/'evidence-provenance.json')
        self.assertEqual(archived['baseline'],proof.BASE)
        for path,digest in archived['protected_baseline_SHA256'].items():
            historical=subprocess.check_output(['git','show',proof.BASE+':'+path])
            self.assertEqual(proof.base.sha(historical),digest)
        self.assertLess((proof.REPORT/'implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
