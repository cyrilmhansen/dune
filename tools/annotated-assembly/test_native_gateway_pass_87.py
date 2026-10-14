#!/usr/bin/env python3
import argparse
import subprocess
import unittest
import run_native_gateway_pass_87 as proof
class CombinedGateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.evidence=proof.prove(IMAGES)
    def test_actual_mixed_execution_and_oracle(self):
        self.assertTrue(self.evidence['one_controller'])
        self.assertTrue(self.evidence['previous_k23_exactly_preserved'])
        for s in self.evidence['sources']:
            self.assertTrue(s['single_oracle_order_verified'])
            self.assertTrue(s['full_equivalence'])
            self.assertEqual(s['combined_host'],s['k23']+s['k123'])
            self.assertEqual(len(s['roots']),s['combined_host'])
            self.assertEqual(len({r['entry_step'] for r in s['roots']}),len(s['roots']))
            self.assertEqual(s['combined_guest'],s['k23_guest'] if s['k123']==0 else s['k23_guest']-7605)
    def test_rejection_and_transaction_failures(self):
        s=next(s for s in self.evidence['sources'] if s['source']=='FACTOR')
        self.assertIn('k123 descriptor',s['rejections'])
        self.assertIn('invalid CALL word',s['rejections'])
        self.assertIn('unexpected predicate proof',s['errors'])
        self.assertIn('omitted k123 oracle',s['controller_failures'])
        self.assertIn('eligible k123 preparation journal failure',s['controller_failures'])
        self.assertTrue(self.evidence['Pass86_natural_RAM_hashes_preserved'])
    def test_publication_baseline_and_no_knowledge_promotions(self):
        self.assertEqual(self.evidence['knowledge_promotions'],0)
        self.assertEqual(self.evidence['baseline'],proof.BASE)
        historical=proof.load('research/host-compiler/pass-86/evidence-provenance.json')
        for path,digest in historical['protected_baseline_SHA256'].items():
            self.assertEqual(proof.sha(subprocess.check_output(['git','show',proof.BASE+':'+path])),digest)
        self.assertLess((proof.REPORT/'implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
