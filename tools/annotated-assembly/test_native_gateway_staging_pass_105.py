#!/usr/bin/env python3
"""Scoped staged reuse: behavior is mandatory; performance is measured separately."""
import argparse,json,math,os,subprocess,unittest
from pathlib import Path
OUT=Path('_build/host-compiler-pass-105')
class GatewayStaging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/native_gateway_staging.exe'],check=True)
        subprocess.run(['_build/default/bin/native_gateway_staging.exe','--images',IMAGES,'--output',str(OUT/'comparison.json'),'--repeats','3'],check=True)
        cls.q=json.loads((OUT/'comparison.json').read_text())
    def test_complete_Pass104_identity_and_chronology(self):
        self.assertTrue(self.q['all_passed'])
        old=json.loads(Path('research/host-compiler/pass-104/mixed-execution.json').read_text())['sources']
        for s,p in zip(self.q['sources'],old):
            self.assertEqual(s['source'],p['source'])
            self.assertEqual((s['guest'],s['host'],s['declined']),(p['installed_guest'],p['installed_host'],p['declined']))
            self.assertEqual(s['roots'],p['roots'])
            self.assertEqual((s['REL_sha256'],s['final_RAM_sha256']),(p['REL_sha256'],p['final_RAM_sha256']))
            self.assertTrue(s['all_equivalence'])
            self.assertEqual(s['declined_profile']['declined_invocations'],s['declined'])
            self.assertTrue(s['declined_profile']['pre_index_error_preserved'].startswith('error:'))
    def test_binding_failures_recovery_and_oracles(self):
        for s in self.q['sources']:
            if s['profile']:
                for label in ['changed full RAM','changed PC','changed SP','changed flags','changed DMA','changed filesystem','changed ancestry','changed image','same-boundary staged recovery','hardware continuation','descriptor','predicate','late child']:
                    self.assertIn(label,s['context_negatives'])
            self.assertIn('missing oracle',s['oracle_negatives'])
            self.assertIn('incorrect oracle',s['oracle_negatives'])
            if s['host']>1:self.assertIn('reordered oracles',s['oracle_negatives'])
    def test_measured_samples_and_compact_packet(self):
        for s in self.q['sources']:
            for name in ['control','optimized']:
                samples=s[name]['samples']
                self.assertEqual(len(samples),self.q['repeats'])
                self.assertTrue(all(math.isfinite(t)and t>0 for t in samples))
                self.assertEqual(s[name]['median'],sorted(samples)[len(samples)//2])
            # Never turn noisy, parallel-run wall times into a historical invariant.
        self.assertLess(Path('research/host-compiler/pass-105/implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
