#!/usr/bin/env python3
"""Installed three-domain gateway; prior receipts remain immutable."""
import argparse,hashlib,json,os,subprocess,unittest
from pathlib import Path
OUT=Path('_build/host-compiler-pass-103')
class InstalledK33(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/native_scanned_gateway.exe'],check=True)
        subprocess.run(['_build/default/bin/native_scanned_gateway.exe','--images',IMAGES,'--output',str(OUT/'mixed.json')],check=True)
        cls.q=json.loads((OUT/'mixed.json').read_text())
    def test_five_source_equivalence_and_measured_oracle_order(self):
        self.assertTrue(self.q['all_passed'])
        gold=json.loads(Path('research/host-compiler/pass-74/single-hybrid-summary.json').read_text())['sources']
        for s,g in zip(self.q['sources'],gold):
            self.assertEqual(s['source'],g['result']['source'])
            self.assertEqual((s['REL_sha256'],s['INT_sha256']),(g['result']['REL_sha256'],g['result']['INT_sha256']))
            self.assertTrue(s['full_equivalence'] and s['ordered_oracle_exhaustion'])
            self.assertEqual(s['installed_host'],s['k23']+s['k123']+s['k33'])
            self.assertEqual(len(s['roots']),s['installed_host'])
            self.assertEqual(s['pass87_host'],s['installed_host']-s['k33']+len(s['absorbed_roots']))
            self.assertEqual([r['entry_step'] for r in s['roots']],sorted({r['entry_step'] for r in s['roots']}))
            removed=sum(r['return_step']-r['entry_step']+1 for r in s['roots'])
            self.assertEqual(s['concrete_guest']-s['installed_guest'],removed)
    def test_historical_k33_scope_and_RAM_witnesses(self):
        frames=json.loads(Path('research/host-compiler/pass-71/frames.json').read_text())
        actual=[(s,r) for s in self.q['sources'] for r in s['roots'] if r['route']=='k33']
        archived=[f for f in frames if f['k']==33]
        self.assertEqual(len(actual),len(archived))
        for (s,r),f in zip(actual,archived):
            self.assertEqual((r['entry_RAM_sha256'],r['post_RAM_sha256']),(f['entry_RAM_sha256'],f['exit_RAM_sha256']))
            self.assertIn('eligible failure/retry',s['negatives'])
            self.assertIn('eligible new journal error',s['failures'])
            self.assertIn('missing new oracle',s['failures'])
    def test_legacy_scope_and_failures_are_preserved(self):
        old=json.loads(Path('research/host-compiler/pass-87/mixed-execution.json').read_text())['sources']
        for s,p in zip(self.q['sources'],old):
            self.assertEqual((s['pass87_guest'],s['pass87_host']),(p['combined_guest'],p['combined_host']))
        self.assertLess(Path('research/host-compiler/pass-103/implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
