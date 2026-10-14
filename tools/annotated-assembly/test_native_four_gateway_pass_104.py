#!/usr/bin/env python3
"""Actual four-domain native execution with one live oracle chronology."""
import argparse,json,os,subprocess,unittest
from pathlib import Path
OUT=Path('_build/host-compiler-pass-104')
class FourDomainGateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/native_scanned_gateway.exe'],check=True)
        subprocess.run(['_build/default/bin/native_scanned_gateway.exe','--k216','--images',IMAGES,'--output',str(OUT/'mixed.json')],check=True)
        cls.q=json.loads((OUT/'mixed.json').read_text())
    def test_five_concrete_goldens_and_native_chronology(self):
        self.assertTrue(self.q['all_passed'])
        gold=json.loads(Path('research/host-compiler/pass-74/single-hybrid-summary.json').read_text())['sources']
        for s,g in zip(self.q['sources'],gold):
            self.assertEqual(s['source'],g['result']['source'])
            self.assertEqual((s['REL_sha256'],s['INT_sha256']),(g['result']['REL_sha256'],g['result']['INT_sha256']))
            self.assertTrue(s['full_equivalence'] and s['ordered_oracle_exhaustion'])
            self.assertEqual(s['installed_host'],sum(s[k] for k in ['k23','k123','k33','k216']))
            self.assertEqual(len(s['roots']),s['installed_host'])
            self.assertEqual(s['concrete_guest']-s['installed_guest'],sum(r['return_step']-r['entry_step']+1 for r in s['roots']))
            self.assertEqual([r['entry_step'] for r in s['roots']],sorted({r['entry_step'] for r in s['roots']}))
    def test_absorption_and_preserved_modes(self):
        old=json.loads(Path('research/host-compiler/pass-103/mixed-execution.json').read_text())['sources']
        for s,p in zip(self.q['sources'],old):
            self.assertEqual((s['pass103']['guest'],s['pass103']['host'],s['pass103']['declined']),(p['installed_guest'],p['installed_host'],p['declined']))
            self.assertEqual(s['pass87_host'],s['installed_host']-s['k33']-s['k216']+len(s['absorbed_roots']))
            for a in s['absorbed_roots']:
                parent=next(r for r in s['roots']if r['entry_step']==a['parent_entry_step'])
                self.assertEqual(a['absorbed_by'],parent['route'])
                self.assertLess(parent['entry_step'],a['entry_step'])
                self.assertLess(a['entry_step'],parent['return_step'])
    def test_historical_RAM_and_negative_domains(self):
        frames=json.loads(Path('research/host-compiler/pass-71/frames.json').read_text())
        for k in [33,216]:
            actual=[(s,r) for s in self.q['sources']for r in s['roots']if r['route']==f'k{k}']
            archived=[f for f in frames if f['k']==k]
            self.assertEqual(len(actual),len(archived))
            expected={f['entry_RAM_sha256']:f['exit_RAM_sha256'] for f in archived}
            for s,r in actual:
                self.assertEqual(r['post_RAM_sha256'],expected[r['entry_RAM_sha256']])
                for label in ['eligible failure/retry','late handler code propagates','unsupported index']:
                    self.assertIn(label,s['negatives'])
                for label in ['missing new oracle','wrong new input','wrong new post-state','wrong new entry RAM','wrong new post RAM','eligible new journal error','fresh controller recovery']:
                    self.assertIn(label,s['failures'])
        s=next(s for s in self.q['sources']if s['k216'])
        for label in ['descriptor candidate count','unsupported later record','cache sentinel alias','output error','output record boundary']:
            self.assertIn(label,s['negatives'])
        self.assertLess(Path('research/host-compiler/pass-104/implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
