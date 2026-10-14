#!/usr/bin/env python3
import argparse,json,os,subprocess,unittest
from pathlib import Path
OUT=Path('_build/host-compiler-pass-90')
class SoftwareSelector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/software_selector_3de4_proof.exe'],check=True)
        subprocess.run(['_build/default/bin/software_selector_3de4_proof.exe','--images',IMAGES,'--output',str(OUT/'proof.json')],check=True)
        cls.q=json.loads((OUT/'proof.json').read_text())
    def test_natural_software_scope_and_full_shadow(self):
        self.assertTrue(self.q['all_passed'])
        self.assertEqual(len(self.q['cases'])+len(self.q['declined']),8)
        for c in self.q['cases']:
            self.assertEqual(c['exit_SP'],c['entry_SP']+2)
            self.assertEqual(c['PC'],0x42b4)
            self.assertTrue(c['full_state_RAM_ordered_writes_services'])
        self.assertEqual({c['selector'] for c in self.q['cases']},{1,2,4})
        self.assertTrue(any('index 33' in c['reason'] for c in self.q['declined']))
        self.assertTrue(any('index 216' in c['reason'] for c in self.q['declined']))
    def test_rotation_golden_and_no_installation(self):
        self.assertEqual(self.q['synthetic_RAR_cases'],24)
        gold=json.loads(Path('research/host-compiler/pass-74/single-hybrid-summary.json').read_text())['sources']
        self.assertEqual({c['source']:(c['REL_sha256'],c['INT_sha256']) for c in self.q['goldens']},{c['result']['source']:(c['result']['REL_sha256'],c['result']['INT_sha256']) for c in gold})
        self.assertEqual(self.q['native_roots'],0)
    def test_packet(self):
        self.assertLess(Path('research/host-compiler/pass-90/implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
