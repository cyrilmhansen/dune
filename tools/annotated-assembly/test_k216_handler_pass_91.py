#!/usr/bin/env python3
import argparse,json,os,subprocess,unittest
from pathlib import Path
OUT=Path('_build/host-compiler-pass-91')
class K216Segments(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/k216_handler_return_proof.exe'],check=True)
        subprocess.run(['_build/default/bin/k216_handler_return_proof.exe','--images',IMAGES,'--output',str(OUT/'proof.json')],check=True)
        cls.q=json.loads((OUT/'proof.json').read_text())
    def test_two_genuine_boundaries(self):
        self.assertTrue(self.q['all_passed'])
        by_entry={c['input_vector'][0]:c for c in self.q['cases']}
        front=by_entry[0x8992];tail=by_entry[0x8f4a]
        self.assertEqual((front['PC'],front['exit_SP']),(0x8926,front['entry_SP']-2))
        self.assertEqual((tail['PC'],tail['exit_SP']),(0x42b4,tail['entry_SP']+2))
        for c in self.q['cases']:self.assertTrue(c['full_state_RAM_ordered_writes_services'])
    def test_arithmetic_and_goldens(self):
        self.assertEqual(self.q['synthetic_scale_cases'],48)
        old=json.loads(Path('research/host-compiler/pass-74/single-hybrid-summary.json').read_text())['sources']
        self.assertEqual({c['source']:(c['REL_sha256'],c['INT_sha256'])for c in self.q['goldens']},{c['result']['source']:(c['result']['REL_sha256'],c['result']['INT_sha256'])for c in old})
        self.assertEqual(self.q['native_roots'],0)
    def test_packet_and_partial_scope(self):
        p=Path('research/host-compiler/pass-91/implementation-packet.json')
        self.assertLess(p.stat().st_size,28672)
        self.assertFalse(json.loads(p.read_text())['whole_handler_proved'])
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
