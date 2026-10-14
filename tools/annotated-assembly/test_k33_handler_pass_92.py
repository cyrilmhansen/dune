#!/usr/bin/env python3
import argparse,json,os,subprocess,unittest
from pathlib import Path
OUT=Path('_build/host-compiler-pass-92')
class K33Handler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/k33_handler_proof.exe'],check=True)
        subprocess.run(['_build/default/bin/k33_handler_proof.exe','--images',IMAGES,'--output',str(OUT/'proof.json')],check=True)
        cls.q=json.loads((OUT/'proof.json').read_text())
    def test_two_natural_handlers(self):
        self.assertTrue(self.q['all_passed'])
        self.assertEqual({c['source']for c in self.q['cases']},{'FACTOR','OPTIMIST'})
        for c in self.q['cases']:
            self.assertEqual(c['input_vector'][0],0x61fd)
            self.assertEqual((c['PC'],c['exit_SP']),(0x42b4,c['entry_SP']+2))
            self.assertTrue(c['full_state_RAM_ordered_writes_services'])
        self.assertTrue(all(x['route']=='k23'for x in self.q['gateway_inventory']))
    def test_arithmetic_and_goldens(self):
        old=json.loads(Path('research/host-compiler/pass-74/single-hybrid-summary.json').read_text())['sources']
        self.assertEqual({c['source']:(c['REL_sha256'],c['INT_sha256'])for c in self.q['goldens']},{c['result']['source']:(c['result']['REL_sha256'],c['result']['INT_sha256'])for c in old})
        self.assertEqual(self.q['native_roots'],0)
    def test_packet_and_partial_scope(self):
        p=Path('research/host-compiler/pass-92/implementation-packet.json')
        self.assertLess(p.stat().st_size,28672)
        self.assertTrue(json.loads(p.read_text())['selector1_handler_proved'])
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
