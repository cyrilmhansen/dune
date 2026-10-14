#!/usr/bin/env python3
import argparse,json,os,subprocess,unittest
from pathlib import Path
OUT=Path('_build/host-compiler-pass-89')
class IndexedParent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/indexed_parent_397f_proof.exe'],check=True)
        subprocess.run(['_build/default/bin/indexed_parent_397f_proof.exe','--images',IMAGES,'--output',str(OUT/'proof.json')],check=True)
        cls.q=json.loads((OUT/'proof.json').read_text())
    def test_natural_stack_and_full_shadow(self):
        self.assertTrue(self.q['all_passed'])
        self.assertEqual({c['source'] for c in self.q['cases']},{'FIZZBUZ','OPTIMIST'})
        for c in self.q['cases']:
            self.assertEqual(c['exit_SP'],c['entry_SP']+2)
            self.assertTrue(c['full_state_RAM_ordered_writes_services'])
    def test_arithmetic_and_goldens(self):
        self.assertEqual(self.q['synthetic_negation_cases'],64)
        self.assertEqual(self.q['synthetic_predicate_cases'],32)
        gold=json.loads(Path('research/host-compiler/pass-74/single-hybrid-summary.json').read_text())['sources']
        self.assertEqual({c['source']:c['REL_sha256'] for c in self.q['goldens']},{c['result']['source']:c['result']['REL_sha256'] for c in gold})
        self.assertEqual(self.q['native_roots'],0)
    def test_packet(self):
        self.assertLess(Path('research/host-compiler/pass-89/implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
