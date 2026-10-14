#!/usr/bin/env python3
import argparse,json,os,subprocess,unittest
from pathlib import Path
OUT=Path('_build/host-compiler-pass-94')
class K216NestedFront(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/k216_nested_front_proof.exe'],check=True)
        subprocess.run(['_build/default/bin/k216_nested_front_proof.exe','--images',IMAGES,'--output',str(OUT/'proof.json')],check=True)
        cls.q=json.loads((OUT/'proof.json').read_text())
        subprocess.run(['_build/default/bin/k216_nested_front_proof.exe','--predicate','--images',IMAGES,'--output',str(OUT/'predicate.json')],check=True)
        cls.p=json.loads((OUT/'predicate.json').read_text())
    def test_natural_boundaries(self):
        self.assertTrue(self.q['all_passed'] and self.p['all_passed'])
        c,=self.q['cases']
        self.assertEqual((c['input_vector'][0],c['PC'],c['exit_SP']),(0x8926,0x41b5,c['entry_SP']-6))
        self.assertTrue(all(c['full_state_RAM_ordered_writes_services'] for c in self.p['cases']))
        self.assertGreaterEqual(len(self.p['cases']),10)
        self.assertEqual(self.p['synthetic_scale_cases'],4*len(self.p['cases']))
    def test_goldens_and_scope(self):
        old=json.loads(Path('research/host-compiler/pass-74/single-hybrid-summary.json').read_text())['sources']
        for q in [self.q,self.p]:
            self.assertEqual({c['source']:(c['REL_sha256'],c['INT_sha256'])for c in q['goldens']},{c['result']['source']:(c['result']['REL_sha256'],c['result']['INT_sha256'])for c in old})
            self.assertEqual(q['native_roots'],0)
        p=Path('research/host-compiler/pass-94/implementation-packet.json')
        self.assertLess(p.stat().st_size,28672)
        self.assertFalse(json.loads(p.read_text())['whole_667A_complete'])
    def test_capture_integrity(self):
        import hashlib
        from check_selector02_pass_40 import load
        w=[e['witness']for e in load(Path('_build/host-compiler-pass-69/capture/OPTIMIST-2-witnesses.json'))['events']if 'witness'in e]
        self.assertEqual(hashlib.sha256(json.dumps(w,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'338c45ffd5dc8d146f65380e7089bf32573e79b034e829718ce48efae6ea069d')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
