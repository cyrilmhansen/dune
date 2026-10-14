#!/usr/bin/env python3
import argparse,json,os,subprocess,unittest
from pathlib import Path
OUT=Path('_build/host-compiler-pass-95')
class K27Segments(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/k27_handler_segments_proof.exe'],check=True)
        subprocess.run(['_build/default/bin/k27_handler_segments_proof.exe','--images',IMAGES,'--output',str(OUT/'proof.json')],check=True)
        cls.q=json.loads((OUT/'proof.json').read_text())
        subprocess.run(['_build/default/bin/k27_handler_segments_proof.exe','--tail','--images',IMAGES,'--output',str(OUT/'tail.json')],check=True)
        cls.p=json.loads((OUT/'tail.json').read_text())
    def test_natural_boundaries(self):
        self.assertTrue(self.q['all_passed'] and self.p['all_passed'])
        self.assertEqual(len(self.q['cases']),3)
        self.assertEqual(len(self.p['cases']),3)
        for c in self.q['cases']:
            self.assertEqual((c['input_vector'][0],c['PC'],c['exit_SP']),(0x44ea,0x41b5,c['entry_SP']-3))
        for c in self.p['cases']:
            self.assertEqual((c['input_vector'][0],c['PC'],c['exit_SP']),(0x4548,0x42b4,c['entry_SP']+3))
        for q in [self.q,self.p]:
            self.assertTrue(all(c['full_state_RAM_ordered_writes_services']for c in q['cases']))
            self.assertEqual(q['synthetic_scale_cases'],12)
    def test_goldens_and_scope(self):
        old=json.loads(Path('research/host-compiler/pass-74/single-hybrid-summary.json').read_text())['sources']
        for q in [self.q,self.p]:
            self.assertEqual({c['source']:(c['REL_sha256'],c['INT_sha256'])for c in q['goldens']},{c['result']['source']:(c['result']['REL_sha256'],c['result']['INT_sha256'])for c in old})
            self.assertEqual(q['native_roots'],0)
        p=Path('research/host-compiler/pass-95/implementation-packet.json')
        self.assertLess(p.stat().st_size,28672)
        self.assertFalse(json.loads(p.read_text())['whole_k27_complete'])
    def test_capture_integrity(self):
        import hashlib
        from check_selector02_pass_40 import load
        w=[e['witness']for e in load(Path('_build/host-compiler-pass-69/capture/OPTIMIST-2-witnesses.json'))['events']if 'witness'in e]
        self.assertEqual(hashlib.sha256(json.dumps(w,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'338c45ffd5dc8d146f65380e7089bf32573e79b034e829718ce48efae6ea069d')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
