#!/usr/bin/env python3
import argparse,json,os,subprocess,unittest
from pathlib import Path
OUT=Path('_build/host-compiler-pass-97')
class K105Fallback(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/k105_fallback_predicate_proof.exe'],check=True)
        subprocess.run(['_build/default/bin/k105_fallback_predicate_proof.exe','--images',IMAGES,'--output',str(OUT/'proof.json')],check=True)
        cls.q=json.loads((OUT/'proof.json').read_text())
    def test_three_software_windows(self):
        self.assertTrue(self.q['all_passed'])
        self.assertEqual(len(self.q['cases']),3)
        for c in self.q['cases']:
            self.assertEqual((c['input_vector'][0],c['PC'],c['exit_SP']),(0x3fff,0x4288,c['entry_SP']+2))
            self.assertTrue(c['full_state_RAM_ordered_writes_services'])
    def test_arithmetic_and_goldens(self):
        self.assertEqual(self.q['synthetic_cache_cases'],12)
        old=json.loads(Path('research/host-compiler/pass-74/single-hybrid-summary.json').read_text())['sources']
        self.assertEqual({c['source']:(c['REL_sha256'],c['INT_sha256'])for c in self.q['goldens']},{c['result']['source']:(c['result']['REL_sha256'],c['result']['INT_sha256'])for c in old})
        self.assertEqual(self.q['native_roots'],0)
    def test_packet_and_partial_scope(self):
        p=Path('research/host-compiler/pass-97/implementation-packet.json')
        self.assertLess(p.stat().st_size,28672)
        self.assertTrue(json.loads(p.read_text())['k105_fallback_complete'])
        self.assertFalse(json.loads(p.read_text())['k105_gateway_complete'])
    def test_lookup_provenance_and_capture(self):
        import hashlib
        old=json.loads(Path('research/host-compiler/pass-71/frames.json').read_text())
        expected={r['entry_RAM_sha256']for r in old if r['k']==105}
        self.assertEqual({r['entry_RAM_sha256']for r in self.q['gateway_inventory']},expected)
        for r in self.q['gateway_inventory']:
            self.assertEqual((r['index'],r['descriptor'],r['handler'],r['count'],r['fallback_index'],r['fallback_table_word'],r['fallback_record']),(105,0x434f,0x4552,0,2,0x3bf5,0x3bf6))
        from check_selector02_pass_40 import load
        ws=[e['witness']for e in load(Path('_build/host-compiler-pass-69/capture/OPTIMIST-2-witnesses.json'))['events']if'witness'in e]
        self.assertEqual(hashlib.sha256(json.dumps(ws,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'338c45ffd5dc8d146f65380e7089bf32573e79b034e829718ce48efae6ea069d')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
