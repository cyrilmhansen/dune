#!/usr/bin/env python3
import argparse,json,os,subprocess,unittest
from pathlib import Path
OUT=Path('_build/host-compiler-pass-99')
class K27K84Composition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        targets=['k27_k84_composition_proof','k84_gateway_transaction_proof']
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build',*[f'bin/{t}.exe'for t in targets]],check=True)
        cls.q={}
        for target,name,args in [(targets[0],'handler',[]),(targets[0],'prefix',['--prefix']),(targets[0],'complete',['--complete']),(targets[1],'gateway',[])]:
            subprocess.run([f'_build/default/bin/{target}.exe',*args,'--images',IMAGES,'--output',str(OUT/(name+'.json'))],check=True)
            cls.q[name]=json.loads((OUT/(name+'.json')).read_text())
    def test_full_natural_units(self):
        for name,q in self.q.items():
            self.assertTrue(q['all_passed'])
            self.assertEqual(len(q['cases']),3)
            for c in q['cases']:
                self.assertTrue(c['full_state_RAM_ordered_writes_services'])
                self.assertEqual(c['PC'],0x41b5 if name=='prefix'else 0x4536 if name=='gateway'else 0x42b4)
                self.assertEqual(c['exit_SP'],c['entry_SP']-3 if name=='prefix'else c['entry_SP']+2)
        self.assertEqual(self.q['prefix']['synthetic_counter_cases'],16)
        self.assertEqual(self.q['complete']['synthetic_counter_cases'],16)
        for name in ['handler','gateway']:
            self.assertEqual([c['source']for c in self.q[name]['declined']],['FACTOR'])
    def test_frame_identity_and_old_segments(self):
        old=json.loads(Path('research/host-compiler/pass-71/frames.json').read_text())
        expected={(f['entry_RAM_sha256'],f['exit_RAM_sha256'])for f in old if f['k']==84 and f['source']=='OPTIMIST'}
        self.assertEqual({(c['entry_RAM_sha256'],c['post_RAM_sha256'])for c in self.q['gateway']['cases']},expected)
        old=json.loads(Path('research/host-compiler/pass-95/prefix-shadow.json').read_text())['cases']
        self.assertEqual({c['entry_RAM_sha256']for c in self.q['complete']['cases']},{c['entry_RAM_sha256']for c in old})
    def test_goldens_no_installation_and_packet(self):
        gold=json.loads(Path('research/host-compiler/pass-74/single-hybrid-summary.json').read_text())['sources']
        expected={c['result']['source']:(c['result']['REL_sha256'],c['result']['INT_sha256'])for c in gold}
        for q in self.q.values():
            self.assertEqual({c['source']:(c['REL_sha256'],c['INT_sha256'])for c in q['goldens']},expected)
            self.assertEqual(q['native_roots'],0)
        self.assertLess(Path('research/host-compiler/pass-99/implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
