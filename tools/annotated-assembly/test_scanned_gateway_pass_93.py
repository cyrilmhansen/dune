#!/usr/bin/env python3
import argparse,json,os,subprocess,unittest
from pathlib import Path
OUT=Path('_build/host-compiler-pass-93')
class ScannedGateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        targets=['scanned_predicate_proof','k33_gateway_transaction_proof','extended_software_selector_proof']
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build',*[f'bin/{t}.exe'for t in targets]],check=True)
        cls.q={}
        for target,name in zip(targets,['predicate','gateway','dispatcher']):
            subprocess.run([f'_build/default/bin/{target}.exe','--images',IMAGES,'--output',str(OUT/(name+'.json'))],check=True)
            cls.q[name]=json.loads((OUT/(name+'.json')).read_text())
    def test_six_predicates_and_both_complete_gateways(self):
        self.assertEqual(len(self.q['predicate']['cases']),6)
        self.assertEqual({c['source']for c in self.q['gateway']['cases']},{'FACTOR','OPTIMIST'})
        for name in ['predicate','gateway']:
            self.assertTrue(self.q[name]['all_passed'])
            for c in self.q[name]['cases']:self.assertTrue(c['full_state_RAM_ordered_writes_services'])
        old=json.loads(Path('research/host-compiler/pass-71/frames.json').read_text())
        for c in self.q['gateway']['cases']:
            frame=next(f for f in old if f['source']==c['source']and f['k']==33)
            self.assertEqual((c['entry_RAM_sha256'],c['post_RAM_sha256']),(frame['entry_RAM_sha256'],frame['exit_RAM_sha256']))
    def test_seven_windows_and_previous_six_preserved(self):
        q=self.q['dispatcher'];self.assertEqual(len(q['cases']),7)
        self.assertEqual(len(q['declined']),1)
        self.assertEqual(q['declined'][0]['source'],'OPTIMIST')
        self.assertIn('index 216',q['declined'][0]['reason'])
        old=json.loads(Path('research/host-compiler/pass-90/natural-shadow.json').read_text())['cases']
        for c in old:
            now=next(x for x in q['cases']if x['entry_RAM_sha256']==c['entry_RAM_sha256'])
            self.assertEqual((now['input_vector'],now['output_vector'],now['post_RAM_sha256'],now['writes']),(c['input_vector'],c['output_vector'],c['post_RAM_sha256'],c['writes']))
    def test_goldens_no_installation_and_packet(self):
        gold=json.loads(Path('research/host-compiler/pass-74/single-hybrid-summary.json').read_text())['sources']
        expected={c['result']['source']:(c['result']['REL_sha256'],c['result']['INT_sha256'])for c in gold}
        for q in self.q.values():
            self.assertEqual({c['source']:(c['REL_sha256'],c['INT_sha256'])for c in q['goldens']},expected)
            self.assertEqual(q['native_roots'],0)
        self.assertLess(Path('research/host-compiler/pass-93/implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
