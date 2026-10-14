#!/usr/bin/env python3
import argparse,json,os,subprocess,unittest
from pathlib import Path
OUT=Path('_build/host-compiler-pass-102')
class K216Completion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        targets=['k216_complete_handler_proof','k216_gateway_transaction_proof','eight_software_selector_proof']
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build',*[f'bin/{t}.exe'for t in targets]],check=True)
        cls.q={}
        for target,name in zip(targets,['handler','gateway','dispatcher']):
            subprocess.run([f'_build/default/bin/{target}.exe','--images',IMAGES,'--output',str(OUT/(name+'.json'))],check=True)
            cls.q[name]=json.loads((OUT/(name+'.json')).read_text())
    def test_complete_handler_and_gateway(self):
        for name in ['handler','gateway']:
            q=self.q[name];self.assertTrue(q['all_passed'])
            c,=q['cases'];self.assertEqual(c['source'],'OPTIMIST')
            self.assertTrue(c['full_state_RAM_ordered_writes_services'])
            self.assertEqual(c['exit_SP'],c['entry_SP']+2)
        c,=self.q['gateway']['cases']
        old=json.loads(Path('research/host-compiler/pass-71/frames.json').read_text())
        frame,=[f for f in old if f['k']==216]
        self.assertEqual((c['entry_RAM_sha256'],c['post_RAM_sha256']),(frame['entry_RAM_sha256'],frame['exit_RAM_sha256']))
        self.assertEqual((frame['initial_count'],frame['scan_calls']),(8,4))
    def test_eight_and_previous_seven(self):
        q=self.q['dispatcher'];self.assertEqual(len(q['cases']),8);self.assertEqual(q['declined'],[])
        self.assertEqual(q['synthetic_RAR_cases'],24)
        old=json.loads(Path('research/host-compiler/pass-93/dispatcher-shadow.json').read_text())['cases']
        for c in old:
            now=next(x for x in q['cases']if x['entry_RAM_sha256']==c['entry_RAM_sha256'])
            self.assertEqual((now['input_vector'],now['output_vector'],now['post_RAM_sha256'],now['writes']),(c['input_vector'],c['output_vector'],c['post_RAM_sha256'],c['writes']))
    def test_immutable_eighth_witness(self):
        import hashlib
        from check_selector02_pass_40 import load
        old=next(r for r in json.loads(Path('research/host-compiler/pass-69/ownership.json').read_text())if r['id']=='OPTIMIST-2-witnesses')
        ws=[e['witness']for e in load(Path('_build/host-compiler-pass-69/capture/OPTIMIST-2-witnesses.json'))['events']if'witness'in e]
        digest=lambda q:hashlib.sha256(json.dumps(q,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.assertEqual(digest(ws),old['instruction_journal_sha256'])
        self.assertEqual(digest([w['writes']for w in ws]),old['ordered_writes_sha256'])
        now,=[c for c in self.q['dispatcher']['cases']if c['source']=='OPTIMIST'and c['selector']==4]
        def vector(q):
            f=q.get('flags',q)
            psw=2+128*f['sign']+64*f['zero']+16*f['auxiliary_carry']+4*f['parity']+f['carry']
            return[q['pc'],q['sp'],q['a'],256*q['b']+q['c'],256*q['d']+q['e'],256*q['h']+q['l'],psw]
        self.assertEqual((now['input_vector'],now['output_vector'],now['instructions']),(vector(old['entry']),vector(old['ret']['after']),old['instructions']))
    def test_goldens_no_installation_and_packet(self):
        gold=json.loads(Path('research/host-compiler/pass-74/single-hybrid-summary.json').read_text())['sources']
        expected={c['result']['source']:(c['result']['REL_sha256'],c['result']['INT_sha256'])for c in gold}
        for q in self.q.values():
            self.assertEqual({c['source']:(c['REL_sha256'],c['INT_sha256'])for c in q['goldens']},expected)
            self.assertEqual(q['native_roots'],0)
        self.assertLess(Path('research/host-compiler/pass-102/implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
