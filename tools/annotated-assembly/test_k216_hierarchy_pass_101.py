#!/usr/bin/env python3
import argparse,json,os,subprocess,unittest
from pathlib import Path
OUT=Path('_build/host-compiler-pass-101')
class SelectedHierarchy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        target='k216_selected_hierarchy_proof'
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build',f'bin/{target}.exe'],check=True)
        cls.q={}
        for name,args in [('child',['--child']),('parent',[]),('selected',['--selected'])]:
            subprocess.run([f'_build/default/bin/{target}.exe',*args,'--images',IMAGES,'--output',str(OUT/(name+'.json'))],check=True)
            cls.q[name]=json.loads((OUT/(name+'.json')).read_text())
    def test_three_complete_intervals(self):
        for name,pc,resume in [('child',0x887a,0x8931),('parent',0x8926,0x89e1),('selected',0x8992,0x8f4a)]:
            q=self.q[name];self.assertTrue(q['all_passed'])
            c,=q['cases'];self.assertEqual(c['source'],'OPTIMIST')
            self.assertEqual((c['input_vector'][0],c['PC'],c['exit_SP']),(pc,resume,c['entry_SP']+2))
            self.assertTrue(c['full_state_RAM_ordered_writes_services'])
        self.assertEqual(len(self.q['child']['declined']),3)
    def test_original_selected_entry(self):
        old=json.loads(Path('research/host-compiler/pass-91/natural-shadow.json').read_text())['cases']
        old=next(c for c in old if c['input_vector'][0]==0x8992)
        now,=self.q['selected']['cases']
        self.assertEqual((now['input_vector'],now['entry_RAM_sha256']),(old['input_vector'],old['entry_RAM_sha256']))
    def test_goldens_no_installation_and_packet(self):
        gold=json.loads(Path('research/host-compiler/pass-74/single-hybrid-summary.json').read_text())['sources']
        expected={c['result']['source']:(c['result']['REL_sha256'],c['result']['INT_sha256'])for c in gold}
        for q in self.q.values():
            self.assertEqual({c['source']:(c['REL_sha256'],c['INT_sha256'])for c in q['goldens']},expected)
            self.assertEqual(q['native_roots'],0)
        self.assertLess(Path('research/host-compiler/pass-101/implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);o,r=p.parse_known_args();IMAGES=o.images
    unittest.main(argv=[__file__]+r)
