#!/usr/bin/env python3
"""Fresh source/producer/consumer correlation; no new native compiler operation."""
import argparse,hashlib,json,os,subprocess,unittest
from pathlib import Path
from check_typed_literal_pass_109 import derive
OUT=Path('_build/host-compiler-pass-109/capture')
class LiteralRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/typed_literal_capture.exe'],check=True)
        subprocess.run(['_build/default/bin/typed_literal_capture.exe','--images',IMAGES,'--output',OUT],check=True)
        cls.q=derive(OUT)
        (OUT/'proof.json').write_text(json.dumps(cls.q,indent=2)+'\n')
    def test_exact_source_occurrence_and_immutable_acquisition(self):
        q=self.q
        self.assertTrue(q['all_passed'])
        self.assertEqual(q['source']['normalized_byte_span'],[91,93])
        self.assertEqual(q['source']['repository_byte_span'],[88,90])
        self.assertEqual((q['source']['line'],q['source']['column']),(4,18))
        self.assertEqual(q['source']['line_text'],'        if mod(i,15) = 0 then')
        self.assertEqual(q['acquisition']['accumulator'],6)
        self.assertEqual(q['acquisition']['prefix_writes'][0]['value'],0x31)
        self.assertEqual(q['acquisition']['prefix_writes'][1]['value'],0x35)
    def test_retained_record_comparison_and_value_construction(self):
        q=self.q
        r=q['retained_record']
        self.assertEqual([w['source_origin']['source_offset']for w in r['original_digit_writers']],[69,70])
        self.assertEqual(len(r['selected_prefix_comparisons']),2)
        self.assertEqual([p['result']for p in q['constructor']['fold']],[1,15])
        self.assertEqual(q['constructor']['value_field'],{'address':0xa948,'width_bytes':2,'encoding':'little-endian integer','value':15})
        self.assertIn({'step':394565,'offset':0x7b0f,'instruction':'MOV M,E','writes':[[0xab49,15]]},q['consumers_and_publications'])
    def test_real_constructor_replay_and_nonstandard_continuation(self):
        c=self.q['constructor']
        self.assertEqual(c['instructions'],430)
        self.assertEqual(c['ordered_writes'],71)
        self.assertEqual(c['exit_SP'],c['entry_SP']+10)
        self.assertEqual(c['caller_resume_step']-c['entry_step'],c['instructions'])
    def test_observed_attributes_do_not_create_a_typed_contract(self):
        a=self.q['attributes']
        self.assertEqual(a['literal_slots_before'],[2,2,0])
        self.assertEqual(a['literal_slots_after'],[0x15,0x0f,0])
        self.assertEqual(a['context_slots'],a['literal_slots_after'])
        self.assertEqual(a['published_mapped_slots'],a['literal_slots_after'])
        self.assertTrue(self.q['typed_contract_status'].startswith('NOT COMPLETE:'))
    def test_goldens_and_reconstruction(self):
        self.assertEqual(self.q['identity']['REL_sha256'],'68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203')
        old=json.loads(Path('research/host-compiler/pass-105/reconstruction.json').read_text())
        self.assertEqual(sum(q['bytes']for q in old['images'].values()),94720)
        for name,q in old['images'].items():
            b=(Path(IMAGES)/name).read_bytes()
            self.assertEqual(len(b),q['bytes'])
            self.assertEqual(hashlib.sha256(b).hexdigest(),q['SHA256'])
        tree=subprocess.check_output(['git','rev-parse','HEAD:research/annotated-assembly'],text=True).strip()
        self.assertEqual(tree,old['unchanged_annotated_assembly_tree'])
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True)
    args,rest=p.parse_known_args();IMAGES=args.images
    unittest.main(argv=[__file__]+rest)
