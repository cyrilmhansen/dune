#!/usr/bin/env python3
"""Three natural MOD result publications and their equality consumers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
from check_mod_result_pass_111 import derive

OUT = Path('_build/host-compiler-pass-111/capture')


class ModResultProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True, exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune', 'build', 'bin/typed_literal_capture.exe'], check=True)
        subprocess.run(['_build/default/bin/typed_literal_capture.exe', '--images', IMAGES,
                        '--output', str(OUT), '--declaration', '--mod-result'], check=True)
        cls.q = derive(OUT)
        (OUT / 'proof.json').write_text(json.dumps(cls.q, indent=2) + '\n')

    def test_source_to_actual_builtin_dispatch(self):
        self.assertTrue(self.q['all_passed'])
        self.assertEqual([c['literal'] for c in self.q['cases']], ['15','3','5'])
        self.assertEqual([c['source_MOD'][0]['source_offset'] for c in self.q['cases']], [85,161,232])
        self.assertEqual([c['source_equality']['source_offset'] for c in self.q['cases']], [95,170,241])
        self.assertEqual([c['source_zero']['source_offset'] for c in self.q['cases']], [97,172,243])
        self.assertEqual([c['zero_spelling_route']for c in self.q['cases']],
                         ['new spelling record copy','retained spelling comparison','retained spelling comparison'])
        self.assertEqual(len({c['zero_spelling_record_writer']for c in self.q['cases']}),1)
        for c in self.q['cases']:
            self.assertEqual(c['resolved_builtin_record'], 0xfbcf)
            self.assertEqual(c['descriptor_selector'], 20)
            self.assertEqual(c['table_target'], 0x75bb)
            self.assertEqual(c['operation_marker'], 0xd1)

    def test_converted_operand_and_recomputed_result(self):
        for c in self.q['cases']:
            self.assertEqual(c['result_tuple'], [0x15,15,0])
            self.assertEqual(len(c['converted_operand_copy_steps']), 3)
            self.assertEqual([q['value']for q in c['operand_attribute_reads'][1]], [21,15,0])
            self.assertEqual([q['value']for q in c['operand_attribute_reads'][0]],
                             [2,2 if c['literal']=='15'else 1,0])
            self.assertIn('tag retained', c['finalization_law'])
            self.assertIn('not inferred to be runtime', c['word_channel_limit'])

    def test_current_mapping_and_same_valued_publications(self):
        self.assertEqual([c['result_carrier']for c in self.q['cases']], [2,1,0])
        for c in self.q['cases']:
            self.assertEqual(c['result_position'], 4)
            for pub, read in zip(c['publications'],c['consumer_reads']):
                self.assertLess(pub['first_publication_step'],pub['final_publication_step'])
                self.assertEqual(read['address'],pub['address'])
                self.assertEqual(read['result_writer'],pub['final_publication_step'])
            self.assertEqual([p['value']for p in c['publications']], [21,15,0])

    def test_equality_consumption_and_original_call_frames(self):
        for c in self.q['cases']:
            self.assertEqual(c['saved_relation_index'], 2)
            self.assertIn('equality', c['consumer_kind'])
            for role,count,writes in [('finalizer_replay',181,43),('consumer_replay',1804,371)]:
                r=c[role]
                self.assertTrue(r['full_CPU_RAM_accesses_equal'])
                self.assertEqual(r['instructions'],count)
                self.assertEqual(r['writes'],writes)
                self.assertGreater(r['reads'],0)
            self.assertEqual(c['finalizer_replay']['continuation'],0x75c3)
            self.assertEqual(c['consumer_replay']['continuation'],0x87aa)

    def test_semantic_scope_is_typing_not_runtime_evaluation(self):
        self.assertIn('Compiling MOD',self.q['runtime_limit'])
        self.assertIn('same CPU engine',self.q['CPU_limit'])
        self.assertIn('no separate result symbol record',self.q['representation'])
        contract=json.loads(Path('research/host-compiler/pass-111/semantic-contract.json').read_text())
        self.assertEqual(contract['declared_identifier']['precision_binary_digits'],15)
        self.assertEqual(contract['effective_operands']['precision_binary_digits'],15)
        self.assertEqual(contract['result']['precision_binary_digits'],15)
        self.assertIn('Not evaluated',contract['result']['runtime_value'])

    def test_golden_and_reconstruction_preserved(self):
        self.assertEqual(self.q['identity']['REL_sha256'],
                         '68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203')
        old=json.loads(Path('research/host-compiler/pass-105/reconstruction.json').read_text())
        self.assertEqual(sum(q['bytes']for q in old['images'].values()),94720)
        for name,q in old['images'].items():
            b=(Path(IMAGES)/name).read_bytes()
            self.assertEqual(len(b),q['bytes'])
            self.assertEqual(hashlib.sha256(b).hexdigest(),q['SHA256'])
        # Preserve the publication epoch; later legitimate annotation work may advance HEAD.
        tree=subprocess.check_output(['git','rev-parse','ddab50a11d9a44fd351e32af3a40f006db0ac94a:research/annotated-assembly'],text=True).strip()
        self.assertEqual(tree,old['unchanged_annotated_assembly_tree'])


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--images',required=True)
    args,rest=parser.parse_known_args()
    IMAGES=args.images
    unittest.main(argv=[__file__]+rest)
