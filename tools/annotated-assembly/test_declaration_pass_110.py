#!/usr/bin/env python3
"""Selected source declaration and operand provenance; no runtime replacement."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
from check_declaration_pass_110 import derive

OUT = Path('_build/host-compiler-pass-110/capture')


class DeclarationProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True, exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune', 'build', 'bin/typed_literal_capture.exe'], check=True)
        subprocess.run(['_build/default/bin/typed_literal_capture.exe', '--images', IMAGES,
                        '--output', str(OUT), '--declaration'], check=True)
        cls.q = derive(OUT)
        (OUT / 'proof.json').write_text(json.dumps(cls.q, indent=2) + '\n')

    def test_source_and_symbol_ownership(self):
        q = self.q
        self.assertTrue(q['all_passed'])
        self.assertEqual(q['source']['declaration_span'], [39, 51])
        self.assertEqual(q['source']['identifier']['source_offset'], 43)
        self.assertEqual(q['source']['expression_identifier']['source_offset'], 89)
        self.assertEqual(q['declaration']['record'], 0x6fe8)
        self.assertEqual([r['record_offset'] for r in q['record_relocations']], [2, 4, 5, 10])
        self.assertTrue(all(len(r['copy_steps']) == 3 for r in q['record_relocations']))

    def test_qualifier_default_and_fresh_context_computation(self):
        d, law = self.q['declaration'], self.q['metadata_law']
        self.assertEqual((d['qualifier_bits'], d['defaulted_tag']), (0x14, 0x15))
        self.assertEqual(d['defaulted_middle_attribute'], 15)
        self.assertEqual(law['operand1'], [0x15, 15, 0])
        self.assertEqual(law['operand2'], [2, 2, 0])
        self.assertEqual(law['context'], [0x15, 15, 0])
        self.assertEqual(law['decimal_width_lookup'], 7)
        self.assertEqual(min(15, max(15, 7) + 0), law['context'][1])
        # The literal value and the metadata tag have different meanings/values.
        old = json.loads(Path('research/host-compiler/pass-109/source-value-chain.json').read_text())
        self.assertEqual(old['constructor']['value_field']['value'], 15)
        self.assertNotEqual(law['context'][0], 15)

    def test_separate_cpu_window_replays(self):
        for r in self.q['CPU_replays']:
            self.assertTrue(r['full_RAM_CPU_accesses_equal'])
            self.assertGreater(r['ordered_reads'], 0)
            self.assertGreater(r['ordered_writes'], 0)
        self.assertEqual([r['instructions'] for r in self.q['CPU_replays']], [324, 341, 341, 341])
        self.assertIn('same Intel 8080 engine', self.q['engine_limit'])

    def test_natural_one_digit_discriminants(self):
        cases = self.q['natural_discriminants']
        self.assertEqual([q['literal'] for q in cases], ['3', '5'])
        self.assertTrue(all(q['operand_tuple'] == [2,1,0] for q in cases))
        self.assertTrue(all(q['width_lookup'] == 4 for q in cases))
        self.assertTrue(all(q['result_tuple'] == [21,15,0] for q in cases))

    def test_no_speculative_typed_contract(self):
        self.assertTrue(self.q['semantic_status'].startswith('PARTIAL:'))
        self.assertIn('MOD result publication', self.q['semantic_status'])
        self.assertGreater(len(self.q['last_writer_edges']), 80)

    def test_golden_and_reconstruction_identity(self):
        self.assertEqual(self.q['identity']['REL_sha256'],
                         '68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203')
        reconstruction = json.loads(Path('research/host-compiler/pass-105/reconstruction.json').read_text())
        self.assertEqual(sum(q['bytes'] for q in reconstruction['images'].values()), 94720)
        for name, q in reconstruction['images'].items():
            b = (Path(IMAGES) / name).read_bytes()
            self.assertEqual(len(b), q['bytes'])
            self.assertEqual(hashlib.sha256(b).hexdigest(), q['SHA256'])
        tree = subprocess.check_output(['git', 'rev-parse', 'HEAD:research/annotated-assembly'], text=True).strip()
        self.assertEqual(tree, reconstruction['unchanged_annotated_assembly_tree'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--images', required=True)
    args, rest = parser.parse_known_args()
    IMAGES = args.images
    unittest.main(argv=[__file__] + rest)
