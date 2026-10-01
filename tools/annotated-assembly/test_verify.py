#!/usr/bin/env python3
"""Run with --images DIR; originals are mandatory and never regenerated from sources."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import verify as v


class AnnotatedAssemblyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = v.read_json(v.DEFAULT_MANIFEST)
        cls.originals = {i['name']: (IMAGES / i['original_filename']).read_bytes() for i in cls.manifest['images']}
        cls.assembled = {}
        for image in cls.manifest['images']:
            assembly = v.assemble(v.DEFAULT_MANIFEST.parent / image['source'])
            cls.assembled[image['name']] = assembly

    def fixture(self):
        # All task-created /tmp files are small, uniquely named, and automatically removed.
        temporary = tempfile.TemporaryDirectory(prefix='atlas-annotated-assembly-test-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for path in v.DEFAULT_MANIFEST.parent.iterdir():
            if path.suffix in ('.asm', '.json'):
                shutil.copyfile(path, root / path.name)
        return root

    def test_complete_round_trip_all_four_images(self):
        result = v.verify(v.DEFAULT_MANIFEST, IMAGES)
        self.assertEqual(len(result), 4)
        for image in self.manifest['images']:
            rebuilt = bytes(self.assembled[image['name']]['sections'][0]['bytes'])
            self.assertEqual(rebuilt, self.originals[image['name']])
        self.assertEqual(v.progress_markdown(result), (v.DEFAULT_MANIFEST.parent / 'progress.md').read_text())
        self.assertEqual(result, v.read_json(v.DEFAULT_MANIFEST.parent / 'progress.json'))

    def test_one_byte_source_corruption_fails_cli_loudly(self):
        root = self.fixture()
        source = root / 'PLI0.asm'
        # First byte is a known historical JMP opcode, not an expectation from an encoder.
        text = source.read_text()
        self.assertIn('DB 0C3H,', text)
        source.write_text(text.replace('DB 0C3H,', 'DB 0C2H,', 1))
        result = subprocess.run([sys.executable, str(v.HERE / 'verify.py'), '--manifest', str(root / 'manifest.json'),
                                 '--images', str(IMAGES)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('VERIFICATION FAILED', result.stderr)
        self.assertIn('reassembled section SHA-256 mismatch', result.stderr)

    def test_one_byte_original_corruption_detected(self):
        root = self.fixture()
        for name, original in self.originals.items():
            (root / name).write_bytes(original)
        data = bytearray(self.originals['PLI1.OVL'])
        data[-1] ^= 1
        (root / 'PLI1.OVL').write_bytes(data)
        with self.assertRaisesRegex(v.VerificationError, 'original section SHA-256 mismatch'):
            v.verify(root / 'manifest.json', root)

    def test_coordinate_only_label_mapping_is_verified(self):
        root = self.fixture()
        image = next(i for i in self.manifest['images'] if i.get('coordinate_only_labels'))
        offset = image['coordinate_only_labels'][0]
        address = image['runtime_base'] + offset
        source = root / image['source']
        source.write_text(source.read_text().replace(
            f'{image["label_prefix"]}_{offset:04X}: EQU 0{address:04X}H',
            f'{image["label_prefix"]}_{offset:04X}: EQU 0{address + 1:04X}H', 1))
        # No emitted byte changes; a one-byte coordinate shift must still fail.
        with self.assertRaisesRegex(v.VerificationError, 'coordinate-only label mapping'):
            v.verify(root / 'manifest.json', IMAGES)

    def test_manifest_gap_and_overlap(self):
        for delta in (-1, 1):
            with self.subTest(delta=delta):
                image = copy.deepcopy(self.manifest['images'][0])
                image['sections'][1]['start_offset'] += delta
                with self.assertRaisesRegex(v.VerificationError, 'gap/overlap'):
                    v.check_partition(image)
        image = copy.deepcopy(self.manifest['images'][0])
        image['sections'].pop()
        with self.assertRaisesRegex(v.VerificationError, 'trailing gap'):
            v.check_partition(image)

    def test_section_hashes_independent_of_full_image_hash(self):
        # sha256sum independently computes expectations from original slices and actual
        # assembler output. This never calls the production hashing helper.
        for image in self.manifest['images']:
            original = self.originals[image['name']]
            rebuilt = bytes(self.assembled[image['name']]['sections'][0]['bytes'])
            for section in image['sections']:
                a, b = section['start_offset'], section['end_offset']
                for data, field in ((original, 'original_sha256'), (rebuilt, 'reassembled_sha256')):
                    result = subprocess.run(['sha256sum'], input=data[a:b], capture_output=True, check=True)
                    self.assertEqual(result.stdout.decode().split()[0], section[field])
            for field in ('original_sha256', 'reassembled_sha256'):
                bad = copy.deepcopy(image)
                bad['sections'][0][field] = '0' * 64
                with self.assertRaisesRegex(v.VerificationError, 'section SHA-256 mismatch'):
                    v.check_section_hashes(bad, original, rebuilt)

    def test_stable_file_offset_runtime_mapping(self):
        expected = {'PLI.COM': (0x100, 'PLI_119E', 0x129E),
                    'PLI0.OVL': (0x2200, 'PLI0_0000', 0x2200),
                    'PLI1.OVL': (0x2200, 'PLI1_0000', 0x2200),
                    'PLI2.OVL': (0x2200, 'PLI2_7701', 0x9901)}
        for image in self.manifest['images']:
            base, label, address = expected[image['name']]
            self.assertEqual(image['runtime_base'], base)
            self.assertEqual(self.assembled[image['name']]['listing']['symbols'][label], f'{address:04X}')
        root = self.fixture()
        source = root / 'PLI2.asm'
        source.write_text(source.read_text().replace('PLI2_7701:', 'PLI2_7702:', 1))
        with self.assertRaisesRegex(v.VerificationError, 'stable section label'):
            v.verify(root / 'manifest.json', IMAGES)

    def test_wrong_runtime_base_and_comment_detected(self):
        root = self.fixture()
        manifest = copy.deepcopy(self.manifest)
        manifest['images'][1]['runtime_base'] += 1
        (root / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(v.VerificationError, 'runtime mapping'):
            v.verify(root / 'manifest.json', IMAGES)
        (root / 'manifest.json').write_text(json.dumps(self.manifest))
        source = root / 'PLI0.asm'
        source.write_text(source.read_text().replace('+0000 runtime=2200H', '+0000 runtime=2201H', 1))
        with self.assertRaisesRegex(v.VerificationError, 'coordinate comment'):
            v.verify(root / 'manifest.json', IMAGES)

    def test_source_layout_gap_detected_even_if_assembler_zero_fills(self):
        root = self.fixture()
        source = root / 'PLI0.asm'
        # Removing a row and adding ORG would allow some assemblers to silently fill.
        text = source.read_text()
        row = next(line for line in text.splitlines() if line.startswith('PLI0_0010:'))
        source.write_text(text.replace(row, '    ORG 02220H'))
        with self.assertRaisesRegex(v.VerificationError, 'contiguous section|mapping'):
            v.verify(root / 'manifest.json', IMAGES)

    def test_evidence_and_stack_match_checked(self):
        root = self.fixture()
        evidence = v.read_json(root / 'evidence.json')
        seed = next(s for s in evidence['seeds'] if s['id'] == 'PLI2.OVL+6821')
        seed['matched_return_sample']['ret']['reads'][0]['value'] ^= 1
        (root / 'evidence.json').write_text(json.dumps(evidence))
        with self.assertRaisesRegex(v.VerificationError, 'stack-byte relation'):
            v.verify(root / 'manifest.json', IMAGES)

    def test_raw_branch_bytes_stay_unpromoted(self):
        image = self.manifest['images'][0]
        for offset in (0xF29, 0x114B, 0x1195):
            section = next(s for s in image['sections'] if s['start_offset'] <= offset < s['end_offset'])
            self.assertEqual(section['status'], 'RAW')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--images', type=Path, required=True)
    args, unittest_args = parser.parse_known_args()
    IMAGES = args.images.resolve()
    unittest.main(argv=[sys.argv[0], *unittest_args])
