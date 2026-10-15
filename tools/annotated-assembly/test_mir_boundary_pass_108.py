#!/usr/bin/env python3
"""Read-only checks of the bounded Pass108 architectural evidence assessment.
These checks establish witness consistency, not new PL/I semantics or MIR code.
"""
import argparse,hashlib,json,subprocess,unittest
from pathlib import Path
BASELINE='9cc23a96e1fc222749383bfa94efb1f6cf6f759e'
class BoundaryEvidence(unittest.TestCase):
    def test_archived_evidence_identity(self):
        q=json.loads(Path('research/host-compiler/pass-108/boundary-assessment.json').read_text())
        self.assertEqual(q['baseline'],BASELINE)
        for path,digest in q['evidence'].items():
            self.assertEqual(hashlib.sha256(Path(path).read_bytes()).hexdigest(),digest,path)
    def test_numeric_acquisition_field_is_not_a_decimal_value(self):
        q=json.loads(Path('research/host-compiler/pass-44/numeric-acquisition-cases.json').read_text())
        witnesses=[]
        for case in q['cases']:
            self.assertTrue(all(0x30<=b<=0x39 for b in case['prefix']))
            self.assertEqual(case['width'],len(case['prefix']))
            self.assertEqual(case['accumulator'],sum(case['prefix'])%16)
            if case['prefix']==[0x31,0x35]:
                self.assertEqual(case['accumulator'],6)
                self.assertNotEqual(case['accumulator'],15)
                witnesses.append(case)
        self.assertEqual(len(witnesses),1)
        # Inspect the immutable assessed source, not an assumption about future HEAD.
        src=subprocess.check_output(['git','show',BASELINE+':lib/pli80_host/acquisition_parent.ml'],text=True)
        self.assertIn('a(read 0x20c1);hl 0x1c58;add(read !q.hl);ani 15;',src)
    def test_historical_cut_has_explicit_carried_state(self):
        assessment=json.loads(Path('research/host-compiler/pass-108/boundary-assessment.json').read_text())
        witness=assessment['historical_PLI2_entry_cut']
        old=json.loads(Path(witness['artifact']).read_text())
        cut=next(c for c in old['candidates'] if c['dependency_key']==witness['key'])
        self.assertEqual(sum(b-a for a,b in cut['read_before_write_ranges']),witness['read_before_write_bytes'])
        self.assertGreater(witness['read_before_write_bytes'],0)
        self.assertTrue(cut['required_state'])
    def test_historical_images_and_classifier_bytes(self):
        old=json.loads(Path('research/host-compiler/pass-105/reconstruction.json').read_text())
        self.assertEqual(sum(q['bytes']for q in old['images'].values()),94720)
        for name,q in old['images'].items():
            b=(Path(IMAGES)/name).read_bytes()
            self.assertEqual(len(b),q['bytes'])
            self.assertEqual(hashlib.sha256(b).hexdigest(),q['SHA256'])
        pli=(Path(IMAGES)/'PLI.COM').read_bytes()
        self.assertEqual(pli[0x15da:0x15e3],bytes.fromhex('3ac120d630d60a9fc9'))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True)
    args,rest=p.parse_known_args();IMAGES=args.images
    unittest.main(argv=[__file__]+rest)
