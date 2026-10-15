#!/usr/bin/env python3
"""Read-only decimal declaration provenance; no decimal runtime/MIR operation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
from check_decimal_pass_115 import derive

OUT=Path('_build/host-compiler-pass-115/capture')


class DecimalProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True,exist_ok=True)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            subprocess.run(['dune','build','bin/decimal_attribute_capture.exe'],check=True)
        subprocess.run(['_build/default/bin/decimal_attribute_capture.exe','--images',IMAGES,'--output',OUT],check=True)
        cls.q=derive(OUT)
        (OUT/'proof.json').write_text(json.dumps(cls.q,indent=2)+'\n')

    def test_source_qualifiers_and_record_ownership(self):
        q=self.q
        self.assertTrue(q['all_passed'])
        self.assertEqual(q['record'],{'address':0x6fe9,'name':'x','name_publication':99169,
                          'tag':0x16,'precision':7,'scale':2,'fields':[2,4,5]})
        self.assertEqual([q['source_words'][x][0]['source_offset']for x in ['dcl','x','fixed','decimal','precision','scale']], [40,44,46,52,60,62])
        self.assertEqual([r['token']for r in q['keyword_dispatch']],[0x87,0xa2,0x88])
        self.assertEqual([p['value']for p in q['parameters']],[7,2])
        self.assertEqual([d['name']for d in q['natural_declaration_discriminants']],['y','z'])

    def test_retention_and_nonzero_channel(self):
        q=self.q
        self.assertEqual([len(c)for c in q['retained_copies'].values()],[3,3,3,3])
        self.assertEqual(q['selected_consumers']['input_channels'],[7,2,7,2])
        self.assertEqual(q['selected_consumers']['result_channels'],[15,4])
        self.assertGreater(len(q['last_writer_edges']),250)

    def test_literal_point_has_its_own_source_and_branch(self):
        q=self.q['literal_acquisition']
        self.assertEqual([c['spelling']for c in q],['12.50','2.25'])
        self.assertTrue(all(c['lexical_class']==3 for c in q))
        self.assertTrue(all('no source-to-retained-literal payload' in c['limit']for c in q))
        self.assertTrue(self.q['scope'].startswith('PARTIAL:'))

    def test_real_cpu_replays_and_continuations(self):
        self.assertEqual([r['instructions']for r in self.q['CPU_replays']],[306,306,306,334])
        self.assertTrue(all(r['full_RAM_CPU_accesses_equal']for r in self.q['CPU_replays']))
        self.assertEqual([r['writes']for r in self.q['CPU_replays']],[54,54,54,73])
        self.assertIn('same Intel 8080 engine',self.q['engine_limit'])

    def test_preserved_sources_goldens_and_images(self):
        self.assertEqual(hashlib.sha256(Path('examples/pli80/FIXEDDEC.PLI').read_bytes()).hexdigest(),
                         '8936b0b20f6b5cb3def56c83e64e282cae06f2c74838b95579e2590fd9f59e92')
        self.assertEqual(self.q['identity']['REL_sha256'],'b93cddf1e9dd85fa3ef7f8a27740b43da3396c69b10ff03eab248eef2f9e9938')
        self.assertEqual(self.q['identity']['steps'],673691)
        self.assertEqual(self.q['identity']['termination'],'warm_boot')
        self.assertEqual((OUT/'FIXEDDEC.REL').stat().st_size,384)
        old=json.loads(Path('research/host-compiler/pass-105/reconstruction.json').read_text())
        self.assertEqual(sum(q['bytes']for q in old['images'].values()),94720)
        for name,q in old['images'].items():
            b=(Path(IMAGES)/name).read_bytes();self.assertEqual(len(b),q['bytes'])
            self.assertEqual(hashlib.sha256(b).hexdigest(),q['SHA256'])
        baseline='64d356d7db363e2d3df4ae79537f286a8377c52a'
        for n in range(109,115):
            p='research/host-compiler/pass-'+str(n)
            self.assertEqual(subprocess.check_output(['git','diff',baseline,'--',p]),b'')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--images',required=True)
    args,rest=parser.parse_known_args();IMAGES=args.images
    unittest.main(argv=[__file__]+rest)
