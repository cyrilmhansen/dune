#!/usr/bin/env python3
"""Bounded manually source-selected arithmetic composition through real MIR."""
import argparse
import hashlib
import json
import unittest
from pathlib import Path
import test_semantic_mod_pass_112 as prior

SRC=Path('tools/mir/pass114')
OUT=Path('_build/host-compiler-pass-114/proof')


class Arithmetic(unittest.TestCase):
    proof_source=SRC
    proof_output=OUT
    mir_name='arithmetic.mir'
    ocaml_module='arithmetic'

    @classmethod
    def setUpClass(cls):
        prior.SemanticMod.setUpClass.__func__(cls)

    def test_real_engines_and_reference(self):
        self.assertTrue(self.q['all_passed'])
        self.assertFalse(self.q['historical_runtime_observed'])
        self.assertEqual(self.q['engines'],['MIR_interp_arr','MIR_gen'])
        self.assertEqual(self.q['JIT_optimization_level'],0)
        pairs=[]
        for a,b,product,before,take,expected,interp,jit in self.q['cases']:
            pairs.append((a,b))
            self.assertEqual(product,a+a)
            self.assertEqual(before,product+b)
            self.assertEqual(take,before>50)
            self.assertEqual(expected,before-1 if take else before)
            self.assertEqual(interp,expected);self.assertEqual(jit,expected)
            self.assertTrue(all(-32768<=x<=32767 for x in [a,b,product,before,expected]))
        self.assertEqual(len(set(pairs)),len(pairs))

    def test_selected_source_and_discriminants(self):
        rows={(r[0],r[1]):r for r in self.q['cases']}
        required=[(17,25,59,58),(17,16,50,50),(17,17,51,50),(0,0,0,0),(-10,25,5,5),
                  (-10,-25,-45,-45),(0,-32768,-32768,-32768),(16383,1,32767,32766),
                  (-16384,0,-32768,-32768),(16383,-32768,-2,-2),(-16384,32767,-1,-1)]
        for a,b,before,final in required:
            self.assertEqual(rows[a,b][3],before)
            self.assertEqual(rows[a,b][5:],[final,final,final])
        source=Path('examples/pli80/ARITH.PLI').read_text().splitlines()
        self.assertEqual([s.strip()for s in source[1:8]],
          ['dcl a fixed;','dcl b fixed;','dcl c fixed;','a = 17;','b = 25;',
           'c = a * 2 + b;','if c > 50 then c = c - 1;'])
        mir=(SRC/self.mir_name).read_text()
        self.assertEqual(mir.count(': func '),1)
        self.assertIn('mul product, a, 2\n  add result, product, b\n  ble done, result, 50\n  sub result, result, 1',mir)
        self.assertNotIn('call',mir)

    def test_guards_rejection_and_recovery(self):
        self.assertEqual(self.q['OCaml_rejections'],12)
        self.assertEqual(self.q['C_rejections_both_engines'],24)
        self.assertTrue(self.q['input_state_unchanged'])
        self.assertEqual(len(self.q['recoveries']),72)
        for label,engine,result in self.q['recoveries']:
            self.assertTrue(label.startswith(('OCaml ','C ')))
            self.assertIn(engine,['interpreter','JIT']);self.assertEqual(result,58)
        stub=(SRC/'bridge.c').read_text()
        self.assertLess(stub.index('unsupported intermediate range'),stub.index('MIR_init()'))
        self.assertLess(stub.index('operand outside'),stub.index('product ='))
        self.assertIn('MIR_finish(ctx)',stub)
        self.assertNotIn('sum > 50',stub) # no C implementation of returned result

    def test_preserved_historical_identity(self):
        base='468d266b0659180aa3c3d965c902055efd583d78'
        for p in ['lib','bin','examples','research/annotated-assembly']+[
           'research/host-compiler/pass-'+str(n)for n in [109,110,111,112,113]]:
            self.assertEqual(prior.output(['git','diff',base,'--',p]),'')
        reconstruction=json.loads(Path('research/host-compiler/pass-105/reconstruction.json').read_text())
        self.assertEqual(sum(q['bytes']for q in reconstruction['images'].values()),94720)
        for name,q in reconstruction['images'].items():
            data=(Path(IMAGES)/name).read_bytes()
            self.assertEqual(len(data),q['bytes']);self.assertEqual(hashlib.sha256(data).hexdigest(),q['SHA256'])
        docs=Path('docs/pli80-experiments.md').read_text()
        self.assertIn('678,165 | 256 | `ca98a3a7e1900d65f2b8bf73b8ccdd9e0e49ce7f15768607348740b1b7a8e553`',docs)
        for path,digest in [('_build/discriminator-pass-15/screen/ARITH/ARITH.REL','ca98a3a7e1900d65f2b8bf73b8ccdd9e0e49ce7f15768607348740b1b7a8e553'),
                            ('_build/evidence-packet-cross-run/fizzbuz-capture/FIZZBUZ.REL','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203')]:
            if Path(path).exists():self.assertEqual(hashlib.sha256(Path(path).read_bytes()).hexdigest(),digest)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--images',required=True)
    args,rest=parser.parse_known_args();IMAGES=args.images
    unittest.main(argv=[__file__]+rest)
