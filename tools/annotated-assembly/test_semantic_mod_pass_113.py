#!/usr/bin/env python3
"""Signed semantic extension, reusing Pass112's real pinned MIR build recipe."""
import argparse
import hashlib
import json
import unittest
from pathlib import Path
import test_semantic_mod_pass_112 as prior

SRC=Path('tools/mir/pass113')
OUT=Path('_build/host-compiler-pass-113/proof')


class SignedMod(prior.SemanticMod):
    proof_source=SRC
    proof_output=OUT
    mir_name='mod_signed.mir'
    bridge_source=Path('tools/mir/pass112/bridge.c')
    bridge_flags=['-ccopt','-DRUNES_SIGNED_MOD']

    def test_supported_boundaries(self):
        pairs={(r[0],r[1])for r in self.q['cases']}
        self.assertEqual(len(pairs),len(self.q['cases']))
        for b in [3,5,15]:
            for a in [-32768,-32767,-32766,-1,0,32766,32767]:
                self.assertIn((a,b),pairs)
            for n in [-7*b,-2*b,-b,b,2*b,7*b]:
                for a in [n-1,n,n+1]:self.assertIn((a,b),pairs)
        self.assertTrue(all(-32768<=a<=32767 and b in [3,5,15]for a,b in pairs))
        old=json.loads(Path('research/host-compiler/pass-112/mir-results.json').read_text())
        rows={(r[0],r[1]):r for r in self.q['cases']}
        for row in old['cases']:self.assertEqual(rows[tuple(row[:2])],row)
        self.assertEqual(self.q['FIZZBUZ_predicates'],old['FIZZBUZ_predicates'])
        required=[(-1,15,14),(-14,15,1),(-15,15,0),(-16,15,14),
                  (-32768,15,7),(-32768,3,1),(-32768,5,2),(0,15,0),(32767,15,7)]
        for a,b,r in required:self.assertEqual(rows[a,b][3:],[r,r,r])
        # Floor quotient inequalities establish the law independently of remainder.
        for a,b,q,r,_,_ in self.q['cases']:
            self.assertLessEqual(q*b,a);self.assertLess(a,(q+1)*b)
            self.assertEqual(r,a-b*q)

    def test_fail_closed_and_recovery(self):
        self.assertEqual(self.q['OCaml_rejections'],14)
        self.assertEqual(self.q['C_rejections_both_engines'],28)
        self.assertTrue(self.q['input_state_unchanged'])
        recovery=self.q['recoveries']
        self.assertEqual(len(recovery),4*(14+28))
        self.assertEqual(self.q['additional_recovery_calls_per_engine'],1+len(recovery)//2)
        for _,engine,a,expected,actual in recovery:
            self.assertIn(engine,['interpreter','JIT'])
            self.assertIn(a,[-32768,32767]);self.assertEqual(expected,7);self.assertEqual(actual,7)
        stub=self.bridge_source.read_text()
        self.assertLess(stub.index('caml_invalid_argument'),stub.index('MIR_init()'))
        self.assertIn('a < RUNES_MOD_MIN || a > 32767',stub)
        self.assertIn('#define RUNES_MOD_MIN 0',stub) # Pass112 default unchanged
        self.assertNotIn('answer +',stub)
        mir=(SRC/self.mir_name).read_text()
        self.assertEqual(mir.count(': func '),1)
        self.assertIn('mod result, a, b\n  bge done, result, 0\n  add result, result, b\ndone:\n  ret result',mir)
        self.assertNotIn('call',mir)
        reference=(SRC/'reference.ml').read_text()
        self.assertIn('descend (q-1) (multiple-b)',reference)
        self.assertNotIn(' mod ',reference)
        self.assertNotIn('execute',reference)

    def test_published_evidence_preserved(self):
        baseline='af04987ed6afb4cc7b5d33107279144e474543d9'
        for n in [109,110,111,112]:
            path='research/host-compiler/pass-'+str(n)
            self.assertEqual(prior.output(['git','diff',baseline,'--',path]),'')
        # The executable historical reference is deliberately not resumed.
        self.assertFalse(self.q['historical_runtime_MOD_observed'])
        identity=json.loads(Path('research/host-compiler/pass-112/preservation.json').read_text())
        self.assertEqual(identity['historical_bytes'],94720)
        golden=Path('_build/evidence-packet-cross-run/fizzbuz-capture/FIZZBUZ.REL')
        if golden.exists():
            self.assertEqual(hashlib.sha256(golden.read_bytes()).hexdigest(),identity['FIZZBUZ_REL_SHA256'])


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--images',required=True)
    args,rest=parser.parse_known_args();prior.IMAGES=args.images
    unittest.main(argv=[__file__]+rest)
