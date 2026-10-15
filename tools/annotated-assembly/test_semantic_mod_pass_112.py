#!/usr/bin/env python3
"""Optional real upstream MIR semantic operation; ordinary Dune has no MIR dependency."""
import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import unittest
from pathlib import Path

PIN='a8ab7c31cd5f9b23b77d84c60b3d83e62d9d304c'
OUT=Path('_build/host-compiler-pass-112/proof')
SRC=Path('tools/mir/pass112')


def run(args, **kw):
    return subprocess.run([str(x)for x in args],check=True,**kw)


def output(args):
    return subprocess.check_output([str(x)for x in args],text=True).strip()


class SemanticMod(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Pass113 reuses this narrow build recipe with a separate source/output
        # directory and signed-domain C defines; Pass112 defaults stay intact.
        OUT=getattr(cls,'proof_output',globals()['OUT'])
        SRC=getattr(cls,'proof_source',globals()['SRC'])
        mir_name=getattr(cls,'mir_name','mod_positive.mir')
        bridge=getattr(cls,'bridge_source',SRC/'bridge.c')
        flags=getattr(cls,'bridge_flags',[])
        OUT.mkdir(parents=True,exist_ok=True)
        upstream=(OUT/'upstream').resolve()
        if not upstream.exists():
            run(['git','init',upstream])
            run(['git','-C',upstream,'remote','add','origin','https://github.com/vnmakarov/mir.git'])
            run(['git','-C',upstream,'fetch','--depth','1','origin',PIN])
            run(['git','-C',upstream,'checkout','--detach','FETCH_HEAD'])
        if output(['git','-C',upstream,'rev-parse','HEAD'])!=PIN:
            raise RuntimeError('MIR revision differs from reviewed pin')
        if output(['git','-C',upstream,'diff','HEAD','--']):
            raise RuntimeError('Modified pinned MIR sources')
        run(['make','-j2','libmir.a'],cwd=upstream)
        build=(OUT/'ffi').resolve();build.mkdir(exist_ok=True)
        (build/'mod_text.h').write_text('static const char mod_text[] = '+json.dumps((SRC/mir_name).read_text())+';\n')
        for name in ['fixed_binary_mod.mli','fixed_binary_mod.ml','reference.ml','demo.ml']:
            shutil.copyfile(SRC/name,build/name)
        run(['ocamlopt','-ccopt','-I'+str(upstream),'-ccopt','-I'+str(build),
             *flags,'-c',bridge.resolve(),'-o',build/'bridge.o'],cwd=build)
        run(['ocamlopt','-c','fixed_binary_mod.mli'],cwd=build)
        run(['ocamlopt','-c','fixed_binary_mod.ml'],cwd=build)
        run(['ocamlopt','-o','demo','fixed_binary_mod.cmx','reference.ml','demo.ml','bridge.o',
             '-cclib',upstream/'libmir.a','-cclib','-lm','-cclib','-ldl','-cclib','-lpthread'],cwd=build)
        cls.q=json.loads(output([build/'demo']))
        (OUT/'mir-results.json').write_text(json.dumps(cls.q,indent=2)+'\n')
        cls.upstream={'repository':'https://github.com/vnmakarov/mir','revision':PIN,'license':'MIT',
            'host':platform.platform(),'machine':platform.machine(),'OCaml':output(['ocamlopt','-version']),
            'C_compiler':output(['cc','--version']).splitlines()[0],
            'MIR_source_SHA256':hashlib.sha256((SRC/mir_name).read_bytes()).hexdigest(),
            'library_SHA256':hashlib.sha256((upstream/'libmir.a').read_bytes()).hexdigest(),
            'upstream_file_SHA256':{name:hashlib.sha256((upstream/name).read_bytes()).hexdigest()
                                   for name in ['mir.h','mir-gen.h','MIR.md','mir-interp.c','mir-gen-x86_64.c','LICENSE']}}
        (OUT/'upstream.json').write_text(json.dumps(cls.upstream,indent=2)+'\n')

    def test_real_MIR_interpreter_and_JIT(self):
        self.assertTrue(self.q['all_passed'])
        self.assertEqual(self.q['engines'],['MIR_interp_arr','MIR_gen'])
        self.assertEqual(self.q['JIT_optimization_level'],0)
        self.assertFalse(self.q['historical_runtime_MOD_observed'])
        for a,b,q,expected,interp,jit in self.q['cases']:
            self.assertEqual(a,q*b+expected)
            self.assertGreaterEqual(expected,0)
            self.assertLess(expected,b)
            self.assertEqual(interp,expected)
            self.assertEqual(jit,expected)
        self.assertEqual(self.q['accepted_cases_per_engine'],len(self.q['cases']))

    def test_supported_boundaries(self):
        pairs={(r[0],r[1])for r in self.q['cases']}
        self.assertEqual(len(pairs),len(self.q['cases']))
        for b in [3,5,15]:
            for a in [0,b-1,b,b+1,2*b-1,2*b,2*b+1,7*b-1,7*b,7*b+1,32766,32767]:
                self.assertIn((a,b),pairs)
            for i in range(1,16):self.assertIn((i,b),pairs)
        self.assertTrue(all(0<=a<=32767 and b in [3,5,15]for a,b in pairs))

    def test_all_FIZZBUZ_expression_predicates(self):
        rows=self.q['FIZZBUZ_predicates']
        self.assertEqual({(r[0],r[1])for r in rows},{(i,b)for i in range(1,16)for b in [3,5,15]})
        for i,b,expected,interp,jit in rows:
            self.assertEqual(interp,expected);self.assertEqual(jit,expected)
        self.assertEqual([i for i,b,r,_,_ in rows if b==15 and r],[15])
        self.assertEqual([i for i,b,r,_,_ in rows if b==3 and r],[3,6,9,12,15])
        self.assertEqual([i for i,b,r,_,_ in rows if b==5 and r],[5,10,15])

    def test_fail_closed_and_recovery(self):
        self.assertEqual(self.q['OCaml_rejections'],15)
        self.assertEqual(self.q['C_rejections_both_engines'],30)
        self.assertTrue(self.q['input_state_unchanged'])
        self.assertEqual(self.q['additional_recovery_calls_per_engine'],1)
        stub=(SRC/'bridge.c').read_text()
        self.assertLess(stub.index('caml_invalid_argument'),stub.index('MIR_init()'))
        self.assertIn('MIR_interp_arr',stub);self.assertIn('MIR_gen(ctx, function)',stub)
        body=(SRC/'mod_positive.mir').read_text()
        self.assertEqual(body.count(': func '),1)
        self.assertIn('mod result, a, b',body)
        self.assertNotIn('call',body)
        # The independently inspected OCaml reference has neither / nor mod.
        reference=(SRC/'reference.ml').read_text()
        self.assertIn('subtract (q+1) (r-b)',reference)
        self.assertNotIn(' mod ',reference)

    def test_historical_identity_and_existing_typing_contract(self):
        c=json.loads(Path('research/host-compiler/pass-111/semantic-contract.json').read_text())
        self.assertEqual(c['result']['precision_binary_digits'],15)
        self.assertIn('Not evaluated',c['result']['runtime_value'])
        old=json.loads(Path('research/host-compiler/pass-105/reconstruction.json').read_text())
        self.assertEqual(sum(q['bytes']for q in old['images'].values()),94720)
        for name,q in old['images'].items():
            b=(Path(IMAGES)/name).read_bytes()
            self.assertEqual(len(b),q['bytes'])
            self.assertEqual(hashlib.sha256(b).hexdigest(),q['SHA256'])
        baseline='6495d609fa046ee51ecc34525da3bfd89b463809'
        self.assertEqual(output(['git','rev-parse',baseline+':research/annotated-assembly']),old['unchanged_annotated_assembly_tree'])


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--images',required=True)
    args,rest=parser.parse_known_args();IMAGES=args.images
    unittest.main(argv=[__file__]+rest)
