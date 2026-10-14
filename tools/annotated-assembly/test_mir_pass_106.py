#!/usr/bin/env python3
"""Optional pinned upstream MIR experiment; normal project build has no MIR dependency."""
import argparse, hashlib, json, os, platform, shutil, subprocess, unittest
from pathlib import Path
OUT = Path('_build/host-compiler-pass-106')
SRC = Path('tools/mir/pass106')
PIN = 'a8ab7c31cd5f9b23b77d84c60b3d83e62d9d304c'
def run(args, **kw):
    return subprocess.run([str(x) for x in args], check=True, **kw)
def output(args):
    return subprocess.check_output([str(x) for x in args], text=True).strip()
class ActualMir(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUT.mkdir(parents=True, exist_ok=True)
        upstream = (OUT/'upstream').resolve()
        if not upstream.exists():
            run(['git','init',upstream])
            run(['git','-C',upstream,'remote','add','origin','https://github.com/vnmakarov/mir.git'])
            run(['git','-C',upstream,'fetch','--depth','1','origin',PIN])
            run(['git','-C',upstream,'checkout','--detach','FETCH_HEAD'])
        if output(['git','-C',upstream,'rev-parse','HEAD']) != PIN:
            raise RuntimeError('MIR revision differs from reviewed pin')
        if output(['git','-C',upstream,'diff','HEAD','--']):
            raise RuntimeError('modified upstream MIR source')
        run(['make','-j2','libmir.a'],cwd=upstream)
        if not os.environ.get('RUNES_HOST_IMAGES'):
            run(['dune','build','bin/mir_carrier_evidence.exe'])
        run(['_build/default/bin/mir_carrier_evidence.exe','--images',IMAGES,
             '--output',OUT/'historical.json'])
        cls.h = json.loads((OUT/'historical.json').read_text())
        with (OUT/'vectors.txt').open('w') as f:
            for q in cls.h['natural_cases']:
                entry=bytes(q['entry_A']+q['entry_B'])
                expected=bytes(q['exit_A']+q['exit_B']+[x[1] for x in q['ordered_publications']])
                f.write(f"{q['source_slot']} {q['destination_slot']} {entry.hex()} {expected.hex()}\n")
        build=(OUT/'ffi').resolve(); build.mkdir(exist_ok=True)
        # Fixed reviewed text only. No arbitrary MIR program enters the C stub.
        (build/'transfer_text.h').write_text('static const char transfer_text[] = '+
                                           json.dumps((SRC/'transfer.mir').read_text())+';\n')
        shutil.copyfile(SRC/'demo.ml',build/'demo.ml')
        run(['ocamlopt','-ccopt','-I'+str(upstream),'-ccopt','-I'+str(build),
             '-c', (SRC/'bridge.c').resolve(),'-o',build/'bridge.o'],cwd=build)
        run(['ocamlopt','-o','demo','demo.ml','bridge.o','-cclib',str(upstream/'libmir.a'),
             '-cclib','-lm','-cclib','-ldl','-cclib','-lpthread'],cwd=build)
        cls.m=json.loads(output([build/'demo',(OUT/'vectors.txt').resolve()]))
        (OUT/'mir-results.json').write_text(json.dumps(cls.m,indent=2)+'\n')
        cls.provenance={'repository':'https://github.com/vnmakarov/mir','revision':PIN,
          'license':'MIT','host':platform.platform(),'machine':platform.machine(),
          'OCaml':output(['ocamlopt','-version']), 'C_compiler':output(['cc','--version']).splitlines()[0],
          'library_SHA256':hashlib.sha256((upstream/'libmir.a').read_bytes()).hexdigest(),
          'MIR_source_SHA256':hashlib.sha256((SRC/'transfer.mir').read_bytes()).hexdigest(),
          'upstream_file_SHA256':{name:hashlib.sha256((upstream/name).read_bytes()).hexdigest()
                                  for name in ['mir.h','mir-gen.h','MIR.md','LICENSE']}}
        (OUT/'upstream.json').write_text(json.dumps(cls.provenance,indent=2)+'\n')
    def test_historical_projection(self):
        self.assertTrue(self.h['all_passed'])
        self.assertGreater(len(self.h['natural_cases']),0)
        for q in self.h['natural_cases']:
            self.assertEqual(q['CPU_writes'],8)
            self.assertEqual(q['entry_SP'],q['exit_SP'])
        self.assertEqual(self.h['synthetic_cases'],56)
        self.assertEqual(self.h['REL_sha256'],'68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203')
    def test_real_interpreter_JIT_and_rejections(self):
        self.assertTrue(self.m['all_passed'])
        self.assertEqual(self.m['natural_cases'],len(self.h['natural_cases']))
        self.assertEqual(self.m['synthetic_cases'],112)
        self.assertEqual(self.m['negative_cases'],12)
        self.assertEqual(self.m['engines'],['MIR_interp_arr','MIR_gen'])
    def test_reconstruction_identity(self):
        old=json.loads(Path('research/host-compiler/pass-105/reconstruction.json').read_text())
        self.assertEqual(sum(q['bytes'] for q in old['images'].values()),94720)
        for name,q in old['images'].items():
            b=(Path(IMAGES)/name).read_bytes()
            self.assertEqual(len(b),q['bytes'])
            self.assertEqual(hashlib.sha256(b).hexdigest(),q['SHA256'])
        self.assertEqual(output(['git','rev-parse','HEAD:research/annotated-assembly']),old['unchanged_annotated_assembly_tree'])
        self.assertFalse(output(['git','diff','HEAD','--','research/annotated-assembly']))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--images',required=True)
    args,rest=p.parse_known_args(); IMAGES=args.images
    unittest.main(argv=[__file__]+rest)
