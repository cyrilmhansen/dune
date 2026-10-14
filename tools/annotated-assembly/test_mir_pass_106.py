#!/usr/bin/env python3
"""Optional pinned upstream MIR experiment; normal project build has no MIR dependency."""
import argparse, hashlib, json, os, platform, shutil, subprocess, unittest
from pathlib import Path
OUT = Path('_build/host-compiler-pass-107/pass106-regression')
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
            for kind,cases in [('natural',cls.h['natural_cases']),
                               ('deduced-source6',cls.h['source6_synthetic_cases'])]:
                for q in cases:
                    entry=bytes(q['entry_A']+q['entry_B'])
                    expected=bytes(q['exit_A']+q['exit_B']+[x[1] for x in q['ordered_publications']])
                    f.write(f"{kind} {q['source_slot']} {q['destination_slot']} {entry.hex()} {expected.hex()}\n")
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
        self.assertEqual(self.h['synthetic_cases'],80)
        self.assertEqual(self.h['synthetic_self_copies'],10)
        archived=json.loads(Path('research/host-compiler/pass-106/historical-shadow.json').read_text())
        self.assertEqual(self.h['natural_cases'],archived['natural_cases'])
        self.assertEqual(self.h['REL_sha256'],'68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203')
    def test_real_interpreter_JIT_and_rejections(self):
        self.assertTrue(self.m['all_passed'])
        self.assertEqual(self.m['natural_cases'],len(self.h['natural_cases']))
        self.assertEqual(self.m['synthetic_cases'],136)
        self.assertEqual(self.m['CPU_source6_synthetic_cases'],24)
        self.assertEqual(self.m['negative_cases'],12)
        self.assertEqual(self.m['engines'],['MIR_interp_arr','MIR_gen'])
    def test_source6_CPU_branch_and_effects(self):
        cases=self.h['source6_synthetic_cases']
        self.assertEqual(len(cases),24)
        self.assertEqual({q['destination_slot'] for q in cases},set(range(8)))
        self.assertEqual({q['pattern'] for q in cases},{'distinct','same-valued','zero'})
        for q in cases:
            dst=q['destination_slot']; sp=q['entry_SP']
            self.assertEqual(q['source_slot'],6)
            self.assertEqual(q['classification'],'DEDUCED / STATIC / UNOBSERVED')
            self.assertEqual(q['endpoint'],0x9b7e)
            self.assertEqual(q['exit_SP'],sp)
            self.assertEqual(q['instructions'],24)
            self.assertEqual(q['CPU_writes'],6)
            self.assertIn(0x794a,q['instruction_offsets'])
            self.assertIn(0x7955,q['instruction_offsets'])
            self.assertNotIn(0x7958,q['instruction_offsets'])
            self.assertNotIn(0x7961,q['instruction_offsets'])
            self.assertEqual(q['physical_writes'],[
                [0xae03,6],[0xae02,dst],[0xadab+dst,0],
                [sp-1,0xad],[sp-2,0xb9],[0xadb3+dst,q['entry_B'][6]]])
            expected_a=q['entry_A'].copy(); expected_a[dst]=0
            expected_b=q['entry_B'].copy(); expected_b[dst]=q['entry_B'][6]
            self.assertEqual(q['exit_A'],expected_a)
            self.assertEqual(q['exit_B'],expected_b)
            self.assertEqual(q['ordered_publications'],[
                [0xadab+dst,0],[0xadb3+dst,q['entry_B'][6]]])
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
    p.add_argument('--output',type=Path,default=OUT)
    args,rest=p.parse_known_args(); IMAGES=args.images; OUT=args.output
    unittest.main(argv=[__file__]+rest)
