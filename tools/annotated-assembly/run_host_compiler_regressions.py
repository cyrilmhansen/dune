#!/usr/bin/env python3
"""Quiet regression categories with timed, bounded, isolated execution.

Build-mutating Dune stages are serial. Subsequent categories consume immutable
artifacts; native experiments/corruption fixtures use unique temporary outputs.
The local Dune-exec launcher invokes the exact already-built executable so those
read-only categories never contend over the shared build directory.
"""
import argparse,concurrent.futures,hashlib,json,os,re,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--images',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--categories',help='comma-separated incremental categories; build/project remain mandatory');p.add_argument('--workers',type=int,choices=range(1,5),default=4);args=p.parse_args()
os.chdir(ROOT);out=args.output.resolve();out.mkdir(parents=True,exist_ok=True);images=str(Path(args.images).resolve());env=dict(os.environ,RUNES_HOST_IMAGES=images,PYTHONDONTWRITEBYTECODE='1');started=time.perf_counter()
cmds={'project':['dune','runtest'],'native-unit':['dune','exec','test/native_packed_scan.exe'],'pass16':['python3','tools/annotated-assembly/test_host_boundary_pass_16.py','--images',images,'-v'],'pass15':['python3','tools/annotated-assembly/test_attribute_discriminator_pass_15.py','--images',images,'-v'],'pass14':['python3','tools/annotated-assembly/test_fizzbuz_pass_14.py','--images',images,'-v'],'pass13':['python3','tools/annotated-assembly/test_fizzbuz_pass_13.py','--images',images,'-v'],'baseline':['python3','tools/annotated-assembly/test_minimal_baseline.py','--images',images,'-v']}
for n in range(1,13):cmds['minimal-pass-'+str(n)]=['python3',f'tools/annotated-assembly/test_minimal_pass_{n}.py',*(['--capture','_build/minimal-baseline/capture']if n==8 else ['--images',images]),'-v']
cmds['recursive-unit']=['dune','exec','test/native_recursive_mapped.exe']
cmds['pass19-native']=['python3','tools/annotated-assembly/test_native_7c1b_pass_19.py','--images',images,'-v']
cmds['balance-unit']=['dune','exec','test/native_balance_scan.exe']
cmds.update({'packet-continuation':['python3','tools/annotated-assembly/test_procedure_evidence_packet.py','--images',images,'-v'],'V1':['python3','tools/annotated-assembly/test_decompilation_annotations.py','-v'],'roundtrip-tests':['python3','tools/annotated-assembly/test_verify.py','--images',images,'-v'],'roundtrip':['python3','tools/annotated-assembly/verify.py','--images',images]})
cmds['pass17-native']=['python3','tools/annotated-assembly/test_native_7bbf_pass_17.py','--images',images,'-v']
cmds['pass18-native']=['python3','tools/annotated-assembly/test_native_7b7a_pass_18.py','--images',images,'-v']
cmds['mapped-unit']=['dune','exec','test/native_mapped_publication.exe']
cmds['pass20-native']=['python3','tools/annotated-assembly/test_native_mapped_publication_pass_20.py','--images',images,'-v']
cmds['attribute-unit']=['dune','exec','test/native_attribute_auxiliary.exe']
cmds['emitter-unit']=['dune','exec','test/resident_int_emitter.exe']
cmds['pass21-native']=['python3','tools/annotated-assembly/test_native_attribute_auxiliary_pass_21.py','--images',images,'-v']
cmds['pass22']=['python3','tools/annotated-assembly/test_int_emitter_pass_22.py','--images',images,'-v']
cmds['pass23']=['python3','tools/annotated-assembly/test_native_int_emitter_pass_23.py','--images',images,'-v']
cmds['native-emitter-unit']=['dune','exec','test/native_int_emitter.exe']
cmds['word-emitter-unit']=['dune','exec','test/native_word_emitters.exe']
cmds['pass24']=['python3','tools/annotated-assembly/test_native_word_emitters_pass_24.py','--images',images,'-v']
cmds['range-unit']=['dune','exec','test/native_range_processing.exe']
cmds['pass25']=['python3','tools/annotated-assembly/test_native_7d53_pass_25.py','--images',images,'-v']
cmds['publication-unit']=['_build/default/test/native_publication_primitives.exe']
cmds['pass26']=['python3','tools/annotated-assembly/test_native_publication_primitives_pass_26.py','--images',images,'-v']
cmds['range-publication-unit']=['_build/default/test/native_range_publication.exe']
cmds['pass27']=['python3','tools/annotated-assembly/test_native_7e5f_pass_27.py','--images',images,'-v']
cmds['control-unit']=['_build/default/test/native_mapped_control.exe']
cmds['input-unit']=['_build/default/test/native_input_processing.exe']
cmds['pass28']=['python3','tools/annotated-assembly/test_native_8048_pass_28.py','--images',images,'-v']
cmds['gate-unit']=['_build/default/test/native_attribute_gate.exe']
cmds['pass29']=['python3','tools/annotated-assembly/test_native_80b7_pass_29.py','--images',images,'-v']
cmds['pass30']=['python3','tools/annotated-assembly/test_240a_pass_30.py','--images',images,'-q']
cmds['pass31']=['python3','tools/annotated-assembly/test_native_2511_pass_31.py','--images',images,'-q']
cmds['pass32']=['python3','tools/annotated-assembly/test_6223_pass_32.py','--images',images,'-q']
cmds['pass33']=['python3','tools/annotated-assembly/test_60e5_pass_33.py','--images',images,'-q']
cmds['historical-leaf-queries']=['_build/default/test/archaeology_60e5_leaves.exe']
cmds['pass34']=['python3','tools/annotated-assembly/test_5a46_pass_34.py','--images',images,'-q']
cmds['pass35']=['python3','tools/annotated-assembly/test_3dd9_pass_35.py','--images',images,'-q']
cmds['pass36']=['python3','tools/annotated-assembly/test_3a76_pass_36.py','--images',images,'-q']
cmds['pass37']=['python3','tools/annotated-assembly/test_small_gates_pass_37.py','--images',images,'-q']
cmds['pass38']=['python3','tools/annotated-assembly/test_acquisition_reentry_pass_38.py','--images',images,'-q']
cmds['pass39']=['python3','tools/annotated-assembly/test_state_transformation_pass_39.py','--images',images,'-q']
cmds['pass40']=['python3','tools/annotated-assembly/test_selector02_pass_40.py','--images',images,'-q']
cmds['pass41']=['python3','tools/annotated-assembly/test_acquisition_pass_41.py','--images',images,'-q']
cmds['pass42']=['python3','tools/annotated-assembly/test_causal_5929_pass_42.py','--images',images,'-q']
cmds['pass43']=['python3','tools/annotated-assembly/test_native_5929_pass_43.py','--images',images,'-q']
cmds['acquisition-parent-unit']=['_build/default/test/native_acquisition_parent.exe']
for name,file in [('pass44-roots','test_reentrant_acquisition_pass_44.py'),('pass44-family','test_acquisition_family_pass_44.py'),('pass44-numeric','test_numeric_acquisition_pass_44.py'),('pass44-hybrids','test_native_reentry_hybrids_pass_44.py')]:
 cmds[name]=['python3','tools/annotated-assembly/'+file,'--images',images,'-q']
cmds['pass56']=['python3','tools/annotated-assembly/test_external_reference_generation_pass_56.py','--images',images,'-q']
cmds['pass55']=['python3','tools/annotated-assembly/test_pli2_pointer_generation_pass_55.py','--images',images,'-q']
cmds['pass54']=['python3','tools/annotated-assembly/test_pli2_compact_emission_pass_54.py','--images',images,'-q']
cmds['pass53']=['python3','tools/annotated-assembly/test_pli2_emission_adapters_pass_53.py','--images',images,'-q']
cmds['pass52']=['python3','tools/annotated-assembly/test_buffered_rel_emission_pass_52.py','--images',images,'-q']
cmds['pass51']=['python3','tools/annotated-assembly/test_output_termination_pass_51.py','--images',images,'-q']
cmds['pass50']=['python3','tools/annotated-assembly/test_delimiter_driver_pass_50.py','--images',images,'-q']
cmds['pass49']=['python3','tools/annotated-assembly/test_initialization_parent_pass_49.py','--images',images,'-q']
cmds['pass48']=['python3','tools/annotated-assembly/test_acquisition_frame_pass_48.py','--images',images,'-q']
cmds['pass47']=['python3','tools/annotated-assembly/test_recursive_parent_pass_47.py','--images',images,'-q']
cmds['pass46']=['python3','tools/annotated-assembly/test_parent_pass_46.py','--images',images,'-q']
cmds['pass45-local']=['python3','tools/annotated-assembly/test_local_gates_pass_45.py','--images',images,'-q']
cmds['pass45-root']=['python3','tools/annotated-assembly/test_native_wrapper_pass_45.py','--images',images,'-q']
cmds['classifier-unit']=['_build/default/test/native_classifier.exe']
cmds['dynamic-progress']=['python3','-c',"import json,subprocess;from pathlib import Path;p=Path("+repr(str(out/'dynamic-progress.json'))+");subprocess.run(['python3','tools/annotated-assembly/minimal_dynamic_progress.py','--output',str(p)],check=True);assert json.loads(p.read_text())==json.loads(Path('research/minimal-baseline/dynamic-progress.json').read_text())"]
cmds['diff-check']=['git','diff','--check']

def run(name,cmd):
 start=time.perf_counter()
 with(out/(name+'.log')).open('w')as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,env=env)
 text=(out/(name+'.log')).read_text();match=re.search(r'Ran (\d+) tests?',text)
 value=dict(return_code=r.returncode,elapsed_seconds=round(time.perf_counter()-start,3),command=cmd,python_tests=int(match[1])if match else 0)
 if r.returncode:print(name,'FAILED', (out/(name+'.log')).read_text()[-1800:],flush=True)
 return value
if args.categories:
 selected=set(args.categories.split(','));unknown=selected-set(cmds)
 if unknown:raise SystemExit('Unknown categories: '+','.join(sorted(unknown)))
 cmds={k:v for k,v in cmds.items()if k in selected or k=='project'}
results={'build':run('build',['dune','build','@all','-j','4'])}
if results['build']['return_code']:raise SystemExit(1)
results['project']=run('project',cmds.pop('project')+['-j','4'])
if results['project']['return_code']:raise SystemExit(1)
# Resolve all public binaries from the existing Dune declarations; no semantic shim.
entries=re.findall(r'\(name ([^()\s]+)\)\s*\(public_name ([^()\s]+)\)',(ROOT/'bin/dune').read_text());aliases={public:str(ROOT/'_build/default/bin'/ (name+'.exe'))for name,public in entries}
launch=out/'readonly-launchers';launch.mkdir(exist_ok=True)
body="#!/usr/bin/env python3\nimport os,sys\nfrom pathlib import Path\nALIASES="+repr(aliases)+"\nROOT="+repr(str(ROOT))+"\na=sys.argv[1:]\nassert a and a[0]=='exec', 'Parallel categories cannot mutate the Dune build'\nn=a[1]; rest=a[2:]\nif rest and rest[0]=='--':rest=rest[1:]\np=Path(ALIASES[n]) if n in ALIASES else Path(ROOT)/'_build/default'/n\nassert p.is_file(), str(p)\nos.execv(str(p),[str(p),*rest])\n"
shim=launch/'dune';shim.write_text(body);shim.chmod(0o755);env['PATH']=str(launch)+os.pathsep+env.get('PATH','')
# Test binaries directly; their CLI identity/output semantics are unchanged.
for k,cmd in cmds.items():
 if cmd[:2]==['dune','exec']:cmds[k]=['_build/default/'+cmd[2]]
# Schedule the previously measured heavy native experiments early.
priority={'pass17-native':1000,'pass18-native':900,'pass19-native':800,'pass20-native':700}
items=sorted(cmds.items(),key=lambda kv:priority.get(kv[0],0),reverse=True)
with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers)as pool:
 futures={pool.submit(run,k,c):k for k,c in items}
 for f in concurrent.futures.as_completed(futures):results[futures[f]]=f.result()
wall=round(time.perf_counter()-started,3);total=round(sum(v['elapsed_seconds']for v in results.values()),3);slow=sorted(results,key=lambda k:results[k]['elapsed_seconds'],reverse=True)[:10]
summary=dict(all_passed=all(v['return_code']==0 for v in results.values()),wall_seconds=wall,sum_category_seconds=total,safe_parallel_workers=args.workers,serial_categories=['build','project'],categories=results,top_10_slowest=[dict(category=k,elapsed_seconds=results[k]['elapsed_seconds'])for k in slow],isolation='Serial shared Dune build/tests; later categories read prebuilt binaries and immutable captures, with unique temporary outputs; PYTHONDONTWRITEBYTECODE=1; Dune-exec launcher rejects build commands',binary_hashes={k:hashlib.sha256(Path(v).read_bytes()).hexdigest()for k,v in aliases.items()})
(out/'results.json').write_text(json.dumps(summary,indent=2)+'\n');print('Categories',len(results),'passed',sum(v['return_code']==0 for v in results.values()),'wall',wall,'sum',total,'workers',args.workers,flush=True)
raise SystemExit(not summary['all_passed'])
