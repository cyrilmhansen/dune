#!/usr/bin/env python3
"""Explicit active regression and preserved exhaustive historical epochs.

Build-mutating Dune stages remain serial. Later categories consume prebuilt
artifacts through the existing read-only launcher; profiles only select tests.
"""
import argparse,concurrent.futures,hashlib,json,os,re,subprocess,sys,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
POLICY=ROOT/'research/host-compiler/validation-policy.json'

def commands(images,out):
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
 cmds['pass60']=['python3','tools/annotated-assembly/test_carrier_generation_pass_60.py','--images',images,'-q']
 cmds['pass62']=['python3','tools/annotated-assembly/test_paired_carrier_publication_pass_62.py','--images',images,'-q']
 cmds['pass61']=['python3','tools/annotated-assembly/test_73d0_parent_family_pass_61.py','--images',images,'-q']
 cmds['pass59']=['python3','tools/annotated-assembly/test_carrier_clear_emission_pass_59.py','--images',images,'-q']
 cmds['pass58']=['python3','tools/annotated-assembly/test_indexed_carrier_transfer_pass_58.py','--images',images,'-q']
 cmds['pass57']=['python3','tools/annotated-assembly/test_pending_generation_pass_57.py','--images',images,'-q']
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
 cmds['build']=['dune','build','@all','-j','4']
 cmds['validation-runner-tests']=['python3','tools/annotated-assembly/test_validation_runner.py','-q']
 return cmds

def readonly_commands(cmds,out,env,root=ROOT):
 # Resolve all public binaries from the existing Dune declarations; no semantic shim.
 entries=re.findall(r'\(name ([^()\s]+)\)\s*\(public_name ([^()\s]+)\)',(root/'bin/dune').read_text());aliases={public:str(root/'_build/default/bin'/ (name+'.exe'))for name,public in entries}
 launch=out/'readonly-launchers';launch.mkdir(exist_ok=True)
 body="#!/usr/bin/env python3\nimport os,sys\nfrom pathlib import Path\nALIASES="+repr(aliases)+"\nROOT="+repr(str(root))+"\na=sys.argv[1:]\nassert a and a[0]=='exec', 'Parallel categories cannot mutate the Dune build'\nn=a[1]; rest=a[2:]\nif rest and rest[0]=='--':rest=rest[1:]\np=Path(ALIASES[n]) if n in ALIASES else Path(ROOT)/'_build/default'/n\nassert p.is_file(), str(p)\nos.execv(str(p),[str(p),*rest])\n"
 shim=launch/'dune';shim.write_text(body);shim.chmod(0o755);env['PATH']=str(launch)+os.pathsep+env.get('PATH','')
 # Test binaries directly; their CLI identity/output semantics are unchanged.
 for k,cmd in cmds.items():
  if cmd[:2]==['dune','exec']:cmds[k]=['_build/default/'+cmd[2]]
 return aliases

def select_categories(available,policy,profile=None,categories=None,extras=None):
 """Pure selection. Legacy --categories still mandates build/project only."""
 extra_names=set(filter(None,(extras or '').split(',')))
 if extras is not None and profile!='active':
  raise ValueError('--extra-categories requires --profile active')
 if categories and profile is not None:
  raise ValueError('--categories cannot be combined with --profile; use active extras')
 if categories:
  names=set(categories.split(','));unknown=names-(set(available)-{'build'})
  if unknown:raise ValueError('Unknown categories: '+','.join(sorted(unknown)))
  return 'legacy-categories',sorted(names|{'build','project'}),[]
 profile=profile or 'historical-full'
 if profile=='historical-full':names=set(available)
 elif profile=='active':names=set(policy['profiles']['active']['core_categories'])|extra_names
 else:raise ValueError('Unknown profile: '+profile)
 unknown=names-set(available)
 if unknown:raise ValueError('Unknown categories: '+','.join(sorted(unknown)))
 return profile,sorted(names),sorted(extra_names)

def selection_metadata(profile,selected,extras,workers,policy):
 return dict(profile=profile,validation_tier='FULL'if profile=='historical-full'else'ACTIVE/INCREMENTAL'if profile=='active'else'INCREMENTAL',selected_categories=selected,extra_categories=extras,selected_category_count=len(selected),workers=workers,last_certified_full_epoch=policy['current_full_epoch'],certificate_limit=policy['certificate_limit'])

class Progress:
 """One lock for whole lines/tails; active names are registered by workers."""
 def __init__(self,total,interval=45,stream=None,clock=time.monotonic):
  self.total=total;self.interval=interval;self.stream=stream or sys.stdout;self.clock=clock
  self.completed=0;self.active={};self.lock=threading.Lock();self.last_done=clock();self.last_heartbeat=self.last_done
  self.stop_event=threading.Event();self.thread=None
 def line(self,text):print(text,file=self.stream,flush=True)
 def start(self,name):
  with self.lock:
   self.active[name]=self.clock();self.line(f'[START {self.completed:3}/{self.total}] {name}')
 def done(self,name,elapsed,ok,tail=''):
  with self.lock:
   self.active.pop(name,None);self.completed+=1;self.last_done=self.clock()
   self.line(f'[DONE  {self.completed:3}/{self.total}] {name} {"OK"if ok else"FAILED"} {elapsed:.3f}s')
   if tail:self.line(f'[FAIL {name}]\n{tail}')
 def heartbeat(self):
  with self.lock:
   now=self.clock()
   if not self.active or now-max(self.last_done,self.last_heartbeat)<self.interval:return False
   def duration(start):
    seconds=int(now-start);return f'{seconds//60:02}m{seconds%60:02}s'
   running=','.join(f'{name}:{duration(start)}'for name,start in sorted(self.active.items()))
   self.line(f'[HEARTBEAT {self.completed:3}/{self.total}] active={running}');self.last_heartbeat=now;return True
 def __enter__(self):
  def loop():
   while not self.stop_event.wait(min(1,self.interval)):self.heartbeat()
  self.thread=threading.Thread(target=loop,daemon=True);self.thread.start();return self
 def __exit__(self,*_):self.stop_event.set();self.thread.join()

def run_category(name,cmd,out,env,progress):
 progress.start(name);start=time.perf_counter()
 with(out/(name+'.log')).open('w')as f:
  try:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,env=env);code=r.returncode
  except OSError as e:f.write(str(e)+'\n');code=127
 elapsed=round(time.perf_counter()-start,3);text=(out/(name+'.log')).read_text();match=re.search(r'Ran (\d+) tests?',text)
 value=dict(return_code=code,elapsed_seconds=elapsed,command=cmd,python_tests=int(match[1])if match else 0)
 progress.done(name,elapsed,code==0,text[-1800:]if code else'');return value

def timing_hints(policy):
 """Optional scheduling data; never category membership or certificate validity."""
 try:
  receipt=json.loads((ROOT/policy['current_full_epoch']['receipt']).read_text())
  return {k:float(v['elapsed_seconds'])for k,v in receipt['categories'].items()if isinstance(v.get('elapsed_seconds'),(int,float))and 0<=v['elapsed_seconds']<float('inf')}
 except (OSError,ValueError,KeyError,TypeError):return {}

def execute(selected_commands,out,env,metadata,workers=4,heartbeat_seconds=45,hints=None,root=ROOT):
 """Serial build/project, then bounded read-only workers; receipt even on failure."""
 started=time.perf_counter();out.mkdir(parents=True,exist_ok=True);cmds={k:list(v)for k,v in selected_commands.items()};results={};aliases={}
 with Progress(len(cmds),heartbeat_seconds)as progress:
  for name in ['build','project']:
   cmd=cmds.pop(name);cmd=cmd+['-j','4']if name=='project'else cmd
   results[name]=run_category(name,cmd,out,env,progress)
   if results[name]['return_code']:break
  else:
   aliases=readonly_commands(cmds,out,env,root)
   fallback={'pass17-native':1000,'pass18-native':900,'pass19-native':800,'pass20-native':700}
   hints=hints or {};items=sorted(cmds.items(),key=lambda kv:-(hints.get(kv[0],fallback.get(kv[0],0))))
   with concurrent.futures.ThreadPoolExecutor(max_workers=workers)as pool:
    futures={pool.submit(run_category,k,c,out,env,progress):k for k,c in items}
    for f in concurrent.futures.as_completed(futures):results[futures[f]]=f.result()
 wall=round(time.perf_counter()-started,3);total=round(sum(v['elapsed_seconds']for v in results.values()),3);slow=sorted(results,key=lambda k:results[k]['elapsed_seconds'],reverse=True)[:10]
 summary=dict(metadata,all_passed=len(results)==len(selected_commands)and all(v['return_code']==0 for v in results.values()),wall_seconds=wall,sum_category_seconds=total,safe_parallel_workers=workers,serial_categories=['build','project'],category_count=len(results),python_test_count=sum(v['python_tests']for v in results.values()),categories=results,not_run_categories=sorted(set(selected_commands)-set(results)),top_10_slowest=[dict(category=k,elapsed_seconds=results[k]['elapsed_seconds'])for k in slow],isolation='Serial shared Dune build/tests; later categories read prebuilt binaries and immutable captures, with unique temporary outputs; PYTHONDONTWRITEBYTECODE=1; Dune-exec launcher rejects build commands',binary_hashes={k:hashlib.sha256(Path(v).read_bytes()).hexdigest()for k,v in aliases.items()})
 (out/'results.json').write_text(json.dumps(summary,indent=2)+'\n')
 print(f"Profile {metadata['profile']} tier {metadata['validation_tier']}: categories {len(results)}/{len(selected_commands)}, passed {sum(v['return_code']==0 for v in results.values())}, Python tests {summary['python_test_count']}, wall {wall:.3f}s, sum {total:.3f}s, workers {workers}",flush=True)
 return summary

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--images');p.add_argument('--output',type=Path)
 p.add_argument('--categories',help='Legacy incremental category list; build/project remain mandatory')
 p.add_argument('--profile',choices=['historical-full','active'])
 p.add_argument('--extra-categories',help='Explicit direct regressions added to active core')
 p.add_argument('--list-categories',action='store_true',help='Print selected profile/category JSON without running tests')
 p.add_argument('--workers',type=int,choices=range(1,5),default=4)
 args=p.parse_args(argv)
 policy=json.loads(POLICY.read_text());out=(args.output or ROOT/'_build/validation-list-only').resolve();images=str(Path(args.images).resolve())if args.images else'<images>'
 cmds=commands(images,out)
 try:profile,names,extras=select_categories(cmds,policy,args.profile,args.categories,args.extra_categories)
 except ValueError as e:p.error(str(e))
 metadata=selection_metadata(profile,names,extras,args.workers,policy)
 if args.list_categories:print(json.dumps(metadata,indent=2),flush=True);return 0
 if args.images is None or args.output is None:p.error('--images and --output are required for execution')
 os.chdir(ROOT);env=dict(os.environ,RUNES_HOST_IMAGES=images,PYTHONDONTWRITEBYTECODE='1')
 print('Selected categories ('+profile+'): '+','.join(names),flush=True)
 summary=execute({k:cmds[k]for k in names},out,env,metadata,args.workers,hints=timing_hints(policy))
 return 0 if summary['all_passed']else 1

if __name__=='__main__':raise SystemExit(main())
