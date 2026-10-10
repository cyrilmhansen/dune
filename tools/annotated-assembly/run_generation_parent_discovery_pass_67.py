#!/usr/bin/env python3
"""Pass67: explicit PCHL ownership, bounded paired-generation proof, ACTIVE only."""
import argparse,collections,json,os,re,shutil,subprocess,tempfile
from pathlib import Path
from check_selector02_pass_40 import load as witness_load,CAPTURES,coord,children_any
from run_buffered_rel_emission_pass_52 import save,digest
OUT=Path('_build/host-compiler-pass-67');REPORT=Path('research/host-compiler/pass-67')
BASE='2e5b8c4e3ebe68fc7e100557772afdb4a4a4e4cb';IMAGES='/home/john/pli/cpm/pli80/DISK1'
BOUNDS={0x6ea5:0x6f19,0x04e9:0x04ff,0x04ff:0x0515,0x0515:0x052c,0x052c:0x0546,0x8350:0x8357,0x8357:0x8364}
EXTRAS=['pass67','pass66']
def load(p):return json.loads(Path(p).read_text())
def rows_from_window(r):
 ws=r['witnesses'];rets={e['frame']['call_step']:e for e in r['relations']if e['type']=='hardware_frame_return'};by_step={w['step_index']:w for w in ws}
 matched={n:dict(ret=by_step[e['step_index']],relation=e)for n,e in rets.items()if e['step_index']in by_step}
 def reduced(call,body,ret):
  own=[];skip=-1
  for w in body:
   if w['step_index']<=skip:continue
   own.append(w)
   if w['control']['kind']=='call' and w['control']['taken']:
    assert w['step_index']in matched,(coord(w['origin']),w['step_index'])
    skip=matched[w['step_index']]['ret']['step_index']
  return dict(call=call,entry=body[0],ret=ret,own_witnesses=own,nested_returns={w['step_index']:dict(matched[w['step_index']],memory_witnesses=[q for q in body if w['step_index']<q['step_index']<=matched[w['step_index']]['ret']['step_index']and(q['reads']or q['writes'])])for w in own if w['control']['kind']=='call'and w['control']['taken']})
 result={f'PLI2.OVL+{o:04X}':[]for o in BOUNDS};result['PLI2.OVL+6EA5'].append(reduced(r['prior'][-1],ws,r['ret']))
 for w in ws:
  if w['control']['kind']=='call'and w['control']['taken'] and coord(w.get('target_origin'))in result:
   ret=matched[w['step_index']]['ret'];body=[q for q in ws if w['step_index']<q['step_index']<=ret['step_index']]
   result[coord(w['target_origin'])].append(reduced(w,body,ret))
 return result

def discovery():
 OUT.mkdir(parents=True,exist_ok=True);REPORT.mkdir(parents=True,exist_ok=True);allrows={};ownership={};paths={};globals_by_source={}
 for source,capture in CAPTURES.items():
  ring=collections.deque(maxlen=40);current=None;records=[];calls={};windows=[];last=None;targets=collections.Counter()
  for chunk in witness_load(capture/'event-witnesses.json')['chunks']:
   for event in witness_load(capture/'event-witnesses/chunks'/f"{chunk['id']:06d}.json")['events']:
    if event['type']=='instruction':
     w=event['witness'];last=w;k=coord(w['origin'])
     if w['control']['kind']=='call'and w['control']['taken']:calls[w['step_index']]=w;targets[coord(w.get('target_origin'))]+=1
     if k=='PLI2.OVL+6EA5':
      assert current is None;current=dict(entry=w,prior=list(ring),witnesses=[],relations=[]);records.append(current)
     if current is not None:
      current['witnesses'].append(w)
      if k=='PLI2.OVL+6F18':current['ret']=w;current=None
     ring.append(w)
    else:
     if current is not None:current['relations'].append(event)
     if event['type']=='hardware_frame_return':
      call=calls[event['frame']['call_step']];windows.append(dict(call=call['step_index'],ret=event['step_index'],target=coord(call.get('target_origin')),caller=coord(call['origin']),sp=call['sp_after'],relation=event))
  assert current is None
  source_rows={f'PLI2.OVL+{o:04X}':[]for o in BOUNDS};ownership[source]=[];paths[source]=[]
  for r in records:
   prior=r['prior'];gateway=prior[-4:];entry=r['entry'];ret=r['ret'];sp=entry['sp_before']
   assert [coord(w['origin'])for w in gateway]==['PLI2.OVL+20AC','PLI2.OVL+20AF','PLI2.OVL+20B0','PLI2.OVL+20B3']
   push=gateway[1];assert push['writes']==[dict(address=sp+1,old_value=None,new_value=0x42),dict(address=sp,old_value=None,new_value=0xb4)]
   assert gateway[-1]['after']==entry['before']and gateway[-1]['writes']==[]
   assert gateway[2]['reads']==[dict(address=0xad1f,value=0xa5),dict(address=0xad20,value=0x90)]
   assert ret['reads']==[dict(address=sp,value=0xb4),dict(address=sp+1,value=0x42)]and ret['after']['sp']==sp+2 and ret['after']['pc']==0x42b4
   assert not any(q['address']in[sp,sp+1]for w in r['witnesses']for q in w['writes'])
   ancestors=sorted([q for q in windows if q['call']<entry['step_index']<ret['step_index']<q['ret']],key=lambda q:q['ret']-q['call'])
   reduced=rows_from_window(r)
   for k,v in reduced.items():source_rows[k]+=v
   root=reduced['PLI2.OVL+6EA5'][0];children=children_any(root);own=root['own_witnesses'];by={w['origin']['offset']:w for w in own}
   first=next(c for c in children if c['callsite']==0x6ed7);second=next(c for c in children if c['callsite']==0x6ee5)
   assert [first['entry'][k]for k in['c','d','e']]==[2,by[0x6ed1]['reads'][1]['value'],by[0x6ed1]['reads'][0]['value']]
   assert [second['entry'][k]for k in['c','d','e']]==[0,0,0]
   assert [c['target']for c in children if first['call_step']<=c['call_step']<=second['call_step']]==['PLI2.OVL+8072','PLI2.OVL+742A','PLI2.OVL+8072']
   ownership[source].append(dict(entry_step=entry['step_index'],return_step=ret['step_index'],software_entry='PLI2.OVL+6EA5',software_continuation=0x42b4,entry_SP=sp,gateway=gateway,nearest_hardware_owner={k:v for k,v in ancestors[0].items()if k!='relation'},prior_RET=next((coord(w['origin'])for w in reversed(prior)if w['control']['kind']=='return'),None),root_witness_hash=digest(r),child_sequence=[dict(callsite=c['callsite'],target=c['target'],input=c['entry'],output=c['output'],call_step=c['call_step'],return_step=c['return_step'])for c in children]))
   paths[source].append(dict(entry=entry['before'],output=ret['after'],first=first,second=second,branches=[dict(offset=w['origin']['offset'],taken=w['control']['taken'],flags=w['before']['flags'])for w in own if w['control']['kind']=='jump'],reads=[dict(offset=w['origin']['offset'],reads=w['reads'])for w in own if w['reads']],writes=[dict(offset=w['origin']['offset'],writes=w['writes'])for w in own if w['writes']]))
  allrows[source]=source_rows
  globals_by_source[source]={k:dict(calls=targets[k],callers=dict(collections.Counter(coord(w['origin'])for w in calls.values()if coord(w.get('target_origin'))==k)))for k in list(source_rows)+['PLI2.OVL+834D']}
  assert targets['PLI2.OVL+6EA5']==0 and targets['PLI2.OVL+6ED7']==0 and targets['PLI2.OVL+6EE5']==0
  save(OUT/(source+'-software-windows.json'),records)
 save(OUT/'rows.json',allrows);save(OUT/'annotation-rows-PLI2.OVL.json',allrows);save(REPORT/'ownership-map.json',ownership);save(REPORT/'natural-paths.json',paths);save(REPORT/'global-helper-inventory.json',globals_by_source)
 print('Fresh software ownership and paired-call proof passed',flush=True)

def prove(images=IMAGES,focused=False):
 OUT.mkdir(parents=True,exist_ok=True);dest=OUT/'proof';dest.mkdir(exist_ok=True)
 if not os.environ.get('RUNES_HOST_IMAGES'):
  subprocess.run(['dune','build','bin/native_generation_parent.exe'],check=True)
 else:
  assert Path('_build/default/bin/native_generation_parent.exe').is_file(), 'Aggregate build must prepare the proof executable'
 for source in [None,'FACTOR','OPTIMIST']:
  with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
   cmd=['_build/default/bin/native_generation_parent.exe','--toolchain',str(images),'--output-dir',str(Path(tmp)/'results')]+(['--family-only']if focused or source else[])+(['--cross-source',source]if source else[])
   log=dest/((source or 'primary')+'.log')
   with log.open('w')as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT)
   if r.returncode:raise RuntimeError(log.read_text()[-5000:])
   for p in(Path(tmp)/'results').glob('*.json'):
    if focused and source is None and p.name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:continue
    shutil.copyfile(p,dest/((source+'-'if source else'')+p.name))
 print('Independent root/component/CPU/cross proofs passed',flush=True)

LAWS={
 0x6ea5:('Mapped-word paired-generation software handler','Clear AD9F. Fresh low AD0C -> canonical052C mapped word; publish low/high toADA2. Mask HL with DE0400 through8350; canonical resident1A29(A0), OR L, ADI FF, SBB A -> publishADA4; RAR. Supported zero mask skips recursive1FB5 arm. Fresh ADA2 word ->DE, C2 ->canonical8072. Canonical742A ->fresh position HL; low/high publishADA0. Literal DE0,C0 ->canonical8072. FreshADA4 RAR must remainclear.8357(A80,DEADA2) freshly masks pointed word. Canonical1A29(A0), OR L; zero selects literalBC8F6E, nonzeroBC8F69; canonical8248, RET6F18 consumes PUSH-H softwarecontinuation42B4. No hardware CALL at6EA5; supported recursive-gate-clear routes only.'),
 0x04e9:('Mapped high byte','Save C atABFD; paired LHLD ABFD, zero-extend low selector; fresh byte[AAB0+selector] ->C; zero-extend mapped byte; fresh byte[A795+mapped] ->A. DE preserved, BC=mapped, HL=address. DAD sets CY0; NZPA preserved; scratch write and paired high read retained. Byte indices are zero-extended, not bounded by an inferred table capacity.'),
 0x04ff:('Mapped low byte','Save C atABFE; paired LHLD ABFE, zero-extend low selector; fresh byte[AAB0+selector] ->C; zero-extend mapped byte; fresh byte[A7F8+mapped] ->A. DE preserved, BC=mapped, HL=address. DAD CY0 and preserved NZPA, scratch and adjacent paired read retained.'),
 0x0515:('Saved byte word composition','Save E atAC00 then C atABFF. Fresh paired AC00, zero-extend low byte; C8 ->canonical83B4 shift. Fresh ABFF ->A ->canonical8398 OR word. Result HL=(savedE<<8)|savedC, with actual children flags/registers/stack residue.'),
 0x052c:('Mapped word acquisition','Save C atAC01. Fresh paired AC01 lowC ->04FF low lookup. PUSH PSW. Independent fresh pairedAC01 lowC ->04E9 high lookup; E=A. POP B; C=B carries the first actual returned A without restoring flags. Canonical0515 composes the independently acquired low and high bytes; RET0545.'),
 0x8350:('DE and HL word-mask shared tail','A=E; ANA L; L=A. Independently A=D; ANA H; H=A. HL=entryHL AND entryDE, A=high result, BC/DE preserved; final logical flags from high ANA; RET8356. Actual alternate CALL target8350; static preceding834D prefix is not absorbed.'),
 0x8357:('Pointed word byte-mask acquisition','XCHG; E=A; D0; XCHG. Fresh LDAX D AND low mask ->L. Increment DE modulo65536. Fresh LDAX D AND high mask ->H. HL=pointedWord AND zeroextended entryA, A=high result, DE=originalDE+1, BC preserved; exact two reads and logical flags; RET8363.')}

def contracts():
 rows=load(OUT/'rows.json');natural={o:set()for o in BOUNDS}
 for g in rows.values():
  for o in BOUNDS:natural[o].update(w['origin']['offset']for r in g[f'PLI2.OVL+{o:04X}']for w in r['own_witnesses'])
 cross=[]
 for source in ['FACTOR','OPTIMIST']:
  cross+=load(OUT/'proof'/(source+'-natural-instruction-witnesses.json'))
 natural[0x6ea5].update(w['offset']for w in cross if w['owner']=='PLI2.OVL+6EA5')
 text=f'let p="{IMAGES}/PLI2.OVL";;\nlet c=open_in_bin p;; let b=Bytes.create(in_channel_length c);; really_input c b 0(Bytes.length b);; close_in c;;\nlet rec loop o last=if o<last then match I8080.Decode.decode b ~offset:o with Error _->failwith"decode"|Ok d->Printf.printf"%04X %s %s\\n"o(String.concat""(List.init d.length(fun i->Printf.sprintf"%02X"(Char.code(Bytes.get b(o+i))))))(I8080.Instr_format.format d.instr);loop(o+d.length)last;;\n'+''.join(f'loop {o} {end};;\n'for o,end in sorted(BOUNDS.items()))
 (OUT/'decode.ml').write_text(text);out=subprocess.check_output(['ocaml','-I','_build/default/lib/i8080','-I','_build/default/lib/i8080/.i8080.objs/byte','i8080.cma',str(OUT/'decode.ml')],text=True);cfg=[];static={}
 for line in out.splitlines():
  off,b,d=line.split(' ',2);o=int(off,16);owner=next(a for a,end in BOUNDS.items()if a<=o<end);kind='call'if d.startswith('CALL')else'jump'if d.startswith('J')else'return'if d=='RET'else'ordinary';control=dict(kind=kind);target=None
  if kind in ['call','jump']:control['target']=int.from_bytes(bytes.fromhex(b)[1:],'little')
  if kind=='call':target=dict(image=dict(name='PLI.COM'if control['target']<0x2200 else'PLI2.OVL'),offset=control['target']-(0x100 if control['target']<0x2200 else 0x2200))
  evidence='OBSERVED'if o in natural[owner]else'STATIC UNOBSERVED unsupported'
  cfg.append(dict(owner=f'PLI2.OVL+{owner:04X}',offset=o,bytes=b,decoded=d,control=control,evidence=evidence))
  primary={w['origin']['offset']for g in rows.values()for r in g[f'PLI2.OVL+{owner:04X}']for w in r['own_witnesses']}
  if o in natural[owner]and o not in primary:
   static.setdefault(f'PLI2.OVL+{owner:04X}',[]).append(dict(origin=dict(image=dict(name='PLI2.OVL'),offset=o),target_origin=target,bytes=b,disassembly=d,control=control,evidence_class='OBSERVED cross-source'))
 save(REPORT/'cfg.json',cfg);save(OUT/'annotation-static-PLI2.OVL.json',static)
 save(REPORT/'contract-laws-PLI2.OVL.json',{f'PLI2.OVL+{o:04X}':dict(end=BOUNDS[o],description=desc,contract=law,completeness=['stable','partial'if o==0x6ea5 else'complete','partial'if o==0x6ea5 else'complete'])for o,(desc,law)in LAWS.items()})

def annotations():
 env={**os.environ,'RUNES_ANNOTATION_PASS':'67','RUNES_ANNOTATION_BASE':BASE}
 subprocess.run(['python3','tools/annotated-assembly/update_buffered_rel_annotations_pass_52.py',IMAGES,'PLI2.OVL'],env=env,check=True)
 subprocess.run(['python3','tools/annotated-assembly/update_generation_parent_annotations_pass_67.py'],check=True)
 subprocess.run(['python3','tools/annotated-assembly/verify.py','--images',IMAGES,'--write-progress'],check=True)
 subprocess.run(['python3','tools/annotated-assembly/minimal_dynamic_progress.py','--output','research/minimal-baseline/dynamic-progress.json'],check=True)

def topology():
 raw=load('_build/host-compiler-pass-51/residual-map.json');ownership=load(REPORT/'ownership-map.json');out={}
 names=['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in[0x8072,0x7ed6,0x82dd,0x829c,0x7338,0x742a,0x8258,0x82b5,0x7e05,0x7b1b,0x7b99,0x7ae4,0x8248,0x7701,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619,0x7434,0x7630,0x765e]]
 inside=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
 for source,v in raw.items():
  ws=v['windows'];allpre=v['roots']+[r for r in ws if r['target']in names];pre=[r for r in allpre if not any(q is not r and inside(r,q)for q in allpre)]
  ps=[dict(call=r['entry_step']-1,ret=r['return_step'],target='PLI2.OVL+6EA5',caller='PLI2.OVL+20B3')for r in ownership[source]];outer=[r for r in ps if not any(inside(r,q)for q in pre)];absorbed=[r for r in pre if any(inside(r,q)for q in outer)];post=[r for r in pre if r not in absorbed]+outer
  coords=['PLI.COM+119E']+[f'PLI2.OVL+{o:04X}'for o in[0x8072,0x7ed6,0x7338,0x75ce,0x7619,0x7a17,0x742a,0x8248,0x18b3]]
  out[source]=dict(logical=len(ps),external=len(outer),absorbed=dict(collections.Counter(r['target']for r in absorbed)),net_delta=len(outer)-len(absorbed),remaining_enabled_8072_roots=sum(r['target']=='PLI2.OVL+8072'for r in post),remaining_guest={k:dict(calls=len(rs:=[r for r in ws if r['target']==k and not any(q is not r and inside(r,q)for q in post)and r not in post]),callers=dict(collections.Counter(r['caller']for r in rs)))for k in coords})
 save(REPORT/'topology-summary.json',out)

def reports():
 cfg=load(REPORT/'cfg.json');proof=OUT/'proof';paths=load(REPORT/'natural-paths.json');primary=load(proof/'natural-cases.json');cross={}
 old_evidence=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/evidence.json']))
 def historical_counts(evidence):
  return {(seed['id'],w['offset'],r['run']):r['execution_count']for seed in evidence['seeds']for w in seed['instructions']for r in w.get('runs',[])if r['run']in['FACTOR','OPTIMIST']}
 previous=historical_counts(old_evidence);current=historical_counts(load('research/annotated-assembly/evidence.json'))
 assert all(current.get(k)==v for k,v in previous.items()), 'Historical cross-source coverage changed'
 save(REPORT/'historical-coverage-preservation.json',dict(baseline=BASE,prior_instruction_source_totals_preserved=len(previous),sources=['FACTOR','OPTIMIST'],all_preserved=True))
 for source in ['FACTOR','OPTIMIST']:
  data=load(proof/(source+'-natural-cases.json'))['sources'][0]['entries'];root=data[0]['members'];cross[source]=dict(calls=len(root),caller='PLI2.OVL+20B3 PCHL',selectors=dict(collections.Counter(str(r['entry_shared_state']['selector_AD0C'])for r in root)),mapped_words=dict(collections.Counter('/'.join(str(x)for x in r['entry_shared_state']['mapped_word_bytes'])for r in root)),entries=[dict(offset=e['offset'],calls=len(e['members']),proof_hash=digest(e['members']))for e in data],own_instruction_hash=digest(load(proof/(source+'-natural-instruction-witnesses.json'))),gateway_hash=digest(load(proof/(source+'-gateway-witnesses.json'))))
 save(REPORT/'cross-evidence.json',cross)
 syn=[c for c in load(proof/'synthetic-checkpoints.json')['cases']if c['route'].startswith('6EA5_')]
 save(REPORT/'shadow-summary.json',dict(primary=[dict(source=s['source'],entries=[dict(offset=e['offset'],calls=len(e['members']),proof_hash=digest(e['members']))for e in s['entries']])for s in primary['sources']],cross=cross,synthetic=dict(cases=len(syn),routes=dict(collections.Counter(c['route']for c in syn)),hash=digest(syn),concrete_CPU=True),comparison=['all registers/flags/SP/PC','ordered writes/full65536 RAM','stack last writers/child chronology','DMA/filesystem/record/service chronology'],all_passed=True))
 for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:save(REPORT/name,load(proof/name))
 knowledge=dict(RAW_to_UNDERSTOOD=load(REPORT/'archaeology-summary-PLI2.OVL.json')['raw_to_understood'],DECODED_to_UNDERSTOOD=0,STRUCTURED_to_UNDERSTOOD=0,root_observed=sum(len(bytes.fromhex(w['bytes']))for w in cfg if w['owner']=='PLI2.OVL+6EA5'and w['evidence']=='OBSERVED'),helper_observed=sum(len(bytes.fromhex(w['bytes']))for w in cfg if w['owner']!='PLI2.OVL+6EA5'and w['evidence']=='OBSERVED'),static_promoted=0,unsupported_root_bytes=sum(len(bytes.fromhex(w['bytes']))for w in cfg if w['evidence']!='OBSERVED'))
 save(REPORT/'knowledge-summary.json',knowledge)
 semantic=dict(historical_root='PLI2.OVL+6EA5',semantic_inputs=['fresh low AD0C selector','fresh AAB0 index map and independent A7F8/A795 byte values','canonical generation/pending/output state'],semantic_outputs=['mapped word and gate scratch publications','two differentiated8072 transactions separated by742A reset/position publication','selected literal-pointer generation via8248'],shared_historical_state=['AD0C/AD0D, AAB0, A7F8, A795','ABFD..AC01, AD9F, ADA0..ADA4, AD1F','canonical child state and actual PUSH-H continuation42B4'],historical_mechanism=['PUSH H/PCHL software gateway, separate from hardware CALL','paired reads, PSW/POP-B transport and mapped word construction','word masks, resident subtraction, arithmetic carry masks and RAR','fresh register restoration/literal argument setup and hardware child CALL residue'],candidate_modern_operation='Generate a mapped-word relation pair and a selected fixed representation field',confidence={'operational_law':'OBSERVED / DEDUCED bounded recursive-gate-clear contract','compiler_meaning':'HYPOTHESIS','unobserved_recursive_1FB5_arm':'STATIC UNOBSERVED unsupported'},mir_relevance='Future semantic investigation may separate mapped inputs from historical scratch; no MIR API or refactor.')
 save(REPORT/'semantic-extraction.json',semantic)
 import run_host_compiler_regressions as runner
 policy=load('research/host-compiler/validation-policy.json');_,full,_=runner.select_categories(runner.commands(IMAGES,OUT),policy,'historical-full');old=set(load('research/host-compiler/pass-62/validation.json')['categories']);assert old<=set(full)and {'validation-runner-tests',*('pass'+str(i)for i in range(63,68))}<=set(full)
 save(REPORT/'historical-full-selection.json',dict(count=len(full),all_92_preserved=True,additional=sorted(set(full)-old),executed=False))
 command='python3 tools/annotated-assembly/run_host_compiler_regressions.py --profile historical-full --images /home/john/pli/cpm/pli80/DISK1 --output _build/host-compiler-pass-67/full-validation --workers 4'
 save(REPORT/'full-checkpoint-handoff.json',dict(semantic_commit='PENDING_UNTIL_COMMIT',last_certified_FULL='Pass62',requested_profile='historical-full',selected_category_count=len(full),workers=4,historical_bytes=94720,status='pending_external_execution',command=command))
 save(REPORT/'active-dependencies.json',dict(extras=EXTRAS,rationale={'pass67':'New software-owner/argument/stack/component/CPU and hybrid proofs.','pass66':'Shared PLI2 bridge bounds and identity checking now accommodate a separately scoped PCHL ABI; verify existing8072 hardware CALL dispatch and transaction behavior.','not_added':'Canonical child algorithms remain untouched. Local independently correlated child shadows cover8072/742A/8248 and mapped/mask helpers; no chronological accumulation.'}))
 ranking=[];raw=load('_build/host-compiler-pass-51/residual-map.json')
 for name in ['PLI2.OVL+3D10','PLI2.OVL+397F','PLI2.OVL+18B3']:
  ranking.append(dict(candidate=name,natural={s:dict(calls=len(rs:=[r for r in v['windows']if r['target']==name]),spans=[r['ret']-r['call']for r in rs])for s,v in raw.items()},classification='additional compiler predicates and private frame'if name.endswith('3D10')else'broader independent policy; not inferred from inclusive span'))
 save(REPORT/'next-boundary-ranking.json',dict(recommended='Fresh bounded child/predicate discovery for the true3D10 context, before its migration; do not widen to1FB5 or18B3.',ranks=ranking,software_owner='1FB5 is the larger dispatch/save/restore gateway;6EA5 is now a distinct bounded software handler below it.',rejected=['6ED7/6EE5 are CALL instructions, not entries','6ED1 is a branch target/internal argument setup, not a procedure','6EE0 is sequential literal setup; no independently entered procedure','nearest retained1FB5 inclusive window is not a6Exx procedure extent','numeric prior RET6EA4 does not create a hardware CALL entry at6EA5']))
 packet=dict(baseline=BASE,root='PLI2.OVL+6EA5',bounds=[0x6ea5,0x6f19],laws=load(REPORT/'contract-laws-PLI2.OVL.json'),knowledge=knowledge,primary_counts={s:len(rs)for s,rs in paths.items()},paired_arguments={s:[dict(first=[r['first']['entry'][k]for k in ['c','d','e']],second=[r['second']['entry'][k]for k in ['c','d','e']],proof_hash=digest(r))for r in rs]for s,rs in paths.items()},proofs=load(REPORT/'shadow-summary.json'),hierarchy=load(REPORT/'topology-summary.json'),canonical_children=['8072','742A','8248','1A29','83B4','8398'],active_extras=EXTRAS,oracle_queries=0,last_FULL='Pass62',FULL_status='PENDING EXTERNAL EXECUTION',full_trigger=False)
 save(REPORT/'implementation-packet.json',packet);assert(REPORT/'implementation-packet.json').stat().st_size<32768

 def summary_table():
  return '\n'.join(f"|{s['result']['source']}|{s['pre_guest_instructions']} → {s['result']['actual_guest_instructions']}|{s['guest_instructions_removed']}|{sum(s['pre_transition_vector'])} → {s['result']['host_transitions']}|"for s in load(REPORT/'cumulative-hybrid-summary.json')['sources'])
 (REPORT/'README.md').write_text(f'''# Pass67 — bounded paired-generation software handler

Baseline `{BASE}` was verified at HEAD and origin/main. This is a **semantic migration**, following discovery of the genuine software entry **PLI2.OVL+6EA5 [6EA5,6F19), 116 bytes**.6ED7 and6EE5 are CALL instructions; neither is a procedure entry. No artificial root was installed at6ED1 or6EE0. The hardware owner is the larger1FB5 gateway, called at2149. Its inclusive span is not the local handler extent. [Ownership](ownership-map.json), [CFG](cfg.json), and [root paths](natural-paths.json) retain independently derived evidence.

## Ownership and software continuation

The actual gateway executes20AC LXI H,42B4;20AF PUSH H;20B0 fresh LHLD AD1F;20B3 PCHL. Fresh handler pointer90A5 selects6EA5. PCHL changes PC only; it creates **no hardware CALL word**. The PUSH writes42 thenB4 below the gateway SP. Every natural6F18 RET readsB4/42 from that same untouched slot, returns to20B4, and increases SP by2. This ordinary explicit software continuation is distinct from established N2/N8 argument-consuming families. No private host frame or invented CALL word is used. Every child retains its genuine encoded hardware CALL/RET stack residue, including the052C PSW carrier.

Primary logical/external handler roots: **MINIMAL1, FIZZBUZ4, PICTURE1**. Cross evidence: **FACTOR1, OPTIMIST4**. All enter through20B3 PCHL; the nearest enclosing matched hardware frame is1FB5, not a manufactured6Exx CALL frame. Neighboring6EA4 RET belongs to another handler. No natural overlapping CALL entry into this handler was found. Six new bounded child contracts are separately identified:04E9[04E9,04FF),04FF[04FF,0515),0515[0515,052C),052C[052C,0546),8350[8350,8357),8357[8357,8364).8350 is an actual CALL-selected shared tail; static834D prefix is left untouched.

## Exact operation and paired relationship

Fresh lowAD0C is mapped through AAB0.04FF independently reads the low component atA7F8+mapped index;04E9 independently reads the high component atA795+mapped index.052C saves the selector atAC01 and transports the first returned A through PUSH PSW/POP B across the second lookup.0515 publishes E/C atAC00/ABFF, uses canonical83B4(C8) and8398 to form HL=(high<<8)|low. No table capacity is inferred; selectors and mapped indices are zero-extended bytes. Scratch writes and paired adjacent reads remain visible.

6EA5 clearsAD9F and publishes that actual returned word low/high atADA2.8350 masks HL with literalDE0400; canonical resident1A29(A0) computes modulo-word negation. OR L, ADI FF, SBB A forms the nonzero mask, published atADA4. RAR exposes bit0 in CY. All11 natural handlers have the0400 bit clear and skip the recursive1FB5 call arm. That independent gateway arm remains RAW / STATIC / UNOBSERVED / unsupported, rather than being absorbed into this pass.

**6ED7 supplies C=2 and DE=fresh word[ADA2]**. Primary first tuples are2/2/82; OPTIMIST additionally2/2/144. After the actual8072 return, canonical742A resets gated indexed state, publishesFFFF atADA6, and returns fresh1C2C inHL. The parent publishes that word low/high atADA0. **6EE5 then supplies literal C=0, DE=0**, independent of the first returned registers. The calls are ordered and both execute on every accepted path. They share evolving relation/output state; they are not two independent identical invocations. The first call's publications/output precede the742A reset and position read, then the second publication/output. [Child checkpoints](shadow-summary.json) and root journals retain that inter-call state; no child result is recomputed or patched.

FreshADA4 is tested again. Supported clear paths proceed to8357(A80,DEADA2), independently reading low/high and retaining DE increment. Canonical1A29(A0), OR L tests the resulting word. Zero selects literalBC8F6E; nonzero selectsBC8F69. Both invoke canonical8248. The alternate bit80 route is naturally observed once inOPTIMIST; primary roots all select8F6E. No speculative compiler meaning is assigned to these pointer literals or emitted fields.

## Independent proof, staging, and archaeology

All11 roots and their exact052C/04FF/04E9/0515/8350/8357/8072/742A/8248/1A29 windows independently compare registers, flags, SP/PC, ordered writes, all65536 RAM bytes, stack last writers, child chronology, DMA/filesystem and record/service chronology. The96 independent concrete-CPU synthetic discriminants separate low/high mapped bytes, selector from mapped index, indices0/255, adjacentAD0D, incoming carry, final bit80 selection, and valid first8072 equality/adjacent-value success. The742A reset forces the second attempt into its clear-gate fallback; no second-success child output is patched. Negative cases cover code/child/gateway/continuation corruption, table/scratch/stack/sentinel aliases, recursive0400 selection and late position-wrap rejection. Complete copied staging precedes every live effect. Original RAM/DMA/filesystem remain unchanged after rejected preparation.

Canonical8072/742A/8248/1A29/83B4/8398 algorithms are reused. CPU8080, CP/M, Runner and shared journal/capture interpretation are unchanged. The bridge adds one explicitly scoped local PUSH-H/PCHL ABI alongside existing CALL ABIs; historical CALL checking is preserved. No generic runtime or transaction redesign occurred. Annotation verification adds an explicit, canonical Pass67 PUSH-H/PCHL proof kind with separate negative tests; legacy CALL/N2/N8 checks retain their interpretation. This new local ABI is proved narrowly, with no shared capture reinterpretation; **no FULL trigger fired**.

[Knowledge accounting](knowledge-summary.json) reports213 RAW→UNDERSTOOD (100 root-own and113 helper bytes), zero DECODED/STRUCTURED promotions, all naturally OBSERVED. Sixteen root bytes remain RAW in the two recursive-gateway arms. The nine alternate-tail bytes have OPTIMIST natural evidence; no synthetic-only byte is promoted. Bounds stable, local control flow/contract partial over the supported nonrecursive and inherited canonical-child domains. No historical behavior correction. Implementation corrections during development removed an unjustified provisional99 index limit exposed by cross-source inputs and fixed a test-only child-code coordinate. Pragmatic divergence: none. Fidelity debt: unsupported recursive arm, inherited pending/position/output/alias limits, and unknown compiler meaning.

## Measured hierarchy and outputs

|Source|Guest before → after|Removed|Host before → after|
|---|---:|---:|---:|
{summary_table()}

Each new handler absorbs two8072 roots, one742A root and one8248 root. Actual transition deltas are-3/-12/-3. Remaining enabled8072 roots outside this new handler are1/3/2; guest-external8072/7ED6/7338 calls remain zero. External119E remains32/32/39. These are whole-run counter differences, not inclusive window sums. Standalone handler and cumulative hybrids preserve complete REL/INT, filesystem, console/milestones, BDOS and record chronology and warm boot. Exact REL SHA256: MINIMAL7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119; FIZZBUZ68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203; PICTUREc02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1.

[Semantic extraction](semantic-extraction.json) separates mapped inputs and differentiated generation effects from absolute scratch, PSW transport and software/hardware continuation mechanisms. Compiler-level wording remains HYPOTHESIS; no MIR/API or faithful-code refactor. [Next ranking](next-boundary-ranking.json) recommends fresh bounded predicate/child discovery at the true3D10 context before migration, ahead of the less converged397F context and independent large18B3 traversal. The broader1FB5 gateway remains separate.

## ACTIVE validation and pending FULL handoff

ACTIVE extras:pass67 andpass66. Pass67 supplies exhaustive new local proofs; pass66 protects the materially extended shared PLI2 bridge identity/bounds path and legacy8072 CALL dispatch. Immutable older child campaigns are not chronologically accumulated. [Receipt](validation.json) records actual category/test/worker/wall/summed timings and reruns. Exact historical reconstruction remains94720 bytes; oracle queries0. Packet size is recorded separately and stays below32KiB.

**Pass62 remains the last certified FULL epoch. Pass67 FULL status is PENDING EXTERNAL EXECUTION.** Historical-full has not been executed. List-only selection preserves all92 Pass62 categories, validation-runner-tests, andpass63–67:98 categories. Policy epoch is unchanged. After this semantic commit is pushed, run:

```sh
{command}
```

The runner prints START/DONE/WAIT progress. A separate certification task must import the successful external receipt and update the FULL epoch; this semantic commit does not pre-certify it. [Handoff](full-checkpoint-handoff.json) deliberately records PENDING_UNTIL_COMMIT rather than a fabricated self-referencing SHA.

Driver phases: discovery, proof, contracts, annotations, topology, reports, focused, active validation. Exhaustive journals live under ignored_build. No task-owned /tmp directories. User-owned scripts/view-optimist.sh is untouched.
''')

 text=(REPORT/'README.md').read_text()
 coordinates=['6ED7','6EE5','6ED1','6EE0','6EA5','6EA4','6F18','1FB5','20AC','20AF','20B0','20B3','20B4','42B4','90A5','04E9','04FF','0515','052C','0546','8350','8357','8364','834D','8072','742A','8248','1A29','83B4','8398','AD0C','AD0D','AD1F','AD9F','ADA0','ADA2','ADA4','ADA6','AC00','AC01','ABFF','AAB0','A7F8','A795','8F6E','8F69','3D10','397F','18B3','0400','FFFF']
 for token in coordinates:
  text=re.sub(r'(?<=[a-z])'+token,r' '+token,text)
  text=re.sub(token+r'(?=[a-z])',token+' ',text)
 for a,b in [('bytes**.6','bytes**. 6'),('larger1','larger 1'),('at2149','at 2149'),('writes42 thenB4','writes 42 then B4'),('SP by2','SP by 2'),('MINIMAL1','MINIMAL 1'),('FIZZBUZ4','FIZZBUZ 4'),('PICTURE1','PICTURE 1'),('FACTOR1','FACTOR 1'),('OPTIMIST4','OPTIMIST 4'),('The96','The 96'),('passed 28/29','passed 28/29'),('in 405.467','in 405.467'),('passed15','passed 15'),('in 360.777','in 360.777'),('all11','all 11'),('All11','All 11'),('tuples are2','tuples are 2'),('additionally2','additionally 2'),('word low/high at','word low/high at '),('atADA','at ADA'),('all65536','all 65536'),('indices0/255','indices 0/255'),('bit80','bit 80'),('provisional99','provisional 99'),('reports213','reports 213'),('and113','and 113'),('deltas are-3','deltas are -3'),('are1/3/2','are 1/3/2'),('remains32/32/39','remains 32/32/39'),('MINIMAL7339','MINIMAL 7339'),('FIZZBUZ68ec','FIZZBUZ 68ec'),('PICTUREc02f','PICTURE c02f'),('extras:pass','extras: pass'),('andpass','and pass'),('remains94720','remains 94720'),('queries0','queries 0'),('below32KiB','below 32 KiB'),('all92','all 92'),(':98 categories',': 98 categories'),('ignored_build','ignored _build')]:
  text=text.replace(a,b)
 if (REPORT/'validation.json').exists():
  v=load(REPORT/'validation.json')
  text+='\nACTIVE receipt: '+str(v['category_count'])+' categories, '+str(v['python_test_count'])+' Python tests, 39 Dune test stanzas, '+str(v['safe_parallel_workers'])+' workers; wall '+str(v['wall_seconds'])+' seconds, summed '+str(v['sum_category_seconds'])+' seconds. Initial result and any complete-category reruns remain explicitly recorded in the receipt.\n'
  if not v.get('initial_all_passed',True):
   text+='\nThe initial ACTIVE run passed 28/29 categories in 405.467 seconds (640.861 summed). Pass67 failed before its tests because its setup invoked dune build inside a read-only aggregate worker. The driver was corrected to consume the serially prebuilt executable; no semantic/native implementation changed. The COMPLETE Pass67 category rerun passed 15 tests in 360.777 category seconds (361.594 rerun wall, including mandatory build/project). [Initial receipt](validation-initial.json) and [rerun receipt](validation-pass67-rerun.json) preserve the failure and recovery. The combined wall figure above covers both executions; it does not claim an initially green aggregate.\n'
 (REPORT/'README.md').write_text(text)

def validate():
 dest=OUT/'active-validation';tmp=OUT/'tmp';tmp.mkdir(exist_ok=True)
 r=subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--profile','active','--extra-categories',','.join(EXTRAS),'--images',IMAGES,'--output',str(dest),'--workers','4'],env={**os.environ,'TMPDIR':str(tmp.resolve())})
 receipt=load(dest/'results.json');receipt.update(historical_bytes=94720,dune_stanzas=39,reruns=[],historical_full_executed=False,full_trigger_fired=False);save(REPORT/'validation.json',receipt)
 if r.returncode:raise RuntimeError('ACTIVE failed')

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['discovery','proof','contracts','annotations','topology','reports','focused','validate']);p.add_argument('--images',default=IMAGES);p.add_argument('--focused',action='store_true');args=p.parse_args()
 if args.phase=='proof':prove(args.images,args.focused)
 elif args.phase=='focused':subprocess.run(['python3','tools/annotated-assembly/test_generation_parent_discovery_pass_67.py','--images',args.images,'-v'],env={**os.environ,'RUNES_PASS67_REUSE_PROOF':'1'},check=True)
 else:globals()[args.phase]()
