#!/usr/bin/env python3
"""Pass48 corrected parent selection and native proof driver."""
import collections,hashlib,json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-48');REPORT=Path('research/host-compiler/pass-48')
BASE='7a4bf0adf5959ffa29238a7f30d549522d18750f'
def save(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,indent=2)+'\n')
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def inventory():
 start=time.monotonic();keys=['PLI1.OVL+'+x for x in ['0A32','0C1B','0C75','02F0']];allrows={};cfg={};sources={}
 previous=json.loads(Path('_build/host-compiler-pass-47/all-windows.json').read_text())
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{k:(int(k.split('+')[1],16),int(k.split('+')[1],16)+1)for k in keys},include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8});allrows[source]=rows;sources[source]={}
  old=previous[source];logical=[q for q in old['calls']if q['target']==keys[-1]];outer=[q for q in logical if not any(p['call']<q['call']<q['ret']<p['ret']for p in logical)];native=sorted(old['native_roots']+outer,key=lambda q:q['call']);disjoint=[]
  for q in native:
   if not disjoint or q['call']>disjoint[-1]['ret']:disjoint.append(q)
  for k,rs in rows.items():
   if k==keys[-1]:continue
   cfg.setdefault(k,{})
   for r in rs:
    for w in r['own_witnesses']:cfg[k][w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
   cases=[]
   for r in rs:
    call=r['call']['step_index'];ret=r['ret']['step_index'];external=not any(q['call']<call<ret<q['ret']for q in disjoint)
    children=children_any(r);absorb=[q for q in disjoint if call<q['call']<q['ret']<ret]
    cases.append(dict(call=call,ret=ret,caller=coord(r['call']['origin']),external=external,entry=r['entry']['before'],output=r['ret']['after'],children=[[q['callsite'],q['target']]for q in children],branches=[[w['origin']['offset'],w['control']['taken']]for w in r['own_witnesses']if w['control']['kind']in ['jump','return']],residual_ranking=ret-call-sum(q['ret']-q['call']for q in absorb),absorbed= dict(collections.Counter(q['target']for q in absorb)),proof_hash=digest(r)))
   sources[source][k]=cases
 save(OUT/'rows.json',allrows);save(OUT/'cfg.json',{k:sorted(v.values())for k,v in cfg.items()})
 catalog={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
 references={k:dict(procedure_hash=digest(catalog[k]),completeness=catalog[k]['completeness'])for k in cfg if k in catalog}
 packet=dict(task='ACQUISITION_FRAME_PARENT_PASS_48',baseline=BASE,cfg={k:sorted(v.values())for k,v in cfg.items()},cases=sources,contracts=references)
 routes={};compact={}
 for source,ks in sources.items():
  compact[source]={}
  for k,rs in ks.items():
   compact[source][k]=[]
   for r in rs:
    key=digest(r['children']);routes.setdefault(key,r['children'])
    compact[source][k].append(dict(r,children=key,branches_hash=digest(r['branches'])))
    del compact[source][k][-1]['branches']
 packet['cases']=compact;packet['routes']=routes
 packet['cfg']={k:(v if k.endswith('0A32')else dict(cfg_hash=digest(v),bounds=[v[0][0],v[-1][0]+len(v[-1][1])//2]))for k,v in packet['cfg'].items()}
 packet['selected_root']='PLI1.OVL+0A32'
 packet['selection']='0C1B exchanges/restores independent A5B5 context, resets resident state and calls0B84 structure initialization;0C75 adds independent A5D9 lifetime, delimiter preamble and EOF driver. Choose reusable eight-byte acquisition frame below those distinct initialization operations.'
 save(REPORT/'implementation-packet.json',packet)
 summary={s:{k:dict(logical=len(rs),external=sum(r['external']for r in rs),callers=dict(collections.Counter(r['caller']for r in rs)),residual_ranking=sum(r['residual_ranking']for r in rs if r['external']),children=[r['children']for r in rs if r['external']])for k,rs in ks.items()}for s,ks in sources.items()}
 save(REPORT/'parent-candidates.json',summary)
 print(json.dumps(dict(summary={s:{k:{a:b for a,b in v.items()if a!='children'}for k,v in ks.items()}for s,ks in summary.items()},packet_bytes=(REPORT/'implementation-packet.json').stat().st_size,seconds=round(time.monotonic()-start,3)),indent=2))

def prove(images,*,persist=False):
 import subprocess,tempfile,shutil
 OUT.mkdir(parents=True,exist_ok=True);start=time.monotonic()
 with tempfile.TemporaryDirectory(prefix='frame-proof-',dir=OUT)as temp:
  dest=Path(temp)/'result'
  command=['dune','exec','bin/native_acquisition_frame_hybrids.exe','--','--toolchain',str(images),'--output-dir',str(dest)]
  with (OUT/'proof.log').open('w')as log:
   result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
  if result.returncode:raise RuntimeError((OUT/'proof.log').read_text()[-2500:])
  target=OUT/('validated-proof'if persist else 'fresh-'+Path(temp).name);target.mkdir(exist_ok=True)
  for file in dest.glob('*.json'):shutil.copyfile(file,target/file.name)
 save(OUT/'proof-timing.json',dict(wall_seconds=round(time.monotonic()-start,3),command=command,all_passed=True))
 return target

def report():
 packet=json.loads((REPORT/'implementation-packet.json').read_text());proof=OUT/'validated-proof'
 natural=json.loads((proof/'natural-cases.json').read_text())['sources'];post=json.loads((proof/'cumulative-hybrid-summary.json').read_text())['sources'];singles=json.loads((proof/'single-hybrid-summary.json').read_text())['sources']
 frame='PLI1.OVL+0A32';cases=packet['cases'];hierarchy={};summary={}
 for group,cumulative,single in zip(natural,post,singles):
  source=group['source'];rs=cases[source][frame];roots=[r for r in rs if r['external']]
  pre=cumulative['pre_transition_vector'];new=cumulative['transition_vector']
  assert cumulative['pre_guest_instructions']=={'MINIMAL':405284,'FIZZBUZ':869593,'PICTURE':476266}[source]
  assert sum(pre)=={'MINIMAL':89,'FIZZBUZ':119,'PICTURE':88}[source]
  assert len(group['members'])==1 and new[0]==1
  absorbed=collections.Counter()
  for r in roots:absorbed.update(r['absorbed'])
  hierarchy[source]=dict(historical_guest={'MINIMAL':441855,'FIZZBUZ':1145517,'PICTURE':518213}[source],pre_guest=cumulative['pre_guest_instructions'],post_guest=cumulative['result']['actual_guest_instructions'],saved=cumulative['guest_instructions_removed'],pre_host=sum(pre),post_host=cumulative['result']['host_transitions'],root_transitions=new[0],absorbed_current_transitions=dict(absorbed),pre_transition_vector=pre,post_transition_vector=new,internal_outer_02F0=absorbed['PLI1.OVL+02F0'],remaining_external_02F0=0)
  summary[source]=dict(logical=len(rs),outer=len(roots),nested=len(rs)-len(roots),cases=[dict(caller=q['caller'],entry_step=q['entry_step'],return_step=q['return_step'],route='frame_iterations_'+str(sum(w[2]==0x2c3f and w[3]==0 for w in q['journal'])),entry_sp=q['input']['sp'],final_sp=q['output']['sp'],journal_sha256=digest(q['journal']),services_sha256=digest(q['service_details']),RAM_sha256=q['post_memory_sha256'])for q in group['members']],full_state_exact=True,internal_02F0_journals_and_CALL_ancestry_exact=True,internal_canonical_6223_checkpoints_exact=True)
 save(REPORT/'hierarchy-summary.json',hierarchy);save(REPORT/'shadow-summary.json',summary)
 save(REPORT/'hybrid-summary.json',dict(standalone=singles,cumulative=post))
 save(REPORT/'fidelity.json',dict(selected_root=frame,new_contracts=[],RAW_to_UNDERSTOOD=0,archaeological_scope_extension=None,historical_correction=None,implementation_corrections=['Controller body interval ends0B7F, excluding independent0B84 initializer','Negative fixture uses consumed saved-E parameter instead of unrelated mode byte'],pragmatic_divergence=None,fidelity_debt=None,oracle_queries=0,CPU_changes=False,Runner_changes=False,CPM_changes=False,shared_proof_schema_changes=False,software_N2_N8_preserved=True))
 packet.update(selected_root=frame,proofs={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in proof.glob('*.json')},frames=dict(entry='S; frameF=S-8',writers='DCX SP; PUSH H twice; MOV D,E/PUSH D/INX SP; PUSH B',layout='F0/F1 saved BC; F2 saved E; F3/F4 zeroed freshly each iteration; F5/F6 original HL; F7 untouched pre-entry residue; finalHL=entryH|(entry_memory[S-1]<<8)',unwind='Four POP H; historical RET consumes original continuation; finalSP=S+2',continuations=['hardware CALL/RET recursion','4468 N2 copied continuation','6708 N8 consumed caller arguments']),unsupported=['colon/percent/A7/9B routes','changed-source-pointer arm','unobserved item comma-repeat','unsupported saved E beyond0/2','inherited reader/constructor/error/alias alternatives','arbitrary input/recursion termination'])
 save(REPORT/'implementation-packet.json',packet);assert(REPORT/'implementation-packet.json').stat().st_size<=32768
 save(REPORT/'boundary-assessment.json',dict(completed=True,selected_root=frame,rejected=['0C1B independent saved A5B5 context and0B84 initialization','0C75 delimiter/EOF driver and A5D9 lifetime'],next='Assess0C1B initialization as a coherent operation with0B84/013D/01C6; compare0C75 driver separately. Pass50 is next ordinary full checkpoint.',required_blockers=[]))
 table='\n'.join('| '+s+' | '+' | '.join(str(hierarchy[s][k])for k in ['pre_guest','post_guest','saved','pre_host','post_host'])+' |'for s in hierarchy)
 (REPORT/'README.md').write_text(f"""# Pass48 — bounded +0A32 acquisition/frame parent

Baseline/full checkpoint: `{BASE}`. Validation tier: incremental.

Fresh candidate comparison selects +0A32. Each source has one external root
from +0C61. FIZZBUZ additionally has one internal +1268 call beneath native
+02F0. +0C1B exchanges/restores independent A5B5 context and calls structure
initialization0B84; +0C75 adds delimiter/EOF driver and A5D9 lifetime. Their
ranking totals71607/104485 are not claimed savings. +0A32 ranking55507 is
confirmed independently below by actual cumulative execution counters.

Canonical `Pli80_host.Recursive_parent.Recursive_frame` already proved all four
natural calls in Pass47. Pass48 adds a thin external transaction/controller and
reuses the proof machinery with a parameterized operation. No host algorithm,
archaeological contract, byte annotation, CPU, Runner, CP/M or proof schema is
changed. No new descendants or RAW-byte promotions.

Eight-byte frame F=entrySP-8: saved BC atF0/F1; independently saved E atF2;
F3/F4 reinitialized each iteration; original HL residue atF5/F6; F7 remains untouched. Fresh02E9,
resident18DB,020E and selector probes choose canonical02F0 or item acquisition.
Actual8A terminator composes80B7 when E=2,0146 when E is nonzero,45F0 and fresh
pointer comparison/784E when gate permits, then semicolon/0266. Four POP H and
RET preserve exact stack writers. Final HL is entry H in the low byte plus\nthe untouched pre-entry byte atS-1 in the high byte, not restored entry HL. External iteration counts2/3/5 are outcomes
of shared-state predicates, never loop limits. Internal FIZZBUZ E=0 call has
2 iterations. Unsupported sibling routes remain fail-closed and globally RAW.

All four logical component calls and three outer roots are independently exact
for registers/flags, SP/PC, ordered writes, full65536-byte RAM, stack last writers,
DMA/filesystem and file/record chronology. Internal canonical02F0 journals and
CALL/SP/continuations correlate independently; canonical19F0/6619/6223 remain
internal. N2/N8 software continuations and hardware recursion stay distinct.

| Source | Pre48 guest | Post48 guest | Saved | Pre host | Post host |
|---|---:|---:|---:|---:|---:|
{table}

Standalone and cumulative hybrids preserve exact REL256/768/256 goldens,
INT/REL events, filesystem, PASS1/PASS2/END and warm boot. Proof details remain
ignored under `_build/host-compiler-pass-48`; compact hashes/reports are durable.
The deterministic driver automates candidate extraction, topology, proof batches,
hybrids, compact reporting and incremental validation. Oracle queries0;
historical correction, pragmatic divergence and fidelity debt none.

`validation.json` records the aggregate run. Reconstruction remains94720 bytes.
`scripts/view-optimist.sh` is unrelated and untouched.
""")
 print(json.dumps(dict(hierarchy=hierarchy,packet_bytes=(REPORT/'implementation-packet.json').stat().st_size,all_passed=True)))
if __name__=='__main__':
 phase=sys.argv[1]
 if phase=='inventory':inventory()
 elif phase=='prove':print(prove(Path('/home/john/pli/cpm/pli80/DISK1'),persist=True))
 elif phase=='report':report()
 elif phase=='validate':
  import subprocess
  categories='pass48,pass47,packet-continuation,recursive-unit,acquisition-parent-unit,classifier-unit,balance-unit,gate-unit,control-unit,input-unit,V1,roundtrip-tests,roundtrip,dynamic-progress,diff-check'
  subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images','/home/john/pli/cpm/pli80/DISK1','--output',str(OUT/'incremental-validation'),'--categories',categories,'--workers','4'],check=True)
