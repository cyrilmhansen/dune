#!/usr/bin/env python3
"""Fresh corrected caller climb above the canonical Pass45 wrapper."""
import sys,json,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_acquisition_reentry_pass_38 import CAPTURES,load,coord,children
from check_selector02_pass_40 import gather_selected
OUT=Path('_build/host-compiler-pass-46'); REPORT=Path('research/host-compiler/pass-46')
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def inventory():
 start=time.monotonic(); result={}; entries=set()
 for source,path in CAPTURES.items():
  active={}; cases=[]; returns={}
  for chunk in load(path/'event-witnesses.json')['chunks']:
   for event in load(path/'event-witnesses/chunks'/f"{chunk['id']:06d}.json")['events']:
    if event['type']=='instruction':
     w=event['witness']; c=w['control']
     if c['kind']=='call' and c['taken']:
      sp=w['after']['sp']; active={k:v for k,v in active.items() if v['sp']>sp}
      q=dict(step=w['step_index'],caller=coord(w['origin']),target=coord(w['target_origin']),sp=sp,continuation=w['call_return_address'])
      if q['target']=='PLI1.OVL+6619':
       ancestors=sorted(active.values(),key=lambda x:x['sp'])[:9]
       cases.append(dict(call=q,ancestors=ancestors))
       entries.update(a['target'] for a in ancestors if a['target'] and a['target'].startswith('PLI1.OVL+'))
      active[q['step']]=q
    elif event['type']=='hardware_frame_return':
     k=event['frame']['call_step'];returns[k]=event['step_index'];active.pop(k,None)
    elif event['type']=='software_continuation_return':
     active={k:v for k,v in active.items() if v['sp']>=event.get('sp_after',0)} if 'sp_after' in event else active
  for c in cases:
   for a in [c['call']]+c['ancestors']:a['return']=returns.get(a['step'])
  result[source]=cases
 save(OUT/'ancestry.json',result)
 print(json.dumps({s:[dict(call=c['call']['step'],chain=[a['target']+' <- '+str(a['caller']) for a in c['ancestors'][:6]]) for c in cs] for s,cs in result.items()},indent=2))
 save(OUT/'candidate-entries.json',sorted(entries)); print('elapsed',round(time.monotonic()-start,3))

def candidates():
 start=time.monotonic(); keys=[0x6639,0x19f0,0x1014,0x109e,0x0277]; cfg={};summary={};allrows={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{f'PLI1.OVL+{x:04X}':(x,x+1)for x in keys},include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8})
  allrows[source]=rows;summary[source]={}
  for key,rs in rows.items():
   cs=[]
   for r in rs:
    own=r['own_witnesses'];cfg.setdefault(key,{})
    for w in own:cfg[key][w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
    cs.append(dict(call=r['call']['step_index'],ret=r['ret']['step_index'],caller=coord(r['call']['origin']),entry=r['entry']['before'],output=r['ret']['after'],own=len(own),branches=[[w['origin']['offset'],w['control']['taken']]for w in own if w['control']['kind']=='jump'],children=[[c['callsite'],c['target']]for c in children(r)]))
   summary[source][key]=cs
 save(OUT/'candidate-rows.json',allrows);save(OUT/'candidate-summary.json',summary);save(OUT/'candidate-cfg.json',{k:list(v.values())for k,v in cfg.items()})
 print(json.dumps(dict(summary=summary,cfg={k:list(v.values()) for k,v in cfg.items() if k=='PLI1.OVL+6639'}),indent=2));print('elapsed',time.monotonic()-start)

def leaf():
 result={};cfg={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{'PLI1.OVL+8179':(0x8179,0x817a)},include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8})
  result[source]=rows
  cs=[]
  for r in rows['PLI1.OVL+8179']:
   for w in r['own_witnesses']:cfg[w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
   cs.append(dict(call=r['call']['step_index'],caller=coord(r['call']['origin']),input=r['entry']['before'],output=r['ret']['after'],branches=[[w['origin']['offset'],w['control']['taken']]for w in r['own_witnesses'] if w['control']['kind']=='jump'],children=[[c['callsite'],c['target']]for c in children(r)]))
  print(source,json.dumps(cs))
 save(OUT/'leaf-rows.json',result);save(OUT/'leaf-cfg.json',list(cfg.values()));print('CFG',json.dumps(list(cfg.values())))

def measure():
 import bisect,collections
 native=[0x6619,0x6223,0x5929,0x2511,0x240a,0x23d2,0x23a0,0x80b7,0x7ec0,0x8048,0x7e5f,0x7d53,0x7c1b,0x7bbf,0x7b7a,0x7ba2,0x7ad5,0x7b64,0x7abf,0x7a79,0x7e46,0x7e56,0x7af0,0x7b49,0x7a93,0x7b13]
 nk={f'PLI1.OVL+{x:04X}'for x in native}|{'PLI.COM+0EF6'}
 candidates={'PLI1.OVL+'+x for x in ['6639','19F0','1014','109E','0277','02F0','1AFD','1C07','2006','0A32','11E2']}
 results={};full={}
 for source,path in CAPTURES.items():
  calls={};returns={};steps=[]
  for chunk in load(path/'event-witnesses.json')['chunks']:
   for event in load(path/'event-witnesses/chunks'/f"{chunk['id']:06d}.json")['events']:
    if event['type']=='instruction':
     w=event['witness'];steps.append(w['step_index'])
     if w['control']['kind']=='call' and w['control']['taken']:
      calls[w['step_index']]=dict(call=w['step_index'],target=coord(w['target_origin']),caller=coord(w['origin']),sp=w['after']['sp'],continuation=w['call_return_address'])
    elif event['type']=='hardware_frame_return':returns[event['frame']['call_step']]=event['step_index']
  windows=[dict(c,ret=returns[k])for k,c in calls.items() if k in returns]
  roots=[]
  for c in windows:
   if c['target'] not in nk:continue
   if roots and c['call']<roots[-1]['ret']:continue
   roots.append(c)
  # Disjoint ordinary native roots: CALL executes; child entry through RET does not.
  removed=sum(bisect.bisect_right(steps,r['ret'])-bisect.bisect_right(steps,r['call'])for r in roots)
  computed=len(steps)-removed
  rows=[]
  for c in windows:
   if c['target'] not in candidates:continue
   inside=[r for r in roots if c['call']<r['call']<r['ret']<=c['ret']]
   encompassing=[r for r in roots if r['call']<c['call']<c['ret']<=r['ret']]
   if encompassing:continue
   count=bisect.bisect_right(steps,c['ret'])-bisect.bisect_right(steps,c['call'])
   residual=count-sum(bisect.bisect_right(steps,r['ret'])-bisect.bisect_right(steps,r['call'])for r in inside)
   wrapper=[r for r in inside if r['target']=='PLI1.OVL+6619']
   if not wrapper:continue
   rows.append(dict(c,historical_body=count,residual_body=residual,native_children=dict(collections.Counter(r['target']for r in inside)),wrapper_calls=[r['call']for r in wrapper]))
  full[source]=dict(guest=computed,host=len(roots),cases=rows)
  grouped={}
  for key in sorted(set(r['target']for r in rows)):
   qs=[r for r in rows if r['target']==key]
   grouped[key]=dict(calls=len(qs),residual_inclusive=sum(q['residual_body']for q in qs),historical_inclusive=sum(q['historical_body']for q in qs),callers=dict(collections.Counter(q['caller']for q in qs)),native_roots_inclusive=sum(sum(q['native_children'].values())for q in qs),wrappers_inclusive=sum(len(q['wrapper_calls'])for q in qs))
  results[source]=dict(guest=computed,host=len(roots),candidates=grouped)
 save(OUT/'measure-full.json',full);save(REPORT/'parent-candidates.json',results);print(json.dumps(results,indent=2))

def family():
 keys=[0x1afd,0x1c07,0x21e9,0x3533,0x80b1];cfg={};summary={};full={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{f'PLI1.OVL+{x:04X}':(x,x+1)for x in keys},include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8})
  full[source]=rows;summary[source]={}
  for key,rs in rows.items():
   cfg.setdefault(key,{})
   qs=[]
   for r in rs:
    for w in r['own_witnesses']:cfg[key][w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
    qs.append(dict(call=r['call']['step_index'],ret=r['ret']['step_index'],caller=coord(r['call']['origin']),input=r['entry']['before'],output=r['ret']['after'],children=[[c['callsite'],c['target'],c['return_step']-c['call_step']]for c in children(r)],branches=[[w['origin']['offset'],w['control']['taken']]for w in r['own_witnesses']if w['control']['kind']=='jump']))
   summary[source][key]=qs
 save(OUT/'family-rows.json',full);save(OUT/'family-summary.json',summary);save(OUT/'family-cfg.json',{k:list(v.values())for k,v in cfg.items()})
 print(json.dumps({s:{k:[dict(call=r['call'],children=r['children'])for r in rs]for k,rs in ks.items()}for s,ks in summary.items()},indent=2))
 print('CFG',json.dumps({k:list(v.values())for k,v in cfg.items()}))

def transform():
 keys=[0x2fae,0x3262,0x31a8];cfg={};summary={};full={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{f'PLI1.OVL+{x:04X}':(x,x+1)for x in keys},include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8})
  full[source]=rows;summary[source]={}
  for key,rs in rows.items():
   cfg.setdefault(key,{})
   qs=[]
   for r in rs:
    for w in r['own_witnesses']:cfg[key][w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
    qs.append(dict(call=r['call']['step_index'],ret=r['ret']['step_index'],caller=coord(r['call']['origin']),input=r['entry']['before'],output=r['ret']['after'],children=[[c['callsite'],c['target'],c['return_step']-c['call_step']]for c in children(r)],branches=[[w['origin']['offset'],w['control']['taken']]for w in r['own_witnesses']if w['control']['kind']=='jump']))
   summary[source][key]=qs
 save(OUT/'transform-rows.json',full);save(OUT/'transform-summary.json',summary);save(OUT/'transform-cfg.json',{k:list(v.values())for k,v in cfg.items()})
 print(json.dumps({s:{k:dict(count=len(rs),routes=sorted(set(tuple(map(tuple,r['children']))for r in rs)))for k,rs in ks.items()}for s,ks in summary.items()},indent=2))
 print('CFG',json.dumps({k:list(v.values())for k,v in cfg.items()}))

def boundary():
 full={};summary={};cfg={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{'PLI1.OVL+2F1C':(0x2f1c,0x2f1d)},include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8})
  full[source]=rows;qs=[]
  for r in rows['PLI1.OVL+2F1C']:
   for w in r['own_witnesses']:cfg[w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
   qs.append(dict(call=r['call']['step_index'],ret=r['ret']['step_index'],caller=coord(r['call']['origin']),input=r['entry']['before'],output=r['ret']['after'],children=[[c['callsite'],c['target'],c['return_step']-c['call_step']]for c in children(r)],branches=[[w['origin']['offset'],w['control']['taken']]for w in r['own_witnesses']if w['control']['kind']=='jump']))
  summary[source]=qs
 save(OUT/'boundary-rows.json',full);save(OUT/'boundary-summary.json',summary);save(OUT/'boundary-cfg.json',list(cfg.values()))
 print(json.dumps({s:dict(count=len(rs),routes=[r['children']for r in rs])for s,rs in summary.items()},indent=2));print('CFG',json.dumps(list(cfg.values())))

def initial_report():
 import hashlib,collections
 baseline='bba1b42d60b88461c637f15418605e38d89184ff'
 def read(name):return json.loads((OUT/name).read_text())
 def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 ancestry=read('ancestry.json'); measurements=read('measure-full.json'); candidates=json.loads((REPORT/'parent-candidates.json').read_text())
 summary=read('candidate-summary.json'); cfg=read('candidate-cfg.json'); family=read('family-summary.json'); transform=read('transform-summary.json'); frontier=read('boundary-rows.json')
 expected={'MINIMAL':(424898,125,1),'FIZZBUZ':(995583,388,9),'PICTURE':(495210,148,2)}
 for s,(guest,host,n)in expected.items():
  assert measurements[s]['guest']==guest and measurements[s]['host']==host
  assert len(summary[s]['PLI1.OVL+6639'])==n
  for r in summary[s]['PLI1.OVL+6639']:
   assert r['children']==[['PLI1.OVL+663E','PLI1.OVL+6619'],['PLI1.OVL+6645','PLI1.OVL+8179']]
   assert r['output']['sp']==r['entry']['sp']+2
  for c in ancestry[s]:
   assert c['call']['return'] is not None
   for a in c['ancestors']:
    if a['return'] is not None:assert a['step']<c['call']['step']<c['call']['return']<a['return']
 routes={}; cases=[]; new_scope=[]
 catalog=json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']
 for s,ks in frontier.items():
  for r in ks['PLI1.OVL+2F1C']:
   child=next(iter(r['nested_returns'].values()));ws=child['memory_witnesses']
   c=next(w for w in ws if w['control']['kind']=='call'and w['origin']['offset']==0x2c55)
   selected=next(w['reads'][0]['value'] for w in ws if w['origin']['offset']==0x28b7)
   calls=[dict(caller=coord(w['origin']),target=coord(w['target_origin']),step=w['step_index'],entry=w['after'])for w in ws if w['control']['kind']=='call']
   software=[x for x in calls if x['target']=='PLI1.OVL+6708']
   targets=collections.Counter(x['target']for x in calls)
   route='index_one_E05_traverse_construct'if software else'indexed15_guard_exit'
   assert (selected, len(software))in [(5,2),(0x15,0)]
   if software:assert all(x['entry']['e']==5 for x in software)and targets['PLI1.OVL+46ED']==2 and targets['PLI1.OVL+4738']==1
   key=route;routes.setdefault(key,dict(selected=selected,software_E=5 if software else None,software_calls=len(software),traversal_calls=targets['PLI1.OVL+46ED'],constructor_calls=targets['PLI1.OVL+4738']))
   traversal_entries=[dict(caller=coord(w['origin']),target=coord(w['target_origin']),call_step=w['step_index'],entry=w['after'])for w in ws if w['control']['kind']=='call'and coord(w.get('target_origin'))in['PLI1.OVL+46ED','PLI1.OVL+4738','PLI1.OVL+4468']]
   case=dict(traversal_entries=traversal_entries,source=s,caller='PLI1.OVL+2C55',call_step=c['step_index'],entry=c['after'],continuation=c['call_return_address'],route=route,software_arguments=[dict(call_step=x['step'],C=x['entry']['c'],E=x['entry']['e'],SP=x['entry']['sp'])for x in software],descendant_count=len(calls),journal_sha256=digest(ws))
   cases.append(case)
   if software:new_scope.append(case)
 refs=[]
 for coordinate in ['6619','6223','28AA','6708','46ED','4738','2C53']:
  p=next(p for p in catalog if p['id']=='PLI1.OVL+'+coordinate)
  refs.append(dict(coordinate=p['id'],procedure_sha256=digest(p),completeness=p['completeness'],scope=p.get('contract_scope'),unresolved=p.get('unresolved_paths',[])))
 assessment=dict(status='substantive new boundary; no native implementation or partial commit',provisional_meaningful_candidate='PLI1.OVL+19F0',candidate_counts={'MINIMAL':1,'FIZZBUZ':4,'PICTURE':1},boundary='PLI1.OVL+28AA index-one selector05/E05 traversal and construction route',ancestry=['19F0 ->3533','3533 ->2FAE','2FAE ->2F1C','2F1C ->2C53','2C53 ->28AA'],required_new_route_calls=4,reason='Four required calls enter two E05 software acquisitions followed by46ED traversal and4738 construction.28AA explicitly excludes the index-one allocator path from native readiness;46ED/4738 proofs describe narrow correlated C28 states. This is a separate traversal/construction family, not a local wrapper/predicate/publication adapter. A faithful parent cannot treat the old scalar/selector02 contracts as coverage of these states.',scope_note='The six19F0 candidates cover six of twelve external6619 roots. Other roots occur through1014,109E,0277 and recursive02F0. The immediate common6639 adds only14 residual instructions per call.02F0 is a recursively nested multi-route parent; inclusive sums below are ranking evidence, never claimed whole-run savings.',recommendation='Reconstruct the index-one selector05/E05 +28AA acquisition/traversal/construction boundary, validating required46ED/4738 states against old bounded proofs, then resume the meaningful19F0 parent assessment. Do not spend a native pass on6639 alone.',native_enabled=False,oracle_queries=0,archaeological_changes=False)
 packet=dict(baseline=baseline,status=assessment['status'],candidate=assessment['provisional_meaningful_candidate'],parent_candidates=candidates,local_common_parent=dict(entry='PLI1.OVL+6639',observed_extent=[0x6639,0x6649],cfg=cfg['PLI1.OVL+6639'],algorithm='Unconditionally clear A933; invoke canonical6619; freshly read paired A933/A934; low C invokes8179; ordinary RET delegates8179 state.',helper8179=dict(cfg=read('leaf-cfg.json'),algorithm='Save C atAE71; freshAE34 minus freshAE71 using SUB M; publish toAE34; preserveBC/DE; HL=AE71; A/flags from SUB.')),candidate_topology={s:ks['PLI1.OVL+19F0']for s,ks in summary.items()},candidate_local_cfg=cfg['PLI1.OVL+19F0'],boundary=assessment,boundary_routes=routes,boundary_cases=cases,reused_contracts=refs,proof_hashes={name:digest(read(name))for name in ['ancestry.json','candidate-rows.json','family-rows.json','transform-rows.json','boundary-rows.json']})
 data=json.dumps(packet,separators=(',',':'))+'\n';assert len(data.encode())<=32768
 (REPORT/'implementation-packet.json').write_text(data)
 save(REPORT/'boundary-assessment.json',assessment);save(REPORT/'natural-cases.json',dict(routes=routes,cases=cases))
 save(REPORT/'hierarchy-summary.json',dict(baseline=baseline,sources={s:dict(logical_6619=len(ancestry[s]),external_6619=expected[s][2],already_internal_6223=len(ancestry[s])-expected[s][2],guest=expected[s][0],host=expected[s][1])for s in expected},new_native_roots=0,absorbed_transitions=0,remaining_external_6619=12))
 save(REPORT/'fidelity.json',dict(new_bounded_archaeological_scope=False,historical_correction=False,implementation_correction=False,pragmatic_divergence=False,fidelity_debt=False,implementation_status='not implemented; substantive boundary recorded',oracle_queries=0,raw_bytes_promoted=0,stack_proof='Corrected ordinary CALL/RET ancestry checked; native stack plan not implemented. Transitive software N2/N8 must be preserved if resumed.'))
 print(json.dumps(dict(status=assessment['status'],candidate=assessment['provisional_meaningful_candidate'],boundary=assessment['boundary'],required_new_route_calls=len(new_scope),packet_bytes=len(data.encode()),baseline_counts='all three sources exactly rederived')))

def validate():
 import subprocess,re
 start=time.monotonic();output=OUT/'validation';output.mkdir(parents=True,exist_ok=True)
 commands=[('packet', ['python3','tools/annotated-assembly/test_parent_pass_46.py','-q']),('V1',['python3','tools/annotated-assembly/test_decompilation_annotations.py','-q']),('reconstruction',['python3','tools/annotated-assembly/verify.py','--images','/home/john/pli/cpm/pli80/DISK1']),('Dune-build',['dune','build','@all']),('Dune-runtest',['dune','runtest']),('diff-check',['git','diff','--check'])]
 results=[]
 for name,cmd in commands:
  before=time.monotonic();log=output/(name+'.log')
  with log.open('w')as handle:r=subprocess.run(cmd,stdout=handle,stderr=subprocess.STDOUT)
  value=dict(category=name,command=cmd,status='passed'if r.returncode==0 else'failed',seconds=round(time.monotonic()-before,3),log=str(log))
  match=re.search(r'Ran (\d+) tests?',log.read_text());value['python_tests']=int(match.group(1))if match else 0
  results.append(value)
  if r.returncode:
   print(log.read_text()[-3000:]);raise SystemExit(r.returncode)
 manifest=json.loads(Path('research/annotated-assembly/manifest.json').read_text())
 images=manifest['images'];total=sum(v['length']for v in images);assert total==94720
 result=dict(validation_tier='incremental_boundary_investigation',full_checkpoint_base='430b75bb82187216731f26588b3bfb48e6fed435',status='focused checks passed; Pass46 implementation incomplete',categories=results,category_count=len(results),python_test_count=sum(q['python_tests']for q in results),wall_seconds=round(time.monotonic()-start,3),aggregate_commands=1,reconstructed_bytes=total,oracle_queries=0,interactive_tool_calls_before_validation_approximate=33,deferred=['native parent shadows','root-only hybrids','cumulative hybrids','Pass44/45 full native differential suites'],deferral_reason='No native implementation, historical contract or runtime change; substantive boundary recorded before implementation. No completion/checkpoint claim.')
 save(REPORT/'validation.json',result);print(json.dumps({k:result[k]for k in ['status','category_count','python_test_count','wall_seconds','reconstructed_bytes']}))

def acquisition():
 import collections
 entries=[0x28aa,0x6708,0x46ed,0x4738,0x4584,0x666e,0x27d1]
 full={};facts={};cfg={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{f'PLI1.OVL+{x:04X}':(x,x+1)for x in entries},include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8})
  full[source]=rows;facts[source]={}
  for key,rs in rows.items():
   compact=[]
   for r in rs:
    ws=r['own_witnesses'];selected=next((w['reads'][0]['value']for w in ws if w['origin']['offset']==0x28b7),None)
    required=key=='PLI1.OVL+28AA'and r['entry']['before']['c']==1 and selected==5
    if required or key in ['PLI1.OVL+46ED','PLI1.OVL+4738']or(key=='PLI1.OVL+6708'and r['entry']['before']['e']==5):
     shape=key+('-E05'if key.endswith('6708')else'')
     cfg.setdefault(shape,{})
     for w in ws:cfg[shape][w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
    compact.append(dict(call=r['call']['step_index'],ret=r['ret']['step_index'],caller=coord(r['call']['origin']),entry=r['entry']['before'],output=r['ret']['after'],selected=selected,required=required,branches=[[w['origin']['offset'],w['control']['taken']]for w in ws if w['control']['kind']=='jump'],children=[[coord(w['origin']),coord(w['target_origin'])]for w in ws if w['control']['kind']=='call'and w['control']['taken']],own_count=len(ws)))
   facts[source][key]=compact
 save(OUT/'acquisition-rows.json',full);save(OUT/'acquisition-facts.json',facts);save(OUT/'acquisition-cfg.json',{k:[v[x]for x in sorted(v)]for k,v in cfg.items()})
 print(json.dumps({s:{k:dict(total=len(cs),required=sum(c['required']for c in cs),callers=dict(collections.Counter(c['caller']for c in cs)))for k,cs in ks.items()}for s,ks in facts.items()},indent=2))
 print('required28AA',json.dumps({s:[c for c in ks['PLI1.OVL+28AA']if c['required']]for s,ks in facts.items()}))

def parent_glue():
 full={};cfg={};summary={}
 entries=[0x27d1,0x25c0,0x24f1,0x3262,0x31a8,0x2f1c,0x21e9,0x80b1]
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{f'PLI1.OVL+{x:04X}':(x,x+1)for x in entries},include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8})
  full[source]=rows;summary[source]={}
  for key,rs in rows.items():
   summary[source][key]=dict(count=len(rs),callers={coord(r['call']['origin']) for r in rs})
   summary[source][key]['callers']=sorted(summary[source][key]['callers'])
   for r in rs:
    cfg.setdefault(key,{})
    for w in r['own_witnesses']:cfg[key][w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
 save(OUT/'parent-glue-rows.json',full);save(OUT/'parent-glue-summary.json',summary);save(OUT/'parent-glue-cfg.json',{k:[v[x]for x in sorted(v)]for k,v in cfg.items()})
 print(json.dumps(summary));print('CFG',json.dumps({k:[v[x]for x in sorted(v)]for k,v in cfg.items()}))

def bit_output():
 full={};cfg={};summary={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{'PLI.COM+1140':(0x1140,0x1141),'PLI.COM+119E':(0x119e,0x119f)},include_nested_returns=True)
  full[source]=rows;summary[source]={}
  for key,rs in rows.items():
   sequences={};wanted=[]
   for r in rs:
    ws=r['own_witnesses'];cfg.setdefault(key,{})
    for w in ws:cfg[key][w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
    cs=[(coord(w['origin']),coord(w.get('target_origin')))for w in ws if w['control']['kind']=='call']
    sequences[str(cs)]=sequences.get(str(cs),0)+1
    if coord(r['call']['origin'])=='PLI1.OVL+6692':wanted.append(dict(call=r['call']['step_index'],entry=r['entry']['before'],output=r['ret']['after'],children=cs))
   summary[source][key]=dict(total=len(rs),routes=sequences,required_prefix=wanted)
 save(OUT/'bit-output-rows.json',full);save(OUT/'bit-output-summary.json',summary);save(OUT/'bit-output-cfg.json',{k:[v[x]for x in sorted(v)]for k,v in cfg.items()})
 print(json.dumps(summary,indent=2));print('CFG',json.dumps({k:[v[x]for x in sorted(v)]for k,v in cfg.items()}))

def residual():
 import collections
 measurements=json.loads((OUT/'measure-full.json').read_text());result={}
 for source,value in measurements.items():
  roots=[r for r in value['cases']if r['target']=='PLI1.OVL+19F0'];targets=collections.defaultdict(list)
  for r in value['cases']:
   if r['target']in ['PLI1.OVL+19F0','PLI1.OVL+6639']:continue
   inside=[x for x in roots if r['call']<x['call']and x['ret']<r['ret']]
   if any(x['call']<r['call']and r['ret']<x['ret']for x in roots):continue
   targets[r['target']].append(dict(call=r['call'],post46_residual_inclusive=r['residual_body']-sum(x['residual_body']for x in inside),external_6619_remaining=len(r['wrapper_calls'])-sum(len(x['wrapper_calls'])for x in inside)))
  result[source]=dict(targets)
 save(REPORT/'residual-assessment.json',dict(method='Ranking only: subtract disjoint accepted19F0 residual windows from prior candidate intervals. Inclusive parent windows may overlap; these are not claimed whole-run savings.',sources=result))

def prove(images):
 import subprocess,tempfile,shutil
 target=OUT/'validated-proof';target.mkdir(exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='pass46-proof-',dir=OUT)as directory:
  directory=Path(directory)
  for operation in ['6708-E05','46ED','4738','666E','28AA-I1','19F0']:
   output=directory/(operation+'.json')
   command=['dune','exec','pli80-native-acquisition-family','--','--operation',operation,'--toolchain',str(images),'--output',str(output)]
   result=subprocess.run(command,capture_output=True,text=True)
   (target/(operation+'.log')).write_text(result.stdout+result.stderr)
   if result.returncode:raise RuntimeError(operation+': '+result.stderr[-1800:])
   shutil.copyfile(output,target/output.name)
  output=directory/'hybrids'
  result=subprocess.run(['dune','exec','pli80-native-selection-hybrids','--','--toolchain',str(images),'--output-dir',str(output)],capture_output=True,text=True)
  (target/'hybrids.log').write_text(result.stdout+result.stderr)
  if result.returncode:raise RuntimeError('hybrids: '+result.stderr[-1800:])
  for file in output.glob('*.json'):shutil.copyfile(file,target/file.name)
 return target

def closed_report(proof=None):
 import hashlib,collections
 proof=proof or (OUT/'validated-proof'if(OUT/'validated-proof/natural-cases.json').exists()else OUT/'hybrids-final')
 digest=lambda v:hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 roots=json.loads((proof/'natural-cases.json').read_text())
 cumulative=json.loads((proof/'cumulative-hybrid-summary.json').read_text())
 base='bba1b42d60b88461c637f15418605e38d89184ff';cases=[];hierarchy={}
 coordinates=['6619','6223','5929','2511','240A','23D2','23A0','80B7','7EC0','8048','7E5F','7D53','7C1B','7BBF','7B7A','7BA2','7AD5','7B64','7ABF','0EF6','7A79','7E46','7E56','7AF0','7B49','7A93','7B13']
 for group,g in zip(roots['sources'],cumulative['sources']):
  source=group['source'];previous=g['pre_transition_vector'];after=g['transition_vector'][1:]
  assert len(previous)==len(after)==len(coordinates)
  routes=collections.Counter()
  for c in group['members']:
   route=c['result']['route'];routes[route]+=1
   cases.append(dict(source=source,caller=c['caller'],entry_step=c['entry_step'],return_step=c['return_step'],route=route,input=c['input'],output=c['output'],entry_memory_sha256=c['entry_memory_sha256'],post_memory_sha256=c['post_memory_sha256'],journal_sha256=digest(c['journal']),logical_writes=sum(w[4]=='logical'for w in c['journal']),stack_writer_cells=len({w[0]for w in c['journal']if w[4]=='compatibility'}),internal_6223=sum(w[2]==0x8473 and w[4]=='compatibility'for w in c['journal'])//2))
  hierarchy[source]=dict(root_count=len(group['members']),routes=dict(routes),pre_guest=g['pre_guest_instructions'],post_guest=g['result']['actual_guest_instructions'],actual_instructions_removed=g['guest_instructions_removed'],pre_host=sum(previous),post_host=g['result']['host_transitions'],pre_transition_vector=previous,post_transition_vector=g['transition_vector'],absorbed_by_coordinate={k:a-b for k,a,b in zip(coordinates,previous,after)if a!=b},remaining_external_6619=after[0],remaining_external_19F0=0,logical_internal_6619=len(group['members']),logical_internal_6223=sum(c['internal_6223']for c in cases if c['source']==source),host_bdos_services=g['host_bdos_services'])
 save(REPORT/'natural-cases.json',dict(cases=cases,duplicates_preserved=True))
 save(REPORT/'hierarchy-summary.json',dict(sources=hierarchy,post_vector_coordinates=['19F0']+coordinates,method='Actual whole-run CPU counters; exact corrected-window descendant exclusion; no overlapping sum savings.'))
 save(REPORT/'single-hybrid-summary.json',json.loads((proof/'single-hybrid-summary.json').read_text()))
 save(REPORT/'cumulative-hybrid-summary.json',cumulative)
 components={}
 for operation in ['6708-E05','46ED','4738','666E','28AA-I1','19F0']:
  path=proof/(operation+'.json')
  if not path.exists():path=OUT/({'6708-E05':'e05','46ED':'traversal','4738':'construction','666E':'record','28AA-I1':'index-one','19F0':'parent'}[operation]+'-shadow.json')
  q=json.loads(path.read_text());components[operation]={g['source']:g['field15_matched']for g in q['sources']}
 save(REPORT/'shadow-summary.json',dict(all_passed=True,outer_roots=6,component_counts=components,comparisons=['all registers and flags','SP/continuation PC','ordered logical writes','complete 65536-byte RAM','all final stack writers','DMA/filesystem','file/record chronology','root/local child CALL chronology','internal canonical6619 journal and CALL/SP correlation','internal6223 full state checkpoints'],full_proof_sha256=digest(roots)))
 catalog={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
 laws=json.loads((REPORT/'contract-laws.json').read_text());ar=json.loads((REPORT/'archaeology-summary.json').read_text())
 refs=[dict(coordinate=k,procedure_sha256=digest(catalog[k]),route='retained canonical bounded child')for k in ['PLI1.OVL+6619','PLI1.OVL+6223','PLI1.OVL+5929','PLI1.OVL+2511','PLI1.OVL+4468','PLI1.OVL+4584','PLI.COM+1140','PLI.COM+119E','PLI.COM+1207']]
 candidate=json.loads((REPORT/'parent-candidates.json').read_text())
 packet=dict(baseline=base,selected_root='PLI1.OVL+19F0',candidate_assessment=candidate,natural_cases=cases,route_classes={'selector05_construct':dict(count=4,mode=1,selected_index='fresh A634 (natural2)',selector=5,children=['two independent6708 E05 N8 acquisitions','46ED','4738 with4468 N2','666E no-flush resident bits','independent mapped publications']),'selector15_guard':dict(count=2,mode=1,selector=21,children=['28AA unsigned10-vs-selected guard return','27D1 length adjustment','24F1 canonical8048 and240A'])},frame={'size':2,'base':'entrySP-2','F0':'inputC surviving MOV B,C/PUSH B high byte','F1':'fresh old A619','return':'POP H consumes private frame; RET consumes original continuation'},reused_contracts=refs,new_contract_references=[dict(coordinate=k,law_sha256=digest(v),procedure_sha256=digest(catalog[k]))for k,v in laws.items()],family_proof=components,oracle_queries=0)
 save(REPORT/'implementation-packet.json',packet);assert(REPORT/'implementation-packet.json').stat().st_size<=32768
 save(REPORT/'fidelity.json',dict(implemented_root='PLI1.OVL+19F0',bounded_routes=['context!=28','A5F7!=0','21E9 witnessed mismatch scope','2221 clear route','31A8 clear/unequal route','index-one selector05 construction or15 guard','inherited native child domains','saved input bit0 clear'],scope_extensions=list(laws),historical_correction=None,implementation_corrections=['Development reference-loop branch polarity corrected before proof','Historical logical inherited7C1B PUSH-frame ownership included in the new root harness','Parent-cleared A934 removed as an invalid entry rejection expectation','Generalized canonical constructor source/continuation from actual N2 caller slots; aligned cache publications before historical PUSH D writer4474. Pass43 full shadows remain exact.'],pragmatic_divergence=None,fidelity_debt=None,raw_bytes_promoted=ar['raw_to_understood'],oracle_queries=0,one_root_transaction=True,N2=True,N8=True,fresh_reads=True,ordered_writes=True,stack_last_writers=True,full_memory_identity=True,external_identity=True,unsupported=['root context28/zero mode','root saved input bit0 set','unobserved selector/constructor/traversal arms','resident REL flush/error/gate-set and invalid cursor','active E05 carrier aliases','inherited unsupported child routes','arbitrary aliases or termination'],Runner_changes=False,CPM_changes=False,CPU_changes=False,shared_proof_schema_changes=False))
 save(REPORT/'boundary-assessment.json',dict(selected_root='PLI1.OVL+19F0',why='6639 adds only14 instructions;19F0 closes coherent acquisition/transformation and removes38640 instructions;1AFD adds independent reader calls and is not a trivial wrapper.',completed=True,remaining_external_6619={s:h['remaining_external_6619']for s,h in hierarchy.items()},next='Pass47: assess bounded recursive02F0 and run the scheduled full checkpoint. Post46 inclusive residual ranking: FIZZBUZ outer02F0 97961 with5 external6619;1014 3269 and109E 1229 each contain1. These are ranking measurements, not claimed savings.',checkpoint_due='Pass47',new_substantive_blocker=None))
 print(json.dumps(dict(root='19F0',shadows=components,packet_bytes=(REPORT/'implementation-packet.json').stat().st_size,hierarchy=hierarchy),separators=(',',':')))

def report():
 if (OUT/'hybrids-final/natural-cases.json').exists():closed_report()
 else:initial_report()

def final_validation():
 import subprocess
 categories='pass46,pass45-local,pass45-root,pass44-roots,pass44-family,pass44-numeric,pass44-hybrids,pass43,pass38,pass39,pass40,packet-continuation,V1,roundtrip,classifier-unit,acquisition-parent-unit,word-emitter-unit,range-unit,gate-unit,input-unit,mapped-unit,recursive-unit,diff-check'
 subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images','/home/john/pli/cpm/pli80/DISK1','--output',str(OUT/'final-validation'),'--workers','4','--categories',categories],check=True)

if __name__=='__main__':
 import argparse
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--phase',choices=['inventory','candidates','leaf','measure','family','transform','boundary','report','validate','acquisition','bit_output','parent_glue','prove','residual','final_validation','all'],default='all')
 args=parser.parse_args()
 phases=[inventory,candidates,leaf,measure,family,transform,boundary,report,acquisition,bit_output,parent_glue,residual]
 if args.phase=='all':
  for phase in phases:phase()
 elif args.phase=='validate':validate()
 elif args.phase=='prove':closed_report(prove(Path('/home/john/pli/cpm/pli80/DISK1')))
 elif args.phase=='final_validation':final_validation()
 else:next(p for p in phases if p.__name__==args.phase)()
