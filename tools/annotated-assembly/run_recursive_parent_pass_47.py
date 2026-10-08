#!/usr/bin/env python3
"""Corrected natural topology and causal packet for the recursive 02F0 parent."""
import collections, hashlib, json, sys, time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_acquisition_reentry_pass_38 import CAPTURES,load,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-47'); REPORT=Path('research/host-compiler/pass-47')
def save(p,v): p.write_text(json.dumps(v,indent=2)+'\n')
def digest(v): return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def extract():
 start=time.monotonic();OUT.mkdir(parents=True,exist_ok=True);REPORT.mkdir(parents=True,exist_ok=True)
 keys=['PLI1.OVL+02F0','PLI1.OVL+80CA','PLI1.OVL+02E9','PLI.COM+18DB','PLI1.OVL+2006','PLI1.OVL+01D8']
 full={};cfg={};cases={};topology={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{k:(int(k.split('+')[1],16),int(k.split('+')[1],16)+1)for k in keys},include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8})
  full[source]=rows;cases[source]={}
  roots=sorted(rows[keys[0]],key=lambda r:r['call']['step_index']);depths={}
  for r in roots:
   a=[q for q in roots if q['call']['step_index']<r['call']['step_index']<r['ret']['step_index']<q['ret']['step_index']]
   parent=max(a,key=lambda q:q['call']['step_index'])if a else None
   depths[r['call']['step_index']]=len(a)+1
   r['recursive_parent_call']=parent['call']['step_index']if parent else None
  topology[source]=dict(logical=len(roots),outer=sum(r['recursive_parent_call']is None for r in roots),nested=sum(r['recursive_parent_call']is not None for r in roots),maximum_depth=max(depths.values(),default=0))
  for k,rs in rows.items():
   cs=[];cfg.setdefault(k,{})
   for r in sorted(rs,key=lambda r:r['call']['step_index']):
    own=r['own_witnesses']
    for w in own: cfg[k][w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
    cs.append(dict(call=r['call']['step_index'],ret=r['ret']['step_index'],caller=coord(r['call']['origin']),entry=r['entry']['before'],output=r['ret']['after'],parent=r.get('recursive_parent_call'),branches=[[w['origin']['offset'],w['control']['taken']]for w in own if w['control']['kind']in ['jump','return']],children=[[c['callsite'],c['target']]for c in children_any(r)],proof_hash=digest(r)))
   cases[source][k]=cs
 catalog=json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']
 contracts={}
 for p in catalog:
  k=p['id']
  if k in cfg: contracts[k]=dict(hash=digest(p),record=p)
 save(OUT/'rows.json',full);save(OUT/'cfg.json',{k:sorted(v.values())for k,v in cfg.items()});save(OUT/'cases.json',cases)
 save(REPORT/'natural-cases.json',dict(canonical_cases='implementation-packet.json#/cases',case_count=sum(len(ks[keys[0]])for ks in cases.values()),case_proof_hashes=[q['proof_hash']for ks in cases.values()for q in ks[keys[0]]]))
 packet=dict(task='RECURSIVE_PARENT_02F0_PASS_47',baseline='2fc80f0b09af0c07e41ca37ed79e6846e1f600d2',topology=topology,cfg={k:sorted(v.values())for k,v in cfg.items()},cases=cases)
 save(OUT/'contracts.json',contracts);save(REPORT/'implementation-packet.json',packet)
 print(json.dumps(dict(topology=topology,local_cfg=packet['cfg'][keys[0]],children={s:[dict(call=r['call'],parent=r['parent'],children=r['children'])for r in ks[keys[0]]]for s,ks in cases.items()},component_counts={s:{k:len(rs)for k,rs in ks.items()}for s,ks in cases.items()},packet_bytes=(REPORT/'implementation-packet.json').stat().st_size,elapsed=round(time.monotonic()-start,3)),indent=2))
def dependencies(parser=False):
 start=time.monotonic(); full={};summary={};cfg={}
 keys=['PLI.COM+1688','PLI.COM+1A33','PLI1.OVL+0261','PLI1.OVL+11E2','PLI1.OVL+13AD','PLI1.OVL+02CA']
 if parser:keys=['PLI1.OVL+0E00','PLI1.OVL+0A32','PLI1.OVL+026B','PLI1.OVL+029C']
 if parser=='boundary':keys=['PLI1.OVL+1014','PLI1.OVL+109E','PLI1.OVL+1187','PLI1.OVL+0A0B']
 if parser=='reader':keys=['PLI1.OVL+1C07','PLI1.OVL+1AFD']
 if parser=='parser-cleanup':keys=['PLI1.OVL+'+x for x in ['4929','41AF','41A6','43AF','438F','0146','0187','086E']]
 if parser=='parser-acquisition':keys=['PLI1.OVL+'+x for x in ['28AA','6708','2C59']]
 if parser=='parser-leaves':keys=['PLI1.OVL+'+x for x in ['2DCA','335B','810B','80EF','3262','31FB','2C53','4986','086E','45F0','8179','0187','8273']]
 if parser=='parser-glue':keys=['PLI1.OVL+'+x for x in ['342F','61B6','0277','0266','0FC9','33AD','0146','8152','2DC3','08D9']]
 if parser=='lookahead':keys=['PLI.COM+'+x for x in ['1688','1843','18A2','18BC','18C5','18DB']]
 if parser=='reader-record':keys=['PLI.COM+'+x for x in ['070C','05B2','0318','02EE']]
 if parser=='reader-fetch':keys=['PLI.COM+0AA9']
 if parser=='reader-refill-children':keys=['PLI.COM+'+x for x in ['0CD9','0B86','0AF5','09CB','0E1F']]
 if parser=='reader-refill':keys=['PLI.COM+0D40']
 if parser=='reader-readflow':keys=['PLI.COM+12AE']
 if parser=='reader-attribute':keys=['PLI1.OVL+256C']
 if parser=='reader-resident':keys=['PLI.COM+1376']
 if parser=='reader-adapters':keys=['PLI1.OVL+'+x for x in ['0D6E','47F7','14C8','14D4','8386','834F','8380','8167','7ED7','13AD','81F1']]
 if parser=='reader-descendants':keys=['PLI1.OVL+'+x for x in ['8268','8167','80B1','14D4','0D94','1BA8','14C8','7ED7','1BE8','13E3','4A26','58BB','590E','33D6']]
 if parser=='reader-family':keys=['PLI1.OVL+1D13','PLI1.OVL+1BBF','PLI1.OVL+140D','PLI1.OVL+1421','PLI1.OVL+14E4','PLI1.OVL+156D']
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{k:(int(k.split('+')[1],16),int(k.split('+')[1],16)+1)for k in keys},include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8})
  full[source]=rows;summary[source]={}
  for k,rs in rows.items():
   cfg.setdefault(k,{})
   for r in rs:
    for w in r['own_witnesses']:cfg[k][w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
   summary[source][k]=dict(count=len(rs),callers=dict(collections.Counter(coord(r['call']['origin'])for r in rs)),routes=[dict(children=list(seq),count=n)for seq,n in collections.Counter(tuple((c['callsite'],c['target'])for c in children_any(r))for r in rs).items()],inclusive=sum(r['ret']['step_index']-r['call']['step_index']for r in rs),own=sum(len(r['own_witnesses'])for r in rs))
 prefix=parser if isinstance(parser,str)else('parser'if parser else'dependency')
 save(OUT/(prefix+'-rows.json'),full);save(OUT/(prefix+'-cfg.json'),{k:sorted(v.values())for k,v in cfg.items()});save(OUT/(prefix+'-summary.json'),summary)
 print(json.dumps(dict(summary=summary,cfg_extents={k:dict(instructions=len(v),minimum=min(v,default=0),maximum=max(v,default=0))for k,v in cfg.items()},elapsed=round(time.monotonic()-start,3)),indent=2))
def measure():
 import bisect
 native={f'PLI1.OVL+{x:04X}'for x in [0x19f0,0x6619,0x6223,0x5929,0x2511,0x240a,0x23d2,0x23a0,0x80b7,0x7ec0,0x8048,0x7e5f,0x7d53,0x7c1b,0x7bbf,0x7b7a,0x7ba2,0x7ad5,0x7b64,0x7abf,0x7a79,0x7e46,0x7e56,0x7af0,0x7b49,0x7a93,0x7b13]}|{'PLI.COM+0EF6'}
 result={};full={}
 for source,path in CAPTURES.items():
  calls={};returns={};steps=[]
  for chunk in load(path/'event-witnesses.json')['chunks']:
   for event in load(path/'event-witnesses/chunks'/f"{chunk['id']:06d}.json")['events']:
    if event['type']=='instruction':
     w=event['witness'];steps.append(w['step_index'])
     if w['control']['kind']=='call'and w['control']['taken']:calls[w['step_index']]=dict(call=w['step_index'],target=coord(w['target_origin']),caller=coord(w['origin']),sp=w['after']['sp'],continuation=w['call_return_address'])
    elif event['type']=='hardware_frame_return':returns[event['frame']['call_step']]=event['step_index']
  windows=[dict(c,ret=returns[k])for k,c in calls.items()if k in returns];roots=[]
  for c in windows:
   if c['target']not in native or(roots and c['call']<roots[-1]['ret']):continue
   roots.append(c)
  count=lambda c:bisect.bisect_right(steps,c['ret'])-bisect.bisect_right(steps,c['call'])
  guest=len(steps)-sum(map(count,roots));cs=[]
  for c in windows:
   if c['target']!='PLI1.OVL+02F0':continue
   inside=[r for r in roots if c['call']<r['call']<r['ret']<=c['ret']]
   cs.append(dict(c,historical_body=count(c),residual_body=count(c)-sum(map(count,inside)),native_children=dict(collections.Counter(r['target']for r in inside)),native_child_calls_sha256=digest([r['call']for r in inside])))
  result[source]=dict(historical=len(steps),guest=guest,host=len(roots),logical_windows=cs)
  full[source]=dict(calls=windows,native_roots=roots)
 save(OUT/'all-windows.json',full);save(REPORT/'hierarchy-summary.json',result)
 expected={'MINIMAL':(414704,112),'FIZZBUZ':(967554,340),'PICTURE':(494793,139)}
 for source,(g,h)in expected.items():assert(result[source]['guest'],result[source]['host'])==(g,h),(source,result[source])
 print(json.dumps({s:dict(guest=r['guest'],host=r['host'],logical=[dict(call=q['call'],residual=q['residual_body'],native=q['native_children'])for q in r['logical_windows']])for s,r in result.items()},indent=2))
def packet():
 cases=json.loads((OUT/'cases.json').read_text());cfg=json.loads((OUT/'cfg.json').read_text());hierarchy=json.loads((REPORT/'hierarchy-summary.json').read_text())
 routes={};states=[];local_counts=collections.Counter();topology={};checks=0
 def reg(q):return [q[k]for k in ['a','b','c','d','e','h','l','sp','pc']]+[int(q['flags'][k])for k in ['sign','zero','auxiliary_carry','parity','carry']]
 for source,ks in cases.items():
  rs=ks['PLI1.OVL+02F0'];topology[source]=dict(logical=len(rs),outer=sum(q['parent']is None for q in rs),nested=sum(q['parent']is not None for q in rs))
  bycall={q['call']:q for q in rs}
  for q in rs:
   depth=1;parent=q['parent']
   while parent is not None:depth+=1;parent=bycall[parent]['parent']
   key=json.dumps(q['children']);route=next((k for k,v in routes.items()if json.dumps(v)==key),None)
   if route is None:route='R'+str(len(routes));routes[route]=q['children']
   states.append(dict(source=source,call=q['call'],ret=q['ret'],caller=q['caller'],parent=q['parent'],depth=depth,route=route,entry=reg(q['entry']),output=reg(q['output']),branches=q['branches'],proof_hash=q['proof_hash']))
   assert q['output']['sp']==q['entry']['sp']+2
   assert(q['output']['h']<<8|q['output']['l'])==(q['entry']['b']<<8|q['entry']['c'])
   checks+=2
  topology[source]['maximum_depth']=max((q['depth']for q in states if q['source']==source),default=0)
 full=json.loads((OUT/'rows.json').read_text())
 laws={}
 for source,ks in full.items():
  for q in ks['PLI1.OVL+02E9']:
   e=q['entry']['before'];o=q['ret']['after'];ws=q['own_witnesses'];w=[(x['address'],x['new_value'])for a in ws for x in a['writes']]
   assert w==[(0xa6cb,0x6a),(0xa6cc,0xa6)]
   assert(o['h'],o['l'])==(0xa6,0x6a)and all(o[k]==e[k]for k in ['a','b','c','d','e','flags'])
   assert o['sp']==e['sp']+2 and o['pc']==q['call']['call_return_address'];local_counts['02E9']+=1;checks+=4
  for q in ks['PLI1.OVL+01D8']:
   e=q['entry']['before'];o=q['ret']['after'];ws=q['own_witnesses'];rar=next(w for w in ws if w['disassembly']=='RAR');v=rar['before']['a'];cy=e['flags']['carry'];result=(v>>1)|(128 if cy else 0)
   assert rar['after']['a']==result and rar['after']['flags']==dict(e['flags'],carry=bool(v&1))
   assert o['a']==result and o['flags']==rar['after']['flags'] and all(o[k]==e[k]for k in ['b','c','d','e'])
   assert[(x['address'],x['new_value'])for w in ws for x in w['writes']]==[(0x2010,0)]
   assert o['sp']==e['sp']+2 and o['pc']==q['call']['call_return_address'];local_counts['01D8_clear_route']+=1;checks+=4
  for q in ks['PLI1.OVL+02F0']:
   e=q['entry']['before'];o=q['ret']['after'];ws=q['own_witnesses'];push=ws[0];pop=ws[-2];ret=ws[-1]
   assert push['disassembly']=='PUSH B'and pop['disassembly']=='POP H'and ret['disassembly']=='RET'
   assert sorted((x['address'],x['new_value'])for x in push['writes'])==[(e['sp']-2,e['c']),(e['sp']-1,e['b'])]
   assert [(x['address'],x['value'])for x in pop['reads']]==[(e['sp']-2,e['c']),(e['sp']-1,e['b'])]
   assert o['pc']==q['call']['call_return_address'];checks+=4
   cs=children_any(dict(q,nested_returns={int(k):v for k,v in q['nested_returns'].items()}))
   assert cs[-1]['target']=='PLI1.OVL+01D8'
   assert all(o[k]==cs[-1]['output'][k]for k in ['a','b','c','d','e','flags']);checks+=2
   for w in ws:
    if w['disassembly']=='RAR':
     b=w['before'];a=w['after'];assert a['a']==(b['a']>>1)|(128 if b['flags']['carry']else 0)
     assert a['flags']==dict(b['flags'],carry=bool(b['a']&1));checks+=2
 catalog={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
 childkeys=sorted({k for cs in routes.values()for _,k in cs});refs={k:dict(hash=digest(catalog[k]),completeness=catalog[k]['completeness'])if k in catalog else dict(status='no ProcedureHypothesis')for k in childkeys}
 summary={s:{k:dict(count=len(rs),proof_hash=digest(rs))for k,rs in ks.items()if k!='PLI1.OVL+02F0'}for s,ks in cases.items()}
 packet=dict(task='RECURSIVE_PARENT_02F0_PASS_47',baseline='2fc80f0b09af0c07e41ca37ed79e6846e1f600d2',state_columns=['A','B','C','D','E','H','L','SP','PC','S','Z','AC','P','CY'],topology=topology,routes=routes,cfg=[f'{o:04X} {b} {d}'for o,b,d in cfg['PLI1.OVL+02F0']],cases=states,child_contracts=refs,component_inventory=summary,local_instruction_laws=dict(base_initialization=dict(coordinate='PLI1.OVL+02E9',cases=local_counts['02E9'],law='HL=A66A; write low6A then highA6 atA6CB/A6CC; preserve A/BC/DE/flags; RET original CALL'),end_gate=dict(coordinate='PLI1.OVL+01D8',cases=local_counts['01D8_clear_route'],law='fresh2010 -> A; RAR actual entryCY; bit0clear observed branch writes2010=0 withHL2010; preserveBC/DE and rotate flags')))
 save(REPORT/'implementation-packet.json',packet)
 assert(REPORT/'implementation-packet.json').stat().st_size<=32768
 save(REPORT/'topology-summary.json',dict(topology=topology,callers={s:dict(collections.Counter(q['caller']for q in ks['PLI1.OVL+02F0']))for s,ks in cases.items()},routes={s:dict(collections.Counter(q['route']for q in states if q['source']==s))for s in cases}))
 save(REPORT/'local-proof-summary.json',dict(status='instruction/dataflow checks; no host root shadow claimed',assertions=checks,natural_case_counts=dict(local_counts),oracle_queries=0))
 print(json.dumps(dict(topology=topology,checks=checks,local_counts=dict(local_counts),packet_bytes=(REPORT/'implementation-packet.json').stat().st_size)))
def assess():
 packet();packet_data=json.loads((REPORT/'implementation-packet.json').read_text())
 readers=json.loads((OUT/'reader-rows.json').read_text());family=json.loads((OUT/'reader-family-summary.json').read_text());family_cfg=json.loads((OUT/'reader-family-cfg.json').read_text());family_cfg.update(json.loads((OUT/'reader-cfg.json').read_text()));roots=json.loads((OUT/'cases.json').read_text());catalog={q['id']:q for q in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
 cases=[];stats={};contracts={}
 for source,ks in readers.items():
  parent_roots=roots[source]['PLI1.OVL+02F0'];stats[source]={}
  for key,rs in ks.items():
   required=[]
   for r in rs:
    call=r['call']['step_index'];ret=r['ret']['step_index'];parents=[q for q in parent_roots if q['call']<call<ret<q['ret']]
    if not parents:continue
    parent=max(parents,key=lambda q:q['call']);required.append(r)
    children=children_any(dict(r,nested_returns={int(k):v for k,v in r['nested_returns'].items()}))
    cases.append(dict(source=source,coordinate=key,caller=coord(r['call']['origin']),call=call,ret=ret,logical_02F0=parent['call'],entry=r['entry']['before'],output=r['ret']['after'],continuation=r['call']['call_return_address'],children=[dict(site=f"{c['callsite']:04X}",target=c['target'],entry=c['entry'],output=c['output'])for c in children]if key.endswith('1AFD')else[dict(site=f"{c['callsite']:04X}",target=c['target'])for c in children],proof_hash=digest(r)))
   stats[source][key]=dict(natural=len(rs),required=len(required),independent=len(rs)-len(required))
 for key in ['PLI1.OVL+1C07','PLI1.OVL+1D13','PLI1.OVL+1BBF','PLI1.OVL+1AFD','PLI1.OVL+1421','PLI1.OVL+140D','PLI1.OVL+14E4','PLI1.OVL+156D']:
  contracts[key]=dict(status='no ProcedureHypothesis'if key not in catalog else catalog[key]['completeness'],local_reached_bytes=sum(len(b)//2 for o,b,d in family_cfg.get(key,[])),natural_counts={source:family[source].get(key,{}).get('count',stats[source].get(key,{}).get('natural',0))for source in roots})
 boundary=dict(status='substantive separate reader/construction family; native root unfinished',family_root='PLI1.OVL+1C07',root_edge=['PLI1.OVL+02F0','PLI1.OVL+2006','PLI1.OVL+1C07'],first_nested_family_edge=['PLI1.OVL+1C07','PLI1.OVL+1D13','PLI1.OVL+1BBF'],distinct_reader='PLI1.OVL+1AFD',rationale=['Pass46 explicitly identified1AFD as a separate reader family above canonical19F0; Pass47 instructions require preserving that boundary.','Required1C07 routes include two different selector-dependent constructions, state/frame handling,1D13/1BBF construction and1421 repeated14C8 processing; this is a separate family rather than a missing predicate wrapper.','The canonical19F0 child covers its six contained windows but does not compute the surrounding reader/frame/transformation behavior.','Unexecuted alternatives are not blockers; the listed six actual1C07/1AFD windows require these laws.'],inventory=stats,contracts=contracts,required_entries=cases,oracle_queries=0,checkpoint='deferred until the next successful semantic commit; no full run on unfinished evidence',no_native_root=True)
 save(REPORT/'boundary-assessment.json',boundary)
 compact=dict(family_root=boundary['family_root'],root_edge=boundary['root_edge'],first_nested_family_edge=boundary['first_nested_family_edge'],distinct_reader=boundary['distinct_reader'],inventory=stats,contracts=contracts,evidence_sha256=digest(boundary),required_entries=[dict(source=q['source'],coordinate=q['coordinate'],caller=q['caller'],call=q['call'],logical_02F0=q['logical_02F0'],sp=q['entry']['sp'],continuation=q['continuation'],proof_hash=q['proof_hash'])for q in cases])
 packet_data['substantive_boundary']=compact;save(REPORT/'implementation-packet.json',packet_data)
 assert(REPORT/'implementation-packet.json').stat().st_size<=32768
 save(REPORT/'natural-cases.json',dict(canonical_cases='implementation-packet.json#/cases',case_count=len(packet_data['cases']),topology=packet_data['topology'],case_proof_hashes=[q['proof_hash']for q in packet_data['cases']]))
 save(REPORT/'fidelity.json',dict(status='assessment; no native coverage claimed',archaeological_scope_extension='none promoted',historical_correction=None,pragmatic_divergence=None,fidelity_debt=None,unfinished_scope='native02F0 and its separate1C07 reader/construction family; this is unproved scope, not pragmatic divergence',raw_promoted=0,oracle_queries=0,canonical_implementations_unchanged=True))
 print(json.dumps(dict(inventory=stats,packet_bytes=(REPORT/'implementation-packet.json').stat().st_size,boundary=boundary['family_root'],contracts=contracts),indent=2))
def quoted_cases():
 rows=json.loads((OUT/'reader-resident-rows.json').read_text());lines=[];summary={}
 for source,ks in rows.items():
  cases=[r for r in ks['PLI.COM+1376']if any(w['origin']['offset']==0x13fc for w in r['own_witnesses'])]
  lines.append(source+' '+','.join(str(r['call']['step_index']+1)for r in cases))
  summary[source]=dict(count=len(cases),cases=[dict(call=r['call']['step_index'],caller=coord(r['call']['origin']),read_count=sum(w['origin']['offset']==0x141a for w in r['own_witnesses']),prefix_appends=sum(w['origin']['offset']==0x1411 for w in r['own_witnesses']),entry=r['entry']['before'],output=r['ret']['after'],proof_hash=digest(r))for r in cases])
 (OUT/'quoted-case-steps.txt').write_text('\n'.join(lines)+'\n');save(OUT/'quoted-cases.json',summary)
 print(json.dumps({s:r['count']for s,r in summary.items()}))

def prove(images):
 """Re-run independent component, recursive logical, outer and hybrid proofs."""
 import subprocess,tempfile,shutil
 target=OUT/'validated-proof';target.mkdir(exist_ok=True,parents=True)
 with tempfile.TemporaryDirectory(prefix='pass47-proof-',dir=OUT)as directory:
  directory=Path(directory)
  for operation in ['reader','reader2','reader3','reader4','reader5','quoted','reader-io','lookahead','root-local','parser-local','header','cleanup','frames','adapters','02F0']:
   output=directory/(operation+'.json');started=time.monotonic()
   command=['dune','exec','pli80-native-acquisition-family','--','--operation',operation,'--toolchain',str(images),'--output',str(output)]
   if operation=='quoted':command+=['--case-steps',str(OUT/'quoted-case-steps.txt')]
   result=__import__('subprocess').run(command,capture_output=True,text=True)
   (target/(operation+'.log')).write_text(result.stdout+result.stderr)
   if result.returncode:raise RuntimeError(operation+': '+(result.stdout+result.stderr)[-1800:])
   shutil.copyfile(output,target/output.name)
   print(operation,'passed',round(time.monotonic()-started,3),flush=True)
  output=directory/'hybrids'
  result=subprocess.run(['dune','exec','pli80-native-recursive-hybrids','--','--toolchain',str(images),'--output-dir',str(output)],capture_output=True,text=True)
  (target/'hybrids.log').write_text(result.stdout+result.stderr)
  if result.returncode:raise RuntimeError('hybrids: '+(result.stdout+result.stderr)[-1800:])
  for file in output.glob('*.json'):shutil.copyfile(file,target/file.name)
 return target

def closed_report(proof=None):
 proof=proof or (OUT/'validated-proof'if(OUT/'validated-proof/natural-cases.json').exists()else OUT/'hybrids-5')
 roots=load(proof/'natural-cases.json');cumulative=load(proof/'cumulative-hybrid-summary.json')
 existing=load(REPORT/'implementation-packet.json')
 for key in ['substantive_boundary','component_inventory']:existing.pop(key,None)
 coordinates=['19F0','6619','6223','5929','2511','240A','23D2','23A0','80B7','7EC0','8048','7E5F','7D53','7C1B','7BBF','7B7A','7BA2','7AD5','7B64','7ABF','0EF6','7A79','7E46','7E56','7AF0','7B49','7A93','7B13']
 hierarchy=load(REPORT/'hierarchy-summary.json');outer=[]
 for group,g in zip(roots['sources'],cumulative['sources']):
  s=group['source'];before=g['pre_transition_vector'];after=g['transition_vector'][1:];assert len(before)==len(after)==len(coordinates)
  h=hierarchy[s];h.update(outer_roots=len(group['members']),post_guest=g['result']['actual_guest_instructions'],actual_instructions_removed=g['guest_instructions_removed'],post_host=g['result']['host_transitions'],pre_transition_vector=before,post_transition_vector=g['transition_vector'],absorbed_by_coordinate={k:a-b for k,a,b in zip(coordinates,before,after)if a!=b},remaining_external_6619=after[1],remaining_external_19F0=after[0],remaining_external_02F0=0,host_bdos_services=g['host_bdos_services'])
  for c in group['members']:
   outer.append(dict(source=s,caller=c['caller'],entry_step=c['entry_step'],return_step=c['return_step'],route=c['result']['route'],input=c['input'],output=c['output'],entry_memory_sha256=c['entry_memory_sha256'],post_memory_sha256=c['post_memory_sha256'],journal_sha256=digest(c['journal']),logical_writes=sum(w[4]=='logical'for w in c['journal']),stack_writer_cells=len({w[0]for w in c['journal']if w[4]=='compatibility'}),internal_6619=sum(w[2]==0x883e and w[4]=='compatibility'for w in c['journal'])//2,internal_19F0=sum(w[2]==0x3d7b and w[4]=='compatibility'for w in c['journal'])//2))
 save(REPORT/'hierarchy-summary.json',hierarchy)
 save(REPORT/'natural-cases.json',dict(logical_cases='implementation-packet.json#/cases',outer_cases=outer,duplicates_preserved=True))
 components={};proof_hashes={}
 paths=list(proof.glob('*.json'))if proof.name=='validated-proof'else list(OUT.glob('*shadow.json'))
 for path in paths:
  q=load(path)
  if not q.get('sources')or not isinstance(q['sources'],list)or not q['sources'][0].get('operation'):continue
  for g in q['sources']:components.setdefault(g['operation'],{})[g['source']]=g['field15_matched']
  proof_hashes[path.name]=digest(q)
 catalog={p['id']:p for p in load(Path('research/annotated-assembly/procedures.json'))['procedures']}
 existing['child_contracts']={k:dict(hash=digest(catalog[k]),completeness=catalog[k]['completeness'])if k in catalog else dict(status='no ProcedureHypothesis')for k in existing['child_contracts']}
 laws={};ar=[]
 for image in ['PLI1.OVL','PLI.COM']:
  laws.update(load(REPORT/('contract-laws-'+image+'.json')));ar.append(load(REPORT/('archaeology-summary-'+image+'.json')))
 raw=sum(q['raw_to_understood']for q in ar)
 existing.update(selected_root='PLI1.OVL+02F0',status='bounded native root complete',oracle_queries=0,new_contract_references=[dict(coordinate=k,procedure_sha256=digest(catalog[k]),law_sha256=digest(v),natural_counts=[catalog[k]['observed_paths']['invocations_by_run'].get(source,0)for source in ['MINIMAL','FIZZBUZ','PICTURE']],represented_bytes=catalog[k]['observed_paths']['represented_bytes'])for k,v in laws.items()],component_proof_hashes=proof_hashes,recursion_law='Actual selector/probe predicates select direct03CD/03E8 or mediated11E2/0A32/0B79 calls. Acquisitions advance shared state; recursive BC is freshly formed/reloaded. No depth schedule/limit. Saved original BC survives on stack and returns via POP H after final01D8.',frames={'02F0':'PUSH B original word; recursive CALL beneath frame; POP H then original RET','11E2':'eleven-byte inherited frame, SPHL discards11','0A32':'eight-byte frame; per-iteration F3/F4 init; four POP H','N2':'canonical4468 copied continuation; finalSP=entrySP+4','N8':'canonical6708 consumed8; copied continuation at entrySP+8; finalSP=entrySP+10'},required_reader_family=['2006','1C07','1D13','1BBF','1421','1AFD','canonical19F0'])
 (REPORT/'implementation-packet.json').write_text(json.dumps(existing,separators=(',',':'))+'\n');assert(REPORT/'implementation-packet.json').stat().st_size<=32768
 save(REPORT/'shadow-summary.json',dict(all_passed=True,logical_counts={'MINIMAL':1,'FIZZBUZ':8,'PICTURE':2},outer_counts={'MINIMAL':1,'FIZZBUZ':1,'PICTURE':2},nested_counts={'MINIMAL':0,'FIZZBUZ':7,'PICTURE':0},max_depth={'MINIMAL':1,'FIZZBUZ':5,'PICTURE':1},component_counts=components,component_proof_hashes=proof_hashes,outer_proof_sha256=digest(roots),comparisons=['all registers/flags','SP/continuation PC','ordered logical writes','65536-byte RAM','all final stack writers','DMA/filesystem/file/record chronology','owned local child CALL chronology','canonical19F0/6619 journal correlation','canonical6223 full-state checkpoints'],software_continuations=['4468 N2','6708 N8']))
 save(REPORT/'single-hybrid-summary.json',load(proof/'single-hybrid-summary.json'));save(REPORT/'cumulative-hybrid-summary.json',cumulative)
 save(REPORT/'fidelity.json',dict(implemented_root='PLI1.OVL+02F0',scope_extensions=list(laws),raw_bytes_promoted=raw,oracle_queries=0,historical_correction=None,implementation_corrections=['Descriptor-sort carry/common restore path','Read-buffer carry sense','Exact service resume/child preview prefix','335B freshly selected acquisition route','0A32 frame reinitialization and actual cached recursion branch','08F8 private writer and83A0 subtraction law'],pragmatic_divergence=None,fidelity_debt=None,CPU_changes=False,Runner_changes=False,CPM_changes=False,shared_proof_schema_changes=False,one_staged_transaction=True,unsupported=['unobserved selector/error/listing/quoted scanner arms','arbitrary reader/constructor aliases','inherited canonical child unsupported states','arbitrary recursion/input termination'],termination_scope='demonstrated state-selected recursive and reader paths; no global termination claim',software_N2=True,software_N8=True))
 save(REPORT/'boundary-assessment.json',dict(completed=True,selected_root='PLI1.OVL+02F0',why='Substantial recursive operation: four outer roots absorb eleven logical calls, six19F0 and six remaining external6619; caller0B79 belongs to distinct acquisition frame.',next='Pass48: bounded native0A32 acquisition/frame composition. Three external windows have55507 residual ranking occurrences (7521/16125/31861), contain all4 new02F0 roots, and reuse the independently proved08D9/frame operations. Compare broader0C1B (71607) and0C75 (104485), which add independent initialization, before any one-level widening.',required_blockers=[],remaining_external_6619={s:h['remaining_external_6619']for s,h in hierarchy.items()},checkpoint='Pass47 scheduled full checkpoint'))
 for image in ['PLI1.OVL','PLI.COM']:
  for when in ['before','after']:
   path=REPORT/(when+'-'+image+'.json');data=load(path)
   if 'procedures'not in data:save(path,dict(full_proof_sha256=digest(data),procedures={k:None if v is None else dict(completeness=v['completeness'],represented_bytes=v['observed_paths']['represented_bytes'],procedure_sha256=digest(v))for k,v in data.items()}))
 print(json.dumps(dict(packet_bytes=(REPORT/'implementation-packet.json').stat().st_size,raw_promoted=raw,counters={s:[h['guest'],h['post_guest'],h['actual_instructions_removed'],h['host'],h['post_host']]for s,h in hierarchy.items()})))


def residual():
 """Ranking only: corrected interval union excluding current native bodies."""
 import bisect
 full=load(OUT/'all-windows.json');summary={}
 for source,data in full.items():
  calls=data['calls'];logical=[q for q in calls if q['target']=='PLI1.OVL+02F0']
  outer=[q for q in logical if not any(p['call']<q['call']<q['ret']<p['ret']for p in logical)]
  roots=sorted(data['native_roots']+outer,key=lambda q:q['call']);disjoint=[]
  for q in roots:
   if not disjoint or q['call']>disjoint[-1]['ret']:disjoint.append(q)
  candidates={q['target']for q in calls if q['target']and q['target'].startswith('PLI1.OVL+')and any(q['call']<r['call']<r['ret']<q['ret']for r in outer)}
  candidates.update('PLI1.OVL+'+key for key in ['08D9','0A32','0146','02CA','11E2'])
  values={}
  for key in candidates:
   windows=[q for q in calls if q['target']==key and not any(r['call']<=q['call']and q['ret']<=r['ret']for r in disjoint)]
   counts=[q['ret']-q['call']-sum(max(0,min(q['ret'],r['ret'])-max(q['call'],r['call']))for r in disjoint)for q in windows]
   values[key]=dict(external_windows=len(windows),residual_inclusive=sum(counts),maximum_window=max(counts,default=0),contains_outer_02F0=sum(any(q['call']<r['call']<r['ret']<q['ret']for q in windows)for r in outer))
  summary[source]=dict(sorted(values.items(),key=lambda kv:kv[1]['residual_inclusive'],reverse=True))
 save(REPORT/'residual-parent-assessment.json',dict(method='Ranking: corrected interval union; nested parent totals overlap and are never whole-run savings.',sources=summary))
 print(json.dumps(summary,separators=(',',':')))

def checkpoint():
 import subprocess
 subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images','/home/john/pli/cpm/pli80/DISK1','--output',str(OUT/'full-checkpoint'),'--workers','4'],check=True)

if __name__=='__main__':
 if len(sys.argv)>1 and sys.argv[1]=='all':closed_report(prove(Path('/home/john/pli/cpm/pli80/DISK1')))
 elif len(sys.argv)>1 and sys.argv[1]=='prove':prove(Path('/home/john/pli/cpm/pli80/DISK1'))
 elif len(sys.argv)>1 and sys.argv[1]=='report':closed_report()
 elif len(sys.argv)>1 and sys.argv[1]=='residual':residual()
 elif len(sys.argv)>1 and sys.argv[1]=='checkpoint':checkpoint()
 elif len(sys.argv)>1 and sys.argv[1]=='dependencies':dependencies()
 elif len(sys.argv)>1 and sys.argv[1]=='measure':measure()
 elif len(sys.argv)>1 and sys.argv[1]=='parser':dependencies(True)
 elif len(sys.argv)>1 and sys.argv[1]=='boundary':dependencies('boundary')
 elif len(sys.argv)>1 and sys.argv[1]=='packet':packet()
 elif len(sys.argv)>1 and sys.argv[1]=='reader':dependencies('reader')
 elif len(sys.argv)>1 and sys.argv[1]=='reader-family':dependencies('reader-family')
 elif len(sys.argv)>1 and sys.argv[1]=='reader-descendants':dependencies('reader-descendants')
 elif len(sys.argv)>1 and sys.argv[1]=='quoted-cases':quoted_cases()
 elif len(sys.argv)>1 and sys.argv[1]=='parser-cleanup':dependencies('parser-cleanup')
 elif len(sys.argv)>1 and sys.argv[1]=='parser-acquisition':dependencies('parser-acquisition')
 elif len(sys.argv)>1 and sys.argv[1]=='parser-leaves':dependencies('parser-leaves')
 elif len(sys.argv)>1 and sys.argv[1]=='parser-glue':dependencies('parser-glue')
 elif len(sys.argv)>1 and sys.argv[1]=='lookahead':dependencies('lookahead')
 elif len(sys.argv)>1 and sys.argv[1]=='reader-record':dependencies('reader-record')
 elif len(sys.argv)>1 and sys.argv[1]=='reader-fetch':dependencies('reader-fetch')
 elif len(sys.argv)>1 and sys.argv[1]=='reader-refill-children':dependencies('reader-refill-children')
 elif len(sys.argv)>1 and sys.argv[1]=='reader-refill':dependencies('reader-refill')
 elif len(sys.argv)>1 and sys.argv[1]=='reader-readflow':dependencies('reader-readflow')
 elif len(sys.argv)>1 and sys.argv[1]=='reader-attribute':dependencies('reader-attribute')
 elif len(sys.argv)>1 and sys.argv[1]=='reader-resident':dependencies('reader-resident')
 elif len(sys.argv)>1 and sys.argv[1]=='reader-adapters':dependencies('reader-adapters')
 elif len(sys.argv)>1 and sys.argv[1]=='assess':assess()
 else:extract()
