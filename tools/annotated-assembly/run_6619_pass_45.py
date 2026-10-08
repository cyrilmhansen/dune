#!/usr/bin/env python3
"""Deterministic Pass45 topology, bounded child evidence and proof summaries."""
import sys,json,hashlib,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_acquisition_reentry_pass_38 import CAPTURES,SPINE,children,coord
from check_selector02_pass_40 import gather_selected
def validate_pass():
 import subprocess
 categories='pass45-local,pass45-root,pass44-roots,pass44-family,pass44-numeric,pass44-hybrids,pass43,pass38,pass39,packet-continuation,V1,roundtrip,classifier-unit,acquisition-parent-unit,word-emitter-unit,range-unit,gate-unit,input-unit,mapped-unit,recursive-unit,diff-check'
 subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images',str(Path('/home/john/pli/cpm/pli80/DISK1')),'--output','_build/host-compiler-pass-45/validation','--workers','4','--categories',categories],check=True)

if '--validate-only' in sys.argv:
 validate_pass();raise SystemExit(0)
start=time.monotonic();sources=[];cfg={}
for source,path in CAPTURES.items():
 rows=gather_selected(path,{f'PLI1.OVL+{x:04X}':(x,x+1)for x in SPINE+[0x6223,0x2259]},include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8})
 roots=rows['PLI1.OVL+6223'];outer=[r for r in roots if not any(p['call']['step_index']<r['call']['step_index']<p['ret']['step_index'] for p in roots)]
 cases=[]
 for r in rows['PLI1.OVL+6619']:
  call=r['call']['step_index'];ret=r['ret']['step_index'];inside=any(p['call']['step_index']<call<ret<p['ret']['step_index'] for p in outer)
  chain=[]
  for key in [f'PLI1.OVL+{x:04X}'for x in SPINE]:
   rs=[p for p in rows[key]if call<=p['call']['step_index']and p['ret']['step_index']<=ret]
   for p in rs:
    ws=p['own_witnesses'];branch=[[w['origin']['offset'],w['control']['taken']]for w in ws if w['control']['kind']=='jump']
    chain.append(dict(entry=key,call=p['call']['step_index'],branches=branch,children=[[c['callsite'],c['target'],c['entry']['c'],c['output']['a']]for c in children(p)]))
    cfg.setdefault(key,{})
    for w in ws:cfg[key][w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
  cases.append(dict(call=call,ret=ret,caller=coord(r['call']['origin']),internal6223=inside,entry=r['entry']['before'],output=r['ret']['after'],chain=chain))
 sources.append(dict(source=source,total=len(cases),internal=sum(c['internal6223']for c in cases),external=sum(not c['internal6223']for c in cases),cases=cases))
packet=dict(baseline='430b75bb82187216731f26588b3bfb48e6fed435',sources=sources,cfg={k:[v[x]for x in sorted(v)]for k,v in cfg.items()},elapsed=time.monotonic()-start)
Path('_build/host-compiler-pass-45/topology-full.json').write_text(json.dumps(packet))

report=Path('research/host-compiler/pass-45');report.mkdir(parents=True,exist_ok=True)
def save(name,value): (report/name).write_text(json.dumps(value,indent=2)+'\n')
layouts={};compact=[];missing=[]
for source in sources:
 cases=[]
 for case in source['cases']:
  own=[p for p in case['chain']if p['call'] in range(case['call'],case['call']+12)]
  shape=[{k:p[k]for k in ['entry','branches','children']}for p in own]
  key=hashlib.sha256(json.dumps(shape,sort_keys=True).encode()).hexdigest()[:12]
  layouts[key]=shape
  cases.append({k:case[k]for k in ['call','ret','caller','internal6223','entry','output']}|dict(route=key))
  if not case['internal6223'] and any(p['entry']=='PLI1.OVL+654E'and len(p['children'])>2 for p in own):missing.append((source['source'],case['call'],case['call']+2))
 compact.append({k:source[k]for k in ['source','total','internal','external']}|dict(cases=cases))
contracts=[]
catalog=json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']
for proc in catalog:
 if proc['id'] in cfg:
  contracts.append(dict(id=proc['id'],sha256=hashlib.sha256(json.dumps(proc,sort_keys=True).encode()).hexdigest(),completeness=proc['completeness']))
view=dict(baseline=packet['baseline'],status='blocked before native implementation',sources=compact,routes=layouts,cfg=packet['cfg'],contracts=contracts)
data=json.dumps(view,separators=(',',':'))+'\n';assert len(data.encode())<=32768
(report/'implementation-packet.json').write_text(data)
rows=gather_selected(CAPTURES['FIZZBUZ'],{f'PLI1.OVL+{x:04X}':(x,x+1) for x in [0x654e,0x345e,0x784e,0x64f2,0x2259,0x21d4]},include_nested_returns=True)
entries=[]
for source,outer,child in missing:
 r=next(r for r in rows['PLI1.OVL+654E']if r['call']['step_index']==child)
 first=next(w for w in r['own_witnesses']if w['origin']['offset']==0x655d)
 search=next(c for c in children(r)if c['callsite']=='PLI1.OVL+6556')
 rotate=next(w for w in r['own_witnesses']if w['origin']['offset']==0x6559)
 branch=next(w for w in r['own_witnesses']if w['origin']['offset']==0x655a)
 entries.append(dict(source=source,outer_6619_call_step=outer,child_654E_call_step=child,ancestry=['663E ->6619','6619 ->65F9','65F9 ->654E','6556 ->57B7'],search=search,rotate=rotate,branch=branch,first_missing_instruction=first,private_frame=dict(bytes=4,base=r['entry']['before']['sp']-4,inherited_HL=r['entry']['before']['h']*256+r['entry']['before']['l'])))
save('first-missing-causal-operation.json',dict(operation='PLI1.OVL+654E search-found/repeat arm',first_coordinate='PLI1.OVL+655D',runtime=0x875d,raw_extent=[0x655d,0x65f6],reason='Pass38 explicitly excludes these three naturally observed loops; canonical Pass44 algorithm requires the 7969 search-found carry to be clear. Required loop includes fresh acquisition, second64F2,345E,classifier,25A9 and a repeat. No operational contract for this route has been established.',entries=entries))
save('topology-summary.json',dict(sources=[{k:s[k]for k in ['source','total','internal','external']}for s in sources],external_callers={'PLI1.OVL+663E':12},external_routes={'clear_repeat':9,'654E_found_repeat':3},packet_bytes=len(data.encode()),full_evidence_bytes=Path('_build/host-compiler-pass-45/topology-full.json').stat().st_size,generation_seconds=round(time.monotonic()-start,3),oracle_queries=0))
save('boundary-assessment.json',dict(status='first missing contract; no partial native commit',next_operation='bounded +654E search-found/repeat route beginning +655D, including its actually required345E/25A9 child scopes',reason='Required by three of nine external FIZZBUZ roots; six internal field80 wrapper calls remain covered by the existing clear-repeat law.',scope_extension=False,correction=False,divergence=False,fidelity_debt=False))

# Continue only to the first child without an established machine-state law.
from check_acquisition_reentry_pass_38 import validate
from check_3dd9_pass_35 import arithmetic,rotate,validate_data_writers
repeat_cases=[];child_gaps=[]
for source,outer,child in missing:
 r=next(r for r in rows['PLI1.OVL+654E']if r['call']['step_index']==child)
 cs=children(r);required=next(c for c in cs if c['target']=='PLI1.OVL+345E')
 # A now-proved bounded345E contract may already be present.
 call=next(w for w in r['own_witnesses']if w['step_index']==required['call_step'])
 before=[w for w in r['own_witnesses']if 0x655d<=w['origin']['offset'] and w['step_index']<required['call_step']]
 # Literal/paired reads and direct writers are independently checked.
 prefix=dict(r,own_witnesses=before)
 validate_data_writers(prefix)
 for w in before:
  arithmetic(w)
  if w['disassembly']=='RAR':rotate(w)
  op,_,arg=w['disassembly'].partition(' ')
  if op in ('LDA','LHLD'):
   a=int(arg[:-1],16);assert [q['address']for q in w['reads']]==([a]if op=='LDA'else[a,a+1])
 # Reuse the established second64F2 clear-repeat law, without reopening children.
 second=next(c for c in cs if c['callsite']=='PLI1.OVL+6578')
 second_row=next(q for q in rows['PLI1.OVL+64F2']if q['call']['step_index']==second['call_step'])
 assert validate(second_row)['route']=='clear_repeat_spine'
 prefix_data=[dict(step=w['step_index'],coordinate=coord(w['origin']),instruction=w['disassembly'],before=w['before'],after=w['after'],reads=w['reads'],writes=w['writes'])for w in before]
 Path(f'_build/host-compiler-pass-45/prefix-{outer}.json').write_text(json.dumps(prefix_data))
 slot_reads=[dict(step=w['step_index'],coordinate=coord(w['origin']),reads=w['reads'])for w in before if w['reads']]
 publications=[dict(coordinate=coord(w['origin']),address=q['address'],value=q['new_value'])for w in before for q in w['writes']]
 branch_checks=[dict(coordinate=coord(w['origin']),input=w['before'],taken=w['control']['taken'])for w in before if w['control']['kind']=='jump']
 acquisition=next(c for c in cs if c['callsite']=='PLI1.OVL+6565')
 repeat_cases.append(dict(source=source,outer_call=outer,child_call=child,found_iterations=sum(c['target']=='PLI1.OVL+784E'for c in cs),search_calls=sum(c['target']=='PLI1.OVL+57B7'for c in cs),child_sequence=[[c['callsite'],c['target']]for c in cs],prefix_sha256=hashlib.sha256(json.dumps(prefix_data,sort_keys=True).encode()).hexdigest(),prefix_reads=slot_reads,prefix_writes=publications,branch_checks=branch_checks,acquisition=acquisition,second_wrapper=second,proof_scope='local prefix equations and established64F2 law; no full repeat reconstruction before345E contract'))
 child_gaps.append(dict(source=source,outer_call_step=outer,caller=required['callsite'],call_step=required['call_step'],entry=required['entry'],historical_return_step=required['return_step'],historical_output=required['output'],call_bytes=call['bytes'],hardware_call_writes=call['writes'],ancestry=['663E ->6619','6619 ->65F9','65F9 ->654E','65A7 ->345E'],required_route='first found7969 search, acquisition, second clear64F2, pointer comparison JC clear ->CALL345E',reason='No ProcedureHypothesis, bounded evidence contract or canonical host implementation for345E. Its returned A and independent flags feedRAR/JNC at65AA/65AB. Historical outputs are oracle evidence, not implementation semantics.'))
 prior=json.loads((report/'first-missing-causal-operation.json').read_text())
 if prior['first_coordinate']=='PLI1.OVL+655D': save('repeat-branch-entry.json',prior)
save('repeat-route-progress.json',dict(status='local prefix reconstructed up to first missing child; whole loop not yet proved',cases=repeat_cases,observed_iterations=[c['found_iterations']for c in repeat_cases],observed_search_calls=[c['search_calls']for c in repeat_cases],oracle_queries=0))
save('first-missing-causal-operation.json',dict(operation='PLI1.OVL+345E',first_coordinate='PLI1.OVL+345E',runtime=0x565e,caller='PLI1.OVL+65A7',entries=child_gaps,scope_extension='pending: no full654E contract promotion',native_enabled=False))
view['status']='blocked at first missing child345E';view['repeat_scope']=dict(prefix='freshA935 into frame0;784E;freshA635 into frame1/2;freshA631 into frame3;second64F2;freshframe3 ->A632;freshA631 ->A633;freshsaved pointer ->A637;freshA635 ->A639;CMP saved frameF0 withA5;JCclear calls345E',missing_child='PLI1.OVL+345E',evidence='repeat-route-progress.json',contract_extension='pending',cases=[dict(outer=c['outer_call_step'],call=c['call_step'],entry=c['entry'])for c in child_gaps])
data=json.dumps(view,separators=(',',':'))+'\n';assert len(data.encode())<=32768;(report/'implementation-packet.json').write_text(data)
save('boundary-assessment.json',dict(status='blocked at first missing child; no partial commit',next_operation='bounded +345E state/flag transformation called from+65A7',subsequent_unassessed_child='25A9',correction=False,scope_extension='pending',native_enabled=False))
# +345E assessment: preserve a single decoded local CFG and correlated child IO.
assessment=[];local_cfg={}
for r in rows['PLI1.OVL+345E']:
 cs=children(r)
 for w in r['own_witnesses']:local_cfg[w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
 assessment.append(dict(call_step=r['call']['step_index'],entry=r['entry']['before'],output=r['ret']['after'],return_coordinate=coord(r['ret']['origin']),children=cs,branches=[dict(coordinate=coord(w['origin']),before=w['before'],after=w['after'],control=w['control'])for w in r['own_witnesses']if w['control']['kind']=='jump']))
Path('_build/host-compiler-pass-45/345e-witnesses.json').write_text(json.dumps(rows['PLI1.OVL+345E']))
save('345e-assessment.json',dict(status='assessment, no reconstructed contract yet',cfg=[local_cfg[k]for k in sorted(local_cfg)],cases=assessment))
# Stop in child order:31FB has a complete law;2259 has no bounded contract.
assessed=json.loads((report/'345e-assessment.json').read_text())
new_gaps=[]
for r in assessed['cases']:
 assert r['children'][0]['target']=='PLI1.OVL+31FB'
 assert sum(c['target']=='PLI1.OVL+31FB'for c in r['children'])==1
 c=r['children'][1];assert c['target']=='PLI1.OVL+2259'and c['callsite']=='PLI1.OVL+3461'
 wrow=next(p for p in json.loads(Path('_build/host-compiler-pass-45/345e-witnesses.json').read_text())if p['call']['step_index']==r['call_step'])
 w=next(w for w in wrow['own_witnesses']if w['step_index']==c['call_step'])
 original=next(g for g in child_gaps if g['call_step']==r['call_step'])
 rotatew=next(w for w in wrow['own_witnesses']if w['origin']['offset']==0x3464)
 branchw=next(w for w in wrow['own_witnesses']if w['origin']['offset']==0x3465)
 rotate(rotatew);assert branchw['control']['taken']and not rotatew['after']['flags']['carry']
 assert w['after']==c['entry']and w['bytes']=='CD5944'
 assert c['output']['pc']==0x5664 and c['output']['sp']==c['entry']['sp']+2
 new_gaps.append(dict(source='FIZZBUZ',outer_6619_call_step=original['outer_call_step'],parent_345E_call_step=r['call_step'],caller=c['callsite'],call_step=c['call_step'],entry=c['entry'],return_step=c['return_step'],historical_output=c['output'],hardware_continuation=0x5664,call_bytes=w['bytes'],hardware_call_writes=w['writes'],preceding_31FB=r['children'][0],consumer_rotate=dict(before=rotatew['before'],after=rotatew['after']),consumer_branch=dict(coordinate='PLI1.OVL+3465',taken=branchw['control']['taken']),ancestry=['663E->6619','6619->65F9','65F9->654E','65A7->345E','3461->2259']))
# The historical gap record is superseded by the independent proof below.
save('345e-entry-evidence.json',json.loads((report/'first-missing-causal-operation.json').read_text()))
save('first-missing-causal-operation.json',dict(operation='PLI1.OVL+2259',first_coordinate='PLI1.OVL+2259',runtime=0x4459,caller='PLI1.OVL+3461',reason='Immediately follows complete31FB; returnedA and flags are consumed by3464RAR/3465JNC. No covering ProcedureHypothesis or canonical host implementation. No captured returned state may substitute for the missing law.',entries=new_gaps,native_enabled=False))
p31=next(p for p in catalog if p['id']=='PLI1.OVL+31FB')
view['status']='blocked at first +345E child lacking a law:2259'
view['345E_assessment']=dict(cfg=assessed['cfg'],bounded_extent_observed=[0x345e,0x34ac],extent_status='executed envelope only, static unexecuted alternatives not assessed',return_coordinate='PLI1.OVL+34AB',child_order=[c['target']for c in assessed['cases'][0]['children']],first_child_contract=dict(id=p31['id'],sha256=hashlib.sha256(json.dumps(p31,sort_keys=True).encode()).hexdigest(),completeness=p31['completeness']),first_missing_child='PLI1.OVL+2259',entries=[dict(call=e['call_step'],entry=e['entry'],continuation=e['hardware_continuation'])for e in new_gaps],first_child_relation='CALL31FB once at345E;entrySP=345EentrySP-2;continuation5661;nextCALL2259 at3461 with current child-return registers',evidence='345e-assessment.json')
data=json.dumps(view,separators=(',',':'))+'\n';assert len(data.encode())<=32768;(report/'implementation-packet.json').write_text(data)
save('boundary-assessment.json',dict(status='blocked at first missing2259 child; no partial commit',next_operation='bounded +2259 result/flag law required by+3461',parent='345E ->654E ->6619',subsequent_unassessed_child='25A9',scope_extension='pending',correction=False,divergence=False,native_enabled=False))

picture2259=gather_selected(CAPTURES['PICTURE'],{'PLI1.OVL+2259':(0x2259,0x22c0)},include_nested_returns=True)['PLI1.OVL+2259']
Path('_build/host-compiler-pass-45/2259-picture-witnesses.json').write_text(json.dumps(picture2259))
assessment2259=[];cfg2259={}
for r in rows['PLI1.OVL+2259']+picture2259:
 for w in r['own_witnesses']:cfg2259[w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
 assessment2259.append(dict(caller=coord(r['call']['origin']),call_step=r['call']['step_index'],entry=r['entry']['before'],output=r['ret']['after'],return_coordinate=coord(r['ret']['origin']),children=children(r),branches=[dict(coordinate=coord(w['origin']),before=w['before'],taken=w['control']['taken'])for w in r['own_witnesses']if w['control']['kind']=='jump']))
Path('_build/host-compiler-pass-45/2259-witnesses.json').write_text(json.dumps(rows['PLI1.OVL+2259']))
Path('_build/host-compiler-pass-45/21d4-witnesses.json').write_text(json.dumps(rows['PLI1.OVL+21D4']))
save('2259-assessment.json',dict(status='assessment, no contract yet',cfg=[cfg2259[k]for k in sorted(cfg2259)],cases=assessment2259))

# Independent native proof plus the next actual causal boundary.
import subprocess
proofs={}
for operation in ('2259','345E'):
 output=Path('_build/host-compiler-pass-45')/(operation.lower()+'-shadow.json')
 command=['dune','exec','pli80-native-acquisition-family','--','--toolchain','/home/john/pli/cpm/pli80/DISK1','--operation',operation,'--output',str(output)]
 if operation=='345E':command.append('--spine')
 run=subprocess.run(command,capture_output=True,text=True)
 assert run.returncode==0,run.stderr[-1800:]+run.stdout[-600:]
 proofs[operation]=json.loads(output.read_text())
assert [s['field15_matched']for s in proofs['2259']['sources']]==[5,1]
assert [s['field15_matched']for s in proofs['345E']['sources']]==[3,0]
save('local-shadow-summary.json',dict(status='2259 and345E bounded shadows complete; no6619 controller',operations={k:[dict(source=s['source'],matched=s['field15_matched'],cases=[{a:b for a,b in c.items() if a!='kind'}for c in s['cases']])for s in v['sources']]for k,v in proofs.items()},comparisons=['registers','flags','SP/PC','ordered logical writes','full65536 RAM','derived final stack writers','DMA','filesystem','record chronology'],oracle_queries=0))
next_entries=[]
for source,outer,child in missing:
 r=next(r for r in rows['PLI1.OVL+654E']if r['call']['step_index']==child)
 cs=children(r);parent=next(c for c in cs if c['target']=='PLI1.OVL+345E');nextc=next(c for c in cs if c['target']=='PLI1.OVL+25A9')
 tail=[w for w in r['own_witnesses']if parent['return_step']<w['step_index']<=nextc['call_step']]
 validate_data_writers(dict(r,own_witnesses=tail))
 for w in tail:
  arithmetic(w)
  if w['disassembly']=='RAR':rotate(w)
  if w['disassembly']=='ADD A' or w['disassembly']=='ADD C':
   old=w['before']['a'];arg=old if w['disassembly']=='ADD A'else w['before']['c'];n=(old+arg)&255
   assert w['after']['a']==n and w['after']['flags']==dict(sign=n>=128,zero=n==0,auxiliary_carry=(old&15)+(arg&15)>15,parity=n.bit_count()%2==0,carry=old+arg>255)
 rotatew=next(w for w in tail if w['origin']['offset']==0x65aa);branchw=next(w for w in tail if w['origin']['offset']==0x65ab)
 assert rotatew['before']==dict(parent['output'],pc=0x87aa) and rotatew['after']['a']==0x80 and not rotatew['after']['flags']['carry']and branchw['control']['taken']
 classifier=next(c for c in cs if c['callsite']=='PLI1.OVL+65CE');assert classifier['output']['a']==4
 callw=next(w for w in tail if w['step_index']==nextc['call_step'])
 next_entries.append(dict(source=source,outer_6619_call_step=outer,caller=nextc['callsite'],call_step=nextc['call_step'],entry=nextc['entry'],historical_output=nextc['output'],hardware_continuation=0x87f3,call_bytes=callw['bytes'],call_stack_writes=callw['writes'],ancestry=['663E->6619','6619->65F9','65F9->654E','65F0->25A9'],tail_sha256=hashlib.sha256(json.dumps(tail,sort_keys=True).encode()).hexdigest()))
 Path(f'_build/host-compiler-pass-45/tail-{outer}.json').write_text(json.dumps(tail))
# Earlier gap record remains historical even after25A9 is closed.
save('first-missing-causal-operation.json',dict(operation='PLI1.OVL+25A9',first_coordinate='PLI1.OVL+25A9',caller='PLI1.OVL+65F0',reason='2259 and345E independently shadowed; tail fresh classifier and publications verified. No bounded25A9 contract or canonical implementation. Do not substitute its captured result.',entries=next_entries,native_enabled=False))
view['status']='2259 and345E closed at demonstrated scope; next missing child25A9'
view['2259_contract']=dict(coordinate='PLI1.OVL+2259',new_bounded_contract=True,natural_counts={'FIZZBUZ':5,'PICTURE':1,'MINIMAL':0},callers={'3461/FIZZBUZ':3,'33C6/FIZZBUZ':2,'33C6/PICTURE':1},route='21D4 ->cacheA64A ->freshpairedA629 low21AD ->RARset ->freshpairedA62A low21AD ->RARset ->freshA64A RARset ->literal00',global_alternatives='RAW227F and later',shadow_evidence='local-shadow-summary.json')
view['next_missing']=dict(coordinate='PLI1.OVL+25A9',entries=[dict(call=e['call_step'],entry=e['entry'])for e in next_entries])
for key in ['PLI1.OVL+2259','PLI1.OVL+345E']:
 proc=next(p for p in catalog if p['id']==key);view['contracts'].append(dict(id=key,sha256=hashlib.sha256(json.dumps(proc,sort_keys=True).encode()).hexdigest(),completeness=proc['completeness']))
view['repeat_scope']['missing_child']='PLI1.OVL+25A9';view['345E_assessment']['first_missing_child']=None
# Earlier gap entries remain useful historical boundary evidence, not current support status.
data=json.dumps(view,separators=(',',':'))+'\n';assert len(data.encode())<=32768;(report/'implementation-packet.json').write_text(data)
save('topology-summary.json',dict(sources=[{k:s[k]for k in ['source','total','internal','external']}for s in sources],external_routes={'clear_repeat':9,'repeat_route_pending25A9':3},packet_bytes=len(data.encode()),oracle_queries=0,generation_seconds=round(time.monotonic()-start,3)))
save('boundary-assessment.json',dict(status='first missing25A9; no partial commit',closed=['2259 allsix natural calls','345E allthree required calls'],next_operation='bounded25A9 at65F0',scope_extension='new bounded2259/345E contracts;654E extension pending',correction=False,divergence=False,fidelity_debt=False,native6619_enabled=False))

# One extraction phase for the newly closed table adapter and complete required repeat route.
new_rows={};new_summary={};new_cfg={}
for source,path in CAPTURES.items():
 selected=gather_selected(path,{'PLI1.OVL+25A9':(0x25a9,0x25aa),'PLI1.OVL+654E':(0x654e,0x654f)},include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8})
 new_rows[source]=selected;new_summary[source]={}
 for key,rs in selected.items():
  cases=[]
  for r in rs:
   cs=children(r)
   shape=[[c['callsite'],c['target']]for c in cs]
   cases.append(dict(call=r['call']['step_index'],caller=coord(r['call']['origin']),entry=r['entry']['before'],output=r['ret']['after'],children=shape,search_results=[c['output']['a']for c in cs if c['target']=='PLI1.OVL+57B7'],entry_sp=r['entry']['before']['sp'],return_sp=r['ret']['after']['sp']))
   for w in r['own_witnesses']:new_cfg.setdefault(key,{})[w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
  new_summary[source][key]=cases
Path('_build/host-compiler-pass-45/closed-rows.json').write_text(json.dumps(new_rows))
save('table-repeat-cases.json',new_summary)
view['status']='complete bounded native implementation; validation recorded separately'
view['repeat_scope']={'route':'found offset <=5; canonical345E returnsbit0clear; independent classifier + savedoffset*8; fresh indexed table25A9 invokes2511; repeat fresh57B7 untilnotfound','evidence':'table-repeat-cases.json','scope_extension':'Pass38 clear route retained; Pass45 three found/repeat cases added','unsupported':'offset>5 and transform-set arm; inherited child unsupported states'}
view['345E_assessment']['first_missing_child']=None
view['closed_descendants']=[{'coordinate':k,'proof':'local-shadow-summary.json' if k in ('PLI1.OVL+2259','PLI1.OVL+345E')else'table-repeat-cases.json'}for k in ['PLI1.OVL+2259','PLI1.OVL+345E','PLI1.OVL+25A9']]
view['cfg']['PLI1.OVL+25A9']=[v for _,v in sorted(new_cfg['PLI1.OVL+25A9'].items())]
view['current_frontier']=None
# The chronological boundary record is retained explicitly as resolved evidence.
save('first-missing-causal-operation.json',{'status':'resolved','operations':['2259','345E','25A9','654E found/repeat'],'current_missing_operation':None})
view.pop('2259_assessment',None)
data=json.dumps(view,separators=(',',':'))+'\n';assert len(data.encode())<=32768;(report/'implementation-packet.json').write_text(data)
save('topology-summary.json',dict(sources=[{k:s[k]for k in ['source','total','internal','external']}for s in sources],external_routes={'clear_repeat':9,'found_repeat':3},packet_bytes=len(data.encode()),oracle_queries=0,generation_seconds=round(time.monotonic()-start,3)))
print(json.dumps(dict(status='bounded descendants closed',counts=[{k:s[k]for k in ['source','total','internal','external']}for s in sources],new_counts={s:{k:len(v)for k,v in rs.items()}for s,rs in new_rows.items()},packet_bytes=len(data.encode()),oracle_queries=0,elapsed=round(time.monotonic()-start,3))))


if '--validate' in sys.argv:validate_pass()
