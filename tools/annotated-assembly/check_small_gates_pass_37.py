"""Compact accumulated-natural cleanup/classifier proof; existing laws composed."""
from check_3a76_pass_36 import (ROOT,CAPTURES,gather,coord,require,pair,load,one,identity,body,children,compact_child,single_child,stack,chronology,summarize,rotate,verify_return,counts,ats,val,writes,cmp,arithmetic,validate_data_writers)
import json,hashlib,time
from pathlib import Path
REPORT=ROOT/'research/host-compiler/pass-37'
ENTRIES=[0x4601,0x239a,0x2355,0x21ad,0x230e,0x213c,0x22cb]
BOUNDS={f'PLI1.OVL+{x:04X}':(x,x+1)for x in ENTRIES}
def increment(value,carry):
 n=(value+1)&255
 return n,dict(sign=n>=128,zero=n==0,auxiliary_carry=(value&15)==15,parity=n.bit_count()%2==0,carry=carry)
def validate_classifier(r):
 ws=r['own_witnesses'];e=r['entry']['before'];out=r['ret']['after'];k=r['entry_key'];cs=children(r)
 for w in ws:
  if w['disassembly']=='RAR':rotate(w)
  elif w['disassembly']=='CMA':require(w['after']['a']==w['before']['a']^255 and w['after']['flags']==w['before']['flags'],'CMA preserves preceding selfSBB flags')
  elif w['disassembly']=='INR A':
   v,f=increment(w['before']['a'],w['before']['flags']['carry']);require(w['after']['a']==v and w['after']['flags']==f,'INR NZPA from increment, CY from child')
  else:arithmetic(w)
 extra={};route=''
 if k.endswith('239A'):
  c=cs[0];require(len(cs)==1 and c['target']=='PLI1.OVL+2355'and c['entry']['c']==0,'fresh zero-index child invocation, not cached classifier result')
  require(out==dict(c['output'],pc=out['pc'],sp=out['sp']),'239A delegates all child channels')
  selected=one(r['nested_returns'][one(ws,0x239c)['step_index']]['memory_witnesses'],0x2362)['reads'][0]['value'];route='zero_index_delegate';extra=dict(selector=selected,child_result=c['output']['a'],child_flags=c['output']['flags'])
 elif k.endswith('213C'):
  value=e['c'];comparisons=[w for w in ws if w['disassembly'].startswith('CPI ')];last=int(comparisons[-1]['disassembly'].split()[1][:-1],16);match=value==last
  require(value not in (0x0b,0x0c,0x0d,3,4),'unobserved equality literal arms excluded')
  require([int(w['disassembly'].split()[1][:-1],16)for w in comparisons]==([11,12,13,2]if value==2 else[11,12,13,2,3,4]),'fresh saved-byte comparison order')
  for w in [w for w in ws if w['disassembly']=='LDA A645H']:require(w['reads'][0]['value']==value,'fresh saved input at every comparison')
  require(out['a']==int(match)and out['flags']==cmp(value,last)and pair(out,'h','l')==0xa645 and pair(out,'b','c')==pair(e,'b','c')and pair(out,'d','e')==pair(e,'d','e'),'literal A does not regenerate final comparison flags')
  route='literal1_equal02'if match else'false_final_CPI04';extra=dict(value=value,last_comparison=last)
 elif k.endswith('21AD'):
  value=e['c'];fast=value!=0x30 and value<=0x31
  require(one(ws,0x21c6)['control']['taken']==(not fast),'reuse cached unsigned-mask conjunction and RAR bit0')
  if fast:
   require(not cs and out['a']==1 and out['flags']==dict(sign=True,zero=False,auxiliary_carry=True,parity=True,carry=True),'literal1 retains ANA FF NZPA and RAR CY')
   require(pair(out,'b','c')==65535 and pair(out,'h','l')==0xa647,'fast ABI comes from POP mask and explicit scratch')
  else:
   require(len(cs)==1 and cs[0]['target']=='PLI1.OVL+213C'and cs[0]['entry']['c']==value,'fresh saved original byte passed to membership leaf')
   require(out==dict(cs[0]['output'],pc=out['pc'],sp=out['sp']),'delegated comparison flags and registers')
  require(pair(out,'d','e')==pair(e,'d','e'),'21AD DE preserved through leaf')
  route='cached_mask_literal1'if fast else'membership_delegate';extra=dict(value=value)
 elif k.endswith('22CB'):
  selected=one(ws,0x22d8)['reads'][0]['value'];last=0x15 if selected==0x15 else 0x19
  require(selected not in (0x16,0x19),'unobserved literal16/19 remain unsupported')
  for off in [0x22d8,0x22ea,0x22fc]:
   for w in ats(ws,off):require(w['reads'][0]['address']==0xa628+e['c']and w['reads'][0]['value']==selected,'independent fresh indexed reread before each comparison')
  require(out['a']==2 and out['flags']==cmp(selected,last)and pair(out,'b','c')==0xa628 and pair(out,'h','l')==0xa628+e['c']and pair(out,'d','e')==pair(e,'d','e'),'same literal2, distinct final CPI15 versus CPI19 provenance')
  route='equal15_literal2'if selected==0x15 else'default_literal2';extra=dict(selector=selected,flags_from=f'CPI{last:02X}')
 elif k.endswith('230E'):
  selected=one(ws,0x231b)['reads'][0]['value'];require(selected not in (0x24,0x25),'unobserved zero-result arm excluded')
  require(one(ws,0x232c)['control']['taken'],'24/25 equality-mask OR/RAR is clear')
  fresh=one(ws,0x233b)['reads'][0];require(fresh['address']==0xa628+e['c']and fresh['value']==selected,'fresh indexed reload for CPI28')
  if selected==0x28:require(not cs and out['a']==1 and out['flags']==cmp(selected,0x28),'literal1 retains matching CPI28');route='equal28_literal1'
  else:
   require(len(cs)==1 and cs[0]['target']=='PLI1.OVL+22CB'and cs[0]['entry']['c']==e['c'],'fresh saved index passed to22CB')
   n,f=increment(cs[0]['output']['a'],cs[0]['output']['flags']['carry']);n,f=increment(n,f['carry'])
   require(out['a']==n and out['flags']==f and all(out[q]==cs[0]['output'][q]for q in ['b','c','d','e','h','l']),'two ordered wrapping increments; CY survives from literal comparison')
   route='literal_delegate_plus_two'
  extra=dict(selector=selected)
 elif k.endswith('2355'):
  selected=one(ws,0x2362)['reads'][0];require(selected['address']==0xa628+e['c'],'selected indexed byte, not position_map')
  c=cs[0];require(c['target']=='PLI1.OVL+21AD'and c['entry']['c']==selected['value'],'selected byte becomes direct21AD input')
  setbit=bool(c['output']['a']&1);require(one(ws,0x2367)['control']['taken']==setbit,'RAR/JC consumes actual child bit0 independently of NZPA')
  if not setbit:
   w=one(ws,0x2366);require(len(cs)==1 and out['a']==5 and out['flags']==w['after']['flags']and all(out[q]==c['output'][q]for q in ['b','c','d','e','h','l']),'literal5 retains child NZPA and rotate CY0')
   route='child_bit_clear_literal5'
  else:
   fresh=one(ws,0x2376)['reads'][0];require(fresh['address']==0xa628+e['c']and fresh['value']==selected['value'],'independent selector reread after21AD')
   if fresh['value']==0x31:require(len(cs)==1 and out['a']==6 and out['flags']==cmp(0x31,0x31),'literal6 from equality31 comparison');route='equal31_literal6'
   else:
    require(fresh['value']!=0x2a and len(cs)==2 and cs[1]['target']=='PLI1.OVL+230E'and cs[1]['entry']['c']==e['c'],'unobserved2A arm excluded; fresh saved index passed to230E')
    require(out==dict(cs[1]['output'],pc=out['pc'],sp=out['sp']),'delegated final230E ABI')
    route='child_bit_set_delegate230E'
  extra=dict(selector=selected['value'],child_gate_byte=c['output']['a'],index=e['c'])
 else:raise ValueError(k)
 return dict(route=route,**extra)
def validate_cleanup(r):
 ws=r['own_witnesses'];e=r['entry']['before'];out=r['ret']['after'];p=pair(e,'b','c');cs=children(r)
 require([c['target']for c in cs]==['PLI1.OVL+4227','PLI1.OVL+428E','PLI1.OVL+4584'],'three established children in exact chronology; no hidden cleanup traversal')
 require([(x['address'],x['value'])for x in writes(ws)]==[(0xa90a,e['b']),(0xa909,e['c']),(0xa863,e['c']),(0xa864,e['b']),(0xa90b,cs[0]['output']['a']),(0xa909,((p+10)&65535)&255),(0xa90a,((p+10)&65535)>>8)],'save input high/low; publish working pointer low/high; cache control; payload+10 low/high')
 field=cs[0]['output']['a']
 # Complete successor child is used as a contract, not reconstructed again.
 require(pair(one(ws,0x4616)['after'],'h','l')==p and pair(cs[1]['entry'],'h','l')==(p+10)&65535,'fresh working pointer carrier for source+10 before successor child')
 q=pair(cs[1]['output'],'h','l');rd=one(ws,0x4625)['reads'];saved=rd[0]['value']+256*rd[1]['value'];require([a['address']for a in rd]==[0xa90b,0xa90c]and rd[0]['value']==field,'cached low byte and genuinely read adjacent high byte are separate sources')
 require(pair(cs[2]['entry'],'b','c')==(p+10)&65535 and pair(cs[2]['entry'],'d','e')==saved,'fresh cached source pointer and paired A90B/A90C argument, not zero-extended assumption')
 # Reuse Pass34 floor contract; inspect only required selected subtraction.
 childws=r['nested_returns'][one(ws,0x4629)['step_index']]['memory_witnesses'];call=one(childws,0x4592);subret=one(childws,0x1a3f);reads=[v for w in childws for v in w['reads']];top=next(v['value']for v in reads if v['address']==0x1c36)+256*next(v['value']for v in reads if v['address']==0x1c37)
 require(q<=top and subret['after']['h']*256+subret['after']['l']==(top-q)&65535,'4584 witnessed floor: actual successor<=fresh top, exact word subtraction')
 require(out==dict(subret['after'],sp=out['sp'],pc=out['pc']),'cleanup delegates floor subtraction state; no invented zero result')
 borrow=(top&255)<(q&255);high=((top-q)&65535)>>8;expected_flags=dict(sign=high>=128,zero=high==0,auxiliary_carry=((top>>8)&15)>=((q>>8)&15)+int(borrow),parity=high.bit_count()%2==0,carry=top<q)
 require(out['flags']==expected_flags,'reused resident high-SBB flag law, distinct from whole-word zero')
 require(pair(out,'b','c')==q and pair(out,'d','e')==0x1c37 and pair(out,'h','l')==(top-q)&65535 and out['a']==((top-q)&65535)>>8,'full returned machine state from reused resident subtraction')
 return dict(route='successor_at_or_below_top',input_pointer=p,control=field,discarded_or_used_adjacent=rd[1]['value'],payload_pointer=(p+10)&65535,successor=q,top=top,result_word=pair(out,'h','l'),children=[compact_child(c)for c in cs])
def analyze(source,capture,images,rows=None):
 rows=gather(capture,BOUNDS,include_nested_returns=True)if rows is None else rows;raw=(images/'PLI1.OVL').read_bytes();resident=(images/'PLI.COM').read_bytes();cases={}
 for k,rs in rows.items():
  cases[k]=[]
  for r in rs:
   verify_return(r['call'],r['ret'],r['relation']);validate_data_writers(r)
   for w in body(r):
    n=w['origin']['image']['name'];o=w['origin']['offset'];b=bytes.fromhex(w['bytes']);require(n in ('PLI1.OVL','PLI.COM')and (raw if n=='PLI1.OVL'else resident)[o:o+len(b)]==b and w['runtime_pc']==o+(0x2200 if n=='PLI1.OVL'else 0x100),'canonical immutable image/byte identity')
   require(r['ret']['after']['sp']==r['entry']['before']['sp']+2,'ordinary original hardware return slot')
   law=validate_cleanup(r)if k.endswith('4601')else validate_classifier(r)
   cases[k].append(identity(r)|dict(law=law,stack=stack(r),chronology=chronology(r)))
 return dict(source=source,structure={k:summarize(v)for k,v in rows.items()},cases=cases)
def build_packet(rows,catalog):
 cfg={};routes={};patterns={};cases=[];contracts={};sources=list(rows);callers=[]
 for source,g in rows.items():
  for key,rs in g.items():
   old={q[0]:q for q in cfg.get(key,[])}
   for r in rs:
    for w in r['own_witnesses']:
     o=w['origin']['offset'];raw=bytes.fromhex(w['bytes']);kind=w['control']['kind'];successors=[o+len(raw)]
     if kind=='return':successors=['outer_return']
     elif kind=='jump':
      target=raw[1]+256*raw[2]-0x2200;successors=[target]if w['disassembly'].startswith('JMP ')else[target,o+len(raw)]
     elif kind=='call':successors=[coord(w['target_origin']),o+len(raw)]
     old[o]=[o,w['bytes'],w['disassembly'],successors]
   cfg[key]=[old[o]for o in sorted(old)]
   for r in rs:
    st=stack(r);own=r['own_witnesses'];cs=children(r)
    route=dict(entry=key,branches=[[w['origin']['offset'],w['control']['taken']]for w in own if w['control']['kind']=='jump'],write_layout=[[w['origin']['offset'],q['address']]for w in own for q in w['writes']if w['control']['kind']!='call'and not w['disassembly'].startswith('PUSH')],children=[[c['callsite'],c['target']]for c in cs])
    if key.endswith('239A'):route['delegated_return_path']=[coord(w['origin'])for w in body(r)if w['control']['kind']=='return'and w['origin']['image']['name']=='PLI1.OVL']
    rid='r'+hashlib.sha256(json.dumps(route,sort_keys=True).encode()).hexdigest()[:8]
    pattern=[[q['relative_address'],q['writer'],q['overwritten_writers']]for q in st];pid='s'+hashlib.sha256(json.dumps(pattern).encode()).hexdigest()[:8]
    vals=lambda z:[z[k]for k in ['a','b','c','d','e','h','l','sp','pc']]+[int(z['flags']['sign'])*128+int(z['flags']['zero'])*64+int(z['flags']['auxiliary_carry'])*16+int(z['flags']['parity'])*4+int(z['flags']['carry'])]
    states=[vals(r['entry']['before']),vals(r['ret']['after'])];write_values=[q['value']for q in writes(own)];stack_values=[q['value']for q in st]
    if rid not in routes:routes[rid]=route|dict(base_abi=states,base_write_values=write_values)
    if pid not in patterns:patterns[pid]=dict(writers=pattern,base_values=stack_values)
    for c in cs:
     k=c['target'];p=catalog.get(k);contracts[k]=None if p is None else dict(id=k,sha256=hashlib.sha256(json.dumps(p,sort_keys=True).encode()).hexdigest(),completeness=p['completeness'])
    if key in ['PLI1.OVL+4601','PLI1.OVL+239A']:
     delta=lambda a,b:[[i,v]for i,v in enumerate(a)if b[i]!=v]
     caller=coord(r['call']['origin'])
     if caller not in callers:callers.append(caller)
     law=validate_cleanup(r)if key.endswith('4601')else validate_classifier(r)
     io=([law[q]for q in ['control','discarded_or_used_adjacent','payload_pointer','successor','top']]if key.endswith('4601')else[law['selector'],law['child_result'],int(law['child_flags']['carry'])])
     cases.append([sources.index(source),callers.index(caller),r['call']['step_index'],r['ret']['step_index'],rid,pid,delta(states[0],routes[rid]['base_abi'][0]),delta(states[1],routes[rid]['base_abi'][1]),delta(write_values,routes[rid]['base_write_values']),delta(stack_values,patterns[pid]['base_values']),io])
 p=catalog['PLI.COM+1A33'];contracts[p['id']]=dict(id=p['id'],sha256=hashlib.sha256(json.dumps(p,sort_keys=True).encode()).hexdigest(),completeness=p['completeness'])
 return dict(baseline='98a01655e0b7cad44f2909c96969cc051eadd174',schema='compact-target-work-packet-v2',sources=sources,callers=callers,abi_columns=['A','B','C','D','E','H','L','SP','PC','SZAPC_bits'],case_columns=['source_id','caller_id','call_step','return_step','route_id','stack_id','entry_deltas','return_deltas','write_value_deltas','stack_value_deltas','partial_child_io'],partial_io_columns={'4601':['control','adjacent_A90C','payload_pointer','successor','top'],'239A':['selected_A628','2355_result','2355_CY']},cfg=cfg,routes=routes,stack_patterns=patterns,contracts=contracts,cases=cases,counts={s:{k:len(v)for k,v in g.items()}for s,g in rows.items()})
def derive(analyses):
 return dict(sources=[dict(source=a['source'],structure={k:{q:v[q]for q in ['calls','callers','returns','own_instruction_occurrences','represented_bytes']}for k,v in a['structure'].items()},routes={k:counts(r['law']['route']for r in v)for k,v in a['cases'].items()},required_gate_classifier=[dict(call_step=r['call_step'],selector=r['law']['selector'],result=r['output']['a'],flags=r['output']['flags'])for r in a['cases']['PLI1.OVL+239A']if r['caller']=='PLI1.OVL+3FB7'],cleanup=[dict(call_step=r['call_step'],values={k:v for k,v in r['law'].items()if k!='children'},return_A=r['output']['a'],return_flags=r['output']['flags'])for r in a['cases']['PLI1.OVL+4601']])for a in analyses])
