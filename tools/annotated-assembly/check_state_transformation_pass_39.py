"""Accumulated natural field transformations, with explicit acquisition delegation."""
from check_acquisition_reentry_pass_38 import (ROOT,CAPTURES,gather,coord,require,pair,load,one,identity,body,children,compact_child,stack,chronology,summarize,rotate,verify_return,counts,ats,val,writes,cmp,arithmetic,validate_data_writers,delegated,encode_full_proof)
from check_small_gates_pass_37 import validate_classifier
from software_continuation import prove
from pathlib import Path
import json,hashlib
REPORT=ROOT/'research/host-compiler/pass-39'
ENTRIES=[0x30c1,0x2c59,0x22c0,0x2221,0x2fc2,0x2c53,0x21d4,0x25d6,0x28aa,0x834f]
BOUNDS={f'PLI1.OVL+{x:04X}':(x,x+1)for x in ENTRIES}
SOFTWARE={'PLI1.OVL+6708':8}
def local_proof(r):
 ws=r['own_witnesses'];validate_data_writers(r)
 for w in ws:
  arithmetic(w);op,_,arg=w['disassembly'].partition(' ')
  if op=='RAR':rotate(w)
  if op in ('LDA','LHLD'):
   a=int(arg[:-1],16);require([q['address']for q in w['reads']]==([a]if op=='LDA'else[a,(a+1)&65535]),'fresh literal/paired reads including discarded neighbors')
  elif op in ('MOV','CMP','ADD','SUB','ANA','ORA')and (arg.endswith(',M')or arg=='M'):
   require([q['address']for q in w['reads']]==[pair(w['before'],'h','l')],'read actual HL carrier, not equal-valued substitute')
  if op in ('JNC','JC','JZ','JNZ'):
   f=w['before']['flags'];taken={'JNC':not f['carry'],'JC':f['carry'],'JZ':f['zero'],'JNZ':not f['zero']}[op]
   require(w['control']['taken']==taken,'actual comparison/rotate flag selects branch')
  if op=='DAD':
   b=pair(w['before'],'h','l');d=pair(w['before'],*{'B':('b','c'),'D':('d','e'),'H':('h','l')}[arg])if arg!='SP'else w['before']['sp']
   require(pair(w['after'],'h','l')==(b+d)&65535 and w['after']['flags']==dict(w['before']['flags'],carry=b+d>65535),'DAD wrapping and independent CY')
 return ws

def mask_at(ws,offset,address,value):
 w=one(ws,offset);require(val(w,address)==value,'fresh independent field read');return value

def validate(r):
 ws=local_proof(r);e=r['entry']['before'];out=r['ret']['after'];k=r['entry_key'];cs=children(r)
 if k.endswith('834F'):
  d=pair(e,'d','e');lo=one(ws,0x834f)['reads'][0];hi=one(ws,0x8353)['reads'][0]
  require(lo['address']==d and hi['address']==(d+1)&65535,'independent little-endian addend reads, DE increments between them')
  low=e['l']|lo['value'];h=e['h']|hi['value']
  f=dict(sign=h>=128,zero=h==0,auxiliary_carry=False,parity=h.bit_count()%2==0,carry=False)
  delegated(out,e,a=h,d=((d+1)&65535)>>8,e=(d+1)&255,h=h,l=low&255,flags=f)
  require(not writes(ws)and not cs,'word-OR leaf no body CALL/PUSH or data publication')
  return dict(route='OR_word_at_DE',input_HL=pair(e,'h','l'),pointer=d,low=lo['value'],high=hi['value'],result=pair(out,'h','l'))
 if k.endswith('21D4'):
  x=val(one(ws,0x21d4),0xa632);y=val(one(ws,0x21dd),0xa633);m=255 if x==0 else 0;n=255 if y==0 else 0;a=m&n
  require(out['a']==a and out['b']==m and out['c']==m and out['flags']==dict(sign=a>=128,zero=a==0,auxiliary_carry=bool((m|n)&8),parity=a.bit_count()%2==0,carry=False),'two zero equality masks AND; final ANA flags independent of input flags')
  require(all(out[q]==e[q]for q in ['d','e','h','l'])and not writes(ws),'DE/HL preserved, only PSW residue')
  return dict(route='zero_masks_AND',A632=x,A633=y,result=a)
 if k.endswith('22C0'):
  require(len(cs)==1 and cs[0]['target']=='PLI1.OVL+21D4','zero-mask child once')
  v=rotate(one(ws,0x22c3));require(v['flags']['carry']and one(ws,0x22c4)['control']['taken'],'demonstrated set-bit shared RET, unsupported clear-bit arm')
  delegated(out,one(ws,0x22c3)['after']);require(not writes(ws),'no local data writes');return dict(route='both_zero_rotate_return',child_result=cs[0]['output']['a'])
 if k.endswith('2221'):
  c=e['c'];v=val(one(ws,0x222e),0xa628+c);require(v not in [0x24,0x25],'literal equality arms remain unsupported')
  for off in [0x2225,0x2237,0x2249]:require([q['address']for q in one(ws,off)['reads']]==[0xa649,0xa64a]and one(ws,off)['reads'][0]['value']==c,'three paired index rereads, adjacent byte read then discarded')
  for off in [0x222e,0x2240,0x2252]:require(val(one(ws,off),0xa628+c)==v,'selected byte reread per guard at declared nonaliasing scope')
  a=255 if 6<=v<=9 else 0;borrow=a==255
  require(out['a']==a and out['flags']==dict(sign=borrow,zero=not borrow,auxiliary_carry=not borrow,parity=True,carry=borrow),'wrapping SUI06 then SUI04 then borrow-mask result')
  require(pair(out,'b','c')==0xa628 and pair(out,'h','l')==0xa628+c and pair(out,'d','e')==pair(e,'d','e'),'indexed-mask ABI')
  return dict(route='nonspecial_range_mask',index=c,selected=v,result=a)
 if k.endswith('25D6'):
  require(len(cs)==1 and cs[0]['target']=='PLI1.OVL+23A0'and cs[0]['entry']['c']==e['c']and cs[0]['entry']['e']==0x10,'saved C, fresh paired read, cached unsigned min with16')
  j=cs[0]['output']['a'];rd=one(ws,0x25ea)['reads'][0];require(j==min(e['c'],16)and rd['address']==0x42dc+j,'clamped current byte lookup, no inferred table capacity')
  delegated(out,cs[0]['output'],a=rd['value'],b=0,c=j,h=(0x42dc+j)>>8,l=(0x42dc+j)&255,flags=dict(cs[0]['output']['flags'],carry=False))
  require([(q['address'],q['value'])for q in writes(ws)]==[(0xa65c,e['c'])],'only saved input data write; unconditional')
  return dict(route='clamped16_lookup',input=e['c'],discarded_neighbor=one(ws,0x25da)['reads'][1]['value'],index=j,address=rd['address'],value=rd['value'])
 if k.endswith('2FC2'):
  x=val(one(ws,0x2fc2),0xa62d);y=val(one(ws,0x2fc8),0xa630);selector=val(one(ws,0x2fce),0xa628);second=val(one(ws,0x2fd9),0xa62a)
  require(cs[0]['target']=='PLI1.OVL+213C'and cs[0]['entry']['c']==second,'fresh second selector membership helper')
  guard=(selector&0x11)==0x11 and (second==0x16 or bool(cs[0]['output']['a']&1))
  require(one(ws,0x2ff0)['control']['taken']==(not guard),'cached conjunction uses actual child bit, not returned flags')
  transformed=x;pos=1
  if guard:
   require(cs[pos]['target']=='PLI1.OVL+25D6'and cs[pos]['entry']['c']==x,'fresh paired cached primary passed to clamp lookup');transformed=cs[pos]['output']['a'];pos+=1
   require(y==0 and one(ws,0x3002)['control']['taken'],'nonzero second cached byte arm remains RAW')
  require(selector==0x15 and one(ws,0x3016)['control']['taken']==False and one(ws,0x3023)['control']['taken'],'supported selector15 resets extra; selector19 alternative remains RAW')
  extra=0;old_primary=val(one(ws,0x303a),0xa62b);newx=(transformed-y)&255
  require(cs[pos]['target']=='PLI1.OVL+23B9'and cs[pos]['entry']['c']==extra and cs[pos]['entry']['e']==y,'fresh extra and independently paired cached secondary maximum');m=max(extra,y);require(cs[pos]['output']['a']==m,'reuse cached max law');pos+=1
  require(cs[pos]['target']=='PLI1.OVL+23B9'and cs[pos]['entry']['c']==(old_primary-extra)&255 and cs[pos]['entry']['e']==newx,'fresh normalized primary and transformed cache maximum');primary=(cs[pos]['output']['a']+m)&255;pos+=1
  require(cs[pos]['target']=='PLI1.OVL+23A0'and cs[pos]['entry']['c']==primary,'final fresh primary/limiter comparison');lim=cs[pos]['entry']['e'];result=min(primary,lim);require(pos+1==len(cs),'exact helper count')
  expected=[(0xa663,x),(0xa664,y)]+([(0xa663,transformed)]if guard else[])+[(0xa62e,0),(0xa62b,(old_primary-extra)&255),(0xa663,newx),(0xa62e,m),(0xa62b,primary),(0xa62b,result)]
  require([(q['address'],q['value'])for q in writes(ws)]==expected,'ordered caches, fresh subtraction, two maxima, wrapping addition, limiter publication')
  delegated(out,cs[-1]['output']);return dict(route='selector15_transform'if guard else'selector15_no_transform',primary_cache=x,secondary_cache=y,second_selector=second,transformed=transformed,old_primary=old_primary,extra=m,primary=primary,limiter=lim,result=result)
 if k.endswith('30C1'):
  require([c['target']for c in cs]==['PLI1.OVL+22C0','PLI1.OVL+2221','PLI1.OVL+2221','PLI1.OVL+213C','PLI1.OVL+2FC2'],'exact complete/scoped children reused in historical order')
  x=val(one(ws,0x30c4),0xa629);y=val(one(ws,0x30e5),0xa62a)
  require(not any(v in [0x19,4,13]for v in [x,y])and one(ws,0x3109)['control']['taken'],'six independent equality masks clear; unobserved selector19 arm excluded')
  require(cs[1]['entry']['c']==1 and cs[2]['entry']['c']==2,'independent indexed-mask children')
  guard=x==0x15 or y==0x15 or bool(cs[1]['output']['a']&1)or bool(cs[2]['output']['a']&1)
  require(guard and not one(ws,0x313b)['control']['taken'],'equality/range OR selects literal15 publication')
  primary=val(one(ws,0x314b),0xa62c);extra=val(one(ws,0x3151),0xa62f);require(cs[3]['entry']['c']==x,'fresh predecessor selector membership')
  nextguard=(0x15&0x11)==0x11 and (x==0x16 or bool(cs[3]['output']['a']&1))
  require(not nextguard and one(ws,0x3179)['control']['taken'],'skip unobserved first-channel conversion')
  require([(q['address'],q['value'])for q in writes(ws)]==[(0xa628,0x15),(0xa665,primary),(0xa666,extra),(0xa62b,primary),(0xa62e,extra)],'selector publication precedes independent cache reads/republication')
  delegated(out,cs[-1]['output']);return dict(route='publish15_cache_then2FC2',first_selector=x,second_selector=y,primary=primary,extra=extra,result=out['a'])
 if k.endswith('2C53'):
  require(len(cs)==1 and cs[0]['target']=='PLI1.OVL+28AA'and cs[0]['entry']['c']==1,'C1 delegated acquisition parent, no invented semantics')
  delegated(out,cs[0]['output']);require(not writes(ws),'no wrapper nonstack writes');return dict(route='C1_delegate28AA')
 if k.endswith('2C59'):
  require([c['target']for c in cs]==['PLI1.OVL+2C53','PLI1.OVL+21AD'],'acquisition THEN fresh selected classifier')
  index=one(ws,0x2c5c)['reads'][0]['value'];selected=val(one(ws,0x2c65),0xa628+index)
  require(cs[1]['entry']['c']==selected and cs[1]['output']['a']&1,'fresh post-acquisition selector enters represented tests')
  # Every comparison/mask uses its own factual fresh read. No classifier shorthand replaces PSW provenance.
  require(index==2,'observed index is metadata/scope of unresolved acquisition; not a proposed native index whitelist')
  require(selected not in [0x2a,0x19,0x28,0x24,0x25,0x31]and selected!=0x16,'observed skip domain for selected byte')
  base=val(one(ws,0x2cc2),0xa628);require(base==0x15,'demonstrated skip path; other state-dependent transformation arms remain unsupported')
  require(not writes(ws),'local guard-only path has no data publications; acquisition effects remain separate')
  delegated(out,cs[1]['output'],a=base,b=0xa6,c=0x28,h=0xa6,l=0x28+index,flags=cmp(base,0x16))
  return dict(route='post_acquisition_skip_guards',index=index,selected=selected,base=base,result=out['a'],acquisition_return=cs[0]['output']['a'])
 raise ValueError(k)

def acquisition_interface(r):
 """Bounded substantial child interface only; do not assert a replacement law."""
 ws=r['own_witnesses'];cs=[]
 for w in ws:
  if w['control']['kind']!='call':continue
  q=r['nested_returns'][w['step_index']]
  if 'software_proof'in q:require(prove(q['software_proof'])==q['software_relation'],'existing eight-byte consumer proof reused')
  else:verify_return(w,q['ret'],q['relation'])
  cs.append(dict(site=w['origin']['offset'],target=coord(w.get('target_origin')),input=w['before'],C=w['before']['c'],E=w['before']['e'],return_A=q['ret']['after']['a'],return_flags=q['ret']['after']['flags'],call_step=w['step_index'],return_step=q['ret']['step_index'],software_argument_bytes=8 if 'software_proof'in q else 0))
 ix=one(ws,0x28ae)['reads'][0]['value'];sel=val(one(ws,0x28b7),0xa628+ix)
 targets=[c['target']for c in cs];route='selected02_copy'if sel==2 else('selected05_existing_scope'if sel==5 else'guard_only')

 if sel==2:
  require(cs[1]['target']=='PLI1.OVL+6708'and cs[1]['E']==2,'required alternate copy input differs from established E05 scope')
  nested=r['nested_returns'][one(ws,0x2985)['step_index']]['memory_witnesses'];require(any(w['origin']['offset']==0x67be for w in nested),'actual alternate arm reached, not static speculation')
 return dict(route=route,index=ix,selected=sel,children=cs,own_instructions=len(ws),own_writes_sha256=chronology(r)['cpu_nonstack_writes_sha256'],scope='Interface only; selected02 calls6708 with E02 entering substantial alternate67BE scope; no output-tuple semantics')

def analyze(rows,images):
 raws={n:(images/n).read_bytes()for n in ['PLI1.OVL','PLI.COM']};result={}
 for s,g in rows.items():
  result[s]={}
  for k,rs in g.items():
   result[s][k]=[]
   for r in rs:
    verify_return(r['call'],r['ret'],r['relation']);require(r['ret']['after']['sp']==r['entry']['before']['sp']+2,'ordinary original continuation')
    for w in body(r):
     name=w['origin']['image']['name'];o=w['origin']['offset'];require(raws[name][o:o+len(bytes.fromhex(w['bytes']))]==bytes.fromhex(w['bytes'])and w['runtime_pc']==o+(0x2200 if name=='PLI1.OVL'else 0x100),'immutable historical image/offset identity')
    law=acquisition_interface(r)if k.endswith('28AA')else validate(r)
    result[s][k].append(identity(r)|dict(law=law,stack=stack(r),chronology=chronology(r)))
 return result

def summary(rows,analyses):
 return {s:{k:dict(calls=len(rs),callers=counts(coord(r['call']['origin'])for r in rs),routes=counts(r['law']['route']for r in analyses[s][k]),returns=counts(coord(r['ret']['origin'])for r in rs))for k,rs in g.items()}for s,g in rows.items()}

def build_packet(rows,catalog):
 cfg={};routes={};patterns={};writers=[];cases=[];contracts={};sources=list(rows);callers=[]
 for source,g in rows.items():
  for key,rs in g.items():
   if key.endswith('28AA'):continue
   old={q[0]:q for q in cfg.get(key,[])}
   for r in rs:
    if not r:continue
    for w in r['own_witnesses']:
     o=w['origin']['offset'];raw=bytes.fromhex(w['bytes']);kind=w['control']['kind'];succ=[o+len(raw)]
     if kind=='return':succ=['outer_return']
     elif kind=='jump'and len(raw)==3:succ=[raw[1]+256*raw[2]-0x2200]+([]if w['disassembly'].startswith('JMP ')else[o+len(raw)])
     elif w['disassembly']=='PCHL':succ=['word[789F+2*saved_E] selected53BB']
     elif kind=='call':succ=[coord(w['target_origin']),o+len(raw)]
     old[o]=[o,w['bytes'],w['disassembly'],succ]
   cfg[key]=[old[o]for o in sorted(old)]
   for r in rs:
    cs=children(r)
    for c in cs:
     k=c['target'];p=catalog.get(k);contracts[k]=None if p is None else dict(id=k,sha256=hashlib.sha256(json.dumps(p,sort_keys=True).encode()).hexdigest(),completeness=p['completeness'])
    if key not in ['PLI1.OVL+30C1','PLI1.OVL+2C59']:continue
    own=r['own_witnesses'];S=r['entry']['before']['sp'];st=stack(r)
    layout=lambda a:['SP',a-S]if S-9<=a<S else a
    route=dict(entry=key,branches=[[w['origin']['offset'],w['control']['taken']]for w in own if w['control']['kind']=='jump'],write_layout=[[w['origin']['offset'],layout(q['address'])]for w in own for q in w['writes']if w['control']['kind']!='call'and not w['disassembly'].startswith('PUSH')],children=[[c['callsite'],c['target']]for c in cs])
    rid='r'+hashlib.sha256(json.dumps(route,sort_keys=True).encode()).hexdigest()[:8];pat=[]
    for q in st:
     if q['writer']not in writers:writers.append(q['writer'])
     # Full overwrite chronology is rederivable and hash-checked outside the view.
     pat.append([q['relative_address'],writers.index(q['writer'])])
    pid='s'+hashlib.sha256(json.dumps(pat).encode()).hexdigest()[:8]
    vals=lambda z:[z[k]for k in ['a','b','c','d','e','h','l','sp','pc']]+[int(z['flags']['sign'])*128+int(z['flags']['zero'])*64+int(z['flags']['auxiliary_carry'])*16+int(z['flags']['parity'])*4+int(z['flags']['carry'])]
    states=[vals(r['entry']['before']),vals(r['ret']['after'])];wv=[q['value']for q in writes(own)];sv=[q['value']for q in st]
    routes.setdefault(rid,route|dict(base_abi=states,base_write_values=wv));patterns.setdefault(pid,dict(writers=pat,base_values=sv))
    delta=lambda a,b:[[i,v]for i,v in enumerate(a)if b[i]!=v]
    caller=coord(r['call']['origin'])
    if caller not in callers:callers.append(caller)
    partial_io=[[c['entry']['a'],pair(c['entry'],'b','c'),pair(c['entry'],'d','e'),c['output']['a'],pair(c['output'],'b','c'),pair(c['output'],'d','e'),pair(c['output'],'h','l'),vals(c['output'])[-1]]for c in cs if catalog.get(c['target'],{}).get('completeness',{}).get('contract')!='complete']
    cases.append([sources.index(source),callers.index(caller),r['call']['step_index'],r['ret']['step_index'],rid,pid,delta(states[0],routes[rid]['base_abi'][0]),delta(states[1],routes[rid]['base_abi'][1]),delta(wv,routes[rid]['base_write_values']),delta(sv,patterns[pid]['base_values']),partial_io,chronology(r)['stack_writes_sha256']])
 return dict(baseline='fe6e25bdae01f787731cb45e1bef17296d7d3b2e',schema='compact-target-work-packet-v2',sources=sources,callers=callers,abi_columns=['A','B','C','D','E','H','L','SP','PC','SZAPC_bits'],case_columns=['source','caller','call','return','route','stack','entry_deltas','return_deltas','write_deltas','stack_deltas','partial_child_io','full_stack_chronology_hash'],partial_io_columns=['entryA','entryBC','entryDE','returnA','returnBC','returnDE','returnHL','returnSZAPC'],cfg=cfg,routes=routes,stack_writers=writers,stack_patterns=patterns,contracts=contracts,cases=cases,counts={s:{k:len(v)for k,v in g.items()}for s,g in rows.items()})
