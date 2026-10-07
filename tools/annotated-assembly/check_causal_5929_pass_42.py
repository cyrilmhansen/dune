"""Bounded pointer selection/constructor composition; source-derived continuation proof."""
from check_acquisition_pass_41 import (ROOT,CAPTURES,gather_selected,coord,require,pair,load,one,body,counts,ats,val,writes,cmp,local_proof,word_read,delegated,chronology,children_any,psw)
from check_5a46_pass_34 import validate_leaf as width_sum,validate_scan
from software_continuation import prove
from pathlib import Path
import json,hashlib
REPORT=ROOT/'research/host-compiler/pass-42';BASE='5531351f24cb7c34b81afd072b38633a5b6fdfde'
TARGETS=[0x5929,0x46a7,0x4651,0x4693,0x4468];HELPERS=[0x4562,0x452b,0x4584,0x422f,0x4275,0x4281,0x428e,0x419f,0x4394,0x83a0]
BOUNDS={f'PLI1.OVL+{o:04X}':(o,o+1)for o in TARGETS+HELPERS};SOFTWARE={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8}
def readword(r,address):
 xs=[q for w in body(r)for q in w['reads']];lo=next(q['value']for q in xs if q['address']==address);hi=next(q['value']for q in xs if q['address']==(address+1)&65535);return lo+256*hi

def known_leaf(r):
 ws=r['own_witnesses'];e=r['entry']['before'];out=r['ret']['after'];key=r['entry_key'];cs=children_any(r)
 if not key.endswith('83A0'):local_proof(r)
 if key.endswith('4562'):return width_sum(r)
 if key.endswith('4584'):return validate_scan(r)
 if key.endswith('422F'):
  j=one(ws,0x422f)['reads'][0]['value'];slot=(0xa761+2*j)&65535;p=one(ws,0x4239)['reads'][0]['value']+256*one(ws,0x423b)['reads'][0]['value'];require([one(ws,o)['reads'][0]['address']for o in [0x4239,0x423b]]==[slot,slot+1],'complete422F selected low/high slot reads')
  delegated(out,e,b=0xa7,c=0x61,d=(slot+1)>>8,e=(slot+1)&255,h=p>>8,l=p&255,flags=dict(e['flags'],carry=False));require([(q['address'],q['value'])for q in writes(ws)]==[(0xa863,p&255),(0xa864,p>>8)],'complete422F low/high working-pointer publication');return dict(index=j,slot=slot,pointer=p)
 if key.endswith('4275'):
  p=readword(r,0xa863);ref=readword(r,0xa8ab);n=(p-ref)&65535;borrow=p<ref;f=dict(sign=borrow,zero=not borrow,auxiliary_carry=not borrow,parity=True,carry=borrow)
  delegated(out,e,a=0 if borrow else 255,b=ref>>8,c=ref&255,d=0xa8,e=0x64,h=n>>8,l=n&255,flags=f);return dict(pointer=p,reference=ref,borrow=borrow,returned_bit=int(not borrow))
 if key.endswith('4281'):
  p=readword(r,0xa863);setbit=p!=0;f=dict(sign=setbit,zero=not setbit,auxiliary_carry=not setbit,parity=True,carry=setbit)
  delegated(out,e,a=255 if setbit else 0,d=0xa8,e=0x64,h=p>>8,l=p&255,flags=f);return dict(pointer=p,mask=out['a'])
 if key.endswith('428E'):
  p=word_read(one(ws,0x4291),0xa863);addr=(p+8)&65535;q=one(ws,0x4295)['reads'][0]['value']+256*one(ws,0x4297)['reads'][0]['value']
  require([one(ws,o)['reads'][0]['address']for o in [0x4295,0x4297]]==[addr,(addr+1)&65535],'complete428E +8 successor bytes');delegated(out,e,b=0,c=8,d=((addr+1)&65535)>>8,e=(addr+1)&255,h=q>>8,l=q&255,flags=dict(e['flags'],carry=p+8>65535));return dict(pointer=p,successor=q)
 if key.endswith('419F'):
  p=word_read(one(ws,0x419f),0xa863);addr=(p+2)&65535;rd=one(ws,0x41a4)['reads'][0];require(rd['address']==addr,'complete419F fresh pointer+2 source');delegated(out,e,a=rd['value'],h=addr>>8,l=addr&255);return dict(pointer=p,address=addr,value=rd['value'])
 if key.endswith('4394'):
  n=e['c'];P=word_read(one(ws,0x4398),0x1c36);p=(P-9-n)&65535;limit=pair(one(ws,0x43af)['after'],'h','l')
  require(p>=limit,'reused allocator guard-success scope only');require(pair(one(ws,0x43ab)['before'],'h','l')==p,'two existing decrement helpers derive selected allocation pointer')
  size=(n+10)&255;expected=[(0xa8f6,n),(0xa863,p&255),(0xa864,p>>8),(0x1c36,(p-1)&255),(0x1c37,((p-1)&65535)>>8),(p,size),((p+1)&65535,0)]
  require([(q['address'],q['value'])for q in writes(ws)]==expected,'existing allocator success publication order, no floor/failure extension');delegated(out,e,a=size,b=0,c=n,d=p>>8,e=p&255,h=((p+1)&65535)>>8,l=(p+1)&255,flags=one(ws,0x43c8)['after']['flags']);return dict(count=n,old_top=P,pointer=p,limit=limit,size=size)
 if key.endswith('83A0'):
  addr=pair(e,'h','l');word=readword(r,addr);n=(-word)&65535;require(e['a']==0,'required complete read-only negation child input');hi=n>>8;f=dict(sign=hi>=128,zero=hi==0,auxiliary_carry=((word>>8)&15)+int(bool(word&255))==0,parity=hi.bit_count()%2==0,carry=word!=0);delegated(out,e,a=hi,d=((addr+1)&65535)>>8,e=(addr+1)&255,h=hi,l=n&255,flags=f);return dict(address=addr,word=word,negated=n)
 return dict(scope='reused complete452B child law',count=e['e'])

def derived_stack(r):
 S=r['entry']['before']['sp'];upper=S+4 if r['entry_key'].endswith('4468')else S;last={}
 for w in body(r):
  if w['control']['kind']=='call'and w['control']['taken']:v=w['call_return_address']
  elif w['disassembly'].startswith('PUSH '):
   z=w['before'];arg=w['disassembly'][5:];v=z['a']*256+psw(z['flags'])if arg=='PSW'else pair(z,*{'B':('b','c'),'D':('d','e'),'H':('h','l')}[arg])
  else:continue
  sp=w['before']['sp'];expected=[(sp-1,v>>8),(sp-2,v&255)];require([(q['address'],q['new_value'])for q in w['writes']]==expected,'stack bytes derived from CALL/PUSH operand, PSW and actual depth')
  for address,value in expected:
   if address<upper:last[address]=dict(relative_address=address-S,value=value,writer=coord(w['origin']),step=w['step_index'],stack_depth=S-sp)
 return [last[n]for n in sorted(last)]

def constructor(r,by):
 ws=local_proof(r);e=r['entry']['before'];out=r['ret']['after'];cs=children_any(r);relation=prove(r['software_proof']);n=e['c'];tag=e['e'];src=pair(one(ws,0x4470)['after'],'b','c')
 require(relation['consumed_caller_bytes']==2,'existing N2 continuation consumption')
 require(out['sp']==e['sp']+4 and out['pc']==r['call']['call_return_address'],'copied continuation RET consumes one caller argument word')
 alloc=known_leaf(by[cs[0]['call_step']]);require(cs[0]['target']=='PLI1.OVL+4394'and cs[0]['entry']['c']==n,'constructor fresh saved count -> existing guard-success allocator');p=alloc['pointer']
 require(word_read(one(ws,0x447c),0xa863)==p,'fresh allocated pointer before header publication');own=[(q['address'],q['value'])for q in writes(ws)];expected=[(0xa900,tag),(0xa8ff,n),(0xa8fe,src>>8),(0xa8fd,src&255),(p+2,tag)]+[(p+k,0)for k in [3,4,5,8,9,6,7]]
 payload=[]
 for index,(dec,rd,store)in enumerate(zip(ats(ws,0x44c0),ats(ws,0x44d8),ats(ws,0x44d9))):
  j=n-index-1;require(dec['writes'][0]['new_value']==j and rd['reads'][0]['address']==(src+j)&65535 and store['writes'][0]['address']==(p+10+j)&65535,'descending payload copy with fresh index and independent source/destination');value=rd['reads'][0]['value'];require(store['writes'][0]['new_value']==value,'current source byte published unconditionally');expected.extend([(0xa8ff,j),((p+10+j)&65535,value)]);payload.append([j,value])
 require(len(payload)==n,'complete selected payload, duplicates retained');slot=known_leaf(by[cs[1]['call_step']]);mask=known_leaf(by[cs[2]['call_step']]);require([c['target']for c in cs[:3]]==['PLI1.OVL+4394','PLI1.OVL+422F','PLI1.OVL+4281'],'existing constructor prefix child order')
 require(one(ws,0x44e4)['control']['taken']==(mask['pointer']!=0),'RAR uses null-mask bit; no value-only ancestry')
 if mask['pointer']==0:
  require(len(cs)==3 and not ats(ws,0x4506),'existing empty-slot arm, no chain traversal');newp=(word_read(one(ws,0x44e7),0x1c36)+1)&65535;selected=0xa761+2*one(ws,0x44ec)['reads'][0]['value'];require(selected==slot['slot']and newp==p,'fresh index reread and fresh top+1, separate from earlier slot result');expected.extend([(selected,p&255),(selected+1,p>>8)]);route='existing_empty_slot';delegated(out,e,a=0,b=p>>8,c=p&255,d=0xa8,e=0x64,h=p>>8,l=p&255,flags=cs[2]['output']['flags'])
 else:
  q=mask['pointer'];walk=[];pos=3
  for c in cs[3:]:
   law=known_leaf(by[c['call_step']]);walk.append(dict(target=c['target'],**law))
   if c['target'].endswith('83A0'):require(law['address']==(q+8)&65535,'fresh successor word negation, fullword ORA test')
   elif c['target'].endswith('428E'):require(law['pointer']==q,'independent successor follow after nonzero test');q=law['successor']
   else:raise ValueError('unsupported constructor descendant')
  require(walk[-1]['target'].endswith('83A0')and walk[-1]['word']==0,'observed zero successor terminates traversal; no arbitrary-chain claim');newp=(word_read(one(ws,0x4513),0x1c36)+1)&65535;require(newp==p,'fresh top+1 after read-only traversal');address=(q+8)&65535;expected.extend([(address,p&255),((address+1)&65535,p>>8)]);route='existing_nonempty_terminal_link';delegated(out,e,a=0,b=p>>8,c=p&255,d=((q+9)&65535)>>8,e=(q+9)&255,h=p>>8,l=p&255,flags=dict(sign=False,zero=True,auxiliary_carry=False,parity=True,carry=False))
 expected.extend([(0xa863,p&255),(0xa864,p>>8)]);require(own==expected,'constructor own ordered writes; child allocator/pointer effects remain separate');return dict(route=route,count=n,tag=tag,source=src,pointer=p,slot=slot['slot'],payload=payload,software=relation,scope='Reused Pass13 empty and earlier nonempty bounded paths, no widened allocator/traversal contract')

def selection(r,by):
 ws=local_proof(r);e=r['entry']['before'];out=r['ret']['after'];cs=children_any(r);require([(q['address'],q['value'])for q in writes(ws)]==[(0xa90f,e['c'])],'save selector once; child publications separate')
 require([c['target']for c in cs[:2]]==['PLI1.OVL+4562','PLI1.OVL+422F'],'current-prefix sum then selected-slot read');summed=known_leaf(by[cs[0]['call_step']]);slot=known_leaf(by[cs[1]['call_step']]);pos=2;comparisons=[]
 while True:
  c=cs[pos];require(c['target']=='PLI1.OVL+4275','fresh working/reference comparison each iteration');law=known_leaf(by[c['call_step']]);comparisons.append(law);pos+=1
  if not law['returned_bit']:break
  c=cs[pos];require(c['target']=='PLI1.OVL+428E','at/above-reference pointer follows fresh +8 successor');known_leaf(by[c['call_step']]);pos+=1
 c=cs[pos];require(c['target']=='PLI1.OVL+4281','null-mask AFTER traversal');null=known_leaf(by[c['call_step']]);pos+=1
 if null['pointer']==0:
  require(pos==len(cs) and r['ret']['origin']['offset']==0x4692,'null pointer follows direct sharedRET');delegated(out,one(ws,0x466b)['after']);route='null_after_reference_walk'if len(comparisons)>1 else'null_selected_slot'
 else:
  c=cs[pos];require(c['target']=='PLI1.OVL+4584'and pair(c['entry'],'b','c')==0x20c6,'paired width/source -> existing payload match');paired=word_read(one(ws,0x466f),0x20c5);require(pair(c['entry'],'d','e')==paired,'neighbor first prefix byte read asD, lowwidthE retained');match=known_leaf(by[c['call_step']]);require(match['route']=='positive_exact_payload_match','required match scope; retry/floor alternatives not generalized');pos+=1
  c=cs[pos];require(c['target']=='PLI1.OVL+4281','fresh null recheck after payload comparison');fresh=known_leaf(by[c['call_step']]);require(fresh['pointer']==null['pointer']and fresh['mask']!=0,'existing payload match leaves current pointer, actualnonnull bit branches');pos+=1
  c=cs[pos];require(c['target']=='PLI1.OVL+419F','fresh pointer+2 tag read');tag=known_leaf(by[c['call_step']]);pos+=1;saved=val(one(ws,0x4687),0xa90f);require(tag['value']==saved and saved==e['c']and pos==len(cs),'required saved-tag equality; mismatches remain RAW')
  delegated(out,c['output'],h=0xa9,l=0x0f,flags=cmp(tag['value'],saved));route='existing_payload_and_tag_match'
 return dict(route=route,input=e['c'],sum=summed['result'],slot=slot['slot'],initial_pointer=slot['pointer'],comparisons=comparisons,result_A=out['a'],returned_pointer=null['pointer'])

def gate(r,by):
 ws=local_proof(r);e=r['entry']['before'];out=r['ret']['after'];cs=children_any(r);require([(q['address'],q['value'])for q in writes(ws)]==[(0xa911,e['c'])],'outer tag saved at distinctA911')
 paired=word_read(one(ws,0x46ab),0xa911);require(paired&255==e['c']and cs[0]['entry']['c']==paired&255,'actual paired read; low only ->selection')
 choose=selection(by[cs[0]['call_step']],by);null=known_leaf(by[cs[1]['call_step']]);require(cs[1]['target']=='PLI1.OVL+4281','independent fresh null-mask, not4651 returnedA')
 if null['pointer']:
  require(len(cs)==2 and one(ws,0x46b6)['control']['taken'],'nonnull working pointer skips constructor');delegated(out,one(ws,0x46b5)['after']);route='reuse_nonnull'
 else:
  require(len(cs)==3 and not one(ws,0x46b6)['control']['taken']and cs[2]['target']=='PLI1.OVL+4693','zero working pointer invokes constructor after fresh tag reread');tag=word_read(one(ws,0x46b9),0xa911)&255;require(cs[2]['entry']['c']==tag,'fresh savedtag feeds wrapper, no reuse of earlierC');child=wrapper(by[cs[2]['call_step']],by);delegated(out,cs[2]['output']);route=child['constructor']['route']
 return dict(route=route,input=e['c'],selection=choose,null_mask=null['mask'],result_A=out['a'])

def wrapper(r,by):
 ws=local_proof(r);e=r['entry']['before'];out=r['ret']['after'];cs=children_any(r);require(len(cs)==1 and cs[0]['target']=='PLI1.OVL+4468','one native-ready bounded constructor child')
 require([(q['address'],q['value'])for q in writes(ws)]==[(0xa910,e['c'])],'saved tag distinct from outerA911');count=word_read(one(ws,0x469b),0x20c5)&255;tagword=word_read(one(ws,0x469f),0xa910);c=cs[0];require(c['entry']['c']==count and pair(c['entry'],'d','e')==tagword,'fresh width low and independent tag/neighbor pair supplied')
 push=one(ws,0x469a);require([(q['address'],q['new_value'])for q in push['writes']]==[(e['sp']-1,0x20),(e['sp']-2,0xc6)],'original caller-owned source argument20C6, high thenlow')
 constructor_r=by[c['call_step']];law=constructor(constructor_r,by);require(law['source']==0x20c6 and law['tag']==e['c'],'POP argument provenance from caller-owned PUSH; savedtag is not copiedcontinuation');delegated(out,c['output']);require(out['sp']==e['sp']+2,'constructor consumesargument; wrapper consumes onlyouteroriginalword')
 return dict(route='reused_constructor_wrapper',input_tag=e['c'],discarded_tag_neighbor=tagword>>8,count=count,constructor=law)

# Parent local proof reuses Pass32 structure and Pass41 acquisition interface.
def parent(r,by):
 ws=local_proof(r);e=r['entry']['before'];out=r['ret']['after'];cs=children_any(r);require([c['target']for c in cs]==['PLI1.OVL+57B7','PLI1.OVL+46A7','PLI1.OVL+239A','PLI1.OVL+2511','PLI1.OVL+784E'],'exact required child sequence, not flattened transformation')
 require(pair(cs[0]['entry'],'b','c')==0x7923 and cs[0]['output']['a']==1 and not one(ws,0x5930)['control']['taken'],'existing bounded57B7 foundbit ->RAR/JNC continuation')
 pairword=word_read(one(ws,0x5933),0x20c3);require(cs[1]['entry']['c']==pairword&255,'fresh paired context supplieslowC togate')
 law=gate(by[cs[1]['call_step']],by);require(not any(q['address']==0x20c3 for w in body(by[cs[1]['call_step']])for q in w['writes']),'gate leaves selector carrier distinct from its returnedA');selector=val(one(ws,0x5948),0x20c3);require(selector not in[3,4,7,8,9],'unobserved selector alternatives remain outside bounded scope');p=word_read(one(ws,0x593a),0xa863);width=val(one(ws,0x594e),0x20c5)
 expected=[(0xa63b,p&255),(0xa63c,p>>8),(0xa635,p&255),(0xa636,p>>8),(0xa631,0),(0xa628,selector),(0xa62b,width),(0xa62e,0),((p+4)&65535,width),((p+5)&65535,0)]
 require([(q['address'],q['value'])for q in writes(ws)]==expected,'ordered independent pointer/selector/width/extra publications')
 require(word_read(one(ws,0x5a23),0xa863)==p and word_read(one(ws,0x5a2b),0xa863)==p,'two independent fresh pointer rereads before+4/+5 writes');require(cs[3]['entry']['c']==(cs[2]['output']['a']+1)&255,'fresh239A ->wrapping INR ->2511, notgateA')
 delegated(out,cs[-1]['output']);return dict(route='found_nonspecial',input_selector=pairword&255,gate_A=cs[1]['output']['a'],fresh_selector=selector,pointer=p,width=width,result239A=cs[2]['output']['a'],input2511=cs[3]['entry']['c'],gate_route=law['route'],final_acquisition_call=cs[-1]['call_step'])

def analyze(rows,images):
 result={};raw=(Path(images)/'PLI1.OVL').read_bytes()
 for source,g in rows.items():
  by={r['call']['step_index']:r for rs in g.values()for r in rs};result[source]={}
  for key in [f'PLI1.OVL+{x:04X}'for x in TARGETS]:
   result[source][key]=[]
   for r in g[key]:
    if key.endswith('4468'):prove(r['software_proof'])
    else:
     from check_acquisition_pass_41 import verify_return
     verify_return(r['call'],r['ret'],r['relation'])
    for w in r['own_witnesses']:
     require(w['origin']['image']['name']=='PLI1.OVL'and w['runtime_pc']==w['origin']['offset']+0x2200 and raw[w['origin']['offset']:w['origin']['offset']+len(bytes.fromhex(w['bytes']))]==bytes.fromhex(w['bytes']),'exact canonical image/offset/encoding')
    law=parent(r,by)if key.endswith('5929')else gate(r,by)if key.endswith('46A7')else selection(r,by)if key.endswith('4651')else wrapper(r,by)if key.endswith('4693')else constructor(r,by)
    result[source][key].append(dict(call=r['call']['step_index'],ret=r['ret']['step_index'],caller=coord(r['call']['origin']),entry=r['entry']['before'],output=r['ret']['after'],law=law,stack=derived_stack(r),chronology=chronology(r)))
 return result

def acquisition_compatibility(rows):
 old=load(ROOT/'research/host-compiler/pass-41/work-packet.json');lookup={(q[0],q[2]):q for q in old['cases']};encode=lambda z:[z[k]for k in['a','b','c','d','e','h','l','sp','pc']]+[psw(z['flags'])];result=[]
 for source,g in rows.items():
  for r in g['PLI1.OVL+5929']:
   c=children_any(r)[-1];q=lookup[(source,c['call_step'])];require(c['target']=='PLI1.OVL+784E'and q[1]=='PLI1.OVL+5A3C'and q[3]==c['return_step']and q[6]==encode(c['entry'])and q[7]==encode(c['output']),'independent Pass41 acquisition case exact input/output/continuation ABI')
   result.append(dict(source=source,parent_call=r['call']['step_index'],acquisition_call=c['call_step'],ret=c['return_step'],prefix=q[8],following=q[9],entry=encode(c['entry']),output=encode(c['output'])))
 return result

def projection(rows,a):
 return {key:dict(counts={s:len(g[key])for s,g in rows.items()},callers=counts(coord(r['call']['origin'])for g in rows.values()for r in g[key]),routes={s:counts(q['law']['route']for q in g[key])for s,g in a.items()})for key in next(iter(a.values()))}

def build_packet(rows,a,catalog):
 cfg={};routes={};patterns={};cases=[];contracts={};encode=lambda z:[z[k]for k in['a','b','c','d','e','h','l','sp','pc']]+[psw(z['flags'])]
 for source,g in a.items():
  for key,qs in g.items():
   for r,q in zip(rows[source][key],qs):
    # Reuse constructor complete bytes/contracts; record required software/window values only.
    if key.endswith('4468'):continue
    union=cfg.setdefault(key,{})
    for w in r['own_witnesses']:union[w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
    for c in children_any(r):
     p=catalog.get(c['target']);contracts[c['target']]=None if p is None else dict(id=c['target'],sha256=hashlib.sha256(json.dumps(p,sort_keys=True).encode()).hexdigest(),completeness=p['completeness'])
    layout=[[w['origin']['offset'],t['address']]for w in r['own_witnesses']for t in w['writes']if not w['disassembly'].startswith('PUSH')and w['control']['kind']!='call'];skeleton=dict(entry=key,route=q['law']['route'],children=[[c['callsite'],c['target']]for c in children_any(r)],write_layout=layout);rid='r'+hashlib.sha256(json.dumps(skeleton,sort_keys=True).encode()).hexdigest()[:8];routes.setdefault(rid,skeleton)
    pat=[[v['relative_address'],v['writer'],v['stack_depth']]for v in q['stack']];pid='s'+hashlib.sha256(json.dumps(pat).encode()).hexdigest()[:8];patterns.setdefault(pid,pat)
    law=q['law'];summary={k:v for k,v in law.items()if k not in['selection','constructor']}
    if 'selection'in law:summary['selection_route']=law['selection']['route']
    if 'constructor'in law:summary.update(constructor_route=law['constructor']['route'],constructor_pointer=law['constructor']['pointer'],source_argument=law['constructor']['source'],consumed_bytes=2,constructor_entrySP=children_any(r)[0]['entry']['sp'],copied_continuation=children_any(r)[0]['output']['pc'])
    cases.append([source,q['caller'],q['call'],q['ret'],rid,pid,encode(q['entry']),encode(q['output']),summary])
 return dict(schema='compact-target-work-packet-v2',baseline=BASE,CFG={k:sorted(v.values())for k,v in cfg.items()},routes=routes,stack_patterns=patterns,contracts=contracts,cases=cases,columns=['source','caller','call','ret','route','stack','entry_ABI','output_ABI','value_differences'],ABI_columns=['A','B','C','D','E','H','L','SP','PC','PSW'],inventory=projection(rows,a),acquisition_compatibility_hash=hashlib.sha256(json.dumps(acquisition_compatibility(rows),sort_keys=True).encode()).hexdigest())

def encode_full_proof(rows,a):
 steps={};windows=[]
 for source,g in rows.items():
  union=steps.setdefault(source,{})
  for key,rs in g.items():
   for r in rs:
    for w in body(r):
     n=str(w['step_index']);require(n not in union or union[n]==w,'one factual step, independent windows share source identity');union[n]=w
    windows.append(dict(source=source,key=key,call=r['call']['step_index'],ret=r['ret']['step_index'],own=[w['step_index']for w in r['own_witnesses']],children=children_any(r),software=r.get('software_relation')))
 return(json.dumps(dict(steps=steps,windows=sorted(windows,key=lambda r:(r['source'],r['key'],r['call'])),analysis=a,acquisition=acquisition_compatibility(rows)),sort_keys=True,separators=(',',':'))+'\n').encode()
