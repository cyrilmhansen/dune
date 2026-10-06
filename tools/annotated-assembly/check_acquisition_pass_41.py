"""Accumulated acquisition proof; required non-refill scope stays distinct from independent reader alternatives."""
from check_selector02_pass_40 import (ROOT,CAPTURES,gather_selected,SOFTWARE,coord,require,pair,load,one,body,counts,ats,val,writes,cmp,arithmetic,stack_extended,children_any,word_read,delegated,verify_return,chronology)
from check_state_transformation_pass_39 import local_proof as old_local
from check_3dd9_pass_35 import psw
from pathlib import Path
import json,hashlib
REPORT=ROOT/'research/host-compiler/pass-41'
BOUNDS={'PLI1.OVL+784E':(0x784e,0x7a15),**{f'PLI.COM+{x:04X}':(x,x+1)for x in [0x1376,0x12d9,0x12ae,0x15da,0x15e3,0x15f9,0x1616,0x1627]},**{f'PLI1.OVL+{x:04X}':(x,x+1)for x in [0x5e98,0x5929]}}

def local_proof(r):
 ordinary=[]
 for w in r['own_witnesses']:
  op,_,arg=w['disassembly'].partition(' ')
  if op in ['INR','DCR']:
   v=w['reads'][0]['value']if arg=='M'else w['before'][arg.lower()];inc=op=='INR';n=(v+(1 if inc else-1))&255;f=dict(sign=n>=128,zero=n==0,auxiliary_carry=(v&15)==15 if inc else(v&15)!=0,parity=n.bit_count()%2==0,carry=w['before']['flags']['carry'])
   require(w['after']['flags']==f,'exact INR/DCR flag producer with inherited CY')
   if arg=='M':require([(q['address'],q['new_value'])for q in w['writes']]==[(pair(w['before'],'h','l'),n)],'current memory carrier modified unconditionally')
   else:require(w['after'][arg.lower()]==n,'byte-width register modification')
  elif op=='ADD':
   a=w['before']['a'];b=w['reads'][0]['value']if arg=='M'else w['before'][arg.lower()];n=(a+b)&255;require(w['after']['a']==n and w['after']['flags']==dict(sign=n>=128,zero=n==0,auxiliary_carry=(a&15)+(b&15)>15,parity=n.bit_count()%2==0,carry=a+b>255),'ADD wrapping and independent flags')
  elif op=='CMA':require(w['after']['a']==w['before']['a']^255 and w['after']['flags']==w['before']['flags'],'complement preserves actual child flags')
  else:ordinary.append(w)
 old_local(dict(r,own_witnesses=ordinary));return r['own_witnesses']

def indexed_reader(r):
 ws=local_proof(r);e=r['entry']['before'];out=r['ret']['after'];idx=val(one(ws,0x12b1),0x1f06);count=val(one(ws,0x12b4),0x1f08)
 require(idx<count and not children_any(r),'required immediate counted-read scope, no refill/retry delegation')
 rd=one(ws,0x12d7)['reads'][0];address=0x1e8e+idx;require(rd['address']==address,'fresh counted-buffer source at old index')
 require([(q['address'],q['value'])for q in writes(ws)]==[(0x1f06,(idx+1)&255)],'index increment published before source read')
 flags=dict(sign=idx>=128,zero=idx==0,auxiliary_carry=((idx+1)&15)!=0,parity=idx.bit_count()%2==0,carry=False)
 delegated(out,e,a=rd['value'],b=0,c=idx,h=address>>8,l=address&255,flags=flags)
 return dict(index=idx,count=count,address=address,value=rd['value'],next_index=(idx+1)&255)

def mask_result(r):
 ws=local_proof(r);e=r['entry']['before'];out=r['ret']['after'];k=r['entry_key'];cs=children_any(r)
 if k.endswith('1616'):
  require(len(cs)==1 and cs[0]['target']=='PLI.COM+0817','single complete conditional-mask child')
  raw=e['c'];masked=raw&0x5f if raw>0x5f else raw;require(cs[0]['entry']['c']==raw and cs[0]['output']['a']==masked,'fresh paired scratch low argument, independent child result')
  word_read(one(ws,0x161a),0x2149);result=255 if masked==0x45 else 0;f=dict(sign=result>=128,zero=result==0,auxiliary_carry=result==0,parity=True,carry=result!=0)
  delegated(out,cs[0]['output'],a=result,flags=f);require([(q['address'],q['value'])for q in writes(ws)]==[(0x2149,raw)],'only own scratch byte, child208F remains distinct')
  return dict(route='masked_equal45',input=raw,masked=masked,result=result,discarded_neighbor=one(ws,0x161a)['reads'][1]['value'])
 if k.endswith('1627'):
  width=val(one(ws,0x162c),0x20c5);context=val(one(ws,0x1639),0x20c1);old=val(one(ws,0x1649),0x1c58);result=(old+context)&15
  require(width<=127,'overflow route remains unsupported');require(val(one(ws,0x1643),0x20c1)==context,'independent context reread before accumulator addition')
  require([(q['address'],q['value'])for q in writes(ws)]==[(0x20c6+width,context),(0x20c5,(width+1)&255),(0x1c58,result)],'prefix byte then width then modulo16 accumulator; same-valued writes retained')
  delegated(out,e,a=result,b=0x20,c=0xc5,h=0x1c,l=0x58,flags=one(ws,0x164a)['after']['flags'])
  return dict(route='bounded_append',width=width,context=context,old_accumulator=old,result=result)
 return dict(route='reused_complete_or_bounded_classifier',input=e['c'],A=out['a'])

def required_acquisition(r,reader_by_step,append_by_step):
 ws=local_proof(r);e=r['entry']['before'];out=r['ret']['after'];cs=children_any(r);by={c['call_step']:c for c in cs}
 require(not val(one(ws,0x137e),0x2012)&1 and not val(one(ws,0x1393),0x20c4)&1,'EOF and reuse guards clear at required scope')
 require([(q['address'],q['value'])for q in writes(ws)[:5]]==[(0x2088,0),(0x2087,0),(0x1c58,0),(0x20c5,0),(0x20c3,0)],'reset order before acquisition, physical prefix buffer retained')
 context=val(ats(ws,0x13ad)[0],0x20c1);initial=context;reads=[];prefix=[];acc=0;last_index=None
 # Actual fresh context loop decisions, with each reader independently proved.
 def checked_read(c):
  nonlocal last_index
  if c['target'].endswith('12D9'):
   wrapper=reader_by_step[c['call_step']];inner=children_any(wrapper)[0];v=indexed_reader(reader_by_step[inner['call_step']]);masked=v['value']&0x5f if v['value']>0x5f else v['value'];require(c['output']['a']==masked and c['output']['c']==v['value'],'adapter read followed by existing mask helper');value=masked
  else:v=indexed_reader(reader_by_step[c['call_step']]);value=v['value']
  if last_index is not None:require(v['index']==last_index,'fresh current reader index follows prior publication without refill')
  last_index=v['next_index'];reads.append(dict(call=c['call_step'],site=c['callsite'],**v,returned=value));return value
 pos=0
 while context in [0,0x20]:
  c=cs[pos];require(c['target']=='PLI.COM+12D9'and c['callsite']==0x13c5,'zero/space context requires counted adapter read');context=checked_read(c);pos+=1
 c=cs[pos];require(c['target']=='PLI.COM+15E3'and c['callsite']==0x13ce,'fresh context classifier precedes selected dispatch');letter=0x41<=context<=0x5a or context==0x3f;require(bool(c['output']['a']&1)==letter,'complete interval/equality predicate reused');pos+=1
 if letter:selector=1
 else:
  c=cs[pos];require(c['target']=='PLI.COM+15DA'and c['callsite']==0x13dd and not c['output']['a']&1,'required nonnumeric dispatch');pos+=1;require(context!=0x27,'quoted-byte acquisition is not required scope');selector=10
 append_index=0
 while True:
  c=cs[pos];require(c['target']=='PLI.COM+1627'and c['callsite']==0x1411,'append current context BEFORE reading following byte');q=mask_result(append_by_step[c['call_step']]);require(q['width']==len(prefix)and q['context']==context and q['old_accumulator']==acc,'current prefix/accumulator, no precomputed source schedule');acc=q['result'];prefix.append(context);pos+=1
  c=cs[pos];require(c['target']=='PLI.COM+12AE'and c['callsite']==0x141a,'following raw read after append');raw=checked_read(c);pos+=1
  c=cs[pos];require(c['target']=='PLI.COM+0817'and c['entry']['c']==raw,'fresh following byte -> conditional mask');context=raw&0x5f if raw>0x5f else raw;require(c['output']['a']==context,'complete conditional transform law');pos+=1
  if selector==10:
   c=cs[pos];require(c['target']=='PLI.COM+15DA'and c['callsite']==0x1443,'independent following-digit predicate');require(not(prefix[-1]==0x2e and c['output']['a']&1),'unobserved dot/digit rewrite excluded');pos+=1;break
  c=cs[pos];require(c['target']=='PLI.COM+15F9'and c['callsite']==0x145a,'fresh continuation child');cont=0x41<=context<=0x5a or context in [0x3f,0x5f]or 0x30<=context<=0x39;require(bool(c['output']['a']&1)==cont,'existing continuation bit law, flags are separate outputs');pos+=1
  if not cont:break
 if selector==1:
  require(len(cs)==pos+1 and cs[pos]['target']=='PLI.COM+1A40','zero-word lookup follows continuation termination')
  slot=0x1c38+2*acc;low=one(ws,0x146c)['reads'][0];high=one(ws,0x146e)['reads'][0];require((low['address'],high['address'])==(slot,slot+1),'fresh accumulator-selected word bytes');word=low['value']+256*high['value'];require(word==0,'required zero-word finish, nonzero lookup alternative remains unsupported')
  delegated(out,e,a=0,b=0x1c,c=0x38,d=0x1c,e=0x5a,h=0,l=0,flags=dict(sign=False,zero=True,auxiliary_carry=False,parity=True,carry=False))
 else:
  require(len(cs)==pos,'single-byte0A acquisition finishes after tested following context');delegated(out,e,a=10,b=0,c=0,h=0x20,l=0x8f,flags=cmp(10,5))
 # Logical own writes and child publication sources jointly prove chronology.
 following=ats(ws,0x141d);masked=ats(ws,0x142f);previous=ats(ws,0x1417)
 require(len(following)==len(prefix)==len(masked)==len(previous),'one previous/raw/masked publication per acquired byte')
 for i in range(len(prefix)):
  require(previous[i]['writes'][0]['new_value']==prefix[i] and following[i]['step_index']<masked[i]['step_index'],'retain old context independently before read; raw publication before transformed publication')
 return dict(route='selector01_zero_word'if selector==1 else'selector0A_single_byte',initial_context=initial,selector=selector,prefix=prefix,width=len(prefix),accumulator=acc,following=context,reads=reads,return_A=out['a'])

def validate_784e(r):
 ws=local_proof(r);e=r['entry']['before'];out=r['ret']['after'];cs=children_any(r);require(cs[0]['target']=='PLI.COM+1376','resident acquisition is first child, arguments not guessed')
 selector=val(one(ws,0x7851),0x20c3);first=val(one(ws,0x785a),0x20c6);context=val(one(ws,0x7866),0x20c1)
 require(not(selector==10 and first==47 and context==42),'unobserved triple rewrite scope excluded')
 for sub,add,mask,k in [(0x78a6,0x78a8,0x78aa,10),(0x78af,0x78b1,0x78b3,1)]:
  difference=(selector-k)&255;require(one(ws,sub)['after']['a']==difference and one(ws,add)['after']['flags']['carry']==(difference!=0)and one(ws,mask)['after']['a']==(255 if difference!=0 else 0),'SUI wrapped difference -> ADIFF carry -> selfSBB inequality mask')
 require(one(ws,0x78b8)['control']['taken']==(selector in [1,10]),'conjunction of inequality masks selects passthrough or handling')
 if selector not in [1,10]:
  require(not writes(ws),'passthrough has no own data publication');delegated(out,one(ws,0x78b7)['after']);return dict(route='passthrough',selector=selector,first=first,context=context,A=out['a'])
 if selector==10:
  require(first not in [0x21,0x5c,0x2a,0x2d,0x3c,0x3e,0x5e],'unobserved literal rewrite arms excluded')
  require([(q['address'],q['value'])for q in writes(ws)]==[(0x20c3,first)],'fresh first prefix byte unconditionally replaces selector')
  delegated(out,one(ws,0x7958)['after']);return dict(route='literal_first_byte',selector=selector,first=first,context=context,A=out['a'])
 width=val(one(ws,0x7991),0x20c5);require(width<=13,'unobserved wide descriptor alternative excluded');table=0x9a32+2*width
 lo=one(ws,0x79a0)['reads'][0];hi=one(ws,0x79a2)['reads'][0];require((lo['address'],hi['address'])==(table,table+1),'fresh width doubled and descriptor pointer table low/high read');pointer=lo['value']+256*hi['value'];count=val(one(ws,0x79a7),pointer)
 comparisons=ats(ws,0x79e3);advances=[];loops=[];last_step=0
 for c in cs[1:]:
  require(c['target']=='PLI.COM+1A1C'and c['callsite']==0x79f4,'descriptor pointer advance helper only')
  group=[w for w in ws if last_step<w['step_index']<c['call_step']];tests=[w for w in group if w['origin']['offset']==0x79e3]
  remaining=one(group,0x79b7)['writes'][0]['new_value'];require(remaining==(count-1)&255,'decrement remaining before reverse traversal');count=remaining
  js=[]
  for w in tests:
   before=[z for z in group if z['step_index']<w['step_index']];j=ats(before,0x79c5)[-1]['reads'][0]['value'];rd=ats(before,0x79da)[-1]['reads'][0];rec=ats(before,0x79db)[-1]['reads'][0]
   require(rd['address']==0x20c6+((j-1)&255) and rec['address']==(pointer+j)&65535,'independent reverse prefix/descriptor reads, including j0 extra reads')
   selected=(j!=0 and rd['value']==rec['value']);require(w['control']['taken']==(not selected),'zero mask AND equality mask, no short-circuit read elimination');js.append(j)
  oldword=word_read(ats(group,0x79d5)[-1],0xaa16);require(oldword==pointer,'fresh descriptor pointer used for comparison')
  width_now=val(one(group,0x79ed),0x20c5);n=(pointer+((width_now+1)&255))&65535;require(c['entry']['a']==(width_now+1)&255 and pair(c['output'],'h','l')==n,'fresh width increment plus resident wrapping pointer addition')
  stores=[w for w in ws if c['return_step']<w['step_index'] and w['origin']['offset']in[0x79f9,0x79fb]][:2];require([(q['address'],q['new_value'])for w in stores for q in w['writes']]==[(0xaa16,n&255),(0xaa17,n>>8)],'descriptor advance low/high publication before j0 test')
  loops.append(dict(pointer=pointer,remaining=count,indices=js));advances.append(n);pointer=n;last_step=c['return_step']
 terminal=r['ret']['origin']['offset'];require(terminal in[0x7a0b,0x7a14],'represented descriptor endpoints only')
 if terminal==0x7a0b:
  rd=one(ws,0x7a07)['reads'][0];require(rd['address']==pointer,'match result reads ADVANCED descriptor byte');delegated(out,e,a=rd['value'],b=0,c=0,d=pointer>>8,e=pointer&255,h=pointer>>8,l=pointer&255,flags=cmp(0,0));route='descriptor_match'
 else:
  require(count==0 and out['a']==0 and [(q['address'],q['new_value'])for q in one(ws,0x7a12)['writes']]==[(0x20c3,1)],'exhaustion publishes1 while returnedA0 remains distinct');delegated(out,ats(ws,0x79b0)[-1]['after'],h=0x20,l=0xc3);route='descriptor_exhausted'
 return dict(route=route,selector=selector,first=first,context=context,width=width,initial_pointer=lo['value']+256*hi['value'],traversal=loops,advanced_pointers=advances,A=out['a'])

def analyze(rows,images):
 result={};raw={n:(Path(images)/n).read_bytes()for n in ['PLI.COM','PLI1.OVL','PLI0.OVL','PLI2.OVL']}
 for source,g in rows.items():
  result[source]={};readers={r['call']['step_index']:r for key in ['PLI.COM+12AE','PLI.COM+12D9']for r in g[key]};appends={r['call']['step_index']:r for r in g['PLI.COM+1627']};acq={r['call']['step_index']:r for r in g['PLI.COM+1376']}
  required={w['step_index']for key in ['PLI1.OVL+5E98','PLI1.OVL+5929']for r in g[key]for w in r['own_witnesses']if w['control']['kind']=='call'and coord(w.get('target_origin'))=='PLI1.OVL+784E'}
  for key,rs in g.items():
   if key not in ['PLI1.OVL+784E','PLI.COM+1376','PLI.COM+1616','PLI.COM+1627']:continue
   result[source][key]=[]
   for r in rs:
    verify_return(r['call'],r['ret'],r['relation'])
    for w in r['own_witnesses']:
     origin=w['origin'];name=origin['image']['name'];off=origin['offset'];b=bytes.fromhex(w['bytes']);require(raw[name][off:off+len(b)]==b and w['runtime_pc']==off+(0x100 if name=='PLI.COM'else 0x2200),'exact historical image/offset/encoding')
    if key.endswith('784E'):
     law=validate_784e(r);call=children_any(r)[0];resident=acq[call['call_step']];require(call['output']==resident['ret']['after'],'independent exact resident CALL/return correlation')
     if r['call']['step_index']in required:law['resident']=required_acquisition(resident,readers,appends)
    elif key.endswith('1376'):
     local_proof(r);law=dict(route='independent_resident_scope',return_site=coord(r['ret']['origin']),scope='Required scope computed in correlated784E roots; independent/refill/quoted/numeric alternatives not globally completed')
    else:law=mask_result(r)
    result[source][key].append(dict(call_step=r['call']['step_index'],return_step=r['ret']['step_index'],caller=coord(r['call']['origin']),entry=r['entry']['before'],output=r['ret']['after'],law=law,stack=stack_extended(r),chronology=chronology(r)))
 return result

def parent_compatibility(rows):
 result=[]
 for source,g in rows.items():
  acquisitions={r['call']['step_index']:r for r in g['PLI1.OVL+784E']}
  for key in ['PLI1.OVL+5E98','PLI1.OVL+5929']:
   for parent in g[key]:
    cs=children_any(parent);picked=[(i,c)for i,c in enumerate(cs)if c['target']=='PLI1.OVL+784E'];require(len(picked)==1,'one direct acquisition per required parent window')
    i,c=picked[0];r=acquisitions[c['call_step']];require(c['entry']==r['entry']['before']and c['output']==r['ret']['after'],'exact independently correlated child entry/return, not equal-value attribution')
    require(not any(q['address']in[0xa863,0xa864,0xa8ab,0xa8ac]for w in body(r)for q in w['writes']),'required acquisition does not mutate working/reference pointer words')
    if key.endswith('5E98'):
     require(cs[i-1]['target']=='PLI1.OVL+5A46'and cs[i+1]['target']=='PLI1.OVL+4275','causal acquisition between pointer producer and subsequent pointer comparison')
     following=one(parent['own_witnesses'],0x5ec3)if len(ats(parent['own_witnesses'],0x5ec3))==1 else ats(parent['own_witnesses'],0x5ec3)[0]
     require(following['before']==c['output'],'no invented register restore before subsequent comparison')
     delegated(parent['nested_returns'][following['step_index']]['ret']['after'],cs[i+1]['output'])
     relation='5A46 pointer production -> required acquisition (pointer words preserved) -> immediate complete4275 comparator'
    else:
     delegated(parent['ret']['after'],c['output']);require(cs[i-1]['target']=='PLI1.OVL+2511'and i==len(cs)-1,'final acquisition follows2511; shared RET delegates complete child machine state')
     relation='2511 -> required acquisition -> shared ordinary parent RET; all data registers/flags delegated'
    result.append(dict(source=source,parent=key,parent_call=parent['call']['step_index'],child_call=c['call_step'],child_return=c['return_step'],relation=relation,after=cs[i+1]['target']if key.endswith('5E98')else'parent_return'))
 return result

BASE='22c38cf8d83b61e602523c48aacf5147a69835ba'
def projection(rows,a):
 return {key:{'counts':{s:len(g[key])for s,g in rows.items()},'callers':counts(coord(r['call']['origin'])for g in rows.values()for r in g[key]),'routes':{s:counts(q['law']['route']for q in g[key])for s,g in a.items()}if key in next(iter(a.values()))else{}}for key in BOUNDS}

def build_packet(rows,a,catalog):
 cfg={};routes={};patterns={};cases=[];contracts={}
 encode=lambda z:[z[k]for k in ['a','b','c','d','e','h','l','sp','pc']]+[psw(z['flags'])]
 for source,g in rows.items():
  for key in ['PLI1.OVL+784E','PLI.COM+1616']:
   for r,q in zip(g[key],a[source][key]):
    if key.endswith('784E')and 'resident'not in q['law']:continue
    resident=next((v for v in g['PLI.COM+1376']if v['call']['step_index']==children_any(r)[0]['call_step']),None)if key.endswith('784E')else None
    for target in [r]+([resident]if resident else[]):
     union=cfg.setdefault(target['entry_key'],{})
     for w in target['own_witnesses']:union[w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
     for c in children_any(target):
      p=catalog[c['target']];contracts[c['target']]=dict(id=c['target'],sha256=hashlib.sha256(json.dumps(p,sort_keys=True).encode()).hexdigest(),completeness=p['completeness'])
    if key.endswith('1616'):continue
    route=q['law']['route'];skeleton=dict(route=route,children=[[c['callsite'],c['target']]for c in children_any(r)],writes=[[w['origin']['offset'],t['address']]for w in r['own_witnesses']for t in w['writes']if not w['disassembly'].startswith('PUSH')and w['control']['kind']!='call'])
    rid='r'+hashlib.sha256(json.dumps(skeleton,sort_keys=True).encode()).hexdigest()[:8];routes[rid]=skeleton
    pat=[[v['relative_address'],v['writer']]for v in q['stack']];pid='s'+hashlib.sha256(json.dumps(pat).encode()).hexdigest()[:8];patterns.setdefault(pid,pat)
    law=q['law']['resident'];cases.append([source,q['caller'],q['call_step'],q['return_step'],rid,pid,encode(q['entry']),encode(q['output']),law['prefix'],law['following'],[[v['index'],v['value']]for v in law['reads']]])
 return dict(schema='compact-target-work-packet-v2',baseline=BASE,CFG={k:sorted(v.values())for k,v in cfg.items()},routes=routes,stack_patterns=patterns,contracts=contracts,cases=cases,columns=['source','caller','call','return','route','stack_pattern','entry_ABI','return_ABI','prefix','following_context','counted_read_index_raw'],ABI_columns=['A','B','C','D','E','H','L','SP','PC','PSW'],inventory=projection(rows,a))

def encode_full_proof(rows,a):
 # Intern each factual step once. Repeated child windows refer to the same step IDs.
 proof={};records=[]
 for source,g in rows.items():
  steps={};proof[source]=steps
  for key,rs in g.items():
   for r in rs:
    for w in body(r):
     n=str(w['step_index']);require(n not in steps or steps[n]==w,'same factual step, one canonical representation');steps[n]=w
    records.append(dict(source=source,key=key,call=r['call']['step_index'],return_step=r['ret']['step_index'],own=[w['step_index']for w in r['own_witnesses']],children=children_any(r),relation=r['relation']))
 return (json.dumps(dict(steps=proof,windows=sorted(records,key=lambda r:(r['source'],r['key'],r['call'])),analysis=a,parent_compatibility=parent_compatibility(rows)),sort_keys=True,separators=(',',':'))+'\n').encode()
