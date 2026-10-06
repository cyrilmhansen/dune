"""Corrected hardware and established eight-byte software windows, without packet architecture changes."""
from check_state_transformation_pass_39 import (ROOT,CAPTURES,coord,require,pair,load,one,body,chronology,counts,ats,val,writes,cmp,arithmetic,validate_data_writers,rotate,stack,verify_return,prove)
from pathlib import Path
import json,hashlib
REPORT=ROOT/'research/host-compiler/pass-40'
ENTRIES=[0x28aa,0x6708]
BOUNDS={f'PLI1.OVL+{x:04X}':(x,x+1)for x in ENTRIES}
SOFTWARE={'PLI1.OVL+6708':8}
def gather_selected(capture, bounds=None, *, include_nested_returns=False, software_callees=None):
    # Opt-in, established POP-D cleanup family only. Bounds/context never assign
    # ownership; a corrected consumer plus prove() must close each child window.
    software_callees = software_callees or {}
    records = {key: [] for key in (BOUNDS if bounds is None else bounds)}
    active, returns, matched = {}, {}, {}
    software_active = {}
    last = None
    index = load(capture / "event-witnesses.json")
    for chunk in index["chunks"]:
        path = capture / "event-witnesses/chunks" / f"{chunk['id']:06d}.json"
        for event in load(path)["events"]:
            if event["type"] == "instruction":
                last = w = event["witness"]
                for r in active.values():
                    r["witnesses"].append(w)
                for r in software_active.values():
                    r["witnesses"].append(w)
                if w["control"]["kind"] == "call" and w["control"]["taken"]:
                    key = coord(w.get("target_origin"))
                    if key in software_callees:

                        software_active[w["step_index"]] = {
                            "entry_key": key, "call": w, "witnesses": []}
                    if key in records and key not in software_callees:
                        active[w["step_index"]] = {
                            "entry_key": key, "call": w, "witnesses": []
                        }
            elif event["type"] == "hardware_frame_return":
                step = event["frame"]["call_step"]
                require(last is not None and last["step_index"] == event["step_index"],
                        "Hardware return event lacks its instruction witness")
                returns[step] = last["step_index"]
                if include_nested_returns:
                    matched[step] = {"ret": last, "relation": event}
                if step in active:
                    r = active.pop(step)
                    r.update(entry=r["witnesses"][0], ret=last, relation=event)
                    records[r["entry_key"]].append(r)
            elif event["type"] == "software_continuation_return" and software_active:
                require(last is not None and last["step_index"] == event["step_index"],
                        "Software return event lacks its instruction witness")
                candidates = []
                for step, child in software_active.items():
                    # Return PC only narrows candidates. It never proves identity.
                    if child["call"]["call_return_address"] != event["return_address"]:
                        continue
                    prefix = [w for w in child["witnesses"]
                              if w["step_index"] <= event["low_byte_writer"]["step"]]
                    proof = {"call": child["call"], "prefix": prefix, "ret": last,
                             "relation": event,
                             "stack_argument_bytes": software_callees[child["entry_key"]]}
                    try:
                        relation = prove(proof)
                    except ValueError:
                        continue  # Remains unresolved; extraction fails below.
                    candidates.append((step, proof, relation))
                require(len(candidates) <= 1, "Ambiguous software continuation ancestry")
                if candidates:
                    step, proof, relation = candidates[0]
                    record=software_active.pop(step)
                    if record["entry_key"] in records:
                        record.update(entry=record["witnesses"][0],ret=last,relation=event,software_proof=proof,software_relation=relation)
                        records[record["entry_key"]].append(record)
                    returns[step] = last["step_index"]
                    matched[step] = {"ret": last, "relation": event,
                                     "software_proof": proof, "software_relation": relation}
    require(not active, "Selected CALL lacks a corrected matched return")
    require(not software_active, "Software child lacks a proven writer/slot/RET relation")
    for rs in records.values():
        for r in rs:
            own, skip = [], -1
            inclusive = r.pop("witnesses")
            for w in inclusive:
                if w["step_index"] <= skip:
                    continue
                own.append(w)
                if w["control"]["kind"] == "call" and w["control"]["taken"]:
                    require(w["step_index"] in returns,
                            "Nested call needs independent continuation reconstruction")
                    skip = returns[w["step_index"]]
            r["own_witnesses"] = own
            if include_nested_returns:
                r["nested_returns"] = {
                    w["step_index"]: dict(matched[w["step_index"]],
                        memory_witnesses=[q for q in inclusive
                            if w["step_index"] < q["step_index"] <= returns[w["step_index"]]
                            and (q["reads"] or q["writes"])])
                    for w in own
                    if w["control"]["kind"] == "call" and w["control"]["taken"]
                }
    return records



from check_state_transformation_pass_39 import local_proof as previous_local, identity, delegated, validate as previous_validate
from check_3dd9_pass_35 import psw
from check_6223_pass_32 import child
ENTRIES += [0x2185,0x8309,0x213c]
BOUNDS.update({f'PLI1.OVL+{x:04X}':(x,x+1)for x in ENTRIES})

def children_any(r):
 result=[]
 for w in r['own_witnesses']:
  if w['control']['kind']!='call':continue
  q=r['nested_returns'][w['step_index']]
  if 'software_proof'in q:require(prove(q['software_proof'])==q['software_relation'],'copied continuation independent proof')
  else:verify_return(w,q['ret'],q['relation'])
  result.append(dict(callsite=w['origin']['offset'],target=coord(w['target_origin']),entry=w['after'],output=q['ret']['after'],call_step=w['step_index'],return_step=q['ret']['step_index']))
 return result

def local_proof(r):
 # Extend the existing reviewed local equations only for the reached INR M.
 ordinary=[]
 for w in r['own_witnesses']:
  if w['disassembly'] in ['INR M','DCR A']:
   old=w['reads'][0]['value']if w['disassembly']=='INR M'else w['before']['a'];inc=w['disassembly']=='INR M';v=(old+(1 if inc else -1))&255
   flags=dict(sign=v>=128,zero=v==0,auxiliary_carry=(old&15)==15 if inc else(old&15)!=0,parity=v.bit_count()%2==0,carry=w['before']['flags']['carry'])
   require(w['after']['flags']==flags,'wrapping INR/DCR independent flag channels')
   if inc:require([(q['address'],q['new_value'])for q in w['writes']]==[(pair(w['before'],'h','l'),v)],'INR carrier and unconditional publication')
   else:require(w['after']['a']==v,'DCR before termination comparison')
  else:ordinary.append(w)
 previous_local(dict(r,own_witnesses=ordinary))
 return r['own_witnesses']

def stack_extended(r):
 """CALL/PUSH source-derived last writers, including consumed caller argument cells."""
 stack(r) # Independent exact PUSH/PSW/CALL byte proof already used by prior passes.
 S=r['entry']['before']['sp'];upper=S+10 if r['entry_key'].endswith('6708')else S
 result={}
 for w in body(r):
  if w['control']['kind']=='call'and w['control']['taken']:
   v=w['call_return_address'];sp=w['before']['sp'];expected=[(sp-1,v>>8),(sp-2,v&255)]
  elif w['disassembly'].startswith('PUSH '):
   reg=w['disassembly'][5:];z=w['before'];v=(z['a']<<8)|psw(z['flags'])if reg=='PSW'else pair(z,*{'B':('b','c'),'D':('d','e'),'H':('h','l')}[reg]);sp=z['sp'];expected=[(sp-1,v>>8),(sp-2,v&255)]
  else:continue
  require([(q['address'],q['new_value'])for q in w['writes']]==expected,'instruction-derived stack writer high then low')
  for a,v in expected:
   if a<upper:
    old=result.get(a);result[a]=dict(relative_address=a-S,value=v,writer=coord(w['origin']),step=w['step_index'],overwritten=[]if old is None else old['overwritten']+[old['writer']])
 return [result[a]for a in sorted(result)]

def word_read(w,address):
 require([q['address']for q in w['reads']]==[address,address+1],'fresh low/high word read including discarded neighbor')
 return w['reads'][0]['value']+256*w['reads'][1]['value']

def validate_leaf(r):
 ws=local_proof(r);e=r['entry']['before'];out=r['ret']['after'];k=r['entry_key'];cs=children_any(r)
 if k.endswith('8309'):
  p=pair(e,'h','l');lo=one(ws,0x8309)['reads'][0];hi=one(ws,0x830b)['reads'][0];require(lo['address']==p and hi['address']==(p+1)&65535,'paired indirect word source')
  word=lo['value']+256*hi['value'];twice=(word+word)&65535;four=(twice+twice)&65535;eight=(four+four)&65535;result=(eight+twice)&65535
  delegated(out,e,b=twice>>8,c=twice&255,d=((p+1)&65535)>>8,e=(p+1)&255,h=result>>8,l=result&255,flags=dict(e['flags'],carry=eight+twice>65535))
  require(not writes(ws)and not cs,'no data writes or delegated operation in multiply10')
  require(pair(one(ws,0x830e)['before'],'h','l')==twice,'temporary PUSH saves doubled word, not input')
  return dict(route='iterative_word_times10',pointer=p,word=word,twice=twice,four=four,eight=eight,result=result,final_carry=eight+twice>65535)
 if k.endswith('213C'):
  c=e['c'];require(c not in [11,12,13,3,4],'unobserved literal-equality alternatives excluded')
  final=2 if c==2 else 4;delegated(out,e,a=int(c==2),h=0xa6,l=0x45,flags=cmp(c,final))
  require([(q['address'],q['value'])for q in writes(ws)]==[(0xa645,c)],'one classifier scratch publication')
  return dict(route='equal02'if c==2 else'false_comparison_prefix',input=c,result=out['a'])
 if k.endswith('2185'):
  c=e['c'];masked=c&240
  if masked==16:
   require(not cs,'nibble10 route skips child');delegated(out,e,a=1,h=0xa6,l=0x46,flags=cmp(masked,16));route='nibble10_literal1'
  else:
   require(len(cs)==1 and cs[0]['target']=='PLI1.OVL+213C'and cs[0]['entry']['c']==c,'fresh low paired scratch -> classifier')
   word_read(one(ws,0x2196),0xa646);rot=one(ws,0x219d)['after']
   if cs[0]['output']['a']&1:delegated(out,rot,a=1);route='child_bit_literal1'
   else:delegated(out,one(ws,0x21ab)['after']);require(out['a']==(255 if c==0x31 else 0),'fallback equality31 mask');route='fallback_equal31_mask'
  require([(q['address'],q['value'])for q in writes(ws)]==[(0xa646,c)],'one saved input write')
  return dict(route=route,input=c,result=out['a'])
 raise ValueError(k)

def validate_alternate(r):
 ws=local_proof(r);e=r['entry']['before'];out=r['ret']['after'];require(e['e']==2,'separate E02 route, E05 not this algorithm');relation=prove(r['software_proof']);S=e['sp']
 pops=[one(ws,x)for x in [0x6710,0x6715,0x6718,0x671d]];args=[]
 for n,w in enumerate(pops):args.append(word_read(w,S+2+2*n))
 source,selector_word,pointer,prefix_word=args;selector=selector_word&255;prefix=prefix_word&255;length=e['c']
 require(length in [1,2],'bounded demonstrated source count domain, not invocation identity')
 require(val(one(ws,0x6731),0xa628+selector)&0x28!=0x28,'fresh base selector chooses alternate')
 require(val(one(ws,0x6b9a),0xa628+selector)==0x15,'alternate selected15 accumulation route')
 require([(q['address'],q['value'])for q in writes(ws)[:10]]==[(0xa9e1,2),(0xa9e0,length),(0xa9df,source>>8),(0xa9de,source&255),(0xa9dd,selector),(0xa9dc,pointer>>8),(0xa9db,pointer&255),(0xa9da,prefix),(0xa863,pointer&255),(0xa864,pointer>>8)],'argument publications high-before-low; pointer copy low-before-high')
 checks=ats(ws,0x6bb5);require(len(checks)==length+1,'fresh-count termination comparisons include final exit')
 digits=[];acc=0;steps=[];cs=children_any(r)
 for i in range(length):
  require(checks[i]['before']['a']==length-1 and checks[i]['reads'][0]['value']==i and not checks[i]['after']['flags']['carry'],'current offset, fresh count minus1')
  rd=ats(ws,0x6bc3)[i]['reads'][0];require(rd['address']==source+i,'fresh source position address');byte=rd['value'];require(0x30<=byte<=0x39,'supported nondot decimal digit byte')
  for off in [0x6be3,0x6bea,0x6c20,0x6c40]:require(ats(ws,off)[i]['reads'][0]['address']==source+i and ats(ws,off)[i]['reads'][0]['value']==byte,'independent source reread, no provenance substitution')
  require(not(acc>0xccc or(acc==0xccc and byte>0x37)),'overflow guard excludes unsupported branch')
  bysite={c['callsite']:c for c in cs if checks[i]['step_index']<c['call_step']<checks[i+1]['step_index']}
  require(set(bysite)=={0x6c03,0x6c0c,0x6c32,0x6c48},'threshold, equality, multiply10, digit subtraction order')
  require(pair(bysite[0x6c03]['entry'],'d','e')==0xccc and pair(bysite[0x6c03]['entry'],'h','l')==0xa948,'threshold subtraction takes working word carrier')
  require(bysite[0x6c03]['output']['flags']['carry']==(acc>0xccc),'actual word borrow determines first overflow channel')
  require(pair(bysite[0x6c0c]['output'],'h','l')==(acc-0xccc)&65535,'independent resident difference word for equality channel')
  mult=bysite[0x6c32];require(pair(mult['output'],'h','l')==(10*acc)&65535,'closed iterative multiply10 child result')
  before=acc;acc=((10*acc+byte)&65535)-0x30;acc&=65535
  require(pair(bysite[0x6c48]['entry'],'d','e')==((10*before+byte)&65535)and bysite[0x6c48]['entry']['a']==0x30 and pair(bysite[0x6c48]['output'],'h','l')==acc,'raw digit addition precedes subtraction30; both word wraps explicit')
  require([(q['address'],q['new_value'])for q in ats(ws,0x6c4b)[i]['writes']]==[(0xa948,acc&255),(0xa949,acc>>8)],'working word publication low then high per iteration')
  require(ats(ws,0x6c51)[i]['writes'][0]['new_value']==i+1,'offset publication AFTER working word')
  digits.append(byte);steps.append(dict(offset=i,byte=byte,before=before,after=acc))
 require(checks[-1]['reads'][0]['value']==length and checks[-1]['after']['flags']['carry'],'exact termination offset exceeds countminus1')
 width=one(ws,0x6c5e)['reads'][0]['value'];require(one(ws,0x6c5e)['reads'][0]['address']==0xa62b+selector,'fresh width channel')
 require(width>7 and prefix!=0x2d,'supported two-byte positive-prefix outcome')
 require(one(ws,0x6c6b)['control']['taken']and pair(cs[-2]['output'],'h','l')==(1<<width)&65535,'reuse historical repeated shifts, not width-normalized substitute')
 require(one(ws,0x6c8e)['control']['taken'],'current width >7 takes two-byte publication')
 delegated(out,e,a=1,b=0xa6,c=0x2b,d=0xa9,e=0x49,h=0xa9,l=0x47,flags=cmp(7,width))
 require(out['sp']==S+10 and out['pc']==r['call']['call_return_address'],'eight argument bytes consumed and copied original continuation')
 return dict(route='E02_selected15_decimal_word',length=length,args=args,selector=selector,prefix=prefix,width=width,digits=digits,iterations=steps,result=acc,continuation=relation)

def validate_parent(r):
 ws=local_proof(r);cs=children_any(r);out=r['ret']['after'];index=word_read(one(ws,0x28ae),0xa634)&255;selected=val(one(ws,0x28b7),0xa628+index)
 require(selected==2,'selected02 bounded parent law')
 expected=[0x2953,0x2985,0x2b06,0x2b0c,0x2b95,0x2bb6,0x2bc7,0x2bd8,0x2be9,0x2c07,0x2c1c,0x2c2d,0x2c3e,0x2c45,0x2c4f]
 require([c['callsite']for c in cs]==expected,'selected02 exact child order, distinct from selector05 graph')
 childresult=cs[1]['output'];require(cs[1]['entry']['e']==2 and cs[1]['entry']['c']in[1,2],'selected byte is E, fresh header minus0A is C')
 require(cs[0]['output']['a']&childresult['a']&1,'parent combines actual child result with saved gate; no constant-output substitution')
 for offset,base in [(0x2998,0xa628),(0x29a3,0xa62b),(0x29ae,0xa62e)]:
  rd=one(ws,offset);wr=one(ws,offset+1);require(rd['reads'][0]['address']==base and wr['writes'][0]['address']==base+index and wr['writes'][0]['new_value']==rd['reads'][0]['value'],'independent base channel -> selected channel fresh read/publication')
 lo=word_read(one(ws,0x2aef),0xa948)&255;high=word_read(one(ws,0x2aff),0xa949)&255;word=lo+256*high
 require(pair(cs[2]['entry'],'h','l')==high and cs[2]['entry']['c']==8 and pair(cs[2]['output'],'h','l')==high<<8,'fresh high byte shifted through established8380')
 require(pair(cs[3]['output'],'h','l')==word,'established834F word OR combines independently published low channel')
 dest=0xa63b+2*index;require([(q['address'],q['new_value'])for off in[0x2b8e,0x2b90]for q in one(ws,off)['writes']]==[(dest,lo),(dest+1,high)],'pointer slot publication low then high before balance/publication children')
 stop=cs[4]['output']['a'];require(one(ws,0x2b98)['writes'][0]['new_value']==stop,'direct stopping cursor cache, not descendant value')
 require(cs[5]['entry']['c']==stop and pair(cs[5]['entry'],'d','e')==word,'fresh cached cursor plus assembled word -> mapped-word publication')
 for start,position in [(6,stop),(10,(stop+1)&255)]:
  for n,base in enumerate([0xa628,0xa62b,0xa62e]):
   c=cs[start+n];require(c['entry']['c']==position and c['entry']['e']==val(one(ws,[0x2bc2,0x2bd3,0x2be4][n]if start==6 else[0x2c17,0x2c28,0x2c39][n]),base+index),'each publication has independently fresh source and paired cursor')
 require(cs[9]['entry']['c']==stop and cs[9]['entry']['e']==0x0a and pair(cs[9]['entry'],'d','e')==word_read(one(ws,0x2c03),0xa661),'first mapped byte uses current paired A661/A662, including neighboring high byte')
 adjusted=(cs[13]['output']['a']+0x13)&255;require(cs[14]['entry']['e']==adjusted and cs[14]['entry']['c']==(stop+1)&255,'classifier result adjusted13 then freshly reloaded cursor -> independent final mapped publication')
 delegated(out,cs[-1]['output']);return dict(route='selected02_acquire_assemble_publish',index=index,selected_before=selected,selected_after=one(ws,0x2ac8)['reads'][0]['value'],word=word,stop=stop,second_position=(stop+1)&255,adjusted=adjusted,child_sites=expected,output_A=out['a'])

def analyze(rows,images):
 raw={n:(Path(images)/n).read_bytes()for n in ['PLI1.OVL','PLI.COM']};result={}
 for source,g in rows.items():
  result[source]={}
  for key,rs in g.items():
   result[source][key]=[]
   for r in rs:
    if key.endswith('6708'):require(prove(r['software_proof'])==r['software_relation'],'software relation reused, not ordinary RET')
    else:verify_return(r['call'],r['ret'],r['relation'])
    for w in body(r):
     name=w['origin']['image']['name'];o=w['origin']['offset'];b=bytes.fromhex(w['bytes']);require(raw[name][o:o+len(b)]==b and w['runtime_pc']==o+(0x2200 if name=='PLI1.OVL'else 0x100),'canonical image plus offset and immutable exact bytes')
    if key.endswith('6708')and r['entry']['before']['e']!=2:
     local_proof(r);law=dict(route='existing_E05_copy_padding',scope='Established MINIMAL Pass8 contract reused; not the decimal-word algorithm',software=prove(r['software_proof']))
    elif key.endswith('6708'):law=validate_alternate(r)
    elif key.endswith('28AA'):
     index=word_read(one(r['own_witnesses'],0x28ae),0xa634)&255;selected=val(one(r['own_witnesses'],0x28b7),0xa628+index)
     law=validate_parent(r)if selected==2 else dict(route='existing_selected05_scope'if selected==5 else'guard_only',index=index,selected=selected)
    else:law=validate_leaf(r)
    result[source][key].append(dict(call_step=r['call']['step_index'],return_step=r['ret']['step_index'],caller=coord(r['call']['origin']),entry=r['entry']['before'],output=r['ret']['after'],law=law,stack=stack_extended(r),chronology=chronology(r)))
 return result

def projection(rows,analyses):
 return {s:{k:dict(calls=len(rs),callers=counts(coord(r['call']['origin'])for r in rs),routes=counts(q['law']['route']for q in analyses[s][k]),input_C=counts(str(r['entry']['before']['c'])for r in rs),input_E=counts(str(r['entry']['before']['e'])for r in rs),return_A=counts(str(r['ret']['after']['a'])for r in rs))for k,rs in g.items()}for s,g in rows.items()}

def build_packet(rows,analyses,catalog):
 cfg={};routes={};patterns={};cases=[];contracts={}
 encode=lambda z:[z[k]for k in ['a','b','c','d','e','h','l','sp','pc']]+[psw(z['flags'])]
 for source,g in rows.items():
  for key,rs in g.items():
   for r,a in zip(rs,analyses[source][key]):
    route=a['law']['route']
    selected=route in ['E02_selected15_decimal_word','selected02_acquire_assemble_publish']or key[-4:]in['2185','8309','213C']
    if not selected:continue
    old=cfg.setdefault(key,{})
    for w in r['own_witnesses']:old[w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
    for c in children_any(r):
     p=catalog.get(c['target']);contracts[c['target']]=None if p is None else dict(id=c['target'],sha256=hashlib.sha256(json.dumps(p,sort_keys=True).encode()).hexdigest(),completeness=p['completeness'])
    if key[-4:]not in['6708','28AA']:continue
    S=r['entry']['before']['sp'];layout=[[w['origin']['offset'],q['address']]for w in r['own_witnesses']for q in w['writes']if w['control']['kind']!='call'and not w['disassembly'].startswith('PUSH')]
    skeleton=dict(entry=key,route=route,writes=layout,children=[[c['callsite'],c['target']]for c in children_any(r)])
    rid='r'+hashlib.sha256(json.dumps(skeleton,sort_keys=True).encode()).hexdigest()[:8]
    pat=[[q['relative_address'],q['writer']]for q in a['stack']];pid='s'+hashlib.sha256(json.dumps(pat).encode()).hexdigest()[:8]
    entry=encode(a['entry']);out=encode(a['output']);wv=[q['value']for q in writes(r['own_witnesses'])];sv=[q['value']for q in a['stack']]
    routes.setdefault(rid,skeleton|dict(base_entry=entry,base_output=out,base_write_values=wv));patterns.setdefault(pid,dict(writers=pat,base_values=sv))
    delta=lambda x,y:[[i,v]for i,v in enumerate(x)if v!=y[i]]
    law={k:v for k,v in a['law'].items()if k not in ['continuation','child_sites']}
    cases.append([source,a['caller'],a['call_step'],a['return_step'],rid,pid,delta(entry,routes[rid]['base_entry']),delta(out,routes[rid]['base_output']),delta(wv,routes[rid]['base_write_values']),delta(sv,patterns[pid]['base_values']),law,a['chronology']['stack_writes_sha256']])
 return dict(schema='compact-target-work-packet-v2',baseline='6010894d20941e9e3dfe2706a6cb37224862a6f8',cfg={k:sorted(v.values())for k,v in cfg.items()},routes=routes,stack_patterns=patterns,contracts=contracts,cases=cases,case_columns=['source','caller','call','return','route','stack','entry_deltas','output_deltas','write_deltas','stack_deltas','law_values','full_stack_chronology_sha256'],ABI_columns=['A','B','C','D','E','H','L','SP','PC','PSW_bits'])

def encode_full_proof(rows,analyses):
 records=[]
 for s,g in rows.items():
  for k,rs in g.items():
   for r,a in zip(rs,analyses[s][k]):
    records.append(dict(source=s,key=k,call=r['call'],ret=r['ret'],relation=r['relation'],law=a['law'],own=r['own_witnesses'],stack=a['stack'],chronology=a['chronology'],children=children_any(r),software=r.get('software_relation')))
 return (json.dumps(records,sort_keys=True,separators=(',',':'))+'\n').encode()
