"""Natural pointer-window traversal, complete mechanical advance/search leaves.

Semantics derive from actual machine state; no invocation-identity laws and no
native implementation. Existing complete pointer/flag helpers remain independent.
"""
from check_3dd9_pass_35 import (ROOT,CAPTURES,gather,coord,require,pair,load,one,
 identity,body,children,compact_child,single_child,stack,chronology,summarize,
 rotate,verify_return,counts,ats,val,writes,cmp,arithmetic,validate_data_writers)
import json,hashlib
REPORT=ROOT/'research/host-compiler/pass-36'
ENTRIES=[0x3a76,0x3963,0x4241,0x424f,0x429d,0x83a3]
BOUNDS={f'PLI1.OVL+{x:04X}':(x,x+1)for x in ENTRIES}
FILES=['natural-cases','route-distribution','state-transition','dependency-assessment']
def validate_advance(r):
 ws=r['own_witnesses'];e=r['entry']['before'];p=pair(one(ws,0x4241)['after'],'h','l');size=one(ws,0x4244)['reads'][0]['value'];fresh=pair(one(ws,0x4247)['after'],'h','l');n=(fresh+size)&65535;out=r['ret']['after']
 require(one(ws,0x4244)['reads'][0]['address']==p,'advance size read from first pointer carrier')
 require(pair(one(ws,0x424a)['before'],'d','e')==size,'only low size byte zero extended')
 require(pair(out,'h','l')==n and pair(out,'d','e')==size and pair(out,'b','c')==pair(e,'b','c')and out['a']==e['a'],'advance exact ABI, A/BC retained')
 require(out['flags']==dict(e['flags'],carry=fresh+size>65535),'DAD only changes CY; NZPA retained')
 require([(x['address'],x['value'])for x in writes(ws)]==[(0xa863,n&255),(0xa864,n>>8)],'advance unconditionally publishes low then high pointer')
 return dict(first_pointer=p,size=size,fresh_pointer=fresh,next_pointer=n,flags=out['flags'])
def validate_subtraction(r):
 ws=r['own_witnesses'];e=r['entry']['before'];a=pair(e,'h','l');v=pair(e,'d','e');lo=one(ws,0x83a4)['reads'][0];hi=one(ws,0x83a8)['reads'][0];word=lo['value']+256*hi['value'];res=(v-word)&65535
 require((lo['address'],hi['address'])==(a,(a+1)&65535),'complete shared subtraction low/high addresses')
 borrow=(v&255)<lo['value'];high=(v>>8)-hi['value']-int(borrow);f=dict(sign=(high&255)>=128,zero=(high&255)==0,auxiliary_carry=((v>>8)&15)>=(hi['value']&15)+int(borrow),parity=(high&255).bit_count()%2==0,carry=v<word);out=r['ret']['after']
 require(pair(out,'h','l')==res and pair(out,'d','e')==(a+1)&65535 and out['a']==res>>8 and pair(out,'b','c')==pair(e,'b','c')and out['flags']==f,'existing83A3 complete word and high-SBB flag contract')
 require(not writes(ws),'existing subtraction has no data publications')
 return dict(minuend=v,subtrahend=word,source=a,difference=res,flags=f)
def validate_search(r):
 ws=r['own_witnesses'];cs=children(r);wanted=r['entry']['before']['c'];out=r['ret']['after'];iterations=[];i=0
 require([(x['address'],x['value'])for x in writes(ws)if x['address']==0xa8f2]==[(0xa8f2,wanted)],'search saves requested byte before first advance')
 for j,w in enumerate(ats(ws,0x4253)):
  advance=single_child(r,w);compare=single_child(r,ats(ws,0x425a)[j]);q=r['nested_returns'][w['step_index']]['memory_witnesses'];nextp=pair(one(q,0x424b)['before'],'h','l');limit=one(r['nested_returns'][ats(ws,0x425a)[j]['step_index']]['memory_witnesses'],0x83a4)['reads'][0]['value']+256*one(r['nested_returns'][ats(ws,0x425a)[j]['step_index']]['memory_witnesses'],0x83a8)['reads'][0]['value']
  require(pair(compare['entry'],'d','e')==nextp and pair(compare['entry'],'h','l')==0xa861,'fresh advanced pointer and explicit A861 limit address ->83A3')
  beyond=nextp>=limit;test=ats(ws,0x425d)[j];require(test['control']['taken']==beyond and compare['output']['flags']['carry']==not_bool(beyond),'JNC consumes actual unsigned subtraction borrow')
  field=None
  if not beyond:
   field=single_child(r,ats(ws,0x4260)[i])['output']['a'];cmpw=ats(ws,0x4266)[i];require(cmpw['reads'][0]['address']==0xa8f2 and cmpw['reads'][0]['value']==wanted and cmpw['before']['a']==field,'fresh requested byte versus fresh complete421F mask')
   require(cmpw['after']['flags']==cmp(field,wanted)and ats(ws,0x4267)[i]['control']['taken']==(field!=wanted),'search field mismatch loop polarity from immediate CMP')
   i+=1
  iterations.append(dict(next_pointer=nextp,limit=limit,beyond=beyond,field=field,wanted=wanted))
 require(len(cs)==2*len(iterations)+i,'advance then subtraction then optional field in every iteration')
 if iterations[-1]['beyond']:
  require(r['ret']['origin']['offset']==0x4274 and pair(out,'h','l')==0 and out['a']==cs[-1]['output']['a']and out['flags']==cs[-1]['output']['flags'],'limit exit preserves subtraction A/flags; clears HL and working pointer only')
  require([(x['address'],x['value'])for x in writes(ws)]==[(0xa8f2,wanted),(0xa863,0),(0xa864,0)],'limit exit clear low then high; no buffer clearing')
  route='at_or_above_limit_clear'
 else:
  require(iterations[-1]['field']==wanted and r['ret']['origin']['offset']==0x426a,'matching-mask exit after advancement')
  require(pair(out,'h','l')==0xa8f2 and out['a']==wanted and out['flags']==cmp(wanted,wanted),'matching return ABI retains CMP, not pointer-add flags')
  require([(x['address'],x['value'])for x in writes(ws)]==[(0xa8f2,wanted)],'matching search no own data write beyond requested-byte scratch')
  route='matching_mask'
 require(pair(out,'d','e')==0xa862 and pair(out,'b','c')==pair(r['entry']['before'],'b','c'),'search DE from subtraction address; BCentry preserved')
 return dict(route=route,wanted=wanted,iterations=iterations)
def not_bool(v):return not v
def validate_classify(r):
 ws=r['own_witnesses'];out=r['ret']['after'];cs=children(r);selector=cs[0]['output']['a'];field=cs[1]['output']['a'];primary=one(ws,0x42b0)['reads'][0]['value'];pointer=pair(one(ws,0x42ac)['after'],'h','l');require(one(ws,0x42b0)['reads'][0]['address']==(pointer+4)&65535,'fresh pointer+4 channel')
 require([(x['address'],x['value'])for x in writes(ws)]==[(0xa8f3,selector),(0xa8f4,field),(0xa8f5,primary)],'classifier field+2, field+3, field+4 caches in exact order')
 for w in ws:
  if w['disassembly']=='RAR':rotate(w)
  else:arithmetic(w)
 require(one(ws,0x42b9)['control']['taken']==(selector!=0x15),'selector15 branch actual immediate CPI')
 if selector==0x15:
  values=[one(ws,o)['after']['a']for o in [0x42bf,0x42c1,0x42c2,0x42c3,0x42c4]];shifted=(primary&252)>>3;res=shifted+1
  require(values==[primary&252,(primary&252)>>1,(primary&252)>>2,shifted,res],'literal ANI FC / three carry shifts / INR order, no ANI07 truncation')
  f=dict(sign=res>=128,zero=res==0,auxiliary_carry=(shifted&15)==15,parity=res.bit_count()%2==0,carry=bool(primary&4));require(out['a']==res and out['flags']==f,'selector15 result1..32; CY=primary.bit2 from last RAR; NZPA from INR')
  require(pair(out,'b','c')==4 and pair(out,'h','l')==(pointer+4)&65535,'selector15 retains first field+4 address and BC4')
  route='selector15_primary_shift_plus_one'
 else:
  require(selector not in (0x16,0x19)and selector&0x24!=0x24 and selector&0x28!=0x28,'bounded observed selector dispatch excludes RAW16/19/24/28 arms')
  if selector==0x30:
   require(out['a']==2 and out['flags']==cmp(selector,0x30)and r['ret']['origin']['offset']==0x432d,'selector30 literal2 retains matching CPI flags')
   route='selector30_literal2'
  else:
   special=((selector in (0x40,0x41))and bool(field&0x40));require(not special and selector not in (0x44,0x42),'unobserved special selector arms remain unsupported')
   require(one(ws,0x4351)['control']['taken']and one(ws,0x435c)['control']['taken']and one(ws,0x4367)['control']['taken'],'fallback gates independently checked')
   require(out['a']==0 and out['flags']==cmp(selector,0x42)and r['ret']['origin']['offset']==0x4393,'fallback literal zero retains CPI42 flags')
   require(pair(out,'b','c')==(65535 if selector in (0x40,0x41)else 0),'fallback BC from POP masks, independent of returned zero')
   route='fallback_literal0'
 require(pair(out,'d','e')==pair(r['entry']['before'],'d','e'),'classifier DE preserved')
 return dict(route=route,selector=selector,field=field,primary=primary,pointer=pointer,result=out['a'],flags=out['flags'])
def validate_frame(r):
 ws=r['own_witnesses'];e=r['entry']['before'];S=e['sp'];ptr=pair(e,'b','c');field=single_child(r,one(ws,0x3973))['output']['a'];c=single_child(r,one(ws,0x397b));out=r['ret']['after']
 require(field!=0x70 and not one(ws,0x3978)['control']['taken'],'bounded3963 field!=70 shortcut; large70 frame route remainsRAW')
 require([(x['address'],x['value'])for x in writes(ws)]==[(0xa863,ptr&255),(0xa864,ptr>>8)],'fresh saved frame BC ->working pointer low/high')
 require(one(ws,0x396c)['reads'][0]['address']==S-10 and one(ws,0x396e)['reads'][0]['address']==S-9,'10-byte inherited frame, low/high saved BC independently read')
 require(out['a']==c['output']['a']and pair(out,'h','l')==c['output']['a']and pair(out,'d','e')==pair(e,'h','l')and pair(out,'b','c')==pair(c['output'],'b','c')and out['flags']==c['output']['flags'],'frame cleanup zeroextends A intoHL and restores inherited HL intoDE via last POP D')
 require(r['ret']['before']['sp']==S,'five POP D consume exact10-byte frame')
 return dict(pointer=ptr,field=field,frame_base=S-10,inherited_HL=pair(e,'h','l'),classify=compact_child(c),result_word=out['a'])
def validate_root(r):
 ws=r['own_witnesses'];e=r['entry']['before'];ptr=pair(e,'b','c');out=r['ret']['after'];cs=children(r)
 for w in ws:
  if w['disassembly']=='RAR':rotate(w)
  elif w['disassembly']=='CMA':require(w['after']['a']==w['before']['a']^255 and w['after']['flags']==w['before']['flags'],'CMA complements mask but preserves pre-complement flags')
  else:arithmetic(w)
 require([(x['address'],x['value'])for x in writes(ws)[:6]]==[(0xa744,e['b']),(0xa743,e['c']),(0xa745,e['c']),(0xa746,e['b']),(0xa863,e['c']),(0xa864,e['b'])],'save input high/low then duplicate working cursor low/high')
 field=single_child(r,one(ws,0x3a85))['output']['a'];require(field!=2 and one(ws,0x3a8a)['control']['taken'],'observed fieldlow3!=2 bypasses unobserved initial adjustment')
 calc=single_child(r,one(ws,0x3a9d));require(pair(calc['entry'],'b','c')==ptr and [(q['address'],q['new_value'])for q in one(ws,0x3aa0)['writes']]==[(0xa723,calc['output']['l']),(0xa724,calc['output']['h'])],'fresh saved input ->3963; its actual HL ->A723 low/high')
 require([(q['address'],q['new_value'])for w in body(r)for q in w['writes']if q['address']==0xa6e2]==[(0xa6e2,0)],'only zero init writes A6E2 in selected complete subtree')
 checks=[]
 for j,w in enumerate(ats(ws,0x3aa9)):
  pred=single_child(r,w);sub=single_child(r,ats(ws,0x3ab3)[j]);current=pair(sub['output'],'b','c');bnd=pred['output']['a'];borrow=sub['output']['flags']['carry'];mask=bnd&(0 if borrow else 255);rot=ats(ws,0x3abb)[j];jump=ats(ws,0x3abc)[j]
  require(rot['before']['a']==mask and jump['control']['taken']==(mask&1==0),'loop AND of returned pointer-mask and independent unsigned comparison, RAR bit0')
  require(sub['entry']['b']==0xa8 and sub['entry']['c']==0x63 and pair(sub['entry'],'d','e')==0xa743,'fresh saved input minus fresh working pointer, not cached prior mask')
  require(borrow==(ptr<current),'resident word borrow determines upper pointer bound')
  checks.append(dict(current_pointer=current,reference_mask=bnd,upper_bound_borrow=borrow,combined_mask=mask,exit=jump['control']['taken']))
 require(len(checks)==2 and not checks[0]['exit']and checks[1]['exit'],'all selected roots one iteration, independently derived second gate exit')
 bound=single_child(r,one(ws,0x3ad6));require(pair(bound['entry'],'b','c')==ptr and pair(bound['entry'],'d','e')==ptr and bound['output']['a']==0 and not one(ws,0x3add)['control']['taken'],'fresh current==original mask OR387F returned0 selects3558')
 require(single_child(r,one(ws,0x3ae6))['output']['a']==0 and one(ws,0x3aea)['control']['taken'],'fresh field-bit7 clear selects represented advance path')
 advance=single_child(r,one(ws,0x3bec));require(advance['entry']['c']==0,'literal requested controlmask0 passed to424F')
 fresh=pair(one(ws,0x3bef)['after'],'h','l');require(fresh==checks[1]['current_pointer']and pair(one(ws,0x3bf2)['before'],'h','l')==fresh,'fresh post-child working pointer ->A745, no child-HL-as-pointer shortcut')
 require(one(ws,0x3bfb)['before']['a']==0 and one(ws,0x3bfd)['control']['taken'],'fresh A6E2 zero selects natural terminal RET')
 require(out['a']==0 and out['flags']==cmp(0,0)and pair(out,'b','c')==checks[-1]['reference_mask']*257 and pair(out,'d','e')==0xa744 and pair(out,'h','l')==(ptr-fresh)&65535,'exact final ABI: BC saved lower mask, HL last subtraction, flags final CPI00')
 require([c['target']for c in cs]==['PLI1.OVL+41AF','PLI1.OVL+3963','PLI1.OVL+4275','PLI.COM+1A33','PLI.COM+1A33','PLI1.OVL+387F','PLI1.OVL+3558','PLI1.OVL+424F','PLI1.OVL+4275','PLI.COM+1A33'],'exact local child chronology')
 route='below_reference'if checks[-1]['reference_mask']==0 else'above_saved_input'
 return dict(route=route,input_pointer=ptr,initial_low3=field,result_word=pair(calc['output'],'h','l'),gate_checks=checks,advanced_pointer=fresh,advance=compact_child(advance),local_writes=writes(ws),ordered_children=[compact_child(c)for c in cs])
def analyze(source,capture,images,rows=None):
 rows=gather(capture,BOUNDS,include_nested_returns=True)if rows is None else rows;image=(images/'PLI1.OVL').read_bytes();resident=(images/'PLI.COM').read_bytes();index=load(capture/'event-witnesses.json');require(index['run_id'].split(':')[0]==source,'selected run identity')
 laws={0x3a76:validate_root,0x3963:validate_frame,0x4241:validate_advance,0x424f:validate_search,0x429d:validate_classify,0x83a3:validate_subtraction};cases={}
 for x,f in laws.items():
  key=f'PLI1.OVL+{x:04X}';cases[key]=[]
  for r in rows[key]:
   verify_return(r['call'],r['ret'],r['relation']);validate_data_writers(r)
   for w in body(r):
    n=w['origin']['image']['name'];raw=bytes.fromhex(w['bytes']);o=w['origin']['offset'];original=image if n=='PLI1.OVL'else resident
    require(n in ('PLI1.OVL','PLI.COM')and original[o:o+len(raw)]==raw and w['runtime_pc']==o+(0x2200 if n=='PLI1.OVL'else 0x100),'canonical immutable historical byte identity')
   require(r['ret']['after']['sp']==r['entry']['before']['sp']+2,'ordinary original-slot return')
   cases[key].append(identity(r)|dict(law=f(r),stack=stack(r),chronology={k:v for k,v in chronology(r).items()if k!='final_stack_writers'}))
 return dict(source=source,capture=str(capture.relative_to(ROOT)),run_id=index['run_id'],capture_sha256=hashlib.sha256((capture/'event-witnesses.json').read_bytes()).hexdigest(),structure={k:summarize(v)for k,v in rows.items()},cases=cases)
def derive(analyses):
 return {'natural-cases':dict(sources=[{k:a[k]for k in ['source','capture','run_id','capture_sha256','structure']}|dict(cases=[{k:r[k]for k in ['caller','call_step','entry_step','return_step','return_coordinate','entry','output']}for r in a['cases']['PLI1.OVL+3A76']])for a in analyses]),'route-distribution':dict(sources=[dict(source=a['source'],root_routes=counts(r['law']['route']for r in a['cases']['PLI1.OVL+3A76']),classification_routes=counts(r['law']['route']for r in a['cases']['PLI1.OVL+429D']),search_routes=counts(r['law']['route']for r in a['cases']['PLI1.OVL+424F']),search_iteration_counts=counts(str(len(r['law']['iterations']))for r in a['cases']['PLI1.OVL+424F']))for a in analyses]),'state-transition':dict(sources=[dict(source=a['source'],cases=[dict(call_step=r['call_step'],law=r['law'],stack=r['stack'],chronology=r['chronology'])for r in a['cases']['PLI1.OVL+3A76']])for a in analyses]),'dependency-assessment':dict(sources=[dict(source=a['source'],cases={k:v for k,v in a['cases'].items()if k!='PLI1.OVL+3A76'})for a in analyses])}
if __name__=='__main__':
 import argparse
 from pathlib import Path
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True);args=p.parse_args()
 for n,d in derive([analyze(s,c,args.images)for s,c in CAPTURES.items()]).items():(args.output_dir/(n+'.json')).write_text(json.dumps(d,separators=(',',':'))+'\n')
