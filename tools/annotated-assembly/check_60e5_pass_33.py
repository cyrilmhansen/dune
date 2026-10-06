"""Accumulated natural +60E5 state transitions; no native implementation."""
from collections import Counter
from pathlib import Path
import hashlib,json
from check_6223_pass_32 import (ROOT,CAPTURES,gather,coord,require,pair,load,one,
 identity,body,child,chronology,summarize,rotate,verify_return,counts)
from check_240a_pass_30 import cmp
REPORT=ROOT/'research/host-compiler/pass-33'
ENTRIES=[0x60e5,0x5e98,0x5e65,0x5e48,0x5e53,0x5e7c,0x6223,0x506e,0x3dd9,0x500f,0x81f1,0x7ff3,0x61a4,0x620c]
BOUNDS={f'PLI1.OVL+{o:04X}':(o,o+1)for o in ENTRIES}
FILES=['natural-cases','route-distribution','state-transition','reentry-ancestry','dependency-assessment']
def ats(ws,o):return [w for w in ws if w['origin']['offset']==o]
def val(w,address):return next(q['value']for q in w['reads']if q['address']==address)
def writes(ws):return [dict(step=w['step_index'],writer=coord(w['origin']),address=q['address'],value=q['new_value'])for w in ws for q in w['writes']if w['control']['kind']!='call'and not w['disassembly'].startswith('PUSH')]
def relation_index(capture,roots):
 result={}
 for chunk in load(capture/'event-witnesses.json')['chunks']:
  for e in load(capture/'event-witnesses/chunks'/f"{chunk['id']:06d}.json")['events']:
   if e['type']=='hardware_frame_return'and any(r['call']['step_index']<e['step_index']<=r['ret']['step_index']for r in roots):result[e['frame']['call_step']]=e
 return result

def frame_setup(r):
 ws=r['own_witnesses'];entry=r['entry']['before'];S=entry['sp'];offsets=[0x60e6,0x60e7]if r['entry_key'].endswith('60E5')else[0x5e98,0x5e99,0x5e9a]
 initial_sp=S-1 if r['entry_key'].endswith('60E5')else S
 for i,o in enumerate(offsets):
  w=one(ws,o);sp=initial_sp-2*i
  require(w['before']['sp']==sp and w['after']['sp']==sp-2,'historical frame PUSH depth')
  require([(q['address'],q['new_value'])for q in w['writes']]==[(sp-1,entry['h']),(sp-2,entry['l'])],'inherited H/L high-then-low frame bytes')
 for w in ws:
  if w['disassembly']!='PUSH PSW':continue
  f=w['before']['flags'];encoded=2+128*int(f['sign'])+64*int(f['zero'])+16*int(f['auxiliary_carry'])+4*int(f['parity'])+int(f['carry']);sp=w['before']['sp']
  require([(q['address'],q['new_value'])for q in w['writes']]==[(sp-1,w['before']['a']),(sp-2,encoded)],'exact PUSH PSW byte encoding and order')
 return dict(entry_H=entry['h'],entry_L=entry['l'],initial_SP=initial_sp,push_coordinates=[f'PLI1.OVL+{o:04X}'for o in offsets])

def validate_leaf(r):
 ws=r['own_witnesses'];key=r['entry_key'];entry=r['entry']['before'];out=r['ret']['after']
 if key.endswith('5E65'):
  c=entry['c'];carrier=one(ws,0x5e69);require([q['address']for q in carrier['reads']]==[0xa942,0xa943],'paired position read')
  base=pair(one(ws,0x5e70)['after'],'h','l');address=(base+2*c)&65535
  lo=one(ws,0x5e74);hi=one(ws,0x5e76);require(lo['reads'][0]['address']==address and hi['reads'][0]['address']==(address+1)&65535,'fresh indexed pointer bytes')
  word=lo['reads'][0]['value']+256*hi['reads'][0]['value']
  require([(q['address'],q['new_value'])for w in ws for q in w['writes']]==[(0xa942,c),(0xa863,word&255),(0xa864,word>>8)],'scratch then low/high pointer publication')
  require(out['a']==entry['a']and pair(out,'b','c')==pair(entry,'b','c')and pair(out,'h','l')==word and pair(out,'d','e')==(address+1)&65535,'5E65 exact returned registers')
  require(out['flags']==dict(entry['flags'],carry=base+2*c>65535),'5E65 NZPA retained; CY from final address DAD')
  return dict(position=c,discarded_neighbor=val(carrier,0xa943),base=base,doubled_offset=2*c,low_address=address,high_address=(address+1)&65535,selected_word=word)
 if key.endswith('5E48'):
  call=child(r,0x5e48);field=call['output']['a'];setbit=bool(field&64);expected=255 if setbit else 0
  require(out['a']==expected,'5E48 field.bit6 mask');require(out['flags']==dict(sign=setbit,zero=not setbit,auxiliary_carry=not setbit,parity=True,carry=setbit),'5E48 final SBB flags')
  require(all(out[k]==call['output'][k]for k in 'bcdehl'),'5E48 delegated non-A registers')
  require(not writes(ws),'5E48 no nonstack writes');return dict(field_byte=field,mask=expected,field_bit6=setbit)
 if key.endswith('81F1'):
  n=entry['c'];loops=ats(ws,0x8201);require(len(loops)==n,'byte countdown iterations')
  require(one(ws,0x81f4)['writes'][0]['new_value']==n,'counter scratch initialized C')
  initial=ats(ws,0x8202)[0]['reads'][0]['value']if n else None
  for i,w in enumerate(loops):
   require(w['reads'][0]['value']==n-i and w['writes'][0]['new_value']==n-i-1,'counter decrement before shared child')
   read=ats(ws,0x8202)[i];store=ats(ws,0x8205)[i];call=ats(ws,0x8209)[i];dec=ats(ws,0x820f)[i]
   require(store['writes'][0]['address']==0xae35 and store['writes'][0]['new_value']==read['reads'][0]['value']==call['before']['c'],'fresh AE32 ->end and child input')
   require(dec['writes'][0]['new_value']==(dec['reads'][0]['value']-1)&255,'fresh current-position decrement after child')
  require(out['a']==0 and pair(out,'h','l')==0xae77 and out['flags']==cmp(0,0),'counter return finalCMP0,0')
  if n:
   last=r['nested_returns'][ats(ws,0x8209)[-1]['step_index']]['ret']['after'];require(all(out[k]==last[k]for k in 'bcde'),'counter final child BC/DE')
  else:require(all(out[k]==entry[k]for k in 'bcde'),'zero counter preserves entry BC/DE')
  return dict(counter=n,iterations=len(loops),initial_position=initial,path='countdown_then_zero_compare')
 if key.endswith('7FF3'):
  q=child(r,0x7fff);saved=one(ws,0x7ff9);require([(one(ws,o)['writes'][0]['address'],one(ws,o)['writes'][0]['new_value'])for o in [0x7ff6,0x7ff8]]==[(0xae66,entry['b']),(0xae65,entry['c'])],'saved input word high then low')
  require(q['entry']['c']==0x0a and pair(q['entry'],'d','e')==pair(entry,'b','c'),'literal0A with fresh saved BC word')
  require(out==dict(q['output'],sp=out['sp'],pc=out['pc']),'7FF3 delegates7E5F')
  return dict(saved_word=pair(entry,'b','c'),child_input_C=0x0a,path='saved_BC_to_word_DE')
 if key.endswith('5E7C'):
  setup=child(r,0x5e7f);tail=child(r,0x5e94);limiter=one(ws,0x5e87)['reads'][0]['value']
  require(pair(setup['entry'],'b','c')==0 and tail['entry']['c']==0,'preparation child BC0 then independent240A C0')
  require([(q['address'],q['new_value'])for w in ws for q in w['writes']if w['control']['kind']!='call']==[(0xa628,0x15),(0xa62b,limiter),(0xa62e,0)],'preparation selector, fresh limiter, extra chronology')
  require(out==dict(tail['output'],sp=out['sp'],pc=out['pc']),'preparation final240A ABI')
  return dict(limiter=limiter,path='saved_word_preparation_then_fresh_limiter')
 if key.endswith('500F'):
  F=entry['sp']-1;rot=rotate(one(ws,0x5015));require(not one(ws,0x5016)['control']['taken'],'natural child4F54 set-bit route')
  require(one(ws,0x5026)['reads'][0]==dict(address=F,value=entry['c']),'fresh private input byte')
  add=one(ws,0x5026);require(add['after']['a']==(add['before']['a']+entry['c'])&255,'wrapping input adjustment')
  require(one(ws,0x5028)['before']['c']==add['after']['a'],'adjusted C passed native2511')
  last=child(r,0x502b);require(all(out[k]==last['output'][k]for k in 'abcde')and out['flags']==last['output']['flags']and pair(out,'h','l')==0xa932,'500F flags/A delegated lastchild, HL is publication address')
  pub=one(ws,0x5031);require(pub['writes'][0]['address']==0xa932 and pub['writes'][0]['new_value']==1,'literal1 independent of child returned A')
  return dict(saved_input=entry['c'],private_frame=F,first_RAR=rot,adjustment_input=add['before']['a'],adjusted_C=add['after']['a'],literal_A932=1,path='found_bit_to_publication')
 if key.endswith('5E53'):
  q=child(r,0x5e53);rot=rotate(one(ws,0x5e56));require(not one(ws,0x5e57)['control']['taken'],'natural bit6set path only')
  require(q['output']['a']==255 and out['a']==0 and out['flags']==rot['flags'],'5E53 literal0 retains rotated mask flags')
  return dict(mask=q['output']['a'],RAR=rot,path='bit6_set_literal0',unobserved='bit6 clear ->419F ->57ED')
 return None

def analyze(source,capture,images,rows=None,relations=None):
 rows=gather(capture,BOUNDS,include_nested_returns=True)if rows is None else rows
 roots=rows['PLI1.OVL+60E5'];relations=relation_index(capture,roots)if relations is None else relations
 image=(images/'PLI1.OVL').read_bytes();index=load(capture/'event-witnesses.json');require(index['run_id'].split(':')[0]==source,'selected run identity')
 for rs in rows.values():
  for r in rs:
   verify_return(r['call'],r['ret'],r['relation'])
   for w in r['own_witnesses']:
    o=w['origin'];require(o['image']['name']=='PLI1.OVL','canonical PLI1 identity');off=o['offset'];b=bytes.fromhex(w['bytes']);require(image[off:off+len(b)]==b and w['runtime_pc']==off+0x2200,'historical bytes and runtime')
 leafcases={k:[identity(r)|dict(law=validate_leaf(r),local_writes=writes(r['own_witnesses']),chronology=chronology(r))for r in rows[k]]for k in ['PLI1.OVL+5E65','PLI1.OVL+5E48','PLI1.OVL+5E53','PLI1.OVL+81F1','PLI1.OVL+7FF3','PLI1.OVL+500F','PLI1.OVL+5E7C']}
 acquisitions=[]
 for r in rows['PLI1.OVL+5E98']:
  ws=r['own_witnesses'];setup=frame_setup(r);cs=[child(r,w['origin']['offset'])for w in ws if w['control']['kind']=='call'and len(ats(ws,w['origin']['offset']))==1]
  # Repeated CALL sites are correlated by actual step, not collapsed by value.
  calls=[]
  for w in ws:
   if w['control']['kind']=='call':
    q=r['nested_returns'][w['step_index']];verify_return(w,q['ret'],q['relation']);calls.append(dict(callsite=coord(w['origin']),target=coord(w['target_origin']),call_step=w['step_index'],return_step=q['ret']['step_index'],entry=w['after'],output=q['ret']['after']))
  tag=one(ws,0x5edd)['before']['a'];require(tag in(0x15,0x80),'bounded natural acquisition tag');route='field80_dispatch'if tag==0x80 else'field15_scan_cleanup'
  require(one(ws,0x5ef7)['control']['taken']==(tag==0x15),'three wrapping equality masks select80 versus15')
  mask_steps=[0x5ee1,0x5ee8,0x5ef2];require([one(ws,o)['after']['a']for o in mask_steps]==[255 if tag==x else 0 for x in (0x40,0x41,0x80)],'separate masks not combined arithmetic')
  if tag==0x80:
   require(one(ws,0x5f19)['control']['taken']==False,'fresh field80 comparison')
   q=next(q for q in calls if q['callsite']=='PLI1.OVL+5F3A');require(q['entry']['c']==one(ws,0x5f39)['after']['c']and q['entry']['e']==one(ws,0x5f34)['reads'][0]['value'],'independent saved selector and pointer+5 inputs')
   require(r['ret']['after']['a']==q['output']['a']==1,'returned acquisition A delegated506E')
   require([q['output']['a']for q in calls if q['target']=='PLI1.OVL+3DD9']==[1,1],'two independent3DD9 predicates')
  else:
   require([q['output']['a']for q in calls if q['target']=='PLI1.OVL+4275']==[255,0],'loop continues once then pointer comparison exit')
   require(one(ws,0x6072)['writes'][0]['new_value']==0,'mismatch01AF controls loop byte')
   require(r['ret']['after']['a']==0 and r['ret']['origin']['offset']==0x60e4,'literal0 cleanup return')
  last=next(q for q in reversed(calls)if q['target']==('PLI1.OVL+506E'if tag==0x80 else'PLI1.OVL+5E53'))
  out=r['ret']['after'];saved_pointer=one(ws,0x5ed2)['writes'][0]['new_value']+256*one(ws,0x5ed4)['writes'][0]['new_value']
  require(pair(out,'h','l')==saved_pointer and all(out[k]==last['output'][k]for k in 'bcde')and out['flags']==(last['output']['flags']if tag==0x80 else rotate(one(ws,0x60bf))['flags']),'acquisition return: restored saved pointer HL, last child BC/DE/flags')
  acquisitions.append(identity(r)|dict(frame_setup=setup,route=route,field_byte=tag,children=calls,local_writes=writes(ws),chronology=chronology(r),branches=[dict(coordinate=coord(w['origin']),input_A=w['before']['a'],flags=w['before']['flags'],taken=w['control']['taken'])for w in ws if w['control']['kind']=='jump']))
 cases=[];reentries=[]
 for r in roots:
  ws=r['own_witnesses'];setup=frame_setup(r);F=r['entry']['before']['sp']-5;oldbase=pair(one(ws,0x60e8)['after'],'h','l');oldindex=val(one(ws,0x60f3),0xa6ca);newbase=(oldbase+2*oldindex+2)&65535
  require(one(ws,0x60fe)['writes']==[dict(address=0xa6cb,old_value=one(ws,0x60fe)['writes'][0]['old_value'],new_value=newbase&255),dict(address=0xa6cc,old_value=one(ws,0x60fe)['writes'][1]['old_value'],new_value=newbase>>8)],'nested pointer-stack advance')
  require([(one(ws,o)['writes'][0]['address'],one(ws,o)['writes'][0]['new_value'])for o in [0x60f0,0x60f2,0x6108,0x610d]]==[(F+2,oldbase&255),(F+3,oldbase>>8),(F+4,oldindex),(F,0)],'five-byte frame publications')
  sites=[0x610f,0x6119,0x611c,0x6129,0x6146,0x6155];require([w['origin']['offset']for w in ws if w['control']['kind']=='call']==sites,'exact natural direct children')
  cs=[child(r,o)for o in sites];acq=next(q for q in acquisitions if q['call_step']==cs[0]['call_step']);saved=one(ws,0x6116)
  require(saved['writes'][0]['address']==F+1 and saved['writes'][0]['new_value']==cs[0]['output']['a'],'save acquisition result into F1')
  for jump,producer,value in [(0x6121,0x611f,3),(0x614b,0x6149,5)]:
   w=one(ws,producer);require(w['after']['flags']==cmp(w['before']['a'],value),'field compare exactflags');require(one(ws,jump)['control']['taken'],'both field-special alternatives unobserved')
  require(val(one(ws,0x6130),F)==0 and one(ws,0x6132)['control']['taken'],'F0 zero skips8214')
  rot=rotate(one(ws,0x6158));require(cs[-1]['entry']['c']==0xfc and cs[-1]['output']['a']==0 and one(ws,0x6159)['control']['taken'],'FC selector mismatch skips repeat/acquisition arm')
  require([(q['address'],q['value'])for o in [0x619a,0x619b]for q in one(ws,o)['reads']]==[(F+1,cs[0]['output']['a']),(F+2,oldbase&255),(F+3,oldbase>>8),(F+4,oldindex)],'exact two POP H restores inherited frame words')
  require(pair(one(ws,0x618d)['before'],'h','l')==oldbase,'restore saved pointer before final index reload')
  require(val(one(ws,0x6191),F+4)==oldindex and val(one(ws,0x6198),F+1)==cs[0]['output']['a'],'return genuinely rereads saved acquisition result')
  out=r['ret']['after'];require(out['a']==cs[0]['output']['a']and pair(out,'d','e')==F+1 and pair(out,'h','l')==(oldbase>>8)+256*oldindex and pair(out,'b','c')==pair(cs[-1]['output'],'b','c')and out['flags']==rot['flags'],'path-specific exact return ABI')
  own=writes(ws);allws=body(r);nested=[q for q in rows['PLI1.OVL+6223']if r['call']['step_index']<q['call']['step_index']and q['ret']['step_index']<r['ret']['step_index']]
  # Corrected relations, original slots, and exact RET consumers prove every
  # enclosing CALL. Similar addresses/values do not supply ancestry.
  ret_by_step={w['step_index']:w for w in allws if w['control']['kind']=='return'}
  spines=[]
  for n in nested:
   spine=[]
   for w in allws:
    rel=relations.get(w['step_index'])
    if w['control']['kind']!='call'or rel is None or not(w['step_index']<=n['call']['step_index']and rel['step_index']>=n['ret']['step_index']):continue
    ret=ret_by_step[rel['step_index']];verify_return(w,ret,rel)
    spine.append(dict(callsite=coord(w['origin']),target=coord(w['target_origin']),call_step=w['step_index'],return_step=rel['step_index'],stack_slot=rel['frame']['stack_slot'],return_coordinate=coord(ret['origin']),return_address=w['call_return_address']))
   require(any(p['callsite']=='PLI1.OVL+5F3A'and p['target']=='PLI1.OVL+506E'for p in spine),'reentry through dispatch child')
   require(any(p['callsite']=='PLI1.OVL+53BD'and p['target']=='PLI1.OVL+500F'for p in spine),'reentry initiating child500F')
   require(spine[-1]['callsite']=='PLI1.OVL+6273'and spine[-1]['target']=='PLI1.OVL+6223','reentry actual CALL')
   spines.append(identity(n)|dict(spine=spine,local_writes_sha256=hashlib.sha256(json.dumps(writes(body(n)),sort_keys=True).encode()).hexdigest()))
  require(len(nested)==(2 if out['a']==1 else 0),'natural reentry/result correlation')
  tracked={0x20c3,0x20c5,0xa628,0xa62b,0xa62e,0xa635,0xa636,0xa63b,0xa63c,0xa642,0xa6ca,0xa6cb,0xa6cc,0xa863,0xa864,0xa932,0xae32,0xae33,0xae34,0xae35}
  state_writes=[dict(step=w['step_index'],writer=coord(w['origin']),address=q['address'],value=q['new_value'])for w in allws for q in w['writes']if q['address']in tracked]
  table_words=[dict(step=w['step_index'],writer=coord(w['origin']),address=q['address'],value=q['new_value'])for w in allws for q in w['writes']if newbase<=q['address']<newbase+2 and w['origin']['offset']not in (0x60fe,0x618d)]
  require(table_words,'actual nested pointer-table publication')
  outer_context=[]
  current=r
  for key in ['PLI1.OVL+61A4','PLI1.OVL+620C','PLI1.OVL+6223']:
   candidates=[p for p in rows[key]if any(w['step_index']==current['call']['step_index']for w in p['own_witnesses']if w['control']['kind']=='call')]
   if not candidates:continue
   require(len(candidates)==1,'unique direct surrounding corrected CALL frame');parent=candidates[0]
   q=parent['nested_returns'][current['call']['step_index']];verify_return(current['call'],q['ret'],q['relation']);require(q['ret']['step_index']==current['ret']['step_index'],'actual surrounding child consumer')
   outer_context.insert(0,identity(parent));current=parent
  cases.append(identity(r)|dict(frame_setup=setup,outer_context=outer_context,tracked_state_writes=state_writes,nested_pointer_slot_writes=table_words,frame_base=F,old_pointer_base=oldbase,old_index=oldindex,new_pointer_base=newbase,route=acq['route'],children=cs,local_writes=own,final_RAR=rot,chronology=chronology(r),nested_6223_call_steps=[n['call']['step_index']for n in nested]))
  if nested:reentries.append(dict(source=source,outer_60E5_call_step=r['call']['step_index'],acquisition_call_step=acq['call_step'],outer_context=outer_context,nested=spines,maximum_60E5_window_depth=max(sum(p['call']['step_index']<=q['call']['step_index']and q['ret']['step_index']<=p['ret']['step_index']for p in roots)for q in roots)))
 dispatch=[]
 for r in rows['PLI1.OVL+506E']:
  if not any(p['call']['step_index']<r['call']['step_index']and r['ret']['step_index']<p['ret']['step_index']for p in roots):continue
  ws=r['own_witnesses'];allws=body(r);pub=[dict(step=w['step_index'],writer=coord(w['origin']),value=q['new_value'])for w in allws for q in w['writes']if q['address']==0xa932]
  require(pub and pub[-1]['writer']=='PLI1.OVL+5031'and pub[-1]['value']==1,'literal1 publication after nested operations')
  require(one(ws,0x5706)['reads'][0]==dict(address=0xa932,value=1),'fresh dispatch-result read')
  dispatch.append(identity(r)|dict(literal_result_writers=pub,jump_table_reads=[dict(step=w['step_index'],coordinate=coord(w['origin']),reads=w['reads'])for w in ws if w['origin']['offset']in(0x50af,0x50b1)],own_children=[child(r,w['origin']['offset'])for w in ws if w['control']['kind']=='call'],chronology=chronology(r)))
 return dict(source=source,capture=str(capture.relative_to(ROOT)),run_id=index['run_id'],capture_sha256=hashlib.sha256((capture/'event-witnesses.json').read_bytes()).hexdigest(),image_sha256=hashlib.sha256(image).hexdigest(),structure={k:summarize(v)for k,v in rows.items()},cases=cases,acquisitions=acquisitions,leaves=leafcases,reentries=reentries,dispatch=dispatch)

def derive(analyses):
 return {
 'natural-cases':dict(sources=[{k:a[k]for k in ['source','capture','run_id','capture_sha256','image_sha256','structure','cases']}for a in analyses]),
 'route-distribution':dict(sources=[dict(source=a['source'],calls=len(a['cases']),routes=counts(c['route']for c in a['cases']),returned_A=counts(str(c['output']['a'])for c in a['cases']),reentries=sum(len(c['nested_6223_call_steps'])for c in a['cases']))for a in analyses]),
 'state-transition':dict(sources=[dict(source=a['source'],acquisitions=a['acquisitions'],dispatch_scope=a['dispatch'])for a in analyses]),
 'reentry-ancestry':dict(sources=[dict(source=a['source'],cases=a['reentries'])for a in analyses]),
 'dependency-assessment':dict(sources=[dict(source=a['source'],leaf_cases=a['leaves'])for a in analyses])}
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True);args=p.parse_args()
 args.output_dir.mkdir(parents=True,exist_ok=True)
 for n,d in derive([analyze(s,c,args.images)for s,c in CAPTURES.items()]).items():(args.output_dir/(n+'.json')).write_text(json.dumps(d,indent=2)+'\n')
