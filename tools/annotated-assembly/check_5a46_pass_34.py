"""Bounded natural pointer acquisition/publication; no native implementation."""
from check_6223_pass_32 import (ROOT,CAPTURES,gather,coord,require,pair,load,one,
 identity,body,child,chronology,summarize,rotate,verify_return,counts)
from check_60e5_pass_33 import ats,val,writes
from check_240a_pass_30 import cmp
import hashlib,json
REPORT=ROOT/'research/host-compiler/pass-34'
ENTRIES=[0x5a46,0x45f0,0x4562,0x4584,0x5e98]
BOUNDS={f'PLI1.OVL+{x:04X}':(x,x+1)for x in ENTRIES}
FILES=['natural-cases','route-distribution','state-correlations','dependency-cases']
def stack_proof(r):
 ws=body(r);S=r['entry']['before']['sp'];lower=min(min(w['before']['sp'],w['after']['sp'])for w in ws);by={}
 for w in ws:
  if w['control']['kind']=='call':
   raw=bytes.fromhex(w['bytes']);continuation=(w['runtime_pc']+len(raw))&65535
   require(w['call_return_address']==continuation,'exact CALL continuation from immutable encoding')
   sp=w['before']['sp'];require([(q['address'],q['new_value'])for q in w['writes']]==[(sp-1,continuation>>8),(sp-2,continuation&255)],'CALL high/low stack writer ancestry')
  if w['disassembly']=='PUSH H':
   sp=w['before']['sp'];require([(q['address'],q['new_value'])for q in w['writes']]==[(sp-1,w['before']['h']),(sp-2,w['before']['l'])],'PUSH H register-derived residue')
  for q in w['writes']:
   if lower<=q['address']<S:
    row=dict(writer=coord(w['origin']),step=w['step_index'],relative_address=q['address']-S,value=q['new_value'])
    by.setdefault(q['address'],[]).append(row)
 return [v[-1]|dict(overwritten_writers=[p['writer']for p in v[:-1]])for a,v in sorted(by.items())]
def validate_scan(r):
 ws=r['own_witnesses'];e=r['entry']['before'];out=r['ret']['after'];n=e['e'];src=pair(e,'b','c')
 require([(q['address'],q['new_value'])for o in [0x4587,0x4589,0x458b]for q in one(ws,o)['writes']]==[(0xa907,n),(0xa906,e['b']),(0xa905,e['c'])],'count then source high/low scratch order')
 sub=child(r,0x4592);p=pair(sub['output'],'b','c');top=pair(sub['output'],'h','l'); # HL is initially the difference, not top
 reads=[q for w in r['nested_returns'][one(ws,0x4592)['step_index']]['memory_witnesses']for q in w['reads']]
 top=next(q['value']for q in reads if q['address']==0x1c36)+256*next(q['value']for q in reads if q['address']==0x1c37)
 require(one(ws,0x4595)['control']['taken']==(p<=top),'record floor JNC after top-pointer borrow')
 if p<=top:
  require([(w['address'],w['value'])for w in writes(ws)]==[(0xa907,n),(0xa906,e['b']),(0xa905,e['c'])],'floor has only three ordered scratch writes')
  require(r['ret']['origin']['offset']==0x45ef,'floor RET exact')
  require(out==dict(sub['output'],pc=out['pc'],sp=out['sp']),'floor returns child subtraction state without forcing zero')
  return dict(route='pointer_at_or_below_top',pointer=p,record_top=top,count=n,source=src,comparisons=[])
 header=one(ws,0x459b)['reads'][0]['value'];require(one(ws,0x45a3)['before']['a']==(header-10)&255,'DCR twice/SUI08 wrapping header length')
 require(not one(ws,0x45a4)['control']['taken']and n>0,'natural positive matching length; retry remains unobserved')
 require(header==((n+10)&255),'length equal independent of content')
 comparisons=[]
 for k,(dec,rd,test)in enumerate(zip(ats(ws,0x45b8),ats(ws,0x45d0),ats(ws,0x45d1))):
  index=n-k-1;require(dec['reads'][0]['value']==index+1 and dec['writes'][0]['new_value']==index,'descending remaining publication')
  require(rd['reads'][0]['address']==(src+index)&65535 and test['reads'][0]['address']==(p+10+index)&65535,'independent source/payload addresses')
  require(rd['reads'][0]['value']==test['reads'][0]['value'],'natural byte comparison matches')
  require(test['after']['flags']==cmp(rd['after']['a'],test['reads'][0]['value']),'exact payload CMP flags')
  comparisons.append(dict(index=index,source_address=rd['reads'][0]['address'],payload_address=test['reads'][0]['address'],value=rd['reads'][0]['value']))
 require(len(comparisons)==n,'all bytes compared, no deduplication')
 require([(w['address'],w['value'])for w in writes(ws)]==[(0xa907,n),(0xa906,e['b']),(0xa905,e['c']),(0xa908,n)]+[(0xa908,i)for i in reversed(range(n))],'scan only ordered scratch writes; selected pointer/payload unchanged')
 require(all(not w['control']['taken']for w in ats(ws,0x45d2))and not ats(ws,0x45da)[-1]['control']['taken'],'mismatch branch absent; final remaining zero exits')
 require(out['a']==0 and pair(out,'b','c')==10 and pair(out,'d','e')==src and pair(out,'h','l')==(p+10)&65535 and out['flags']==cmp(0,0),'matching return ABI independent of input flags')
 require(r['ret']['origin']['offset']==0x45dd,'matching return site')
 return dict(route='positive_exact_payload_match',pointer=p,record_top=top,count=n,source=src,header=header,comparisons=comparisons)
def validate_leaf(r):
 ws=r['own_witnesses'];read=one(ws,0x4562);saved=pair(read['after'],'h','l');q=child(r,0x4569)
 require([x['address']for x in read['reads']]==[0x20c5,0x20c6],'paired width and neighboring first source byte')
 require(pair(q['entry'],'b','c')==0x20c6 and pair(q['entry'],'d','e')==saved,'fresh saved pair -> DE; literal source address')
 require(not writes(ws),'wrapper has only CALL residue')
 require(r['ret']['after']==dict(q['output'],pc=r['ret']['after']['pc'],sp=r['ret']['after']['sp']),'wrapper delegates complete452B ABI')
 projection=r['nested_returns'][one(ws,0x4569)['step_index']]['memory_witnesses']
 # The complete452B contract is reused; source reads are identified by runtime addresses.
 actual=[[x['address'],x['value']]for w in projection for x in w['reads']if 0x20c6<=x['address']<0x20c6+(saved&255)]
 require([a for a,v in actual]==[0x20c6+i for i in reversed(range(saved&255))],'descending source-read chronology')
 require(q['output']['a']==sum(v for a,v in actual)&127,'selected sum mask from actual source reads')
 return dict(saved_pair=saved,count=saved&255,discarded_for_count=saved>>8,source_reads=actual,result=q['output']['a'])
def analyze(source,capture,images,rows=None):
 rows=gather(capture,BOUNDS,include_nested_returns=True)if rows is None else rows
 image=(images/'PLI1.OVL').read_bytes();resident=(images/'PLI.COM').read_bytes();index=load(capture/'event-witnesses.json')
 require(index['run_id'].split(':')[0]==source,'selected source/run identity')
 for rs in rows.values():
  for r in rs:
   verify_return(r['call'],r['ret'],r['relation'])
   for w in body(r):
    name=w['origin']['image']['name'];raw=bytes.fromhex(w['bytes']);off=w['origin']['offset']
    original=image if name=='PLI1.OVL'else resident
    require(name in ('PLI1.OVL','PLI.COM')and original[off:off+len(raw)]==raw and w['runtime_pc']==off+(0x2200 if name=='PLI1.OVL'else 0x100),'nested canonical immutable historical bytes')
   for w in r['own_witnesses']:
    off=w['origin']['offset'];raw=bytes.fromhex(w['bytes']);require(w['origin']['image']['name']=='PLI1.OVL'and image[off:off+len(raw)]==raw and w['runtime_pc']==off+0x2200,'canonical image+offset+exact byte identity')
 leaves=[identity(r)|dict(law=validate_leaf(r),chronology=chronology(r),stack=stack_proof(r))for r in rows['PLI1.OVL+4562']]
 scans=[identity(r)|dict(law=validate_scan(r),chronology=chronology(r),stack=stack_proof(r))for r in rows['PLI1.OVL+4584']]
 wrappers=[]
 for r in rows['PLI1.OVL+45F0']:
  ws=r['own_witnesses'];cs=[child(r,o)for o in [0x45f0,0x45f3,0x45fd]]
  require([w['origin']['offset']for w in ws if w['control']['kind']=='call']==[0x45f0,0x45f3,0x45fd],'45F0 exact child order')
  read=one(ws,0x45f6);require(cs[-1]['entry']['e']==read['after']['l']and cs[-1]['entry']['d']==read['after']['h']and pair(cs[-1]['entry'],'b','c')==0x20c6,'fresh width pair independent of hash child')
  require(r['ret']['after']==dict(cs[-1]['output'],sp=r['ret']['after']['sp'],pc=r['ret']['after']['pc']),'45F0 delegates final scan state')
  require(not writes(ws),'45F0 no local data writes')
  selection=r['nested_returns'][one(ws,0x45f3)['step_index']]['memory_witnesses'];published=one(selection,0x423d)
  low=one(selection,0x4239)['reads'][0];high=one(selection,0x423b)['reads'][0]
  require(high['address']==low['address']+1 and [(q['address'],q['new_value'])for q in published['writes']]==[(0xa863,low['value']),(0xa864,high['value'])],'422F selected slot low/high -> working pointer publication')
  require(not any(q['address']in(0xa863,0xa864)for w in body(r)if w['step_index']>published['step_index']for q in w['writes']),'working pointer not rewritten by subsequent matching scanner')
  wrappers.append(identity(r)|dict(selected_slot=low['address'],selected_pointer=low['value']+256*high['value'],working_pointer_writer=coord(published['origin']),route='hash_select_exact_match',children=cs,fresh_width=read['after']['l'],fresh_neighbor=read['after']['h'],chronology=chronology(r),stack=stack_proof(r)))
 roots=[]
 for r in rows['PLI1.OVL+5A46']:
  ws=r['own_witnesses'];sites=[0x5a46,0x5a4d,0x5a50,0x5a87];cs=[child(r,o)for o in sites]
  require([w['origin']['offset']for w in ws if w['control']['kind']=='call']==sites,'natural direct child order')
  gate_reads=[dict(step=w['step_index'],coordinate=coord(w['origin']),value=q['value'])for w in r['nested_returns'][one(ws,0x5a46)['step_index']]['memory_witnesses']for q in w['reads']if q['address']==0x20c3]
  require(len(gate_reads)==2 and cs[0]['output']['a']==(255 if gate_reads[0]['value']==1 or gate_reads[1]['value']>=0x81 else 0),'complete020E independent selector-read law')
  rot=rotate(one(ws,0x5a49));boundrot=rotate(one(ws,0x5a53))
  require(cs[0]['output']['a']==255 and not one(ws,0x5a4a)['control']['taken'],'selector gate mask set -> acquisition')
  require(cs[2]['output']['a']==255 and one(ws,0x5a54)['control']['taken'],'working pointer >= reference -> returned-mask bit enters publication')
  inc=one(ws,0x5a7a);oldindex=inc['reads'][0]['value'];newindex=(oldindex+1)&255;require(inc['writes'][0]['new_value']==newindex,'byte index wrap publication')
  f=inc['before']['flags'];require(inc['after']['flags']==dict(f,sign=newindex>=128,zero=newindex==0,auxiliary_carry=(oldindex&15)==15,parity=newindex.bit_count()%2==0),'INR flags/CY independently checked')
  firstbase=pair(one(ws,0x5a80)['after'],'h','l');firstslot=(firstbase+2*one(ws,0x5a7b)['reads'][0]['value'])&65535
  require(pair(cs[-1]['entry'],'h','l')==firstslot and pair(cs[-1]['entry'],'d','e')==0xa6a8,'resident subtraction exact slot/limit arguments')
  require(cs[-1]['target']=='PLI.COM+1A2C','reuse resident difference contract')
  # Validate the existing complete contract without replacing its arithmetic.
  require(pair(cs[-1]['output'],'h','l')==(0xa6a8-firstslot)&65535 and cs[-1]['output']['a']==((0xa6a8-firstslot)&65535)>>8 and cs[-1]['output']['flags']['carry']==(0xa6a8<firstslot),'resident difference/borrow')
  require(not one(ws,0x5a8a)['control']['taken'],'natural slot <= limit, unsupported overflow alternative absent')
  carrier=one(ws,0x5a8d);require([q['address']for q in carrier['reads']]==[0xa6ca,0xa6cb],'fresh paired index read and discarded neighboring base-low')
  finalbase=pair(one(ws,0x5a94)['after'],'h','l');slot=(finalbase+2*carrier['after']['l'])&65535
  push=one(ws,0x5a98);pop=one(ws,0x5a9d);pointer=pair(one(ws,0x5a99)['after'],'h','l');S=r['entry']['before']['sp']
  require(pair(push['before'],'h','l')==slot and push['before']['sp']==S,'temporary destination PUSH')
  require([(q['address'],q['value'])for q in pop['reads']]==[(S-2,slot&255),(S-1,slot>>8)],'POP recovers its actual pushed destination')
  require([(q['address'],q['new_value'])for o in [0x5a9e,0x5aa0]for q in one(ws,o)['writes']]==[(slot,pointer&255),((slot+1)&65535,pointer>>8)],'fresh working pointer publication low then high')
  out=r['ret']['after'];expectedflags=dict(cs[-1]['output']['flags'],carry=finalbase+2*carrier['after']['l']>65535)
  producer=next(q for q in wrappers if q['call_step']==cs[1]['call_step'])
  require(producer['selected_pointer']==pointer,'selected422F word supplies fresh root pointer')
  before_read=[w for w in body(r)if w['step_index']<one(ws,0x5a99)['step_index']]
  latest=[(w['origin']['offset'],q['new_value'])for address in (0xa863,0xa864)for w in before_read for q in w['writes']if q['address']==address]
  require(latest==[(0x423d,pointer&255),(0x423d,pointer>>8)],'actual sole latest writers of root working-pointer carrier')
  require(out['a']==cs[-1]['output']['a']and pair(out,'b','c')==pair(cs[-1]['output'],'b','c')and pair(out,'d','e')==pointer and pair(out,'h','l')==(slot+1)&65535 and out['flags']==expectedflags,'natural publication return state from subtraction then address DAD')
  require([(q['address'],q['new_value'])for w in ws for q in w['writes']if w['control']['kind']!='call'and w['disassembly']!='PUSH H']==[(0xa6ca,newindex),(slot,pointer&255),((slot+1)&65535,pointer>>8)],'exact local nonstack write chronology')
  siblings=None
  for parent in rows['PLI1.OVL+5E98']:
   if any(w['step_index']==r['call']['step_index']for w in parent['own_witnesses']):
    a=child(parent,0x5ebd);b=child(parent,0x5ec0)
    first=next(w['step_index']for w in ats(parent['own_witnesses'],0x5ec3)if w['step_index']>b['return_step'])
    c=child(dict(parent,own_witnesses=[w for w in parent['own_witnesses']if w['origin']['offset']!=0x5ec3 or w['step_index']==first]),0x5ec3)
    require(a['return_step']<b['call_step']<b['return_step']<c['call_step'],'subsequent784E then4275 chronology')
    require(b['entry']==dict(out,sp=b['entry']['sp'],pc=b['entry']['pc']),'784E receives acquired state')
    require(c['output']['a']==255,'subsequent natural pointer-bound mask set')
    projection=parent['nested_returns'][one(parent['own_witnesses'],0x5ec0)['step_index']]['memory_witnesses']
    require(not any(q['address']in [0xa863,0xa864,0xa6ca,slot,slot+1]for w in projection for q in w['writes']),'784E leaves selected acquisition/publication cells intact')
    siblings=dict(parent_call_step=parent['call']['step_index'],children=[a,b,c])
  roots.append(identity(r)|dict(route='gate_set_working_pointer_in_range_publish',children=cs,gate_reads=gate_reads,gate_RAR=rot,pointer_mask_RAR=boundrot,old_index=oldindex,new_index=newindex,first_base=firstbase,first_slot=firstslot,discarded_neighbor=carrier['after']['h'],fresh_base=finalbase,final_slot=slot,pointer=pointer,local_writes=writes(ws),chronology=chronology(r),stack=stack_proof(r),subsequent_acquisition=siblings))
 return dict(source=source,capture=str(capture.relative_to(ROOT)),run_id=index['run_id'],capture_sha256=hashlib.sha256((capture/'event-witnesses.json').read_bytes()).hexdigest(),image_sha256=hashlib.sha256(image).hexdigest(),structure={k:summarize(v)for k,v in rows.items()if not k.endswith('5E98')},roots=roots,wrappers=wrappers,leaves=leaves,scans=scans)
def derive(analyses):
 return {'natural-cases':dict(sources=[{k:a[k]for k in ['source','capture','run_id','capture_sha256','image_sha256','structure','roots']}for a in analyses]),'route-distribution':dict(sources=[dict(source=a['source'],root_routes=counts(r['route']for r in a['roots']),scan_routes=counts(r['law']['route']for r in a['scans']),hash_counts=counts(str(r['law']['count'])for r in a['leaves']),selected_pointers=counts(f"{r['pointer']:04X}"for r in a['roots']))for a in analyses]),'state-correlations':dict(sources=[dict(source=a['source'],wrappers=a['wrappers'])for a in analyses]),'dependency-cases':dict(sources=[dict(source=a['source'],leaves=a['leaves'],scans=a['scans'])for a in analyses])}
if __name__=='__main__':
 import argparse
 from pathlib import Path
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True);args=p.parse_args();args.output_dir.mkdir(parents=True,exist_ok=True)
 for n,d in derive([analyze(s,c,args.images)for s,c in CAPTURES.items()]).items():(args.output_dir/(n+'.json')).write_text(json.dumps(d,indent=2)+'\n')
