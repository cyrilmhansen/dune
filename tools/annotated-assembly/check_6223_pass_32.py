"""Corrected natural +6223 routes and bounded immediate dependency evidence.

CALL ancestry, canonical bytes, writes and flags are evidence. Captured child
outputs are observations, never an implementation or a semantic whitelist.
"""
from collections import Counter
from pathlib import Path
import hashlib,json
from check_minimal_pass_2 import coord,load,require,pair
from check_minimal_pass_3 import gather
from check_240a_pass_30 import one,cmp
from check_native_2511_pass_31 import CAPTURES,enclosing_parents
from procedure_evidence_packet import ROOT,verify_return
ENTRIES=[0x6223,0x620c,0x239a,0x256c,0x5929,0x01e8,0x61a4]
BOUNDS={f'PLI1.OVL+{x:04X}':(x,x+1)for x in ENTRIES}
FILES=['natural-roots','route-distribution','child-correlations','dependency-assessment']
REPORT=ROOT/'research/host-compiler/pass-32'
def counts(xs):return dict(sorted(Counter(xs).items()))
def identity(r):
 return dict(caller=coord(r['call']['origin']),call_step=r['call']['step_index'],entry_step=r['entry']['step_index'],return_step=r['ret']['step_index'],return_coordinate=coord(r['ret']['origin']),entry=r['entry']['before'],output=r['ret']['after'])
def body(r):return sorted(r['own_witnesses']+sum((q['memory_witnesses']for q in r['nested_returns'].values()),[]),key=lambda w:w['step_index'])
def ranges(addresses):
 xs=sorted(set(addresses));out=[]
 for a in xs:
  if out and out[-1][1]==a:out[-1][1]=a+1
  else:out.append([a,a+1])
 return out
def child(r,off):
 w=one(r['own_witnesses'],off);q=r['nested_returns'][w['step_index']];verify_return(w,q['ret'],q['relation'])
 projection=q['memory_witnesses'];effects=[dict(step=t['step_index'],coordinate=coord(t['origin']),address=x['address'],value=x['new_value'])for t in projection for x in t['writes']]
 reads=ranges(x['address']for t in projection for x in t['reads']);writes=ranges(x['address']for t in projection for x in t['writes'])
 return dict(observed_cpu_read_ranges=reads,observed_cpu_write_ranges=writes,cpu_memory_write_count=len(effects),cpu_memory_write_chronology_sha256=hashlib.sha256(json.dumps(effects,sort_keys=True).encode()).hexdigest(),lowest_observed_SP=min([w['after']['sp']]+[min(t['before']['sp'],t['after']['sp'])for t in projection]),callsite=coord(w['origin']),target=coord(w['target_origin']),call_step=w['step_index'],return_step=q['ret']['step_index'],return_coordinate=coord(q['ret']['origin']),entry=w['after'],output=q['ret']['after'],instruction_occurrences=q['ret']['step_index']-w['step_index'])
def rotate(w):
 a=w['before']['a'];f=w['before']['flags'];require(w['after']['a']==(a>>1)|(int(f['carry'])<<7),'exact RAR A')
 require(w['after']['flags']==dict(f,carry=bool(a&1)),'RAR changes only CY')
 return dict(step=w['step_index'],coordinate=coord(w['origin']),input_A=a,input_CY=f['carry'],output_A=w['after']['a'],flags=w['after']['flags'])
def chronology(r):
 ws=body(r);sp=r['entry']['before']['sp'];lower=min([sp]+[min(w['before']['sp'],w['after']['sp'])for w in ws]);stack=[];writes=[];calls=[]
 for w in ws:
  for q in w['writes']:
   row=dict(step=w['step_index'],writer=coord(w['origin']),address=q['address'],value=q['new_value'])
   if lower<=q['address']<sp+2:stack.append(row|dict(relative_address=q['address']-sp))
   else:writes.append(row)
  if w['control']['kind']=='call':calls.append([w['step_index'],coord(w['origin']),coord(w.get('target_origin'))])
 final={q['address']:q for q in stack}
 return dict(cpu_nonstack_write_count=len(writes),cpu_nonstack_writes_sha256=hashlib.sha256(json.dumps(writes,sort_keys=True).encode()).hexdigest(),call_chronology_sha256=hashlib.sha256(json.dumps(calls).encode()).hexdigest(),stack_write_count=len(stack),stack_writes_sha256=hashlib.sha256(json.dumps(stack,sort_keys=True).encode()).hexdigest(),final_stack_writers=list(final.values()),lowest_observed_relative_stack_address=min([q['relative_address']for q in stack],default=0))
def summarize(rs):
 ws=[w for r in rs for w in r['own_witnesses']]
 return dict(calls=len(rs),callers=counts(coord(r['call']['origin'])for r in rs),returns=counts(coord(r['ret']['origin'])for r in rs),own_instruction_occurrences=len(ws),own_coordinates=sorted({w['origin']['offset']for w in ws}),represented_bytes=len({w['origin']['offset']+i for w in ws for i in range(len(bytes.fromhex(w['bytes'])))}),direct_call_sites=counts(coord(w['origin'])+' -> '+coord(w['target_origin'])for w in ws if w['control']['kind']=='call'))
def analyze(source,capture,images,rows=None):
 if rows is None:rows=gather(capture,BOUNDS,include_nested_returns=True)
 image=(images/'PLI1.OVL').read_bytes();index=load(capture/'event-witnesses.json');require(index['run_id'].split(':')[0]==source,'selected run identity')
 for rs in rows.values():
  for r in rs:
   verify_return(r['call'],r['ret'],r['relation'])
   for w in r['own_witnesses']:
    require(w['origin']['image']['name']=='PLI1.OVL','canonical image');o=w['origin']['offset'];b=bytes.fromhex(w['bytes'])
    require(image[o:o+len(b)]==b and w['runtime_pc']==o+0x2200,'historical bytes/runtime')
 roots=[];deps={}
 for r in rows['PLI1.OVL+6223']:
  ws=r['own_witnesses'];first=child(r,0x6223);rot=rotate(one(ws,0x6226));taken=one(ws,0x6227)['control']['taken']
  require(taken==not_bool(rot['flags']['carry']),'first JNC polarity')
  second=None;secondrot=None
  if taken:route='B_5929_2511';sites=[0x6223,0x6240,0x6243,0x6249];value_site,add_site,last_site=0x6243,0x6246,0x6249
  else:
   second=child(r,0x622a);secondrot=rotate(one(ws,0x622d));skip=one(ws,0x622e)['control']['taken'];require(skip==not_bool(secondrot['flags']['carry']),'second JNC polarity')
   if skip:route='A_early';sites=[0x6223,0x622a];value_site=add_site=last_site=None
   else:route='A_01E8_256C';sites=[0x6223,0x622a,0x6231,0x6234,0x623a];value_site,add_site,last_site=0x6234,0x6237,0x623a
  require([w['origin']['offset']for w in ws if w['control']['kind']=='call']==sites,'exact direct child order')
  children=[child(r,o)for o in sites];flow=None
  if value_site is not None:
   v=child(r,value_site);add=one(ws,add_site);mov=one(ws,add_site+2);last=child(r,last_site)
   require(add['before']['a']==v['output']['a']and add['after']['a']==(v['output']['a']+0x13)&255,'fresh239A -> ADI13')
   a0=add['before']['a'];v0=(a0+0x13)&255;require(add['after']['flags']==dict(sign=v0>=128,zero=v0==0,auxiliary_carry=(a0&15)+3>15,parity=v0.bit_count()%2==0,carry=a0+0x13>255),'ADI13 flags separatefromchildflags')
   require(mov['after']['c']==add['after']['a']and last['entry']['c']==add['after']['a'],'MOV C,A -> actual child argument')
   flow=dict(returned_A=v['output']['a'],return_flags=v['output']['flags'],after_ADI13=add['after']['a'],addition_flags=add['after']['flags'],subsequent_child=last['target'],input_C=last['entry']['c'])
   require(r['ret']['after']==dict(last['output'],pc=r['ret']['after']['pc'],sp=r['ret']['after']['sp']),'return state delegated final child')
  else:require(r['ret']['after']==dict(one(ws,0x622d)['after'],pc=r['ret']['after']['pc'],sp=r['ret']['after']['sp']),'early RAR return state')
  require(not any(w['writes']for w in ws if w['control']['kind']!='call'),'6223 no local scratch/frame writes')
  pred_body=r['nested_returns'][one(ws,0x6223)['step_index']]['memory_witnesses'];pred_reads=[dict(coordinate=coord(w['origin']),step=w['step_index'],address=q['address'],value=q['value'])for w in pred_body for q in w['reads']if q['address']==0x20c3]
  require(len(pred_reads)==2,'020E two independent selector reads')
  roots.append(identity(r)|dict(route=route,predicate_reads=pred_reads,predicate=first['output']['a'],first_RAR=rot,local_predicate=None if second is None else second['output']['a'],second_RAR=secondrot,children=children,value_flow=flow,chronology=chronology(r)))
 for key,rs in rows.items():
  cases=[]
  for r in rs:
   if key.endswith('6223'):continue
   ws=r['own_witnesses'];cs=[child(r,w['origin']['offset'])for w in ws if w['control']['kind']=='call'];q=identity(r)|dict(children=cs,local_writes=[dict(step=w['step_index'],coordinate=coord(w['origin']),address=x['address'],value=x['new_value'])for w in ws for x in w['writes']if w['control']['kind']!='call'],branches=[dict(coordinate=coord(w['origin']),producer=coord(ws[j-1]['origin']),taken=w['control']['taken'],flags=w['before']['flags'])for j,w in enumerate(ws)if w['control']['kind']=='jump'and w['bytes'][:2]!='C3'])
   if key.endswith('01E8'):
    v=one(ws,0x01ee)['reads'][0]['value'];require(one(ws,0x01f3)['control']['taken']==(v==0x70),'01E8 CPI70/JZ polarity')
    require(v!=0x70,'new01E8 equality arm requires separate analysis')
    require([(x['address'],x['new_value'])for x in one(ws,0x01eb)['writes']]==[(0xa5b0,2),(0xa5b1,0)],'01E8 low then high word2')
    require(r['ret']['after']['a']==v and pair(r['ret']['after'],'h','l')==2 and r['ret']['after']['flags']==cmp(v,0x70),'01E8 return value and compareflags')
    require(all(r['ret']['after'][k]==r['entry']['before'][k]for k in 'bcde'),'01E8 BC/DE preservation')
    q.update(selected_A628=v,path='not70_return')
   elif key.endswith('61A4'):
    require(one(ws,0x61a7)['writes'][0]['address']==0xa941 and one(ws,0x61a7)['writes'][0]['new_value']==0,'61A4 unconditionalzero')
    require(r['ret']['after']==dict(cs[0]['output'],pc=r['ret']['after']['pc'],sp=r['ret']['after']['sp']),'61A4 delegates60E5')
    q.update(result=r['ret']['after']['a'],chronology=chronology(r))
   elif key.endswith('620C'):
    v=cs[0]['output']['a'];require(one(ws,0x620f)['writes'][0]['new_value']==v,'620C cache child A');require(one(ws,0x6214)['control']['taken']==(v!=0),'620C CPI00/JNZ')
    require(one(ws,0x6212)['after']['flags']==cmp(v,0),'620C comparison flags')
    if v==0:require(r['ret']['after']['a']==1 and r['ret']['after']['flags']==cmp(v,0),'zero returns1/comparisonflags')
    else:
     a=(v-4)&255;require(one(ws,0x621d)['after']['a']==a,'first wrapping subtract4');require(one(ws,0x621f)['after']['a']==(a-1)&255,'second subtract1')
     require(r['ret']['after']['a']==(255 if a<1 else 0),'second borrow expanded by SBB A')
     borrow=a<1;require(r['ret']['after']['flags']==dict(sign=borrow,zero=not borrow,auxiliary_carry=not borrow,parity=True,carry=borrow),'620C SBB self exactflags')
    q.update(child_A=v,cached_A945=v,result=r['ret']['after']['a'],path='zero_literal1'if v==0 else'nonzero_sub4_sub1_mask')
   elif key.endswith('239A'):
    require(cs[0]['entry']['c']==0,'239A explicit index0')
    require(r['ret']['after']==dict(cs[0]['output'],pc=r['ret']['after']['pc'],sp=r['ret']['after']['sp']),'239A delegates2355')
    projection=r['nested_returns'][one(ws,0x239c)['step_index']]['memory_witnesses'];selected=one(projection,0x2362)['reads'][0]
    require(selected['address']==0xa628,'2355 selected index0 is fresh A628')
    dispatch_calls=[dict(step=t['step_index'],callsite=coord(t['origin']),target=coord(t.get('target_origin')),input_C=t['before']['c'])for t in projection if t['control']['kind']=='call'and coord(t['origin'])in ['PLI1.OVL+2363','PLI1.OVL+2395','PLI1.OVL+2348']]
    q.update(index=0,dispatch_child_calls=dispatch_calls,selected_A628=selected['value'],selected_read_step=one(projection,0x2362)['step_index'],result=r['ret']['after']['a'])
   elif key.endswith('256C'):
    attr=cs[0]['output']['a'];special=attr==6;expected=[0x2574,0x2581,0x258c,0x2591,0x2599]if special else[0x2574,0x25a4]
    require([w['origin']['offset']for w in ws if w['control']['kind']=='call']==expected,'256C exact highattribute route order')
    require(one(ws,0x2579)['control']['taken']==not_bool(special),'256C CPI06/JNZ')
    sp=r['entry']['before']['sp'];require(one(ws,0x256d)['writes']==[dict(address=sp-1,old_value=one(ws,0x256d)['writes'][0]['old_value'],new_value=r['entry']['before']['c']),dict(address=sp-2,old_value=one(ws,0x256d)['writes'][1]['old_value'],new_value=r['entry']['before']['c'])],'onebyte frame inherited PUSH BC after MOV B,C')
    if special:require(cs[3]['entry']['c']==0,'23D2 index0');q['mapped_word_publication']=dict(position=cs[2]['entry']['c'],word=pair(cs[2]['entry'],'d','e'))
    require(r['ret']['after']==dict(cs[-1]['output'],pc=r['ret']['after']['pc'],sp=r['ret']['after']['sp']),'256C lastchild return delegation')
    q.update(input=r['entry']['before']['c'],attribute=attr,path='attr6_8048_word_23D2_7EC0'if special else'not6_2511',chronology=chronology(r))
   elif key.endswith('5929'):
    rotate(one(ws,0x592f));require(not one(ws,0x5930)['control']['taken'],'all5929 scanfound route')
    require([w['origin']['offset']for w in ws if w['control']['kind']=='call']==[0x592c,0x5937,0x5a34,0x5a39,0x5a3c],'bounded5929 child order')
    selector=one(ws,0x5948)['reads'][0]['value'];primary=one(ws,0x594e)['reads'][0]['value'];pointer=pair(one(ws,0x593a)['after'],'h','l')
    require(selector not in (3,4,7,8,9),'observed5929 excludes static alternative arms')
    require(cs[0]['output']['a']==1,'57B7 found result');require(cs[1]['entry']['c']==one(ws,0x5933)['reads'][0]['value'],'fresh20C3 into46A7')
    require(cs[3]['entry']['c']==(cs[2]['output']['a']+1)&255,'5929 fresh239A -> INR ->2511')
    require([(x['address'],x['new_value'])for o in [0x593d,0x5940]for x in one(ws,o)['writes']]==[(0xa63b,pointer&255),(0xa63c,pointer>>8),(0xa635,pointer&255),(0xa636,pointer>>8)],'two littleendian pointer publications')
    require(one(ws,0x5a2a)['writes'][0]['address']==(pointer+4)&65535 and one(ws,0x5a2a)['writes'][0]['new_value']==primary,'pointer+4 primary')
    require(one(ws,0x5a33)['writes'][0]['address']==(pointer+5)&65535 and one(ws,0x5a33)['writes'][0]['new_value']==0,'pointer+5 zeroextra')
    require(r['ret']['after']==dict(cs[-1]['output'],pc=r['ret']['after']['pc'],sp=r['ret']['after']['sp']),'5929 lastchild return delegation')
    require(one(ws,0x596e)['control']['taken']==not_bool(one(ws,0x596d)['after']['flags']['carry']),'5929 local RAR/JNC polarity')
    rotate(one(ws,0x596d))
    q.update(selector=selector,primary=primary,pointer=pointer,scan_result=cs[0]['output']['a'],result239A=cs[2]['output']['a'],next_C=cs[3]['entry']['c'],chronology=chronology(r))
   cases.append(q)
  if not key.endswith('6223'):deps[key]=dict(structure=summarize(rs),cases=cases)
 # Indirect re-entry is ordinary CALL ancestry, not a direct recursive CALL
 # in6223 and not basic-block ownership. Keep each local route separate.
 for c in sorted(roots,key=lambda c:c['call_step']):
  parents=[p for p in roots if p['call_step']<c['call_step'] and c['return_step']<p['return_step'] and p['entry']['sp']>=c['entry']['sp']+2]
  if parents:
   parent=max(parents,key=lambda p:p['call_step']);envelope=next(q for q in parent['children']if q['call_step']<c['call_step']and c['return_step']<q['return_step'])
   q60=next(q for case in deps['PLI1.OVL+61A4']['cases']for q in case['children']if q['call_step']<c['call_step']and c['return_step']<q['return_step'])
   require(envelope['target']=='PLI1.OVL+620C'and q60['target']=='PLI1.OVL+60E5','indirect reentry envelopes')
   c.update(nearest_enclosing_6223_call_step=parent['call_step'],enclosing_direct_child=envelope['target'],enclosing_60E5_call_step=q60['call_step'],window_depth=parent['window_depth']+1)
  else:c.update(nearest_enclosing_6223_call_step=None,enclosing_direct_child=None,enclosing_60E5_call_step=None,window_depth=1)
 return dict(source=source,capture=str(capture.relative_to(ROOT)),run_id=index['run_id'],capture_sha256=hashlib.sha256((capture/'event-witnesses.json').read_bytes()).hexdigest(),image_sha256=hashlib.sha256(image).hexdigest(),structure=summarize(rows['PLI1.OVL+6223']),roots=roots,dependencies=deps)
def not_bool(x):return not x

def derive(analyses):
 result={n:dict(sources=[])for n in FILES}
 for a in analyses:
  result['natural-roots']['sources'].append({k:a[k]for k in ['source','capture','run_id','capture_sha256','image_sha256','structure','roots']})
  rs=a['roots'];result['route-distribution']['sources'].append(dict(source=a['source'],routes=counts(r['route']for r in rs),predicate_hex=counts(f"{r['predicate']:02X}"for r in rs),local_predicate_hex=counts(f"{r['local_predicate']:02X}"for r in rs if r['local_predicate']is not None),outermost_6223_windows=sum(r['window_depth']==1 for r in rs),indirect_reentry_windows=sum(r['window_depth']>1 for r in rs),maximum_6223_window_depth=max((r['window_depth']for r in rs),default=0),value_flow=counts(str(r['value_flow']['returned_A'])+' +13 -> '+str(r['value_flow']['input_C'])for r in rs if r['value_flow']is not None)))
  result['child-correlations']['sources'].append(dict(source=a['source'],dependencies=a['dependencies']))
  result['dependency-assessment']['sources'].append(dict(source=a['source'],structure={k:v['structure']for k,v in a['dependencies'].items()}))
 return result
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--images',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True);args=p.parse_args()
 analyses=[analyze(s,c,args.images)for s,c in CAPTURES.items()];args.output_dir.mkdir(parents=True,exist_ok=True)
 for n,d in derive(analyses).items():(args.output_dir/(n+'.json')).write_text(json.dumps(d,indent=2)+'\n')
 print({a['source']:a['structure']['calls']for a in analyses})
