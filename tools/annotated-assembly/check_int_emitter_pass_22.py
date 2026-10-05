#!/usr/bin/env python3
"""Bounded resident append/flush archaeology; corrected returns and real BDOS events."""
import argparse,json
from collections import Counter
from pathlib import Path
from minimal_baseline import load
from check_minimal_pass_3 import gather
from check_minimal_pass_2 import coord,pair
from procedure_evidence_packet import ROOT,verify_return
CAPTURES={'MINIMAL':ROOT/'_build/minimal-baseline/capture','FIZZBUZ':ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture','PICTURE':ROOT/'_build/discriminator-pass-15/selected-capture'}
BOUNDS={'PLI.COM+0EF6':(0xef6,0xf2d),'PLI.COM+0328':(0x328,0x338),'PLI.COM+0EA0':(0xea0,0xea7),'PLI.COM+04F2':(0x4f2,0x513)}
REPORT=ROOT/'research/host-compiler/pass-22'
def require(b,s):
 if not b:raise ValueError(s)
def at(ws,o):return next(w for w in ws if coord(w['origin'])==f'PLI.COM+{o:04X}')
def cmp_flags(a,b):
 v=(a-b)&255
 return dict(sign=bool(v&128),zero=v==0,auxiliary_carry=(a&15)>=(b&15),parity=v.bit_count()%2==0,carry=a<b)
def compact_case(c):return {k:v for k,v in c.items()if k!='buffer_after_hex'}
def audit(capture,live):
 require(load(capture/'event-witnesses.json')['run_id'].startswith(live['source']+':'),'Selected capture run identity mismatch')
 rows=gather(capture,BOUNDS,include_nested_returns=True);cases=live['cases'];entries={r['entry']['step_index']:r for r in rows['PLI.COM+0EF6']}
 require(len(cases)==len(entries),'Live/capture invocation mismatch')
 selected={};window=None;last_writes={};read_bytes={};error_calls=Counter()
 for chunk in load(capture/'event-witnesses.json')['chunks']:
  for e in load(capture/'event-witnesses/chunks'/f"{chunk['id']:06d}.json")['events']:
   if e['type']=='instruction':
    w=e['witness'];step=w['step_index']
    if step in entries:window=entries[step];selected[step]={'events':[],'instructions':[],'prior_buffer':dict(read_bytes),'prior_buffer_writers':{a:q for a,q in last_writes.items()if 0x1d8c<=a<0x1e0c}}
    if w['control']['kind']=='call'and w['control']['taken']and coord(w.get('target_origin')) in ['PLI.COM+0EA0','PLI.COM+04F2']:error_calls[coord(w['target_origin'])]+=1
    if window:
     selected[window['entry']['step_index']]['instructions'].append(w)
     if step==window['ret']['step_index']:
      selected[window['entry']['step_index']]['last_writes']={a:q for a,q in last_writes.items()if window['entry']['before']['sp']-10<=a<window['entry']['before']['sp']}
      window=None
    for q in w['writes']:
     last_writes[q['address']]={'step':step,'coordinate':coord(w['origin']),'value':q['new_value']}
     if 0x1d8c<=q['address']<0x1e0c:read_bytes[q['address']]=q['new_value']
   else:
    if window:selected[window['entry']['step_index']]['events'].append(e)
    if e['type']=='host_effect'and e['effect']['kind']=='memory_write':
     q=e['effect'];last_writes[q['address']]={'step':e['step_index'],'coordinate':'HOST/BDOS','value':q['new_value']}
     if 0x1d8c<=q['address']<0x1e0c:read_bytes[q['address']]=q['new_value']
 require(not window,'Lost emitter return')
 non=[];flush=[];chron=[]
 for c in cases:
  r=entries[c['entry_step']];ws=r['own_witnesses'];detail=selected[c['entry_step']];verify_return(r['call'],r['ret'],r['relation'])
  slot=c['input']['sp']
  require(not any(q['address']in [slot,slot+1]for w in detail['instructions']for q in w['writes']),'Original outer return slot overwritten')
  require(c['input']==r['entry']['before']and c['output']==r['ret']['after']and c['caller']==coord(r['call']['origin'])and c['return_step']==r['ret']['step_index'],'State/identity mismatch')
  i=c['entry_index'];next_i=(i+1)&255;dest=0x1d8c+i;C=c['input']['c']
  require(at(ws,0xefa)['reads']==[dict(address=0x1e0c,value=i),dict(address=0x1e0d,value=c['neighbor_1E0D'])],'Index neighboring read')
  require(at(ws,0xf03)['reads']==[dict(address=0x20b0,value=C)],'Fresh saved-byte read')
  require([(q['address'],q['new_value'])for q in at(ws,0xef9)['writes']]==[(0x20b0,C)],'Saved-byte publication')
  require([(q['address'],q['new_value'])for q in at(ws,0xf06)['writes']]==[(dest,C)],'Buffer publication')
  require(at(ws,0xf07)['reads']==[dict(address=0x1e0c,value=i)],'Index reread')
  require(at(ws,0xf0b)['writes'][0]['new_value']==next_i,'Increment publication')
  require(c['buffer_address']==dest and c['new_buffer_byte']==C,'Buffer destination/result')
  if dest in detail['prior_buffer']:require(c['old_buffer_byte']==detail['prior_buffer'][dest],'Old buffer writer value')
  require(at(ws,0xf0e)['after']['flags']==cmp_flags(next_i,128),'CPI80 flags')
  require(at(ws,0xf0e)['before']['a']==next_i and at(ws,0xf10)['before']['flags']==at(ws,0xf0e)['after']['flags'],'Immediate CPI80 flag ancestry')
  require(at(ws,0xf10)['control']['taken']==(next_i!=128),'JNZ polarity')
  o=c['output'];require(o['sp']==c['input']['sp']+2 and o['pc']==r['call']['pc']+3,'Outer SP/continuation')
  if next_i!=128:
   require(c['path']=='non_flush'and c['resulting_index']==next_i,'Nonflush classification')
   require(not r['nested_returns']and not detail['events'],'Nonflush has hidden child/host effect')
   require((o['a'],pair(o,'b','c'),pair(o,'d','e'),pair(o,'h','l'))==(next_i,0x1d8c,pair(c['input'],'d','e'),dest),'Nonflush returned registers')
   require(o['flags']==cmp_flags(next_i,128),'Nonflush final flags')
   non.append(c['entry_step']);continue
  require(c['path']=='flush_success'and c['resulting_index']==0,'Observed flush success')
  require([w['origin']['offset']for w in ws if w['control']['kind']=='call']==[0xf16,0xf21],'Flush helper order')
  calls=[e for e in detail['events']if e['type']=='bdos_call'];resumes=[e for e in detail['events']if e['type']=='bdos_resume'];records=[e for e in detail['events']if e['type']=='bdos_record'];files=[e for e in detail['events']if e['type']=='file_operation'];effects=[e for e in detail['events']if e['type']=='host_effect']
  require([e['function']for e in calls]==[26,21],'BDOS function order')
  require([pair(e['state'],'d','e')for e in calls]==[0x1d8c,0x1ca2],'BDOS arguments')
  require(calls[1]['dma']==0x1d8c and calls[1]['fcb_address']==0x1ca2,'DMA/FCB at write boundary')
  require([e['state']['a']for e in resumes]==[0,0],'BDOS success result')
  require(len(records)==len(files)==1 and records[0]['operation']=='write_record'and files[0]['operation']=='sequential_write'and files[0]['succeeded'],'Record/file event identity')
  record=records[0];require(record['step_index']==calls[1]['step_index']and record['dma']==0x1d8c and record['file']['name']==live['source']+'.INT','Record consuming boundary')
  buf=bytearray(C if a==dest else detail['prior_buffer'][a]for a in range(0x1d8c,0x1e0c));buf[i]=C
  require(buf.hex().upper()==record['data']==c['buffer_after_hex'],'Record comes from current chronological buffer and persists after flush')
  post={q['step']:q for q in live['BDOS_post_boundaries']}
  require(post[calls[1]['step_index']]['index']==0 and post[calls[0]['step_index']]['index']==128,'Index reset ordering at real BDOS boundary')
  require(post[calls[1]['step_index']]['buffer_hex']==record['data'],'Post-host buffer persistence')
  for call,resume in zip(calls,resumes):
   require(post[call['step_index']]['post_host_state']==resume['state'],'Independent post-host register/flag snapshot')
   expected=call['state'].copy();expected.update(a=0,b=0,h=0,l=0);require(resume['state']==expected,'Observed host return state')
  fcb=bytearray.fromhex(calls[1]['fcb_bytes'])
  for e in effects:
   q=e['effect']
   if e['step_index']==calls[1]['step_index']and q['kind']=='memory_write':
    require(q['cause']=='fcb_update'and 0x1ca2<=q['address']<0x1ca2+36,'Only scoped FCB host writes')
    require(fcb[q['address']-0x1ca2]==q['old_value'],'FCB host old value chronology');fcb[q['address']-0x1ca2]=q['new_value']
  require(fcb.hex().upper()==post[calls[1]['step_index']]['FCB_hex'],'FCB post-state follows exact host effects')
  require(at(ws,0xf24)['before']['a']==0 and at(ws,0xf26)['control']['taken'],'CPI00/JZ success polarity')
  require(at(ws,0xf24)['after']['flags']==cmp_flags(0,0)and at(ws,0xf26)['before']['flags']==at(ws,0xf24)['after']['flags'],'Immediate CPI00 flag ancestry')
  require(o['flags']==cmp_flags(0,0),'Flush final flags')
  require((o['a'],pair(o,'b','c'),pair(o,'d','e'),pair(o,'h','l'))==(0,21,0x1ca2,0),'Flush returned state')
  own=detail['instructions'];stack=c['input']['sp'];latest={q['address']:{'step':w['step_index'],'coordinate':coord(w['origin']),'value':q['new_value']}for w in own for q in w['writes'] if stack-10<=q['address']<stack}
  expected=[(stack-2,0x24,0xf21),(stack-1,0x10,0xf21),(stack-4,0x37,0x334),(stack-3,4,0x334),(stack-6,21,0x19bb),(stack-5,0x1c,0x19bb),(stack-8,0xa2,0x19bc),(stack-7,0x1c,0x19bc),(stack-10,0xc6,0x19c3),(stack-9,0x1a,0x19c3)]
  for address,value,off in expected:require(latest[address]['value']==value and latest[address]['coordinate']==f'PLI.COM+{off:04X}','Last writer of flush residue')
  bridge_returns=[]
  for call in calls:
   original=next(w for w in own if w['step_index']==call['frames'][0]['call_step'])
   relation=next(e for e in detail['events']if e['type']=='hardware_frame_return'and e['frame']['call_step']==original['step_index']);ret=next(w for w in own if w['step_index']==relation['step_index']);verify_return(original,ret,relation)
   require(ret['pc']==5 and ret['origin'] is None,'BDOS RET must remain nonhistorical runtime0005')
   for q in ret['reads']:
    writes=[(w,z)for w in own if original['step_index']<=w['step_index']<ret['step_index']for z in w['writes']if z['address']==q['address']]
    require(writes[-1][0]['step_index']==original['step_index'],'Original bridge CALL must be latest return-slot writer')
   bridge_returns.append({'call_step':original['step_index'],'call_coordinate':coord(original['origin']),'call_slot_writes':original['writes'],'ret_step':ret['step_index'],'ret_origin':ret['origin'],'ret_pc':ret['pc'],'ret_slot_reads':ret['reads'],'resumed_pc':ret['pc_after'],'relation':relation})
  buffer_writers=dict(detail['prior_buffer_writers'])
  for w in own:
   if w['step_index']>=calls[1]['step_index']:break
   for q in w['writes']:
    if 0x1d8c<=q['address']<0x1e0c:buffer_writers[q['address']]={'step':w['step_index'],'coordinate':coord(w['origin']),'value':q['new_value']}
  require(bytes(buffer_writers[a]['value']for a in range(0x1d8c,0x1e0c))==buf,'Record producer ancestry')
  guards=[]
  for call in calls:
   interval=[w for w in own if call['frames'][0]['call_step']<w['step_index']<call['step_index']]
   require(at(interval,0x19c6)['control']['taken']==False and at(interval,0x19cf)['control']['taken']==False,'Guard failures unobserved')
   cmp=at(interval,0x19ce);require(cmp['before']['a']==0xaa and cmp['reads'][0]['value']==0xaa,'Guard marker equality')
   signature=[]
   for producer,test in [(0x1a0f,0x1a10),(0x1a14,0x1a15),(0x1a19,0x1a1a)]:
    left,right=at(interval,producer),at(interval,test)
    require(left['reads'][0]['value']==right['reads'][0]['value']and right['after']['flags']['zero'],'Stub signature comparison')
    signature.append({'producer_step':left['step_index'],'compare_step':right['step_index'],'left_read':left['reads'][0],'right_read':right['reads'][0]})
   require([q['left_read']['address']for q in signature]==[5,6,7],'Real BDOS stub signature addresses')
   guards.append({'signature_comparisons':signature,'bdos_step':call['step_index'],'signature_equal_return':at(interval,0x1a1b)['after'],'marker_read':cmp['reads'][0],'guard_branches':[at(interval,o)['step_index']for o in [0x19c6,0x19cf]]})
  row={'source':live['source'],'entry_step':c['entry_step'],'caller':c['caller'],'append_step':at(ws,0xf06)['step_index'],'index80_step':at(ws,0xf0b)['step_index'],'dma_wrapper_call_step':at(ws,0xf16)['step_index'],'index_reset_step':at(ws,0xf1c)['step_index'],'write_wrapper_call_step':at(ws,0xf21)['step_index'],'status_compare_step':at(ws,0xf24)['step_index'],'return_step':c['return_step'],'bridge_returns':bridge_returns,'buffer_writers':[[a,q['step'],q['coordinate'],q['value']]for a,q in sorted(buffer_writers.items())],'bdos_calls':[{k:e[k]for k in ['step_index','function','state','dma','fcb_address','fcb_bytes','frames','bridge_step','bridge_origin']}for e in calls],'bdos_resumes':resumes,'host_effects':effects,'file_events':files,'record':record,'post_host_boundaries':[post[e['step_index']]for e in calls],'guards':guards,'final_stack_writers':[dict(address=a,**latest[a])for a in sorted(latest)],'output':o}
  require(row['append_step']<row['index80_step']<row['dma_wrapper_call_step']<calls[0]['step_index']<row['index_reset_step']<row['write_wrapper_call_step']<calls[1]['step_index']<row['status_compare_step']<row['return_step'],'Complete flush chronology')
  for e in row['bdos_calls']:e['frames']=e['frames'][:3]
  flush.append(c['entry_step']);chron.append(row)
 summary={'source':live['source'],'capture':str(capture.relative_to(ROOT)),'capture_run_id':load(capture/'event-witnesses.json')['run_id'],'calls':len(cases),'non_flush':len(non),'flush_success':len(flush),'flush_error':0,'callers':dict(Counter(c['caller']for c in cases)),'entry_indices':dict(sorted(Counter(c['entry_index']for c in cases).items())),'neighbor_values':dict(Counter(c['neighbor_1E0D']for c in cases)),'records':[q['record']['record']for q in chron],'buffer_persists_after_reset':True,'flushes_on_every_128th_call':all(c['entry_index']==n%128 for n,c in enumerate(cases)),'error_boundary_calls':dict(error_calls),'REL_size':live['REL_size'],'REL_sha256':live['REL_sha256']}
 return rows,{'source':live['source'],'members':[compact_case(c)for c in cases]}, {'source':live['source'],'entry_steps':non},{'source':live['source'],'entry_steps':flush},chron,summary

def build(live):
 results=[audit(CAPTURES[s['source']],s)for s in live['sources']]
 wrappers=[]
 for s,(rows,*_)in zip(live['sources'],results):
  members=[]
  for r in rows['PLI.COM+0328']:
   verify_return(r['call'],r['ret'],r['relation']);ws=r['own_witnesses'];bc=pair(r['entry']['before'],'b','c')
   require([(q['address'],q['new_value'])for w in ws for q in w['writes']if q['address']in [0x2065,0x2066]]==[(0x2066,bc>>8),(0x2065,bc&255)],'0328 high-before-low writes')
   require(at(ws,0x32e)['reads']==[dict(address=0x2065,value=bc&255),dict(address=0x2066,value=bc>>8)],'0328 little endian scratch read')
   members.append({'caller':coord(r['call']['origin']),'entry_step':r['entry']['step_index'],'return_step':r['ret']['step_index'],'input':r['entry']['before'],'output':r['ret']['after'],'argument':bc,'bridge_call_step':at(ws,0x334)['step_index']})
  wrappers.append({'source':s['source'],'calls':len(members),'callers':dict(Counter(c['caller']for c in members)),'members':members})
 return {'emitter-cases':{'sources':[r[1]for r in results]},'nonflush-cases':{'sources':[r[2]for r in results]},'flush-cases':{'sources':[r[3]for r in results]},'bdos-chronology':{'flushes':[q for r in results for q in r[4]]},'buffer-lifecycle':{'sources':[r[5]for r in results]},'bdos-write-wrapper':{'id':'PLI.COM+0328','extent':[0x328,0x338],'sources':wrappers}}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--live',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(exist_ok=True)
 for name,data in build(load(a.live)).items():(a.output/(name+'.json')).write_text(json.dumps(data,indent=2)+'\n')
