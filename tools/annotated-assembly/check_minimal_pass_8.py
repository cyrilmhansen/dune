#!/usr/bin/env python3
"""Pass-8 continuation-family, argument and scoped operation checks.

The gatherer is task-local evidence projection, not a packet profile extension.
Only original-slot hardware events or proved POP D/POP B/PUSH D software
relations isolate descendants. No dynamic-context ownership is used.
"""
import argparse
import json
from collections import Counter
from pathlib import Path
from minimal_baseline import load
from check_minimal_pass_2 import at,coord,pair,require,word
from check_minimal_pass_5 import nonstack_writes
from procedure_evidence_packet import verify_return
from software_continuation import prove
ROOT=Path(__file__).resolve().parents[2]

def gather(capture):
    keys=['PLI1.OVL+4468','PLI1.OVL+6708','PLI1.OVL+43D5','PLI1.OVL+4B69','PLI1.OVL+28AA','PLI1.OVL+419F','PLI1.OVL+41A6','PLI1.OVL+429D']
    records={k:[] for k in keys};active={};matched={};software={};writers={};last=None
    for chunk in load(capture/'event-witnesses.json')['chunks']:
     for event in load(capture/'event-witnesses/chunks'/f"{chunk['id']:06d}.json")['events']:
      if event['type']=='instruction':
       last=w=event['witness']
       for r in active.values():r['witnesses'].append(w)
       if w['control']['kind']=='call' and w['control']['taken'] and coord(w.get('target_origin')) in records:
        key=coord(w['target_origin']);s=w['sp_before']
        active[w['step_index']]={'entry_key':key,'call':w,'witnesses':[],'caller_stack_writers':{str((s+i)%65536):writers.get((s+i)%65536) for i in range(10)}}
       for q in w['writes']:writers[q['address']]={'witness':w,'access':q}
      elif event['type']=='hardware_frame_return':
       cs=event['frame']['call_step'];matched[cs]={'ret':last,'relation':event,'kind':'hardware'}
       if cs in active:
        r=active.pop(cs);r.update(entry=r['witnesses'][0],ret=last,relation=event,return_kind='hardware');verify_return(r['call'],last,event);records[r['entry_key']].append(r)
      elif event['type']=='software_continuation_return':
       cs_candidates=[]
       for cs,r in active.items():
        if r['call']['call_return_address']!=event['return_address']:continue
        writer=event['low_byte_writer']['step'];prefix=[w for w in r['witnesses'] if w['step_index']<=writer]
        if not any(w['disassembly']=='POP D' for w in prefix):continue
        sample={'call':r['call'],'prefix':prefix,'event':event,'ret':last}
        try:n=prove({'call':sample['call'],'prefix':prefix,'ret':last,'relation':event,'stack_argument_bytes':2*sum(w['disassembly']=='POP B' for w in prefix)})['consumed_caller_bytes']//2
        except (ValueError,StopIteration):continue
        cs_candidates.append((cs,n,sample))
       require(len(cs_candidates)<=1,'Ambiguous continuation ancestry')
       if cs_candidates:
        cs,n,sample=cs_candidates[0];r=active.pop(cs);r.update(entry=r['witnesses'][0],ret=last,relation=event,return_kind='software',consumed_caller_bytes=2*n,continuation_sample=sample)
        software[cs]={'ret':last,'relation':event,'kind':'software','consumed_caller_bytes':2*n,'continuation_sample':sample};records[r['entry_key']].append(r)
      elif event['type']=='host_effect':
       d=event.get('effect',event.get('detail',{}))
       if 'address' in d:writers.pop(d['address'],None)
      elif event['type']=='bdos_record' and event.get('operation')=='read_record':
       for i in range(len(bytes.fromhex(event['data']))):writers.pop((event['dma']+i)%65536,None)
    require(not active,'Selected call has no proven return')
    returns=dict(matched);returns.update(software)
    for key,rs in records.items():
     for r in rs:
      own=[];skip=-1;nested={}
      for w in r['witnesses']:
       if w['step_index']<=skip:continue
       own.append(w)
       if w['control']['kind']=='call' and w['control']['taken']:
        require(w['step_index'] in returns,'Unresolved nested return '+str(coord(w['origin']))+' -> '+str(coord(w.get('target_origin'))))
        result=returns[w['step_index']];skip=result['ret']['step_index'];nested[w['step_index']]=dict(result,memory_witnesses=[q for q in r['witnesses'] if w['step_index']<q['step_index']<=skip and (q['reads'] or q['writes'])])
      r['own_witnesses']=own;r['nested_returns']=nested
    return records

def forensic(r):
    sample=r['continuation_sample']
    proof={'call':r['call'],'prefix':sample['prefix'],'ret':r['ret'],'relation':r['relation'],'stack_argument_bytes':r['consumed_caller_bytes']}
    relation=prove(proof);args=[]
    for pop in [w for w in sample['prefix'] if w['disassembly']=='POP B']:
        low,high=pop['reads'];value=low['value']+256*high['value'];producers=[]
        for q in (low,high):
            p=r['caller_stack_writers'][str(q['address'])]
            require(p is not None and p['access']['new_value']==q['value'],'Argument writer/value missing')
            producers.append({'step':p['witness']['step_index'],'coordinate':coord(p['witness']['origin']),'instruction':p['witness']['disassembly'],'address':q['address'],'value':q['value']})
        require(producers[0]['step']==producers[1]['step'],'Caller word has different byte producers')
        args.append({'address':low['address'],'value':value,'pop_step':pop['step_index'],'pop_coordinate':coord(pop['origin']),'producer':producers[0]['coordinate'],'producer_step':producers[0]['step'],'byte_writers':producers})
    # Carrier words are not result slots: only copied continuation overwrites
    # the highest carrier slot; transient body saves stay below that slot.
    addresses={q['address'] for w in sample['prefix'] if w['disassembly']=='POP B' for q in w['reads']}
    carrier_writes=[(w['step_index'],w['disassembly'],q['address'],q['new_value']) for w in r['own_witnesses'] for q in w['writes'] if q['address'] in addresses]
    writer=relation['continuation_writer_step']
    require(all(s==writer and op=='PUSH D' for s,op,a,v in carrier_writes),'Caller carrier used as an unproved result slot')
    return dict(relation,arguments=args,carrier_writes=carrier_writes,caller=coord(r['call']['origin']))


def nret(r,offset):
    w=at(r['own_witnesses'],offset)[0]
    return r['nested_returns'][w['step_index']]


def read(ws,offset):
    return at(ws,offset)[0]['reads'][0]


def validate_copy(r):
    ws=r['own_witnesses'];f=forensic(r);argv=[a['value'] for a in f['arguments']]
    source,selector,cursor,extra=argv[0],argv[1]&255,argv[2],argv[3]&255
    count=r['entry']['before']['c'];saved_e=r['entry']['before']['e']
    require((read(ws,0x6731)['value'] & 0x28)==0x28 and saved_e==5 and (read(ws,0x6755)['value'] & 0x22)!=0x22,'Copy outside observed scope')
    require(word(at(ws,0x6720)[0])==cursor,'Initial working cursor mismatch')
    stores=at(ws,0x67A1);guards=at(ws,0x6771);source_tests=at(ws,0x677B)
    require(len(guards)==len(stores)+1 and len(source_tests)==len(stores),'Copy loop records uncorrelated')
    values=[];aliases=[];limits=[]
    for k,g in enumerate(guards):
        limits.append({'offset':k,'selector':selector,'address':g['reads'][0]['address'],'limit':g['reads'][0]['value']})
        require(g['before']['a']==k and g['reads'][0]['address']==0xA62B+selector,'Fresh selector/limit address mismatch')
        stop=k>=g['reads'][0]['value'];branch=next(w for w in ws if w['step_index']==g['step_index']+1)
        require(branch['control']['taken']==stop,'Unsigned limit polarity mismatch')
        if stop:
            require(k==len(stores),'Loop continued after stop');break
        t=source_tests[k];branch=next(w for w in ws if w['step_index']==t['step_index']+1)
        require(t['before']['a']==k and t['reads'][0]['value']==count and branch['control']['taken']==(k>=count),'Source/padding polarity mismatch')
        if k<count:
            group=[w for w in ws if t['step_index']<w['step_index']<stores[k]['step_index']]
            q=read(group,0x6789)
            require(q['address']==source+k,'Source pointer progression mismatch');value=q['value']
        else:value=0x20
        q=stores[k]['writes'][0]
        require((q['address'],q['new_value'])==(0xA948+k,value),'Copy/padding publication mismatch')
        values.append(value)
        if 0xA9DA<=q['address']<=0xA9DD:
            aliases.append({'offset':k,'address':q['address'],'value':value,'step':stores[k]['step_index']})
        if q['address']==0xA9DD:selector=value
    require(at(ws,0x67AE)[0]['writes'][0]['new_value']==len(stores),'Published copy count mismatch')
    sub=at(ws,0x67B7)[0];mask=at(ws,0x67B8)[0];comp=at(ws,0x67B9)[0];out=r['ret']['after']
    borrow=len(stores)<count
    require(sub['after']['flags']['carry']==borrow and mask['after']['a']==(255 if borrow else 0),'Final borrow mask mismatch')
    require(out['a']==(0 if borrow else 255) and out['flags']==mask['after']['flags'] and comp['after']['flags']==mask['after']['flags'],'CMA return A versus flags mismatch')
    return dict(f,source=source,initial_selector=argv[1]&255,final_selector=selector,initial_cursor=cursor,source_count=count,extra_byte=extra,output_count=len(values),source_reads=min(count,len(values)),padding=len(values)-min(count,len(values)),output_bytes=values,control_aliases=aliases,limit_history=limits,returned_A=out['a'],returned_flags=out['flags'])


def validate_getter(r):
    ws=r['own_witnesses'];out=r['ret']['after'];before=r['entry']['before'];p=word(ws[0] if r['entry_key'].endswith('419F') else ws[1]);offset=2 if r['entry_key'].endswith('419F') else 3
    q=next(w for w in ws if w['disassembly']=='MOV A,M')['reads'][0]
    require(q['address']==(p+offset)&65535 and out['a']==q['value'] and pair(out,'h','l')==q['address'],'Field getter address/value mismatch')
    require(all(out[n]==before[n] for n in ('d','e')) and not nonstack_writes(ws),'Field getter effects mismatch')
    return {'pointer':p,'offset':offset,'address':q['address'],'returned_A':out['a']}


def validate_selector(r):
    ws=r['own_witnesses'];p=word(at(ws,0x42AC)[0]);out=r['ret']['after']
    field2=nret(r,0x429D)['ret']['after']['a'];field3=nret(r,0x42A3)['ret']['after']['a'];field4=read(ws,0x42B0)['value']
    require(field2==0x30 and out['a']==2 and out['flags']==at(ws,0x4326)[0]['after']['flags'],'Selector30 result/flag mismatch')
    require(nonstack_writes(ws)==[(0xA8F3,field2),(0xA8F4,field3),(0xA8F5,field4)],'Selector caches mismatch')
    return {'pointer':p,'field2':field2,'field3':field3,'field4':field4,'returned_A':2,'flags':out['flags']}


def validate_short(r):
    ws=r['own_witnesses'];f=forensic(r);arg=f['arguments'][0]['value'];before=r['entry']['before'];out=r['ret']['after'];p=word(at(ws,0x43E5)[0]);delta=nret(r,0x4409)['ret']['after']['a']
    for offset,addr,value in [(0x43ED,p+2,arg&255),(0x43F5,p+3,0x4C),(0x43FF,p+4,before['c']),(0x4408,p+5,before['e'])]:
        require([(q['address'],q['new_value']) for q in at(ws,offset)[0]['writes']]==[(addr,value)],'Short block byte fields mismatch')
    i=at(ws,0x440F)[0]['reads'][0]['value'];lo=read(ws,0x4422);hi=read(ws,0x4424);head=lo['value']+256*hi['value']
    require((lo['address'],hi['address'])==(0xA8AB+2*i,0xA8AC+2*i),'Head-slot read address mismatch')
    require(nonstack_writes([*at(ws,0x4426),*at(ws,0x4428)])==[(p+8,head&255),(p+9,head>>8)],'New block head copy mismatch')
    oldlo=read(ws,0x443C);oldhi=read(ws,0x443E);old=oldlo['value']+256*oldhi['value']
    require((oldlo['address'],oldhi['address'])==(head+2,head+3),'Old head word address mismatch')
    require(delta==2 and nonstack_writes([*at(ws,0x4450),*at(ws,0x4452)])==[(head+2,(old+delta)&255),(head+3,((old+delta)%65536)>>8)],'Old word addition publication mismatch')
    require(nonstack_writes([*at(ws,0x4464),*at(ws,0x4466)])==[(p+6,old&255),(p+7,old>>8)],'Saved original word publication mismatch')
    require((out['a'],pair(out,'b','c'),pair(out,'d','e'),pair(out,'h','l'))==(((old+delta)%65536)>>8,6,old,p+7),'Short final registers mismatch')
    return dict(f,argument_low=arg&255,ignored_high=arg>>8,input_C=before['c'],input_E=before['e'],new_pointer=p,head_slot=0xA8AB+2*i,old_head=head,old_word=old,delta=delta,new_old_word=(old+delta)%65536,flags=out['flags'])


def validate_reset(r):
    ws=r['own_witnesses'];top=word(ws[0]);q=(top+1)%65536;before=r['entry']['before'];out=r['ret']['after']
    require(q>=0xAE7A and at(ws,0x4B77)[0]['control']['taken'],'Reset guard polarity mismatch')
    table=[w for w in ws if w['origin']['offset'] in (0x4BA8,0x4BAA)]
    require(nonstack_writes(table)==[(0xA761+j,0) for j in range(256)],'128-word zero-fill mismatch')
    require(len(at(ws,0x4BB0))==128 and at(ws,0x4B98)[-1]['reads'][0]['value']==128,'Reset loop count/guard mismatch')
    child=nret(r,0x4BBA);newp=pair(child['ret']['after'],'h','l')-7;head=word(at(ws,0x4BC3)[0]);lo=read(ws,0x4BCB);hi=read(ws,0x4BCD);current=lo['value']+256*hi['value']
    require(at(ws,0x4BB5)[0]['before']['c']==0x30 and child['kind']=='software' and child['consumed_caller_bytes']==2,'Reset caller carrier/software relation mismatch')
    require(nonstack_writes([*at(ws,0x4BD1),*at(ws,0x4BD3)])==[(head+2,(current-2)%65536 &255),(head+3,((current-2)%65536)>>8)],'Reset old-word subtraction mismatch')
    require(pair(out,'b','c')==(current-2)%65536 and pair(out,'h','l')==head+3,'Reset output registers mismatch')
    return {'top_before':top,'initial_pointer':q,'zeroed_words':128,'created_pointer':newp,'old_head':head,'word_before_parent_subtract':current,'word_after':(current-2)%65536,'caller_carrier_word':pair(at(ws,0x4BB5)[0]['before'],'b','c')}


def validate_large(r):
    ws=r['own_witnesses'];first=nret(r,0x2985);second=nret(r,0x2AB4)
    require(len(ws)==351 and len({coord(w['origin']) for w in ws})==351,'28AA own footprint changed')
    require(first['kind']==second['kind']=='software' and first['consumed_caller_bytes']==second['consumed_caller_bytes']==8,'28AA callee isolation mismatch')
    save=at(ws,0x2956)[0];pop=at(ws,0x2988)[0]
    require({q['address']:q['value'] for q in pop['reads']}=={q['address']:q['new_value'] for q in save['writes']},'Saved PSW source is not caller word')
    original=save['before']['a'];retA=first['ret']['after']['a'];taken=not((original&1) and (retA&1))
    require(at(ws,0x298C)[0]['control']['taken']==taken and pop['after']['b']==original,'Combined first predicate polarity mismatch')
    require(at(ws,0x2AB8)[0]['control']['taken']==bool(second['ret']['after']['a']&1),'Second returned-A-bit polarity mismatch')
    return {'own_coordinates':351,'own_occurrences':351,'first_call':first['continuation_sample']['call']['step_index'],'saved_2185_A':original,'first_return_A':retA,'first_JNC_taken':taken,'second_call':second['continuation_sample']['call']['step_index'],'second_return_A':second['ret']['after']['a'],'second_JC_taken':True,'local_callee_occurrences':19}


def check(records):
    rows=[]
    for key,rs in records.items():
        members=[]
        for r in rs:
            if r['return_kind']=='hardware':verify_return(r['call'],r['ret'],r['relation'])
            if key.endswith('4468'):m=forensic(r)
            elif key.endswith('6708'):m=validate_copy(r)
            elif key.endswith('43D5'):m=validate_short(r)
            elif key.endswith('4B69'):m=validate_reset(r)
            elif key.endswith('28AA'):m=validate_large(r)
            elif key.endswith(('419F','41A6')):m=validate_getter(r)
            elif key.endswith('429D'):m=validate_selector(r)
            else:raise ValueError(key)
            members.append(dict(m,call_step=r['call']['step_index']))
        rows.append({'entry':key,'invocations_checked':len(rs),'own_coordinates':len({coord(w['origin']) for r in rs for w in r['own_witnesses']}),'own_occurrences':sum(len(r['own_witnesses']) for r in rs),'members':members})
    return rows


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--capture',type=Path,default=ROOT/'_build/minimal-baseline/capture');p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();rows=check(gather(args.capture));args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(rows,indent=2)+'\n')
    print('PASS8:',sum(r['invocations_checked'] for r in rows),'invocations; continuation identities, arguments and scoped operations checked')
