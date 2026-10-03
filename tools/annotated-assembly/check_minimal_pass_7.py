#!/usr/bin/env python3
"""Pass-7 scoped helper contracts and parent joins; no new compiler capture."""
import argparse
import json
from pathlib import Path

from check_minimal_pass_2 import at, pair, require, word
from check_minimal_pass_3 import gather
from check_minimal_pass_5 import nonstack_writes, packet_local, validate_packet_member
from check_minimal_pass_6 import call_states, validate_member as validate_pass6_member
from procedure_evidence_packet import build, render, verify_return

ROOT=Path(__file__).resolve().parents[2]
DIRECT=('PLI1.OVL+7A79','PLI1.OVL+82E1','PLI1.OVL+82BB','PLI1.OVL+82C9',
        'PLI1.OVL+7ABF','PLI1.OVL+7E46','PLI1.OVL+7E56')
PACKETS={'PLI1.OVL+7BBF':(0,()),'PLI1.OVL+7C1B':(5,(0,3)),'PLI1.OVL+7D53':(0,())}


def read(ws,offset):
    return at(ws,offset)[0]['reads'][0]


def nested(r,w):
    return r['nested_returns'].get(w['step_index'],r['nested_returns'].get(str(w['step_index'])))


def nzpa(state):
    return {k:state['flags'][k] for k in ('sign','zero','parity','auxiliary_carry')}


def validate_software_sample(sample):
    """Task-local structural proof, not a new packet/continuation profile."""
    call=sample['call'];prefix=sample['prefix'];event=sample['event'];ret=sample['ret']
    pop=next(w for w in prefix if w['disassembly']=='POP D')
    writer=event['low_byte_writer']['step']
    require(writer==event['high_byte_writer']['step'],'Software continuation mixed writers')
    push=next(w for w in prefix if w['step_index']==writer)
    require({q['address']:q['value'] for q in pop['reads']}=={q['address']:q['new_value'] for q in call['writes']},'Software original-slot POP mismatch')
    between=[w for w in prefix if pop['step_index']<w['step_index']<writer]
    require(all(w['disassembly'] in ('POP B','DCX H','MOV M,B','MOV M,C') for w in between),'Software DE ancestry unproved')
    slot=event['stack_slot'];target=call['call_return_address']
    require(push['disassembly']=='PUSH D' and {q['address']:q['new_value'] for q in push['writes']}=={slot:target&255,slot+1:target>>8},'Software copied continuation mismatch')
    require({q['address']:q['value'] for q in ret['reads']}=={q['address']:q['new_value'] for q in push['writes']} and ret['pc_after']==target and ret['sp_before']==slot and ret['sp_after']==slot+2,'Software RET proof mismatch')
    words=sum(w['disassembly']=='POP B' for w in prefix)
    require(ret['sp_after']==call['sp_before']+2*words,'Software caller-word consumption mismatch')
    return words


def validate_direct(r):
    verify_return(r['call'],r['ret'],r['relation'])
    key=r['entry_key'];ws=r['own_witnesses'];inp=r['entry']['before'];out=r['ret']['after']
    writes=nonstack_writes(ws)
    if key=='PLI1.OVL+7A79':
        pos=inp['c'];j=read(ws,0x7A86);lo=read(ws,0x7A8E);hi=read(ws,0x7A90)
        require(j['address']==0xAA1F+pos and (lo['address'],hi['address'])==(0xAB49+2*j['value'],0xAB4A+2*j['value']),'Mapped word address mismatch')
        value=lo['value']+256*hi['value']
        require((pair(out,'h','l'),pair(out,'b','c'),pair(out,'d','e'))==(value,j['value'],hi['address']) and out['a']==inp['a'],'Mapped word registers mismatch')
        require(writes==[(0xAE38,pos)] and nzpa(out)==nzpa(inp) and not out['flags']['carry'],'Mapped word preservation mismatch')
        return {'position':pos,'map_index':j['value'],'word_address':lo['address'],'word':value}
    if key in ('PLI1.OVL+82E1','PLI1.OVL+82C9'):
        if key.endswith('+82E1'):
            ptr=pair(inp,'h','l');mask=pair(inp,'d','e');lo=read(ws,0x82E2);hi=read(ws,0x82E6)
            require((lo['address'],hi['address'])==(ptr,(ptr+1)%65536),'Indirect AND read order mismatch')
            value=lo['value']+256*hi['value'];de=(ptr+1)%65536;flag_step=0x82E7
        else:
            value=pair(inp,'d','e');mask=pair(inp,'h','l');de=value;flag_step=0x82CD
        result=value & mask
        require(pair(out,'h','l')==result and out['a']==result>>8 and pair(out,'d','e')==de and pair(out,'b','c')==pair(inp,'b','c'),'Word AND output mismatch')
        require(not writes and not out['flags']['carry'] and nzpa(out)==nzpa(at(ws,flag_step)[0]['after']),'Word AND flag/write mismatch')
        return {'value':value,'mask':mask,'result':result}
    if key=='PLI1.OVL+82BB':
        lp,rp=pair(inp,'h','l'),pair(inp,'d','e');ll=read(ws,0x82BB);lh=read(ws,0x82BD);rl=read(ws,0x82BE);rh=read(ws,0x82C2)
        require([q['address'] for q in (ll,lh,rl,rh)]==[lp,(lp+1)%65536,rp,(rp+1)%65536],'Word addition read order/alias mismatch')
        left=ll['value']+256*lh['value'];right=rl['value']+256*rh['value'];total=left+right
        require((pair(out,'h','l'),pair(out,'b','c'),pair(out,'d','e'),out['a'])==(total%65536,left,(rp+1)%65536,(total%65536)>>8),'Word addition registers mismatch')
        high=(total%65536)>>8;low_carry=int(ll['value']+rl['value']>255)
        expected={'carry':total>65535,'zero':high==0,'sign':bool(high&128),'parity':high.bit_count()%2==0,
                  'auxiliary_carry':(lh['value']&15)+(rh['value']&15)+low_carry>15}
        require(out['flags']==expected and not writes,'High ADC flags/write mismatch')
        return {'left_pointer':lp,'right_pointer':rp,'left':left,'right':right,'sum':total%65536}
    if key=='PLI1.OVL+7ABF':
        j=read(ws,0x7ACC);q=read(ws,0x7AD3)
        require(j['address']==0xAA1F+inp['c'] and q['address']==0xAD9D+j['value'],'Second auxiliary address mismatch')
        require((out['a'],pair(out,'b','c'),pair(out,'h','l'),pair(out,'d','e'))==(q['value'],j['value'],q['address'],pair(inp,'d','e')),'Second auxiliary result mismatch')
        require(writes==[(0xAE3B,inp['c'])] and nzpa(out)==nzpa(inp) and not out['flags']['carry'],'Second auxiliary flags/write mismatch')
        return {'position':inp['c'],'index':j['value'],'address':q['address'],'returned':q['value'],'preserved_NZPA':nzpa(out)}
    require(key in ('PLI1.OVL+7E46','PLI1.OVL+7E56'),'Unknown direct target')
    if key.endswith('+7E46'):
        mapping=nested(r,at(ws,0x7E4A)[0]);value=pair(mapping['ret']['after'],'h','l');argument=value & 255;emit_offset=0x7E52
        require(writes==[(0xAE52,value&255),(0xAE53,value>>8)],'Word cache publication mismatch')
        require(at(ws,0x7E4D)[0]['step_index']<at(ws,emit_offset)[0]['step_index'],'Cache publication must precede emission')
    else:
        value=word(at(ws,0x7E56)[0]);argument=value>>8;emit_offset=0x7E5B
        require(not writes,'High-byte wrapper own writes')
    call=at(ws,emit_offset)[0];post=nested(r,call)['ret']['after']
    require(call['before']['c']==argument,'Wrapper emission argument mismatch')
    require(all(out[k]==post[k] for k in ('a','b','c','d','e','h','l','flags')),'Wrapper result is emitter state, not word byte')
    return {'word':value,'emitted_C':argument,'emitter_call_step':call['step_index'],'result_A':out['a'],'result_flags':out['flags']}


def validate_bbf(p,iv):
    ws=packet_local(p,iv);calls=[p['calls'][str(s)] for s in iv['nested_calls']]
    first=call_states(p,calls[0])[1];initial=pair(first,'h','l');current=initial;count=15;iterations=[]
    for branch in at(ws,0x7C02):
        group=[w for w in ws if (iterations[-1]['branch_step'] if iterations else iv['entry_step']-1)<w['step_index']<=branch['step_index']]
        local_calls=[c for c in calls if group[0]['step_index']<=c['pre_call_state_step']<=branch['step_index']]
        and_call=next(c for c in local_calls if c['target']=='PLI1.OVL+82E1');add_call=next(c for c in local_calls if c['target']=='PLI1.OVL+82BB');mask_call=next(c for c in local_calls if c['target']=='PLI1.OVL+82C9')
        pre,post=call_states(p,and_call)
        require((pair(pre,'h','l'),pair(pre,'d','e'),pair(post,'h','l'),pair(post,'d','e'))==(0xAE4D,0x8000,current&0x8000,0xAE4E),'Old top-bit pointer/mask mismatch')
        pre,post=call_states(p,add_call);old=current;current=(current*2)%65536
        require(pair(pre,'h','l')==pair(pre,'d','e')==0xAE4D and pair(post,'h','l')==current and pair(post,'d','e')==0xAE4E,'Same-word doubling/pointer mismatch')
        stores=[w for w in group if w['origin']['offset'] in (0x7BED,0x7BEF)]
        require(nonstack_writes(stores)==[(0xAE4D,current&255),(0xAE4E,current>>8)],'Shifted word publication mismatch')
        require(pair(call_states(p,mask_call)[1],'h','l')==current&0x8000,'New top-bit mask mismatch')
        positive=count!=0;equal=(old&0x8000)==(current&0x8000);taken=not(positive and equal)
        require(branch['control']['taken']==taken,'Top-bit/count branch polarity mismatch')
        require(at(group,0x7BFE)[0]['after']['b']==(255 if positive else 0),'Saved counter mask preservation mismatch')
        iterations.append({'old_word':old,'shifted_word':current,'counter':count,'branch_taken':taken,'branch_step':branch['step_index']})
        if not taken:count-=1
    out=ws[-1]['after'];writer=next(c for c in calls if c['target']=='PLI1.OVL+7B2E');pre,post=call_states(p,writer)
    require(len(iterations)<=16 and count==16-len(iterations) and out['a']==count and pre['e']==count and pre['c']==ws[0]['before']['c'],'Final counter/publication relation mismatch')
    require(pair(out,'d','e')==count+256*(current&255) and not out['flags']['carry'] and nzpa(out)==nzpa(at(ws,0x7C00)[-1]['after']),'Final mixed neighbor/flag result mismatch')
    return {'position':ws[0]['before']['c'],'initial_word':initial,'shifted_word':current,'shifts':len(iterations),'returned_counter':count,'auxiliary_address':pair(post,'h','l'),'iterations':iterations}


def validate_d53(p,iv):
    base=validate_packet_member(p,iv);channels=[]
    for s in iv['nested_calls']:
        c=p['calls'][str(s)];pre,_=call_states(p,c)
        if c['target']=='PLI.COM+0EF6':
            channel={'PLI1.OVL+7DCC':'mapped-byte','PLI1.OVL+7E11':'second-auxiliary-byte','PLI1.OVL+7E20':'primary-auxiliary-byte'}[c['callsite']]
            channels.append({'channel':channel,'byte':pre['c'],'call_step':s})
        elif c['target'] in ('PLI1.OVL+7E46','PLI1.OVL+7E56'):
            effects=c['callee_memory_effects']['guest_instruction_accesses']
            emission=[q['new_value'] for e in effects if e['coordinate']=='PLI.COM+0EF9' for q in e['writes'] if q['address']==0x20B0]
            require(len(emission)==1,'Wrapper emitter saved-C channel mismatch')
            low=c['target'].endswith('+7E46')
            if low:
                cache=[q for e in effects if e['coordinate']=='PLI1.OVL+7E4D' for q in e['writes']]
                require([q['address'] for q in cache]==[0xAE52,0xAE53] and emission[0]==cache[0]['new_value'],'Cached low-byte emission mismatch')
                value=cache[0]['new_value']+256*cache[1]['new_value']
            else:
                cache=[q for e in effects if e['coordinate']=='PLI1.OVL+7E56' for q in e['reads']]
                require([q['address'] for q in cache]==[0xAE52,0xAE53] and emission[0]==cache[1]['value'],'Fresh high-byte emission mismatch')
                value=cache[0]['value']+256*cache[1]['value']
            channels.append({'channel':'mapped-word-low' if low else 'mapped-word-high','word':value,'byte':emission[0],'wrapper_call_step':s})
    return dict(base,emission_channels=channels)


def collect(capture,images,output):
    cat={p['id']:p for p in json.loads((ROOT/'research/annotated-assembly/procedures.json').read_text())['procedures']}
    records=gather(capture,{k:(cat[k]['start_offset'],cat[k]['end_offset']) for k in DIRECT},include_nested_returns=True)
    packets={k:build(capture,images,k,frame,slots) for k,(frame,slots) in PACKETS.items()}
    output.mkdir(parents=True,exist_ok=True)
    for k,p in packets.items():
        stem=k.replace('.OVL','');(output/(stem+'.json')).write_text(json.dumps(p,separators=(',',':'))+'\n');(output/(stem+'.md')).write_text(render(p))
    regions=[]
    for k in (*DIRECT,*PACKETS):
        if k in DIRECT:members=[dict(validate_direct(r),call_step=r['call']['step_index']) for r in records[k]]
        else:
            fn=validate_bbf if k.endswith('+7BBF') else validate_d53 if k.endswith('+7D53') else validate_pass6_member
            members=[dict(fn(packets[k],iv),call_step=iv['call_step'],invocation_class=iv['class']) for iv in packets[k]['invocations']]
        regions.append({'entry':k,'invocations_checked':len(members),'members':members})
    return regions,records,packets


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--images',type=Path,required=True)
    parser.add_argument('--capture',type=Path,default=ROOT/'_build/minimal-baseline/capture');parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();result,_,_=collect(args.capture,args.images,args.output.parent/'packets')
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(result,indent=2)+'\n')
    print('PASS7:',sum(r['invocations_checked'] for r in result),'correlated invocations checked')
