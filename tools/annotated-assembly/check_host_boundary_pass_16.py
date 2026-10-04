#!/usr/bin/env python3
"""Read-only Pass-16 evidence projection; no compiler, ownership or snapshot engine."""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from check_minimal_pass_2 import coord, require
from check_minimal_pass_3 import gather
from check_minimal_pass_7 import validate_bbf
from check_fizzbuz_pass_14 import checker_input
from minimal_baseline import load
from procedure_evidence_packet import ROOT, verify_return

BASELINE='095e384e4e99664800dee2ab6104a8dce9902078'
FIZZ=ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture'
REPORT=ROOT/'research/host-compiler/pass-16'
CUTS=(319757,664916)

def intervals(addresses):
    out=[]
    for a in sorted(set(addresses)):
        if out and out[-1][1]==a:out[-1][1]=a+1
        else:out.append([a,a+1])
    return out

def dependency_inputs(witnesses):
    """Actual byte reads before any write, including same-value writes; no alias inference."""
    written=set();inputs={};post={};writes=[]
    for w in sorted(witnesses,key=lambda w:w['step_index']):
        for q in w['reads']:
            if q['address'] not in written:
                require(inputs.get(q['address'],q['value'])==q['value'],'Unrecorded input mutation')
                inputs[q['address']]=q['value']
        for q in w['writes']:
            written.add(q['address']);post[q['address']]=q['new_value']
            writes.append([w['step_index'],q['address'],q['new_value']])
    return inputs,post,writes

def check_snapshot_inputs(witnesses,captured):
    expected,_,_=dependency_inputs(witnesses)
    require(captured==expected,'Snapshot omits or alters an observed input byte')

def rel_audit(raw):
    """Bounded LINK-80 item reader for validation only (manual section 1.6).

    Accept observed name-only request control 3; reject reserved 4/8 and truncation.
    Preserve bit offsets, module alignment and all trailing bytes; never encode.
    """
    bits=''.join(f'{v:08b}' for v in raw);pos=0;items=[];alignment=[]
    def get(n):
        nonlocal pos
        require(pos+n<=len(bits),'Truncated REL item')
        value=int(bits[pos:pos+n],2) if n else 0;pos+=n;return value
    def address():
        kind=get(2);lo=get(8);hi=get(8);return [kind,lo+256*hi]
    while True:
        start=pos;row={'start_bit':start}
        if get(1)==0:row.update(kind='absolute_byte',value=get(8))
        else:
            kind=get(2)
            if kind:row.update(kind='relative_word',address_type=kind,value=get(8)+256*get(8))
            else:
                control=get(4);require(control not in (4,8),f'Reserved REL control unsupported at bit {start}: {control}')
                row.update(kind='special',control=control)
                if 5<=control<=14:row['address']=address()
                if control<=7:row['name_hex']=bytes(get(8) for _ in range(get(3))).hex()
        row['end_bit']=pos;items.append(row)
        if row.get('control')==14:
            pad=(-pos)%8;alignment.append({'start_bit':pos,'bits':bits[pos:pos+pad]});get(pad)
        if row.get('control')==15:break
    return dict(logical_items=len(items),kind_counts=dict(Counter(i['kind'] for i in items)),
                special_counts=dict(Counter(str(i['control']) for i in items if 'control' in i)),
                item_sequence_sha256=hashlib.sha256(json.dumps(items,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                first_items=items[:5],last_items=items[-5:],end_file_bit=pos,
                module_alignment=alignment,trailing_bit_count=len(bits)-pos,
                trailing_bits_sha256=hashlib.sha256(bits[pos:].encode()).hexdigest(),
                trailing_all_zero=set(bits[pos:])<=set('0'))

def scan(capture,images):
    index=load(capture/'event-witnesses.json');timeline=load(capture/'compiler-timeline.json')
    markers={0,*CUTS,timeline['total_steps']-1}
    for e in timeline['events']:
        if e['kind']=='console_message':markers.update([e['first_step']-1,e['first_step'],e['last_step']-1,e['last_step']])
        elif e['kind']=='image_first_execution':markers.add(e['step'])
    selected_addresses={0x1D8A,0x1D8B,0x1E0C,0x1C36,0x1C37,0x2029,0x202B,0x2011,0xA863,0xA864,*range(0xAE33,0xAE54),*range(0xAA1A,0xAA1F)}
    observed_state={}
    def state_write(address,value,step,source):
        if address in selected_addresses:observed_state[f'{address:04X}']=dict(value=value,writer_step=step,source=source)
    points={};calls={};bits=[];records=[];int_records=[];last=None;image_counts=Counter();source_reads=[]
    dependency={n:{'written':set(),'inputs':set(),'writes':set(),'external':Counter()} for n in CUTS}
    active={};bounded={k:dict(invocations=0,inputs=set(),writes=set(),external=Counter(),samples=[]) for k in ['PLI.COM+119E','PLI1.OVL+7D53']}
    bit_by_epoch=Counter();canonical_counts=Counter();mode_values=Counter();padding_calls=[]
    for c in index['chunks']:
        chunk=load(capture/'event-witnesses/chunks'/f"{c['id']:06d}.json")
        require(chunk['run_id']==index['run_id'],'Mixed capture chunks')
        for event in chunk['events']:
            n=event.get('step_index',-1)
            if event['type']=='instruction':
                last=w=event['witness'];n=w['step_index'];key=coord(w['origin'])
                if w['origin']:
                    name=w['origin']['image']['name'];o=w['origin']['offset'];raw=bytes.fromhex(w['bytes'])
                    require(images[name][o:o+len(raw)]==raw,'Historical instruction bytes mismatch')
                    require(w['pc']==o+(256 if name=='PLI.COM' else 0x2200),'Runtime coordinate mismatch')
                    canonical_counts[key]+=1;image_counts[name]+=1
                else:image_counts['NONHISTORICAL']+=1
                if n in markers:points[str(n)]={'coordinate':key,'runtime_pc':w['pc'],'bytes':w['bytes'],'instruction':w['disassembly'],'state':w['before'],'observed_prior_state_writes':dict(observed_state)}
                if w['control']['kind']=='call' and w['control']['taken']:
                    target=coord(w.get('target_origin'));r=calls.setdefault(target,dict(count=0,first=n,last=n,callers=Counter()));r['count']+=1;r['last']=n;r['callers'][key]+=1
                    if target=='PLI.COM+1140':bits.append(w['before']['c']&1);bit_by_epoch['before_PLI2' if n<CUTS[1] else 'PLI2_onward']+=1
                    if target=='PLI.COM+119E' and n>1140000:padding_calls.append(dict(step=n,caller=key,C=w['before']['c'],E=w['before']['e']))
                for q in w['writes']:state_write(q['address'],q['new_value'],n,key)
                for r in active.values():
                    for q in w['reads']:
                        if q['address'] not in r['written']:r['inputs'].add(q['address'])
                    for q in w['writes']:r['written'].add(q['address'])
                if w['control']['kind']=='call' and w['control']['taken'] and coord(w.get('target_origin')) in bounded:
                    active[n]=dict(call=w,key=coord(w['target_origin']),inputs=set(),written=set(),external=Counter())
                if key=='PLI.COM+1144':mode_values[w['after']['a']]+=1
                for cut,d in dependency.items():
                    if n<cut:continue
                    for q in w['reads']:
                        if q['address'] not in d['written']:d['inputs'].add(q['address'])
                    for q in w['writes']:d['written'].add(q['address']);d['writes'].add(q['address'])
            elif event['type']=='hardware_frame_return' and event['frame']['call_step'] in active:
                r=active.pop(event['frame']['call_step']);verify_return(r['call'],last,event);b=bounded[r['key']];b['invocations']+=1;b['inputs'].update(r['inputs']);b['writes'].update(r['written']);b['external'].update(r['external'])
                if len(b['samples'])<3:b['samples'].append(dict(call_step=r['call']['step_index'],return_step=n,caller=coord(r['call']['origin']),input_state=r['call']['after'],post_state=last['after'],read_before_write_ranges=intervals(r['inputs']),written_ranges=intervals(r['written'])))
            elif event['type']=='host_effect' and event['effect']['kind']=='memory_write':
                for cut,d in dependency.items():
                    if n>=cut:d['written'].add(event['effect']['address']);d['writes'].add(event['effect']['address'])
                for r in active.values():r['written'].add(event['effect']['address'])
                state_write(event['effect']['address'],event['effect']['new_value'],n,'host_effect')
            elif event['type']=='bdos_record':
                if event['operation']=='read_record':
                    for i,v in enumerate(bytes.fromhex(event['data'])):state_write((event['dma']+i)&65535,v,n,'bdos_record:'+event['file']['name'])
                row=dict(step=n,file=event['file']['name'],operation=event['operation'],record=event['record'],dma=event['dma'],sha256=hashlib.sha256(bytes.fromhex(event['data'])).hexdigest())
                if row['file']=='FIZZBUZ.REL':records.append(row)
                if row['file']=='FIZZBUZ.INT':int_records.append(row)
                if row['file']=='FIZZBUZ.PLI':source_reads.append(row)
                for r in active.values():
                    r['external'][(row['file'],row['operation'])]+=1
                    for a in range(event['dma'],event['dma']+128):
                        a&=65535
                        if event['operation']=='read_record':r['written'].add(a)
                        elif a not in r['written']:r['inputs'].add(a)
                for cut,d in dependency.items():
                    if n<cut:continue
                    d['external'][(row['file'],row['operation'])]+=1
                    for a in range(event['dma'],event['dma']+128):
                        a&=65535
                        if event['operation']=='read_record':d['written'].add(a);d['writes'].add(a)
                        elif a not in d['written']:d['inputs'].add(a)
    require(not active,'Unmatched bounded ordinary operation')
    canonical=load(capture/'canonical-code-blocks.json')
    require(canonical_counts==Counter({f"{i['image']['name']}+{i['offset']:04X}":i['execution_count'] for i in canonical['instructions']}),'Witness/canonical counts mismatch')
    raw=(capture/'FIZZBUZ.REL').read_bytes();packed=bytes(sum(bits[i+j]<<(7-j) for j in range(8)) for i in range(0,len(bits),8))
    require(packed==raw,'Bit-writer call sequence does not reproduce exact REL')
    require(len(records)==6 and all(r['operation']=='write_record' and r['record']==i and r['dma']==0x1D0A and r['sha256']==hashlib.sha256(raw[128*i:128*(i+1)]).hexdigest() for i,r in enumerate(records)),'REL record/file identity mismatch')
    return dict(run_id=index['run_id'],steps=timeline['total_steps'],markers=points,
                timeline_events=[e for e in timeline['events'] if e['kind']!='file_operation' or e['operation'] in ('OPEN','CLOSE','MAKE','DELETE')],
                image_instruction_counts=dict(image_counts),source_record_reads=source_reads,INT_records=int_records,REL_records=records,
                bounded_dependencies={k:dict(invocations=b['invocations'],read_before_write_ranges=intervals(b['inputs']),written_ranges=intervals(b['writes']),external_records=[dict(file=f,operation=o,count=c) for (f,o),c in sorted(b['external'].items())],samples=b['samples'],scope='Corrected ordinary-return inclusive subtree; exact numeric byte accesses including host/record effects. Unions are navigation, not independent interchangeable input sets.') for k,b in bounded.items()},
                call_inventory={k:dict(v,callers=dict(v['callers'])) for k,v in sorted(calls.items(),key=lambda p:str(p[0]))},
                phase_snapshot_dependencies={str(n):dict(entry=points[str(n)],read_before_write_ranges=intervals(d['inputs']),read_before_write_bytes=len(d['inputs']),written_ranges=intervals(d['writes']),external_records=[dict(file=f,operation=o,count=c) for (f,o),c in sorted(d['external'].items())],scope='Observed suffix data reads including BDOS WRITE DMA; CPU/host/record-read writes kill inputs. Instruction fetches are verified separately. Not a proof for other paths or sufficient BDOS checkpoint implementation.') for n,d in dependency.items()},
                rel=dict(size=len(raw),sha256=hashlib.sha256(raw).hexdigest(),bit_writer_calls=len(bits),bits_by_epoch=dict(bit_by_epoch),gate_values={str(k):v for k,v in mode_values.items()},all_writer_bits_reproduce_file=True,late_counted_writer_calls=padding_calls,**rel_audit(raw)))

def timeline_projection(facts):
    """Keep chronological report small; full CALL inventory feeds the separate audit."""
    projected=json.loads(json.dumps(facts))
    calls=projected.pop('call_inventory')
    families=('PLI.COM+070C','PLI.COM+12AE','PLI.COM+1376','PLI.COM+1140',
              'PLI.COM+119E','PLI.COM+1207','PLI0.OVL+24BC','PLI1.OVL+4B69',
              'PLI1.OVL+8273','PLI1.OVL+4929','PLI1.OVL+28AA','PLI1.OVL+4468',
              'PLI1.OVL+7C1B','PLI1.OVL+7BBF','PLI1.OVL+7D53','PLI2.OVL+1FB5',
              'PLI2.OVL+7557','PLI2.OVL+753C','PLI2.OVL+7701')
    projected['major_families']={k:calls[k] for k in families if k in calls}
    projected['CALL_inventory_sha256']=hashlib.sha256(json.dumps(calls,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    for n,marker in projected['markers'].items():
        if int(n) not in CUTS:marker.pop('observed_prior_state_writes',None)
    return projected

def operation_capture(capture):
    rs=gather(capture,{'PLI1.OVL+7BBF':(0x7BBF,0x7C1B)},include_nested_returns=True)['PLI1.OVL+7BBF'];out=[]
    for r in rs:
        verify_return(r['call'],r['ret'],r['relation']);view,iv=checker_input(r);meaning=validate_bbf(view,iv)
        ws=r['own_witnesses']+[w for c in r['nested_returns'].values() for w in c['memory_witnesses']]
        inputs,post,writes=dependency_inputs(ws)
        mapread=next(q for w in ws for q in w['reads'] if q['address']==0xAA1F+meaning['position'])
        j=mapread['value'];F=r['entry']['before']['sp']
        expected={0xAE39,0xAA1F+meaning['position'],0xAB49+2*j,0xAB4A+2*j,F,(F+1)&65535}
        require(set(inputs)==expected,f'Selected operation omitted inputs: {sorted(set(inputs)-expected)}; missing {sorted(expected-set(inputs))}')
        require(not any(w['origin'] is None for w in ws),'Unexpected nonhistorical operation effect')
        out.append(dict(call_step=r['call']['step_index'],caller=coord(r['call']['origin']),entry_step=r['entry']['step_index'],entry_coordinate=coord(r['entry']['origin']),return_step=r['ret']['step_index'],return_coordinate=coord(r['ret']['origin']),input_state=r['entry']['before'],post_state=r['ret']['after'],input_memory={f'{a:04X}':v for a,v in sorted(inputs.items())},input_ranges=intervals(inputs),post_written_bytes={f'{a:04X}':v for a,v in sorted(post.items())},written_ranges=intervals(post),ordered_writes_sha256=hashlib.sha256(json.dumps(writes,separators=(',',':')).encode()).hexdigest(),write_count=len(writes),map_index=j,word_address=0xAB49+2*j,branch_producer='PLI1.OVL+7C01 RAR after +7C00 ANA',**{k:v for k,v in meaning.items() if k!='iterations'}))
    return dict(run_id=load(capture/'event-witnesses.json')['run_id'],capture=str(capture.relative_to(ROOT)),invocations=len(out),members=out)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--images',type=Path,required=True);p.add_argument('--output',type=Path,default=ROOT/'_build/host-compiler-pass-16');args=p.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    manifest=load(ROOT/'research/annotated-assembly/manifest.json');images={}
    for m in manifest['images']:
        images[m['name']]=(args.images/m['name']).read_bytes();require(hashlib.sha256(images[m['name']]).hexdigest()==m['sha256'],'Historical image hash mismatch')
    timeline=scan(FIZZ,images);(args.output/'timeline.json').write_text(json.dumps(timeline,indent=2)+'\n');operations=[operation_capture(c) for c in [ROOT/'_build/minimal-baseline/capture',FIZZ,ROOT/'_build/discriminator-pass-15/selected-capture']]
    for name,value in [('timeline',timeline),('operation-captures',operations)]:
        (args.output/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps(dict(rel=timeline['rel'],operation_counts={x['run_id'].split(':')[0]:x['invocations'] for x in operations}),indent=2))

if __name__=='__main__':main()
