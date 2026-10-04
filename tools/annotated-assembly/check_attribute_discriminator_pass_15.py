#!/usr/bin/env python3
"""Narrow packed-table timeline audit; no global immutability/provenance inference."""
from collections import Counter
from pathlib import Path
from minimal_baseline import load
from check_minimal_pass_2 import coord,require

START,END=0x1B4B,0x1C4B


def audit_table(capture,initial):
    index=load(capture/'event-witnesses.json');memory={START+i:v for i,v in enumerate(initial)};latest={a:None for a in memory};writers=[];active={};pending_returns={};readers=[];last=None;low_checks=0
    def write(address,value,writer):
        if START<=address<END:
            memory[address]=value;latest[address]=dict(writer,address=address,value=value);writers.append(latest[address])
    for c in index['chunks']:
        chunk=load(capture/'event-witnesses/chunks'/f"{c['id']:06d}.json")
        require(chunk['run_id']==index['run_id'],'Mixed table-audit capture run')
        for event in chunk['events']:
            if event['type']=='instruction':
                last=w=event['witness'];key=coord(w['origin'])
                if w['control']['kind']=='call' and w['control']['taken'] and coord(w.get('target_origin'))=='PLI1.OVL+7B64':
                    active[w['step_index']]=dict(call_step=w['step_index'],caller=key,input_C=w['before']['c'])
                if key in ['PLI1.OVL+7B71','PLI1.OVL+7A77']:
                    q=w['reads'][0];address=q['address'];require(START<=address<END,'Packed-table read outside byte-indexed span')
                    require(q['value']==memory[address],'Read differs from chronological table writes/initial image')
                    if key.endswith('+7B71'):
                        candidates=[r for r in active.values() if 'read_step' not in r];require(len(candidates)==1,'Ambiguous high-attribute helper read')
                        r=candidates[0];require(address==START+r['input_C'],'Mapped byte/table address mismatch')
                        r.update(read_step=w['step_index'],table_address=address,read_byte=q['value'],initial_byte=initial[address-START],latest_writer=latest[address],source='INITIAL_IMAGE / no observed prior write' if latest[address] is None else 'OBSERVED latest writer')
                    else:
                        require(w['before']['a']==7 and w['after']['a']==(q['value']&7),'Low3 instruction contract mismatch');low_checks+=1
                if key=='PLI1.OVL+7B77':
                    require(len(active)==1,'Ambiguous high-attribute transformation')
                    call_step,r=next(iter(active.items()));require(r.get('read_step') is not None,'Transform lacks table read')
                    require(w['after']['a']==((r['read_byte']>>3)&7),'High3 actual transformation mismatch')
                    r.update(transform_step=w['step_index'],transformed_attribute=w['after']['a']);readers.append(r);pending_returns[call_step]=r;active.pop(call_step)
                for q in w['writes']:write(q['address'],q['new_value'],dict(kind='guest_instruction',step=w['step_index'],coordinate=key,runtime_pc=w['pc']))
            elif event['type']=='hardware_frame_return' and event['frame']['call_step'] in pending_returns:
                r=pending_returns.pop(event['frame']['call_step']);require(last['origin']['offset']==0x7B79 and r.get('read_step') is not None,'Attribute return/read mismatch')
                require(last['after']['a']==((r['read_byte']>>3)&7),'High3 return relation mismatch')
                r.update(return_step=last['step_index'],returned_attribute=last['after']['a'],returned_flags=last['after']['flags'])
            elif event['type']=='host_effect':
                e=event['effect']
                if e['kind']=='memory_write':write(e['address'],e['new_value'],dict(kind='host_effect',step=event['step_index'],cause=e['cause']))
            elif event['type']=='bdos_record' and event['operation']=='read_record':
                for i,v in enumerate(bytes.fromhex(event['data'])):write((event['dma']+i)&65535,v,dict(kind='bdos_record',step=event['step_index'],file=event['file'],record=event['record']))
    require(not active,'High-attribute CALL has no complete read/transform')
    if 'hardware_frame_returns' in index['summary']:require(not pending_returns,'Corrected high-attribute return missing')
    changed=[a for a in memory if memory[a]!=initial[a-START]]
    return dict(run_id=index['run_id'],observed_table_write_count=len(writers),written_addresses=sorted({w['address'] for w in writers}),writers=writers,changed_final_addresses=changed,high_attribute_reads=readers,high_distribution=dict(Counter(r['transformed_attribute'] for r in readers)),low_instruction_checks=low_checks,corrected_return_matches=len(readers)-len(pending_returns),scope='Exact initial256 bytes plus chronological guest writes, explicit host memory writes and BDOS read-record writes. Same-valued writes replace writer identity. No global immutability claim.')
