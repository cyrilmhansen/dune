#!/usr/bin/env python3
"""Ticket-bounded +7D53 correlations over corrected return projections.

Full V0.2 rejects a nonhistorical emitter descendant. This adapter supplies the
existing Pass-7 checker with its required fields; it is not a packet, does not
run packet validation, and retains origin=None effects instead of fabricating
historical coordinates. No ownership/ABI/evidence-model inference occurs here.
"""
from collections import Counter
from check_minimal_pass_2 import at,coord,require
from check_minimal_pass_7 import validate_d53
from procedure_evidence_packet import verify_return

KEY='PLI1.OVL+7D53'


def checker_input(record):
    """In-memory compatibility input only; never serialize it as V0.2 evidence."""
    own=record['own_witnesses'];steps={str(w['step_index']):dict(w,coordinate=coord(w['origin'])) for w in own}
    instructions={coord(w['origin']):dict(decoded=w['disassembly']) for w in own};calls={}
    for w in own:
        if w['control']['kind']!='call' or not w['control']['taken']:continue
        n=w['step_index'];child=record['nested_returns'].get(str(n),record['nested_returns'].get(n));ret=child['ret']
        verify_return(w,ret,child['relation'])
        steps[str(ret['step_index'])]=dict(ret,coordinate=coord(ret['origin']))
        calls[str(n)]=dict(callsite=coord(w['origin']),target=coord(w['target_origin']),pre_call_state_step=n,post_return_state_step=ret['step_index'],callee_memory_effects=dict(guest_instruction_accesses=[dict(step=q['step_index'],coordinate=coord(q['origin']),runtime_pc=q['pc'],reads=q['reads'],writes=q['writes']) for q in child['memory_witnesses']]))
    iv=dict(call_step=record['call']['step_index'],entry_step=record['entry']['step_index'],return_step=record['ret']['step_index'],local_steps=[w['step_index'] for w in own],nested_calls=[int(n) for n in calls])
    return dict(entry=KEY,steps=steps,instructions=instructions,calls=calls),iv


def summarize(record):
    view,iv=checker_input(record);base=validate_d53(view,iv);ws=record['own_witnesses'];calls=list(view['calls'].values())
    path='equal_range' if base['return'].endswith('+7D5D') else 'gate' if base['return'].endswith('+7D65') else 'work'
    result=dict(base,call_step=iv['call_step'],caller=coord(record['call']['origin']),path=path,parent_return_step=record['ret']['step_index'],reverse=[],forward=[],unsupported_effects=[])
    for c in calls:
        for e in c['callee_memory_effects']['guest_instruction_accesses']:
            if e['coordinate'] is None:result['unsupported_effects'].append(dict(call_step=c['pre_call_state_step'],target=c['target'],**e))
    for call in [c for c in calls if c['callsite']=='PLI1.OVL+7D9D']:
        n=call['pre_call_state_step'];ret=call['post_return_state_step'];pre=view['steps'][str(n)]['before'];post=view['steps'][str(ret)]['after']
        cache=next(w for w in at(ws,0x7DA0) if w['step_index']>ret)
        skip=next(c for c in calls if c['callsite']=='PLI1.OVL+7DA7' and c['pre_call_state_step']>ret)
        skip_pre=view['steps'][str(skip['pre_call_state_step'])]['before'];skip_post=view['steps'][str(skip['post_return_state_step'])]['after'];replace=next(w for w in at(ws,0x7DAA) if w['step_index']>skip['post_return_state_step'])
        require(cache['before']['a']==post['a'] and cache['writes'][0]['new_value']==post['a'],'Top-level returnedA/AE50 writer mismatch')
        require(skip_pre['c']==pre['c'] and replace['writes'][0]['new_value']==skip_post['a'],'Independent reverse-scan/cursor writer mismatch')
        next_branch=next(w for w in at(ws,0x7D8A) if w['step_index']>replace['step_index'])
        result['reverse'].append(dict(call_step=n,return_step=ret,input_position=pre['c'],returned_A=post['a'],returned_flags=post['flags'],AE50_write_step=cache['step_index'],AE50_value=cache['writes'][0]['new_value'],skip_call_step=skip['pre_call_state_step'],skip_input=skip_pre['c'],skip_return=skip_post['a'],skip_flags=skip_post['flags'],cursor_write_step=replace['step_index'],cursor_value=replace['writes'][0]['new_value'],next_loop_branch_step=next_branch['step_index'],next_saved_cursor=next_branch['before']['c'],next_begin_minus1=next_branch['before']['a'],next_loop_taken=next_branch['control']['taken']))
    starts=at(ws,0x7DC5)
    for i,w in enumerate(starts):
        end=starts[i+1]['step_index'] if i+1<len(starts) else record['ret']['step_index']
        group=[c for c in calls if w['step_index']<=c['pre_call_state_step']<end]
        mapped=view['steps'][str(group[0]['post_return_state_step'])]['after']['a'];cursor=w['before']['c'];transform=next((c for c in group if c['target']=='PLI1.OVL+7B64'),None)
        attr=view['steps'][str(transform['post_return_state_step'])]['after']['a'] if transform else None
        channels=[c for c in base['emission_channels'] if w['step_index']<=c.get('call_step',c.get('wrapper_call_step',-1))<end]
        publish=next(c for c in group if c['target']=='PLI1.OVL+7BA2');effects=publish['callee_memory_effects']['guest_instruction_accesses'];old=next(q['value'] for e in effects if e['coordinate']=='PLI1.OVL+7BAA' for q in e['reads'] if q['address']==0xAE33)
        table=[q for e in effects for q in e['writes'] if e['coordinate']=='PLI1.OVL+7AEE'];fresh=[q for e in effects for q in e['reads'] if e['coordinate']=='PLI1.OVL+7BBA'];new=[q for e in effects for q in e['writes'] if e['coordinate']=='PLI1.OVL+7BBB']
        require(len(table)==len(fresh)==len(new)==1,'Recycling publication/read/write footprint mismatch')
        require(table[0]['new_value']==old and fresh[0]['address']==0xAA1F+cursor and new[0]['address']==0xAE33 and new[0]['new_value']==fresh[0]['value'],'Distinct recycle/fresh map relation mismatch')
        result['forward'].append(dict(map_call_step=w['step_index'],cursor=cursor,mapped=mapped,transform_call_step=transform['pre_call_state_step'] if transform else None,attribute=attr,channels=channels,recycle_call_step=publish['pre_call_state_step'],recycle_old_index=old,recycle_write=table[0],fresh_map_read=fresh[0],new_index_write=new[0]))
    if at(ws,0x7DB3):result['forward_start']=dict(cursor=at(ws,0x7DB3)[0]['writes'][0]['new_value'],step=at(ws,0x7DB3)[0]['step_index'])
    if at(ws,0x7E42):result['end_publication']=dict(value=at(ws,0x7E42)[0]['writes'][0]['new_value'],step=at(ws,0x7E42)[0]['step_index'])
    return result


def compose(parent,recursive_packet):
    """Use actual recursive child edges and matched windows, never contexts."""
    inv={i['call_step']:i for i in recursive_packet['invocations']};rows=[]
    def local(node,offset):return [recursive_packet['steps'][str(n)] for n in node['local_steps'] if recursive_packet['steps'][str(n)]['coordinate']==f'PLI1.OVL+{offset:04X}']
    def walk(n):
        require(n in inv,'Missing exact top-level/recursive invocation');yield n
        for step in inv[n]['nested_calls']:
            c=recursive_packet['calls'][str(step)]
            if c['recursive_child_invocation'] is not None:yield from walk(c['recursive_child_invocation'])
    for call in parent['reverse']:
        top=inv[call['call_step']];selected=[]
        for n in walk(top['call_step']):
            node=inv[n];special=local(node,0x7C56);fallback=local(node,0x7CD0)
            if special or fallback:
                selected.append(dict(call_step=n,class_id=node['class'],input_position=recursive_packet['steps'][str(node['entry_step'])]['before']['c'],mapped=local(node,0x7C2C)[0]['writes'][0]['new_value'],path='mapped1E_special' if special else 'mapped17_predecessor_fallback',predecessor=local(node,0x7CCB)[0]['before']['a'] if fallback else None,returned_A=recursive_packet['steps'][str(node['return_step'])]['after']['a'],top_level=n==top['call_step']))
        if selected:
            require(parent['call_step']<top['call_step']<top['return_step']<parent['parent_return_step'] and top['return_step']==call['return_step'],'Child window outside exact parent chronology')
            rows.append(dict(parent_call_step=parent['call_step'],caller=parent['caller'],begin=parent['begin'],end=parent['end'],reverse=call,top_child_class=top['class'],top_child_mapped=local(top,0x7C2C)[0]['writes'][0]['new_value'],selected_descendants=selected,forward_start=parent.get('forward_start'),forward_cursors=[i['cursor'] for i in parent['forward']],end_publication=parent.get('end_publication')))
    return rows


def local_path_signature(record):
    """Own transfer sequence; caller continuation targets are not local paths."""
    return tuple((w['origin']['offset'],w['control']['kind'],w['control'].get('taken'),
                  None if w['control']['kind']=='return' else w['control'].get('target'))
                 for w in record['own_witnesses']
                 if w['control']['kind'] in ('call','jump','return'))
