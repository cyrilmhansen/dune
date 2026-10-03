"""Validate the observed POP D / POP B / PUSH D cleanup family.

This proves a writer/slot/RET relation. It does not infer procedure ownership,
argument meanings, arbitrary continuations, or a packet frame profile.
"""


def prove(proof):
    call, prefix, ret, event = (proof[k] for k in ('call', 'prefix', 'ret', 'relation'))
    def need(condition, message):
        if not condition:
            raise ValueError('Software continuation: '+message)
    pops = [w for w in prefix if w['disassembly'] == 'POP D']
    need(len(pops) == 1, 'original return POP D is not unique')
    pop = pops[0]; original = call['sp_after']; target = call['call_return_address']
    need(call['control']['kind'] == 'call' and call['control']['taken']
         and original == (call['sp_before']-2)&65535 and target == (call['pc']+3)&65535,
         'CALL word/stack equation differs')
    need(pop['sp_before'] == original and pop['sp_after'] == (original+2)&65535,
         'original return POP stack movement differs')
    need(pop['reads'] == [{'address': original, 'value': target & 255},
                         {'address': (original+1)&65535, 'value': target >> 8}],
         'POP does not consume original CALL slot')
    need({q['address']: q['new_value'] for q in call['writes']} ==
         {q['address']: q['value'] for q in pop['reads']}, 'CALL/POP byte ancestry differs')
    writer_step = event['low_byte_writer']['step']
    need(writer_step == event['high_byte_writer']['step'], 'continuation has mixed writers')
    pushes = [w for w in prefix if w['step_index'] == writer_step]
    need(len(pushes) == 1 and pushes[0]['disassembly'] == 'PUSH D', 'writer is not recorded PUSH D')
    push = pushes[0]
    between = [w for w in prefix if pop['step_index'] < w['step_index'] < writer_step]
    need(all(w['disassembly'] in ('POP B', 'DCX H', 'MOV M,B', 'MOV M,C') for w in between),
         'DE ancestry not supported between POP/PUSH')
    arguments = [w for w in between if w['disassembly'] == 'POP B']
    need(arguments, 'no proven caller words consumed')
    for i, w in enumerate(arguments):
        address = (original+2+2*i)&65535
        need([q['address'] for q in w['reads']] == [address, (address+1)&65535]
             and w['sp_before'] == address and w['sp_after'] == (address+2)&65535,
             'caller word consumption order/addresses differ')
    count = 2*len(arguments); slot = (original+count)&65535
    need(proof['stack_argument_bytes'] == count, 'declared consumption differs from POPs')
    need(push['sp_after'] == slot and event['stack_slot'] == slot,
         'relocated slot differs from consumed-byte equation')
    writes = {q['address']: q['new_value'] for q in push['writes']}
    need(writes == {slot: target & 255, (slot+1)&65535: target >> 8}, 'copied word differs')
    need(ret['disassembly'] == 'RET' and {q['address']: q['value'] for q in ret['reads']} == writes
         and ret['sp_before'] == slot and ret['sp_after'] == (slot+2)&65535
         and ret['pc_after'] == target, 'RET does not consume copied continuation')
    need(event['type'] == 'software_continuation_return' and event['step_index'] == ret['step_index']
         and event['return_address'] == target, 'corrected consumer event differs')
    for field, address in [('low_byte_writer',slot),('high_byte_writer',(slot+1)&65535)]:
        fact = event[field]
        need(fact['step'] == writer_step and fact['pc'] == push['pc']
             and fact['origin'] == push['origin'] and fact['value'] == writes[address],
             'latest writer identity differs')
    return {'call_step':call['step_index'], 'original_return_slot':original,
            'original_return_pop_step':pop['step_index'], 'continuation_register':'DE',
            'continuation_writer_step':writer_step, 'relocated_return_slot':slot,
            'consumed_caller_bytes':count, 'software_ret_step':ret['step_index'],
            'final_SP_minus_preCALL':count, 'argument_pop_steps':[w['step_index'] for w in arguments]}
