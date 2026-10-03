"""Bounded local packet navigation; no path merging or interprocedural semantics."""

import re
from collections import Counter

FLAGS = ('carry', 'zero', 'sign', 'parity')
PAIRS = {'B': ('c', 'b'), 'D': ('e', 'd'), 'H': ('l', 'h'), 'PSW': ('flags', 'a')}
CONDITIONS = {'NZ': ('zero', False), 'Z': ('zero', True), 'NC': ('carry', False),
              'C': ('carry', True), 'PO': ('parity', False), 'PE': ('parity', True),
              'P': ('sign', False), 'M': ('sign', True)}


def call_contract(contract, entry, target, memory_witnesses, catalog):
    """Recognize only explicit preservation clauses and one simple scope form.

    Ordinary nested-stack-only effects exclude the caller's storage above the
    pre-CALL SP. Partial substitution is conditional on its retained scope;
    the recorded inner return can establish its A-bit guard, not every alias
    precondition. Everything unspecified stays unresolved.
    """
    scope = contract['contract_scope'] if contract else None
    complete = contract and contract['completeness']['contract'] == 'complete'
    kind = ('RECURSIVE inherited partial' if target == entry and not complete else
            'COMPLETE' if complete else 'PARTIAL' if contract else 'MISSING / OPAQUE')
    proof = []
    guard = re.search(r'(?:([A-Z0-9.]+)\+|\+)([0-9A-F]{4}) returns A bit0=([01])', scope or '')
    if guard:
        key = (guard[1] or target.split('+')[0]) + '+' + guard[2]
        callee = catalog.get(key, {})
        returns = set(callee.get('returns', {}).get('observed_file_offsets', []))
        proof = [{'step': w['step_index'], 'coordinate': key.split('+')[0] + f"+{w['origin']['offset']:04X}",
                  'a': w['after']['a']} for w in memory_witnesses
                 if w['origin']['image']['name'] == key.split('+')[0] and w['origin']['offset'] in returns]
    scoped = bool(complete or (guard and proof and all((p['a'] & 1) == int(guard[3]) for p in proof)))
    text = (contract.get('clobbers', '') + ' ' + contract.get('contract', '')).lower() if contract else ''
    ordinary = contract and contract['returns']['convention'].startswith('ordinary hardware CALL word')
    stack_only = any(s in text for s in ('only stack writes (call/push psw)', 'nested call stack only'))
    outputs = contract.get('outputs', '').lower() if contract else ''
    preserved = []
    if scoped:
        if re.search(r'flags (?:preserved|unchanged)', outputs):
            preserved.extend(FLAGS)
        for reg in ('a', 'bc', 'de', 'hl'):
            if re.search(r'\b' + reg + r' (?:preserved|unchanged)\b', outputs):
                preserved.extend({'bc': ('b', 'c'), 'de': ('d', 'e'), 'hl': ('h', 'l')}.get(reg, (reg,)))
    clobbered = set(re.findall(r'\b(?:a|bc|de|hl|flags)\b', (contract.get('clobbers', '').split(';')[0].lower() if contract else '')))
    forbidden = set(''.join(x for x in clobbered if x != 'flags')) | (set(FLAGS) if 'flags' in clobbered else set())
    preserved = [x for x in preserved if x not in forbidden]
    return {'kind': kind, 'scope': scope, 'declared_clobbers': contract.get('clobbers') if contract else None, 'scope_guard_evidence': proof,
            'scope_status': 'complete declared scope' if complete else
                'guard established; remaining scope preconditions retained' if scoped else 'unresolved',
            'algorithmic_contract': 'available at stated scope' if contract else 'unavailable',
            'preserved_state': preserved,
            'caller_storage_preserved': bool(scoped and ordinary and stack_only),
            'all_memory_preserved': bool(scoped and (re.search(r'\bno memory writes(?:[.;]|$)', text) or 'memory unchanged' in outputs)),
            'unspecified_state': 'unresolved; concrete equality does not preserve a definition'}


def preserved_address(call, address, frame, frame_bytes, steps):
    policy = call['contract_presentation']
    start = steps[str(call['pre_call_state_step'])]['before']['sp']
    convention = call.get('return_convention', {})
    if convention.get('kind') == 'SOFTWARE CLEANUP RETURN' and \
            (address - start) & 65535 < convention['consumed_caller_bytes']:
        return False  # Consumed caller words cease to be persistent parent locals.
    if any(q['address'] == address for e in call['callee_memory_effects']['guest_instruction_accesses'] for q in e['writes']):
        return False  # Even a same-value write replaces the caller definition.
    if policy['all_memory_preserved']:
        return True
    # Restrict the nested-stack clause to known caller locals/saves/return word.
    span = (frame + frame_bytes + 2 - start) & 65535
    return policy['caller_storage_preserved'] and span < 32768 and (address - start) & 65535 < span


def negate(expr):
    return expr['arg'] if expr['op'] == 'not' else {'op': 'not', 'arg': expr}


def condition_expression(nodes, ref, bit=None):
    """Small algebra over instruction effects, not symbolic execution."""
    n = nodes[ref]
    op, args = n['operation'], [a['node'] for a in n['inputs']]
    if op in ('MOV', 'PUSH', 'POP', 'load', 'store', 'read', 'call-preserved-storage', 'call-preserved-state') and args:
        return condition_expression(nodes, args[0], bit)
    if bit is not None:
        if op == 'CMA':
            return negate(condition_expression(nodes, args[0], bit))
        if op in ('ORA', 'ANA', 'XRA'):
            return {'op': {'ORA': 'or', 'ANA': 'and', 'XRA': 'xor'}[op],
                    'args': [condition_expression(nodes, a, bit) for a in args]}
        if op == 'SBB A':
            return condition_expression(nodes, args[0])
        return {'op': 'bit', 'node': ref, 'bit': bit}
    if op == 'flag-copy':
        return condition_expression(nodes, args[0])
    if op in ('bit0', 'bit7'):
        return condition_expression(nodes, args[0], 0 if op == 'bit0' else 7)
    if op == 'constant':
        return {'op': 'constant', 'value': bool(n['value'])}
    if op in ('equal', 'borrow'):
        return {'op': op, 'nodes': args, 'width': 8}
    if op == 'zero':
        return {'op': 'zero', 'node': args[0]}
    # A known flag result from a boundary is still only a boundary source.
    return {'op': 'flag', 'node': ref}


def condition_text(expr, nodes):
    op = expr['op']
    if op == 'not':
        return 'NOT (' + condition_text(expr['arg'], nodes) + ')'
    if op in ('or', 'and', 'xor'):
        return '(' + f' {op.upper()} '.join(condition_text(a, nodes) for a in expr['args']) + ')'
    def source(ref):
        n = nodes[ref]
        return n.get('source', n['coordinate'] + '.' + n['output'])
    if op == 'bit':
        return source(expr['node']) + f".bit{expr['bit']}==1"
    if op in ('equal', 'borrow'):
        args = [source(a) for a in expr['nodes']]
        return args[0] + (' == ' if op == 'equal' else ' < ') + ' + '.join(args[1:])
    if op == 'zero':
        return source(expr['node']) + '==0'
    if op == 'constant':
        return str(expr['value'])
    return source(expr['node']) + '==1'


def derive_local(packet):
    """Forward definitions per invocation; retain only branch/publication roots."""
    instructions, steps, calls = packet['instructions'], packet['steps'], packet['calls']
    nodes, predicates, operational = {}, {}, {}
    procedure = packet['accumulated_knowledge']['procedure']
    role_addresses = {r['runtime_address'] + i: r for r in packet['accumulated_knowledge']['roles']
                      if r['id'] in procedure['data_role_ids'] for i in range(r['width'] or 1)}
    layout = re.search(r'words F\+(\d+(?:/\+\d+)*)', ' '.join(procedure['memory_state']))
    word_offsets = [int(x) for x in layout[1].split('/+')] if layout else []
    roots = []
    for invocation in packet['invocations']:
        frame, size = invocation['F'], invocation['frame_relation']['bytes']
        registers, flags, memory = {}, {}, {}
        events, children, decrements = [], [], []
        first = invocation['first_written_local_bytes']
        summary = {'invocation': invocation['call_step'], 'events': events,
                   'recursive_calls': children, 'frame_decrements': decrements,
                   'frame_word_offsets': word_offsets, 'first_written_local_bytes': first}
        operational[str(invocation['call_step'])] = summary
        def node(step, output, operation, value, inputs=(), **extra):
            ref = f'{step}:{output}'
            nodes[ref] = {'step': step, 'coordinate': steps[str(step)]['coordinate'], 'output': output,
                          'operation': operation, 'value': value,
                          'inputs': [{'kind': kind, 'node': parent} for kind, parent in inputs], **extra}
            return ref
        def read(s, index=0):
            q = s['reads'][index]
            address = q['address']
            rel = q.get('deduced_frame_relation')
            source = f"byte[{rel['expression'] if rel else f'{address:04X}H'}]"
            return node(step, f'read:{index}', 'read' if address in memory else 'observed-read', q['value'],
                        [('value', memory[address])] if address in memory else [], source=source,
                        address=address, producer_status='local writer' if address in memory else 'earlier writer unresolved')
        def operand(s, name):
            if name == 'M':
                return read(s)
            if re.fullmatch(r'[0-9A-F]{2,4}H', name):
                return node(step, 'immediate', 'constant', int(name[:-1], 16), source=name)
            key = name.lower()
            if key not in registers:
                registers[key] = node(step, f'input:{key}', 'unresolved-input', s['before'][key],
                                      source=s['coordinate'] + '.input_' + name,
                                      producer_status='producer unavailable; stopped')
            return registers[key]
        for step in invocation['local_steps']:
            s = steps[str(step)]
            parts = instructions[s['coordinate']]['decoded'].replace(',', ' ').split()
            op, args = parts[0], parts[1:]
            outputs = {}
            if op[0] in 'JRC' and op[1:] in CONDITIONS:
                flag, sense = CONDITIONS[op[1:]]
                ref = flags.get(flag)
                if ref:
                    expr = condition_expression(nodes, ref)
                    if not sense:
                        expr = negate(expr)
                    predicates[str(step)] = {'invocation': invocation['call_step'], 'coordinate': s['coordinate'],
                        'tested_flag': flag, 'flag_definition': ref, 'condition': expr,
                        'condition_text': condition_text(expr, nodes), 'status': 'DEDUCED local condition',
                        'taken': s['control']['taken']}
                    roots.append(ref)
                else:
                    predicates[str(step)] = {'invocation': invocation['call_step'], 'coordinate': s['coordinate'],
                        'tested_flag': flag, 'status': 'polarity unresolved', 'reason': 'flag producer unavailable',
                        'taken': s['control']['taken']}
            if str(step) in calls:
                c = calls[str(step)]
                kept = set(c['contract_presentation']['preserved_state'])
                registers = {k: v for k, v in registers.items() if k in kept}
                flags = {k: v for k, v in flags.items() if k in kept}
                memory = {a: node(step, f'preserved-memory:{a}', 'call-preserved-storage', nodes[v]['value'],
                                  [('value', v)], contract=c['contract_presentation'])
                          for a, v in memory.items() if preserved_address(c, a, frame, size, steps)}
                post = steps[str(c['post_return_state_step'])]['after']
                for key, ref in list(registers.items()):
                    assert nodes[ref]['value'] == post[key], 'Declared register preservation violated'
                    registers[key] = node(step, f'preserved:{key}', 'call-preserved-state', post[key],
                                          [('value', ref)], contract=c['contract_presentation'])
                for key, ref in list(flags.items()):
                    assert nodes[ref]['value'] == post['flags'][key], 'Declared flag preservation violated'
                    flags[key] = node(step, f'preserved:{key}', 'call-preserved-state', post['flags'][key],
                                      [('flag', ref)], contract=c['contract_presentation'])
                for reg in 'abcdehl':
                    if reg not in kept:
                        registers[reg] = node(step, f'returned:{reg}', 'call-output', post[reg],
                            source=c['target'] + f'.returned_{reg.upper()} at {c["callsite"]}',
                            contract=c['contract_presentation'], producer_status='boundary; no pre-call dependency')
                for flag in FLAGS:
                    if flag not in kept:
                        flags[flag] = node(step, f'returned:{flag}', 'call-output', post['flags'][flag],
                            source=c['target'] + '.' + flag, contract=c['contract_presentation'])
                if c['recursive_child_invocation'] is not None:
                    children.append({'call_step': step, 'callsite': c['callsite'], 'mode_C': s['before']['c'],
                                     'child_invocation': c['recursive_child_invocation']})
                # Guest effects are navigation evidence, never new definitions.
                for e in c['callee_memory_effects']['guest_instruction_accesses']:
                    for q in e['writes']:
                        if q['address'] in role_addresses:
                            events.append({'step': e['step'], 'coordinate': e['coordinate'], 'channel': 'callee-role-write',
                                'address': q['address'], 'value': q['new_value'],
                                'role': role_addresses[q['address']]['id'], 'call_step': step})
                continue
            if op == 'MOV':
                parent = operand(s, args[1])
                key = args[0].lower()
                outputs[key] = node(step, key, 'MOV', s['writes'][0]['new_value'] if key == 'm' else s['after'][key], [('value', parent)])
            elif op == 'MVI':
                key = args[0].lower()
                outputs[key] = node(step, key, 'constant', int(args[1][:-1], 16), source=args[1])
            elif op in ('LDA', 'LDAX'):
                outputs['a'] = node(step, 'a', 'load', s['after']['a'], [('value', read(s))])
            elif op == 'LHLD':
                for index, reg in enumerate(('l', 'h')):
                    outputs[reg] = node(step, reg, 'load', s['after'][reg], [('value', read(s, index))])
            elif op == 'LXI' and args[0] != 'SP':
                for reg in PAIRS[args[0]]:
                    outputs[reg] = node(step, reg, 'constant', s['after'][reg], source=s['coordinate'] + '.' + reg)
            elif op == 'XCHG':
                for dest, source in [('d', 'h'), ('e', 'l'), ('h', 'd'), ('l', 'e')]:
                    outputs[dest] = node(step, dest, 'MOV', s['after'][dest], [('value', operand(s, source.upper()))])
            elif op == 'CMA':
                outputs['a'] = node(step, 'a', op, s['after']['a'], [('value', operand(s, 'A'))])
            elif op in ('RAR', 'RAL', 'RRC', 'RLC'):
                a = operand(s, 'A')
                old_carry = flags.get('carry')
                flags['carry'] = node(step, 'carry', 'bit0' if op in ('RAR', 'RRC') else 'bit7',
                                      s['after']['flags']['carry'], [('value', a)])
                # Rotation output needs old carry for RAR/RAL; stop that output
                # when unavailable, while retaining its independent carry bit.
                inputs = [('value', a)]
                if op in ('RAR', 'RAL'):
                    old = old_carry
                    if old is None:
                        old = node(step, 'input:carry', 'unresolved-input', s['before']['flags']['carry'],
                                   source=s['coordinate'] + '.input_CY', producer_status='earlier flag producer unresolved')
                    inputs.append(('flag', old))
                outputs['a'] = node(step, 'a', op, s['after']['a'], inputs,
                                    producer_status='old carry unresolved' if len(inputs) == 1 and op in ('RAR', 'RAL') else 'local')
            elif op in ('ANA', 'ORA', 'XRA', 'ANI', 'ORI', 'XRI', 'CMP', 'CPI', 'SUB', 'SUI', 'SBB', 'SBI', 'ADD', 'ADI', 'ADC', 'ACI'):
                left, right = operand(s, 'A'), operand(s, args[0])
                inputs = [('value', left), ('value', right)]
                carry_op = op in ('SBB', 'SBI', 'ADC', 'ACI')
                if carry_op:
                    if 'carry' in flags:
                        inputs.append(('flag', flags['carry']))
                    else:
                        registers.clear(); flags.clear(); memory.clear()
                        continue
                if op == 'SBB' and args[0] == 'A':
                    outputs['a'] = node(step, 'a', 'SBB A', s['after']['a'], [inputs[-1]])
                    flags['carry'] = node(step, 'carry', 'flag-copy', s['after']['flags']['carry'], [inputs[-1]])
                    flags['zero'] = node(step, 'zero', 'zero', s['after']['flags']['zero'], [('value', outputs['a'])])
                else:
                    normalized = {'ANI': 'ANA', 'ORI': 'ORA', 'XRI': 'XRA'}.get(op, op)
                    value = node(step, 'a', normalized, s['after']['a'], inputs)
                    if op not in ('CMP', 'CPI'):
                        outputs['a'] = value
                    if op in ('CMP', 'CPI', 'SUB', 'SUI', 'SBB', 'SBI'):
                        flags['carry'] = node(step, 'carry', 'borrow', s['after']['flags']['carry'], inputs)
                    elif normalized in ('ANA', 'ORA', 'XRA'):
                        flags['carry'] = node(step, 'carry', 'constant', False)
                    else:
                        flags.pop('carry', None)
                    flags['zero'] = node(step, 'zero', 'equal' if op in ('CMP', 'CPI') else 'zero',
                                         s['after']['flags']['zero'], inputs if op in ('CMP', 'CPI') else [('value', value)])
                # Sign/parity are not simplified by this bounded implementation.
                for flag in ('sign', 'parity'):
                    flags.pop(flag, None)
            elif op in ('INR', 'DCR'):
                parent = operand(s, args[0]); reg = args[0].lower()
                result = s['writes'][0]['new_value'] if reg == 'm' else s['after'][reg]
                outputs[reg] = node(step, reg, op, result, [('value', parent)])
                flags['zero'] = node(step, 'zero', 'zero', s['after']['flags']['zero'], [('value', outputs[reg])])
                flags.pop('sign', None); flags.pop('parity', None)
                if op == 'DCR':
                    n = nodes[parent]
                    while 'address' not in n and n['operation'] in ('MOV', 'load', 'read') and n['inputs']:
                        n = nodes[n['inputs'][0]['node']]
                    if 'address' in n and ((n['address'] - frame) & 65535) < size:
                        decrements.append({'step': step, 'coordinate': s['coordinate'],
                            'F_offset': (n['address'] - frame) & 65535, 'before': nodes[parent]['value'], 'after': result})
            elif op == 'PUSH':
                low, high = PAIRS[args[0]]
                for index, reg in enumerate((high, low)):
                    if reg != 'flags':
                        outputs[f'write:{index}'] = node(step, f'push:{reg}', 'PUSH', s['writes'][index]['new_value'], [('value', operand(s, reg.upper()))])
            elif op == 'POP':
                for index, reg in enumerate(PAIRS[args[0]]):
                    if reg != 'flags':
                        outputs[reg] = node(step, reg, 'POP', s['after'][reg], [('value', read(s, index))])
                    else:
                        flags.clear()  # Packed flag dependencies intentionally unresolved.
            elif op in ('SHLD', 'STA', 'STAX'):
                for index, reg in enumerate(('l', 'h') if op == 'SHLD' else ('a',)):
                    outputs[f'write:{index}'] = node(step, f'store:{index}', 'store', s['writes'][index]['new_value'], [('value', operand(s, reg.upper()))])
            elif op in ('DAD', 'INX', 'DCX', 'XTHL'):
                if op == 'DAD':
                    registers.pop('h', None); registers.pop('l', None)
                    flags.pop('carry', None)
                elif op == 'XTHL':
                    registers.pop('h', None); registers.pop('l', None)
                elif args[0] != 'SP':
                    for reg in PAIRS[args[0]]:
                        registers.pop(reg, None)
            elif op not in ('SPHL', 'NOP', 'JMP', 'RET') and op[1:] not in CONDITIONS:
                registers.clear(); flags.clear(); memory.clear()
            for reg, ref in outputs.items():
                if reg in 'abcdehl' and len(reg) == 1:
                    registers[reg] = ref
            for index, q in enumerate(s['writes']):
                address = q['address']
                source = outputs.get(f'write:{index}', outputs.get('m'))
                if source:
                    memory[address] = source
                else:
                    memory.pop(address, None)
                delta = (address - frame) & 65535
                if delta < size:
                    event = {'channel': 'frame-write', 'F_offset': delta}
                elif address in role_addresses:
                    event = {'channel': 'role-write', 'role': role_addresses[address]['id']}
                elif op in ('MOV', 'STAX'):
                    event = {'channel': 'indirect-write'}
                else:
                    continue
                event.update(step=step, coordinate=s['coordinate'], address=address, value=q['new_value'])
                if source:
                    event['source_definition'] = source; roots.append(source)
                events.append(event)
        # Each member retains one ordered event stream; class rows only reference it.
        events.sort(key=lambda e: e['step'])
    reachable = set()
    def visit(ref):
        if ref not in reachable:
            reachable.add(ref)
            for edge in nodes[ref]['inputs']:
                visit(edge['node'])
    for ref in roots:
        visit(ref)
    packet['local_dependencies'] = {'scope': 'DEDUCED per-invocation local definitions; call outputs are boundary leaves',
                                  'nodes': {k: v for k, v in nodes.items() if k in reachable}, 'branches': predicates}
    packet['operational_summaries'] = operational
    for cls in packet['invocation_classes']:
        cls['operational_members'] = [str(n) for n in cls['invocations']]
    for site in packet['callsites']:
        site['contract_presentation'] = calls[str(site['call_steps'][0])]['contract_presentation']
        statuses = {}
        for step in site['call_steps']:
            status = calls[str(step)]['contract_presentation']['scope_status']
            statuses.setdefault(status, []).append(step)
        site['scope_status_groups'] = [{'status': status, 'call_steps': refs} for status, refs in statuses.items()]
    for key, branch in packet['branches'].items():
        branch['dependency_steps'] = [str(o['step']) for o in branch['observations'] if str(o['step']) in predicates]
        groups = {}
        for ref in branch['dependency_steps']:
            pred = predicates[ref]
            signature = pred.get('condition_text', 'polarity unresolved')
            groups.setdefault(signature, []).append(ref)
        classes = {i['call_step']: i['class'] for i in packet['invocations']}
        branch['polarity_summaries'] = [{'condition': text, 'dependency_steps': refs,
            'outcomes': [{'taken': taken, 'count': sum(predicates[r]['taken'] == taken for r in refs),
                         'classes': dict(sorted(Counter(classes[predicates[r]['invocation']] for r in refs
                                                        if predicates[r]['taken'] == taken).items()))}
                        for taken in (False, True)]} for text, refs in groups.items()]


def navigation_effects(packet):
    """Concrete guest effects only. A missing write is not a helper contract."""
    role_ids = packet['accumulated_knowledge']['procedure']['data_role_ids']
    roles = [r for r in packet['accumulated_knowledge']['roles'] if r['id'] in role_ids]
    word_roles = {r['runtime_address']: r for r in roles if r['width'] == 2}
    invocations = {i['call_step']: i for i in packet['invocations']}
    for key, call in packet['calls'].items():
        invocation = invocations[call['invocation']]
        addresses = Counter(q['address'] for e in call['callee_memory_effects']['guest_instruction_accesses']
                            for q in e['writes']
                            if packet['instructions'][e['coordinate']]['decoded'].split()[0] not in ('PUSH', 'CALL', 'XTHL'))
        call['observed_effects'] = {'scope': 'OBSERVED invocation-subtree guest writes; host effects unavailable; not an algorithmic contract',
            'write_addresses': [{'address': a, 'count': n} for a, n in sorted(addresses.items())],
            'caller_frame_written_offsets': sorted((a - invocation['F']) & 65535 for a in addresses
                                                   if ((a - invocation['F']) & 65535) < invocation['frame_relation']['bytes']),
            'watched_word_roles_without_guest_writes': [r['id'] for a, r in word_roles.items()
                                                       if a not in addresses and a + 1 not in addresses]}
    for key, summary in packet['operational_summaries'].items():
        invocation = invocations[int(key)]
        events = summary['events']
        local = {n: packet['steps'][str(n)] for n in invocation['local_steps']}
        accesses = {n: (s['coordinate'], s['writes'], s['reads'], None) for n, s in local.items()}
        for n in invocation['nested_calls']:
            for e in packet['calls'][str(n)]['callee_memory_effects']['guest_instruction_accesses']:
                accesses[e['step']] = (e['coordinate'], e['writes'], e['reads'], n)
        summary['role_word_writes'] = []
        summary['role_word_reads'] = []
        for n, (coordinate, writes, reads, call_step) in sorted(accesses.items()):
            by_address = {q['address']: q['new_value'] for q in writes}
            read_by_address = {q['address']: q['value'] for q in reads}
            for a, role in word_roles.items():
                if a in read_by_address and a + 1 in read_by_address:
                    summary['role_word_reads'].append({'step': n, 'coordinate': coordinate, 'role': role['id'],
                        'address': a, 'value': read_by_address[a] + 256 * read_by_address[a + 1], 'call_step': call_step})
                if a in by_address and a + 1 in by_address:
                    summary['role_word_writes'].append({'step': n, 'coordinate': coordinate, 'role': role['id'],
                        'address': a, 'value': by_address[a] + 256 * by_address[a + 1], 'call_step': call_step})
        # These are snapshots after recorded byte writes, never entry memory.
        slots = {}
        summary['frame_word_writes'] = []
        for event in events:
            if event['channel'] != 'frame-write':
                continue
            offset = event['F_offset']; slots[offset] = event['value']
            if offset - 1 in summary['frame_word_offsets'] and offset - 1 in slots:
                summary['frame_word_writes'].append({'step': event['step'], 'coordinate': event['coordinate'],
                    'F_offset': offset - 1, 'value': slots[offset - 1] + 256 * slots[offset],
                    'scope': 'last observed local byte writes; no entry snapshot or host-effect reconstruction'})
    for site in packet['callsites']:
        groups = {}
        for n in site['call_steps']:
            effects = packet['calls'][str(n)]['observed_effects']
            signature = (tuple(a['address'] for a in effects['write_addresses']), tuple(effects['caller_frame_written_offsets']))
            groups.setdefault(signature, []).append(n)
        site['observed_effect_groups'] = [{'write_addresses': list(addresses), 'caller_frame_written_offsets': list(offsets),
                                          'call_steps': members} for (addresses, offsets), members in groups.items()]


def validate_local(packet):
    """Check references/effects against retained concrete records, not prose."""
    nodes = packet['local_dependencies']['nodes']
    invocations = {i['call_step']: i for i in packet['invocations']}
    for relation in packet['deduced']['local_write_read_relations']:
        address = relation['address']
        writer = packet['steps'][str(relation['writer_step'])]
        reader = packet['steps'][str(relation['reader_step'])]['reads'][relation['reader_access']]
        assert any(q['address'] == address and q['new_value'] == relation['value'] for q in writer['writes']), 'Writer relation mismatch'
        assert reader['address'] == address and reader['value'] == relation['value'], 'Reader relation mismatch'
        for step in relation['preserved_across_calls']:
            call = packet['calls'][str(step)]; iv = invocations[relation['invocation']]
            assert call['invocation'] == iv['call_step'] and relation['writer_step'] <= step < relation['reader_step'], 'Call relation chronology mismatch'
            assert preserved_address(call, address, iv['F'], iv['frame_relation']['bytes'], packet['steps']), 'Unsupported writer preservation'
    for ref, n in nodes.items():
        assert n['coordinate'] == packet['steps'][str(n['step'])]['coordinate'], 'Dependency coordinate mismatch'
        for edge in n['inputs']:
            assert edge['kind'] in ('value', 'flag') and edge['node'] in nodes, 'Dependency edge mismatch'
            assert nodes[edge['node']]['step'] <= n['step'], 'Dependency chronology mismatch'
        if n['operation'] == 'call-output':
            call = packet['calls'][str(n['step'])]
            after = packet['steps'][str(call['post_return_state_step'])]['after']
            key = n['output'].split(':')[1]
            assert n['value'] == (after[key] if key in after else after['flags'][key]), 'Call output mismatch'
        if n['operation'] == 'call-preserved-storage':
            call = packet['calls'][str(n['step'])]
            iv = next(i for i in packet['invocations'] if i['call_step'] == call['invocation'])
            address = int(n['output'].split(':')[1])
            assert preserved_address(call, address, iv['F'], iv['frame_relation']['bytes'], packet['steps']), 'Unsupported call preservation'
    for key, pred in packet['local_dependencies']['branches'].items():
        s = packet['steps'][key]
        assert pred['coordinate'] == s['coordinate'] and pred['taken'] == s['control']['taken'], 'Dependency branch mismatch'
        if 'flag_definition' in pred:
            assert nodes[pred['flag_definition']]['value'] == s['before']['flags'][pred['tested_flag']], 'Flag definition mismatch'
    for key, summary in packet['operational_summaries'].items():
        iv = next(i for i in packet['invocations'] if i['call_step'] == int(key))
        assert [c['call_step'] for c in summary['recursive_calls']] == [s for s in iv['nested_calls']
                     if packet['calls'][str(s)]['recursive_child_invocation'] is not None], 'Child order mismatch'
        for e in summary['events']:
            if 'call_step' not in e:
                assert any(q['address'] == e['address'] and q['new_value'] == e['value']
                           for q in packet['steps'][str(e['step'])]['writes']), 'Publication event mismatch'


def dependency_chain(packet, predicate):
    nodes = packet['local_dependencies']['nodes']
    selected = set()
    def visit(ref):
        if ref not in selected:
            selected.add(ref)
            for edge in nodes[ref]['inputs']:
                visit(edge['node'])
    if 'flag_definition' in predicate:
        visit(predicate['flag_definition'])
    return [nodes[r] for r in sorted(selected, key=lambda r: (nodes[r]['step'], r))]
