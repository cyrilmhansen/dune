"""Source-correlated MOD result ownership; evidence checker, no compiler execution.

The source adapter below checks the already established resident copy sequence.
It does not build a general provenance engine. Witness steps are evidence
coordinates and never select production compiler behavior.
"""
import bisect
import hashlib
import json
from pathlib import Path


def derive(directory):
    directory = Path(directory)
    steps, writers, checkpoints = {}, {}, {}
    source = (directory / 'source.bin').read_bytes()
    identity = json.loads((directory / 'identity.json').read_text())
    old109 = json.loads(Path('research/host-compiler/pass-109/source-value-chain.json').read_text())
    old110 = json.loads(Path('research/host-compiler/pass-110/declaration-provenance.json').read_text())

    def need(ok, message):
        if not ok:
            raise AssertionError('Pass111: ' + message)

    with (directory / 'events.jsonl').open() as stream:
        for line in stream:
            q = json.loads(line)
            if q['kind'] == 'record_read':
                for i, v in enumerate(bytes.fromhex(q['data'])):
                    writers.setdefault(q['dma'] + i, []).append((q['step'], v, q))
            elif q['kind'] == 'checkpoint':
                checkpoints[q['step']] = q
            elif q['kind'] == 'step' and q['step'] < 550000:
                steps[q['step']] = q
                for k, a, v in q['accesses']:
                    if k == 'W':
                        writers.setdefault(a, []).append((q['step'], v, None))
    need(all(i in steps for i in range(550000)), 'complete original bounded journal')
    need(identity['source_sha256'] == old109['identity']['source_sha256'] ==
         hashlib.sha256(source).hexdigest(), 'same normalized historical source')
    edges = []

    def last(address, step):
        ws = writers.get(address, [])
        i = bisect.bisect_left(ws, (step,)) - 1
        need(i >= 0, 'known last writer ' + hex(address))
        return ws[i]

    def read(step, address, writer=None):
        values = [v for k, a, v in steps[step]['accesses'] if k == 'R' and a == address]
        need(len(values) == 1, 'one actual data read')
        w = last(address, step)
        need(w[1] == values[0], 'fresh read agrees with last writer')
        if writer is not None:
            need(w[0] == writer, 'no intervening write')
        edges.append(dict(read_step=step, address=address, writer_step=w[0], value=w[1]))
        return w

    def ins(step, name):
        need(steps[step]['instruction'] == name, 'actual instruction ' + str(step))

    def store(step, address, value):
        need(['W', address, value] in steps[step]['accesses'], 'actual publication')

    def find(start, end, offset):
        return next(i for i in range(start, end) if steps[i]['image'] == 'PLI1.OVL' and
                    steps[i]['offset'] == offset)

    def copy_a(load, address, store_step, destination, writer=None):
        w = read(load, address, writer)
        value = steps[load]['after']['a']
        need(all(steps[i]['before']['a'] == steps[i]['after']['a'] == value
                 for i in range(load + 1, store_step)), 'A ownership between load/store')
        need(steps[store_step]['before']['a'] == value, 'loaded A reaches publication')
        store(store_step, destination, value)
        return w

    def load_before_store(step, address):
        for j in reversed(range(step - 4, step)):
            if ['R', address, steps[step]['before']['a']] in steps[j]['accesses']:
                need(all(steps[k]['instruction'] == 'RET' for k in range(j + 1, step)),
                     'resident A transfer only across RET')
                return j
        raise AssertionError('Pass111: missing resident source read')

    def file_origin(address, before):
        w = last(address, before)
        s = w[0]
        need(w[2] is None and steps[s]['image'] == 'PLI.COM' and steps[s]['offset'] == 0xe3d,
             'resident source line-copy owner')
        ins(s - 1, 'LDA 20ABH')
        ab = read(s - 1, 0x20ab)[0]
        ins(ab, 'MOV M,C'); ins(ab - 3, 'MOV C,L'); ins(ab - 4, 'LHLD 20A9H')
        need(steps[ab]['before']['c'] == steps[ab - 3]['after']['c'] == w[1], 'line-copy C transfer')
        a9 = read(ab - 4, 0x20a9)[0]
        ins(a9, 'STA 20A9H')
        a = read(load_before_store(a9, 0x209a), 0x209a)[0]
        ins(a, 'STA 209AH')
        first = read(load_before_store(a, 0x2098), 0x2098)[0]
        ins(first, 'STA 2098H'); ins(first - 1, 'RET'); ins(first - 2, 'MOV A,M')
        access = steps[first - 2]['accesses']
        need(len(access) == 1 and access[0][0] == 'R', 'one raw source byte')
        raw = access[0][1]
        owner = read(first - 2, raw)[2]
        need(owner is not None and owner['file'] == 'FIZZBUZ.PLI', 'source file is actual byte owner')
        offset = owner['record'] * 128 + raw - owner['dma']
        need(source[offset] == access[0][2] == w[1], 'whole resident copy preserves source byte')
        return dict(source_offset=offset, byte=w[1], record_read_step=owner['step'],
                    raw_read_step=first - 2, line_write_step=s)

    def prefix_origin(step):
        ins(step - 1, 'LDA 20C1H')
        context = read(step - 1, 0x20c1)[0]
        candidates = [steps[i] for i in range(context - 25, context)]
        raw = next(q for q in candidates if q['instruction'] == 'MOV A,M' and
                   any(k == 'R' and 0x1e8e <= a <= 0x1f0d for k, a, v in q['accesses']))
        scratch = next(q for q in candidates if q['instruction'] == 'MOV M,C' and
                       any(k == 'W' and a == 0x208f for k, a, v in q['accesses']))
        need(scratch['before']['c'] == raw['after']['a'], 'normalizer consumes lexical byte')
        masks = [q for q in candidates if q['instruction'] == 'ANI 5FH']
        if masks:
            q = masks[-1]
            read(q['step'] - 1, 0x208f, scratch['step'])
            expected = raw['after']['a'] & 0x5f
            need(q['after']['a'] == expected, 'actual letter normalization')
        else:
            q = next(q for q in reversed(candidates) if q['instruction'] == 'LDA 208FH')
            read(q['step'], 0x208f, scratch['step'])
            expected = raw['after']['a']
            need(expected <= 0x5f, 'actual unchanged punctuation/digit route')
        need(steps[context]['before']['a'] == steps[step]['before']['a'] == expected,
             'normalized byte reaches prefix')
        return dict(prefix_write_step=step, normalized=expected,
                    **file_origin(raw['accesses'][0][1], raw['step']))

    def replay(entry, end):
        q, r = checkpoints[entry], checkpoints[end]
        result = json.loads((directory / (q['ram'] + '-replay.json')).read_text())
        accesses = [a for i in range(entry, end) for a in steps[i]['accesses']]
        need(result['state'] == r['state'], 'separate replay complete registers/flags')
        need((directory / (q['ram'] + '-replay.ram')).read_bytes() ==
             (directory / r['ram']).read_bytes(), 'separate replay complete 64 KiB RAM')
        need(result['writes'] == [a[1:] for a in accesses if a[0] == 'W'], 'complete ordered writes')
        need(json.loads((directory / (q['ram'] + '-accesses.json')).read_text()) == accesses,
             'complete ordered data reads/writes')
        need(result['instructions'] == end - entry, 'actual window instruction extent')
        ram = (directory / q['ram']).read_bytes()
        continuation = ram[q['state']['sp']] | ram[q['state']['sp'] + 1] << 8
        need(r['state']['pc'] == continuation and r['state']['sp'] == q['state']['sp'] + 2,
             'RET consumes original hardware word exactly once')
        return dict(entry_step=entry, exit_step=end, image=q['image'], offset=q['offset'],
                    instructions=result['instructions'], reads=sum(a[0] == 'R' for a in accesses),
                    writes=len(result['writes']), continuation=continuation,
                    entry_RAM_SHA256=q['RAM_sha256'], exit_RAM_SHA256=r['RAM_sha256'],
                    full_CPU_RAM_accesses_equal=True)

    cases = []
    for spelling, common_entry, common_exit, finalizer, finalizer_exit, consumer, consumer_exit in [
        ('15',393452,393793,395769,395950,400417,402221),
        ('3',463314,463655,465509,465690,470063,471867),
        ('5',530112,530453,532307,532488,536861,538665),
    ]:
        begin_edges = len(edges)
        source_start = source.index(('mod(i,' + spelling + ')').encode())
        name_cmp = max(i for i, q in steps.items() if i < common_entry and
                       q['instruction'] == 'CMP M' and ['R',0xfbd9,ord('M')] in q['accesses'])
        # The actual reverse identifier comparisons retain each prefix byte's owner.
        origins = []
        for j in range(3):
            compare = name_cmp - 26 * j
            read(compare, 0xfbd9 + j)
            ins(compare - 1, 'LDAX D')
            w = read(compare - 1, 0x20c6 + j)
            origins.append(prefix_origin(w[0]))
            need(steps[compare]['after']['flags']['zero'], 'MOD name comparison succeeds')
        need([q['source_offset'] for q in origins] == list(range(source_start,source_start+3)),
             'actual source MOD occurrence, not token coincidence')
        # Follow lookup result through the actual saved field and restored pointer.
        field_store = find(name_cmp, common_entry, 0x5a9e)
        # The source pointer is supplied by the successful lookup, not reconstructed
        # from the name or selected using its value.
        pointer_load = field_store - 3
        ins(pointer_load, 'LHLD A863H'); read(pointer_load, 0xa863); read(pointer_load,0xa864)
        need(steps[pointer_load]['after']['h'] << 8 | steps[pointer_load]['after']['l'] == 0xfbcf,
             'resolved record pointer')
        ins(pointer_load+1,'XCHG')
        field = next(a for k,a,v in steps[field_store]['accesses'] if k=='W')
        store(field_store,field,0xcf); store(field_store+2,field+1,0xfb)
        dispatch_call = max(i for i in range(name_cmp,common_entry) if steps[i]['image']=='PLI1.OVL' and
                            steps[i]['offset']==0x5f3a)
        desc_read = dispatch_call-4
        ins(desc_read,'MOV E,M'); read(desc_read,0xfbd4)
        need(steps[desc_read]['before']['h']<<8|steps[desc_read]['before']['l']==0xfbd4,
             'handler selector read at resolved record+5')
        # Saved A75A is reached via the record field, then restored into A863.
        restore = max(i for i in range(name_cmp,dispatch_call) if steps[i]['image']=='PLI1.OVL' and steps[i]['offset']==0x413d)
        saved_pair = steps[restore-1]
        need(saved_pair['instruction']=='LHLD A75AH','fresh selected pointer restore')
        saved_writer=read(restore-1,0xa75a)[0];read(restore-1,0xa75b,saved_writer)
        saved_load=saved_writer-4
        read(saved_load,field,field_store);read(saved_load+2,field+1,field_store+2)
        ins(saved_writer-1,'XCHG')
        read(dispatch_call-6,0xa863,restore);read(dispatch_call-6,0xa864,restore)
        need(steps[desc_read]['after']['e']==20,'actual selected descriptor field')
        # Read selector from the duplicated byte-local frame, follow the two-byte
        # table and real PCHL, retaining the original CALL frame.
        root=dispatch_call+1
        transfer=find(root,common_entry,0x50b3)
        index_read=transfer-9
        index_address=steps[index_read]['accesses'][0][1]
        selector_writer=read(index_read,index_address)[0]
        need(steps[selector_writer]['instruction']=='PUSH D' and
             any(k=='W'and v==20 for k,a,v in steps[selector_writer]['accesses']), 'actual saved selector byte')
        lo=read(transfer-4,0x789f+20*2)[1];hi=read(transfer-2,0x78a0+20*2)[1]
        need(lo|hi<<8==0x75bb and steps[transfer]['after']['pc']==0x75bb,'table-driven MOD PCHL')
        ins(transfer+1,'MVI C,CFH');ins(transfer+2,'CALL 720FH')

        # Bind the already published common-context proof by complete RAM identity.
        old = next(q for q in old110['CPU_replays'] if q['entry_step']==common_entry)
        need(checkpoints[common_entry]['RAM_sha256']==old['entry_RAM_sha256'] and
             checkpoints[common_exit]['RAM_sha256']==old['exit_RAM_sha256'], 'preserved Pass110 boundary')
        input_ram=(directory/checkpoints[common_entry]['ram']).read_bytes()
        operand_channels=[]
        for offsets,dests in [([0x7aa7,0x7abd,0x7ad3],[0xa62a,0xa62d,0xa630]),
                              ([0x7aa7,0x7abd,0x7ad3],[0xa629,0xa62c,0xa62f])]:
            group=[]
            for offset,dest in zip(offsets,dests):
                copied=max(i for i in range(common_entry-400,common_entry) if any(k=='W'and a==dest for k,a,v in steps[i]['accesses']))
                load=copied-2
                need(steps[load]['offset']==offset,'actual mapped operand attribute reader')
                addr=steps[load]['accesses'][0][1]
                read(load,addr)
                copy_a(load,addr,copied,dest)
                group.append(dict(read_step=load,address=addr,destination=dest,value=input_ram[dest]))
            operand_channels.append(group)
        copies=[]
        for offset,base,dest in [(0x2998,0xa628,0xa62a),(0x29a3,0xa62b,0xa62d),(0x29ae,0xa62e,0xa630)]:
            load=find(common_exit,finalizer,offset)
            w=copy_a(load,base,load+1,dest)
            need(common_entry<=w[0]<common_exit,'converted literal uses common context owner')
            copies.append(load+1)
        if spelling=='15':
            constructor=old109['constructor']
            need(checkpoints[constructor['entry_step']]['RAM_sha256']==constructor['entry_RAM_sha256'],
                 'preserved Pass109 constructor entry')
        entry_ram=(directory/checkpoints[finalizer]['ram']).read_bytes()
        need([entry_ram[a] for a in [0xa628,0xa62c,0xa62d,0xa62f,0xa630]]==[21,15,15,0,0],
             'actual finalizer inherited operand attributes')
        tag_owner=read(finalizer,0xa628)[0]
        need(common_entry<=tag_owner<common_exit,'result tag remains owned by common context')
        ins(finalizer+1,'ANI 14H');ins(finalizer+2,'CPI 14H')
        need(steps[finalizer+2]['after']['flags']['zero'],'selected result-finalization branch')
        read(finalizer+4,0xa62f);read(finalizer+6,0xa630,copies[2])
        # Byte arithmetic law derived separately from the executed instructions.
        zero=max(entry_ram[0xa62f],entry_ram[0xa630])
        middle=(entry_ram[0xa62d]-entry_ram[0xa630]+zero)&255
        store(finalizer+19,0xa62e,zero)
        read(finalizer+21,0xa62d,copies[1]);read(finalizer+22,0xa630,copies[2])
        read(finalizer+24,0xa62e,finalizer+19)
        store(finalizer+25,0xa62b,middle)
        need(not any(k=='W'and a==0xa628 for i in range(finalizer,finalizer_exit)
                     for k,a,v in steps[i]['accesses']), 'result tag retained, not freshly copied')
        emission=find(common_exit,finalizer,0x5028)
        need(steps[emission]['before']['c']==0xcf+2, 'actual selected operation emission marker')
        need(steps[emission]['instruction']=='CALL 4711H','real operation emission CALL')
        cap=find(finalizer,finalizer_exit,0x2437)
        middle_read=find(finalizer,cap,0x2426)
        read(middle_read,0xa62b,finalizer+25)
        cap_input=read(middle_read+1,0xa642)[1]
        store(cap,0xa62b,min(middle,cap_input))
        publications=[]
        for offset,base in [(0x7b2c,0xac73),(0x7b47,0xad08),(0x7b62,0xad9d)]:
            pub=find(finalizer,finalizer_exit,offset)
            address,value=next((a,v) for k,a,v in steps[pub]['accesses'] if k=='W')
            carrier=address-base
            need(not publications or carrier==publications[0]['address']-0xac73,
                 'all result channels use one current mapped carrier')
            map_read=pub-5
            mapping=read(map_read,0xaa23)
            need(mapping[1]==carrier,'fresh position4 mapping')
            source_base,source_offset,owner={0xac73:(0xa628,0x23df,tag_owner),
                                             0xad08:(0xa62b,0x23f0,cap),
                                             0xad9d:(0xa62e,0x2401,finalizer+19)}[base]
            load=find(finalizer,pub,source_offset)
            read(load,source_base,owner)
            scratch_write=pub-12
            ins(scratch_write,'MOV M,E')
            need(all(steps[i]['before']['e']==steps[i]['after']['e']==value
                     for i in range(load+1,scratch_write)), 'publisher E ownership')
            need(steps[scratch_write]['before']['e']==value,'fresh value reaches publisher scratch')
            read(pub-1,{0xac73:0xae42,0xad08:0xae44,0xad9d:0xae46}[base],scratch_write)
            first_pub=max(i for i in range(common_exit,finalizer) if ['W',address,value]in steps[i]['accesses'])
            need(emission<first_pub<finalizer and steps[first_pub]['offset']==offset, 'first result publication belongs to selected operation path')
            publications.append(dict(address=address,value=value,first_publication_step=first_pub,
                                     final_publication_step=pub,map_writer=mapping[0]))
        need([q['value']for q in publications]==[21,15,0],'result tuple')
        need(publications[0]['final_publication_step']<publications[1]['final_publication_step']<
             publications[2]['final_publication_step'],'ordered final tag/middle/zero publications')
        root_return=find(finalizer_exit,consumer,0x570d)
        original=steps[dispatch_call]['before']['sp']-2
        ins(root_return,'RET')
        read(root_return,original,dispatch_call);read(root_return,original+1,dispatch_call)
        need(steps[root_return]['after']['pc']==0x813d,'original outer hardware continuation')

        # Source '=' is normalized, acquired, moved into token20C3, found in the
        # actual relation table, and retained in the enclosing operator frame.
        relation_search=max(i for i in range(root_return,consumer) if steps[i]['image']=='PLI1.OVL' and
                            steps[i]['offset']==0x6556)
        matched=find(relation_search,consumer,0x6564)
        saved_index=steps[matched]['before']['a']
        need(saved_index==2,'measured equality table index')
        token_read=matched-10
        token_writer=read(token_read,0x20c3)[0]
        ins(token_writer,'STA 20C3H');ins(token_writer-1,'LDA 20C6H')
        prefix=read(token_writer-1,0x20c6)[0]
        equal_origin=prefix_origin(prefix)
        need(equal_origin['source_offset']==source_start+len('mod(i,'+spelling+')')+1 and
             equal_origin['byte']==ord('='),'actual following equality source')
        need(steps[token_read+1]['after']['flags']['zero'],'actual successful equality-table comparison')
        op_slot=steps[matched]['accesses'][0][1]
        op_read=consumer-3
        read(op_read,op_slot,matched)
        need(steps[op_read+1]['after']['flags']['carry']==False,'actual relation selection guard')
        need(steps[consumer-1]['instruction']=='CALL 565EH','real equality preparation CALL')
        zero_prefix=next(i for i in range(matched,consumer) if ['W',0x20c6,ord('0')]in steps[i]['accesses'])
        zero_origin=prefix_origin(zero_prefix)
        need(zero_origin['source_offset']==equal_origin['source_offset']+2,'actual equality right-hand zero')
        matches=[i for i in range(zero_prefix+1,consumer) if steps[i]['instruction']=='CMP M' and
                 steps[i-1]['instruction']=='LDAX D' and ['R',0x20c6,ord('0')]in steps[i-1]['accesses'] and
                 any(k=='R'and v==ord('0')for k,a,v in steps[i]['accesses'])]
        if matches:
            zero_event=matches[0]
            read(zero_event-1,0x20c6,zero_prefix)
            zero_record_byte=steps[zero_event]['accesses'][0][1]
            record_owner=read(zero_event,zero_record_byte)[0]
            need(steps[zero_event]['after']['flags']['zero'],'actual retained zero-spelling match')
            zero_route='retained spelling comparison'
        else:
            zero_event=find(zero_prefix,consumer,0x44d9)
            read(zero_event-1,0x20c6,zero_prefix)
            ins(zero_event-1,'LDAX D')
            zero_record_byte=steps[zero_event]['accesses'][0][1]
            copy_a(zero_event-1,0x20c6,zero_event,zero_record_byte,zero_prefix)
            record_owner=zero_event
            zero_route='new spelling record copy'
        zero_meta=find(zero_event,consumer,0x594b)
        copy_a(zero_meta-1,0x20c3,zero_meta,0xa628)
        copy_a(zero_meta+1,0x20c5,zero_meta+2,0xa62b)
        store(zero_meta+4,0xa62e,0)
        # Right operand readers precede the left-result readers in +31FB.
        for offset,destination,value,base,owner in [(0x7aa7,0xa62a,2,0xac73,zero_meta),
                                                   (0x7abd,0xa62d,1,0xad08,zero_meta+2),
                                                   (0x7ad3,0xa630,0,0xad9d,zero_meta+4)]:
            load=find(consumer,consumer_exit,offset)
            address=steps[load]['accesses'][0][1]
            pub=read(load,address)[0]
            need(steps[pub]['offset']=={0xac73:0x7b2c,0xad08:0x7b47,0xad9d:0x7b62}[base],
                 'zero attribute canonical publisher')
            read(pub-17,{0xac73:0xa628,0xad08:0xa62b,0xad9d:0xa62e}[base],owner)
            need(steps[pub-17]['after']['e']==value,'source zero attribute reaches publisher')
            copy_a(load,address,load+2,destination,pub)
        reads=[]
        for offset,pub,dest in zip([0x7aa7,0x7abd,0x7ad3],publications,[0xa629,0xa62c,0xa62f]):
            load=next(i for i in range(consumer,consumer_exit) if steps[i]['image']=='PLI1.OVL' and
                      steps[i]['offset']==offset and any(k=='R'and a==pub['address'] for k,a,v in steps[i]['accesses']))
            read(load,pub['address'],pub['final_publication_step'])
            map_load=load-4
            read(map_load,0xaa23,pub['map_writer'])
            need(steps[map_load]['before']['h']<<8|steps[map_load]['before']['l']==0xaa23,
                 'consumer freshly selects the same position')
            copy_a(load,pub['address'],load+2,dest,pub['final_publication_step'])
            reads.append(dict(step=load,address=pub['address'],destination=dest,
                              result_writer=pub['final_publication_step']))
        common_call=find(consumer,consumer_exit,0x3481)
        for item in reads:
            use=next(i for i in range(common_call+1,consumer_exit) if
                     any(k=='R'and a==item['destination'] for k,a,v in steps[i]['accesses']))
            read(use,item['destination'],item['step']+2)
        need(steps[common_call]['instruction']=='CALL 52C1H','equality common-type preparation')
        result_ram=(directory/checkpoints[consumer_exit]['ram']).read_bytes()
        need([result_ram[a]for a in [0xa628,0xa62b,0xa62e]]==[21,15,0], 'equality conversion context')
        cases.append(dict(literal=spelling,source_MOD=origins,source_equality=equal_origin,
                          source_zero=zero_origin,zero_spelling_event=zero_event,zero_record_byte=zero_record_byte,
                          zero_spelling_route=zero_route,zero_spelling_record_writer=record_owner,
                          lookup_name_compare=name_cmp,resolved_builtin_record=0xfbcf,
                          record_field=field,dispatch_call=dispatch_call,root_entry=root,
                          descriptor_selector=20,PCHL_step=transfer,table_target=0x75bb,
                          operation_emission_call=emission,operation_marker=0xd1,
                          common_context_entry=common_entry,common_context_exit=common_exit,
                          operand_attribute_reads=operand_channels,
                          operand_words_before_conversion=[int.from_bytes(input_ram[0xa63d:0xa63f],'little'),int.from_bytes(input_ram[0xa63f:0xa641],'little')],
                          word_channel_limit='Compiler carrier words are not inferred to be runtime i or runtime MOD values',
                          converted_operand_copy_steps=copies,
                          finalization_law='middle=(converted_right_middle-right_zero+max(left_zero,right_zero)) mod256; tag retained',
                          result_position=4,result_carrier=publications[0]['address']-0xac73,result_tuple=[21,middle,zero],
                          publications=publications,root_return=root_return,
                          consumer_entry=consumer,consumer_exit=consumer_exit,
                          consumer_kind='source-correlated equality operand preparation',
                          saved_relation_slot=op_slot,saved_relation_index=saved_index,
                          consumer_reads=reads,equality_common_call=common_call,
                          finalizer_replay=replay(finalizer,finalizer_exit),
                          consumer_replay=replay(consumer,consumer_exit),
                          last_writer_edge_count=len(edges)-begin_edges))
    return dict(all_passed=True,identity=identity,
                capture_SHA256=hashlib.sha256((directory/'events.jsonl').read_bytes()).hexdigest(),
                cases=cases,last_writer_edges=edges,
                status='SELECTED MOD RESULT ATTRIBUTES AND EQUALITY CONSUMER ESTABLISHED',
                representation='Mapped expression carrier with retained tag and recomputed numeric attributes; no separate result symbol record established',
                runtime_limit='Compiling MOD is observed; no runtime MOD value is computed by this proof',
                CPU_limit='Original execution and copied window replays use the same CPU engine')
