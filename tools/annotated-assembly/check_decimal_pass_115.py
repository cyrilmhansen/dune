"""Selected FIXEDDEC provenance checks; witnesses never implement a compiler."""
import bisect,hashlib,json
from pathlib import Path


def derive(directory):
    directory=Path(directory)
    source=(directory/'source.bin').read_bytes()
    identity=json.loads((directory/'identity.json').read_text())
    steps={};checkpoints=[];exits={};records=[];writers={};edges=[]
    def need(ok,msg):
        if not ok:raise AssertionError('Pass115: '+msg)
    for line in (directory/'events.jsonl').open():
        q=json.loads(line)
        if q['kind']=='step':steps[q['step']]=q
        elif q['kind']=='checkpoint':checkpoints.append(q)
        elif q['kind']=='checkpoint_exit':exits[q['ram']]=q
        elif q['kind']=='record_read':records.append(q)
    for line in (directory/'writes.jsonl').open():
        n,im,off,a,v=json.loads(line);writers.setdefault(a,[]).append((n,v,None))
    for q in records:
        for i,v in enumerate(bytes.fromhex(q['data'])):
            writers.setdefault(q['dma']+i,[]).append((q['step'],v,q))
    for a in writers:writers[a].sort(key=lambda q:q[0])
    need(hashlib.sha256(source).hexdigest()==identity['source_sha256'],'normalized source identity')
    def last(address, step):
        ws = writers.get(address, [])
        i = bisect.bisect_left(ws, (step,)) - 1
        need(i >= 0, 'known last writer for ' + hex(address))
        return ws[i]

    def read(step, address, writer=None):
        q = steps[step]
        values = [v for k, a, v in q['accesses'] if k == 'R' and a == address]
        need(len(values) == 1, 'one owned read')
        w = last(address, step)
        need(w[1] == values[0], 'last-writer value agrees')
        if writer is not None:
            need(w[0] == writer, 'no intervening writer')
        edges.append(dict(read_step=step, address=address, writer_step=w[0], value=w[1]))
        return w

    def instruction(step, name):
        need(steps[step]['instruction'] == name, 'instruction ' + str(step))

    def writes(step, expected):
        need([a[1:] for a in steps[step]['accesses'] if a[0] == 'W'] == expected,
             'ordered publication ' + str(step))

    def load_before_store(step, address):
        # This resident source adapter transfers A across only a RET.
        for j in reversed(range(step - 4, step)):
            if j in steps and ['R', address, steps[step]['before']['a']] in steps[j]['accesses']:
                need(all(steps[k]['instruction'] == 'RET' for k in range(j + 1, step)),
                     'source adapter A ownership across return')
                return j
        raise AssertionError('Pass115: missing resident source read')

    def file_origin(address, before):
        w = last(address, before)
        store = w[0]
        need(w[2] is None and steps[store]['image'] == 'PLI.COM' and
             steps[store]['offset'] == 0xe3d, 'actual source line-copy owner')
        instruction(store - 1, 'LDA 20ABH')
        ab = read(store - 1, 0x20ab)[0]
        instruction(ab, 'MOV M,C')
        instruction(ab - 3, 'MOV C,L')
        instruction(ab - 4, 'LHLD 20A9H')
        need(steps[ab - 3]['after']['c'] == w[1], 'paired transfer reaches C')
        a9 = read(ab - 4, 0x20a9)[0]
        instruction(a9, 'STA 20A9H')
        a9load = load_before_store(a9, 0x209a)
        a = read(a9load, 0x209a)[0]
        instruction(a, 'STA 209AH')
        aload = load_before_store(a, 0x2098)
        first = read(aload, 0x2098)[0]
        instruction(first, 'STA 2098H')
        glyph = first - 2
        instruction(glyph, 'MOV A,M')
        instruction(first - 1, 'RET')
        access = steps[glyph]['accesses']
        need(len(access) == 1 and access[0][0] == 'R', 'actual source address')
        raw_address = access[0][1]
        owner = read(glyph, raw_address)
        record = owner[2]
        need(record is not None and record['file'] == 'FIXEDDEC.PLI', 'source record owns byte')
        offset = record['record'] * 128 + raw_address - record['dma']
        need(source[offset] == w[1] == steps[glyph]['after']['a'], 'source-copy byte identity')
        return dict(source_offset=offset, value=w[1], record_read_step=record['step'],
                    raw_read_step=glyph, line_address=address, line_write_step=store)

    def prefix_origin(write):
        q = steps[write]
        instruction(write - 1, 'LDA 20C1H')
        context = read(write - 1, 0x20c1)[0]
        candidates = [steps[i] for i in range(context - 25, context) if i in steps]
        raw = next(r for r in candidates if r['instruction'] == 'MOV A,M' and
                   any(k == 'R' and 0x1e8e <= a <= 0x1f0d for k, a, v in r['accesses']))
        raw_step = raw['step']
        scratch = next(r for r in candidates if r['instruction'] == 'MOV M,C' and
                       any(k == 'W' and a == 0x208f for k, a, v in r['accesses']))
        need(scratch['before']['c'] == raw['after']['a'], 'normalizer input is lexical byte')
        masks = [r for r in candidates if r['instruction'] == 'ANI 5FH']
        if masks:
            mask = masks[-1]
            read(mask['step'] - 1, 0x208f, scratch['step'])
            need(mask['after']['a'] == (raw['after']['a'] & 0x5f) == q['before']['a'],
                 'observed lowercase normalization')
        else:
            fresh = next(r for r in reversed(candidates) if r['instruction'] == 'LDA 208FH')
            read(fresh['step'], 0x208f, scratch['step'])
            need(raw['after']['a'] <= 0x5f and fresh['after']['a'] == q['before']['a'],
                 'observed unchanged digit normalization')
        need(steps[context]['before']['a'] == q['before']['a'], 'normalized context publication')
        origin = file_origin(raw['accesses'][0][1], raw_step)
        return dict(prefix_write_step=write, normalized=q['before']['a'], **origin)

    words={}
    for label,first,length,text in [('dcl',96784,3,b'dcl'),('x',98122,1,b'x'),
        ('fixed',99327,5,b'fixed'),('decimal',100983,7,b'decimal'),
        ('precision',102867,1,b'7'),('scale',103383,1,b'2')]:
        pubs=[]
        for i in range(length):
            n=next(n for n in sorted(steps) if first<=n<first+900 and
                   any(k=='W'and a==0x20c6+i for k,a,v in steps[n]['accesses']))
            pubs.append(prefix_origin(n))
        offsets=[q['source_offset']for q in pubs]
        need(offsets==list(range(offsets[0],offsets[0]+length)),'contiguous source '+label)
        need(source[offsets[0]:offsets[-1]+1]==text,'selected source spelling '+label)
        words[label]=pubs
    need(source[words['dcl'][0]['source_offset']:words['scale'][0]['source_offset']+3]==b'dcl x fixed decimal(7,2);','whole selected declaration')
    # Actual keyword comparisons consume those acquired letters backwards.
    keyword=[]
    for label,token in [('dcl',0x81),('fixed',0xa2),('decimal',0x88)]:
        # Record the observed token rather than deriving a type from its byte.
        group=words[label];lo=group[-1]['prefix_write_step'];hi=lo+1200
        publication=next(q for n,q in steps.items()if lo<n<hi and q['image']=='PLI0.OVL'and q['offset']==0x43c9)
        end=publication['step'];comparisons=[];table=[]
        for i,pub in reversed(list(enumerate(group))):
            hits=[q for n,q in steps.items()if lo<n<end and q['image']=='PLI0.OVL'and q['offset']==0x439b and
                  ['R',0x20c6+i,pub['normalized']]in q['accesses'] and steps[n+1]['after']['a']==0]
            hit=hits[-1];n=hit['step'];read(n,0x20c6+i,pub['prefix_write_step']);instruction(n+1,'SUB M')
            table.append((i,steps[n+1]['accesses'][0][1]));comparisons.append(n)
        need(len({address-i for i,address in table})==1,'one successful keyword record')
        need(all(steps[n+1]['after']['flags']['zero']for n in comparisons),'all keyword comparisons equal')
        need(steps[end-1]['after']['a']==publication['before']['a'],'matched record token reaches publication')
        value=publication['accesses'][0][2]
        if label!='dcl':need(value==token,'known FIXED/DECIMAL token')
        keyword.append({'source_word':label,'comparisons':comparisons,'token':value,'publication':publication['step']})
    instruction(99168,'LDAX B');read(99168,0x20c6,98122);writes(99169,[[0x6ff3,0x58]])
    # The declaration path freshly consumes each source-owned keyword token.
    read(100695,0x20c3,100331);read(102409,0x20c3,102094)
    read(100702,0x6871);instruction(100703,'ADI 0EH')
    need(steps[100703]['after']['a']==21,'actual FIXED qualifier ordinal')
    read(102416,0x6871);instruction(102417,'ADI 0EH')
    need(steps[102417]['after']['a']==18,'actual DECIMAL qualifier ordinal')
    # Explicit qualifier tokens determine separate historical table entries.
    for n,addr,value,writer in [(100719,0x6890,21,100712),(102433,0x6890,18,102426)]:
        read(n,addr,writer);need(steps[n]['after']['a']==value,'qualifier ordinal')
    for n,addr,expected in [(100791,0x22ca,0x14),(102505,0x22be,0x12)]:
        need(steps[n]['accesses']==[['R',addr,expected]],'immutable qualifier table selection')
    read(102507,0x6feb,100797);need(steps[102507]['after']['a']==0x16,'FIXED OR DECIMAL qualifier bits')
    writes(102511,[[0x6feb,0x16]])
    # Two independent source parameters, not the acquisition checksum field.
    parameters=[]
    for name,n,number,store,target in [('precision',103054,7,103074,0x6883),('scale',103553,2,103573,0x6884)]:
        origin=words[name][0];read(n,0x20c6,origin['prefix_write_step'])
        instruction(n+1,'SUI 30H');need(steps[n+1]['after']['a']==number,'single decimal digit numeric subtraction')
        writes(store,[[0x2153,number]]);writes(store+2,[[0x2154,0]])
        get=next(q for j,q in steps.items()if store<j<store+25 and q['instruction']=='LHLD 2153H')
        read(get['step'],0x2153,store);read(get['step'],0x2154,store+2)
        local=next(q for j,q in steps.items()if get['step']<j<get['step']+6 and ['W',target,number]in q['accesses'])
        parameters.append({'role':name,'value':number,'digit_read':n,'numeric_write':store,'parameter_local':target,'local_write':local['step']})
    read(103801,0x6883,103097);read(103803,0x6884,103596)
    writes(103807,[[0x687f,2]]);writes(103809,[[0x687e,7]])
    read(103876,0x687e,103809);writes(103877,[[0x6fed,7]])
    read(103881,0x687f,103807);writes(103882,[[0x6fee,2]])
    for n,addr,writer in [(104696,0x6feb,102511),(104710,0x6fed,103877),(104717,0x6fee,103882)]:read(n,addr,writer)
    read(104879,0xffde,104713);writes(104881,[[0x6fed,7]])
    read(104888,0xffdf,104720);writes(104890,[[0x6fee,2]])
    # Chase actual LDAX/MOV copies backwards, preserving record reuse.
    def copy_chain(address,before,initial):
        chain=[];a=address;t=before
        while True:
            n,v,_=last(a,t)
            if n==initial:break
            need(steps[n]['instruction']in ['MOV M,A','STAX D'],'record copy store')
            need(steps[n-1]['instruction']in ['LDAX B','MOV A,M'],'record copy load '+str((a,n,steps[n-1]['instruction'])))
            load=steps[n-1];need(len(load['accesses'])==1,'single copy source')
            src=load['accesses'][0][1];read(n-1,src)
            need(load['after']['a']==steps[n]['before']['a']==v,'copy A reaches publication')
            chain.append({'read':n-1,'write':n,'from':src,'to':a,'value':v});a=src;t=n-1
            need(len(chain)<8,'bounded declaration copies')
        return list(reversed(chain))
    relocations={}
    for delta,initial in [(2,104864),(4,104881),(5,104890),(10,99169)]:
        # FBDD is the selected x record; its later direct field reads are proved below.
        relocations[str(delta)]=copy_chain(0xfbdd+delta,375000,initial)
    # Selected later declaration field reads and publication into operand channels.
    read(375682,0xfbe1);read(375687,0xfbe2)
    writes(375683,[[0xa62b,7]]);writes(375688,[[0xa62e,2]])
    # The operation-specific precision/scale algebra is independent of matching 2.
    read(380586,0xa62d);read(380588,0xa62c)
    instruction(380588,'ADD M');instruction(380589,'INR A');writes(380591,[[0xa62b,15]])
    read(380592,0xa630);read(380594,0xa62f)
    instruction(380594,'ADD M');writes(380596,[[0xa62e,4]])
    need(steps[380588]['after']['a']==14 and steps[380594]['after']['a']==4,'distinct product attribute laws')
    literals=[]
    for spelling,first in [('12.50',134278),('2.25',139282)]:
        pubs=[]
        for i in range(len(spelling)):
            n=next(n for n in sorted(steps)if first<=n<first+900 and
                   any(k=='W'and a==0x20c6+i for k,a,v in steps[n]['accesses']))
            pubs.append(prefix_origin(n))
        offsets=[q['source_offset']for q in pubs]
        need(offsets==list(range(offsets[0],offsets[0]+len(spelling))),'literal contiguous source')
        need(source[offsets[0]:offsets[-1]+1]==spelling.encode(),'decimal digits and point source ownership')
        point=pubs[spelling.index('.')]
        token=next(q for n,q in steps.items()if first<n<pubs[-1]['prefix_write_step']and ['W',0x20c3,3]in q['accesses'])
        n=token['step'];instruction(n-3,'CPI 2EH');need(steps[n-3]['after']['flags']['zero'],'decimal point determines lexical branch')
        read(n-4,0x20c1,last(0x20c1,point['prefix_write_step']-1)[0]);instruction(n,'MVI M,03H')
        literals.append({'spelling':spelling,'source_origins':pubs,'point_classification':n,
          'lexical_class':3,'limit':'Source acquisition and decimal-point branch only; no source-to-retained-literal payload or intrinsic attribute chain claimed.'})
    discriminants=[]
    for cp,name,record,prefix,publication in [(checkpoints[1],'y',0x6ff4,110449,111504),(checkpoints[2],'z',0x6fff,122784,123839)]:
        origin=prefix_origin(prefix);need(source[origin['source_offset']]==ord(name),'separate declaration source name')
        read(publication-1,0x20c6,prefix);writes(publication,[[record+10,ord(name.upper())]])
        ram=(directory/cp['ram']).read_bytes()
        need(cp['state']['b']*256+cp['state']['c']==record,'actual completion argument record')
        need([ram[record+i]for i in [2,4,5,10]]==[0x16,7,2,ord(name.upper())],'natural same-declaration attributes')
        discriminants.append({'name':name,'record':record,'source_origin':origin,'name_publication':publication,'entry':cp['step'],'tuple':[0x16,7,2]})
    # Exact original hardware entries and copied CPU replays, including all RAM.
    replays=[]
    for cp in checkpoints:
        path=cp['ram'];ex=exits[path+'-exit.ram'];lo=cp['step'];hi=ex['step']
        need(all(n in steps for n in range(lo,hi)),'complete bounded checkpoint window')
        caller=steps[lo-1]
        need(caller['bytes'].startswith('cd')and caller['after']==cp['state'],'original hardware CALL ancestry')
        actual=[steps[n]for n in range(lo,hi)]
        replay=json.loads((directory/(path+'-replay.json')).read_text())
        ac=[a for q in actual for a in q['accesses']]
        journal=json.loads((directory/(path+'-accesses.json')).read_text())
        need(ac==journal,'all ordered replay reads/writes')
        need(all(q['before']['pc']!=5 for q in actual),'bounded windows have no BDOS service')
        need(replay['state']==ex['state'],'all CPU/flags including PC/SP')
        need((directory/(path+'-replay.ram')).read_bytes()==(directory/(path+'-exit.ram')).read_bytes(),'all 64KiB RAM')
        ram=(directory/path).read_bytes();sp=cp['state']['sp'];ret=int.from_bytes(ram[sp:sp+2],'little')
        read(hi-1,sp,lo-1);read(hi-1,sp+1,lo-1)
        need(ex['state']['pc']==ret and ex['state']['sp']==sp+2,'actual RET consumes original hardware continuation')
        replays.append({'entry':lo,'exit':hi,'instructions':hi-lo,'original_return':ret,
                        'entry_RAM_SHA256':hashlib.sha256(ram).hexdigest(),'exit_RAM_SHA256':hashlib.sha256((directory/(path+'-exit.ram')).read_bytes()).hexdigest(),
                        'reads':sum(a[0]=='R'for a in ac),'writes':sum(a[0]=='W'for a in ac),'full_RAM_CPU_accesses_equal':True})
    return {'all_passed':True,'identity':identity,'source_words':words,'keyword_dispatch':keyword,
      'record':{'address':0x6fe9,'name':'x','name_publication':99169,'tag':0x16,'precision':7,'scale':2,'fields':[2,4,5]},
      'parameters':parameters,'literal_acquisition':literals,'natural_declaration_discriminants':discriminants,'retained_copies':relocations,'selected_consumers':{'precision_read':375682,'scale_read':375687,
       'product_precision_write':380591,'product_scale_write':380596,'input_channels':[7,2,7,2],'result_channels':[15,4]},
      'last_writer_edges':edges,'CPU_replays':replays,'engine_limit':'Original and copied replay use the same Intel 8080 engine; not independent CPU-engine validation.',
      'scope':'PARTIAL: declaration precision/scale provenance and decimal literal acquisition proved; retained literal typing, operation ownership and multiplication-to-assignment conversion remain open.'}
