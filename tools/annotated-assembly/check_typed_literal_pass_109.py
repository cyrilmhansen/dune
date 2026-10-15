"""One historical literal's read/write ownership proof; no compiler implementation."""
import bisect,hashlib,json
from pathlib import Path

def require(ok,label):
    if not ok: raise AssertionError('Pass109: '+label)

def derive(directory):
    directory=Path(directory)
    identity=json.loads((directory/'identity.json').read_text())
    source=(directory/'source.bin').read_bytes()
    require(hashlib.sha256(source).hexdigest()==identity['source_sha256'],'actual normalized source identity')
    archive=json.loads(Path('research/host-compiler/pass-44/numeric-acquisition-cases.json').read_text())
    case=next(q for q in archive['cases'] if q['prefix']==[0x31,0x35])
    steps={}; checkpoints=[]; writers={}; records=[]
    def remember(address,step,value,kind,event):
        writers.setdefault(address,[]).append((step,value,kind,event))
    with (directory/'events.jsonl').open() as stream:
        for line in stream:
            q=json.loads(line)
            if q['kind']=='record_read':
                records.append(q)
                for i,value in enumerate(bytes.fromhex(q['data'])):
                    if 0xfb00<=q['dma']+i<0xfd7e:remember(q['dma']+i,q['step'],value,'record',q)
            elif q['kind']=='checkpoint':checkpoints.append(q)
            elif q['kind']=='step':
                if 350000<=q['step']<=400000:steps[q['step']]=q
                for kind,address,value in q['accesses']:
                    if kind=='W':remember(address,q['step'],value,'CPU',
                        {k:q[k]for k in ['step','image','offset','instruction']})
    def at(step):
        require(step in steps,'captured instruction '+str(step));return steps[step]
    def last(address,step):
        found=writers.get(address,[])
        i=bisect.bisect_left([q[0]for q in found],step)-1
        require(i>=0,'last writer available '+hex(address));return found[i]
    def read_link(q,address):
        values=[v for kind,a,v in q['accesses'] if kind=='R' and a==address]
        require(len(values)==1,'one concrete read '+hex(address))
        writer=last(address,q['step']);require(writer[1]==values[0],'last writer value')
        return writer
    def load_before_store(store,address):
        candidates=[at(i)for i in range(store['step']-4,store['step'])]
        load=next((q for q in reversed(candidates)if ['R',address,store['before']['a']]in q['accesses']),None)
        require(load is not None,'load before A store')
        require(load['after']['a']==store['before']['a'],'loaded A reaches store')
        for i in range(load['step']+1,store['step']):
            require(at(i)['instruction']=='RET','only RET between data load/store')
        return load
    def file_origin(buffer_address,before_step):
        # Concrete resident source-copy chain, with each historical scratch reread.
        w=last(buffer_address,before_step);require(w[2]=='CPU' and w[3]['offset']==0xe3d,'line buffer producer')
        store=at(w[0]);load=at(w[0]-1)
        require(load['instruction']=='LDA 20ABH','fresh line-copy scratch read')
        ab=at(read_link(load,0x20ab)[0]);require(ab['instruction']=='MOV M,C','scratch supplied by C')
        mov=at(ab['step']-3);pair=at(ab['step']-4)
        require(mov['instruction']=='MOV C,L' and pair['instruction']=='LHLD 20A9H','paired source transfer to C')
        require(at(ab['step']-2)['instruction']=='CALL 0F1FH' and at(ab['step']-1)['instruction']=='LXI H,20ABH','original copy CALL ownership')
        a9=at(read_link(pair,0x20a9)[0]);require(a9['instruction']=='STA 20A9H','raw character scratch')
        a9load=load_before_store(a9,0x209a)
        a=at(read_link(a9load,0x209a)[0]);require(a['instruction']=='STA 209AH','reader channel 209A')
        aload=load_before_store(a,0x2098)
        first=at(read_link(aload,0x2098)[0]);require(first['instruction']=='STA 2098H','reader channel 2098')
        glyph=at(first['step']-2)
        require(at(first['step']-1)['instruction']=='RET' and glyph['instruction']=='MOV A,M','original source byte load')
        require(len(glyph['accesses'])==1 and glyph['accesses'][0][0]=='R','source address from actual read')
        addr=glyph['accesses'][0][1];owner=read_link(glyph,addr)
        require(owner[2]=='record' and owner[3]['file']=='FIZZBUZ.PLI','source file is last writer, not equal-value matching')
        record=owner[3];offset=record['record']*128+addr-record['dma']
        value=source[offset]
        require(value==w[1]==glyph['after']['a']==mov['after']['c']==ab['before']['c'],'whole character-copy value law')
        return {'source_offset':offset,'value':value,'file_read_step':record['step'],
                'source_memory':addr,'source_load_step':glyph['step'],
                'line_buffer_address':buffer_address,'line_buffer_write_step':w[0],
                'copy_steps':[glyph['step'],first['step'],aload['step'],a['step'],a9load['step'],a9['step'],pair['step'],mov['step'],ab['step'],load['step'],store['step']]}
    entry=next(q for q in checkpoints if q['step']==case['entry_step'])
    require(entry['state']==case['entry'],'immutable Pass44 entry CPU/flags')
    ret=at(case['return_step']);require(ret['instruction']=='RET' and ret['after']==case['output'],'immutable Pass44 actual return')
    prefix=[];origins=[]
    for i,value in enumerate(case['prefix']):
        address=0x20c6+i
        write=next(q for q in steps.values()if case['entry_step']<=q['step']<=case['return_step']and ['W',address,value]in q['accesses'])
        load=at(write['step']-1);require(load['instruction']=='LDA 20C1H','fresh digit context for prefix')
        context=read_link(load,0x20c1)
        normalized=at(context[0]);require(normalized['instruction']=='STA 20C1H','normalized context owner')
        before=[at(j)for j in range(normalized['step']-20,normalized['step'])]
        bufload=next(q for q in before if q['instruction']=='MOV A,M' and any(k=='R'and 0x1e8e<=a<0x1f06 for k,a,v in q['accesses']))
        raw=at(bufload['step']+2);require(raw['instruction']=='STA 20C1H' and raw['before']['a']==value,'raw reader to context')
        normpair=at(bufload['step']+6);require(normpair['instruction']=='LHLD 20C1H','fresh context pair before normalization')
        require(read_link(normpair,0x20c1)[0]==raw['step'],'normalizer consumes that raw context')
        require(normalized['before']['a']==value,'actual digit survives canonical normalization')
        origin=file_origin(bufload['accesses'][0][1],bufload['step']);origins.append(origin)
        prefix.append({'address':address,'value':value,'writer_step':write['step'],'source_buffer_read_step':bufload['step'],
                       'context_writes':[raw['step'],normalized['step']]})
    offsets=[q['source_offset']for q in origins]
    require(offsets==[91,92] and source[91:93]==b'15','second textual occurrence proven')
    line_start=source.rfind(b'\n',0,91)+1
    spelling={'normalized_byte_span':[91,93],'line':source[:91].count(b'\n')+1,'column':91-line_start+1,
              'line_text':source[line_start:source.find(b'\r',91)].decode('ascii'),'origins':origins}
    constructor=next(q for q in checkpoints if q['image']=='PLI1.OVL'and q['offset']==0x6708 and q['step']>case['return_step'])
    frame=next(q for q in checkpoints if q['image']=='PLI1.OVL'and q['offset']==0x6726 and q['step']>constructor['step'])
    ram=(directory/frame['ram']).read_bytes();pointer=ram[0xa9de]|ram[0xa9df]<<8
    record=ram[0xa9db]|ram[0xa9dc]<<8
    require(ram[0xa9e0:0xa9e2]==bytes([2,2]),'actual count/E02 arguments')
    comparisons=[];retained=[]
    for i,value in enumerate(case['prefix']):
        match=next(q for q in steps.values()if case['return_step']<q['step']<constructor['step']and q['instruction']=='CMP M'and ['R',pointer+i,value]in q['accesses'])
        lhs=at(match['step']-1)
        require(lhs['instruction']=='LDAX D' and ['R',0x20c6+i,value]in lhs['accesses'],'prefix-to-retained-record comparison')
        require(read_link(lhs,0x20c6+i)[0]==prefix[i]['writer_step'] and match['after']['flags']['zero'],'actual fresh comparison succeeds')
        old=read_link(match,pointer+i)
        require(old[2]=='CPU' and old[0]<case['entry_step'],'retained digit record predates selected acquisition')
        copied=at(old[0]);require(copied['instruction']=='MOV M,A' and copied['offset']==0x44d9,'original retained payload producer')
        original_load=at(copied['step']-1);require(original_load['instruction']=='LDAX D','retained payload copied from prefix')
        original_prefix=read_link(original_load,0x20c6+i)
        # The original record's source owner is separately tied to the loop bound.
        old_context_load=at(original_prefix[0]-1)
        require(old_context_load['instruction']=='LDA 20C1H','retained prefix consumed its current context')
        old_normal=at(read_link(old_context_load,0x20c1)[0])
        earlier_read=next(q for q in [at(j)for j in range(old_normal['step']-20,old_normal['step'])]
                          if q['instruction']=='MOV A,M' and ['R',0x1e9e+i,value]in q['accesses'])
        old_raw=at(earlier_read['step']+2)
        if old_raw['instruction']=='STA 20C1H':
            require(old_raw['before']['a']==value,'retained digit raw context ownership')
            require(read_link(at(earlier_read['step']+6),0x20c1)[0]==old_raw['step'],'retained digit normalizer read ownership')
        else:
            # First source occurrence enters the direct +12D9 reader/normalizer,
            # rather than the later +141D raw-context publication route.
            require(old_raw['instruction']=='MOV C,A' and old_raw['after']['c']==value,'direct reader result passed to normalizer')
            require(at(earlier_read['step']+3)['instruction']=='CALL 0917H','direct normalizer CALL')
            scratch=at(earlier_read['step']+5)
            require(scratch['instruction']=='MOV M,C' and scratch['accesses']==[['W',0x208f,value]],'direct normalizer scratch producer')
            require(read_link(at(earlier_read['step']+10),0x208f)[0]==scratch['step'],'direct normalizer fresh result read')
            require(old_normal['step']==earlier_read['step']+13,'direct reader/normalizer context publication')
        require(old_normal['before']['a']==value,'retained digit normalization')
        earlier=file_origin(0x1e9e+i,earlier_read['step'])
        require(earlier['source_offset']==69+i,'retained bytes originate at earlier loop-bound spelling')
        retained.append({'address':pointer+i,'writer_step':old[0],'original_prefix_writer':original_prefix[0],'source_origin':earlier})
        comparisons.append({'prefix_read_step':lhs['step'],'record_compare_step':match['step'],'record_address':pointer+i})
    require(record==0xfba8 and pointer==record+10,'actual retained record and payload pointer')
    end=next(q for q in checkpoints if q['image']=='PLI1.OVL'and q['offset']==0x2988 and q['step']>constructor['step'])
    replay=json.loads((directory/(constructor['ram']+'-replay.json')).read_text())
    require(replay['state']==end['state'],'separate concrete window full exit CPU/flags')
    require((directory/(constructor['ram']+'-replay.ram')).read_bytes()==(directory/end['ram']).read_bytes(),'separate concrete window full 64 KiB RAM')
    actual_writes=[]
    for i in range(constructor['step'],end['step']):
        actual_writes.extend([[a,v]for k,a,v in at(i)['accesses']if k=='W'])
    require(replay['writes']==actual_writes and replay['instructions']==end['step']-constructor['step'],'ordered writes and complete window coverage')
    zero=next(q for q in steps.values()if frame['step']<q['step']<end['step']and q['image']=='PLI1.OVL'and q['offset']==0x6ba3)
    require(zero['accesses']==[['W',0xa948,0],['W',0xa949,0]],'fresh zero initialization of conversion field')
    number=0;construction=[]
    for i,value in enumerate(case['prefix']):
        digit=next(q for q in steps.values()if frame['step']<q['step']<end['step']and q['image']=='PLI1.OVL'and q['offset']==0x6c40 and ['R',pointer+i,value]in q['accesses'])
        require(read_link(digit,pointer+i)[0]==retained[i]['writer_step'],'constructor consumes original retained byte without intervening write')
        number=number*10+value-0x30
        pub=next(q for q in steps.values()if q['step']>digit['step']and q['offset']==0x6c4b and q['image']=='PLI1.OVL')
        require(pub['accesses']==[['W',0xa948,number&255],['W',0xa949,number>>8]],'independent positional conversion vs concrete writes')
        construction.append({'digit_read_step':digit['step'],'payload_address':pointer+i,'byte':value,'result':number,'write_step':pub['step']})
    require(number==15,'recovered numeric payload')
    published=[]
    for offset in [0x2af4,0x2b11,0x2b13,0x2b8e,0x2b90,0x7b0f,0x7b11,0x7b2c,0x7b47,0x7b62]:
        q=next(q for q in steps.values()if end['step']<=q['step']<end['step']+400 and q['image']=='PLI1.OVL'and q['offset']==offset)
        published.append({'step':q['step'],'offset':offset,'instruction':q['instruction'],'writes':[a[1:]for a in q['accesses']if a[0]=='W']})
    # Explicit last-writer edges through caller scratch and the canonical publisher.
    # These are witness coordinates, not a semantic implementation selected by trace.
    edges=[]
    for read_step,address,writer_step in [
        (394392,0xa948,394251),(394392,0xa949,394251),
        (394398,0xa949,394251),
        (394429,0xa863,394394),(394433,0xa864,394394),
        (394449,0xa863,394439),(394449,0xa864,394441),
        (394543,0xa863,394439),(394543,0xa864,394441),
        (394562,0xae3f,394549),(394562,0xae40,394547)]:
        require(read_link(at(read_step),address)[0]==writer_step,'actual caller/publisher last-writer edge')
        edges.append({'read_step':read_step,'address':address,'writer_step':writer_step})
    for read_step,exchange_step,store_steps in [(394449,394450,[394452,394454]),(394543,394544,[394547,394549]),(394562,394563,[394565,394567])]:
        exchange=at(exchange_step)
        require(exchange['instruction']=='XCHG' and exchange['after']['d']==0 and exchange['after']['e']==number,'word reaches DE through actual XCHG')
        for step in store_steps:
            store=at(step)
            require(store['before']['d']==0 and store['before']['e']==number,'DE carrier retained before publication')
    require(at(394556)['accesses']==[['R',0xaa21,0]] and at(394564)['after']['h']==0xab and at(394564)['after']['l']==0x49,'actual mapped destination and pointer POP')
    final=next(q for q in checkpoints if q['image']=='PLI1.OVL'and q['offset']==0x2c52 and q['step']>end['step'])
    before=(directory/constructor['ram']).read_bytes();after=(directory/final['ram']).read_bytes()
    attributes={'literal_slots_before':[before[a]for a in [0xa62a,0xa62d,0xa630]],
                'literal_slots_after':[after[a]for a in [0xa62a,0xa62d,0xa630]],
                'context_slots':[before[a]for a in [0xa628,0xa62b,0xa62e]],
                'published_mapped_slots':[after[a]for a in [0xac73,0xad08,0xad9d]],
                'status':'Observed raw metadata; language meaning of the complete encoding not independently decoded'}
    require(attributes['literal_slots_before']==[2,2,0] and attributes['literal_slots_after']==[21,15,0],'actual metadata transition')
    require(attributes['published_mapped_slots']==[21,15,0],'actual downstream metadata publications')
    spelling['repository_byte_span']=[88,90]
    require(Path('examples/pli80/FIZZBUZ.PLI').read_bytes()[88:90]==b'15','repository span')
    return {'all_passed':True,'identity':identity,'source':spelling,'acquisition':{'entry_step':case['entry_step'],'return_step':case['return_step'],'prefix_writes':prefix,'accumulator':6,'width':2,'selector':2},
            'retained_record':{'address':record,'digits_pointer':pointer,'original_digit_writers':retained,'selected_prefix_comparisons':comparisons},
            'constructor':{'entry_step':constructor['step'],'return_step':end['step']-1,'caller_resume_step':end['step'],'entry_SP':constructor['state']['sp'],'exit_SP':end['state']['sp'],
                           'instructions':replay['instructions'],'ordered_writes':len(actual_writes),'entry_RAM_sha256':constructor['RAM_sha256'],'post_RAM_sha256':replay['RAM_sha256'],
                           'input_ram':constructor['ram'],'post_ram':end['ram'],'fresh_zero_step':zero['step'],'fold':construction,'value_field':{'address':0xa948,'width_bytes':2,'encoding':'little-endian integer','value':number}},
            'consumers_and_publications':published,'consumer_last_writer_edges':edges,'attributes':attributes,'typed_contract_status':'NOT COMPLETE: contextual language evidence and observed metadata are kept separate; exact literal attribute decoding remains unproved'}
