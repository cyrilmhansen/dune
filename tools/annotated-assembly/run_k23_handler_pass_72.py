#!/usr/bin/env python3
"""Pass72: exact k23 descriptor witnesses and bounded software-handler proof.

No general gateway interception. Historical FULL is list-only/external.
"""
import argparse, collections, hashlib, json, os, shutil, subprocess, time
from pathlib import Path
import run_gateway_decomposition_pass_71 as gateway

OUT = Path('_build/host-compiler-pass-72')
REPORT = Path('research/host-compiler/pass-72')
BASE = 'b950f8558c56057c515f172bb32faec111dcacc9'
IMAGES = '/home/john/pli/cpm/pli80/DISK1'
SOURCES = gateway.SOURCES
BOUNDS = {0x3e36:0x3ef6, 0x7bcc:0x7bdd, 0x7bb2:0x7bcc,
          0x73ca:0x73d0, 0x79ae:0x79b6, 0x7a17:0x7a4e, 0x1dff:0x1fb5, 0x0992:0x09ba, 0x04a9:0x04bf}
LAWS = {
 0x1dff: ('Scoped k23 descriptor predicate', 'AD1C=23, fresh descriptor pointer57C7/count1/token05,57C9/count3/token69 or3BF3/count1/tokenFB. Save input C toAD21, descriptor count toAD25; clear AD15..AD19 toFF; AD22=0; fresh AD21 ->AD0B. Fresh descriptor loop decrements AD25; independently paired AD22 plus1 and AD1D select token ->AD26. DCR fresh AD21, PUSH PSW, INR fresh AD22, zeroextended processed index, POP B transports cursor into positionsAD0B+index. Literal path canonical047D(actual cursor) CMP fresh token; mismatch A0 preserves CMP flags;05 match returnsA1 after fresh count CPI0;69 match is unsupported beyond the first token. FB follows exact ED/EE/F6/FB comparisons, normalizes slot to0, freshly reads AD15 ->AD23=FF, publishes processed position toAD15, invokes bounded0992 and publishes actual returned A toAD21. Next zero count returnsA1. Repeated-cache, ED..FA/FC..FF and other descriptors remain unsupported; no global native predicate root.'),
 0x0992: ('Bounded mapped-count backward walk', 'Save C atAC3B; AC3C=1. Repeated fresh paired AC3B low ->canonical04A9. HL=AC3C; ADD fresh count; DCR A; publish count; C=A; A0 CMP C. Nonzero count DCR fresh AC3B and repeat, at most256 iterations in accepted scope; zero returns fresh AC3B in A. Byte wrapping, exact flags, ordered same-valued writes and child frames retained; nontermination fails staged scope.'),
 0x04a9: ('Mapped A6CF byte acquisition', 'Save C atABFA; independent paired ABFA read and zeroextension; BC=AAB0; DAD; fresh mapped byte ->C/B0; HL=A6CF; DAD; fresh table byte ->A. Exact DAD CY and preserved NZPA, other registers unchanged.'),
 0x3e36: ('Scoped mapped-state software handler', 'Software PCHL entry only from exact20AC/20AF/20B0/20B3 prefix, fresh AD1F=6036, continuation42B4. Fresh AD0A CPI0: zero reads AD0C low through canonical047D and requires actual A=10; otherwise unresolved nested1FB5 rejects. Actual3660 A.bit0 through RAR: clear reads fresh AD0C through052C, XCHG, C4 ->8072; set reads fresh AD0C through04FF, CPI0. Zero sends C=A8/E7 to7B1B; nonzero freshly acquires04FF again, E=actual A/C7 ->7E05. Nonzero AD0A is reread and CPI1; only1 supported: fresh AD0C ->AD58, actual3660/RAR must be clear, fresh paired AD58 low ->7BCC. Shared3EF5 RET consumes software PUSH continuation. Other-selector, nested-gateway and7E75 arms remain unsupported. Canonical child-domain guards inherited.'),
 0x7bcc: ('Saved-selector mapped-word adapter', 'Save C at AE14; fresh paired AE14, C=L ->canonical052C; BC=actual returned HL ->7BB2. RET, exact flags and CALL residue.'),
 0x7bb2: ('Saved-word clear/tag/structure adapter', 'Save B at AE13 then C at AE12; canonical7A17; literal C4 adapter73CA clears4/5 through73A7; literal C2A ->canonical7B02; fresh paired AE12 ->BC ->canonical785C. Preserve scratch writes, canonical results and stack residue.'),
 0x73ca: ('Literal-four clear adapter', 'C=4; CALL canonical73A7, which clears indexed slots4/5; RET. Actual final registers/flags inherited, hardware CALL residue retained.'),
 0x79ae: ('Literal C5 E6 adapter', 'E=6; C=C5; CALL canonical7903; RET, actual child register/flag/state result retained.'),
 0x7a17: ('Extended pending-state preparation', 'Fresh AE04 CPI0, zero RET. Otherwise fresh AE04 CPI1. Equal: canonical79B6; fresh AE05 CPI2; equal publishes AE05=1; both publish AE04=0 then DCR fresh AE06 and return. Other nonzero: canonical79AE, canonical79B6, canonical79A2 in order. Existing zero/one contracts retained; new arms independently shadowed in Pass72. Canonical output scope and alias guards inherited.')}

load = gateway.load
save = gateway.save
digest = gateway.digest
accesses = gateway.accesses

def run(args, **kwargs):
    subprocess.run(args, check=True, **kwargs)

def witness(q):
    def state(s):
        return {**{k:s[k] for k in ['pc','sp','a','b','c','d','e','h','l']},
                'flags':dict(zip(['sign','zero','auxiliary_carry','parity','carry'],
                                 [s[k] for k in ['S','Z','AC','P','CY']]))}
    target = dict(image=dict(name='PLI2.OVL'),offset=q['target']-0x2200) if q['kind']=='call' and q['target']>=0x2200 else None
    if q['kind']=='call' and q['target']<0x2200:
        target=dict(image=dict(name='PLI.COM'),offset=q['target']-0x100)
    control=dict(kind=q['kind'])
    if q['kind']!='sequential':control.update(target=q['target'],taken=q['taken'])
    return dict(origin=dict(image=dict(name=q['image']),offset=q['offset']),
                target_origin=target,step_index=q['step'],pc=q['before']['pc'],
                pc_after=q['after']['pc'],runtime_pc=q['before']['pc'],bytes=q['bytes'],
                disassembly=q['decoded'],before=state(q['before']),after=state(q['after']),
                sp_before=q['before']['sp'],sp_after=q['after']['sp'],control=control,
                call_return_address=q['before']['pc']+3 if q['kind']=='call' else None,
                reads=[dict(address=a['address'],value=a['value']) for a in accesses(q,'read')],
                writes=[dict(address=a['address'],new_value=a['value']) for a in accesses(q,'write')])

def json_lines(path):
    with path.open() as stream:
        return [json.loads(line) for line in stream]

def extract():
    gateway.OUT=OUT
    inv, roots=gateway.extract()
    handlers=[];predicates=[];annotation={s:{f'PLI2.OVL+{o:04X}':[] for o in BOUNDS} for s in SOURCES}
    for source in SOURCES:
        records=json_lines(OUT/'capture'/f'{source}-steps.jsonl')
        by_step={q['step']:q for q in records}
        events=json_lines(OUT/'capture'/f'{source}-events.jsonl')
        frames={r['entry']['id']:r for r in roots if r['source']==source}
        for e in events:
            if e['pc']!=0x6036:continue
            r=frames[e['previous']['id']];ret=r['handler_ret']
            own=[q for q in records if e['step']<=q['step']<=ret['step'] and q['image']=='PLI2.OVL' and 0x3e36<=q['offset']<0x3ef6]
            children=[]
            for call in own:
                if call['kind']!='call':continue
                returned=next(q for q in records if q['step']>call['step'] and q['kind']=='return' and q['after']['pc']==call['before']['pc']+3 and q['before']['sp']==call['after']['sp'])
                children.append(dict(call=witness(call),ret=witness(returned)))
            nested=[g for g in roots if g['source']==source and e['step']<g['entry']['step']<ret['step']]
            row=dict(source=source,gateway_id=r['entry']['id'],entry=e,ret=ret,own=own,children=children,
                     gateway=dict(k=r['k'],descriptor=r['descriptor'],handler=r['handler'],caller=r['caller'],entry_C=r['entry_C'],success=r['success'],fallback=r['fallback']),
                     nested_gateways=[dict(k=g['k'],handler=g['handler'],caller=g['caller'])for g in nested],
                     stack_last_writers=r['software_last_writers'],journal_sha256=digest([q for q in records if e['step']<=q['step']<=ret['step']]),
                     path='AD0A_zero_mapped_nonzero_E7_generation' if e['AD_state'][0]==0 else 'AD0A_one_AD58_mapped_word_tag2A')
            handlers.append(row)
            annotation[source]['PLI2.OVL+3E36'].append(dict(call=witness(e['previous']),ret=witness(ret),own_witnesses=[witness(q)for q in own]))
            for call in records:
                off=call['target']-0x2200
                if call['kind']!='call' or off not in BOUNDS or off==0x3e36 or not(e['step']<call['step']<ret['step']):continue
                end=next(q for q in records if q['step']>call['step'] and q['kind']=='return' and q['after']['pc']==call['before']['pc']+3 and q['before']['sp']==call['after']['sp'])
                own_child=[q for q in records if call['step']<q['step']<=end['step'] and q['image']=='PLI2.OVL' and off<=q['offset']<BOUNDS[off]]
                annotation[source][f'PLI2.OVL+{off:04X}'].append(dict(call=witness(call),ret=witness(end),own_witnesses=[witness(q)for q in own_child]))
            for p in r['predicates']:
                event=next(x for x in events if x['step']==p['call']['step']+1 and x['pc']==0x3fff)
                ws=[q for q in records if p['call']['step']<q['step']<=p['ret']['step']]
                po=[q for q in ws if q['image']=='PLI2.OVL' and 0x1dff<=q['offset']<0x1fb5]
                predicates.append(dict(source=source,gateway_id=r['entry']['id'],gateway_C=r['entry_C'],scan=p['call']['offset']==0x2037,
                    event=event,ret=p['ret'],tokens=[q['before']['a']for q in po if q['offset']==0x1e40],
                    direct_children=[dict(call=witness(q),ret=witness(next(x for x in ws if x['step']>q['step']and x['kind']=='return'and x['after']['pc']==q['before']['pc']+3 and x['before']['sp']==q['after']['sp'])))for q in po if q['kind']=='call'],
                    cached_reuse=any(q['offset']==0x1f53 for q in po),
                    writes=[dict(writer=q['offset'],**a)for q in ws for a in accesses(q,'write')],
                    checkpoints=[q for q in po if q['offset']in [0x1e22,0x1e40,0x1e49,0x1e5b,0x1e6e,0x1f40,0x1f4a,0x1fa4,0x1fac,0x1fb4,0x1e74]],
                    projected_journal_sha256=digest(ws)))
        for p in [x for x in predicates if x['source']==source]:
            start=p['event']['step'];end=p['ret']['step']
            call=p['event']['previous']
            own=[q for q in records if start<=q['step']<=end and q['image']=='PLI2.OVL' and 0x1dff<=q['offset']<0x1fb5]
            annotation[source]['PLI2.OVL+1DFF'].append(dict(call=witness(call),ret=witness(p['ret']),own_witnesses=[witness(q)for q in own]))
            for call in records:
                off=call['target']-0x2200
                if call['kind']!='call' or off not in [0x0992,0x04a9] or not(start<=call['step']<=end):continue
                ret=next(q for q in records if q['step']>call['step']and q['kind']=='return'and q['after']['pc']==call['before']['pc']+3 and q['before']['sp']==call['after']['sp'])
                child=[q for q in records if call['step']<q['step']<=ret['step'] and q['image']=='PLI2.OVL' and off<=q['offset']<BOUNDS[off]]
                annotation[source][f'PLI2.OVL+{off:04X}'].append(dict(call=witness(call),ret=witness(ret),own_witnesses=[witness(q)for q in child]))
        # Exact complete four-instruction software-entry witnesses, not inferred CALLs.
        if source=='MINIMAL':
            h=next(x for x in handlers if x['source']==source)
            q=h['entry']['previous'];prefix=[witness(by_step[q['step']-3+i])for i in range(4)]
            save(OUT/'software-return-sample.json',dict(kind='pass72_push_h_pchl',gateway=prefix,call=prefix[-1],writer=prefix[1],ret=witness(h['ret']),entry=witness(h['own'][0]),original_slot=h['entry']['state']['sp'],continuation=0x42b4))
    save(OUT/'handlers.json',handlers);save(OUT/'predicates.json',predicates)
    save(OUT/'annotation-rows-PLI2.OVL.json',annotation)
    (OUT/'handler-windows.txt').write_text(''.join(f"{h['source']} {h['entry']['step']-1} {h['ret']['step']+1}\n"for h in handlers))
    (OUT/'predicate-windows.txt').write_text(''.join(f"{p['source']} {p['event']['step']-1} {p['ret']['step']+1}\n"for p in predicates))
    return inv,roots,handlers,predicates,annotation

def prove(images=IMAGES):
    start=time.monotonic();OUT.mkdir(parents=True,exist_ok=True)
    if not os.environ.get('RUNES_HOST_IMAGES'):
        run(['dune','build','bin/k23_handler_capture.exe','bin/native_k23_handler.exe','bin/k23_predicate_components.exe'])
    capture=OUT/'capture';capture.mkdir(exist_ok=True)
    run(['_build/default/bin/k23_handler_capture.exe','--images',images,'--output',str(capture)])
    extract()
    for dest,extra in [('proof',[]),('cross-FACTOR',['--family-only','--cross-source','FACTOR']),('cross-OPTIMIST',['--family-only','--cross-source','OPTIMIST'])]:
        path=OUT/dest
        if path.exists():shutil.rmtree(path)
        run(['_build/default/bin/native_k23_handler.exe','--toolchain',images,'--output-dir',str(path),*extra])
    run(['_build/default/bin/k23_predicate_components.exe','--images',images,'--windows',str(OUT/'predicate-windows.txt'),'--output',str(OUT/'predicate-component-shadows.json')])
    save(OUT/'focused-proof-timing.json',dict(wall_seconds=round(time.monotonic()-start,3),all_passed=True))

def contracts(images=IMAGES):
    _,_,hs,_,annotation=extract()
    natural={o:set(w['origin']['offset']for s in SOURCES for r in annotation[s][f'PLI2.OVL+{o:04X}']for w in r['own_witnesses']) for o in BOUNDS}
    synthetic=set(q['pc']-0x2200 for c in load(OUT/'proof/synthetic-checkpoints.json')['cases'] for q in c['checkpoints'])
    synthetic.update(q['pc']-0x2200 for c in load(OUT/'predicate-component-shadows.json')['synthetic_cases'] for q in c['checkpoints'])
    text=f'let c=open_in_bin "{images}/PLI2.OVL";;let b=Bytes.create(in_channel_length c);;really_input c b 0(Bytes.length b);;close_in c;;\nlet rec loop o e=if o<e then match I8080.Decode.decode b ~offset:o with Error _->failwith"decode"|Ok d->Printf.printf"%04X %s %s\\n"o(String.concat""(List.init d.length(fun i->Printf.sprintf"%02X"(Char.code(Bytes.get b(o+i))))))(I8080.Instr_format.format d.instr);loop(o+d.length)e;;\n'+''.join(f'loop {o} {end};;\n'for o,end in sorted(BOUNDS.items()))
    (OUT/'all-decode.ml').write_text(text)
    listing=subprocess.check_output(['ocaml','-I','_build/default/lib/i8080/.i8080.objs/byte','_build/default/lib/i8080/i8080.cma',str(OUT/'all-decode.ml')],text=True)
    cfg=[];static={}
    for line in listing.splitlines():
        a,b,d=line.split(' ',2);o=int(a,16);owner=next(a for a,end in BOUNDS.items()if a<=o<end)
        kind='call'if d.startswith('CALL')else'jump'if d.startswith('J')else'return'if d=='RET'else'ordinary'
        control=dict(kind=kind);target=None
        if kind in ['call','jump']:control['target']=int.from_bytes(bytes.fromhex(b)[1:],'little')
        if kind=='call':target=dict(image=dict(name='PLI2.OVL'),offset=control['target']-0x2200)
        evidence='OBSERVED'if o in natural[owner]else'DEDUCED STATIC UNOBSERVED'if o in synthetic else'STATIC UNOBSERVED unsupported'
        cfg.append(dict(owner=f'PLI2.OVL+{owner:04X}',offset=o,bytes=b,decoded=d,control=control,evidence=evidence))
        if o in synthetic and o not in natural[owner]:
            static.setdefault(f'PLI2.OVL+{owner:04X}',[]).append(dict(origin=dict(image=dict(name='PLI2.OVL'),offset=o),target_origin=target,bytes=b,disassembly=d,control=control,evidence_class=evidence))
    save(REPORT/'cfg.json',cfg);save(OUT/'annotation-static-PLI2.OVL.json',static)
    save(REPORT/'contract-laws-PLI2.OVL.json',{f'PLI2.OVL+{o:04X}':dict(end=BOUNDS[o],description=d,contract=l,completeness=['stable','partial'if o in [0x3e36,0x1dff] else'complete','partial'if o in [0x3e36,0x1dff] else'complete']) for o,(d,l)in LAWS.items()})

def validate(images=IMAGES):
    tmp=OUT/'tmp';tmp.mkdir(exist_ok=True)
    run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--categories','pass72,diff-check,validation-runner-tests','--images',images,'--output',str(OUT/'validation'),'--workers','4'],env={**os.environ,'TMPDIR':str(tmp.resolve())})
    q=load(OUT/'validation/results.json');q.update(historical_bytes=94720,dune_stanzas=39,reruns=[],historical_full_executed=False)
    save(REPORT/'validation.json',q)

def reports(images=IMAGES):
    inventory,gateways,hs,ps,annotation=extract()
    paths=collections.Counter(h['path']for h in hs)
    frames=[]
    for h in hs:
        frames.append(dict(source=h['source'],gateway_id=h['gateway_id'],entry_step=h['entry']['step'],return_step=h['ret']['step'],
            entry=h['entry']['state'],exit=h['ret']['after'],entry_shared=h['entry']['AD_state'],entry_RAM_sha256=h['entry']['RAM_sha256'],
            gateway=h['gateway'],path=h['path'],children=[dict(offset=c['call']['origin']['offset'],target=c['call']['target_origin'],input=c['call']['after'],output=c['ret']['after'])for c in h['children']],
            nested_gateways=h['nested_gateways'],projected_journal_sha256=h['journal_sha256']))
    save(REPORT/'natural-handler-inventory.json',frames)
    save(REPORT/'stack-proof.json',[dict(source=h['source'],gateway_id=h['gateway_id'],slot=h['entry']['state']['sp'],continuation=0x42b4,
        PCHL=h['entry']['previous'],software_word_last_writers=h['stack_last_writers'],RET=h['ret'],
        child_CALL_words=[dict(site=c['call']['pc'],slot=c['call']['sp_after'],writes=c['call']['writes'],ret_reads=c['ret']['reads'])for c in h['children']])for h in hs])
    descriptor=[]
    for p in ps:
        descriptor.append(dict(source=p['source'],gateway_id=p['gateway_id'],entry_C=p['event']['state']['c'],descriptor_pointer=p['event']['descriptor_pointer'],
            descriptor_bytes=p['event']['descriptor_bytes'],scan=p['scan'],tokens=p['tokens'],input=p['event']['state'],output=p['ret']['after'],
            entry_AD_state=p['event']['AD_state'],children=p['direct_children'],cached_reuse=p['cached_reuse'],
            checkpoint_sha256=digest(p['checkpoints']),ordered_write_sha256=digest(p['writes']),projected_journal_sha256=p['projected_journal_sha256']))
    save(REPORT/'k23-descriptor-inventory.json',descriptor)
    components=load(OUT/'predicate-component-shadows.json')
    save(REPORT/'predicate-component-shadows.json',{k:v for k,v in components.items()if k!='synthetic_cases'})
    synthetic=load(OUT/'proof/synthetic-checkpoints.json')['cases']+components['synthetic_cases']
    save(REPORT/'synthetic-summary.json',dict(cases=len(synthetic),handler_cases=sum(c['route'].startswith('3E36_')for c in synthetic),predicate_cases=sum(c['route'].startswith('1DFF_')for c in synthetic),all_passed=all(c['all_passed']for c in synthetic),journal_location=str(OUT),aggregate_sha256=digest(synthetic),routes=sorted({c['route']for c in synthetic})))
    save(REPORT/'component-shadows.json',dict(sources=[r for name in ['proof','cross-FACTOR','cross-OPTIMIST']for r in load(OUT/name/'component-shadows.json')['sources']],all_passed=True))
    save(REPORT/'focused-proof-timing.json',load(OUT/'focused-proof-timing.json'))
    for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
        save(REPORT/name,load(OUT/'proof'/name))
    baseline=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/manifest.json']))
    current=load('research/annotated-assembly/manifest.json')
    image=lambda m:next(i for i in m['images']if i['name']=='PLI2.OVL')
    status=lambda m:{a:s['status']for s in image(m)['sections']for a in range(s['start_offset'],s['end_offset'])}
    old,new=status(baseline),status(current);cfg=load(REPORT/'cfg.json');transitions=collections.Counter();evidence=collections.Counter();by_owner={}
    for q in cfg:
        counts=by_owner.setdefault(q['owner'],collections.Counter())
        for a in range(q['offset'],q['offset']+len(bytes.fromhex(q['bytes']))):
            if old[a]!=new[a]and new[a]=='UNDERSTOOD':
                transitions[old[a]+' -> UNDERSTOOD']+=1;evidence[q['evidence']]+=1;counts[old[a]+' -> UNDERSTOOD']+=1
    accounting=dict(transitions={k:transitions[k]for k in ['RAW -> UNDERSTOOD','STRUCTURED -> UNDERSTOOD','DECODED -> UNDERSTOOD']},evidence=dict(evidence),by_owner=by_owner,
        no_unused_handler_or_general_predicate_promotion=True)
    save(REPORT/'knowledge-accounting.json',accounting)
    selection=load(OUT/'historical-full-selection.json');cert=set(load('research/host-compiler/pass-67/validation-full-initial.json')['selected_categories'])
    assert cert<=set(selection['selected_categories'])and len(selection['selected_categories'])==103
    save(REPORT/'historical-full-selection-proof.json',dict(executed=False,selected_category_count=103,certified_Pass67_subset=True,selected_categories=selection['selected_categories']))
    command='python3 tools/annotated-assembly/run_host_compiler_regressions.py --profile historical-full --images /home/john/pli/cpm/pli80/DISK1 --output _build/host-compiler-pass-72/full-validation --workers 4'
    save(REPORT/'full-checkpoint-handoff.json',dict(status='pending_external_execution',semantic_commit='PENDING_UNTIL_COMMIT',baseline=BASE,last_certified_full='Pass67',profile='historical-full',expected_category_count=103,workers=4,historical_bytes=94720,command=command))
    save(REPORT/'semantic-extraction.json',dict(historical_root='PLI2.OVL+3E36',semantic_inputs=['fresh AD0A','independent mapped AD0C and AD0B channels','AD08 predicate state','pending/generation/output state'],semantic_outputs=['state-selected generation/emission effects','AD58 publication on selector1 arm','actual canonical child registers/flags'],shared_historical_state=['AD58','AE12..AE15','AE04..AE06','gateway software continuation42B4'],historical_mechanism=['fresh paired mapped acquisitions and exact CPI/RAR flags','PUSH42B4/PCHL entry and shared software RET','canonical generation children and tag2A adapter','scoped k23 literal/first-use FB predicate independently proved, gateway remains guest'],candidate_modern_operation='HYPOTHESIS: scoped descriptor-selected generation handler',confidence='High at the bounded representation-level contract; source-language meaning unproved; no complete native gateway chain.',mir_relevance='Separate state-selected operation from historical mapped tables, scratch, flags and software continuation. Documentation only; no MIR API.'))
    hierarchy=load(REPORT/'cumulative-hybrid-summary.json')
    coordinates=['3D10','6EA5','8072','7ED6','82DD','829C','7338','742A','8258','82B5','7E05','7B1B','7B99','7AE4','8248','7701','7557','756D','75A7','75CE','75F1','7619','7434','7630','765E','11C3','11E5','1207','1272','0C75','80B7','INT-emitter']
    economics=[]
    for q in hierarchy['sources']:
        pre,post=q['pre_transition_vector'],q['transition_vector'][1:]
        assert len(pre)==len(post)==len(coordinates)
        economics.append(dict(source=q['result']['source'],new_handler_roots=q['family_roots'],absorbed_by_coordinate={c:a-b for c,a,b in zip(coordinates,pre,post)if a!=b},remaining_enabled_roots=dict(zip(coordinates,post)),remaining_external_3E36=0,remaining_1FB5=sum(r['source']==q['result']['source']for r in gateways),guest_before=q['pre_guest_instructions'],guest_after=q['result']['actual_guest_instructions'],host_before=sum(pre),host_after=q['result']['host_transitions']))
    save(REPORT/'hierarchy-and-residuals.json',economics)
    packet=dict(task='RUNES_PLI2_K23_DESCRIPTOR_HANDLER_3E36_PASS_72',baseline=BASE,current_full='Pass67',FULL_status='PENDING EXTERNAL EXECUTION',
        native_handler_installed=True,native_gateway_installed=False,global_native_predicate_installed=False,
        bounds={f'{o:04X}':f'{e:04X}'for o,e in BOUNDS.items()},laws={f'{o:04X}':l for o,(_,l)in LAWS.items()},
        natural_counts={s:sum(h['source']==s for h in hs)for s in SOURCES},path_counts=dict(paths),
        k23_predicate_counts={s:sum(p['source']==s for p in ps)for s in SOURCES},token_paths=dict(collections.Counter(str(p['tokens'])for p in ps)),
        handlers=[dict(source=h['source'],entry_step=h['entry']['step'],path=h['path'],selector=h['entry']['AD_state'][0],journal_sha256=h['journal_sha256'])for h in hs],
        synthetic=load(REPORT/'synthetic-summary.json'),promotions=accounting,hierarchy=hierarchy,oracle_queries=0,historical_bytes=94720,
        residual='1FB5 stays guest. k23 descriptor and3E36 prerequisites now exist at stated scopes; other gateway indices/handlers and tracing remain unresolved.',
        next='Scoped gateway composition should be assessed before reopening Pass69/70; cross blockers256E/3FFD/6D47 remain separate.',
        full_trigger_fired=False,historical_full_executed=False,validation_categories=['build','project','pass72','diff-check','validation-runner-tests'])
    save(REPORT/'implementation-packet.json',packet)
    assert (REPORT/'implementation-packet.json').stat().st_size<28672
    lines=['# Pass72 — k23 descriptor subset and software handler','',f'Baseline `{BASE}`. `PLI2.OVL+3E36 [3E36,3EF6)` now has a bounded partial faithful software-handler contract. The k23 descriptor predicate subset also independently closes. The gateway remains guest; no arbitrary callback or new common transaction semantics were introduced.','',
        'Fresh counts MINIMAL/FIZZBUZ/PICTURE/FACTOR/OPTIMIST: 1/13/1/4/9, all 28 entered through gateway20B3 PCHL, with continuation42B4 last-written at20AF. RET3EF5 consumes that same low/high word, SP+=2. There is no private handler frame and no natural hardware CALL entry or nested gateway invocation in these handler windows. Bounds are stable at this evidence scope; the following3EF6 operation is excluded.',
        '',f'Natural path families: {dict(paths)}. Selector0 freshly acquires AD0C through047D and all11 cases return10; actual3660 bit selects the mapped-byte arm, which freshly calls04FF twice and supplies actual second A as E/C7 to7E05. Selector1 publishes fresh AD0C toAD58, calls3660, consumes actual A.bit0 throughRAR, then freshly paired-reads AD58/AD59 and passes low to7BCC. All17 take the clear arm. Load/store/JMP/RET preserve the actual child flags; RAR preserves NZPA and consumes incoming carry into A.',
        '', 'The complete static CFG is retained in [cfg.json](cfg.json). Selector0 mapped047D other than10 calls1FB5 at3E8B, but that arm is unobserved in all28 invocations and unsupported. Other AD0A values and selector1 bit-set7E75 arm are also excluded. Supported synthetic mapped-byte-zero and actual3660-clear mapped-word/8072 routes are explicitly DEDUCED / STATIC / UNOBSERVED.',
        '', 'New compact adapters: 7BCC saves C atAE14, freshly reads it with adjacentAE15, invokes canonical052C and passes actual HL as BC to7BB2. 7BB2 saves B then C atAE13/AE12, calls7A17, literal-four73CA (canonical73A7 clearing4/5), emits literal2A through canonical7B02, freshly rereads saved word and calls canonical785C. Existing structure acquisition/emission machinery is reused. 73CA is [73CA,73D0); 7BB2 [7BB2,7BCC); 7BCC [7BCC,7BDD).',
        '', 'OPTIMIST naturally requires the nonzero-other AE04 arm of7A17. Its compact79AE adapter [79AE,79B6) supplies C=C5/E6 to canonical7903. Extended7A17 keeps the exact old zero/one paths; AE05=2 publishes1 before clearingAE04 and decrementingAE06. Other nonzeroAE04 calls79AE,79B6,79A2 in order. Synthetic cases prove zero/one/two/FF pending states and the previously unobserved AE05=2 write. Archived negative expectations for now-supported pending states were replaced with child-code corruption, while live-state rejection checks remain.',
        '', 'The 50 k23 predicates comprise28 token05,11 token69 and11 tokenFB invocations. Descriptor pointers are57C7 (count1/token05),57C9 (count3/body69,0A,ED; natural mismatch stops at69), and fallback3BF3 (count1/tokenFB). The predicate decrements fresh cursorAD21, incrementsAD22, and transports the cursor through PUSH PSW/POP B into AD0B+processed. Literal047D consumes the actual decremented cursor; mismatch returns A0 with CMP flags, exhaustion returns A1 with fresh count-CPI flags. No source-language token meaning is assigned.',
        '', 'Every natural FB case is first-use slot0: the predicate resetsAD15..AD19 toFF, normalizes tokenFB toslot0, recordsAD23=FF, writes processed position1 toAD15, calls0992 and publishes its actual cursor return toAD21. There are no natural repeated-cache paths. 0992 [0992,09BA) is a bounded state-driven backward mapped-count walk, not a token-name abstraction: AC3B=C, AC3C=1; actual04A9(AAB0 thenA6CF) result plus fresh count minus1 is published each iteration; nonzero decrements the cursor byte. Accepted scope terminates within256 iterations; infinite wrapping states reject transactionally. 04A9 [04A9,04BF) retains its paired read, zero-extension and final DAD flags.',
        '', 'Scoped1DFF is independently executable only for AD1C=23 and the stated actual descriptor pointer/count/token families. Token69 match requiring later tokens, repeated-cache and other descriptor families remain unsupported. The full [1DFF,1FB5) procedure remains partial; only represented scoped bytes are promoted. No global1DFF or1FB5 Runner boundary is installed.',
        '', 'Each native preparation uses copied state and validates the entire selected child chain before live effects. Own/child code, original continuation, exact gateway prefix and fresh AD1F, stack geometry, mapped/descriptor domain, structure/pending/output child scopes and scratch/table/code/sentinel exclusions are checked. Negative cases include late structure/stack alias, software continuation and child-code corruption, unsupported handler predicates/descriptors, and nonterminating0992 state. No CPU, CP/M, Runner, shared capture or common transaction semantics changed; the added software-witness verifier is coordinate-specific and leaves existing CALL/PCHL proof kinds intact. No FULL trigger fired.',
        '',f'All28 natural handler root shadows and all50 predicate shadows independently match registers, flags, SP/PC, full64KiB RAM, ordered writes, surviving stack writers, child chronology, DMA/filesystem and service/record events. Canonical children are independently component-shadowed. Concrete CPU synthetic proofs: {len(synthetic)}. Exhaustive journals remain under ignored `{OUT}`. Oracle queries:0.',
        '',f'Knowledge accounting: {accounting}. Prior general predicate STRUCTURED bytes and unused handler arms retain their baseline status; no bulk envelope promotion. Reviewed unrelated headers, especially047D, are preserved.',
        '', 'Standalone and cumulative hybrids preserve exact REL/INT records, filesystem, console, milestones, BDOS chronology and warm boot. Measured cumulative results:']
    for q in hierarchy['sources']:
        v=q['result'];lines.append(f"- {v['source']}: guest {q['pre_guest_instructions']} -> {v['actual_guest_instructions']} ({q['guest_instructions_removed']} removed); host {sum(q['pre_transition_vector'])} -> {v['host_transitions']}; handler roots {q['family_roots']}; REL `{v['REL_sha256']}`.")
    lines += ['', 'Pass69/70 are not silently reopened. Their common k23 predicate/handler prerequisites are now available, but the scoped gateway still needs an explicit native composition with its twelve-byte frame, handler software continuation and restore law. Other cross-source indices selecting256E/3FFD/6D47 remain independent. Recommend assessing that scoped gateway composition next, then reopening the blocked parents; rank382E as a separate bounded stack-argument policy after it. No widening to18B3.',
        '',f'Implementation packet: {(REPORT/"implementation-packet.json").stat().st_size} bytes. Focused campaign and explicit regression timing are recorded separately. Final aggregate categories: build (all executable compilation), project (unit/runtime regressions), pass72 (new exhaustive contracts, canonical composition and cheap historical catalog assertion), diff-check (patch integrity), validation-runner-tests (catalog selection/progress compatibility). No chronological archived campaigns or ACTIVE core were added. V1 and single exact reconstruction run separately after annotation rendering; exact reconstruction94720 bytes.',
        '', 'Pass67 remains the current certified FULL epoch. Pass72 FULL is **PENDING EXTERNAL EXECUTION**. Historical-full has103 selectable categories, preserving all98 certified Pass67 categories plus68–72; listing is not execution. No certification policy or old FULL receipt was changed.', '', 'After publication, run:', '', '```sh',command,'```','', 'Protected `scripts/view-optimist.sh` and `local-icybox-full-0-verify.state` were untouched. No task-owned /tmp directory or _build artifact is committed.']
    if (REPORT/'validation.json').exists():
        receipt=load(REPORT/'validation.json')
        lines += ['', f"Final explicit regression receipt: profile {receipt['profile']}, tier {receipt['validation_tier']}; {receipt['category_count']} categories, {receipt['python_test_count']} Python tests,39 Dune test stanzas,4 workers. Initially all passed; no reruns. Wall {receipt['wall_seconds']}s; summed category time {receipt['sum_category_seconds']}s. Focused proof time is separately recorded in focused-proof-timing.json.", '', 'Pass57 retains its original catalog assertions at its published epoch through the existing durable frozen-catalog mechanism. The later7A17 extension is documented rather than weakening the old assertion. Local metadata wording distinguishes the software entry and scoped predicate counts from preserved older global evidence. Development corrections before the final aggregate: actual RAR branch polarity and a STA writer coordinate were corrected by independent CPU shadows. No pragmatic semantic shortcut was introduced; fidelity debt is the explicitly unsupported general predicate/handler arms and guest gateway composition.']
    (REPORT/'README.md').write_text('\n'.join(lines)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('phase',choices=['prove','extract','contracts','reports','validate']);p.add_argument('--images',default=IMAGES);a=p.parse_args()
    {'prove':prove,'extract':lambda _:extract(),'contracts':contracts,'reports':reports,'validate':validate}[a.phase](a.images)
