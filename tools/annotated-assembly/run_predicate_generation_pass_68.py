#!/usr/bin/env python3
"""Pass68 bounded predicate handler, fresh concrete ancestry, ACTIVE only."""
import argparse,collections,json,os,shutil,subprocess,tempfile
from pathlib import Path
from check_selector02_pass_40 import load as witness_load,coord
from run_buffered_rel_emission_pass_52 import save,digest
OUT=Path('_build/host-compiler-pass-68');REPORT=Path('research/host-compiler/pass-68')
BASE='3671495556f7be05719713303c25cca21f10b453';IMAGES='/home/john/pli/cpm/pli80/DISK1'
BOUNDS={0x3d10:0x3de4,0x3bfb:0x3c08,0x3660:0x3675,0x3790:0x37cb,0x047d:0x0493,0x059e:0x05b4,0x7c22:0x7c33,0x7cb4:0x7cc5,0x7c0e:0x7c22,0x7ca0:0x7cb4,0x7b02:0x7b1b,0x78e9:0x7903,0x7897:0x78e9,0x785c:0x7897,0x77cc:0x785c,0x8342:0x834d}
EXTRAS=['pass68','pass67']
def load(p):return json.loads(Path(p).read_text())
LAWS={
0x3d10:('Predicate-directed stack-carried generation handler','DCX SP; PUSH H creates three mutable bytes. Canonical 3BFB, RAR consumes actual A.bit0; clear arm requiring 1FB5 is unsupported. Canonical 3660 result bit0 selects local-byte acquisition via 04FF or local-word acquisition via 3790. Local byte is published at frameSP; nonzero composes C7/E=local byte 7E05, zero composes C=A8/E7 7B1B, then freshly mapped AD0C word feeds 7CB4. Local word is published low/high at frameSP+1/+2; actual repeated 3BFB result selects C4/DE=fresh local word 8072 then fresh AD0C low 7C22. Changed-second-predicate arms remain unsupported. INX SP; POP H consumes overwritten local word or retained pushed-high/stale adjacent byte; RET original continuation, finalSP=entrySP+2. Canonical child domains, immutable mapped state, supported listing/type/index/alias routes only.'),
0x047d:('Mapped A609 byte acquisition','Save C at ABF8; independently paired-read ABF8, zero-extend low selector; fresh AAB0[selector] becomes zeroextended BC; fresh A609[index] becomes A. Exact DAD CY and preserved NZPA, HL=A609+index. Already UNDERSTOOD in prior archaeology; no new byte promotion.'),
0x059e:('Mapped A9E7 byte acquisition','Save C at AC06; independently paired-read AC06, zero-extend selector; fresh AAB0[selector] -> zeroextended BC; fresh A9E7[index] -> A. HL=target, DAD carry0, NZPA preserved.'),
0x3bfb:('Fresh mapped equality-five mask','Fresh paired AD0C, C=L, canonical 047D; SUI5/SUI1/SBB A returns FF exactly when mapped A=5, otherwise0. Exact subtraction flags and child register result retained.'),
0x3660:('AD08 bit gate or mapped-less-than-eight mask','Fresh AD08 RAR exposes old bit0; set returns literal1 with RAR flags. Clear: fresh paired AD0B, C=L, canonical059E; SUI8/SBB A returns FF iff mapped byte<8, otherwise0, exact arithmetic flags.'),
0x3790:('Mapped word acquisition with bounded nonnegative byte route','Save C AD4F; paired reread C ->059E; CPI8. >=8: fresh AD4F, DCR A,C=A, canonical052C word. <8: fresh AD4F,DCR,C ->04FF, publish A at AD4F; RLC/RAR bit7 gate; supported clear route fresh paired AD4F,H0. Negative shared-tail839B route is static unsupported.'),
0x7c22:('Fresh mapped-word adapter to tag22 structure emission','Save C AE1B; paired reread ->052C; BC=actual HL; canonical7C0E; RET.'),
0x7cb4:('Fresh mapped-word adapter to tag32 structure emission','Save C AE27; paired reread ->052C; BC=actual HL; canonical7CA0; synthetic-only supported route.'),
0x7c0e:('Saved word, tag22, structure emission composition','Save B at AE1A then C at AE19; C22 ->7B02; fresh paired AE19 ->BC ->785C; RET.'),
0x7ca0:('Saved word, tag32, structure emission composition','Save B at AE26 then C at AE25; C32 ->7B02; fresh paired AE25 ->BC ->785C; RET. Synthetic-only supported route.'),
0x7b02:('Saved selector prefix adapter','Save C AE0B; paired reread ->78E9; fresh AE0B CPI E9; supported nonE9 RET. E9/7413 arm remains unsupported.'),
0x78e9:('Three independently reread selector operations','Save C ADFF; independent paired reread before7897,746F,7557, each C=low saved selector. Children reused; actual return state retained.'),
0x7897:('Bounded fresh selector scan, supported no-match route','Save C ADFD; fresh ADAA RAR bit0 clear returns. Set initializes ADFE=0; compare A7 against fresh index; scan0..7: paired ADFE zeroextended plus94B9, fresh ADFD CMP fresh pointed byte; mismatch INR fresh ADFE and loop until index8. Matched selector arms remain unsupported, immutable table data excludes them for literal22/32.'),
0x785c:('Saved position and structure emission, listing-clear scope','Save B ADFA then C ADF9; fresh ADEF word ->ADFB low/high; fresh ADF9 ->BC ->77CC; fresh201D RAR bit0 clear RET. Listing-set arm remains unsupported.'),
0x77cc:('Structure word sum and type-selected canonical emission','Save B ADF4 then C ADF3; fresh ADF3 pointer ->AC9F low/high; target+2 ->ADF5; fresh AC9F+3 ->ADF6; fresh AC9F+6 and ADEF ->8342, sum ->ADF7 low/high. Repeated fresh ADF6 ANI1F/CPI comparisons:9 ->765E,11H unsupported pointer generator,8 ->7630,10H unsupported pointer generator,other ->765E. Fresh ADF7 ->BC. Finally HL0 ->ADEF low/high. Nonwrapping nonalias eight-byte structure scope.'),
0x8342:('Fresh pointed-word addition','MOV C,M; INX H; MOV B,M; LDAX D; ADD C; L=A; INX D; LDAX D; ADC B; H=A; RET. Low/high reads independently ordered, HL=u16(firstWord+secondWord), BC=firstWord, DE=originalDE+1; actual final ADC flags.')}

def discovery():
 OUT.mkdir(parents=True,exist_ok=True);REPORT.mkdir(parents=True,exist_ok=True);dest=OUT/'capture';dest.mkdir(exist_ok=True)
 if not os.environ.get('RUNES_HOST_IMAGES'):subprocess.run(['dune','build','bin/predicate_generation_capture.exe'],check=True)
 subprocess.run(['_build/default/bin/predicate_generation_capture.exe','--toolchain',IMAGES,'--output-dir',str(dest)],check=True)
 rows={};inventory={};stacks={};paths={}
 for source in ['MINIMAL','FIZZBUZ','PICTURE','FACTOR','OPTIMIST']:
  counts=load(dest/(source+'-capture-summary.json'));inventory[source]=dict(roots=counts['roots'],global_calls=counts['global_calls'],REL_sha256=counts['REL_sha256'],prior_software_dispatch=counts.get('prior_software_dispatch',[]));rows[source]={f'PLI2.OVL+{o:04X}':[]for o in BOUNDS};stacks[source]=[];paths[source]=[]
  for file in sorted(dest.glob(source+'-*-witnesses.json')):
   events=witness_load(file)['events'];ws=[e['witness']for e in events if e['type']=='instruction'];by={w['step_index']:w for w in ws};calls={w['step_index']:w for w in ws if w['control']['kind']=='call'and w['control']['taken']};matched={e['frame']['call_step']:dict(ret=by[e['step_index']],relation=e)for e in events if e['type']=='hardware_frame_return'and e['step_index']in by}
   assert ws[0]['origin']['offset']==0x3e0d and ws[-1]['origin']['offset']==0x3de3
   for n,call in calls.items():
    key=coord(call.get('target_origin'))
    if key not in rows[source]:continue
    ret=matched[n]['ret'];body=[w for w in ws if n<w['step_index']<=ret['step_index']];own=[];skip=-1
    for w in body:
     if w['step_index']<=skip:continue
     own.append(w)
     if w['control']['kind']=='call'and w['control']['taken']:skip=matched[w['step_index']]['ret']['step_index']
    rows[source][key].append(dict(call=call,entry=body[0],ret=ret,own_witnesses=own,nested_returns={w['step_index']:matched[w['step_index']]for w in own if w['control']['kind']=='call'and w['control']['taken']}))
   root=rows[source]['PLI2.OVL+3D10'][-1];sp=root['entry']['sp_before'];mem={};history=[]
   for w in ws:
    for v in w['reads']:
     if sp-512<=v['address']<=sp+1 and v['address']in mem:assert mem[v['address']]==v['value']
    for v in w['writes']:
     if sp-512<=v['address']<=sp+1:
      mem[v['address']]=v['new_value'];history.append(dict(step=w['step_index'],writer=coord(w['origin']),address=v['address'],value=v['new_value']))
   assert root['ret']['after']['sp']==sp+2 and root['ret']['after']['pc']==ws[0]['pc']+3
   own=root['own_witnesses'];pop=next(w for w in own if w['disassembly']=='POP H');stores=[w for w in own if w['origin']['offset']in[0x3d7b,0x3d7d]]
   assert [q['address']for q in pop['reads']]==[sp-2,sp-1]
   assert pop['after']['l']==stores[0]['writes'][0]['new_value'] and pop['after']['h']==stores[1]['writes'][0]['new_value']
   stacks[source].append(dict(entry_SP=sp,original_CALL=ws[0],PUSH_H=own[1],local_stores=stores,POP_H=pop,RET=root['ret'],last_writers={str(a):next(h for h in reversed(history)if h['address']==a)for a in mem},journal_sha256=digest(history)))
   children=[dict(callsite=w['origin']['offset'],target=coord(w['target_origin']),input=w['after'],output=matched[w['step_index']]['ret']['after'])for w in own if w['control']['kind']=='call']
   paths[source].append(dict(children=children,own_offsets=[w['origin']['offset']for w in own],branches=[dict(offset=w['origin']['offset'],control=w['control'],before=w['before'],after=w['after'])for w in own if w['control']['kind']in['jump','return']],entry=root['entry']['before'],output=root['ret']['after']))
 save(OUT/'rows.json',rows);save(OUT/'annotation-rows-PLI2.OVL.json',rows);save(REPORT/'natural-inventory.json',inventory);save(REPORT/'stack-proof.json',stacks);save(REPORT/'natural-paths.json',paths)

def prove(images=IMAGES,focused=False):
 OUT.mkdir(parents=True,exist_ok=True)
 if not (OUT/'rows.json').exists():discovery()
 if not os.environ.get('RUNES_HOST_IMAGES'):subprocess.run(['dune','build','bin/native_predicate_generation.exe'],check=True)
 dest=OUT/'proof';dest.mkdir(exist_ok=True)
 for source in ['primary','FACTOR','OPTIMIST']:
  with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
   target=Path(tmp)/'result';cmd=['_build/default/bin/native_predicate_generation.exe','--toolchain',images,'--output-dir',str(target)]
   if source!='primary':cmd+=['--cross-source',source,'--family-only']
   elif focused:cmd+=['--family-only']
   print('START Pass68 proof '+source,flush=True);subprocess.run(cmd,check=True)
   for p in target.glob('*.json'):shutil.copyfile(p,dest/((''if source=='primary'else source+'-')+p.name))
   print('DONE Pass68 proof '+source,flush=True)

def contracts():
 rows=load(OUT/'rows.json');natural={o:set()for o in BOUNDS};synthetic=set()
 for source,g in rows.items():
  for o in BOUNDS:natural[o].update(w['origin']['offset']for r in g[f'PLI2.OVL+{o:04X}']for w in r['own_witnesses'])
 for c in load(OUT/'proof/synthetic-checkpoints.json')['cases']:
  if c['route'].startswith('3D10_'):synthetic.update(q['pc']-0x2200 for q in c['checkpoints'])
 text=f'let c=open_in_bin "{IMAGES}/PLI2.OVL";;let b=Bytes.create(in_channel_length c);;really_input c b 0(Bytes.length b);;close_in c;;\nlet rec loop o last=if o<last then match I8080.Decode.decode b ~offset:o with Error _->failwith"decode"|Ok d->Printf.printf"%04X %s %s\\n"o(String.concat""(List.init d.length(fun i->Printf.sprintf"%02X"(Char.code(Bytes.get b(o+i))))))(I8080.Instr_format.format d.instr);loop(o+d.length)last;;\n'+''.join(f'loop {o} {end};;\n'for o,end in sorted(BOUNDS.items()))
 (OUT/'all-decode.ml').write_text(text);out=subprocess.check_output(['ocaml','-I','_build/default/lib/i8080/.i8080.objs/byte','_build/default/lib/i8080/i8080.cma',str(OUT/'all-decode.ml')],text=True);cfg=[];static={}
 for line in out.splitlines():
  off,b,d=line.split(' ',2);o=int(off,16);owner=next(a for a,end in BOUNDS.items()if a<=o<end);kind='call'if d.startswith('CALL')else'jump'if d.startswith('J')else'return'if d=='RET'else'ordinary';control=dict(kind=kind);target=None
  if kind in ['call','jump']:control['target']=int.from_bytes(bytes.fromhex(b)[1:],'little')
  if kind=='call':target=dict(image=dict(name='PLI.COM'if control['target']<0x2200 else'PLI2.OVL'),offset=control['target']-(0x100 if control['target']<0x2200 else 0x2200))
  evidence='OBSERVED'if o in natural[owner]else'DEDUCED STATIC UNOBSERVED'if o in synthetic else'STATIC UNOBSERVED unsupported'
  cfg.append(dict(owner=f'PLI2.OVL+{owner:04X}',offset=o,bytes=b,decoded=d,control=control,evidence=evidence))
  if o in synthetic and o not in natural[owner]:static.setdefault(f'PLI2.OVL+{owner:04X}',[]).append(dict(origin=dict(image=dict(name='PLI2.OVL'),offset=o),target_origin=target,bytes=b,disassembly=d,control=control,evidence_class='DEDUCED STATIC UNOBSERVED concrete CPU discriminant'))
 pairs=load(OUT/'proof/synthetic-helper-pairs.json');matches={}
 for q in pairs:matches.setdefault(q['coordinate'],q)
 save(OUT/'annotation-static-matches-PLI2.OVL.json',matches)
 save(REPORT/'cfg.json',cfg);save(OUT/'annotation-static-PLI2.OVL.json',static)
 partial={0x3d10,0x3790,0x7b02,0x7897,0x785c,0x77cc}
 save(REPORT/'contract-laws-PLI2.OVL.json',{f'PLI2.OVL+{o:04X}':dict(end=BOUNDS[o],description=desc,contract=law,completeness=['stable','partial'if o in partial else'complete','partial'if o in partial else'complete'])for o,(desc,law)in LAWS.items()})

def annotations():
 subprocess.run(['python3','tools/annotated-assembly/update_buffered_rel_annotations_pass_52.py',IMAGES,'PLI2.OVL'],env={**os.environ,'RUNES_ANNOTATION_PASS':'68','RUNES_ANNOTATION_BASE':BASE},check=True)
 subprocess.run(['python3','tools/annotated-assembly/update_predicate_generation_annotations_pass_68.py'],check=True)
 subprocess.run(['python3','tools/annotated-assembly/verify.py','--images',IMAGES,'--write-progress'],check=True)
 subprocess.run(['python3','tools/annotated-assembly/minimal_dynamic_progress.py','--output','research/minimal-baseline/dynamic-progress.json'],check=True)

def validate():
 dest=OUT/'active-validation';tmp=OUT/'tmp';tmp.mkdir(exist_ok=True)
 r=subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--profile','active','--extra-categories',','.join(EXTRAS),'--images',IMAGES,'--output',str(dest),'--workers','4'],env={**os.environ,'TMPDIR':str(tmp.resolve())})
 receipt=load(dest/'results.json');receipt.update(historical_bytes=94720,dune_stanzas=39,reruns=[],historical_full_executed=False,full_trigger_fired=False);save(REPORT/'validation.json',receipt)
 if r.returncode:raise RuntimeError('ACTIVE failed')

def reports():
 cfg=load(REPORT/'cfg.json');inventory=load(REPORT/'natural-inventory.json');proof=OUT/'proof';components=load(proof/'component-shadows.json');hybrid=load(proof/'cumulative-hybrid-summary.json');synthetic=load(proof/'synthetic-checkpoints.json');paths=load(REPORT/'natural-paths.json')
 old=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/manifest.json']));new=load('research/annotated-assembly/manifest.json');old_image=next(x for x in old['images']if x['name']=='PLI2.OVL');new_image=next(x for x in new['images']if x['name']=='PLI2.OVL')
 oldstatus={a:s['status']for s in old_image['sections']for a in range(s['start_offset'],s['end_offset'])};newstatus={a:s['status']for s in new_image['sections']for a in range(s['start_offset'],s['end_offset'])};transitions=collections.Counter();kind=collections.Counter();rootkind=collections.Counter();helperkind=collections.Counter()
 for w in cfg:
  for a in range(w['offset'],w['offset']+len(bytes.fromhex(w['bytes']))):
   if oldstatus[a]!='UNDERSTOOD'and newstatus[a]=='UNDERSTOOD':
    transitions[oldstatus[a]+' -> UNDERSTOOD']+=1;cls='OBSERVED'if w['evidence']=='OBSERVED'else'DEDUCED STATIC UNOBSERVED';kind[cls]+=1;(rootkind if w['owner']=='PLI2.OVL+3D10'else helperkind)[cls]+=1
 full=load(OUT/'full-selection.txt');cert=load('research/host-compiler/pass-67/validation-full.json');assert set(cert['categories'])<=set(full['selected_categories'])and len(full['selected_categories'])==99
 save(REPORT/'historical-full-selection.json',dict(category_count=99,certified_Pass67_subset=True,executed=False,additional=['pass68']))
 raw=load('_build/host-compiler-pass-51/residual-map.json');parent67=load('research/host-compiler/pass-67/ownership-map.json');rows=load(OUT/'rows.json');topology={}
 names=['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in[0x8072,0x7ed6,0x82dd,0x829c,0x7338,0x742a,0x8258,0x82b5,0x7e05,0x7b1b,0x7b99,0x7ae4,0x8248,0x7701,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619,0x7434,0x7630,0x765e]]
 inside=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
 for source,v in raw.items():
  ws=v['windows'];allpre=v['roots']+[r for r in ws if r['target']in names]+[dict(call=r['entry_step']-1,ret=r['return_step'],target='PLI2.OVL+6EA5',caller='PLI2.OVL+20B3')for r in parent67[source]];pre=[r for r in allpre if not any(q is not r and inside(r,q)for q in allpre)]
  outer=[dict(call=r['call']['step_index'],ret=r['ret']['step_index'],target='PLI2.OVL+3D10',caller=coord(r['call']['origin']))for r in rows[source]['PLI2.OVL+3D10']];absorbed=[r for r in pre if any(inside(r,q)for q in outer)];post=[r for r in pre if r not in absorbed]+outer
  coords=['PLI.COM+119E']+[f'PLI2.OVL+{x:04X}'for x in [0x3d10,0x04ff,0x7b1b,0x7b99,0x7d47,0x7e05,0x8072,0x3bfb,0x3660,0x3790,0x7c22,0x7cb4,0x83dc,0x397f,0x18b3]]
  topology[source]=dict(new_roots=len(outer),native_roots_before=len(pre),native_roots_after=len(post),absorbed=dict(collections.Counter(r['target']for r in absorbed)),net_delta=len(outer)-len(absorbed),remaining_external={k:dict(calls=len(rs:=[r for r in ws if r['target']==k and not any(q is not r and inside(r,q)for q in post)and r not in post]),callers=dict(collections.Counter(r['caller']for r in rs)))for k in coords})
 save(REPORT/'topology-summary.json',topology)
 summary=dict(root='PLI2.OVL+3D10',extent=[0x3d10,0x3de4],natural_counts={s:d['roots']for s,d in inventory.items()},promotions=dict(transitions),promotions_evidence=dict(kind),root_own_promotions=dict(rootkind),helper_promotions=dict(helperkind),unchanged_understood_047D_bytes=22,component_shadows=components,root_shadows=2,cross_root_shadows=1,synthetic_CPU_proofs=len([c for c in synthetic['cases']if c['route'].startswith('3D10_')]),oracle_queries=0,historical_bytes=94720,FULL_trigger_fired=False,historical_full_executed=False,current_certified_FULL='Pass67',next_ordinary_FULL='approximately Pass72',hierarchy=topology)
 save(REPORT/'shadow-summary.json',summary)
 extraction=dict(historical_root='PLI2.OVL+3D10',semantic_inputs=['Fresh mapped selectors and predicate bytes AD08/AD0B/AD0C/AD0D/AD0E','Supported generation relation/output state'],semantic_outputs=['Predicate-selected canonical generation/emission and exact historical state publications'],shared_historical_state=['AAB0 mapped indices; A609/A9E7/A7F8/A795 mapped channels','AD4F; ADF3..ADFF; AE19..AE1B; AE25..AE27; AC9F; ADEF','Canonical carrier/output state and original continuation'],historical_mechanism=['DCX SP/PUSH H creates three mutable bytes, not preserved HL','Local word overwrites pushed high byte and DCX slot; POP H consumes transformed bytes','Independent LHLD rereads; equality and less-than masks; actual child-return RAR gates','Explicit fresh index0..7 scan and separate canonical emission helpers'],candidate_modern_operation='Predicate-directed generation using mapped state and a stack-carried intermediate',confidence=dict(instruction_law='OBSERVED and DEDUCED within explicit bounded contract',candidate_modern_operation='HYPOTHESIS',excluded_gateway='STATIC UNOBSERVED unsupported'),mir_relevance='Documentation only; separates the bounded state transformation from 8080 realization. No API or compiler-level interpretation is established.')
 save(REPORT/'semantic-extraction.json',extraction)
 ranking=[dict(rank=1,candidate='branch-owned caller context around 3DE4 / CALL site3E0D',reason='Small immediate composition converging on 3D10; discover real software-entry/continuation and predicates before selecting a root. 3DE4 has zero hardware CALLs and is not promoted here.'),dict(rank=2,candidate='PLI2.OVL+397F',reason='Independent genuine CALL context in FIZZBUZ and OPTIMIST; prefer bounded predicate/child convergence before migration.'),dict(rank=3,candidate='PLI2.OVL+18B3',reason='One natural call per source but large traversal with unrelated descendants; separate substantial problem.')]
 save(REPORT/'next-boundaries.json',ranking)
 packet=dict(task='RUNES_PLI2_PREDICATE_GENERATION_HANDLER_3D10_PASS_68',baseline=BASE,root=dict(entry='PLI2.OVL+3D10',extent=[0x3d10,0x3de4],counts=summary['natural_counts'],caller='PLI2.OVL+3E0D',routes=['OBSERVED mapped nonnegative local word / C4 8072 / tag22 structure emission','DEDUCED mapped local byte zero / A8-E7 7B1B / tag32 emission','DEDUCED mapped local byte nonzero / C7 7E05 / tag32 emission']),laws=LAWS,proof=dict(natural_primary=2,cross_OPTIMIST=1,synthetic_CPU=summary['synthetic_CPU_proofs'],comparison=['all registers/flags/SP/PC','ordered logical/compatibility writes','all64KiB RAM','stack last writers and child CALL chronology','DMA/filesystem/services/records/console/BDOS chronology']),promotions={k:v for k,v in summary.items()if 'promotion'in k},topology=topology,hybrids=hybrid,next_boundaries=ranking,oracle_queries=0,unsupported=['1FB5 gateway','changed second3BFB bit','3790 negative shared tail839B','7897 matched selector','785C listing-set','77CC types11H/10H','7B02 E9/7413'],validation=dict(tier='ACTIVE/INCREMENTAL',extras=EXTRAS,last_certified_FULL='Pass67',historical_full_executed=False))
 save(REPORT/'implementation-packet.json',packet);assert (REPORT/'implementation-packet.json').stat().st_size<32768
 lines=['# Pass68 — predicate-directed generation handler','',f'Baseline `{BASE}`. Canonical `PLI2.OVL+3D10 [3D10,3DE4)` has a bounded partial contract. All primary and cross-source natural roots close; the independent gateway arm remains unsupported.','', 'Fresh natural counts MINIMAL/FIZZBUZ/PICTURE/FACTOR/OPTIMIST: 0/1/1/0/1. Every root is hardware-called at +3E0D and returns at +3DE3. No overlapping hardware CALL target appears inside the root. MINIMAL and FACTOR have no natural coverage. All three roots take 3BFB / 3660 / 3790 / 3BFB / 8072 / 7C22; actual predicate A results are FF/00/FF. The natural local word is 0001 (FIZZBUZ), 0007 (PICTURE), 0001 (OPTIMIST); consult machine evidence for the authoritative returned channels.','', '3BFB freshly maps low AD0C through AAB0 then A609 and builds equality5 with SUI5/SUI1/SBB A. 3660 uses fresh AD08.bit0, otherwise maps low AD0B through AAB0/A9E7 and constructs less-than8 with SUI8/SBB A. RAR consumes each actual child return, preserving NZPA and exposing old A.bit0; predicates are never recomputed from memory.','', '3790 saves its selector and maps A9E7. Below8 it decrements the saved selector, acquires the mapped low byte through canonical04FF and zero-extends a nonnegative byte; at least8 it acquires a full word through canonical052C. Negative extension839B remains unsupported. Word input comes from fresh AD0D; C4/DE are built from fresh stack-local bytes before canonical8072. Fresh AD0C then drives 7C22.','', 'DCX SP and PUSH H create frameSP=entrySP−3. PUSH writes initial H at entrySP−2 and initial L at entrySP−3. Word stores overwrite entrySP−2 with low and entrySP−1 with high. Exit INX SP/POP H consumes those transformed bytes; it does not restore original HL. The original CALL slot remains untouched, finalSP=entrySP+2. Synthetic byte paths overwrite frameSP instead, and their POP consumes pushed-high/stale adjacent storage. [Stack proof](stack-proof.json) retains exact writes, reads, CALL continuations and last writers.','', 'The synthetic mapped-byte arm acquires fresh AD0E through canonical04FF, publishes its actual A at frameSP and consumes a second3BFB result. Zero selects literal C=A8/E7 canonical7B1B; nonzero supplies C7/E=local byte to canonical7E05. Fresh AD0C feeds tag32 adapter7CB4. The excluded changed-second-predicate arms statically contain 83DC and other emission sequences, but are neither migrated nor promoted. 83DC has separate natural callers; no contract is claimed here.','', 'Required compact descendants: 047D,059E,3BFB,3660,3790,7C22,7CB4,7C0E,7CA0,7B02,78E9,7897,785C,77CC,8342. 047D was already UNDERSTOOD; its bytes are not new knowledge. The tag22/tag32 wrappers independently save/reread word carriers, emit via 78E9 (7897 / canonical746F / canonical7557), then785C. The explicit selector scan publishes ADFE and freshly reads every index0..7, terminating at8; literal22/32 do not match the immutable table. No fixed natural iteration count selects behavior.','', '77CC publishes fresh pointer to AC9F, reads pointer+2/+3 into ADF5/ADF6, freshly rereads AC9F+6 and adds that pointed word to fresh ADEF through8342. The low/high ADD/ADC chronology is retained. Fresh type comparisons select canonical765E for9/default or7630 for8. Types11H/10H pointer generators remain unsupported. 785C requires fresh201D.bit0 clear; listing-set stays RAW. The complete transaction is staged, including code, continuation, stack/scratch/sentinel/pointer guards and all later child domains; unsupported state causes no live effects.','', f'Independent natural component/root shadows and {summary["synthetic_CPU_proofs"]} concrete-CPU synthetic proofs passed: carry differences, mapped byte0/1/7/127, independent word low/high (0000/0102/0201/7F7F/FFFF), structure types8/9/default and negative code/continuation/alias scopes. Comparisons include all registers/flags, ordered writes, complete RAM and surviving stack residue; whole-run hybrids include full service/record/filesystem/console chronology. Exhaustive instruction journals remain under ignored `_build`.','', 'Knowledge accounting: '+json.dumps(dict(transitions))+'; evidence '+json.dumps(dict(kind))+'; root-own '+json.dumps(dict(rootkind))+'; helper '+json.dumps(dict(helperkind))+'. Unsupported +1FB5 and neighboring +3DE4 bytes were not promoted. [CFG](cfg.json) distinguishes OBSERVED from DEDUCED STATIC UNOBSERVED and unsupported static decode.','', 'Whole-run measured results:']
 for s in hybrid['sources']:
  r=s['result'];lines.append(f'- {r["source"]}: guest {s["pre_guest_instructions"]} -> {r["actual_guest_instructions"]}, removed {s["guest_instructions_removed"]}; host {sum(s["pre_transition_vector"])} -> {r["host_transitions"]}. REL `{r["REL_sha256"]}`.')
 lines+=['','Hierarchy: '+json.dumps(topology)+'. New helpers are internal algorithms, not additional Runner roots. Equal helpers elsewhere remain enabled at their existing boundaries.','', 'Historical correction: none. Implementation correction: new corruption-test coordinates were corrected during focused development; no prior native algorithm changed. Archaeology extension: bounded predicate/stack/structure emission contracts. Pragmatic divergence: none within supported domains. Fidelity debt: explicit unsupported gateway, negative-extension, selector-match, listing and pointer-generator arms; higher compiler meaning remains hypothesis.','', 'Semantic extraction separates the supported state operation from masks, mapped tables, stack carriers and exact child chronology. It defines no MIR/API. [Semantic extraction](semantic-extraction.json). Packet '+str((REPORT/'implementation-packet.json').stat().st_size)+' bytes; zero historical oracle queries.','', 'ACTIVE extras: pass68 plus pass67. Pass67 is selected because this diff extends the existing low-offset mapped PLI2 bridge identity/bounds family and its stack proof selection; it verifies the established software/mapped handler remains intact. Other canonical child implementations are untouched and independently shadowed locally, so their archived campaigns are not accumulated. Metadata/catalog/annotations and progress were finalized before aggregate validation.','', 'Pass67 remains the current certified FULL epoch. Next ordinary FULL approximately Pass72. No FULL trigger fired; historical-full was not executed. List-only selection preserves all98 certified categories plus pass68 =99.','', 'Recommended Pass69: discover the branch-owned caller context above3D10/+3E0D; do not invent a hardware root at3DE4. 397F follows as an independent bounded candidate; 18B3 remains a separate large traversal. +3E36 and +1FB5 are not widened into. [Ranking](next-boundaries.json).','', 'Driver phases: discovery (five fresh concrete captures), proof (primary/cross components, synthetic CPU, standalone/cumulative hybrids), contracts/CFG, annotations/global metadata, reports/packet, ACTIVE validation. Exact reconstruction94720 bytes; no runtime/CPU/CPM/common transaction or capture-interpretation changes. User-owned `scripts/view-optimist.sh` is untouched.']
 if (REPORT/'validation.json').exists():
  v=load(REPORT/'validation.json');lines+=['',f'ACTIVE: {v["category_count"]} categories, {v["python_test_count"]} Python tests,39 Dune stanzas,{v["safe_parallel_workers"]} workers; wall {v["wall_seconds"]} s, summed {v["sum_category_seconds"]} s. all_passed={v["all_passed"]}; reruns={v["reruns"]}. Receipt tier ACTIVE/INCREMENTAL, current FULL reference Pass67.']
 (REPORT/'README.md').write_text('\n'.join(lines)+'\n')

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['discovery','proof','contracts','annotations','reports','validate']);p.add_argument('--images',default=IMAGES);p.add_argument('--focused',action='store_true');args=p.parse_args()
 if args.phase=='proof':prove(args.images,args.focused)
 else:globals()[args.phase]()
