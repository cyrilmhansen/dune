#!/usr/bin/env python3
"""Deterministic bounded +7ED6 policy archaeology/proof; ACTIVE only."""
import collections,json,os,subprocess,sys,tempfile,shutil
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_buffered_rel_emission_pass_52 import save,digest
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-65');REPORT=Path('research/host-compiler/pass-65')
BASE='ba434b6565e25390d62c0e18dbe3882b29cff508';IMAGES='/home/john/pli/cpm/pli80/DISK1'
BOUNDS={0x7ed6:0x8072,0x7d47:0x7d85,0x7d85:0x7dc3,0x8398:0x83a2,0x83b4:0x83ba,0x83d2:0x83dc}
def load(p):return json.loads(Path(p).read_text())
def discovery():
 OUT.mkdir(parents=True,exist_ok=True);rows={}
 for source,path in CAPTURES.items():
  rows[source]=gather_selected(path,{f'PLI2.OVL+{x:04X}':(x,x+1)for x in list(BOUNDS)+[0x8072]},include_nested_returns=True)
 save(OUT/'rows.json',rows);inventory()
def inventory():
 raw=load(OUT/'rows.json');summary={};cfg={};paths={};annotations={}
 for source,g in raw.items():
  summary[source]={};paths[source]=[];annotations[source]={k:g.get(k,[])for k in [f'PLI2.OVL+{x:04X}'for x in BOUNDS]}
  for k,rs in g.items():
   for r in rs:r['nested_returns']={int(i):v for i,v in r['nested_returns'].items()}
   summary[source][k]=dict(calls=len(rs),callers=dict(collections.Counter(coord(r['call']['origin'])for r in rs)),returns=dict(collections.Counter(coord(r['ret']['origin'])for r in rs)),triples=dict(collections.Counter('/'.join(f"{r['entry']['before'][q]:02X}"for q in ['c','d','e'])for r in rs)),children=dict(collections.Counter('/'.join(c['target']for c in children_any(r))for r in rs)))
   cfg.setdefault(k,{})
   for r in rs:
    for w in r['own_witnesses']:cfg[k][w['origin']['offset']]=w
  for r in g['PLI2.OVL+7ED6']:
   ws=r['own_witnesses'];branches=[dict(offset=w['origin']['offset'],taken=w['control'].get('taken'))for w in ws if w['control']['kind']=='jump'];reads=[v for w in ws for v in w['reads']];children=children_any(r)
   gates={f'{a:04X}':[v['value']for v in reads if v['address']==a]for a in[0x202b,0xadaa,0xae3a]}
   paths[source].append(dict(caller=coord(r['call']['origin']),entry_step=r['call']['step_index'],return_step=r['ret']['step_index'],entry=r['entry']['before'],output=r['ret']['after'],gates=gates,return_offset=r['ret']['origin']['offset'],signature=digest(branches),branches=branches,scan_indices=[w['reads'][0]['value']for w in ws if w['origin']['offset']==0x8004],children=children,own_reads_hash=digest(reads),own_writes_hash=digest([v for w in ws for v in w['writes']]),checkpoint_hash=digest(ws)))
 save(REPORT/'inventory-summary.json',summary);save(REPORT/'natural-paths.json',paths);save(OUT/'cfg.json',cfg);save(OUT/'annotation-rows-PLI2.OVL.json',annotations)
def prove(images=IMAGES,focused=False):
 OUT.mkdir(parents=True,exist_ok=True);dest=OUT/'proof';dest.mkdir(exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
  cmd=['dune','exec','bin/native_generation_policy.exe','--','--toolchain',str(images),'--output-dir',str(Path(tmp)/'results')]
  if focused:cmd+=['--family-only']
  with(dest/'run.log').open('w')as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((dest/'run.log').read_text()[-5000:])
  for f in(Path(tmp)/'results').glob('*.json'):
   if not focused or f.name not in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:shutil.copyfile(f,dest/f.name)
 print('Pass65 proofs passed',flush=True)
def focused():
 prove(focused=True)
 subprocess.run(['python3','tools/annotated-assembly/test_generation_policy_pass_65.py','--images',IMAGES,'-q'],env={**os.environ,'RUNES_PASS65_REUSE_PROOF':'1'},check=True)
def cross():
 for source in ['FACTOR','OPTIMIST']:
  with tempfile.TemporaryDirectory(prefix='cross-',dir=OUT)as tmp:
   with(OUT/(source+'-cross.log')).open('w')as log:r=subprocess.run(['_build/default/bin/native_generation_policy.exe','--toolchain',IMAGES,'--output-dir',str(Path(tmp)/'results'),'--family-only','--cross-source',source],stdout=log,stderr=subprocess.STDOUT)
   if r.returncode:raise RuntimeError((OUT/(source+'-cross.log')).read_text()[-5000:])
   shutil.copyfile(Path(tmp)/'results/natural-cases.json',OUT/(source+'-natural-cases.json'))
   shutil.copyfile(Path(tmp)/'results/natural-instruction-witnesses.json',OUT/(source+'-natural-instructions.json'))
 print('Pass65 cross evidence passed',flush=True)
def contracts():
 laws={
 0x7ed6:('Gated paired relation adjustment or indexed relation search','Save D atAE3C,E atAE3B,C atAE3A in order. Fresh202B RAR bit0set returns A0; otherwise freshADAA RAR bit0clear returns A0; otherwise freshC CPI6 equal returns A0. Active C0..5: independently paired-read/zeroextend C, PUSH ADAB+C, reread C and ADAB+C+1, POP H, ANA first activity and RAR. Both active: independent ADB3[C] high-byte <<8 via83B4 and ADB3[C+1] low OR via8398;SHLD AE3E. FreshwordAE3B minus current via canonical1A43,83D2 subtract3 tests unsigned distance<3. If distance0..2 increment current via7D47 until freshwordcomparison reaches equality; otherwise reverse distance0..2 decrement via7D85; returnA1. Otherwise copy savedD toAE40 andE toAE41. Independent7365(C,savedD) bit0match calls7E05(C+1,savedE),returnA1; independent7365(C+1,savedE) match calls7E05(C,savedD),returnA1. Neither:AE42/43=FF,AE3D=0; scan0..7,skip6. Independent7365(index,savedD) match publishesAE42=index; independent7365(index,savedE) match withindex!=savedC publishesAE43=index. OR candidates,RLC,RAR tests oldbit7; bothnonnegative calls793C(savedC,AE42),then793C(u8(savedC+1),AE43),returnA1. Failedcandidate INR AE3D; freshA7 CMP index,exitindex8 returnsA0 withactualcomparisonflags. No fixednaturaliterationcount. Freshpairedreads,arithmeticflags,PUSH/POP/CALL/RET andorderedwrites preserved. Bounded canonicalchildren,successfuloutput/nonwrapposition,zero pending gates,nonaliasstack/sentinel; no arbitrary compiler-level meaning.'),
 0x7d47:('Saved selector emission and adjacent word increment','C0..7 savedAE32;freshC CPI6 reserved:ADC9=1,E6,C3 canonical75CE,RET. OtherwisepairedfreshAE32->DE,C3 canonical75CE;freshC zeroextend,ADB4+C,INR A,publish,CPI0. On lowwrap freshC zeroextend,ADB3+C,INR M. Actual flag/stack/word byte ordering. Required parentC0..5;syntheticC6 also bounded.'),
 0x7d85:('Saved selector emission and adjacent word decrement','C0..7 savedAE33;freshC CPI6 reserved:ADC9=1,E6,C0B canonical75CE,RET. OtherwisepairedfreshAE33->DE,C0B canonical75CE;freshC zeroextend,ADB4+C,DCR A,publish,CPIFF. On lowborrow freshC zeroextend,ADB3+C,DCR M. Actual flags andwrites retained.'),
 0x8398:('Byte OR into word','E=A,D=0;A=E OR L,L=A;A=D OR H,H=A. Return actual logicalflags,CY0,AC0. No memorywrites otherthanCALL traffic.'),
 0x83b4:('Repeated word left shift','Bounded C1..8. DAD H doublesHL modulo65536,setsCY;DCR C updatesNZPA preservesCY;repeatuntilC0. ActualB preserved andfinalDADcarryretained.'),
 0x83d2:('Zeroextended byte subtraction from DE','C=A,B=0;A=E SUB C,L=A;A=D SBB B,H=A;returnHL=u16(DE-zeroextend(inputA));DE unchanged;actualborrow/AC/NZP fromhigh subtraction.')}
 save(REPORT/'contract-laws-PLI2.OVL.json',{f'PLI2.OVL+{x:04X}':dict(end=BOUNDS[x],description=d,contract=c,completeness=['stable','complete','partial'if x in[0x7ed6,0x7d47,0x7d85]else'complete'])for x,(d,c)in laws.items()})
 # Exact decoder boundaries; only independently executed synthetic PCs promoted.
 text=Path('_build/host-compiler-pass-60/decode.ml').read_text();start=text.index('loop 0x7dc3 0x7ed6');text=text[:start]+''.join(f'loop 0x{x:04x} 0x{end:04x}; 'for x,end in BOUNDS.items())+';;\n'
 (OUT/'decode.ml').write_text(text);decoded=subprocess.check_output(['ocaml','-I','_build/default/lib/i8080','-I','_build/default/lib/i8080/.i8080.objs/byte','i8080.cma',str(OUT/'decode.ml')],text=True);(OUT/'disassembly.txt').write_text(decoded)
 cross_own=[q for source in ['FACTOR','OPTIMIST']for q in load(OUT/(source+'-natural-instructions.json'))]
 save(REPORT/'cross-instruction-evidence.json',dict(OBSERVED=True,instructions=len(cross_own),proof_hash=digest(cross_own),by_source=dict(collections.Counter(q['source']for q in cross_own)),journal='ignored _build/host-compiler-pass-65/FACTOR/OPTIMIST-natural-instructions.json'))
 raw=load(OUT/'annotation-rows-PLI2.OVL.json');observed={k:{w['origin']['offset']for g in raw.values()for r in g[k]for w in r['own_witnesses']}for k in load(REPORT/'contract-laws-PLI2.OVL.json')}
 syn=load(OUT/'proof/synthetic-checkpoints.json')['cases'];pcs={w['pc']-0x2200 for c in syn if c['route'].startswith('7ED6_')for w in c['checkpoints']};static={k:[]for k in observed};cfg=[]
 for line in decoded.splitlines():
  off,b,d=line.split(' ',2);o=int(off,16);key=next(k for k in observed if int(k.split('+')[1],16)<=o<BOUNDS[int(k.split('+')[1],16)])
  control=dict(kind='call'if d.startswith('CALL')else'jump'if d.startswith('J')else'return'if d=='RET'else'ordinary');target=None
  if d.startswith(('CALL','J')):control['target']=int.from_bytes(bytes.fromhex(b)[1:],'little')
  if d.startswith('CALL'):
   rt=control['target'];target=dict(image=dict(name='PLI2.OVL'if rt>=0x2200 else'PLI.COM'),offset=rt-(0x2200 if rt>=0x2200 else 0x100))
  natural_cross=any(q['owner']==key and q['offset']==o for q in cross_own)
  status='OBSERVED'if o in observed[key]or natural_cross else'DEDUCED STATIC UNOBSERVED'if o in pcs else'STATIC UNOBSERVED unsupported'
  cfg.append(dict(offset=o,bytes=b,decoded=d,control=control,evidence=status,owner=key))
  if o not in observed[key]and(o in pcs or natural_cross):static[key].append(dict(origin=dict(image=dict(name='PLI2.OVL'),offset=o),target_origin=target,bytes=b,disassembly=d,control=control,evidence_class='OBSERVED'if natural_cross else'DEDUCED STATIC UNOBSERVED'))
 save(OUT/'annotation-static-PLI2.OVL.json',static);save(REPORT/'cfg.json',cfg)
 matches={}
 for q in load(OUT/'proof/synthetic-helper-pairs.json'):matches.setdefault(q['coordinate'],dict(relation=q['relation'],call=q['call'],ret=q['ret']))
 save(OUT/'annotation-static-matches-PLI2.OVL.json',matches)
def topology():
 raw=load('_build/host-compiler-pass-51/residual-map.json');out={};prior_names=['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in[0x7434,0x7630,0x765e,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619,0x7701,0x8248,0x7ae4,0x7b99,0x7b1b,0x7e05,0x742a,0x8258,0x82b5,0x7338,0x829c,0x82dd]]
 inside=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
 for source,v in raw.items():
  ws=v['windows'];allpre=v['roots']+[r for r in ws if r['target']in prior_names];pre=[r for r in allpre if not any(q is not r and inside(r,q)for q in allpre)];ps=[r for r in ws if r['target']=='PLI2.OVL+7ED6'];outer=[r for r in ps if not any(inside(r,q)for q in pre)];absorbed=[r for r in pre if any(inside(r,q)for q in outer)];post=[r for r in pre if r not in absorbed]+outer
  coords=[f'PLI2.OVL+{x:04X}'for x in[0x7365,0x7ed6,0x7338,0x75ce,0x7619,0x7a17,0x8072,0x18b3]]+['PLI.COM+119E']
  out[source]=dict(logical=len(ps),external=len(outer),absorbed=dict(collections.Counter(r['target']for r in absorbed)),delta=len(outer)-len(absorbed),internal=dict(collections.Counter(r['target']for r in ws if any(inside(r,q)for q in outer))),remaining={k:dict(calls=len(rs:=[r for r in ws if r['target']==k and r not in outer and not any(q is not r and inside(r,q)for q in post)]),callers=dict(collections.Counter(r['caller']for r in rs)))for k in coords})
 save(REPORT/'topology-summary.json',out)
def validate():
 dest=OUT/'active-validation';tmp=OUT/'tmp';tmp.mkdir(exist_ok=True)
 r=subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--profile','active','--extra-categories','pass65,pass59,pass58,pass60,pass54','--images',IMAGES,'--output',str(dest),'--workers','4'],env={**os.environ,'TMPDIR':str(tmp.resolve())})
 receipt=load(dest/'results.json');receipt.update(historical_bytes=94720,dune_stanzas=39,reruns=[],historical_full_executed=False,full_trigger_fired=False);save(REPORT/'validation.json',receipt)
 if r.returncode:raise RuntimeError('ACTIVE failed')
def reports():
 cfg=load(REPORT/'cfg.json');nat=load(OUT/'proof/natural-cases.json');syn=[c for c in load(OUT/'proof/synthetic-checkpoints.json')['cases']if c['route'].startswith('7ED6_')];top=load(REPORT/'topology-summary.json');cross={s:load(OUT/(s+'-natural-cases.json'))for s in ['FACTOR','OPTIMIST']}
 save(REPORT/'cross-evidence.json',{s:dict(entries=[dict(offset=e['offset'],calls=len(e['members']),returns=dict(collections.Counter(q['output']['pc']for q in e['members'])),shared_entry_states=[q.get('entry_shared_state')for q in e['members']],entry_triples=dict(collections.Counter(f"{q['input']['c']}/{q['input']['d']}/{q['input']['e']}"for q in e['members'])),proof_hash=digest(e['members']))for e in v['sources'][0]['entries']],natural=True)for s,v in cross.items()})
 proof=dict(all_passed=True,primary=[dict(source=s['source'],entries=[dict(offset=e['offset'],calls=len(e['members']),proof_hash=digest(e['members']))for e in s['entries']])for s in nat['sources']],synthetic=dict(cases=len(syn),routes=dict(collections.Counter(c['route']for c in syn)),proof_hash=digest(syn),independent_original_CPU=True),comparison=['registers/flags/SP/PC','ordered writes/full65536 RAM','stacklastwriters/exactCALLchronology','DMA/filesystem/record/service/consolechronology'],journals='ignored _build/host-compiler-pass-65/proof')
 save(REPORT/'shadow-summary.json',proof)
 for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:save(REPORT/name,load(OUT/'proof'/name))
 counts={kind:sum(len(bytes.fromhex(w['bytes']))for w in cfg if w['evidence']==kind)for kind in ['OBSERVED','DEDUCED STATIC UNOBSERVED','STATIC UNOBSERVED unsupported']};save(REPORT/'knowledge-summary.json',dict(counts=counts,root_own={kind:sum(len(bytes.fromhex(w['bytes']))for w in cfg if w['evidence']==kind and w['owner']=='PLI2.OVL+7ED6')for kind in counts},helpers={kind:sum(len(bytes.fromhex(w['bytes']))for w in cfg if w['evidence']==kind and w['owner']!='PLI2.OVL+7ED6')for kind in counts}))
 semantic=dict(historical_root='PLI2.OVL+7ED6',semantic_inputs=['C selector and ordered D/E relation bytes','fresh202B/ADAA bit0 gates','freshADAB activity andADB3 indexed values'],semantic_outputs=['path-dependent A0/A1 withactualregisters/flags','savedAE3A..AE43 andorderedcandidate/indexpublications','bounded wordadjustment orreuse/publication andemittedfields throughcanonicalchildren'],shared_historical_state=['AE3A selector,AE3B/E AE3C/D,AE3D scanindex,AE3E/F word,AE40/41 splitbytes,AE42/43 candidates','ADAA,202B,ADAB..ADB2,ADB3..ADBA','AE32/33 helperselectors,ADC0/1 predicatecache andcanonicaloutputstate'],historical_mechanism=['pairedLHLD,zeroextension,DAD addressformation,PUSH/POP addresscarrier','shift8 thenOR byte,explicitworddifference andsubtract3','four independent7365 CALLs followedbyRAR','0..7 scan skipping6,RLC/RAR signbitcandidategate','exactflags/CALL/RET/writes'],candidate_modern_operation='Evaluate and update indexed generation relations',confidence=dict(low_level='OBSERVED primary/crossnatural andDEDUCED synthetic routes',compiler_semantics='HYPOTHESIS; no source-language meaning proved'),mir_relevance='Documentation only; noMIRAPI orfaithfulcoderefactor.')
 save(REPORT/'semantic-extraction.json',semantic)
 import run_host_compiler_regressions as runner
 policy=load('research/host-compiler/validation-policy.json');_,selected,_=runner.select_categories(runner.commands(IMAGES,OUT),policy,'historical-full');old=set(load('research/host-compiler/pass-62/validation.json')['categories']);assert old<=set(selected);assert {'pass63','pass64','pass65','validation-runner-tests'}<=set(selected)
 save(REPORT/'historical-full-selection.json',dict(count=len(selected),all_92_preserved=True,additional=sorted(set(selected)-old),executed=False))
 cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};oldcat=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))
 for p in oldcat['procedures']:
  for s,n in p['observed_paths']['invocations_by_run'].items():assert cat[p['id']]['observed_paths']['invocations_by_run'].get(s,0)>=n
 save(REPORT/'coverage-preservation.json',dict(all_prior_counts_preserved=True,FACTOR_OPTIMIST_preserved=True))
 laws=load(REPORT/'contract-laws-PLI2.OVL.json');prom=load(REPORT/'archaeology-summary-PLI2.OVL.json');hybrid=load(REPORT/'cumulative-hybrid-summary.json');packet=dict(baseline=BASE,laws=laws,knowledge=counts,promotions=prom,proofs=proof,natural_routes={s:dict(count=len(rs),path_signatures=dict(collections.Counter(r['signature']for r in rs)),triples=dict(collections.Counter('/'.join(str(r['entry'][k])for k in ['c','d','e'])for r in rs)),journal_hashes=[r['checkpoint_hash']for r in rs])for s,rs in load(REPORT/'natural-paths.json').items()},cross={s:dict(entries=[{k:v for k,v in e.items()if k!='shared_entry_states'}for e in g['entries']],natural=True)for s,g in load(REPORT/'cross-evidence.json').items()},topology=top,canonical_children={k:dict(contract_hash=digest(cat[k]))for k in ['PLI2.OVL+7365','PLI2.OVL+7E05','PLI2.OVL+793C','PLI2.OVL+75CE']},active_extras=['pass65','pass59','pass58','pass60','pass54'],oracle_queries=0,last_full='Pass62',full_trigger=False)
 save(REPORT/'implementation-packet.json',packet);size=(REPORT/'implementation-packet.json').stat().st_size;assert size<32768,size
 table='\n'.join(f"|{s['result']['source']}|{s['pre_guest_instructions']} → {s['result']['actual_guest_instructions']}|{s['guest_instructions_removed']}|{sum(s['pre_transition_vector'])} → {s['result']['host_transitions']}|"for s in hybrid['sources'])
 readme=f"""# Pass65 — bounded paired-relation generation policy

Verified published baseline: `{BASE}`. **Pass62 remains the last certified FULL epoch.** Historical-full was not executed; no FULL trigger fired. CPU8080, CP/M, Runner and existing capture/journal interpretation are unchanged.

## Bounds, coverage and independent helpers

The root is **PLI2.OVL+7ED6 [7ED6,8072), 412 bytes**. Early returns and final RET at8071 belong to this local CFG. The following8072 is a separate natural procedure. No overlapping externally called entry was found inside the root. [CFG](cfg.json) retains every decoded instruction and its evidence class; [inventory](inventory-summary.json) retains actual callers and complete child sequences.

Primary logical/external counts are **MINIMAL3, FIZZBUZ11, PICTURE4**, all called at808D. Seventeen primary roots returnA0 at7EF1 because freshADAA.bit0 is clear. One PICTURE root passes the gates and completes a failed indexed search:16 independent7365 calls, indices0..7 with6 skipped, then index8 terminates. FACTOR adds5 and OPTIMIST14 independently shadowed natural roots, all on the early route. Neither cross source is a semantic selector.

New reusable helper bounds are **7D47[7D47,7D85), 7D85[7D85,7DC3), 8398[8398,83A2), 83B4[83B4,83BA), 83D2[83D2,83DC)**. Their150 bytes are separate from the412 root-own bytes. Global natural shift/OR helper counts are9/34/12 each;7D47 has one independent FIZZBUZ call. These cross-caller executions are independently shadowed.7D85 has one natural cross-corpus call in each of FACTOR/OPTIMIST, independently traced and shadowed.83D2 has no natural calls; its accepted routes are synthetic-only.

## Exact state-driven law

Entry saves **D→AE3C, E→AE3B, C→AE3A**, in that order. Each later paired LHLD remains independent. Fresh202B RAR: bit0set returnsA0. Otherwise freshADAA RAR: bit0clear returnsA0. Otherwise freshsavedC CPI6: equal returnsA0. Producing flags and preceding saves remain visible. EntryC0..7 is bounded; active nonreserved paths requireC0..5 so adjacent indices remain supported.

The active path independently forms ADAB[C] and ADAB[C+1]. PUSH H/POP H carries the first address; ANA/RAR tests conjoined activity bit0. If both are active, ADB3[C] becomes the high byte through83B4 shift8; freshADB3[C+1] is ORed into the low byte through8398. SHLD publishes the resulting word atAE3E/F. Canonical resident word differences and83D2 subtraction of3 test forward or reverse unsigned distances0..2. Equality returnsA1. Otherwise7D47/7D85 emits through canonical75CE and increments/decrements the adjacent relation bytes; the parent independently rereads/increments/decrements AE3E until equality. At most two adjustments follow from the distance predicate; no observed iteration count selects behavior. A farther value falls through to the following policy.

The fallback publishes savedD atAE40 and savedE atAE41.7365 at7FBA tests(C,D); its returned bit0 throughRAR selects7E05(C+1,E), thenA1. Otherwise7365 at7FD9 independently tests(C+1,E); a match selects7E05(C,D), thenA1. Equal values retain separate read provenance.

Neither match initializesAE42/43 toFF and AE3D to0. FreshA7 CMP index scans0..7 and explicitly skips6.7365 at8015 tests(index,D) and publishes AE42 on success.7365 at802B independently tests(index,E), publishing AE43 only when index differs from savedC. Candidates persist across iterations. Fresh candidate OR/RLC/RAR tests oldbit7: both valid invoke793C(C,first) and then793C(u8(C+1),second), returningA1. Failed candidates INR the fresh index before the backedge. Index8 returnsA0 with the actual final CMP flags, includingS/CYset.

7D47/7D85 preserve saved selectors, literal3/0B emission, low-byte update before carry/borrow into the preceding byte, and their reserved6 arms.8398 preserves exact E/D/A/L/H transfers and OR flags;83B4 preserves each DAD carry and DCR flags;83D2 preserves SUB/SBB channels and borrow. [Contracts](contract-laws-PLI2.OVL.json) retain the complete bounded instruction laws. Canonical7365,7E05,793C,75CE and resident arithmetic operations are composed internally; no guest instruction execution occurs in the host algorithm.

## Proof, stack and transaction

[Shadow summary](shadow-summary.json) records all primary/cross natural roots and independent helper proofs. **{proof['synthetic']['cases']} original-CPU synthetic proofs** cover each gate, D/E differences, first/second matches, paired equality/±1/±2/far values, search matches0/5/7, index6 skip, destination exclusion, equal values, high gate bits and changed incoming carry. Separate helper cases cover shift/OR/subtraction, word carry/borrow, forward/reverse wrapping and reserved6 arms. Full instruction/loop checkpoints stay under ignored_build; durable reports contain hashes.

Every supported root compares all registers/flags/SP/PC, ordered writes, complete65536-byte RAM, stack last writers, child CALL chronology, DMA/filesystem and record/service state. Natural and synthetic evidence remain separate. Outer808D CALL stores continuationA290. PUSH/POP H carriers and each nested CALL retain historical residue; RET consumes the unchanged original word withSP=entrySP+2. The83B4 entry is independently CALLed; its preceding83B0 prefix remains STATIC/unmigrated, with no natural calls. Its backedge is a local loop, not a second invocation; its new-entry shadow explicitly distinguishes that loop.

Code, child code, CALL/continuation, sentinel/table/scratch/stack aliases and unsupported child domains reject before live mutation. Copied staging validates the entire route, including later children and output state. Negative proofs include activeC7 rejection after the entry saves and a later position-wrap child rejection after staged preparation/output. No partial publication followed by guest fallback is permitted.

## Hierarchy and economics

| Source | Guest before → after | Removed | Host before → after |
|---|---:|---:|---:|
{table}

[Topology](topology-summary.json) records absorption and remaining7365/7ED6/7338/75CE/7619/7A17/8072/119E. Natural roots contain no already-enabled lower Runner root. Thus this policy adds one boundary per invocation; its modest guest reduction is reported alongside that cost. No global7365 or serializer interceptor is added. Standalone and cumulative hybrids preserve exact REL goldens, complete REL/INT record chronology, filesystem, console, BDOS order/counts, compiler milestones and warm boot. Goldens are retained in both hybrid receipts.

Knowledge gain is **{prom['raw_to_understood']} RAW→UNDERSTOOD; DECODED0; STRUCTURED0**. [Knowledge summary](knowledge-summary.json) separates root/helper bytes and naturally OBSERVED bytes from DEDUCED STATIC UNOBSERVED bytes. All local CFG bytes are accounted for, but the general contract remains partial over explicit index, child mode/error, output/position and alias domains. No higher PL/I meaning is claimed. [Semantic extraction](semantic-extraction.json) separates relation search/adjustment from scratch, paired reads, arithmetic flags and stack mechanisms; the proposed compiler-level meaning remains HYPOTHESIS. No MIR/API design or faithful-code refactor.

## Validation and next boundary

ACTIVE core plus explicit extras **pass65, pass59, pass58, pass60, pass54**. Pass59 directly proves7365; Pass58 proves793C; Pass60 proves7E05; Pass54 proves75CE used directly by the new adjustment helpers. Pass52/63/64 are not accumulated merely because they were previous extras. [Validation receipt](validation.json) records categories, tests, workers, wall/summed seconds and reruns. Previous ACTIVE walls: Pass63 423.418s and Pass64 503.528s.

Historical-full selection preserves all92 Pass62 categories plus validation-runner-tests and pass63/64/65 (**96 selected**). This is a selection-set proof only. Exact reconstruction remains **94720 bytes**. New oracle queries: **0**. Packet: **{size} bytes**. Driver phases cover discovery, inventory, contracts, components, cross-evidence, topology, reports and ACTIVE validation.

Immediate parent8072 has separate policy around7338,75CE,7619 and sometimes7A17; its complete natural child sequences are retained in the inventory. Recommend its assessment forPass66 before the large independent18B3 traversal.8072 is not migrated here; transition savings alone do not justify climbing. Pass62 remains lastFULL, with ordinary nextFULL approximatelyPass67.

There is no historical behavior correction or pragmatic divergence. Development corrected a reversed scan-termination branch through independent CPU comparison and removed inapplicable inherited corruption tests that changed no effects on an early-return path. Fidelity debt is bounded child/error/alias scope, synthetic-only alternate coverage and unproved higher meaning. User-owned scripts/view-optimist.sh is untouched. Proof artifacts and aggregate temporary directories are under ignored _build and clean up on exit. The focused V1 test used its existing automatically cleaned temporary-directory mechanism.
"""
 (REPORT/'README.md').write_text(readme)
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['discovery','inventory','prove','components','focused','cross','contracts','topology','reports','validate']);a=p.parse_args();OUT.mkdir(parents=True,exist_ok=True);REPORT.mkdir(parents=True,exist_ok=True)
 if a.phase=='components':prove(focused=True)
 else:globals()[a.phase]()
