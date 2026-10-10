#!/usr/bin/env python3
"""Pass64 resident dependencies and lifecycle proofs; ACTIVE validation only."""
import collections,json,os,subprocess,sys,tempfile,shutil
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_buffered_rel_emission_pass_52 import save,digest
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-64');REPORT=Path('research/host-compiler/pass-64')
BASE='2cf8fa26f42c51eea1755438f11a4e110e9821d4'
RESIDENT={0x124b:0x1272,0x05ff:0x0611,0x05f8:0x05ff,0x0466:0x047d,0x044b:0x0466,0x0421:0x044b,0x03f4:0x0421,0x03e9:0x03f4,0x0390:0x03e9,0x0380:0x0390}
def load(p):return json.loads(Path(p).read_text())
def discovery():
 OUT.mkdir(parents=True,exist_ok=True)
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{'PLI2.OVL+82DD':(0x82dd,0x82de),**{f'PLI.COM+{x:04X}':(x,x+1)for x in RESIDENT}},include_nested_returns=True)
  save(OUT/(source+'-all-rows.json'),rows)
 inventory()
def inventory():
 rows={s:load(OUT/(s+'-all-rows.json'))for s in CAPTURES};save(OUT/'rows.json',rows)
 summary={};annotations={};cfg={}
 for source,g in rows.items():
  parents=g['PLI2.OVL+82DD'];windows=[(r['call']['step_index'],r['ret']['step_index'])for r in parents]
  annotations[source]={k:[r for r in rs if k=='PLI2.OVL+82DD'or any(a<r['call']['step_index']<r['ret']['step_index']<b for a,b in windows)]for k,rs in g.items()}
  summary[source]={}
  for k,rs in g.items():
   for r in rs:r['nested_returns']={int(i):v for i,v in r['nested_returns'].items()}
   summary[source][k]=dict(global_natural_calls=len(rs),inside_parent_calls=len(annotations[source][k]),callers=dict(collections.Counter(coord(r['call']['origin'])for r in rs)),returns=dict(collections.Counter(coord(r['ret']['origin'])for r in rs)),child_sequences=dict(collections.Counter('/'.join(c['target']for c in children_any(r))for r in rs)))
  for k,rs in annotations[source].items():
   cfg.setdefault(k,{})
   for r in rs:
    for w in r['own_witnesses']:cfg[k][w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
 save(REPORT/'inventory-summary.json',summary);save(OUT/'cfg.json',{k:sorted(v.values())for k,v in cfg.items()})
 save(OUT/'annotation-rows-PLI.COM.json',{s:{k:v for k,v in g.items()if k.startswith('PLI.COM')}for s,g in annotations.items()})
 save(OUT/'annotation-rows-PLI2.OVL.json',{s:{k:v for k,v in g.items()if k.startswith('PLI2')}for s,g in annotations.items()})

def prove(images='/home/john/pli/cpm/pli80/DISK1',focused=False):
 dest=OUT/'proof';dest.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
  cmd=['dune','exec','bin/native_output_lifecycle.exe','--','--toolchain',str(images),'--output-dir',str(Path(tmp)/'results')]
  if focused:cmd+=['--family-only']
  with(dest/'run.log').open('w')as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((dest/'run.log').read_text()[-4000:])
  for f in(Path(tmp)/'results').glob('*.json'):
   if not focused or f.name not in['single-hybrid-summary.json','cumulative-hybrid-summary.json']:shutil.copyfile(f,dest/f.name)
 print('Pass64 proof passed',flush=True)
def cross():
 for source in ['FACTOR','OPTIMIST']:
  with tempfile.TemporaryDirectory(prefix='cross-',dir=OUT)as tmp:
   cmd=['_build/default/bin/native_output_lifecycle.exe','--toolchain','/home/john/pli/cpm/pli80/DISK1','--output-dir',str(Path(tmp)/'results'),'--family-only','--cross-source',source]
   with(OUT/(source+'-proof.log')).open('w')as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
   if r.returncode:raise RuntimeError((OUT/(source+'-proof.log')).read_text()[-3000:])
   shutil.copyfile(Path(tmp)/'results/natural-cases.json',OUT/(source+'-natural-cases.json'))
 print('Pass64 cross-evidence passed',flush=True)
def contracts():
 laws={
 0x124b:('Conditional byte alignment and counted trailer','Fresh2029 bit0 set returns; otherwise fresh1D05 bit0 clear returns. Active output: while fresh1D8B !=0 call canonical1140(C0); then canonical119E(C9E,E7), bits1001111. No close occurs. Successful bounded writer scope inherited.'),
 0x05ff:('Saved pointer line and dollar string output','Save B at2080 then C at207F. Canonical05F8 polls then emits CR/LF. Fresh paired207F word becomes BC for03F4 dollar-terminated string. Console-only, no key-present/listing/redirected output.'),
 0x05f8:('Poll and CR LF output','Canonical05B2 zero-key route then canonical03E9 CR and LF; actual child flags/registers returned.'),
 0x0466:('Fresh cached word hexadecimal output','Save B at2073 then C at2072; independent paired2072 reads acquire high byte then low byte. Each invokes044B. Four uppercase hexadecimal characters; actual scratch/register/flags/service chronology retained.'),
 0x044b:('Cached byte high and low hexadecimal fields','Save C2071. Fresh byte ANI F8,RAR four times -> C high nibble;0421. Fresh byte ANI0F -> C low nibble;0421. Fresh independent reads retained.'),
 0x0421:('Nibble character construction','Save C2070; A9 CMP fresh M. If CY then fresh saved value ADI41,SUI0A; otherwise ADI30. Publish2070; paired reread low to C;0390. Bounded caller nibble0..15.'),
 0x03f4:('Indexed dollar-terminated string output','Save B206E then C206D;206C=0. Repeated paired206C read with high discarded ->DE zero-extended index; paired206D pointer,DAD D; fresh byte ->206F,CPI24; RET on dollar. Otherwise paired206F low ->C,0390;INR byte206C and retry. Nonwrapping terminator within256 bytes; no scratch/stack alias.'),
 0x03e9:('Ordered CR LF output','C0D calls0390; C0A calls0390; return actual second child state.'),
 0x0390:('Bounded console character policy','Save C206B. Fresh202A RAR requires bit0 clear; fresh201E RAR requires bit0 clear. Fresh paired206B low -> C;0380. Listing/page/file routes remain RAW unsupported.'),
 0x0380:('Character carrier BDOS2 output','Save C206A; fresh paired206A high discarded; zeroextended low ->DE viaXCHG; C2; canonical19BB signature/sentinel service gate and BDOS2; exact service returned A/B alias L/H.')}
 save(REPORT/'contract-laws-PLI.COM.json',{f'PLI.COM+{x:04X}':dict(end=RESIDENT[x],description=d,contract=c,completeness=['stable','partial'if x in[0x0390,0x124b]else'complete','partial'])for x,(d,c)in laws.items()})
 save(REPORT/'contract-laws-PLI2.OVL.json',{'PLI2.OVL+82DD':dict(end=0x8340,description='Buffered representation trailer and three console words',completeness=['stable','complete','partial'],contract='119E(C9A,E7),fresh1C2C ->11E5;119E(C9C,E7);freshAE6A RAR bit0 selects BC0->11E5 if set else11C3.124B aligns and emits7-bit9E trailer. Three05FF calls print CRLF and dollar strings from literal94EB/94FA/9507; three0466 calls emit words from fresh1C2C, freshACA3->SHLDAC9F->freshAC9F->p+2 low/p+3 high, and fresh1C2E respectively. Final RET. Console-only zero-key route, successful writer, nonwrapping/nonalias structure/string/stack/sentinel scope, excluding the full active/inherited stack region; no file close or warm boot inside root. General compiler meaning unknown.')})
 # Six alternate-arm bytes executed independently by original CPU synthetics.
 image=Path('/home/john/pli/cpm/pli80/DISK1/PLI2.OVL').read_bytes()
 static=[]
 for o,n,d in [(0x8303,3,'LXI B,0000H'),(0x8306,3,'CALL 12C3H')]:
  w=dict(origin=dict(image=dict(name='PLI2.OVL'),offset=o),bytes=image[o:o+n].hex().upper(),disassembly=d,control=dict(kind='call'if o==0x8306 else'none',target=0x12c3 if o==0x8306 else None),evidence_class='DEDUCED STATIC UNOBSERVED')
  if o==0x8306:w['target_origin']=dict(image=dict(name='PLI.COM'),offset=0x11c3)
  static.append(w)
 save(OUT/'annotation-static-PLI2.OVL.json',{'PLI2.OVL+82DD':static})

def topology():
 raw=load('_build/host-compiler-pass-51/residual-map.json');out={};parents_report={};rank={}
 inside=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
 previous=['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in[0x7434,0x7630,0x765e,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619,0x7701,0x8248,0x7ae4,0x7b99,0x7b1b,0x7e05,0x742a,0x8258,0x82b5,0x7338,0x829c]]
 coords=['PLI.COM+'+f'{x:04X}'for x in[0x119e,0x11e5,0x11c3,0x124b,0x05ff,0x0466]]+[f'PLI2.OVL+{x:04X}'for x in[0x82dd,0x7ed6,0x18b3]]
 for source,v in raw.items():
  ws=v['windows'];all_pre=v['roots']+[r for r in ws if r['target']in previous];pre=[r for r in all_pre if not any(q is not r and inside(r,q)for q in all_pre)]
  ps=[r for r in ws if r['target']=='PLI2.OVL+82DD'];outer=[r for r in ps if not any(q is not r and inside(r,q)for q in pre+ps)];absorbed=[r for r in pre if any(inside(r,q)for q in outer)]
  out[source]=dict(logical=len(ps),external=len(outer),callers=dict(collections.Counter(r['caller']for r in ps)),absorbed=dict(collections.Counter(r['target']for r in absorbed)),net_host_delta=len(outer)-len(absorbed),logical_internal=dict(collections.Counter(r['target']for r in ws if any(inside(r,q)for q in outer))),remaining={k:dict(calls=len(rs:=[r for r in ws if r['target']==k and r not in outer and not any(q is not r and inside(r,q)for q in pre+outer)]),callers=dict(collections.Counter(r['caller']for r in rs)))for k in coords})
  parents_report[source]=[]
  for r in ps:
   ancestors=[q for q in ws if inside(r,q)];q=min(ancestors,key=lambda q:q['ret']-q['call'])if ancestors else None
   parents_report[source].append(dict(callsite=r['caller'],true_parent=q['target']if q else None,widened=False,reason='Broader compiler-phase lifecycle; not this bounded output operation.'))
  post=[r for r in pre if r not in absorbed]+outer;rank[source]=[]
  for k in ['PLI2.OVL+7ED6','PLI2.OVL+18B3']:
   rs=[r for r in ws if r['target']==k];residual=0;contained=collections.Counter();seq=collections.Counter()
   for r in rs:
    cs=[q for q in ws if inside(q,r)];direct=[q for q in cs if not any(z is not q and inside(q,z)for z in cs)];seq['/'.join(q['target']for q in direct)]+=1
    lower=[q for q in post if inside(q,r)];contained.update(q['target']for q in lower);residual+=r['ret']-r['call']-sum(q['ret']-q['call']for q in lower)
   rank[source].append(dict(coordinate=k,calls=len(rs),callers=dict(collections.Counter(r['caller']for r in rs)),direct_sequences=dict(seq),ranking_only_guest_residual=residual,contained_native_roots=dict(contained)))
 save(REPORT/'topology-summary.json',out);save(REPORT/'immediate-parent-summary.json',parents_report)
 save(REPORT/'next-boundary-ranking.json',dict(sources=rank,decision='Prefer7ED6 broader carrier-generation policy assessment;18B3 is a separate large traversal/structure sequence.82DD caller046E belongs to broad0457 compiler phase;no upward migration. Ranking is not savings.'))

def validate():
 dest=OUT/'active-validation';tmp=OUT/'tmp';tmp.mkdir(exist_ok=True)
 cmd=['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--profile','active','--extra-categories','pass64,pass52,pass63','--images','/home/john/pli/cpm/pli80/DISK1','--output',str(dest),'--workers','4']
 r=subprocess.run(cmd,env={**os.environ,'TMPDIR':str(tmp.resolve())});receipt=load(dest/'results.json');assert receipt['validation_tier']=='ACTIVE/INCREMENTAL'and receipt['last_certified_full_epoch']['name']=='Pass62'
 receipt.update(historical_bytes=94720,dune_stanzas=39,reruns=[],historical_full_executed=False,full_trigger_fired=False);save(REPORT/'validation.json',receipt)
 if r.returncode:raise RuntimeError('ACTIVE validation failed')

def reports():
 raw=load(OUT/'rows.json');nat=load(OUT/'proof/natural-cases.json');top=load(REPORT/'topology-summary.json');hybrid=load(OUT/'proof/cumulative-hybrid-summary.json');cfg=load(OUT/'cfg.json')
 provenance={};proofs=[];economics=[]
 for source,g in raw.items():
  r=g['PLI2.OVL+82DD'][0];w={q['origin']['offset']:q for q in r['own_witnesses']};word=lambda site:sum(q['value']<<(8*i)for i,q in enumerate(w[site]['reads']))
  provenance[source]=dict(entry=r['entry']['before'],caller=coord(r['call']['origin']),continuation=r['ret']['after']['pc'],AE6A=w[0x82f3]['reads'][0]['value'],first_word=word(0x8312),final_word=word(0x8337),structure_pointer=word(0x8320),payload_low=w[0x832b]['reads'][0]['value'],payload_high=w[0x832d]['reads'][0]['value'],return_state=r['ret']['after'],ordered_parent_reads=[q for x in r['own_witnesses']for q in x['reads']],ordered_parent_writes=[q for x in r['own_witnesses']for q in x['writes']],instruction_checkpoint_hash=digest(r['own_witnesses']))
  n=next(q for q in nat['sources']if q['source']==source);proofs.append(dict(source=source,entries=[dict(coordinate=('PLI2.OVL'if e['offset']>=0x2200 else'PLI.COM')+f"+{e['offset']:04X}",calls=len(e['members']),proof_hash=digest(e['members']))for e in n['entries']],record_service_proof_hash=digest(n)))
  h=next(q for q in hybrid['sources']if q['result']['source']==source);before=sum(h['pre_transition_vector']);after=h['result']['host_transitions'];assert after-before==top[source]['net_host_delta']
  economics.append(dict(source=source,pre_guest=h['pre_guest_instructions'],post_guest=h['result']['actual_guest_instructions'],removed=h['guest_instructions_removed'],pre_host=before,post_host=after,net_host_delta=after-before,roots=h['family_roots'],absorbed=top[source]['absorbed'],remaining=top[source]['remaining']))
  save(OUT/(source+'-instruction-checkpoints.json'),r)
 cross={s:dict(natural_roots=len(rs:=load(OUT/(s+'-natural-cases.json'))['sources'][0]['entries'][0]['members']),callers=dict(collections.Counter(q['caller']for q in rs)),proof_hash=digest(rs))for s in['FACTOR','OPTIMIST']}
 synthetic=[q for q in load(OUT/'proof/synthetic-checkpoints.json')['cases']if q['route'].startswith('82DD_')];assert len(synthetic)==42
 for source,values in cross.items():
  r=load(OUT/(source+'-natural-cases.json'))['sources'][0]['entries'][0]['members'][0]
  ws=[q for q in r['journal']if q[2]==0xa523];pointer=ws[0][1]+(ws[1][1]<<8)
  assert pointer+4<=r['input']['sp']-512
  words=[];high=None
  for q in r['journal']:
   if q[2]==0x0569:high=q[1]
   if q[2]==0x056b:words.append((high<<8)|q[1])
  values.update(entry=r['input'],return_state=r['output'],structure_pointer=pointer,console_words=words,AE6A_bit0=bool(any(q[2]==0xa4fd for q in r['journal'])),entry_RAM_hash=r['entry_memory_sha256'],post_RAM_hash=r['post_memory_sha256'])
 save(REPORT/'natural-provenance.json',provenance);save(REPORT/'cross-evidence.json',cross);save(REPORT/'hierarchy-summary.json',dict(sources=economics))
 shadows=dict(all_passed=True,natural=proofs,cross=cross,synthetic=dict(cases=42,route_counts=dict(collections.Counter(q['route']for q in synthetic)),original_concrete_CPU=True,exact_service_record_DMA_filesystem=True,proof_hash=digest(synthetic)),comparison=['all registers/flags/SP/PC','full64KiBRAM/ordered writes/stack last writers','exact childCALLs andBDOS/service/RELrecord/file chronology','complete filesystem/console/INTRELchronology in hybrids'],journals='ignored _build/host-compiler-pass-64/proof')
 save(REPORT/'shadow-summary.json',shadows)
 for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:save(REPORT/name,load(OUT/'proof'/name))
 promotions={image:load(REPORT/('archaeology-summary-'+image+'.json'))for image in['PLI.COM','PLI2.OVL']}
 fidelity=dict(RAW_to_UNDERSTOOD=sum(q['raw_to_understood']for q in promotions.values()),DECODED_to_UNDERSTOOD=0,STRUCTURED_to_UNDERSTOOD=0,OBSERVED_natural_bytes=304,DEDUCED_STATIC_UNOBSERVED_bytes=6,historical_correction='Provisional task decode said final LHLD1C2C; actual8337 reads1C2E. This corrects the candidate description, not historical behavior.',implementation_correction='Development BDOS2 resume prediction corrected to existingCPM A/B->L/H alias convention; independent syntheticruntime DMA initialized to natural entryDMA.',pragmatic_divergence=None,fidelity_debt='Console-only zero-key required routes; listing/redirected/key-present paths remain unsupported; writer errors and pointer/string aliases/wrap excluded; stronger compiler meaning unproved.',full_trigger_fired=False,historical_full_executed=False,oracle_queries=0,historical_bytes=94720)
 save(REPORT/'fidelity.json',fidelity)
 semantic=dict(historical_root='PLI2.OVL+82DD',semantic_inputs=['fresh words1C2C and1C2E','freshAE6A bit0','freshACA3 pointer andtarget+2 low/+3 high payload','bufferedREL state andthree dollar-terminated literal strings'],semantic_outputs=['7-bit1001101,tag40word,7-bit1001110,tag40/tag00zero word,byte alignment and7-bit1001111','three orderedCRLF/string/four-hex-character console groups','AC9F low/high pointer publication and exact child/service/stack state'],shared_historical_state=['1C2C/1C2E','ACA3/A4 AC9F/A0 AE6A','resident206A..2080scratch','202A/201E console gates','1D05/2029 output gates','REL buffer/index/FCB/DMA/sentinel/hardware stack'],historical_mechanism=['RAR bit0 gate anddistinct fixedtag children','countedRLC serialization andexplicitpadding','pairedLHLD andlow/highSHLD','threeINXH payload byte acquisition','byte indexed dollar loop','ANI F8/RARx4/ANI0F nibble construction','canonicalpoll/signature gate andBDOS2 console services','exactCALL/PSW/RET residue'],candidate_modern_operation='Emit representation trailer and display three hexadecimal words',confidence=dict(low_level_operation='OBSERVED all five natural sources; DEDUCED exact instruction interpretation',compiler_lifecycle_meaning='HYPOTHESIS; no source-language item names or statistics meaning asserted',AE6A_clear_arm='DEDUCED STATIC UNOBSERVED'),mir_relevance='Documentation only; no MIR/API design or faithful-code refactor.')
 save(REPORT/'semantic-extraction.json',semantic)
 cat={q['id']:q for q in load('research/annotated-assembly/procedures.json')['procedures']};old=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))
 for q in old['procedures']:
  for source,count in q['observed_paths']['invocations_by_run'].items():assert cat[q['id']]['observed_paths']['invocations_by_run'].get(source,0)>=count
 save(REPORT/'coverage-preservation.json',dict(all_prior_catalog_totals_preserved=True,FACTOR_OPTIMIST_preserved=True))
 import run_host_compiler_regressions as runner
 policy=load('research/host-compiler/validation-policy.json');cmds=runner.commands('/home/john/pli/cpm/pli80/DISK1',OUT);_,selected,_=runner.select_categories(cmds,policy,'historical-full');oldnames=set(load('research/host-compiler/pass-62/validation.json')['categories']);assert oldnames<=set(selected);assert {'validation-runner-tests','pass63','pass64'}<=set(selected)
 save(REPORT/'historical-full-selection.json',dict(selected_count=len(selected),Pass62_categories=len(oldnames),all_Pass62_preserved=True,additional_categories=sorted(set(selected)-oldnames),executed=False))
 packet=dict(task='RUNES_PLI2_OUTPUT_LIFECYCLE_82DD_PASS_64',baseline=BASE,extent=[0x82dd,0x8340],laws={image:load(REPORT/('contract-laws-'+image+'.json'))for image in['PLI.COM','PLI2.OVL']},provenance={k:{a:b for a,b in v.items()if a not in ['ordered_parent_reads','ordered_parent_writes']}for k,v in provenance.items()},proofs=proofs,synthetic=shadows['synthetic'],cross=cross,economics=economics,promotions=promotions,fidelity=fidelity,canonical_children={k:dict(contract_hash=digest(cat[k]),route_id='successful_buffered_writer_or_service_gate')for k in['PLI.COM+1140','PLI.COM+119E','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+05B2','PLI.COM+19BB']},active_extras=['pass64','pass52','pass63'],last_certified_full_epoch='Pass62')
 save(REPORT/'implementation-packet.json',packet);size=(REPORT/'implementation-packet.json').stat().st_size;assert size<28672,size
 table='\n'.join(f"|{h['source']}|{h['pre_guest']} → {h['post_guest']}|{h['removed']}|{h['pre_host']} → {h['post_host']}|"for h in economics)
 text=f"""# Pass64 — representation trailer and console word output

Baseline: `{BASE}`, verified against published origin/main. **Pass62 remains the last certified FULL epoch.** Historical-full was not executed and no FULL trigger fired. CPU8080, CP/M, Runner and shared journal/capture interpretation are unchanged.

## Bounds and natural evidence

PLI2.OVL+82DD has stable extent **[82DD,8340), 99 bytes**, ordinary RET at833F and no overlapping natural entry. MINIMAL, FIZZBUZ and PICTURE each have one logical and one corrected external root, called at046E inside true parent0457. FACTOR and OPTIMIST each add one independently shadowed natural root. Full entry/return state, ordered reads/writes and values are in [natural-provenance.json](natural-provenance.json) and [cross-evidence.json](cross-evidence.json).

The natural direct sequence is119E,11E5,119E,11E5,124B,05FF,0466,05FF,0466,05FF,0466. AE6A bit0 is set in every primary root. The alternate tag00 arm is synthetic-only evidence.

## Exact operation

Literal C=9A,E=7 invokes canonical119E and emits bits7..1 MSB-first: **1001101**. Fresh1C2C low/high becomesBC for canonical11E5 (tag40,low8,high8). Literal9C,E7 emits **1001110**. FreshAE6A RAR setsCY to oldbit0 and preservesNZPA. WithBC=0, bit0 set selects11E5/tag40 and clear selects11C3/tag00. Equal zero words retain distinct representations.

124B reads2029 and1D05 bit0 gates. The accepted active-output route repeatedly rereads1D8B and calls1140(C=0) until byte-aligned, then119E(C=9E,E=7) emits **1001111**. It aligns and adds a trailer; it does not close a file. The suppressed2029 earlyRET at1252 remainsRAW and outside accepted staging scope. Later independent1272 still owns file close.

Three05FF calls receive literalBC pointers94EB,94FA,9507. Each prints CR/LF followed by a fresh dollar-terminated string. Three0466 calls print four hexadecimal characters from **fresh1C2C**, **structure payload**, and **fresh1C2E**, respectively. The final source corrects the provisional task decode's1C2C wording; historical behavior is unchanged.

The structure acquisition independently executes LHLDACA3, SHLDAC9F low then high, freshLHLDAC9F, twoINXH, low byte[p+2] toC, oneINXH and high byte[p+3] toB. Same-valued pointer writes and independent rereads remain visible. The Pass63 parent operation is not substituted here. Accepted targets are nonwrapping and exclude code/output/carrier/stack/sentinel aliases.

## Resident dependency contracts

| Entry | Extent | Bounded law |
|---|---|---|
|124B|[124B,1272)|Active output: zero padding to byte alignment, then7-bit9E trailer; no close.|
|05FF|[05FF,0611)|Save B2080 then C207F;05F8;fresh paired pointer ->03F4.|
|05F8|[05F8,05FF)|Canonical05B2 zero-key poll, then03E9.|
|0466|[0466,047D)|Save B2073 then C2072; independent high/low reads ->044B.|
|044B|[044B,0466)|Save C2071;fresh ANI F8/RARx4 high nibble and fresh ANI0F low nibble ->0421.|
|0421|[0421,044B)|Save C2070; compare9; ADI30 or ADI41/SUI0A; publish/reload character ->0390.|
|03F4|[03F4,0421)|Save pointer206D/E; index206C=0; fresh indexed reads,206F publication,dollar comparison,0390,INR index.|
|03E9|[03E9,03F4)|Ordered C0D then C0A calls to0390.|
|0390|[0390,03E9)|Save206B; fresh202A/201E bit0 clear; paired low carrier ->0380. Other arms remainRAW.|
|0380|[0380,0390)|Save206A; fresh paired low byte zeroextended intoDE; C2 ->canonical19BB/BDOS2.|

The new reusable console laws live in `resident_console.ml`. Canonical serializer, bit writer, poll and signature/service gate algorithms are reused. Existing CP/M A/B->L/H return aliasing is preserved. Strings require a nonwrapping dollar terminator within256 bytes and exclude scratch/output/FCB/stack aliases. Listing, redirected output, key-present poll and writer errors remain unsupported. No independent large subsystem was required by the natural operation.

## Proof and transaction

Each primary root independently compares every register and flag, SP/PC, ordered writes, full65536RAM, stack last writers, childCALL chronology, DMA/filesystem and record/service chronology. Per-source resident shadows include124B1,05FF3,0466 3,05F8 3,03E9 3,03F4 3,0390 56,0380 56,044B6 and0421 12, plus independent119E/1140/tag-family correlations. Global caller counts are separately retained in [inventory-summary.json](inventory-summary.json); natural calls outside the selected root are not silently intercepted.

**42 synthetic original-CPU executions**, 14 classes per primary state, distinguishAE6A clear/set/high-only, staleAC9F, independent payload bytes and pointer bytes, irrelevant neighbors, page crossing, maximum nonstack target ending exactly at the protected stack region, independent1C2C/1C2E values, referenced string data and a record-boundary flush. Independent concrete BDOS execution checks console text, service order, record bytes, DMA and filesystem as well as complete RAM/register/flag/stack-write equality. Synthetic-only evidence remains DEDUCED STATIC UNOBSERVED.

Corrupt code/child code, CALL/continuation, unsafe stack, pointer/scratch/output/sentinel aliases, output/listing/file gates and wrapping targets reject before live mutation. The whole RAM/process/filesystem/event transaction is staged before acceptance; a later unsupported child cannot leave earlier emissions live.

No private frame exists. Outer CALL046E writes continuation2671 at entrySP (naturalFFFA). Child CALL words and deeper PSW/signature/service frames retain actual historical writers. Final CALL833C writesA53F belowSP. FinalRET consumes the unchanged outer word, with SP=entrySP+2. Intermediate instruction checkpoints and exhaustive journals remain under ignored `_build/host-compiler-pass-64`, with hashes in [shadow-summary.json](shadow-summary.json).

## Hierarchy and measured effects

| Source | Pass63 → Pass64 guest | Removed | Host before → after |
|---|---:|---:|---:|
{table}

Each new82DD root absorbs two previously external11E5 roots: host delta **-1/-1/-1**. No new resident leaf Runner roots are enabled. Suppression applies only inside exact corrected parent windows. Remaining external119E is **32/32/39**,11E5 is1/1/1,11C3 is zero,124B is zero,05FF is3/3/3 and0466 is zero. See [topology-summary.json](topology-summary.json). Ranking windows are not savings.

Standalone and cumulative hybrids preserve REL/INT record chronology, filesystem, console, compiler milestones, BDOS order/counts and warm boot. Exact REL goldens:

- MINIMAL:7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119
- FIZZBUZ:68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203
- PICTURE:c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1

## Knowledge and future boundary

RAW→UNDERSTOOD **310**:211resident and99parent. DECODED→UNDERSTOOD0; STRUCTURED→UNDERSTOOD0. **304 naturally OBSERVED bytes;6 DEDUCED STATIC UNOBSERVED bytes** in the alternate zero-word arm. Root bounds are stable, local CFG complete, contract partial over explicit domains. Resident0390 remains locally partial and124B1252 remainsRAW. Existing child contracts are unchanged. FACTOR/OPTIMIST catalog totals are preserved. Exact reconstruction: **94720 bytes**. New historical oracle queries: **0**.

[semantic-extraction.json](semantic-extraction.json) separates representation trailer and three-word display from scratch, pointer, nibble, flag and stack mechanisms. Stronger compiler lifecycle/statistics meaning remains HYPOTHESIS. No MIR/API design or faithful-code refactor. Fidelity debt is unsupported listing/key/error/alias/wrapping scope and unproved higher meaning. Development fixes corrected the local BDOS2 resume prediction and initialized independent synthetic DMA correctly; runtime semantics did not change.

Recommend **7ED6 for Pass65 assessment** before large18B3 traversal. Immediate parent0457 introduces a broader compiler phase and is deferred.82DD remains separate from829C. [next-boundary-ranking.json](next-boundary-ranking.json) records post-pass topology and ranking evidence.

## Validation

ACTIVE core plus explicit extras **pass64,pass52,pass63**. Pass52 covers canonical119E/1140/tag-family and successful flush contracts. Pass63 directly regresses the shared bridge/native proof code extended here and the independently established pointer-publication mechanism; its parent algorithm is not called. Pass64 is registered for future historical-full, not permanent active core.

The95-category historical-full selection preserves every92Pass62 category plusvalidation-runner-tests,pass63,pass64. This is a selection-set proof only. Pass62 remains last certified FULL; next ordinary FULL remains approximatelyPass67 unless a real trigger fires.

```sh
python3 tools/annotated-assembly/run_output_lifecycle_pass_64.py validate
```

[validation.json](validation.json) records ACTIVE/INCREMENTAL categories, extras, workers, tests, timings and reruns after execution. Reports, catalog, progress and packet are finalized before aggregate validation. Packet: **{size} bytes**. Driver phases: discovery, inventory, contracts, components, prove, cross, topology, reports and active validation.

User-owned `scripts/view-optimist.sh` and unrelated untracked files are untouched. No task temporary directory was created under `/tmp`; temporary proof directories under ignored `_build` clean up on exit.
"""
 (REPORT/'README.md').write_text(text)

if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['discovery','inventory','contracts','components','prove','cross','topology','reports','validate']);a=p.parse_args()
 if a.phase in['components','prove']:prove(focused=a.phase=='components')
 else:globals()[a.phase]()
