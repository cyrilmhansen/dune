#!/usr/bin/env python3
"""Execution-owned pending-generation discovery; anchors never assign entry identity."""
import collections,json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_buffered_rel_emission_pass_52 import save,digest
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-57');REPORT=Path('research/host-compiler/pass-57')
BASE='7bd9ca0a11984e7f618293bb2ab4f2c0d4b79314'
def discovery():
 start=time.monotonic();raw=json.loads(Path('_build/host-compiler-pass-51/residual-map.json').read_text());entries=sorted({"PLI2.OVL+7397","PLI2.OVL+73A7"}|{r['target']for v in raw.values()for r in v['windows']if r['target'].startswith('PLI2.OVL+')and 0x7900<=int(r['target'].split('+')[1],16)<0x7c00});full={};cfg={};summary={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{k:(int(k.split('+')[1],16),int(k.split('+')[1],16)+1)for k in entries},include_nested_returns=True);full[source]=rows;summary[source]={}
  for k,rs in rows.items():
   own={w['origin']['offset']:[w['origin']['offset'],w['bytes'],w['disassembly']]for r in rs for w in r['own_witnesses']};cfg.setdefault(k,{}).update(own)
   summary[source][k]=dict(calls=len(rs),callers=dict(collections.Counter(coord(r['call']['origin'])for r in rs)),children=dict(collections.Counter('/'.join(c['target']for c in children_any(r))for r in rs)),entry_hash=digest([r['entry']['before']for r in rs]),return_hash=digest([r['ret']['after']for r in rs]))
 save(OUT/'rows.json',full);save(OUT/'cfg.json',{k:sorted(v.values())for k,v in cfg.items()});save(REPORT/'discovery-summary.json',summary)
 print(json.dumps(dict(entries=entries,inventory=summary,CFG={k:sorted(v.values())for k,v in cfg.items()},seconds=round(time.monotonic()-start,3)),indent=2))
def prove(images='/home/john/pli/cpm/pli80/DISK1',focused=False):
 import subprocess,tempfile,shutil
 dest=OUT/'proof';dest.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
  cmd=['dune','exec','bin/native_pending_generation.exe','--','--toolchain',str(images),'--output-dir',str(Path(tmp)/'results')]
  if focused:cmd+=['--family-only']
  with(dest/'run.log').open('w')as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((dest/'run.log').read_text()[-4000:])
  for f in(Path(tmp)/'results').glob('*.json'):
   if not focused or f.name in ['component-shadows.json','natural-cases.json']:shutil.copyfile(f,dest/f.name)
 print('proof passed')
def topology():
 raw=json.loads(Path('_build/host-compiler-pass-51/residual-map.json').read_text());result={}
 inside=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
 for source,v in raw.items():
  ws=v['windows'];prior=v['roots']+[r for r in ws if r['target']in['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in[0x7434,0x7630,0x765e,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619,0x7701,0x8248]]]
  pre=[r for r in prior if not any(q is not r and inside(r,q)for q in prior)]
  parents=[r for r in ws if r['target']=='PLI2.OVL+7AE4'];outer=[r for r in parents if not any(inside(r,q)for q in pre)]
  absorbed=[r for r in pre if any(inside(r,q)for q in outer)]
  residual={k:dict(calls=len(rs:=[r for r in ws if r['target']==k and r not in outer and not any(q is not r and inside(r,q)for q in pre+outer)]),callers=dict(collections.Counter(r['caller']for r in rs)))for k in['PLI2.OVL+79E2','PLI2.OVL+7A17','PLI2.OVL+73D0','PLI2.OVL+7AE4','PLI.COM+119E']}
  result[source]=dict(logical=len(parents),external=len(outer),callers=dict(collections.Counter(r['caller']for r in parents)),absorbed=dict(collections.Counter(r['target']for r in absorbed)),net_host_delta=len(outer)-len(absorbed),remaining=residual,logical_internal=dict(collections.Counter(r['target']for r in ws if any(inside(r,q)for q in outer))))
 save(REPORT/'topology-summary.json',result);print(json.dumps(result,indent=2))
def contracts():
 rows=json.loads((OUT/'rows.json').read_text());scopes={
 0x7397:(0x73a7,'Fresh indexed carrier clear','Save C atADC2; paired-readADC2/ADC3,discard high;BC=ADAB;HL=ADAB+zeroextended index modulo16;publish zero atHL;return actual DAD carry and preserved NZPA. Scope index<8.',['stable','complete','complete']),
 0x73a7:(0x73c4,'Two adjacent fresh carrier clears','Save C atADC3;fresh compare6. Supported non6 route independently paired-readsADC3 intoC;canonical7397;fresh LDA ADC3;INR;C=result;canonical7397. No cached first index. Index6 earlyRET73B3 unobserved/RAW,unsupported.',['provisional','partial','partial']),
 0x7903:(0x793c,'Saved selector/index field emission','Save E atAE01 then C atAE00. Fresh AE01 SUI6,SUI1,SBB yields equality6 mask atADCA. Fresh AE00 CPI C1. If C1,freshADCA RAR;setCY arm unsupported;clearCY fresh AE01 intoC,canonical73A7. Then freshAE00 intoC,fresh pairedAE01 intoDE,canonical75CE;RET actual state. C1/E6 RAW branch excluded.',['provisional','partial','partial']),
 0x79b6:(0x79be,'Fixed C5/E4 emission adapter','Literal E4,C C5;canonical7903;RET actual state. Constants encoded at entry,not high-level item names.',['stable','complete','partial']),
 0x7a17:(0x7a4e,'Fresh AE04 pending-gate drain','Retain clearAE04 earlyRET. Fresh nonzeroAE04 reread andCPI1;only1 supported. Canonical79B6 then freshAE05 CPI2;onlynot2 route supported. Publish AE04=0 then fresh DCR byte[AE06],wrapping8bits;returnedA/BC/DE remain actual child/comparison state;HL=AE06;NZPA fromDCR,CY fromCPI2. Other AE04 values,AE05=2 alternatives RAW/unsupported.',['provisional','partial','partial']),
 0x7ac4:(0x7ad4,'Saved selector seven gate','Save C atAE08;freshly read andCPI7;equal calls canonical79E2,otherwiseRET comparison state. AE05 nonzero child unsupported.',['stable','complete','partial']),
 0x7ad4:(0x7ae4,'Saved selector four gate','Save C atAE09;freshly read andCPI4;equal calls canonical7A17,otherwiseRET comparison state.',['stable','complete','partial']),
 0x7ae4:(0x7b02,'Saved selector pending-generation policy','Save C atAE0A. Independent paired reloadsAE0A/AE0B transferL intoC before canonical7AC4 and7AD4. Fresh LDA AE0A,CPI5;equal canonical7A17,otherwiseRET actual comparison state. AE04/AE05 independently fresh gates;one selector decides7/4/5 calls,not caller/source.',['stable','complete','partial'])}
 laws={f'PLI2.OVL+{x:04X}':dict(end=e,description=d,contract=c+' Copied staging validates immutable code,originalCALL/continuation,nonalias scratch/stack/output state;inherited successful writer/nonzero position/clear201D scopes. Unsupported route rejects before live mutation.',completeness=z)for x,(e,d,c,z)in scopes.items()}
 save(REPORT/'contract-laws-PLI2.OVL.json',laws)
 save(OUT/'annotation-rows-PLI2.OVL.json',{source:{k:g[k]for k in laws}for source,g in rows.items()})
 topology()
def reports():
 import subprocess
 load=lambda p:json.loads(Path(p).read_text());raw=load(OUT/'rows.json');laws=load(REPORT/'contract-laws-PLI2.OVL.json');proof=OUT/'proof';natural=load(proof/'natural-cases.json');post=load(proof/'cumulative-hybrid-summary.json');top=load(REPORT/'topology-summary.json')
 shadow=[];hierarchy=[];routes={};checkpoints={}
 for r,h in zip(natural['sources'],post['sources']):
  source=r['source'];shadow.append(dict(source=source,entries=[dict(coordinate=f"PLI2.OVL+{e['offset']:04X}",cases=len(e['members']),proof_hash=digest(e['members']))for e in r['entries']]))
  g=top[source];assert h['result']['host_transitions']-sum(h['pre_transition_vector'])==g['net_host_delta']
  hierarchy.append(dict(source=source,roots=g['external'],absorbed=g['absorbed'],pre_guest=h['pre_guest_instructions'],post_guest=h['result']['actual_guest_instructions'],saved=h['guest_instructions_removed'],pre_host=sum(h['pre_transition_vector']),post_host=h['result']['host_transitions'],net_host_delta=g['net_host_delta'],remaining=g['remaining']))
  rs=raw[source]['PLI2.OVL+7AE4'];routes[source]=dict(selectors=dict(collections.Counter(str(z['entry']['before']['c'])for z in rs)),nonzero_drains=sum(any(w['origin']['offset']==0x7afe for w in z['own_witnesses'])for z in rs))
  for z in rs:z['nested_returns']={int(k):v for k,v in z['nested_returns'].items()}
  points=[dict(call=z['call']['step_index'],children=children_any(z),fresh_reads=[dict(site=w['origin']['offset'],reads=w['reads'])for w in z['own_witnesses']if w['origin']['offset']in[0x7ae8,0x7aef,0x7af6]])for z in rs];save(OUT/('checkpoints-'+source+'.json'),points);checkpoints[source]=digest(points)
 save(REPORT/'shadow-summary.json',dict(all_passed=True,sources=shadow,components=load(proof/'component-shadows.json'),child_checkpoint_hashes=checkpoints,comparison=['all registers/flags/SP/PC','ordered logical writes','65536 RAM bytes','final stack last writers','exact child CALL chronology','DMA/filesystem','record and service boundary chronology'],synthetic=['selectors7/4/5 select actual gates','AE04 0/1 vs unsupported2','AE05 nonzero seven-gate rejection','fresh AE06 wrapping decrement at0/1','cursor127:7','immutable code/continuation/scratch/stack rejection']))
 save(REPORT/'hierarchy-summary.json',dict(sources=hierarchy,suppression='Only exact corrected7AE4 windows internalize children;no global leaf interception. The cost of24 new parent transitions replaces3 existing75CE roots;net +21 across corpus,explicitly reported.'))
 for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:save(REPORT/name,load(proof/name))
 baseline=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/manifest.json']));cur=load('research/annotated-assembly/manifest.json');im=lambda m:next(i for i in m['images']if i['name']=='PLI2.OVL');oldim=im(baseline);newim=im(cur);status=lambda im,a:next(q['status']for q in im['sections']if q['start_offset']<=a<q['end_offset']);counts={};total=collections.Counter()
 for k,law in laws.items():
  c=collections.Counter(status(oldim,a)for a in range(int(k.split('+')[1],16),law['end'])if status(newim,a)=='UNDERSTOOD'and status(oldim,a)!='UNDERSTOOD');counts[k]=dict(c);total.update(c)
 save(REPORT/'fidelity.json',dict(archaeological_scope_extension=True,promotions=dict(total),by_contract=counts,historical_correction=None,discovery_coordinate_correction='7AD0 is CALL site inside7AC4;7ABE is internal reset block inside7AA3,not naturally called entries.',implementation_correction=['Development7903 cross-case CALL corrected from75A7 to actual73A7 before successful component proof.','Synthetic final DCR assertion scoped to selector5;selector4 correctly has later CPI5 flags.','Development reports-phase dispatch mistakenly ran a redundant proof;corrected before aggregate validation.'],pragmatic_divergence=None,fidelity_debt=None,oracle_queries=0,cpu_runner_cpm_changes=False,proof_schema_redesign=False,interactive_call_count='not instrumented',scripts_view_optimist_untouched=True))
 boundary=dict(selected='PLI2.OVL+7AE4',extent=[0x7ae4,0x7b02],anchors={'7AD0':'valid CALL instruction,not observed entry;owner7AC4','7ABE':'valid LXI instruction/internal block,not observed entry;owner7AA3'},candidates={'7AC4':'only selector7 gate;subsumed by7AE4','7AD4':'only selector4 gate;subsumed by7AE4','7AE4':'one saved-selector pending policy;selected','7AA3':'separate state transition through79BE/7903;used cross-evidence,not artificial merged root','7B99':'adds two independentADAB/ADB3 indexed transfers via793C plus field emission;defer coherent transfer transaction','7E05':'independent AE36/37,ADAA,202B masks;7314 transform and repeated fields;distinct broader generation policy'},economics='24 new roots absorb3 formerly-native75CE roots. Guest savings confirmed798;host boundaries+21. No serializer leaf explosion or unproved higher parent.',next='Assess7B99/793C indexed carrier-transfer and emission transaction;7E05 is separate broader gated generation.')
 save(REPORT/'boundary-assessment.json',boundary)
 semantic=dict(historical_root='PLI2.OVL+7AE4',semantic_inputs=['byte selector','fresh pending gate AE04','fresh preparation gate AE05','pending count AE06','current output cursor/position where emission occurs'],semantic_outputs=['selector-dependent pending-generation preparation','conditional fixedC5/E4 field emission','pending gate clear and wrapping count decrement'],shared_historical_state=['AE08,AE09,AE0A selector carriers;paired readAE0B','AE04,AE05,AE06 independent gates/count','AE00,AE01,ADCA;output caches,1C2C andREL buffer'],historical_mechanism=['register transfer from independently paired LHLD reads','CPI literals7/4/5 select child policy','SUI/SUI/SBB equality mask in7903','hardware CALL words and final stack residue','fresh DCR flags retained only when no later comparison overwrites them'],candidate_modern_operation='Prepare pending generation according to byte selector',confidence=dict(semantic_inputs='OBSERVED',semantic_outputs='DEDUCED low-level effects;pending terminology descriptive',shared_historical_state='OBSERVED',historical_mechanism='OBSERVED/DEDUCED',candidate_modern_operation='HYPOTHESIS'),mir_relevance='May inform a future stateful emission policy operation;no MIR API or code refactor implied.')
 save(REPORT/'semantic-extraction.json',semantic)
 cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};prior=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))
 for p in prior['procedures']:
  for source,n in p['observed_paths']['invocations_by_run'].items():assert cat[p['id']]['observed_paths']['invocations_by_run'].get(source,0)>=n
 packet=dict(task='PLI2_PENDING_GENERATION_DISCOVERY_PASS_57',baseline=BASE,selected=boundary,laws=laws,topology=top,route_classes=routes,proofs=shadow,checkpoints=checkpoints,promotions=dict(total),reused_contracts={k:dict(hash=digest(cat[k]),completeness=cat[k]['completeness'])for k in['PLI2.OVL+79E2','PLI2.OVL+75CE','PLI2.OVL+7557','PLI2.OVL+753C','PLI.COM+119E','PLI.COM+1140']},AE04_AE05='Independent fresh gates,not interchangeable. AE05 stays0 across all79E2 natural calls. AE04=1 drains viafixedC5/E4;freshAE05!=2 thenAE04 clear beforeAE06 decrement. No proof of arbitrary global state machine.',oracle_queries=0)
 save(REPORT/'implementation-packet.json',packet);size=(REPORT/'implementation-packet.json').stat().st_size;assert size<=28672
 table='\n'.join(f"|{h['source']}|{h['pre_guest']}|{h['post_guest']}|{h['saved']}|{h['pre_host']} → {h['post_host']}|{h['roots']}|"for h in hierarchy)
 (REPORT/'README.md').write_text(f"""# Pass57 — saved-selector pending-generation policy

Baseline `{BASE}` is published Pass56/FULL checkpoint. Pass57 is incremental.

Discovery establishes naturally called +7AC4 [7AC4,7AD4),+7AD4 [7AD4,7AE4),+7AE4 [7AE4,7B02). +7AD0 is the CALL79E2 inside7AC4,not an observed entry. +7ABE is an LXI/internal reset block in7AA3,not an observed entry. This corrects search-anchor terminology,not historical behavior. Full execution-owned CFGs/journals are ignored under `_build/host-compiler-pass-57`.

Selected7AE4 has2/21/1 logical and external calls. Save C atAE0A;fresh paired reload includingAE0B andtransfer low before7AC4;independent reread before7AD4;fresh LDA/CPI5 before optional7A17. 7AC4 independently publishesAE08 thenCPI7 andequal79E2;7AD4 publishesAE09 thenCPI4 andequal7A17. Selector distribution and actual child checkpoints are in packet. No caller/source dispatch.

All natural79E2 calls remainAE05=0;no nonzero extension needed. FreshAE04-zero7A17 unchanged. Three FIZZBUZ AE04=1 cases fresh-reread/compare1,call79B6(E4,C C5) then7903,independently readAE05 andcompare2;non2 path publishesAE04=0,then fresh wrappingDCR AE06. DCR produces NZPA;CY survivesCPI2. Parent may overwrite those flags with laterCPI5 on selector4. AE04 andAE05 are independent gates;no speculative global state-machine/item semantics.

7903 savesE/C atAE01/AE00,derives equality6 mask atADCA,freshCPI C1,conditionally rereads maskRAR. C1 with clear mask calls73A7;then independent savedC/E reloads feedcanonical75CE. C1/E6 alternative unsupported. All6 natural cross-cases proved,including3C1/E2 outside selected roots. 73A7 saves indexADC3,compares6,supportednon6 route calls7397 with fresh low index,then fresh LDA/INR andcalls7397 again. 7397 savesADC2,pairedreadsADC2/ADC3,discardsH,addsADAB,publishes0 atactualindexed carrier. Index<8 scope;index6 early73A7 RET remainsRAW/unaccepted.

New/extended contracts:7397,73A7,7903,79B6,7A17,7AC4,7AD4,7AE4. Natural component counts and proofs in shadow-summary.json. Root and independent components compare allregs/flags/SP/PC,orderedwrites,full64KiBRAM,derivedstacklastwriters,childCALLchronology,DMA/FS,record/servicechronology. Original CALL words survive;no private frame invented. Synthetic gates,selectors,wrappingcounter,recordboundary,code/continuation/aliases checked in copiedstaging. Unsupported routes reject without live mutation.

7B99 adds independent indexedADAB/ADB3 transfer through793C;7E05 adds broaderAE36/37,ADAA/202B gates and7314transform. Both deferred rather than constructing an artificial ancestor. 7AA3 separate reset/transfer policy remains guest;its7903 calls provide anti-overfitting evidence.

|Source|Pass56 guest|Pass57 guest|Removed|Host pre → post|Roots|
|---|---:|---:|---:|---:|---:|
{table}

Actual savings798,net host+21:24 parent roots replace3 formerlyexternal75CE roots. This explicitly modest tradeoff closes a pending-state law without globally intercepting helpers/serializers or claiming a higher unproved generation transaction. All contained lower operations internal;same operations elsewhere remain enabled. +79E2 remaining0/0/0;7A17 remaining1/10/3;73D0 remaining5/26/5;7AE4 remaining0/0/0;external119E unchanged36/36/43. Caller distribution in topology-summary.json.

Standalone andcumulative hybrids preserve exactRELgoldens,REL/INTchronology,FS,console,PASS1/PASS2/END,BDOS ordering/counts andwarmboot. Promotions {dict(total)};DECODED/STRUCTURED0. Exact historical image94720bytes. Zero oraclequeries. Scopeextension;historicalcorrection/divergence/fidelitydebt:none. Development implementation corrections separated in fidelity.json. Historical FACTOR/OPTIMIST catalog totals retained.

Packet{size}bytes. Driver automates entrydiscovery,correctedwindows,CFG/caller/routegroups,component/root/hybridproof,transition/residualmaps,contract/compactreport generation andincremental aggregate. Interactive callcount notinstrumented. Semantic-extraction.json documents only this selected parent's possible clean operation and historical mechanisms;no refactor/MIR design.

Next assess7B99/793C indexedcarriertransfer/emission;broader7E05 remainsseparate. scripts/view-optimist.sh untouched. Validation receipt records final aggregate outcome.
""")
 save(REPORT/'validation.json',dict(validation_tier='INCREMENTAL',full_checkpoint_base=BASE,status='ready for aggregate',reruns=[],historical_bytes=94720))
 print('reports finalized;packet',size)
def validate():
 import subprocess
 dest=OUT/'incremental-validation';categories='pass57,pass56,pass55,pass54,pass53,pass52,pass24,packet-continuation,V1,roundtrip,roundtrip-tests,dynamic-progress,diff-check'
 r=subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images','/home/john/pli/cpm/pli80/DISK1','--output',str(dest),'--workers','4','--categories',categories])
 receipt=json.loads((dest/'results.json').read_text());v=json.loads((REPORT/'validation.json').read_text());v.update(status='passed initially'if receipt['all_passed']else'initial validation failed',initial_all_passed=receipt['all_passed'],all_passed=receipt['all_passed'],categories=receipt['categories'],category_count=len(receipt['categories']),python_test_count=sum(q['python_tests']for q in receipt['categories'].values()),dune_test_rule_stanzas=39,workers=4,wall_seconds=receipt['wall_seconds'],summed_category_seconds=receipt['sum_category_seconds'],slowest_categories=receipt['top_10_slowest']);save(REPORT/'validation.json',v);assert r.returncode==0
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['discovery','topology','contracts','components','prove','reports','validate']);a=p.parse_args()
 if a.phase in ['components','prove']:prove(focused=a.phase=='components')
 else:globals()[a.phase]()
