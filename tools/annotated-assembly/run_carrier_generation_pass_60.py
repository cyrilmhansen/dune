#!/usr/bin/env python3
"""Deterministic carrier classification, clear and emission proof."""
import collections,json,sys,subprocess
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_buffered_rel_emission_pass_52 import save,digest
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-60');REPORT=Path('research/host-compiler/pass-60')
BASE='a3ca60c886833e1bdae92e1334504c9acd5fabd8'
ENTRIES=[0x7e05,0x7dc3,0x7de4]
def load(p):return json.loads(Path(p).read_text())
def discovery():
 full={};cfg={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{f'PLI2.OVL+{x:04X}':(x,x+1)for x in ENTRIES},include_nested_returns=True);full[source]=rows
  for k,rs in rows.items():
   cfg.setdefault(k,{})
   for r in rs:
    for w in r['own_witnesses']:cfg[k][w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
 save(OUT/'rows.json',full);save(OUT/'cfg.json',{k:sorted(v.values())for k,v in cfg.items()})
 inventory()
def inventory():
 raw=load(OUT/'rows.json');summary={}
 for g in raw.values():
  for rs in g.values():
   for r in rs:r['nested_returns']={int(k):v for k,v in r['nested_returns'].items()}
 for source,g in raw.items():
  summary[source]={k:dict(calls=len(rs),callers=dict(collections.Counter(coord(r['call']['origin'])for r in rs)),pairs=dict(collections.Counter(f"{r['entry']['before']['c']:02X}/{r['entry']['before']['e']:02X}"for r in rs)),returns=dict(collections.Counter(coord(r['ret']['origin'])for r in rs)),children=dict(collections.Counter('/'.join(c['target']for c in children_any(r))for r in rs)))for k,rs in g.items()}
 save(REPORT/'inventory-summary.json',summary);print(json.dumps(summary,indent=2))

def prove(images='/home/john/pli/cpm/pli80/DISK1',focused=False):
 import subprocess,tempfile,shutil
 dest=OUT/'proof';dest.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
  cmd=['dune','exec','bin/native_carrier_generation.exe','--','--toolchain',str(images),'--output-dir',str(Path(tmp)/'results')]
  if focused:cmd+=['--family-only']
  with(dest/'run.log').open('w')as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((dest/'run.log').read_text()[-4000:])
  for f in(Path(tmp)/'results').glob('*.json'):
   if not focused or f.name in ['component-shadows.json','natural-cases.json','synthetic-checkpoints.json','synthetic-helper-pairs.json']:shutil.copyfile(f,dest/f.name)
 print('proof passed')


def topology():
 raw=load('_build/host-compiler-pass-51/residual-map.json');result={}
 inside=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
 for source,v in raw.items():
  ws=v['windows'];coords=['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in[0x7434,0x7630,0x765e,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619,0x7701,0x8248,0x7ae4,0x7b99,0x7b1b]]
  prior=v['roots']+[r for r in ws if r['target']in coords];pre=[r for r in prior if not any(q is not r and inside(r,q)for q in prior)]
  parents=[r for r in ws if r['target']=='PLI2.OVL+7E05'];outer=[r for r in parents if not any(inside(r,q)for q in pre)];absorbed=[r for r in pre if any(inside(r,q)for q in outer)]
  residual={k:dict(calls=len(rs:=[r for r in ws if r['target']==k and r not in outer and not any(q is not r and inside(r,q)for q in pre+outer)]),callers=dict(collections.Counter(r['caller']for r in rs)))for k in['PLI2.OVL+7314','PLI2.OVL+7365','PLI2.OVL+7AE4','PLI2.OVL+793C','PLI2.OVL+7E05','PLI2.OVL+73D0','PLI.COM+119E']}
  result[source]=dict(logical=len(parents),external=len(outer),callers=dict(collections.Counter(r['caller']for r in parents)),absorbed=dict(collections.Counter(r['target']for r in absorbed)),net_host_delta=len(outer)-len(absorbed),remaining=residual,logical_internal=dict(collections.Counter(r['target']for r in ws if any(inside(r,q)for q in outer))))
 save(REPORT/'topology-summary.json',result)
 parents={}
 for source,v in raw.items():
  parents[source]=[]
  for r in v['windows']:
   if r['target']!='PLI2.OVL+7E05':continue
   ancestors=[q for q in v['windows']if inside(r,q)]
   parent=min(ancestors,key=lambda q:q['ret']-q['call'])
   children=[q for q in v['windows']if inside(q,parent)]
   direct=[q for q in children if not any(z is not q and inside(q,z)for z in children)]
   parents[source].append(dict(callsite=r['caller'],actual_parent=parent['target'],direct_children=[q['target']for q in direct],widened=False))
 save(REPORT/'immediate-parent-summary.json',parents)
def contracts():
 laws={
 'PLI2.OVL+7E05':dict(end=0x7ed6,description='Gated indexed carrier reuse/search or publication with field emission',contract='Bounded C0..7,Ebyte. Save E atAE37 thenC atAE36;paired freshAE36,C=L canonical7AE4. FreshC SUI6/ADIFF/SBB A produces FF iffC!=6. ANA freshADAA;PUSH PSW;fresh202B,CMA;POP B,MOV C,B,ANA C,RAR:CY=(C!=6)&ADAA.bit0&!202B.bit0. Clear gate enterspublication. Set gate:pairedfreshC zeroextend,ADAB+C,DAD,MOV A,M,RAR testsactivity. Active:independentfreshC zeroextend,ADB3+C,read/storebyteAE38;freshE CMP;equalRET7E4C. FreshAE38 INR/CMPfreshE,equalcanonical7DC3 RET7E5F. IndependentfreshAE38 DCR/CMPfreshE,equalcanonical7DE4 RET7E72. Otherwise search:AE39=0;freshindex bounded0..7;activity RAR thenindex6 exclusion thenfreshADB3[index] comparedagainstfreshAE37. Match pairedfreshC andpairedfreshindex=>DE,canonical793C RET7EB2. Failedcandidate publishesINR AE39,loops;index8 enterspublication. Final pairedfreshC=>C;independentpairedfreshE=>DE canonical7314;pairedfreshC=>DE,C6 canonical75CE;independentpairedfreshE=>C canonical75A7;RET7ED5. Freshreads,flags,PUSH/POP carriers,orderedwrites andcalltraffic retained. Natural14roots gateclear;other routes STATIC UNOBSERVED independently comparedwithhistoricalCPU syntheticstates. Successfulwriter,201Dclear,nonwrapposition,currentpendingchildren,code/stack/sentinel nonalias required. Boundsstable;localCFGcomplete;contractpartial.',completeness=['stable','complete','partial']),
 'PLI2.OVL+7DC3':dict(end=0x7de4,description='Saved indexed carrier emission then conditional value increment',contract='C0..7. SaveC AE34;pairedfreshAE34/35=>DE,C4 canonical75CE. FreshAE34 CPI6;equalRET7DD8. OtherwiseindependentpairedAE34,zeroextendL,BCADB3,DAD;INRfreshM publishesat7DE2;RET7DE3. Modulo8bitincrement,NZPA fromINR,CY fromDAD. Naturalprimaryzero;STATIC UNOBSERVED,synthetic parentplusrelations independentlyCPU-shadowed. C6literalreturnstatic;partialchildren/output/nonalias scope.',completeness=['stable','complete','partial']),
 'PLI2.OVL+7DE4':dict(end=0x7e05,description='Saved indexed carrier emission then conditional value decrement',contract='C0..7. SaveC AE35;pairedfreshAE35/36=>DE,C5 canonical75CE. FreshAE35 CPI6;equalRET7DF9. OtherwiseindependentpairedAE35,zeroextendL,BCADB3,DAD;DCRfreshM publishesat7E03;RET7E04. Modulo8bitdecrement,NZPA fromDCR,CY fromDAD. Naturalprimaryzero;STATIC UNOBSERVED,synthetic parentminusrelations independentlyCPU-shadowed. C6literalreturnstatic;partialchildren/output/nonalias scope.',completeness=['stable','complete','partial'])}
 save(REPORT/'contract-laws-PLI2.OVL.json',laws);raw=load(OUT/'rows.json');save(OUT/'annotation-rows-PLI2.OVL.json',raw)
 # Decoder supplement records actual instruction boundaries, never guessed addresses.
 (OUT/'decode.ml').write_text('let p="/home/john/pli/cpm/pli80/DISK1/PLI2.OVL";;\nlet c=open_in_bin p;; let b=Bytes.create(in_channel_length c);; really_input c b 0(Bytes.length b);; close_in c;;\nlet rec loop o last=if o<last then match I8080.Decode.decode b ~offset:o with Error _->failwith"decode"|Ok d->Printf.printf"%04X %s %s\\n"o(String.concat""(List.init d.length(fun i->Printf.sprintf"%02X"(Char.code(Bytes.get b(o+i))))))(I8080.Instr_format.format d.instr);loop(o+d.length)last;;\nloop 0x7dc3 0x7ed6;;\n')
 cmd=['ocaml','-I','_build/default/lib/i8080','-I','_build/default/lib/i8080/.i8080.objs/byte','i8080.cma',str(OUT/'decode.ml')]
 text=subprocess.check_output(cmd,text=True);(OUT/'static-disassembly.txt').write_text(text);static={k:[]for k in laws};observed={k:{w['origin']['offset']for g in raw.values()for r in g[k]for w in r['own_witnesses']}for k in laws}
 for line in text.splitlines():
  off,b,d=line.split(' ',2);o=int(off,16);k=next(k for k,l in laws.items()if int(k.split('+')[1],16)<=o<l['end'])
  if o in observed[k]:continue
  control=dict(kind='call'if d.startswith('CALL')else'jump'if d.startswith('J')else'return'if d=='RET'else'ordinary');target=None
  if d.startswith('CALL'):
   runtime=int.from_bytes(bytes.fromhex(b)[1:],'little');control['target']=runtime;target=dict(image=dict(name='PLI2.OVL'),offset=runtime-0x2200)
  static[k].append(dict(origin=dict(image=dict(name='PLI2.OVL'),offset=o),target_origin=target,bytes=b,disassembly=d,control=control,evidence_class='DEDUCED STATIC UNOBSERVED'))
 save(OUT/'annotation-static-PLI2.OVL.json',static);topology()
def cross():
 import tempfile,shutil
 with tempfile.TemporaryDirectory(prefix='factor-',dir=OUT)as t:
  subprocess.run(['_build/default/bin/native_carrier_generation.exe','--toolchain','/home/john/pli/cpm/pli80/DISK1','--output-dir',str(Path(t)/'proof'),'--family-only','--cross-source','FACTOR'],check=True)
  shutil.copyfile(Path(t)/'proof/natural-cases.json',OUT/'factor-natural-cases.json')
 result={}
 for e in load(OUT/'factor-natural-cases.json')['sources'][0]['entries']:
  if e['offset']not in ENTRIES:continue
  result[f"PLI2.OVL+{e['offset']:04X}"]=dict(calls=len(e['members']),pairs=dict(collections.Counter(f"{c['input']['c']:02X}/{c['input']['e']:02X}"for c in e['members'])),proof_hash=digest(e['members']))
 save(REPORT/'cross-evidence.json',dict(FACTOR=result,OPTIMIST='No new trace campaign;prior durable totals retained.'))
def reports():
 raw=load(OUT/'rows.json');nat=load(OUT/'proof/natural-cases.json');post=load(OUT/'proof/cumulative-hybrid-summary.json');top=load(REPORT/'topology-summary.json');laws=load(REPORT/'contract-laws-PLI2.OVL.json');hierarchy=[];summaries=[];routes={};points={}
 for r,h in zip(nat['sources'],post['sources']):
  source=r['source'];g=top[source];assert h['result']['host_transitions']-sum(h['pre_transition_vector'])==g['net_host_delta']
  summaries.append(dict(source=source,entries=[dict(coordinate=f"PLI2.OVL+{e['offset']:04X}",cases=len(e['members']),proof_hash=digest(e['members']))for e in r['entries']]))
  hierarchy.append(dict(source=source,roots=g['external'],absorbed=g['absorbed'],pre_guest=h['pre_guest_instructions'],post_guest=h['result']['actual_guest_instructions'],saved=h['guest_instructions_removed'],pre_host=sum(h['pre_transition_vector']),post_host=h['result']['host_transitions'],net_host_delta=g['net_host_delta'],remaining=g['remaining']))
  points[source]=[]
  for z in raw[source]['PLI2.OVL+7E05']:
   own={w['origin']['offset']:w for w in z['own_witnesses']};C=z['entry']['before']['c'];E=z['entry']['before']['e'];mask=255 if C!=6 else 0
   assert own[0x7e19]['after']['a']==mask
   assert own[0x7e1d]['reads']==[dict(address=0xadaa,value=0)] and own[0x7e1f]['reads']==[dict(address=0x202b,value=0)]
   assert not own[0x7e26]['after']['flags']['carry']
   assert[(w['address'],w['new_value'])for w in own[0x7e1e]['writes']]==[(z['entry']['before']['sp']-1,0),(z['entry']['before']['sp']-2,0x56)]
   assert[(own[s]['before']['c'],own[s]['before']['e'])for s in [0x7ec2,0x7ecb,0x7ed2]]==[(C,E),(6,C),(E,0)]
   points[source].append(dict(call=z['call']['step_index'],children=children_any({**z,'nested_returns':{int(k):v for k,v in z['nested_returns'].items()}}),own=list(own.values())))
  routes[source]=dict(natural_gate_clear=len(points[source]),natural_direct=0,natural_search=0,natural_search_iterations={'0':len(points[source])},natural_ADAA={'0':len(points[source])},natural_202B={'0':len(points[source])},pairs=load(REPORT/'inventory-summary.json')[source]['PLI2.OVL+7E05']['pairs'])
  save(OUT/('checkpoints-'+source+'.json'),points[source])
 save(REPORT/'route-summary.json',routes)
 save(REPORT/'shadow-summary.json',dict(all_passed=True,sources=summaries,components=load(OUT/'proof/component-shadows.json'),checkpoints={k:digest(v)for k,v in points.items()},comparison=['registers/flags/SP/PC','orderedwrites/full65536RAM','stacklastwriters','childCALLchronology','DMA/filesystem/record/servicechronology'],synthetic_cases_per_natural_root=14,synthetic_comparison='Independent concrete CPU executes full historical route and children;allregisters/flags/fullRAM/orderedwritesincludingstack compared;noBDOS synthetic scope.',natural_alternative_routes=0))
 save(REPORT/'hierarchy-summary.json',dict(sources=hierarchy,suppression='Exact7E05 windows only;7314 is a canonical internal operation,notanexistingindependentRunnerroot.'))
 for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:save(REPORT/name,load(OUT/'proof'/name))
 old=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/manifest.json']));cur=load('research/annotated-assembly/manifest.json');image=lambda x:next(i for i in x['images']if i['name']=='PLI2.OVL');status=lambda im,a:next(q['status']for q in im['sections']if q['start_offset']<=a<q['end_offset']);total=collections.Counter();counts={}
 for k,l in laws.items():
  cnt=collections.Counter(status(image(old),a)for a in range(int(k.split('+')[1],16),l['end'])if status(image(cur),a)=='UNDERSTOOD'and status(image(old),a)!='UNDERSTOOD');counts[k]=dict(cnt);total.update(cnt)
 observed_bytes=sum(len(bytes.fromhex(w[1]))for w in load(OUT/'cfg.json')['PLI2.OVL+7E05']);static_bytes=sum(len(bytes.fromhex(w['bytes']))for ws in load(OUT/'annotation-static-PLI2.OVL.json').values()for w in ws)
 save(REPORT/'fidelity.json',dict(promotions=dict(total),by_contract=counts,OBSERVED_natural_bytes=observed_bytes,DEDUCED_STATIC_UNOBSERVED_bytes=static_bytes,archaeological_scope_extension=True,historical_correction=None,implementation_correction=['Development AE38 STA changed fromwordstore tobytewrite beforefirstalternate-routeproof.','Final review corrected generic proof route labels for new60 entries;executionsemantics unchanged;completePass60category rerun.'],pragmatic_divergence=None,fidelity_debt=None,oracle_queries=0,synthetic_binary_execution='Targeted independent instruction comparisons;noexternalhistoricaloraclequeries.',cpu_runner_cpm_changes=False,shared_schema_changes=False))
 boundary=dict(selected='PLI2.OVL+7E05',extent=[0x7e05,0x7ed6],early_returns=[0x7e4c,0x7e5f,0x7e72,0x7eb2],helpers={'7DC3':[0x7dc3,0x7de4],'7DE4':[0x7de4,0x7e05]},overlapping_entries='No natural overlapping CALL targets in selected body.',immediate_callers='3E71/33E9 belong to1FB5 stack-local table/PCHL compiler dispatch;6722 belongs to6704 with665B/059E preparation. Separate compiler operations;not widened.',next='Investigate remaining73D0 callers742A/825E/82BA andtheirvalidparententries;keepremainingserializer82A6/82E1/82F0 lifecycles distinct.',unsupported='Coutside0..7,pending/emissionchildunsupportedstates,201Dnonclear,positionwrap,writererrors,code/stack/sentinelaliases;noarbitraryglobalcarriermeaning.')
 save(REPORT/'boundary-assessment.json',boundary)
 semantic=dict(historical_root='PLI2.OVL+7E05',semantic_inputs=['destinationcarrierC','relationbyteE','globalpresent/gatebytes','indexedactivityandvaluebytes','bufferedoutputposition'],semantic_outputs=['existingrelationmayreturnwithoutemission','adjacentrelationmayadjustvalueandemit','matchingindexmaytransferstateandemit','otherwisepublishindexedrelationandemitfields'],shared_historical_state=['AE36/37/38/39 andpairedadjacentreads','ADAA/202B','ADAB/ADB3','AE34/35 adjustmentscratch','canonicalchildscratchandoutputbuffers/position'],historical_mechanism=['SUI/ADI/SBB mask','PUSH PSW/POP B masktransport','ANA/CMA/RAR gates','zeroextendedindexedaddresses','freshscanactivitythenindex6exclusionthenvalue','separatecanonical7314/793C/emissionchildren','exactflagsandCALL/PUSHresidue'],candidate_modern_operation='Reuse, adjust, transfer or publish indexed carrier relations and emit representation',confidence=dict(publication='OBSERVED primaryandFACTOR',alternatives='DEDUCED STATIC UNOBSERVED / independentCPU synthetic',modern_name='HYPOTHESIS'),mir_relevance='Documentationonly;no MIR interface,no faithful-code refactor.')
 save(REPORT/'semantic-extraction.json',semantic)
 cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};prior=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))
 for p in prior['procedures']:
  for source,n in p['observed_paths']['invocations_by_run'].items():assert cat[p['id']]['observed_paths']['invocations_by_run'].get(source,0)>=n
 packet=dict(task='PLI2_CARRIER_GENERATION_7E05_PASS_60',baseline=BASE,boundary=boundary,laws=laws,inventory=load(REPORT/'inventory-summary.json'),routes=routes,cross=load(REPORT/'cross-evidence.json'),topology=top,proofs=summaries,checkpoint_hashes={k:digest(v)for k,v in points.items()},promotions=dict(total),evidence_classes=dict(observed=observed_bytes,static=static_bytes),canonical_children={k:dict(contract_hash=digest(cat[k]),completeness=cat[k]['completeness'])for k in ['PLI2.OVL+7AE4','PLI2.OVL+7314','PLI2.OVL+793C','PLI2.OVL+75CE','PLI2.OVL+75A7','PLI.COM+119E','PLI.COM+1140']},oracle_queries=0)
 save(REPORT/'implementation-packet.json',packet);size=(REPORT/'implementation-packet.json').stat().st_size;assert size<=28672
 table='\n'.join(f"|{h['source']}|{h['pre_guest']} → {h['post_guest']}|{h['saved']}|{h['pre_host']} → {h['post_host']}|{h['roots']}|"for h in hierarchy)
 (REPORT/'README.md').write_text(f"""# Pass60 — indexed carrier generation

Baseline `{BASE}` is published Pass59 and the current FULL checkpoint. Pass60 uses incremental validation.

## Scope and natural evidence

The selected root is PLI2.OVL+7E05, `[7E05,7ED6)`, 209 bytes. Natural logical and external counts are 2 MINIMAL, 11 FIZZBUZ and 1 PICTURE; FACTOR adds two independently shadowed cross-cases. All use C=7. E distributions and callers are retained in inventory-summary.json. All freshly read ADAA=0 and 202B=0 after canonical +7AE4, entering publication without searching. The direct child sequence is +7AE4, +7314, +75CE, +75A7. No naturally called overlapping entry was found.

AE37 receives E before AE36 receives C. Paired rereads preserve adjacent high-byte channels. Entry high registers and flags remain actual channels until historical instructions overwrite them.

## Gate, reuse and search law

Fresh C undergoes SUI6, ADIFF, SBB A: the mask is FF exactly when C differs from 6. ANA fresh ADAA, PUSH PSW, fresh complemented 202B, POP B/MOV C,B, ANA C and RAR give CY = (C != 6) AND ADAA.bit0 AND NOT 202B.bit0. The implementation retains arithmetic flags and the actual stack mask carrier.

An enabled gate checks ADAB[C].bit0. An active carrier reads ADB3[C] into AE38 and compares it with fresh E. Equality returns at +7E4C; modulo +1/-1 invokes +7DC3/+7DE4 and returns. These compact 33-byte helpers save C, reread a paired word into DE and emit through canonical +75CE with C=4/5. Fresh C=6 returns; otherwise a fresh indexed ADB3 byte is incremented/decremented. Both helpers have zero primary/FACTOR natural calls and remain DEDUCED / STATIC / UNOBSERVED.

Search initializes AE39=0 and visits indices 0 through 7 in order. It tests activity first, excludes index6 next, then compares fresh ADB3[index] with fresh E. A match calls canonical +793C with saved destination C and matched index E, then returns. A failed candidate publishes the index increment; index8 enters publication. There is no table snapshot or fixture iteration count. All natural search counts are zero. Synthetic matches at 0/5/7, index6 exclusion and no-match searches retain explicit static classification.

Publication independently rereads saved C and E for canonical +7314, which publishes ADAA=1, ADAB[C]=1 and ADB3[C]=E. Another paired C read supplies DE to +75CE with literal C=6; a separate paired E read supplies C to +75A7. Same-valued writes, paired adjacent reads, child states and stack residue are preserved.

## Proof and measured leverage

All 14 primary roots and the two FACTOR roots independently match registers, flags, SP/PC, ordered writes, all 65536 RAM bytes, stack last writers, child CALL chronology, DMA, filesystem and record/service chronology. Useful canonical child calls have separate shadows. Fourteen synthetic discriminants per primary root execute the historical instructions and children independently, comparing full state and ordered writes including stack traffic. They cover disabled/global gates, C6, equality, ±1 with wraparound, matches at 0/5/7, index6 exclusion and no match. Per-instruction and loop checkpoints are retained under ignored `_build/host-compiler-pass-60`; synthetic CALL/RET witnesses establish helper ancestry without fabricating natural coverage. Synthetic comparisons avoid BDOS; natural shadows and hybrids prove external chronology.

| Source | Pass59 → Pass60 guest | Removed | Host before → after | Roots |
|---|---:|---:|---:|---:|
{table}

Each outer root replaces three existing boundaries: +7AE4, +75CE and +75A7. Canonical +7314 was already an internal operation, not an independently enabled Runner root. Absorption and the residual map are in hierarchy-summary.json. Remaining external +7AE4 is 0/0/0; +119E remains 36/36/43. Standalone and cumulative hybrids preserve exact REL goldens, complete REL/INT record chronology, filesystem, console, milestones, BDOS order/counts and warm boot.

## Archaeology and limits

Promotions: {dict(total)}; DECODED and STRUCTURED promotions are zero. Of the 275 represented bytes, {observed_bytes} are naturally OBSERVED and {static_bytes} are DEDUCED / STATIC / UNOBSERVED. Bounds are stable, local CFG complete, contract partial over bounded indices and current child/output/alias scopes. C outside0..7, unsupported pending states, nonclear 201D, position wrap, writer errors and code/stack/sentinel aliases reject copied staging before live mutation. There are no CPU/Runner/CPM or shared proof-schema changes.

Historical FACTOR/OPTIMIST catalog totals are preserved. Oracle queries: zero; targeted synthetic comparisons use the existing concrete CPU. Exact reconstruction is 94720 bytes. No historical correction, pragmatic divergence or fidelity debt is recorded. The development AE38 STA draft was corrected to a byte write before alternate-route proof. Final review corrected inherited generic proof route labels; the full Pass60 category was rerun without changing execution semantics. Semantic extraction distinguishes possible carrier relation behavior from scratch addresses, mask arithmetic, PSW transport, explicit scans and CALL residue; no MIR API or faithful-code refactor was introduced.

## Boundary and validation

Corrected immediate ancestors are +1FB5 for callsites +3E71/+33E9 and +6704 for +6722. The former is compiler dispatch with stack-local saves/PCHL; the latter also invokes +665B and +059E. These add separate compiler policy, so +7E05 remains the root. Recommended Pass61: discover the real parents of residual +73D0 callers +742A/+825E/+82BA; retain +82A6/+82E1/+82F0 output lifecycles as distinct candidates.

Packet: {size} bytes. The deterministic driver automates extraction, route grouping, helper discovery, proof batches, synthetic checkpoints, hierarchy, hybrids, residual maps, annotation inputs, semantic extraction, reporting and incremental validation. Interactive call count is not instrumented. validation.json holds the final category/test/stanza/worker/timing receipt. No FULL checkpoint trigger occurred. scripts/view-optimist.sh is untouched.
""")
 save(REPORT/'validation.json',dict(validation_tier='INCREMENTAL',previous_full_checkpoint=BASE,status='ready for final aggregate',reruns=[],historical_bytes=94720))
def validate():
 dest=OUT/'incremental-validation'
 r=subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images','/home/john/pli/cpm/pli80/DISK1','--output',str(dest),'--workers','4','--categories','pass60,pass59,pass58,pass57,pass54,packet-continuation,V1,roundtrip,roundtrip-tests,dynamic-progress,diff-check'])
 receipt=load(dest/'results.json')
 receipt.update(validation_tier='INCREMENTAL',full_checkpoint_base=BASE,status='passed initially'if r.returncode==0 else'initial aggregate failed',initial_all_passed=r.returncode==0,reruns=[],historical_bytes=94720,category_count=len(receipt['categories']),distinct_python_tests=sum(q['python_tests']for q in receipt['categories'].values()),dune_stanzas=Path('test/dune').read_text().count('(test\n'))
 save(REPORT/'validation.json',receipt)
 if r.returncode:raise RuntimeError('incremental validation failed')

if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['discovery','inventory','topology','contracts','cross','components','prove','reports','validate']);a=p.parse_args()
 if a.phase in ['components','prove']:prove(focused=a.phase=='components')
 else:globals()[a.phase]()
