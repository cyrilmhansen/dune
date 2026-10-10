#!/usr/bin/env python3
"""Pass66 +8072 composition discovery/proofs; validation is ACTIVE only."""
import argparse,collections,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_buffered_rel_emission_pass_52 import save,digest
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-66');REPORT=Path('research/host-compiler/pass-66')
BASE='9ce85f006bea3969a23decf975497cd8a20afa04';IMAGES='/home/john/pli/cpm/pli80/DISK1'
BOUNDS={0x8072:0x80b2};EXTRAS=['pass66','pass65']
def load(p):return json.loads(Path(p).read_text())
def discovery():
 rows={s:gather_selected(p,{'PLI2.OVL+8072':(0x8072,0x8073)},include_nested_returns=True)for s,p in CAPTURES.items()}
 save(OUT/'rows.json',rows);inventory()
def inventory():
 rows=load(OUT/'rows.json');summary={};paths={}
 for source,g in rows.items():
  rs=g['PLI2.OVL+8072'];paths[source]=[]
  for r in rs:
   r['nested_returns']={int(i):v for i,v in r['nested_returns'].items()};cs=children_any(r)
   compact=[dict(target=c['target'],entry=c['entry'],output=c['output'],call_offset=c['callsite'])for c in cs]
   ws=r['own_witnesses'];reads=[q for w in ws for q in w['reads']];branches=[dict(offset=w['origin']['offset'],taken=w['control'].get('taken'))for w in ws if w['control']['kind']=='jump']
   paths[source].append(dict(caller=coord(r['call']['origin']),entry_step=r['call']['step_index'],return_step=r['ret']['step_index'],entry=r['entry']['before'],output=r['ret']['after'],children=compact,branches=branches,path_signature=digest(branches),paired_reads=[dict(offset=w['origin']['offset'],reads=w['reads'])for w in ws if w['disassembly'].startswith('LHLD')],root_checkpoint_hash=digest(ws)))
  summary[source]=dict(logical=len(rs),callers=dict(collections.Counter(coord(r['call']['origin'])for r in rs)),returns=dict(collections.Counter(coord(r['ret']['origin'])for r in rs)),triples=dict(collections.Counter('/'.join(f"{r['entry']['before'][k]:02X}"for k in ['c','d','e'])for r in rs)),paths=dict(collections.Counter('/'.join(c['target']for c in p['children'])for p in paths[source])))
 save(REPORT/'inventory-summary.json',summary);save(REPORT/'natural-paths.json',paths);save(OUT/'annotation-rows-PLI2.OVL.json',rows)
def cross():
 for source in ['FACTOR','OPTIMIST']:
  with tempfile.TemporaryDirectory(prefix='cross-',dir=OUT)as tmp:
   with(OUT/(source+'-cross.log')).open('w')as log:r=subprocess.run(['_build/default/bin/native_generation_composition.exe','--toolchain',IMAGES,'--output-dir',str(Path(tmp)/'results'),'--family-only','--cross-source',source],stdout=log,stderr=subprocess.STDOUT)
   if r.returncode:raise RuntimeError((OUT/(source+'-cross.log')).read_text()[-5000:])
   for name in ['natural-cases.json','natural-instruction-witnesses.json']:shutil.copyfile(Path(tmp)/'results'/name,OUT/(source+'-'+name))
 print('Pass66 independent cross-source proofs passed',flush=True)
def prove(images=IMAGES,focused=False):
 dest=OUT/'proof';dest.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
  cmd=['dune','exec','bin/native_generation_composition.exe','--','--toolchain',str(images),'--output-dir',str(Path(tmp)/'results')]+(['--family-only']if focused else[])
  with(dest/'run.log').open('w')as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((dest/'run.log').read_text()[-5000:])
  for f in(Path(tmp)/'results').glob('*.json'):
   if not focused or f.name not in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:shutil.copyfile(f,dest/f.name)
 if not focused:cross()
 print('Pass66 primary root/component/synthetic proofs passed',flush=True)
def contracts():
 law='Save D at AE46, E at AE45, C at AE44 in order. Fresh AE44 CPI4 selects canonical7A17 only when equal. Independently LHLD AE44 -> C=L; LHLD AE45 -> DE via XCHG; canonical7ED6. RAR consumes actual returned A: CY=old A.bit0, A=(old CY<<7)|(old A>>1), NZPA preserved. CYset returns at8094. CYclear: independently reread AE44 -> C and AE45 -> DE, canonical7338. Fresh LHLD AE44 -> DE via XCHG, C=1, canonical75CE (E=fresh saved selector, D=adjacent saved E). Fresh LHLD AE45 -> BC (saved E low/D high), canonical7619, RET80B1 with final child channels. No opaque cached tuple; all paired reads, same-valued saves, flags and hardware CALL/RET residue retained. Bounded canonical child index/pending/error/output/position/alias domains; arbitrary compiler meaning unproved.'
 save(REPORT/'contract-laws-PLI2.OVL.json',{'PLI2.OVL+8072':dict(end=0x80b2,description='Saved relation attempt with fallback publication and field emission',contract=law,completeness=['stable','complete','partial'])})
 text=f'let p="{IMAGES}/PLI2.OVL";;\nlet c=open_in_bin p;; let b=Bytes.create(in_channel_length c);; really_input c b 0(Bytes.length b);; close_in c;;\nlet rec loop o last=if o<last then match I8080.Decode.decode b ~offset:o with Error _->failwith"decode"|Ok d->Printf.printf"%04X %s %s\\n"o(String.concat""(List.init d.length(fun i->Printf.sprintf"%02X"(Char.code(Bytes.get b(o+i))))))(I8080.Instr_format.format d.instr);loop(o+d.length)last;;\nloop 0x8072 0x80b2;;\n'
 (OUT/'decode.ml').write_text(text);decoded=subprocess.check_output(['ocaml','-I','_build/default/lib/i8080','-I','_build/default/lib/i8080/.i8080.objs/byte','i8080.cma',str(OUT/'decode.ml')],text=True);(OUT/'disassembly.txt').write_text(decoded)
 rows=load(OUT/'rows.json');natural={w['origin']['offset']for g in rows.values()for r in g['PLI2.OVL+8072']for w in r['own_witnesses']}
 for source in ['FACTOR','OPTIMIST']:natural.update(q['offset']for q in load(OUT/(source+'-natural-instruction-witnesses.json'))if q['owner']=='PLI2.OVL+8072')
 syn=load(OUT/'proof/synthetic-checkpoints.json')['cases'];pcs={w['pc']-0x2200 for c in syn if c['route'].startswith('8072_')for w in c['checkpoints']};cfg=[];static=[]
 for line in decoded.splitlines():
  off,b,d=line.split(' ',2);o=int(off,16);kind='call'if d.startswith('CALL')else'jump'if d.startswith('J')else'return'if d=='RET'else'ordinary';control=dict(kind=kind);target=None
  if kind in ['call','jump']:control['target']=int.from_bytes(bytes.fromhex(b)[1:],'little')
  if kind=='call':target=dict(image=dict(name='PLI2.OVL'),offset=control['target']-0x2200)
  evidence='OBSERVED'if o in natural else'DEDUCED STATIC UNOBSERVED'if o in pcs else'STATIC UNOBSERVED unsupported'
  cfg.append(dict(offset=o,bytes=b,decoded=d,control=control,evidence=evidence,owner='PLI2.OVL+8072'))
  if o not in{w['origin']['offset']for g in rows.values()for r in g['PLI2.OVL+8072']for w in r['own_witnesses']}:
   assert o in natural or o in pcs,(hex(o),d)
   static.append(dict(origin=dict(image=dict(name='PLI2.OVL'),offset=o),target_origin=target,bytes=b,disassembly=d,control=control,evidence_class=evidence))
 save(REPORT/'cfg.json',cfg);save(OUT/'annotation-static-PLI2.OVL.json',{'PLI2.OVL+8072':static})
def annotations():
 env={**os.environ,'RUNES_ANNOTATION_PASS':'66','RUNES_ANNOTATION_BASE':BASE}
 subprocess.run(['python3','tools/annotated-assembly/update_buffered_rel_annotations_pass_52.py',IMAGES,'PLI2.OVL'],env=env,check=True)
 subprocess.run(['python3','tools/annotated-assembly/update_generation_composition_annotations_pass_66.py'],check=True)
 subprocess.run(['python3','tools/annotated-assembly/verify.py','--images',IMAGES,'--write-progress'],check=True)
 subprocess.run(['python3','tools/annotated-assembly/minimal_dynamic_progress.py','--output','research/minimal-baseline/dynamic-progress.json'],check=True)
def focused():
 subprocess.run(['python3','tools/annotated-assembly/test_generation_composition_pass_66.py','--images',IMAGES,'-q'],env={**os.environ,'RUNES_PASS66_REUSE_PROOF':'1'},check=True)
def topology():
 # Reuse the immutable corrected window map, not inclusive window sums as savings.
 raw=load('_build/host-compiler-pass-51/residual-map.json');out={}
 prior_names=['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in[0x7434,0x7630,0x765e,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619,0x7701,0x8248,0x7ae4,0x7b99,0x7b1b,0x7e05,0x742a,0x8258,0x82b5,0x7338,0x829c,0x82dd,0x7ed6]]
 inside=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
 for source,v in raw.items():
  ws=v['windows'];allpre=v['roots']+[r for r in ws if r['target']in prior_names];pre=[r for r in allpre if not any(q is not r and inside(r,q)for q in allpre)];ps=[r for r in ws if r['target']=='PLI2.OVL+8072'];outer=[r for r in ps if not any(inside(r,q)for q in pre)];absorbed=[r for r in pre if any(inside(r,q)for q in outer)];post=[r for r in pre if r not in absorbed]+outer
  coords=[f'PLI2.OVL+{x:04X}'for x in[0x7ed6,0x7338,0x75ce,0x7619,0x7a17,0x8072,0x18b3]]+['PLI.COM+119E']
  out[source]=dict(logical=len(ps),external=len(outer),absorbed=dict(collections.Counter(r['target']for r in absorbed)),delta=len(outer)-len(absorbed),internal=dict(collections.Counter(r['target']for r in ws if any(inside(r,q)for q in outer))),remaining={k:dict(calls=len(rs:=[r for r in ws if r['target']==k and r not in outer and not any(q is not r and inside(r,q)for q in post)]),callers=dict(collections.Counter(r['caller']for r in rs)))for k in coords})
 save(REPORT/'topology-summary.json',out)
def validate():
 dest=OUT/'active-validation';tmp=OUT/'tmp';tmp.mkdir(exist_ok=True)
 r=subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--profile','active','--extra-categories',','.join(EXTRAS),'--images',IMAGES,'--output',str(dest),'--workers','4'],env={**os.environ,'TMPDIR':str(tmp.resolve())})
 receipt=load(dest/'results.json');receipt.update(historical_bytes=94720,dune_stanzas=39,reruns=[],historical_full_executed=False,full_trigger_fired=False);save(REPORT/'validation.json',receipt)
 if r.returncode:raise RuntimeError('ACTIVE failed')
def reports():
 cfg=load(REPORT/'cfg.json');nat=load(OUT/'proof/natural-cases.json');syn=[c for c in load(OUT/'proof/synthetic-checkpoints.json')['cases']if c['route'].startswith('8072_')];paths=load(REPORT/'natural-paths.json');top=load(REPORT/'topology-summary.json');cross={}
 for source in ['FACTOR','OPTIMIST']:
  v=load(OUT/(source+'-natural-cases.json'));cross[source]=dict(natural=True,entries=[dict(offset=e['offset'],calls=len(e['members']),callers=dict(collections.Counter(q['caller']for q in e['members'])),triples=dict(collections.Counter('/'.join(str(q['input'][k])for k in ['c','d','e'])for q in e['members'])),continuations=dict(collections.Counter(q['output']['pc']for q in e['members'])),proof_hash=digest(e['members']))for e in v['sources'][0]['entries']])
 for source,g in cross.items():
  instructions=load(OUT/(source+'-natural-instruction-witnesses.json'));root=[w for w in instructions if w['owner']=='PLI2.OVL+8072']
  g['own_return_sites']=dict(collections.Counter(f"PLI2.OVL+{w['offset']:04X}"for w in root if w['kind']=='return'));g['instruction_proof_hash']=digest(root)
 save(REPORT/'cross-evidence.json',cross)
 proof=dict(all_passed=True,primary=[dict(source=s['source'],entries=[dict(offset=e['offset'],calls=len(e['members']),proof_hash=digest(e['members']))for e in s['entries']])for s in nat['sources']],synthetic=dict(cases=len(syn),routes=dict(collections.Counter(c['route']for c in syn)),proof_hash=digest(syn),original_concrete_CPU=True),comparison=['all registers/flags/SP/PC','ordered writes/full65536 RAM','stack last writers/child CALL chronology','DMA/filesystem/record/service/console chronology'],journals='ignored _build/host-compiler-pass-66/proof')
 save(REPORT/'shadow-summary.json',proof)
 for n in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:save(REPORT/n,load(OUT/'proof'/n))
 counts={k:sum(len(bytes.fromhex(w['bytes']))for w in cfg if w['evidence']==k)for k in ['OBSERVED','DEDUCED STATIC UNOBSERVED','STATIC UNOBSERVED unsupported']};save(REPORT/'knowledge-summary.json',dict(root_own=counts,helper_bytes=0))
 semantic=dict(historical_root='PLI2.OVL+8072',semantic_inputs=['selector C and ordered relation bytes D/E','fresh AE04 pending state when selector4','fresh lower indexed-relation gates/tables'],semantic_outputs=['visible input scratch saves and optional pending preparation','actual lower result bit selects success return or fallback','fallback adjacent publication and selector/word representations'],shared_historical_state=['AE44=C,AE45=E,AE46=D','canonical AE3A..AE43, ADAB/ADB3 and pending AE04..06','canonical publication/output/position scratch and buffers'],historical_mechanism=['high-to-low MOV M saves','six independent paired LHLD reads and XCHG','CPI4 conditional preparation','RAR actual child accumulator through actual returned carry','canonical7338/75CE/7619 with distinct argument provenance','exact CALL/RET/flags/stack and same-valued writes'],candidate_modern_operation='Attempt indexed relation reuse; otherwise publish and emit generation state',confidence=dict(low_level='OBSERVED natural fallback plus DEDUCED STATIC UNOBSERVED success and synthetic pending routes',compiler_meaning='HYPOTHESIS; no source-language meaning assigned'),mir_relevance='Documentation only; no MIR API or faithful-code modernization.')
 save(REPORT/'semantic-extraction.json',semantic)
 raw=load('_build/host-compiler-pass-51/residual-map.json');ranking={}
 for source,v in raw.items():
  ws=v['windows'];ps=[p for p in ws if p['target']=='PLI2.OVL+8072'];contexts=[]
  for p in ps:
   ancestors=sorted([q for q in ws if q['call']<p['call']<p['ret']<=q['ret']],key=lambda q:q['ret']-q['call'])
   contexts.append(dict(callsite=p['caller'],nearest_retained_parent=ancestors[0]['target']if ancestors else None,span=ancestors[0]['ret']-ancestors[0]['call']if ancestors else None))
  ranking[source]=contexts
 save(REPORT/'next-boundary-ranking.json',dict(recommended='Bounded parent discovery around the paired 6ED7/6EE5 callsites; search anchors, not asserted entries',contexts=ranking,alternatives=['Actual retained3D10/397F parent windows introduce additional compiler policy; assess independently.','18B3 remains a separate large traversal/structure phase with unrelated children; do not widen for inclusive leverage.'],full_handoff='Pass67 ordinary historical-full epoch is due; finalize its semantic work before certification.'))
 import run_host_compiler_regressions as runner
 policy=load('research/host-compiler/validation-policy.json');_,full,_=runner.select_categories(runner.commands(IMAGES,OUT),policy,'historical-full');old=set(load('research/host-compiler/pass-62/validation.json')['categories']);assert old<=set(full);assert {'pass63','pass64','pass65','pass66','validation-runner-tests'}<=set(full)
 save(REPORT/'historical-full-selection.json',dict(count=len(full),all_92_preserved=True,additional=sorted(set(full)-old),executed=False))
 cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};oldcat=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))
 for p in oldcat['procedures']:
  for s,n in p['observed_paths']['invocations_by_run'].items():assert cat[p['id']]['observed_paths']['invocations_by_run'].get(s,0)>=n
 save(REPORT/'coverage-preservation.json',dict(prior_counts_preserved=True,FACTOR_OPTIMIST_preserved=True))
 rationale={'pass66':'New exhaustive local root/component/CPU synthetic and hybrid proofs.','pass65':'Adjacent canonical child and recent shared PLI2 dispatch/bounds/preparation and proof hooks receive the new8072 selection; regress existing7ED6 route/code/alias semantics independently.','not_added':'7338/75CE/7619/7A17 algorithms remain untouched. Their independently correlated local component shadows preserve required behavior; archived pass62/pass54/pass57 campaigns are not automatic extras.'}
 save(REPORT/'active-dependencies.json',dict(extras=EXTRAS,rationale=rationale))
 packet=dict(baseline=BASE,law=load(REPORT/'contract-laws-PLI2.OVL.json'),knowledge=counts,promotions=load(REPORT/'archaeology-summary-PLI2.OVL.json'),proofs=proof,natural={s:dict(count=len(rs),path_signatures=dict(collections.Counter(r['path_signature']for r in rs)),triples=dict(collections.Counter('/'.join(str(r['entry'][k])for k in ['c','d','e'])for r in rs)),checkpoint_hashes=[r['root_checkpoint_hash']for r in rs])for s,rs in paths.items()},cross=cross,topology=top,canonical_children={k:dict(contract_hash=digest(cat[k]))for k in ['PLI2.OVL+7A17','PLI2.OVL+7ED6','PLI2.OVL+7338','PLI2.OVL+75CE','PLI2.OVL+7619']},active_extras=EXTRAS,oracle_queries=0,last_full='Pass62',full_trigger=False)
 save(REPORT/'implementation-packet.json',packet);size=(REPORT/'implementation-packet.json').stat().st_size;assert size<32768,size
 hybrid=load(REPORT/'cumulative-hybrid-summary.json');table='\n'.join(f"|{s['result']['source']}|{s['pre_guest_instructions']} → {s['result']['actual_guest_instructions']}|{s['guest_instructions_removed']}|{sum(s['pre_transition_vector'])} → {s['result']['host_transitions']}|"for s in hybrid['sources'])
 crosscounts=', '.join(f"{s} {g['entries'][0]['calls']}"for s,g in cross.items())
 (REPORT/'README.md').write_text(f'''# Pass66 — saved generation composition

Published baseline verified: `{BASE}`. Pass62 remains the last certified FULL epoch. No FULL trigger fired; historical-full was not executed. CPU8080, CP/M, Runner execution semantics and shared journal/capture interpretation are unchanged. Pass67 is the planned next ordinary FULL-certification epoch.

## Bounds and natural topology

**PLI2.OVL+8072 [8072,80B2), 64 bytes**; early RET8094 and final RET80B1 are owned by this local CFG. No overlapping natural entry was found. Following80B2 is separate and not promoted. [Exact decode/CFG](cfg.json), [inventory](inventory-summary.json), and [per-root paths](natural-paths.json) preserve evidence.

Primary logical/external roots: **MINIMAL3, FIZZBUZ11, PICTURE4**. All18 natural roots use fallback. Optional selector4 preparation occurs0/1/1; the other16 bypass7A17. Callers are2943/6ED7/6EE5; FIZZBUZ additionally3D8E/38A8 and PICTURE3D8E. Distributions are recorded exactly, with no caller/source semantic selector. Cross evidence: **{crosscounts}**, independently shadowed with their direct children. [Cross report](cross-evidence.json) keeps those cases separate.

## Instruction law and provenance

Entry LXI H,AE46; MOV M,D; DCX H; MOV M,E; DCX H; MOV M,C publishes **D→AE46, E→AE45, C→AE44** in order, including same-valued writes. Fresh AE44 CPI4 produces the predicate; only equality invokes canonical7A17. Its actual returned state precedes fresh saved-input restoration. The saved carriers preserve the original triple across clobbering preparation and lower-generation paths; the PICTURE scan visibly changes the child argument registers before the parent restores them.

LHLD AE44 reads C low and adjacent E high; MOV C,L. Independent LHLD AE45 reads E low/D high; XCHG supplies DE. Canonical7ED6 receives the freshly restored triple. **RAR consumes actual returned A/CY**, not a recomputed relation predicate: CY=oldA.bit0, A=(oldCY<<7)|(oldA>>1), NZPA preserved. JNC selects fallback; CYset RET8094 suppresses every later child. Natural child A is0 in all18; returned CY is0 in17 and1 in onePICTURE failed-scan case. That parent RAR yieldsA80/CY0, still fallback. Supported success cases are synthetic-only, clearly DEDUCED STATIC UNOBSERVED.

Fallback independently repeats LHLD AE44/MOV C,L and LHLD AE45/XCHG, invoking **canonical7338(C=entryC,D=entryD,E=entryE)**. It publishes adjacent relations using its established bounded law. No local duplication of7338 occurs.

Then **fresh LHLD AE44; XCHG; C=1; canonical75CE** supplies DE with **E=saved selector C, D=adjacent saved E**. It is not the original DE tuple.75CE emits its historically proved field representation from the low E channel. Finally **fresh LHLD AE45; B=H; C=L; canonical7619** receives **BC=savedD<<8 | savedE**. Final registers/flags come from actual7619; RET consumes the original caller word. All six paired reads remain independent and ordered low then high. Component journals show none of the preparation/publication children overwrites AE44..46 at the supported indices; the host retains fresh rereads nonetheless.

The representation-level policy is conditional preparation, actual-result-gated relation attempt, and fallback adjacent publication plus selector/word emission. Higher compiler meaning remains HYPOTHESIS. [Semantic extraction](semantic-extraction.json) separates that possible operation from scratch, register transfers, RAR and hardware stack mechanisms; no MIR/API design or faithful-code refactor.

## Independent proof and transaction

All primary and cross roots independently compare registers, all flags, SP/PC, ordered writes, complete65536-byte RAM, stack last writers, DMA/filesystem, record/service chronology and child CALLs. Canonical **7A17,7ED6,7338,75CE,7619** are independently shadowed at the exact contained windows. Intermediate CPU states and pointer/read/write witnesses are retained under ignored_build with durable proof hashes.

**{len(syn)} independent concrete-CPU synthetic proofs** discriminate selector0/4/5/6, D/E and selector channels, stale overwritten scratch, both incoming carry values, pending preparation, each lower early gate, failed search, actual success equality/adjustment/match/search, early-return suppression and fallback emissions. Synthetic success is induced by valid lower memory inputs; child output is never patched. [Shadows](shadow-summary.json) retains route grouping and hashes.

Each ordinary child CALL writes its encoded continuation below the original outer CALL slot. No private frame is invented. Full journals retain7338 PSW transport,7ED6 nested frames and output-child residue. Parent has no PUSH/POP itself. Every root returns SP=entrySP+2 to its actual original continuation, unchanged. CPI4, lower flags, RAR and JNC are tracked instructionally.

Copied staging validates own and selected child code/CALLs, continuation, entry stack, scratch/sentinel/table aliases and all bounded child/output/position scopes before live mutation. Negatives cover own/child code, origin/CALL/continuation, stack and sentinel aliases, unsupported selector7, pending mode2, and a late fallback position-wrap rejection after staged preparation/publications. Live RAM/DMA/filesystem remain unchanged after rejection. No partial native effects precede fallback.

## Hierarchy and measured counters

|Source|Guest before → after|Removed|Host before → after|
|---|---:|---:|---:|
{table}

[Hierarchy/residual map](topology-summary.json) reports absorption by coordinate, internal counts and remaining external7ED6/7338/75CE/7619/7A17/8072/119E. No leaf interception was added. Standalone8072 and cumulative hybrids preserve exact MINIMAL/FIZZBUZ/PICTURE REL goldens, full REL/INT record chronology, filesystem, console/milestones, BDOS order/counts and warm boot. Both hybrid receipts retain actual whole-run counters and hashes; inclusive window sums are not savings.

**64 RAW→UNDERSTOOD, DECODED0, STRUCTURED0**. Naturally OBSERVED bytes: **{counts['OBSERVED']}**; DEDUCED STATIC UNOBSERVED bytes: **{counts['DEDUCED STATIC UNOBSERVED']}**. No helper-body promotion or adjacent procedure promotion. Bounds stable, local CFG complete, general contract partial over canonical index/pending/output/error/position/alias domains. Historical behavior correction: none. Native algorithm correction: none. Development test-harness fixes normalized JSON ancestry keys and separated archived hybrid synthetic records from the Pass66-only count. Pragmatic divergence: none. Fidelity debt is bounded inherited child domains, synthetic-only success coverage and unproved compiler meaning.

## Validation policy and handoff

ACTIVE extras are **pass66, pass65**. Pass66 independently proves/composes every required canonical child. Pass65 is a justified adjacent-child regression because this change extends shared PLI2 dispatch/bounds/preparation and local shadow selection.7338/75CE/7619/7A17 algorithms remain untouched, so pass62/pass54/pass57 are not accumulated as automatic multi-minute campaigns. [Rationale](active-dependencies.json) and [ACTIVE receipt](validation.json) record selection, timings, workers, tests and reruns. Compare measured cost with Pass65 782.972 seconds; no proof was removed to meet a time target.

Historical-full selection includes all92 Pass62 categories plus validation-runner-tests and pass63–66 (**97 categories**); listing proof only. Exact reconstruction remains **94720 bytes**, oracle queries **0**, packet **{size} bytes**. Driver phases: fresh discovery/inventory, components, cross evidence, contracts/CFG, topology, reports and explicit ACTIVE validation. Proof artifacts and temporary directories live under ignored_build and clean up on exit. User-owned scripts/view-optimist.sh is untouched.

[Next-boundary ranking](next-boundary-ranking.json) recommends bounded valid-entry discovery around the paired6ED7/6EE5 callsites, not artificial roots there. Nearest retained owning windows generally reach1FB5, a broader compiler policy;3D10/397F contexts have additional semantics and remain separate.18B3 remains an independent large traversal. No immediate caller was migrated. **Pass67 should run the planned historical-full epoch after its semantic work and metadata are finalized**; Pass66 ACTIVE is not FULL certification.
''')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['discovery','inventory','prove','components','cross','contracts','annotations','topology','reports','focused','validate']);a=p.parse_args();OUT.mkdir(parents=True,exist_ok=True);REPORT.mkdir(parents=True,exist_ok=True)
 if a.phase=='components':prove(focused=True)
 else:globals()[a.phase]()
