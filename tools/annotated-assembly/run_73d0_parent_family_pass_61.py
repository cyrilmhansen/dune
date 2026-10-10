#!/usr/bin/env python3
"""Deterministic 73D0 true-parent discovery and proof proof."""
import collections,json,sys,subprocess
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_buffered_rel_emission_pass_52 import save,digest
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-61');REPORT=Path('research/host-compiler/pass-61')
BASE='d19ce2f2012109802f968630b4cec45716b6a807'
ENTRIES=[0x742a,0x8258,0x82b5,0x7423,0x79a2]
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
  cmd=['dune','exec','bin/native_73d0_parent_family.exe','--','--toolchain',str(images),'--output-dir',str(Path(tmp)/'results')]
  if focused:cmd+=['--family-only']
  with(dest/'run.log').open('w')as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((dest/'run.log').read_text()[-4000:])
  for f in(Path(tmp)/'results').glob('*.json'):
   if not focused or f.name in ['component-shadows.json','natural-cases.json','synthetic-checkpoints.json','synthetic-helper-pairs.json']:shutil.copyfile(f,dest/f.name)
 print('proof passed')




def contracts():
 laws={
 'PLI2.OVL+7423':dict(end=0x742a,description='Publish literal FFFF word at ADA6',contract='HL=FFFF;SHLD ADA6 writes low FF then high FF;RET consumes original hardware word. All flags and other registers preserved; no children or private frame.',completeness=['stable','complete','complete']),
 'PLI2.OVL+79A2':dict(end=0x79ae,description='Zero three consecutive preparation gate bytes',contract='LXI H AE04;publish zero AE04; INX H;publish zero AE05;INX H;publish zero AE06;RET. Final HL=AE06;all flags and other registers preserved. Sequential same-valued writes retained;independent following79AF entry excluded.',completeness=['stable','complete','complete']),
 'PLI2.OVL+742A':dict(end=0x7434,description='Reset indexed carriers, publish FFFF and freshly return position word',contract='CALL canonical73D0 at742A;CALL canonical7423 at742D;fresh LHLD1C2C low/high;RET7433. FinalHL=freshposition;otherregisters/flags actual73D0 outputs. No private frame;child CALL words survive belowentrySP. Canonicalchild/nonalias scope inherited.',completeness=['stable','complete','partial']),
 'PLI2.OVL+8258':dict(end=0x829c,description='Save word and position, emit incremented word and captured position fields',contract='Save B atAE67 thenC atAE66;canonical73D0. FreshLHLD1C2C thenSHLD AE68 low/high captures position. IndependentLHLD AE66;INXH modulo 65536;BC=HL;canonical7434. Fresh 201D RAR;requirebit0clear. FreshAE68 pairedword ->BC canonical7630;independentfreshAE68 pairedword ->BC canonical7434;canonical7423;RET829B. Same-valuedwrites/freshreads/flags/callresidue retained. 201D-set arm8277..8288 STATIC UNOBSERVED unsupported:CALL745A;literalBC94E5;resident03F4;freshsavedposition;resident0466. Successfulwriter,nonwrapposition andcanonicalchild/noalias scope required;no source/caller/fixture dispatch.',completeness=['stable','partial','partial']),
 'PLI2.OVL+82B5':dict(end=0x82dd,description='Reset carrier and preparation state with fixed zero field emission',contract='PublishADAA=1;canonical73D0 clearsADAA andADAB[0..7]. HL0 SHLDADA8 low/high;BC0 canonical7434;canonical7423 publishesFFFF ADA6. ZeroADC9 thenADCA;zeroAE6A;canonical79A2 sequentiallyzeroAE04..AE06;RET82DC. FinalHL=AE06;flags/registers actual7434 outputs. Ordered same-valuedwrites andhardwareCALLresidue retained. Canonicalwriter/position/nonalias scope inherited.',completeness=['stable','complete','partial'])}
 save(REPORT/'contract-laws-PLI2.OVL.json',laws);save(OUT/'annotation-rows-PLI2.OVL.json',load(OUT/'rows.json'))

def topology():
 raw=load('_build/host-compiler-pass-51/residual-map.json');result={};boundary={}
 inside=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
 targets=[f'PLI2.OVL+{x:04X}'for x in[0x742a,0x8258,0x82b5]]
 previous=['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in[0x7434,0x7630,0x765e,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619,0x7701,0x8248,0x7ae4,0x7b99,0x7b1b,0x7e05]]
 coords=[f'PLI2.OVL+{x:04X}'for x in[0x73d0,0x7314,0x7365,0x7423,0x7434,0x7630,0x79a2,0x8258,0x82b5]]+['PLI.COM+119E']
 for source,v in raw.items():
  ws=v['windows'];prior=v['roots']+[r for r in ws if r['target']in previous];pre=[r for r in prior if not any(q is not r and inside(r,q)for q in prior)]
  parents=[r for r in ws if r['target']in targets];outer=[r for r in parents if not any(q is not r and inside(r,q)for q in pre+parents)]
  absorbed=[r for r in pre if any(inside(r,q)for q in outer)]
  per={k:dict(logical=len(rs:=[r for r in parents if r['target']==k]),external=len(os:=[r for r in outer if r['target']==k]),callers=dict(collections.Counter(r['caller']for r in rs)),absorbed=dict(collections.Counter(r['target']for r in absorbed if any(inside(r,q)for q in os))),net_host_delta=len(os)-sum(any(inside(r,q)for q in os)for r in absorbed))for k in targets}
  remaining={k:dict(calls=len(rs:=[r for r in ws if r['target']==k and r not in outer and not any(q is not r and inside(r,q)for q in pre+outer)]),callers=dict(collections.Counter(r['caller']for r in rs)))for k in coords}
  result[source]=dict(parents=per,external=len(outer),absorbed=dict(collections.Counter(r['target']for r in absorbed)),net_host_delta=len(outer)-len(absorbed),remaining=remaining,logical_internal=dict(collections.Counter(r['target']for r in ws if any(inside(r,q)for q in outer))))
  boundary[source]=[]
  for r in parents:
   ancestors=[q for q in ws if inside(r,q)];parent=min(ancestors,key=lambda q:q['ret']-q['call'])if ancestors else None
   children=[q for q in ws if parent and inside(q,parent)];direct=[q for q in children if not any(z is not q and inside(q,z)for z in children)]
   boundary[source].append(dict(target=r['target'],callsite=r['caller'],actual_parent=parent['target']if parent else None,direct_children=[q['target']for q in direct],widened=False))
 save(REPORT/'topology-summary.json',result);save(REPORT/'immediate-parent-summary.json',boundary)

def cross():
 import tempfile,shutil
 with tempfile.TemporaryDirectory(prefix='factor-',dir=OUT)as t:
  subprocess.run(['_build/default/bin/native_73d0_parent_family.exe','--toolchain','/home/john/pli/cpm/pli80/DISK1','--output-dir',str(Path(t)/'proof'),'--family-only','--cross-source','FACTOR'],check=True)
  shutil.copyfile(Path(t)/'proof/natural-cases.json',OUT/'factor-natural-cases.json')
 result={f"PLI2.OVL+{e['offset']:04X}":dict(calls=len(e['members']),proof_hash=digest(e['members']))for e in load(OUT/'factor-natural-cases.json')['sources'][0]['entries']}
 save(REPORT/'cross-evidence.json',dict(FACTOR=result,OPTIMIST='Prior durable coverage totals preserved;no new trace infrastructure.'))


def reports():
 raw=load(OUT/'rows.json');nat=load(OUT/'proof/natural-cases.json');post=load(OUT/'proof/cumulative-hybrid-summary.json');top=load(REPORT/'topology-summary.json');laws=load(REPORT/'contract-laws-PLI2.OVL.json');hierarchy=[];summaries=[];routes={};checkpoints={}
 for source,g in raw.items():
  proof=next(v for v in nat['sources']if v['source']==source);h=next(v for v in post['sources']if v['result']['source']==source);t=top[source]
  assert h['result']['host_transitions']-sum(h['pre_transition_vector'])==t['net_host_delta']
  summaries.append(dict(source=source,entries=[dict(coordinate=f"PLI2.OVL+{e['offset']:04X}",cases=len(e['members']),proof_hash=digest(e['members']),stack_pattern='ordinary-call-no-private-frame')for e in proof['entries']]))
  hierarchy.append(dict(source=source,roots=t['external'],per_parent=t['parents'],absorbed=t['absorbed'],pre_guest=h['pre_guest_instructions'],post_guest=h['result']['actual_guest_instructions'],saved=h['guest_instructions_removed'],pre_host=sum(h['pre_transition_vector']),post_host=h['result']['host_transitions'],net_host_delta=t['net_host_delta'],remaining=t['remaining'],internal_calls=t['logical_internal']))
  routes[source]={};checkpoints[source]={}
  for k,rs in g.items():
   routes[source][k]=dict(calls=len(rs),child_sequence_hashes=dict(collections.Counter(digest([w['target_origin']for w in r['own_witnesses']if w['control']['kind']=='call'])for r in rs)),entry_BC=dict(collections.Counter(f"{r['entry']['before']['b']:02X}{r['entry']['before']['c']:02X}"for r in rs)))
   checkpoints[source][k]=[dict(call=r['call'],own=r['own_witnesses'],ret=r['ret'],children=children_any({**r,'nested_returns':{int(i):v for i,v in r['nested_returns'].items()}}))for r in rs]
   if k=='PLI2.OVL+8258':
    own=lambda r:{w['origin']['offset']:w for w in r['own_witnesses']}
    routes[source][k].update(mode_bit0_clear=len(rs),mode_bit0_set=0,captured_position=dict(collections.Counter(str(sum(v['value']<<(8*i)for i,v in enumerate(own(r)[0x8261]['reads'])))for r in rs)))
  save(OUT/('checkpoints-'+source+'.json'),checkpoints[source])
 synth=[v for v in load(OUT/'proof/synthetic-checkpoints.json')['cases']if v['route'].startswith('8258_')]
 save(REPORT/'route-summary.json',routes)
 save(REPORT/'shadow-summary.json',dict(all_passed=True,sources=summaries,components=load(OUT/'proof/component-shadows.json'),checkpoints={s:digest(g)for s,g in checkpoints.items()},synthetic_discriminants=dict(cases=len(synth),routes=dict(collections.Counter(v['route']for v in synth)),proof_hash=digest(synth),comparison='Independent original instructions;registers/flags/SP/PC/fullRAM/orderedwrites/stackwriters;no syntheticBDOS'),comparison=['all registers and flags','SP/PC/original continuation','ordered writes/full65536RAM','stack last writers and child CALL chronology','DMA/filesystem/REL-INT records/service chronology']))
 save(REPORT/'hierarchy-summary.json',dict(sources=hierarchy,suppression='Exact accepted outer windows only. 73D0/7423/79A2 are canonical internal primitives,not independently enabled Runner roots.'))
 for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:save(REPORT/name,load(OUT/'proof'/name))
 old=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/manifest.json']));cur=load('research/annotated-assembly/manifest.json');image=lambda x:next(i for i in x['images']if i['name']=='PLI2.OVL');status=lambda im,a:next(q['status']for q in im['sections']if q['start_offset']<=a<q['end_offset']);total=collections.Counter();counts={}
 for k,l in laws.items():
  cnt=collections.Counter(status(image(old),a)for a in range(int(k.split('+')[1],16),l['end'])if status(image(cur),a)=='UNDERSTOOD'and status(image(old),a)!='UNDERSTOOD');counts[k]=dict(cnt);total.update(cnt)
 observed=sum(len(bytes.fromhex(w[1]))for ws in load(OUT/'cfg.json').values()for w in ws)
 fidelity=dict(promotions=dict(total),by_contract=counts,RAW_to_UNDERSTOOD=total['RAW'],DECODED_to_UNDERSTOOD=total['DECODED'],STRUCTURED_to_UNDERSTOOD=total['STRUCTURED'],OBSERVED_natural_bytes=observed,DEDUCED_STATIC_UNOBSERVED_bytes=0,unsupported_RAW_ranges={'PLI2.OVL+8258':[[0x8277,0x8288]]},archaeological_scope_extension=True,historical_correction=None,implementation_correction='Development INX H draft explicitly wrapped before synthetic wrap proof;no historical behavior correction.',pragmatic_divergence=None,fidelity_debt='Unobserved201D-set listing arm remains RAW/unsupported;inherited writer-error/position-wrap/alias states excluded.',oracle_queries=0,cpu_runner_cpm_changes=False,shared_schema_changes=False)
 save(REPORT/'fidelity.json',fidelity)
 mapped=load('_build/host-compiler-pass-51/residual-map.json');nextmap={}
 for source,v in mapped.items():
  counts=collections.Counter()
  for r in v['windows']:
   if r['caller']not in ['PLI2.OVL+7352','PLI2.OVL+7361','PLI2.OVL+82A6','PLI2.OVL+82E1','PLI2.OVL+82F0']:continue
   ancestors=[q for q in v['windows']if q['call']<r['call']<r['ret']<=q['ret']];q=min(ancestors,key=lambda q:q['ret']-q['call'])
   counts[(r['caller'],q['target'])]+=1
  nextmap[source]=[dict(callsite=c,true_parent=p,calls=n)for(c,p),n in sorted(counts.items())]
 boundary=dict(selected_roots=['PLI2.OVL+742A','PLI2.OVL+8258','PLI2.OVL+82B5'],family_design='Three distinct operations share canonical reset/publication/emission primitives;no parameterized unification.',true_callsite_disposition={'825E':'internal CALL in8258','82BA':'internal CALL in82B5','742A':'actual CALL-target entry'},missing_natural_helpers='Only7423 and79A2;all other complete natural8258 children canonical.',unobserved_8258_children=[dict(callsite='8277',target='PLI2.OVL+745A'),dict(callsite='827D',target='PLI.COM+03F4',literal_BC='94E5'),dict(callsite='8285',target='PLI.COM+0466')],unobserved_8258_status='STATIC UNOBSERVED RAW unsupported;listing/output policy not required bynaturalclearroute.',immediate_parent_assessment='742A belongs to1FB5 compiler dispatch or259B;8258 belongs to1FB5;82B5 startup CALL0457 has no enclosing ordinary matched window. Independent compiler semantics;not widened.',next='Rank true7338 two-publication carrier parent against separate829C field generation and82DD lifecycle. Keep independent lifecycles separate;Pass62 scheduled FULL after semantic closure.',next_topology=nextmap)
 save(REPORT/'boundary-assessment.json',boundary)
 semantic=dict(historical_roots=boundary['selected_roots'],semantic_inputs={'742A':['shared reset gate/carrier activity','current emitted position'],'8258':['input wordBC','current position captured afterreset','201D clear mode'],'82B5':['current generation/output state']},semantic_outputs={'742A':['reset indexedcarrier state if gate active','FFFFpublication','returnfreshposition'],'8258':['emit incrementedinput andcapturedposition fields','restorecapturedposition publication','FFFFpublication'],'82B5':['reset selectedcarrier/preparation bytes','emitfixedzero field','FFFFpublication']},shared_historical_state=['ADAA/ADAB canonicalreset andADC4/5scan','ADA6/7 FFFF;ADA8/9zero','AE66/67 savedword;AE68/69capturedposition;201D','ADC9/ADCA/AE6A;AE04/AE05/AE06','1C2C andcanonicalRELbuffer/cursor/scratch'],historical_mechanism=['high-before-low entrysave','LHLD/SHLD paired low/high reads/writes','INXH modulo 65536','RAR bit0 mode selection','literaloutput adapters','exact flags andordinary hardwareCALL/RET residue;no private frame'],candidate_modern_operation='Distinct generation-state reset, captured-position emission and fixed-state initialization policies',confidence=dict(low_level_laws='OBSERVED primary andFACTOR;DEDUCED instruction semantics',wrap='DEDUCED synthetic independentCPU',modern_description='HYPOTHESIS;no source-language meaning claimed'),mir_relevance='Documentation only;no common API/MIR design or faithful-code refactor.')
 save(REPORT/'semantic-extraction.json',semantic)
 cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};prior=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))
 for p in prior['procedures']:
  for source,n in p['observed_paths']['invocations_by_run'].items():assert cat[p['id']]['observed_paths']['invocations_by_run'].get(source,0)>=n
 save(REPORT/'coverage-preservation.json',dict(all_prior_catalog_totals_preserved=True,FACTOR=load(REPORT/'cross-evidence.json')['FACTOR'],OPTIMIST='Prior catalog values preserved unchanged.'))
 packet=dict(task='PLI2_73D0_PARENT_GENERATION_FAMILY_PASS_61',baseline=BASE,selected_roots=boundary['selected_roots'],family_design=boundary['family_design'],laws=laws,inventory=load(REPORT/'inventory-summary.json'),routes=routes,proofs=summaries,checkpoint_hashes={k:digest(v)for k,v in checkpoints.items()},promotions=fidelity,cross=load(REPORT/'cross-evidence.json'),hierarchy=[{k:v for k,v in h.items()if k not in ['internal_calls','remaining','per_parent']}for h in hierarchy],canonical_children={k:dict(contract_hash=digest(cat[k]),route_id=cat[k]['description'],completeness=cat[k]['completeness'])for k in ['PLI2.OVL+73D0','PLI2.OVL+7434','PLI2.OVL+7630','PLI2.OVL+753C','PLI2.OVL+7550','PLI.COM+11E5','PLI.COM+119E','PLI.COM+1140']},unsupported=boundary['unobserved_8258_status'],oracle_queries=0)
 save(REPORT/'implementation-packet.json',packet);size=(REPORT/'implementation-packet.json').stat().st_size;assert size<=28672,size
 table='\n'.join(f"|{h['source']}|{h['pre_guest']} → {h['post_guest']}|{h['saved']}|{h['pre_host']} → {h['post_host']}|{h['roots']}|"for h in hierarchy)
 (REPORT/'README.md').write_text(f'''# Pass61 — three true parents of canonical +73D0

Baseline `{BASE}` is published Pass60. Pass59 remains the current FULL checkpoint. This pass is INCREMENTAL; no CPU/Runner/CPM or shared-schema trigger occurred.

## Selected operations and natural topology

The selected real entries are PLI2.OVL+742A `[742A,7434)` (10 bytes), +8258 `[8258,829C)` (68 bytes) and +82B5 `[82B5,82DD)` (40 bytes). +825E/+82BA are internal CALL sites, not roots. Corrected logical/external counts are respectively 3/14/3, 1/11/1 and 1/1/1 across MINIMAL/FIZZBUZ/PICTURE; all 36 primary calls are external before this pass. Natural returns are +7433/+829B/+82DC. No overlapping natural entry was found. Callers and entry register distributions are retained in inventory-summary.json. FACTOR adds 9/3/1 independently shadowed parent calls. Prior FACTOR/OPTIMIST catalog coverage totals are preserved.

These are three distinct operations sharing canonical primitives, rather than one parameterized law. +742A resets carriers, publishes FFFF, and returns a fresh position. +8258 captures an input word and output position for field emission. +82B5 initializes/reset several carriers and emits a fixed zero field. Shared +73D0 and +7423 do not make their input/state/output laws isomorphic.

## Exact laws and newly reconstructed helpers

+7423 `[7423,742A)` (7 bytes) sets HL=FFFF and SHLD writes low FF then high FF at ADA6/ADA7. Flags and other registers are preserved. Natural primary counts 5/26/5, FACTOR 13; all callers lie in the three selected parents. Its local bounds/CFG/contract are complete. +79A2 `[79A2,79AE)` (12 bytes) writes zero to AE04, then AE05, then AE06; final HL=AE06, flags and other registers preserved. Primary counts 1/1/1, FACTOR 1. The following independent +79AF is excluded. Its local bounds/CFG/contract are complete.

+742A calls canonical +73D0, calls canonical +7423, then freshly LHLD1C2C and returns. Registers/flags come from actual child state, except HL receives the fresh position. Bounds stable, local CFG complete, contract partial over child/alias scope.

+82B5 publishes ADAA=1, invokes canonical +73D0 to clear ADAA/ADAB[0..7], writes the word ADA8/9=0, supplies BC=0 to canonical +7434, invokes +7423, zeros ADC9 then ADCA then AE6A, and invokes +79A2. It preserves ordered same-valued publications. Final HL=AE06; flags and other registers are actual adapter results. Complete natural child sequence: +73D0, +7434, +7423, +79A2. Bounds stable, local CFG complete, contract partial over canonical output/alias scope.

+8258 saves B atAE67 before C atAE66. After canonical +73D0, fresh 1C2C is captured with low/high SHLD toAE68/69. An independent paired input reread is incremented modulo 65536 and supplied as BC to +7434. Fresh 201D RAR tests bit0; all 13 primary and three FACTOR calls take the clear branch. Another paired AE68 read supplies captured position to +7630; another independent read supplies it to +7434. +7630 increments position twice, while the final +7434 republishes the captured position. +7423 publishes FFFF before RET. Complete natural chronology: +73D0, +7434, +7630, +7434, +7423. No required natural child remains opaque. Bounds stable; local CFG and contract partial because the 17-byte arm `[8277,8288)` is STATIC/UNOBSERVED and RAW. Exact static CALLs there are +745A, resident +03F4 with literal BC94E5, and resident +0466 after a fresh saved-position read. This listing/output alternative rejects staging; it is not fabricated as natural coverage or promoted.

## Independent proofs and stack

Every primary parent, +7423/+79A2 component and useful canonical +73D0/+7434/+7630 call independently matches registers, flags, SP/PC, ordered logical writes, all 65536 RAM bytes, stack last writers, child CALL chronology, DMA, filesystem and record/service chronology. Canonical +119E/+1140 children inside selected windows have separate shadows: 15/125/15 serializer and94/784/94 writer calls. Exhaustive natural per-call journals and intermediate local/child checkpoints stay under ignored `_build/host-compiler-pass-61`. Their hashes are durable in shadow-summary.json.

Two targeted +8258 discriminants per primary call use BC=FFFF (input increment wraps to0) and BC=7F2A with captured position 1234. The existing concrete CPU independently executes original instructions and children; full registers/flags/RAM/ordered writes and stack writers match. No synthetic BDOS services occur. These 26 cases prove state-driven arithmetic and distinct saved-word/position carriers without source/caller dispatch. They do not cover or promote the listing arm. Rejection checks include201D-set, code/caller/continuation corruption, stack aliases, writer scope and new publication/sentinel aliases; copied staging rejects before live mutation.

There is no private frame. Original CALL word remains at entrySP. Each local CALL writes resume high atSP-1 then low atSP-2; children may leave deeper historical residue. RET reads original low/high and gives SP=entrySP+2 and original continuation. Canonical descendants preserve their actual hardware/PUSH/POP frames. Per-call last-writer journals prove surviving stack bytes; no new software continuation mechanism is introduced.

## Hierarchy, hybrids and actual leverage

| Source | Pass60 → Pass61 guest | Removed | Host before → after | Outer roots |
|---|---:|---:|---:|---:|
{table}

Each +8258 replaces two +7434 roots and one +7630 root: host delta -2 percall. +82B5 replaces one +7434 root: delta0. +742A adds one boundary percall because canonical +73D0 was not globally intercepted. Total host deltas +1/-8/+1 are measured, not inclusive-window estimates. Absorbed +7434 totals3/23/3 and +7630 totals1/11/1. Internal primitive calls include +73D0 (5/26/5), +7423 (5/26/5), +79A2 (1/1/1), and exact adapter descendants. Suppression uses corrected outer windows only. All external +73D0 calls disappear:0/0/0. +119E remains36/36/43; no global serializer interceptor was introduced.

Standalone and cumulative hybrids pass exact REL goldens, full REL/INT record chronology, filesystem, console, PASS1/PASS2/END, BDOS ordering/counts and warm boot. Hashes: MINIMAL 7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119; FIZZBUZ 68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203; PICTURE c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1. Machine-readable hybrid summaries include complete record hashes.

## Archaeology, extraction and next boundary

Promotions: RAW→UNDERSTOOD 120; DECODED→UNDERSTOOD 0; STRUCTURED→UNDERSTOOD 0. All 120 promoted bytes are naturally OBSERVED; no STATIC/UNOBSERVED bytes promoted. +8258 represents 51 of 68 bytes. Existing canonical children are unchanged. Exact reconstruction remains 94720 bytes. Oracle queries 0. No historical correction or pragmatic divergence. The draft INX increment was explicitly wrapped before the synthetic proof; this is an implementation correction. Fidelity debt remains the unobserved listing arm and inherited unsupported writer/error/wrap/alias states, all fail closed.

Semantic-extraction.json documents distinct state reset/publication/captured-position operations separately from scratch addresses, paired reads, bit gate and stack/flag machinery. No faithful-code refactor or MIR/API design occurred.

One-level ancestry shows +742A in compiler dispatch +1FB5 or +259B; +8258 in +1FB5. Startup +82B5 is called at +0457 without a matched enclosing ordinary procedure. These introduce separate compiler semantics, so no widening. Residual +7314 callers +7352/+7361 both belong to real +7338, with3/11/4 calls; rank this next against distinct +829C field-generation and +82DD lifecycle parents. Serializer callsites +82A6 belong to +829C; +82E1/+82F0 belong to +82DD. They remain separate and unabsorbed. Pass62 is the next ordinary FULL checkpoint after semantic closure.

Packet: {size} bytes. The deterministic driver automates fresh entries/call discovery, component/root proofs, route and checkpoint grouping, hierarchy, hybrids, cross-evidence, residual maps, contracts, report generation and incremental validation. Interactive call count is not instrumented. validation.json records category/test/stanza/worker/timing/rerun results. scripts/view-optimist.sh is untouched.
''')
 save(REPORT/'validation.json',dict(validation_tier='INCREMENTAL',previous_full_checkpoint='a3ca60c886833e1bdae92e1334504c9acd5fabd8',status='ready for final aggregate',reruns=[],historical_bytes=94720))

def validate():
 dest=OUT/'incremental-validation'
 r=subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images','/home/john/pli/cpm/pli80/DISK1','--output',str(dest),'--workers','4','--categories','pass61,pass60,pass59,pass58,pass57,pass53,packet-continuation,V1,roundtrip,roundtrip-tests,dynamic-progress,diff-check'])
 receipt=load(dest/'results.json');receipt.update(validation_tier='INCREMENTAL',full_checkpoint_base='a3ca60c886833e1bdae92e1334504c9acd5fabd8',status='passed initially'if r.returncode==0 else'initial aggregate failed',initial_all_passed=r.returncode==0,reruns=[],historical_bytes=94720,category_count=len(receipt['categories']),distinct_python_tests=sum(q['python_tests']for q in receipt['categories'].values()),dune_stanzas=Path('test/dune').read_text().count('(test\n'))
 save(REPORT/'validation.json',receipt)
 if r.returncode:raise RuntimeError('incremental validation failed')

def check_cached():
 import unittest,test_73d0_parent_family_pass_61 as suite
 suite.IMAGES=Path('/home/john/pli/cpm/pli80/DISK1');suite.prove=lambda _:None
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(suite.TrueParents))
 if not result.wasSuccessful():raise RuntimeError('focused cached checks failed')

if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['discovery','inventory','contracts','topology','cross','components','prove','reports','check_cached','validate']);a=p.parse_args()
 if a.phase in ['components','prove']:prove(focused=a.phase=='components')
 else:globals()[a.phase]()
