#!/usr/bin/env python3
"""Deterministic Paired carrier publication discovery and proof."""
import collections,json,sys,subprocess
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_buffered_rel_emission_pass_52 import save,digest
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-62');REPORT=Path('research/host-compiler/pass-62')
BASE='a409348e69e69e6760a0defc9b275ec1d30393c0'
ENTRIES=[0x7338,0x7314]
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
  summary[source]={k:dict(calls=len(rs),callers=dict(collections.Counter(coord(r['call']['origin'])for r in rs)),triples=dict(collections.Counter(f"{r['entry']['before']['c']:02X}/{r['entry']['before']['d']:02X}/{r['entry']['before']['e']:02X}"for r in rs)),returns=dict(collections.Counter(coord(r['ret']['origin'])for r in rs)),children=dict(collections.Counter('/'.join(c['target']for c in children_any(r))for r in rs)))for k,rs in g.items()}
 save(REPORT/'inventory-summary.json',summary);print(json.dumps(summary,indent=2))


def prove(images='/home/john/pli/cpm/pli80/DISK1',focused=False):
 import subprocess,tempfile,shutil
 dest=OUT/'proof';dest.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
  cmd=['dune','exec','bin/native_paired_carrier_publication.exe','--','--toolchain',str(images),'--output-dir',str(Path(tmp)/'results')]
  if focused:cmd+=['--family-only']
  with(dest/'run.log').open('w')as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((dest/'run.log').read_text()[-4000:])
  for f in(Path(tmp)/'results').glob('*.json'):
   if not focused or f.name in ['component-shadows.json','natural-cases.json','synthetic-checkpoints.json','synthetic-helper-pairs.json']:shutil.copyfile(f,dest/f.name)
 print('proof passed')





def topology():
 raw=load('_build/host-compiler-pass-51/residual-map.json');result={};boundary={}
 inside=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
 targets=['PLI2.OVL+7338']
 previous=['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in[0x7434,0x7630,0x765e,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619,0x7701,0x8248,0x7ae4,0x7b99,0x7b1b,0x7e05,0x742a,0x8258,0x82b5]]
 coords=[f'PLI2.OVL+{x:04X}'for x in[0x7314,0x7338,0x7365,0x7423,0x7434,0x7630,0x79a2,0x8258,0x82b5]]+['PLI.COM+119E']
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
  subprocess.run(['_build/default/bin/native_paired_carrier_publication.exe','--toolchain','/home/john/pli/cpm/pli80/DISK1','--output-dir',str(Path(t)/'proof'),'--family-only','--cross-source','FACTOR'],check=True)
  shutil.copyfile(Path(t)/'proof/natural-cases.json',OUT/'factor-natural-cases.json')
 result={f"PLI2.OVL+{e['offset']:04X}":dict(calls=len(e['members']),proof_hash=digest(e['members']))for e in load(OUT/'factor-natural-cases.json')['sources'][0]['entries']}
 save(REPORT/'cross-evidence.json',dict(FACTOR=result,OPTIMIST='Prior durable coverage totals preserved;no new trace infrastructure.'))


def contracts():
 law=dict(end=0x7365,description='Save three carriers and publish a bounded adjacent relation pair',completeness=['stable','complete','partial'],contract='Save D atADBF then E atADBE then C atADBD, preserving flags. FreshADBD CPI6: C6 returns immediately with comparison flags (DEDUCED STATIC UNOBSERVED). Otherwise requireC0..5 so both canonical7314 indices are supported. PairedLHLDADBE ->L=E,H=D;A=H;independentpairedLHLDADBD ->L=C,H=E;E=A,C=L;CALL7314 at7352 publishes(C,D). FreshLDAADBD INR A computesu8(C+1), NZPA fromINR, CY preserved. IndependentpairedLHLDADBE;PUSHPSW735C writes accumulator high then packedflags low;A=L;E=A;POPB735F restoresB=incrementedselector andC=packedflags;MOVC,B;CALL7314 at7361 publishes(u8(C+1),E). RET7364 consumes original hardware word. Savedbytes freshly reread;no privateframe/host-local replacement. All childflags/stack residue retained. C>=7 rejects before mutation;FF increment wouldwrap but first canonical indexFF unsupported. Code/caller/continuation/scratch/table/stack/sentinel aliases excluded;no source/caller/ordinal dispatch.')
 save(REPORT/'contract-laws-PLI2.OVL.json',{'PLI2.OVL+7338':law})
 raw=load(OUT/'rows.json');save(OUT/'annotation-rows-PLI2.OVL.json',{s:{'PLI2.OVL+7338':g['PLI2.OVL+7338']}for s,g in raw.items()})
 save(OUT/'annotation-static-PLI2.OVL.json',{'PLI2.OVL+7338':[dict(origin=dict(image=dict(name='PLI2.OVL'),offset=0x7348),bytes='C9',disassembly='RET',control=dict(kind='return'),evidence_class='DEDUCED STATIC UNOBSERVED;independent synthetic C6 CPU proof')]})

def ranking():
 raw=load('_build/host-compiler-pass-51/residual-map.json');out={}
 inside=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
 baseline=['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in[0x7434,0x7630,0x765e,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619,0x7701,0x8248,0x7ae4,0x7b99,0x7b1b,0x7e05,0x742a,0x8258,0x82b5,0x7338]]
 for source,v in raw.items():
  ws=v['windows'];pre=v['roots']+[r for r in ws if r['target']in baseline];pre=[r for r in pre if not any(q is not r and inside(r,q)for q in pre)]
  pictured=[]
  for r in ws:
   if r['caller']in['PLI2.OVL+7FBA','PLI2.OVL+7FD9','PLI2.OVL+8015','PLI2.OVL+802B']and r['target']=='PLI2.OVL+7365':
    q=min([q for q in ws if inside(r,q)],key=lambda q:q['ret']-q['call']);pictured.append(dict(callsite=r['caller'],true_parent=q['target']))
  targets=['PLI2.OVL+829C','PLI2.OVL+82DD','PLI2.OVL+7ED6'];candidates=[]
  for k in targets:
   rs=[r for r in ws if r['target']==k];residual=0;absorbed=collections.Counter();sequences=collections.Counter()
   for r in rs:
    child=[q for q in ws if inside(q,r)];direct=[q for q in child if not any(z is not q and inside(q,z)for z in child)]
    sequences['/'.join(q['target']for q in direct)]+=1
    lower=[q for q in pre if inside(q,r)];absorbed.update(q['target']for q in lower);residual+=r['ret']-r['call']-sum(q['ret']-q['call']for q in lower)
   candidates.append(dict(coordinate=k,calls=len(rs),callers=dict(collections.Counter(r['caller']for r in rs)),direct_sequences=dict(sequences),residual_ranking_only=residual,contained_native_roots=dict(absorbed),hypothetical_transition_delta=len(rs)-sum(absorbed.values())))
  out[source]=dict(candidates=candidates,PICTURE_7365_parent_discovery=pictured)
 save(REPORT/'next-boundary-ranking.json',dict(sources=out,decision='Prefer829C as next compact field-generation assessment;82DD is an independent lifecycle/finalization operation. PICTURE-only7365 callsites are all internal to the true7ED6 parent;recover its broader state law before migration. Ranking values are not savings and no additional root is migrated.'))

def reports():
 raw=load(OUT/'rows.json');nat=load(OUT/'proof/natural-cases.json');top=load(REPORT/'topology-summary.json');post=load(OUT/'proof/cumulative-hybrid-summary.json');laws=load(REPORT/'contract-laws-PLI2.OVL.json');hierarchy=[];proofs=[];checkpoints={}
 for source,g in raw.items():
  t=top[source];h=next(v for v in post['sources']if v['result']['source']==source);p=next(v for v in nat['sources']if v['source']==source)
  assert h['result']['host_transitions']-sum(h['pre_transition_vector'])==t['net_host_delta']
  hierarchy.append(dict(source=source,roots=t['external'],pre_guest=h['pre_guest_instructions'],post_guest=h['result']['actual_guest_instructions'],removed=h['guest_instructions_removed'],pre_host=sum(h['pre_transition_vector']),post_host=h['result']['host_transitions'],delta=t['net_host_delta'],absorbed_runner_roots=t['absorbed'],internal_calls=t['logical_internal'],remaining=t['remaining']))
  proofs.append(dict(source=source,entries=[dict(coordinate=f"PLI2.OVL+{e['offset']:04X}",count=len(e['members']),proof_hash=digest(e['members']),stack_pattern='original_CALL;childCALL;PSW_PUSH_POP_B;childCALL;original_RET')for e in p['entries']]))
  checkpoints[source]=[dict(call=r['call'],own=r['own_witnesses'],children=children_any({**r,'nested_returns':{int(k):v for k,v in r['nested_returns'].items()}}),ret=r['ret'])for r in g['PLI2.OVL+7338']]
  save(OUT/('checkpoints-'+source+'.json'),checkpoints[source])
 routes={}
 for source,g in raw.items():
  rs=g['PLI2.OVL+7338'];routes[source]=dict(calls=len(rs),C=dict(collections.Counter(str(r['entry']['before']['c'])for r in rs)),D=dict(collections.Counter(str(r['entry']['before']['d'])for r in rs)),E=dict(collections.Counter(str(r['entry']['before']['e'])for r in rs)),C6=sum(r['entry']['before']['c']==6 for r in rs),C_FF=sum(r['entry']['before']['c']==255 for r in rs))
 factor=load(OUT/'factor-natural-cases.json')['sources'][0];rs=next(e['members']for e in factor['entries']if e['offset']==0x7338)
 routes['FACTOR']=dict(calls=len(rs),C=dict(collections.Counter(str(r['input']['c'])for r in rs)),D=dict(collections.Counter(str(r['input']['d'])for r in rs)),E=dict(collections.Counter(str(r['input']['e'])for r in rs)),C6=sum(r['input']['c']==6 for r in rs),C_FF=sum(r['input']['c']==255 for r in rs))
 save(REPORT/'route-summary.json',routes)
 save(REPORT/'hierarchy-summary.json' ,dict(sources=hierarchy,suppression='Exact accepted7338 windows only;7314 is canonical internal primitive,not a prior Runner interceptor. External residual7314 describes guest calls;expected -one host/root hypothesis does not apply to current enabled baseline.'))
 synth=load(OUT/'proof/synthetic-checkpoints.json');synth['cases']=[v for v in synth['cases']if v['route'].startswith('7338_')]
 save(REPORT/'shadow-summary.json',dict(all_passed=True,sources=proofs,components=load(OUT/'proof/component-shadows.json'),checkpoint_hashes={k:digest(v)for k,v in checkpoints.items()},synthetic=dict(cases=len(synth['cases']),routes=dict(collections.Counter(v['route']for v in synth['cases'])),proof_hash=digest(synth),classification='DEDUCED STATIC UNOBSERVED original concreteCPU full-state proof'),comparison=['all registers/flags','SP/PC/continuation','ordered writes/full65536RAM','stack last writers/child chronology','DMA/filesystem/record/service chronology']))
 for n in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:save(REPORT/n,load(OUT/'proof'/n))
 old=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/manifest.json']));cur=load('research/annotated-assembly/manifest.json');im=lambda v:next(q for q in v['images']if q['name']=='PLI2.OVL');status=lambda i,a:next(s['status']for s in i['sections']if s['start_offset']<=a<s['end_offset'])
 promotions=collections.Counter(status(im(old),a)for a in range(0x7338,0x7365)if status(im(cur),a)=='UNDERSTOOD'and status(im(old),a)!='UNDERSTOOD');observed=sum(len(bytes.fromhex(w[1]))for w in load(OUT/'cfg.json')['PLI2.OVL+7338'])
 fidelity=dict(promotions=dict(promotions),RAW_to_UNDERSTOOD=promotions['RAW'],DECODED_to_UNDERSTOOD=promotions['DECODED'],STRUCTURED_to_UNDERSTOOD=promotions['STRUCTURED'],OBSERVED_bytes=observed,DEDUCED_STATIC_UNOBSERVED_bytes=45-observed,represented_bytes=45,bounds='stable',control_flow='complete',contract='partial',unsupported='C>=7 includingFF;code/caller/continuation/stack/scratch/table/sentinel aliases;canonical child unsupportedstates.',archaeological_scope_extension=True,historical_correction=None,implementation_correction=None,discovery_corrections=['Exact[7338,7365) has45bytes,not approximate43.','Residualcanonical7314 calls are not enabled Runner boundaries;actualhostdelta measured rather than predictedminusone/root.'],pragmatic_divergence=None,fidelity_debt='Bounded C0..5 publications and C6 earlyreturn only;unobservedC6 proved synthetically but not OBSERVED;higher compiler meaning unproved.',oracle_queries=0)
 save(REPORT/'fidelity.json',fidelity)
 semantic=dict(historical_root='PLI2.OVL+7338',semantic_inputs=['base carrier selector C','first value D','second value E'],semantic_outputs=['C6: no table publication;three scratch saves remain observable','C0..5:publish relation D at C and relation E at u8(C+1)'],shared_historical_state=['ADBD/ADBE/ADBF savedC/E/D','canonicalADBB/ADBC scratch;ADAA gate;ADAB/ADB3 indexed state'],historical_mechanism=['reverse-address save order D,E,C','independent pairedLHLD reads','INR byte NZPA andpreservedCY','PUSHPSW/POPB transports selector through actualstack andpackedflags','two canonical7314 operations;exact hardwareCALL/RET residue'],candidate_modern_operation='Publish adjacent carrier relation pair unless selector is six',confidence=dict(publication_law='OBSERVED primary andFACTOR;DEDUCED instructions',early_return='DEDUCED STATIC UNOBSERVED synthetic CPU',future_semantic_name='HYPOTHESIS;no source-language meaning assigned'),mir_relevance='Documentation only;no MIR/API or faithful-code refactor.')
 save(REPORT/'semantic-extraction.json',semantic)
 cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};prior=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))
 for p in prior['procedures']:
  for source,n in p['observed_paths']['invocations_by_run'].items():assert cat[p['id']]['observed_paths']['invocations_by_run'].get(source,0)>=n
 save(REPORT/'coverage-preservation.json',dict(all_prior_catalog_totals_preserved=True,cross=load(REPORT/'cross-evidence.json')))
 packet=dict(task='PLI2_PAIRED_CARRIER_PUBLICATION_7338_PASS_62',baseline=BASE,root='PLI2.OVL+7338',laws=laws,inventory=load(REPORT/'inventory-summary.json'),proofs=proofs,checkpoint_hashes={k:digest(v)for k,v in checkpoints.items()},synthetic=load(REPORT/'shadow-summary.json')['synthetic'],canonical_child=dict(coordinate='PLI2.OVL+7314',contract_hash=digest(cat['PLI2.OVL+7314']),route_id='bounded_index0..7',proof_hash=digest([e for v in proofs for e in v['entries']if e['coordinate']=='PLI2.OVL+7314'])),hierarchy=hierarchy,fidelity=fidelity,cross=load(REPORT/'cross-evidence.json'),next_boundary='829C assessed before independent82DD lifecycle',oracle_queries=0)
 save(REPORT/'implementation-packet.json',packet);size=(REPORT/'implementation-packet.json').stat().st_size;assert size<=28672,size
 table='\n'.join(f"|{h['source']}|{h['pre_guest']} → {h['post_guest']}|{h['removed']}|{h['pre_host']} → {h['post_host']}|{h['roots']}|"for h in hierarchy)
 (REPORT/'README.md').write_text(f"""# Pass62 — paired carrier publication

The baseline is published Pass61 `{BASE}`. The scheduled FULL aggregate was interrupted at the user’s request before completion. The implementation is published with FULL validation pending; no aggregate success is claimed. [validation.json](validation.json) records focused evidence and pending status.

To run the full checkpoint later from `/home/john/pli/lab`:

```bash
python3 tools/annotated-assembly/run_paired_carrier_publication_pass_62.py validate
```

This uses all categories and four workers, records detailed results under `_build/host-compiler-pass-62/full-validation/`, and updates the durable validation receipt. The previous completed FULL checkpoint remains Pass59 until this aggregate succeeds.

## Entry, topology and scope

The real entry is PLI2.OVL+7338, with exact bounds `[7338,7365)` (**45 bytes**, rather than the approximate 43). No overlapping natural entry was found. All calls originate at +809D inside the broader +8072 policy. Primary logical/external counts are MINIMAL 3, FIZZBUZ 11 and PICTURE 4. Each root contains exactly two +7314 calls. FACTOR adds five independently shadowed roots and ten corresponding children. Prior FACTOR/OPTIMIST catalog totals are preserved.

Natural C values are 0, 2 and 4. [inventory-summary.json](inventory-summary.json) retains the complete C/D/E tuples, callers and returns; [route-summary.json](route-summary.json) records individual carrier distributions, early-return coverage and wrapping coverage. No natural C=6 case occurs. The early RET at +7348 has independent synthetic CPU proof and remains **DEDUCED / STATIC / UNOBSERVED**.

## Exact historical law

The parent writes ADBF=D, ADBE=E, ADBD=C, in that order. HL descends through these addresses; the saves preserve flags. A fresh ADBD read and CPI 6 select the early return.

Otherwise the parent independently reads the little-endian words at ADBE and ADBD. These reads select saved D as E and saved C as C for canonical +7314 at +7352. The first child publishes the relation `(C,D)`. Its supported table and scratch writes do not overlap ADBD..ADBF.

After the first child, a fresh ADBD read and INR compute `u8(C+1)`. INR replaces NZPA and preserves CY. Another paired ADBE read obtains saved E/D. PUSH PSW at +735C writes the incremented accumulator high and packed flags low below SP. MOV A,L and MOV E,A select saved E. POP B restores B as the incremented selector and temporarily C as the packed flags byte; MOV C,B restores the selector. Canonical +7314 at +7361 publishes `(u8(C+1),E)`. RET +7364 consumes the original continuation.

No cached entry values replace the fresh paired reads, flags or actual stack transport. Canonical +7314 is unchanged. Accepted scope is C=0..5 for two publications, plus C=6 for early return. Bounds are stable and local CFG complete; the general contract remains partial. C=7 rejects because its second child would use index 8. C=FF rejects because its first child index is unsupported; the parent does not pretend to support global wrapping indices. Code, caller, continuation, scratch/table, stack and sentinel aliases fail closed during copied staging. Both child indices are validated before any live mutation.

## Independent proofs and stack

All 18 primary and five FACTOR roots independently match registers, flags, SP/PC, ordered writes, all 65536 RAM bytes, stack last writers, child chronology, DMA, filesystem and record/service state. Canonical +7314 has separate useful global shadows: 8/33/9 primary calls and 12 FACTOR calls. Natural per-instruction checkpoints retain carrier saves, CPI, paired reads, both child windows, INR, PUSH/POP and RET. Full journals remain ignored under `_build/host-compiler-pass-62`; [shadow-summary.json](shadow-summary.json) retains hashes.

There are 54 targeted primary synthetic proofs: C=0, C=5 and C=6 with distinct D=91/E=2C, repeated at each natural entry state. The original concrete CPU independently compares full registers/flags/RAM, ordered writes and stack writer chronology. C=6 returns with A=6 and CPI flags, original BC/DE, HL=ADBD and only the three scratch writes. Unsupported C=7/7F/FE/FF and alias negatives reject before publication.

There is no private frame. The entry CALL word stays at entry SP. First child CALL writes continuation runtime 9555 below SP; canonical +7314 leaves its actual deeper PUSH/POP address carrier. Parent PUSH PSW reuses the child CALL slots, and POP B restores SP. Second child CALL overwrites those slots with runtime 9564 and leaves its own deeper residue. Final RET returns to the original caller with SP=entrySP+2. Last-writer journals account for surviving bytes, including overwritten PSW carriers.

## Measured hierarchy and hybrids

| Source | Pass61 → Pass62 guest | Removed | Host before → after | Roots |
|---|---:|---:|---:|---:|
{table}

The task's predicted minus-one transition per root assumed standalone +7314 interceptors. Current +7314 is a canonical internal primitive, **not an enabled Runner boundary**. External residual calls were guest work. The new parent therefore adds one measured transition per root and absorbs two guest +7314 calls, with no previously enabled native roots suppressed. No artificial leaf interceptor was added to manufacture the predicted savings. External +7314 becomes 0/0/0; +119E remains 36/36/43. Suppression is confined to exact accepted windows.

Standalone and cumulative hybrids preserve exact REL hashes, full REL/INT record chronology, filesystem, console, PASS1/PASS2/END, BDOS ordering/counts and warm boot. The hashes are:

- MINIMAL: `7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119`
- FIZZBUZ: `68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203`
- PICTURE: `c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1`

## Archaeology and next boundary

RAW → UNDERSTOOD: {promotions['RAW']}; DECODED → UNDERSTOOD: {promotions['DECODED']}; STRUCTURED → UNDERSTOOD: {promotions['STRUCTURED']}. Of the 45 represented bytes, {observed} are naturally OBSERVED and {45-observed} is DEDUCED / STATIC / UNOBSERVED (early RET). Prior canonical children are unchanged. Historical reconstruction remains exactly 94720 bytes. Oracle queries: zero. There is no historical correction, implementation correction or pragmatic divergence. The size and Runner-boundary findings correct task orientation/accounting, not historical behavior. Fidelity debt is explicit bounded index/alias scope and unproved higher compiler meaning.

[semantic-extraction.json](semantic-extraction.json) separates the possible adjacent relation publication concept from scratch addresses, paired reads, byte flags, PSW transport and hardware stack machinery. There is no faithful-code refactor or MIR/API design.

The immediate +8072 parent also uses +7ED6, +75CE, +7619 and sometimes +7A17; its wider generation policy is deferred. [next-boundary-ranking.json](next-boundary-ranking.json) compares +829C field generation, +82DD lifecycle/finalization and true +7ED6. All four PICTURE-only +7365 callsites (+7FBA/+7FD9/+8015/+802B) belong to +7ED6; they are not separate entries. +829C is the preferred compact Pass63 assessment, while +82DD has greater residual leverage but introduces a separate finalization/output lifecycle. Ranking values are not savings.

Packet: {size} bytes. Driver phases automate discovery/inventory, contracts, component/root proofs, cross-evidence, topology, ranking, reports, focused checks and full-checkpoint dispatch. Interactive call count is not instrumented. Full logs remain ignored under `_build`. `scripts/view-optimist.sh` is untouched.
""")
 save(REPORT/'validation.json',dict(validation_tier='FULL',full_checkpoint_base='a3ca60c886833e1bdae92e1334504c9acd5fabd8',status='ready for final aggregate',reruns=[],historical_bytes=94720))

def validate():
 dest=OUT/'full-validation';r=subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images','/home/john/pli/cpm/pli80/DISK1','--output',str(dest),'--workers','4'])
 receipt=load(dest/'results.json');receipt.update(validation_tier='FULL',full_checkpoint_base='a3ca60c886833e1bdae92e1334504c9acd5fabd8',status='passed initially'if r.returncode==0 else'initial aggregate failed',initial_all_passed=r.returncode==0,reruns=[],historical_bytes=94720,category_count=len(receipt['categories']),distinct_python_tests=sum(v['python_tests']for v in receipt['categories'].values()),dune_stanzas=Path('test/dune').read_text().count('(test\n'))
 receipt['summed_category_seconds']=sum(v['elapsed_seconds']for v in receipt['categories'].values());receipt['slowest_categories']=sorted([dict(category=k,seconds=v['elapsed_seconds'])for k,v in receipt['categories'].items()],key=lambda v:-v['seconds'])[:8]
 save(REPORT/'validation.json',receipt)
 if r.returncode:raise RuntimeError('full validation failed')

def check_cached():
 import unittest,test_paired_carrier_publication_pass_62 as suite
 suite.IMAGES=Path('/home/john/pli/cpm/pli80/DISK1');suite.prove=lambda _:None
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(suite.PairedPublication))
 if not result.wasSuccessful():raise RuntimeError('focused checks failed')

if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['discovery','inventory','contracts','topology','ranking','cross','components','prove','reports','check_cached','validate']);a=p.parse_args()
 if a.phase in ['components','prove']:prove(focused=a.phase=='components')
 else:globals()[a.phase]()
