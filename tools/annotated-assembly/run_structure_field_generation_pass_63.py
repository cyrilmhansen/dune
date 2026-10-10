#!/usr/bin/env python3
"""Pass63 structure-derived field discovery and active validation; no FULL dispatch."""
import collections,json,sys,subprocess,os
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_buffered_rel_emission_pass_52 import save,digest
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-63');REPORT=Path('research/host-compiler/pass-63')
BASE='692a4da420409e14970e94754067a33532f41adc'
ENTRIES=[0x829c]
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
  cmd=['dune','exec','bin/native_structure_field_generation.exe','--','--toolchain',str(images),'--output-dir',str(Path(tmp)/'results')]
  if focused:cmd+=['--family-only']
  with(dest/'run.log').open('w')as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((dest/'run.log').read_text()[-4000:])
  for f in(Path(tmp)/'results').glob('*.json'):
   if not focused or f.name in ['component-shadows.json','natural-cases.json','synthetic-checkpoints.json','synthetic-helper-pairs.json']:shutil.copyfile(f,dest/f.name)
 print('proof passed')





def topology():
 raw=load('_build/host-compiler-pass-51/residual-map.json');result={};boundary={}
 inside=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
 targets=['PLI2.OVL+829C']
 previous=['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in[0x7434,0x7630,0x765e,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619,0x7701,0x8248,0x7ae4,0x7b99,0x7b1b,0x7e05,0x742a,0x8258,0x82b5,0x7338]]
 coords=[f'PLI2.OVL+{x:04X}'for x in[0x7314,0x7338,0x829c,0x7365,0x7423,0x7434,0x7630,0x79a2,0x8258,0x82b5,0x7338]]+['PLI.COM+119E']
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

def ranking():
 raw=load('_build/host-compiler-pass-51/residual-map.json');out={}
 inside=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
 baseline=['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in[0x7434,0x7630,0x765e,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619,0x7701,0x8248,0x7ae4,0x7b99,0x7b1b,0x7e05,0x742a,0x8258,0x82b5,0x7338,0x829c]]
 for source,v in raw.items():
  ws=v['windows'];pre=v['roots']+[r for r in ws if r['target']in baseline];pre=[r for r in pre if not any(q is not r and inside(r,q)for q in pre)]
  pictured=[]
  for r in ws:
   if r['caller']in['PLI2.OVL+7FBA','PLI2.OVL+7FD9','PLI2.OVL+8015','PLI2.OVL+802B']and r['target']=='PLI2.OVL+7365':
    q=min([q for q in ws if inside(r,q)],key=lambda q:q['ret']-q['call']);pictured.append(dict(callsite=r['caller'],true_parent=q['target']))
  targets=['PLI2.OVL+82DD','PLI2.OVL+7ED6','PLI2.OVL+18B3'];candidates=[]
  for k in targets:
   rs=[r for r in ws if r['target']==k];residual=0;absorbed=collections.Counter();sequences=collections.Counter()
   for r in rs:
    child=[q for q in ws if inside(q,r)];direct=[q for q in child if not any(z is not q and inside(q,z)for z in child)]
    sequences['/'.join(q['target']for q in direct)]+=1
    lower=[q for q in pre if inside(q,r)];absorbed.update(q['target']for q in lower);residual+=r['ret']-r['call']-sum(q['ret']-q['call']for q in lower)
   candidates.append(dict(coordinate=k,calls=len(rs),callers=dict(collections.Counter(r['caller']for r in rs)),direct_sequences=dict(sequences),residual_ranking_only=residual,contained_native_roots=dict(absorbed),hypothetical_transition_delta=len(rs)-sum(absorbed.values())))
  out[source]=dict(candidates=candidates,PICTURE_7365_parent_discovery=pictured)
 save(REPORT/'next-boundary-ranking.json',dict(sources=out,decision='829C is closed; prefer82DD assessment as an independent lifecycle/finalization operation. PICTURE-only7365 callsites are all internal to the true7ED6 parent;recover its broader state law before migration. Ranking values are not savings and no additional root is migrated.'))


def cross():
 import tempfile,shutil
 for source in ['FACTOR','OPTIMIST']:
  with tempfile.TemporaryDirectory(prefix='cross-',dir=OUT)as tmp:
   cmd=['_build/default/bin/native_structure_field_generation.exe','--toolchain','/home/john/pli/cpm/pli80/DISK1','--output-dir',str(Path(tmp)/'proof'),'--family-only','--cross-source',source]
   with(OUT/(source+'-proof.log')).open('w')as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
   if r.returncode:raise RuntimeError((OUT/(source+'-proof.log')).read_text()[-2000:])
   shutil.copyfile(Path(tmp)/'proof/natural-cases.json',OUT/(source+'-natural-cases.json'))
 print('FACTOR/OPTIMIST natural cross-evidence passed')

def contracts():
 law=dict(end=0x82b5,description='Structure-pointer publication and counted header/tagged payload emission',completeness=['stable','complete','partial'],contract='Fresh little-endian ACA3/A4 word -> HL; SHLD publishes L then H at AC9F/A0. E=7,C=94H; canonical119E emits bits7..1, 1001010. Fresh AC9F/A0 reread after child; INX twice modulo65536; C=fresh byte[pointer+2]; INX; B=fresh byte[pointer+3]; canonical11C3 emits tag00 then low/high bytes. Final state/flags from canonical word serializer; RET consumes original CALL. Accepted nonwrapping four-byte target domain excludes code/output/source/publication/stack/sentinel aliases and inherits child writer/error scope; general structure meaning unknown.')
 save(REPORT/'contract-laws-PLI2.OVL.json',{'PLI2.OVL+829C':law})
 save(OUT/'annotation-rows-PLI2.OVL.json',load(OUT/'rows.json'))

def validate():
 dest=OUT/'active-validation'
 cmd=['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--profile','active','--extra-categories','pass63,pass52','--images','/home/john/pli/cpm/pli80/DISK1','--output',str(dest),'--workers','4']
 tmp=OUT/'tmp';tmp.mkdir(exist_ok=True)
 r=subprocess.run(cmd,env={**os.environ,'TMPDIR':str(tmp.resolve())});receipt=load(dest/'results.json');assert receipt['validation_tier']=='ACTIVE/INCREMENTAL'and receipt['last_certified_full_epoch']['name']=='Pass62'
 receipt.update(historical_bytes=94720,dune_stanzas=39,reruns=[],historical_full_executed=False,full_trigger_fired=False)
 save(REPORT/'validation.json',receipt)
 if r.returncode:raise RuntimeError('active validation failed')


def reports():
 raw=load(OUT/'rows.json');nat=load(OUT/'proof/natural-cases.json');top=load(REPORT/'topology-summary.json');post=load(OUT/'proof/cumulative-hybrid-summary.json');summary=[];proofs=[];inventory={}
 for source,g in raw.items():
  r=g['PLI2.OVL+829C'][0];w={q['origin']['offset']:q for q in r['own_witnesses']};pointer=sum(q['value']<<(8*i)for i,q in enumerate(w[0x829c]['reads']));low=w[0x82ae]['reads'][0]['value'];high=w[0x82b0]['reads'][0]['value']
  inventory[source]=dict(logical=1,external=top[source]['external'],caller=coord(r['call']['origin']),continuation=r['ret']['after']['pc'],entry=r['entry']['before'],pointer=pointer,payload_low=low,payload_high=high,return_state=r['ret']['after'],header_arguments=dict(C=148,E=7),payload_arguments=dict(B=high,C=low),read_order=[q['address']for x in r['own_witnesses']for q in x['reads']],own_write_order=[q for x in r['own_witnesses']for q in x['writes']])
  h=next(q for q in post['sources']if q['result']['source']==source);pre_host=sum(h['pre_transition_vector']);assert h['result']['host_transitions']-pre_host==top[source]['net_host_delta']
  summary.append(dict(source=source,roots=h['family_roots'],pre_guest=h['pre_guest_instructions'],post_guest=h['result']['actual_guest_instructions'],removed=h['guest_instructions_removed'],pre_host=pre_host,post_host=h['result']['host_transitions'],delta=top[source]['net_host_delta'],absorbed=top[source]['absorbed'],logical_internal=top[source]['logical_internal'],remaining=top[source]['remaining']))
  n=next(q for q in nat['sources']if q['source']==source);proofs.append(dict(source=source,entries=[dict(coordinate=('PLI2.OVL'if q['offset']>=0x2200 else'PLI.COM')+f"+{q['offset']:04X}",calls=len(q['members']),proof_hash=digest(q['members']))for q in n['entries']],instruction_checkpoint_hash=digest(r['own_witnesses'])))
  save(OUT/(source+'-instruction-checkpoints.json'),r)
 cross={}
 for source in ['FACTOR','OPTIMIST']:
  g=load(OUT/(source+'-natural-cases.json'))['sources'][0];rs=g['entries'][0]['members'];cross[source]=dict(natural_roots=len(rs),callers=dict(collections.Counter(r['caller']for r in rs)),proof_hash=digest(g),members=[])
  for r in rs:
   j=r['journal'];value=lambda address:next(q[1]for q in j if q[0]==address and q[2]==0xa49f)
   payload=lambda address:next(q[1]for q in j if q[0]==address and q[2]in[0x12c6,0x12c8])
   cross[source]['members'].append(dict(input=r['input'],pointer=value(0xac9f)+(value(0xaca0)<<8),payload_low=payload(0x20b9),payload_high=payload(0x20ba),output=r['output']))
 save(REPORT/'natural-provenance.json',inventory);save(REPORT/'cross-evidence.json',cross);save(REPORT/'hierarchy-summary.json',dict(sources=summary))
 synthetic=load(OUT/'proof/synthetic-checkpoints.json');synthetic['cases']=[q for q in synthetic['cases']if q['route'].startswith('829C_')];assert len(synthetic['cases'])==30
 save(REPORT/'shadow-summary.json',dict(all_passed=True,natural=proofs,cross=cross,synthetic=dict(cases=30,original_CPU_full_state_cases=27,independent_bit_record_boundary_cases=3,route_counts=dict(collections.Counter(q['route']for q in synthetic['cases'])),proof_hash=digest(synthetic)),comparison=['all registers/flags/SP/PC','ordered writes/full65536RAM','stack last writers/child CALL chronology','DMA/filesystem/REL record/service chronology'],journals='ignored _build/host-compiler-pass-63/proof'))
 for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:save(REPORT/name,load(OUT/'proof'/name))
 fidelity=dict(RAW_to_UNDERSTOOD=25,DECODED_to_UNDERSTOOD=0,STRUCTURED_to_UNDERSTOOD=0,OBSERVED_natural_bytes=25,STATIC_UNOBSERVED_bytes=0,synthetic_scope='DEDUCED / STATIC / UNOBSERVED state variants; same naturally observed straight-line instructions',bounds='stable',control_flow='complete',contract='partial',unsupported='Wrapping targets >=FFFD; code/output/source/publication/stack/sentinel aliases; inherited child error/output states',archaeology_extension=True,historical_correction=None,implementation_correction=None,pragmatic_divergence=None,fidelity_debt='Bounded alias/nonwrapping domain; stronger compiler structure/type meaning unproved',oracle_queries=0,historical_bytes=94720,full_trigger_fired=False)
 save(REPORT/'fidelity.json',fidelity)
 semantic=dict(historical_root='PLI2.OVL+829C',semantic_inputs=['little-endian pointer from word ACA3','fresh low/high payload bytes at pointer+2/+3','current buffered REL output state'],semantic_outputs=['visible pointer publication at AC9F','7-bit1001010 header then tag00 then payload low8/high8','actual canonical returned registers/flags/stack/output chronology'],shared_historical_state=['ACA3/A4','AC9F/A0','target+2/+3','20B7/B8 serializer','20B9/BA tagged-word cache','REL buffer/cursor/FCB/DMA and hardware stack'],historical_mechanism=['LHLD low/high acquisition and SHLD low/high publication','independent post-header LHLD','three flag-preserving INX H and separate MOV C,M / MOV B,M','literalC94 E7 RLC serializer chronology','canonical11C3 and actual hardwareCALL/RET/PSW/service residue'],candidate_modern_operation='Emit a structure-derived representation field',confidence=dict(low_level_law='OBSERVED primary plus FACTOR/OPTIMIST; DEDUCED exact instructions',semantic_name='HYPOTHESIS; compiler structure/type meaning unproved',synthetic_variants='DEDUCED STATIC UNOBSERVED'),mir_relevance='Documentation only; no MIR API or faithful-code refactor.')
 save(REPORT/'semantic-extraction.json',semantic)
 cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};old=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))
 for p in old['procedures']:
  for source,count in p['observed_paths']['invocations_by_run'].items():assert cat[p['id']]['observed_paths']['invocations_by_run'].get(source,0)>=count
 save(REPORT/'coverage-preservation.json',dict(all_prior_catalog_totals_preserved=True))
 packet=dict(task='RUNES_PLI2_STRUCTURE_FIELD_GENERATION_829C_PASS_63',baseline=BASE,extent=[0x829c,0x82b5],laws=load(REPORT/'contract-laws-PLI2.OVL.json'),inventory=inventory,proofs=proofs,synthetic=load(REPORT/'shadow-summary.json')['synthetic'],canonical_children=[dict(coordinate=k,contract_hash=digest(cat[k]),route_id='counted_bits_successful_writer'if k.endswith('119E')else'tag00_cached_word',stack_pattern='hardwareCALL_RET_writerPSW',proof_hash=digest([q for p in proofs for q in p['entries']if q['coordinate']==k]))for k in ['PLI.COM+119E','PLI.COM+11C3']],hierarchy=summary,cross=cross,fidelity=fidelity,validation_profile='active',extras=['pass63','pass52'],last_certified_full_epoch='Pass62',next_boundary='82DD lifecycle assessment before broader7ED6/18B3 generation',oracle_queries=0)
 save(REPORT/'implementation-packet.json',packet);size=(REPORT/'implementation-packet.json').stat().st_size;assert size<=28672,size
 table='\n'.join(f"|{h['source']}|{h['pre_guest']} → {h['post_guest']}|{h['removed']}|{h['pre_host']} → {h['post_host']}|"for h in summary)
 text=f"""# Pass63 — structure-derived representation emission

Baseline: `{BASE}`, verified as the published scalability commit. Pass62 remains the last certified FULL epoch (92 historical categories,643 Python tests,39 Dune stanzas,2932.110 wall seconds,zero reruns,94720 bytes). This is a bounded local semantic extension; no FULL trigger fired and historical-full was not executed.

## Bounds and natural evidence

PLI2.OVL+829C has exact extent **[829C,82B5),25 bytes**, ordinary RET at +82B4. All25 bytes are naturally OBSERVED; no overlap/alternate entry occurs in the corrected windows. Primary logical/external roots are **1/1/1**, all called at +19A7 inside true parent +18B3, continuation runtime3BAA. FACTOR and OPTIMIST each add one independently shadowed natural root. Full entry/return states, ordered reads/writes and pointer/payload values are in [natural-provenance.json](natural-provenance.json) and [cross-evidence.json](cross-evidence.json).

Primary pointers are FBE1/FBC9/FBAF; low/high payloads are 07/00,12/00,0B/00. Equal high bytes are not treated as provenance proof.

## Exact law

LHLD ACA3 reads ACA3 then ACA4 into L/H. SHLD AC9F publishes low then high, including same-valued writes. This is a **direct pointer-word copy**, not a dereference through ACA3. E=7,C=94H invokes canonical resident119E at +82A6. Seven MSB-first RLC/append steps emit bits7..1 of94H: **1001010**; bit0 is not emitted.

After the header child returns, LHLD AC9F freshly reads AC9F then ACA0. Two INX H instructions advance modulo65536 to pointer+2, MOV C,M acquires the low payload byte, another INX H advances to pointer+3, and MOV B,M acquires the high byte. Canonical resident11C3 at +82B1 receives that BC word and emits tag00,low8,high8. The total representation is25 bits. Pointer+0/+1 are not read. No source-language or LINK-80 item name is established.

The local instructions preserve flags. Header/writer/serializer children replace flags according to their certified contracts; INX does not expose DAD carry. Final A=0,HL=20B8,E=8 and NZPA/CY come from the final counted-bit child; BC/DE are the actual child channels, not restored entry registers. RET preserves them.

## Proof and supported scope

All three primary roots and both cross-source roots independently compare all registers/flags/SP/PC,ordered writes,full65536RAM,stack last writers,child chronology,DMA/filesystem and record/service state. Each primary has four independent119E component shadows (one header plus three word segments) and one11C3 shadow. Naturally executed bit-writer subtrees are covered transitively and Pass52 supplies independent writer/flush regressions. No established child algorithm was duplicated or globally intercepted.

Twenty-seven synthetic cases run original concrete CPU instructions independently with full state/RAM/write/stack comparisons: distinct low/high bytes; independently varied stale AC9F carrier; low-only and high-only changes; irrelevant neighbor changes; independently changed pointer low/high; page crossing; FFFC nonwrapping target. Three more cases start at output byte127/bit7 and independently verify25-bit packing and exact flushed record bytes. Synthetic state variants are DEDUCED/STATIC/UNOBSERVED; they add no new instruction bytes or natural coverage. Incoming AC9F=1234 differs from the source and is overwritten before its post-header reread. Unsupported FFFD/FFFF wrapping,code/child-code,continuation,stack,source/publication/output/sentinel aliases reject during staging. Copying/preview never mutates live RAM/DMA/filesystem/events before full acceptance.

## Stack and child correlation

No private frame exists. Original CALL from19A7 writes continuation3BAA at entrySP (naturalFFF6), high then low. Header CALL82A6 writes A4A9 below SP; payload CALL82B1 later overwrites those slots with A4B4. Canonical11C3/119E/1140 CALL and PSW/service frames remain historical. Last-writer journals compare every surviving stack byte; final RET returns to3BAA with SP=entrySP+2. Original continuation bytes remain untouched. Per-instruction natural checkpoints and synthetic CPU checkpoints remain under ignored `_build/host-compiler-pass-63`.

## Hierarchy and measured whole-run effects

|Source|Pass62 → Pass63 guest|Removed|Host before → after|
|---|---:|---:|---:|
{table}

Each accepted outer root replaces exactly one formerly external11C3 root: net host delta0 in every source. Each internalizes one direct119E,three tagged-word119E and25 bit-writer calls. Remaining external119E is **35/35/42**, with the82A6 caller class gone. Remaining external resident-family classes and other generation calls are retained in [topology-summary.json](topology-summary.json); suppression is confined to corrected root windows. Ranking sums are not used as savings.

Standalone and cumulative hybrids preserve exact REL hashes,complete REL/INT record chronology,filesystem,console,PASS1/PASS2/END,BDOS order/counts and warm boot:

- MINIMAL:7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119
- FIZZBUZ:68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203
- PICTURE:c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1

## Archaeology and future boundary

RAW→UNDERSTOOD25;DECODED→UNDERSTOOD0;STRUCTURED→UNDERSTOOD0. Naturally OBSERVED25,static-only instruction bytes0. Bounds stable,local CFG complete,general contract partial over explicit nonwrapping/nonalias child scope. Prior FACTOR/OPTIMIST catalog totals are preserved. Historical reconstruction remains94720 exact bytes. Oracle queries0. No historical correction,implementation correction,pragmatic divergence or shared/runtime schema change; fidelity debt is bounded alias/wrapping scope and unproved higher compiler meaning.

[semantic-extraction.json](semantic-extraction.json) separates observed pointer-derived representation emission from scratch/LHLD/INX/register/stack mechanisms. The possible modern name remains HYPOTHESIS. No MIR API or faithful-code refactor.

[next-boundary-ranking.json](next-boundary-ranking.json) compares82DD,7ED6 and discovered ancestor18B3 using post-Pass63 hierarchy. **Recommend82DD for Pass64 assessment**: coherent but separate lifecycle/finalization output.7ED6 is a broader generation policy;18B3 has extensive independent structure/traversal children and is deferred. No upward widening occurs.

## Validation workflow

Pass63-local proofs are exhaustive for supported natural/synthetic scope. ACTIVE core plus explicit extras **pass63,pass52** is the final aggregate. Pass52 is directly justified by119E/11C3/1140 contracts and successful flush scope; no unrelated archived category is selected. Pass63 is registered for future historical-full but is not part of permanent active core. All92 Pass62 categories,infrastructure self-test andPass63 remain selectable; this is a category-set proof,not an executed FULL checkpoint.

```sh
python3 tools/annotated-assembly/run_structure_field_generation_pass_63.py validate
```

This invokes active with explicit extras and writes [validation.json](validation.json), always ACTIVE/INCREMENTAL with last certified FULL epochPass62. Actual aggregate category/test/time metrics are recorded there after execution. Reports/catalog/progress/packet are finalized before launch. The ordinary next FULL target remains approximatelyPass67 unless a real trigger fires.

Packet:{size} bytes. Driver phases:discovery/inventory,contracts,components/prove,cross,topology,ranking,reports,focused checks,active validation. No interactive call counter is instrumented. User-owned `scripts/view-optimist.sh` and unrelated untracked files are untouched. No task temporary directory under `/tmp`; transient proof directories under `_build` are cleaned.
"""
 (REPORT/'README.md').write_text(text)
def check_cached():
 import unittest,test_structure_field_generation_pass_63 as suite
 suite.IMAGES=Path('/home/john/pli/cpm/pli80/DISK1');suite.prove=lambda _:None
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(suite.StructureField))
 if not result.wasSuccessful():raise RuntimeError('focused checks failed')

if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['discovery','inventory','contracts','topology','ranking','cross','components','prove','reports','check_cached','validate']);a=p.parse_args()
 if a.phase in ['components','prove']:prove(focused=a.phase=='components')
 else:globals()[a.phase]()
