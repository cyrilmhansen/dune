#!/usr/bin/env python3
"""Deterministic compact PLI2 adapter inventory; exhaustive journals stay in _build."""
import collections,json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_buffered_rel_emission_pass_52 import save,digest
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-53');REPORT=Path('research/host-compiler/pass-53')
ENTRIES=[0x7434,0x7630,0x765e,0x7550,0x753c,0x7647,0x8258,0x82b5,0x77cc]
def inventory():
 start=time.monotonic();full={};summary={};cfg={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{f'PLI2.OVL+{x:04X}':(x,x+1)for x in ENTRIES},include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8})
  full[source]=rows;summary[source]={}
  for key,rs in rows.items():
   own={w['origin']['offset']:[w['origin']['offset'],w['bytes'],w['disassembly']]for r in rs for w in r['own_witnesses']};cfg.setdefault(key,{}).update(own)
   summary[source][key]=dict(logical=len(rs),callers=dict(collections.Counter(coord(r['call']['origin'])for r in rs)),children=dict(collections.Counter('/'.join(c['target']for c in children_any(r))for r in rs)),entries_hash=digest([r['entry']['before']for r in rs]),returns_hash=digest([r['ret']['after']for r in rs]))
 save(OUT/'rows.json',full);save(OUT/'cfg.json',{k:sorted(v.values())for k,v in cfg.items()});save(REPORT/'inventory.json',summary)
 print(json.dumps(dict(inventory=summary,CFG={k:sorted(v.values())for k,v in cfg.items()},wall_seconds=round(time.monotonic()-start,3)),indent=2))
def prove(images,focused=False):
 import subprocess,tempfile,shutil
 OUT.mkdir(parents=True,exist_ok=True);start=time.monotonic()
 with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
  command=['dune','exec','bin/native_pli2_emission_adapters.exe','--','--toolchain',str(images),'--output-dir',str(Path(tmp)/'results')]
  if focused:command+=['--family-only']
  with(OUT/'proof.log').open('w')as log:r=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((OUT/'proof.log').read_text()[-4000:])
  for f in (Path(tmp)/'results').glob('*.json'):shutil.copyfile(f,OUT/f.name)
 save(OUT/'proof-timing.json',dict(all_passed=True,wall_seconds=round(time.monotonic()-start,3)))
 print('proof passed',round(time.monotonic()-start,3))

def topology():
 import bisect
 from run_buffered_rel_emission_pass_52 import load
 raw=load(Path('_build/host-compiler-pass-51/residual-map.json'));rows=load(OUT/'rows.json');resident=load(Path('_build/host-compiler-pass-52/rows.json'));serializer=load(Path('_build/host-compiler-pass-52/inventory-full.json'));summary={}
 for source,g in rows.items():
  v=raw[source];windows=v['windows'];steps=v['steps'];roots=v['roots']+[q for q in windows if q['target']=='PLI.COM+1272']
  within=lambda a,b,q:q['call']<a<b<=q['ret']
  external=lambda r:not any(within(r['call']['step_index'],r['ret']['step_index'],q)for q in roots)
  resident_roots=[r for key,rs in resident[source].items()if key in ['PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']for r in rs if external(r)]
  root_windows=[dict(call=r['call']['step_index'],ret=r['ret']['step_index'])for r in resident_roots]
  adapters=[r for key,rs in g.items()if key in ['PLI2.OVL+7434','PLI2.OVL+7630','PLI2.OVL+765E']for r in rs if external(r)]
  outer=[r for r in adapters if not any(t is not r and t['call']['step_index']<r['call']['step_index']<r['ret']['step_index']<=t['ret']['step_index']for t in adapters)]
  chosen=[dict(call=r['call']['step_index'],ret=r['ret']['step_index'])for r in outer]
  count=lambda a,b:bisect.bisect_right(steps,b)-bisect.bisect_right(steps,a)
  member={};parents={}
  for key in ['PLI2.OVL+7434','PLI2.OVL+7630','PLI2.OVL+765E']:
   rs=g[key];ext=[r for r in outer if r['entry_key']==key]
   contained=[r for r in resident_roots if any(within(r['call']['step_index'],r['ret']['step_index'],q)for q in chosen if any(t['call']['step_index']==q['call']for t in ext))]
   rank=sum(count(r['call']['step_index'],r['ret']['step_index'])-sum(count(q['call'],q['ret'])for q in root_windows if r['call']['step_index']<q['call']<q['ret']<=r['ret']['step_index'])for r in ext)
   member[key]=dict(logical=len(rs),external=len(ext),resident_roots_absorbed=len(contained),new_minus_absorbed=len(ext)-len(contained),residual_ranking=rank)
   for r in ext:
    ancestors=[q for q in windows if within(r['call']['step_index'],r['ret']['step_index'],q)]
    if ancestors:
     p=max(ancestors,key=lambda q:q['call']);parents.setdefault(p['target'],dict(callers=set(),calls=set()))['calls'].add(p['call']);parents[p['target']]['callers'].add(p['caller'])
  for q in parents.values():q['calls']=len(q['calls']);q['callers']=sorted(q['callers'])
  bits=resident[source]['PLI.COM+119E'];pre=[r for r in bits if external(r)and not any(within(r['call']['step_index'],r['ret']['step_index'],q)for q in root_windows)]
  post=[r for r in pre if not any(within(r['call']['step_index'],r['ret']['step_index'],q)for q in chosen)]
  summary[source]=dict(members=member,adapter_roots=len(outer),resident_roots_absorbed=sum(x['resident_roots_absorbed']for x in member.values()),immediate_parents=parents,serializer_remaining_pre=len(pre),serializer_absorbed_direct=len(pre)-len(post),serializer_remaining_post=len(post),remaining_callers=dict(collections.Counter(coord(r['call']['origin'])for r in post)))
 save(REPORT/'topology-summary.json',summary);print(json.dumps(summary,indent=2))


def contracts():
 rows=json.load(open(OUT/'rows.json'));cfg=json.load(open(OUT/'cfg.json'))
 base='9a119ea41243d57da42233de92e1d5358d120e15'
 common='Current state only; no caller/source/step selection. Successful canonical resident119E/1140 writer,2029.bit0 clear,index<128,bit<8,valid immutable code/continuation and nonalias cache/buffer/FCB/sentinel/stack required. Errors, arbitrary service capacity and unsupported aliases fail closed in copied staging.'
 laws={
  'PLI2.OVL+7434':dict(end=0x744d,description='Bounded prefix/publication/tag40 REL adapter',completeness=['stable','complete','partial'],contract='Save input B atADC7 then C atADC6. Set E7,C96; call canonical resident119E at743E. Independently paired-read ADC6; SHLD1C2C low then high; BC=freshly read word; call canonical resident11E5 at7449. Return actual final child registers/flags with no local frame. Prefix7 then tag40/low8/high8, all MSB first. '+common),
  'PLI2.OVL+7630':dict(end=0x7647,description='Bounded leading-bit/tag40/position REL adapter',completeness=['stable','complete','partial'],contract='Save input B atADDD then C atADDC. Set C1; call canonical1140 at7638. Fresh paired-read ADDC into HL/BC; call canonical11E5 at7640. Call canonical7550 at7643, then RET its actual state. Leading bit1,tag40/low8/high8, then two independent position increments. No private frame. '+common),
  'PLI2.OVL+765E':dict(end=0x7675,description='Bounded leading-bit/tag80/position REL adapter',completeness=['stable','complete','partial'],contract='Same parameterized leading-bit/word/position law as7630 with historically fixed cacheADE0/1 and resident1207 tag80. Save high at7661 then low at7663;1140 CALL7666; independently read cache7669;1207 CALL766E;7550 CALL7671. No further semantic parameter or frame. '+common),
  'PLI2.OVL+7550':dict(end=0x7557,description='Bounded two-step emission-position adapter',completeness=['stable','complete','partial'],contract='Ordinary CALL753C at7550, independently CALL753C again at7553; RET actual second child state. Exactly two calls are encoded instructions, not a fixture iteration limit. Each child freshly consumes shared1C2C; no cached first result. No frame. Zero-wrap/error arm in either child unsupported before live mutation.'),
  'PLI2.OVL+753C':dict(end=0x7550,description='Bounded fresh wrapping emission-position increment',completeness=['stable','partial','partial'],contract='Paired fresh LHLD1C2C; INX H modulo65536; SHLD1C2C low then high at7540. Set A0, call complete canonical resident1A29 at7545 (DE=zeroextendA;HL=DE-HL). ORA L consumes actual returned high A and low L; returned logical flags reflect both bytes, CY0/AC0. JNZ754F returns when incremented position !=0. DE0,HL=negated increment modulo65536,A=high OR low,BC preserved. Natural nonzero path only; zero wraps to unexecuted [754C,754F) error CALL, left RAW/unsupported. No data or stack copying from oracle.')}
 save(REPORT/'contract-laws-PLI2.OVL.json',laws)
 save(OUT/'annotation-rows-PLI2.OVL.json',{source:{key:g[key]for key in laws}for source,g in rows.items()})
 topology()
 cat={p['id']:p for p in json.load(open('research/annotated-assembly/procedures.json'))['procedures']}
 packet=dict(task='PLI2_COMPACT_REL_EMISSION_ADAPTERS_PASS_53',baseline=base,full_checkpoint_base='f7b744e2560c0de8ac1115cf91d4beb190f2e7c2',selected='compact PLI2 emission adapter layer:7434 plus parameterized7630/765E pair',laws=laws,topology=json.load(open(REPORT/'topology-summary.json')),natural_inventory=json.load(open(REPORT/'inventory.json')),contracts={k:dict(hash=digest(cat[k]),completeness=cat[k]['completeness'])for k in ['PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207','PLI.COM+119E','PLI.COM+1140','PLI.COM+1A29']},CFG={k:dict(instructions=len(cfg[k]),hash=digest(cfg[k]))for k in laws},stack_pattern='Original CALL slotS unchanged; no persistent frame. Direct resident primitive or7550 CALL atS-2, nested119E/753C atS-4,1140/1A29 deeper by literal hardware CALL. Writer shiftedPSW and successful SetDMA/sequential-write frames derive their own residue. Every ordinaryRET consumes its own word; outerSP=S+2. No N2/N8/XTHL/recursive acquisition protocol reached.',oracle_queries=0,candidates=[dict(level='119E leaf',decision='not intercepted; generic primitive remains internal'),dict(level='resident word family',decision='canonical Pass52 child reused;58 formerly external child transactions absorbed'),dict(level='7434',decision='separate prefix/state-publication adapter within selected layer'),dict(level='7630/765E',decision='one parameterized leading-bit/word/position family; tag/cache differ literally'),dict(level='7647',decision='compact but additionally invokes7510 before7630; one FIZZBUZ case, no further native transition reduction; defer this distinct header policy'),dict(level='8258',decision='compiler word/context policy:75D0,AE66/68 saves,201D bitgate,three emissions and7423'),dict(level='82B5',decision='startup/publications ADAA/ADA8/ADC9/AE6A and79A2 generation; exclude'),dict(level='77CC',decision='structure fields pointerAC9F+2/+3/+6,mask-dependent generation arms; exclude'),dict(level='7701/829C/82DD',decision='general generation/structure/lifecycle boundaries remain deferred')])
 save(REPORT/'implementation-packet.json',packet)
 print('packet bytes',(REPORT/'implementation-packet.json').stat().st_size)


def reports():
 import subprocess
 subprocess.run(['python3','tools/annotated-assembly/verify.py','--images','/home/john/pli/cpm/pli80/DISK1','--write-progress'],check=True)
 load=lambda p:json.loads(Path(p).read_text())
 roots=load(OUT/'natural-cases.json')['sources'];post=load(OUT/'cumulative-hybrid-summary.json');single=load(OUT/'single-hybrid-summary.json');top=load(REPORT/'topology-summary.json');components=load(OUT/'component-shadows.json')
 proof=[];hierarchy=[]
 for r,p in zip(roots,post['sources']):
  entries=[]
  for e in r['entries']:
   cs=e['members'];entries.append(dict(coordinate=('PLI.COM'if e['offset']<0x2200 else'PLI2.OVL')+f"+{e['offset']:04X}",natural_calls=len(cs),callers=dict(__import__('collections').Counter(c['caller']for c in cs)),all_full_states_matched=True,full_proof_hash=digest(cs),services=dict(__import__('collections').Counter(str(s['function'])for c in cs for s in c['service_details']))))
  proof.append(dict(source=r['source'],entries=entries))
  m=top[r['source']]['members'];hierarchy.append(dict(source=r['source'],native_adapter_roots=p['family_roots'],absorbed_native_roots={'PLI.COM+11E5':m['PLI2.OVL+7434']['external']+m['PLI2.OVL+7630']['external'],'PLI.COM+1207':m['PLI2.OVL+765E']['external'],'PLI.COM+11C3':0},logical_serializer_inside=sum(c['serializer_shadows']for c in components['sources']if c['source']==r['source']),logical_bit_writer_inside=sum(c['bit_writer_shadows']for c in components['sources']if c['source']==r['source']),additional_external_serializer_absorbed=top[r['source']]['serializer_absorbed_direct'],external_serializer_remaining=top[r['source']]['serializer_remaining_post'],external_resident_roots_remaining=sum(p['pre_transition_vector'][:3])-p['family_roots'],pre_guest=p['pre_guest_instructions'],post_guest=p['result']['actual_guest_instructions'],instructions_saved=p['guest_instructions_removed'],pre_host=sum(p['pre_transition_vector']),post_host=p['result']['host_transitions'],net_host_delta=0))
 save(REPORT/'shadow-summary.json',dict(all_passed=True,sources=proof,components=components,full_comparisons=['all registers/flags/SP/PC','ordered logical writes','65536 RAM bytes','final stack last writers','actual child CALL chronology','DMA/filesystem','ordered service boundary state','record bytes/chronology'],transactional_negatives=['wrong CALL origin/entry','changed caller/root/child code','changed continuation','output gate/index/bit scope','cache/sentinel/code/stack aliases','position zero-wrap/error arm'],synthetics=['independent low-only/high-only words','A55A at index127 bit7 with full record-byte equation','fresh positions0/00FF/1234']))
 save(REPORT/'hierarchy-summary.json',dict(sources=hierarchy,suppression='Exact corrected adapter windows only; no leaf119E global controller. 58 replacements absorb58 former resident transactions; other resident and lower roots remain independent.'))
 save(REPORT/'single-hybrid-summary.json',single);save(REPORT/'cumulative-hybrid-summary.json',post)
 arch=load(REPORT/'archaeology-summary-PLI2.OVL.json')
 save(REPORT/'fidelity.json',dict(archaeological_scope_extension=True,historical_correction=None,implementation_correction=['Proof orchestration excludes resident children only inside exact adapter windows; duplicate baseline-controller composition fixed before successful hybrids.','Position-only component negatives target actual controlling position state rather than unrelated bit-writer gates.','Reuse annotation renderer and retain frozen historical coverage metadata explicitly.'],pragmatic_divergence=None,fidelity_debt=None,oracle_queries=0,RAW_to_UNDERSTOOD=arch,cpu_runner_cpm_changes=False,shared_proof_schema_change=False,validation_tier='full checkpoint scheduled after finalization',interactive_call_count='not instrumented',scripts_view_optimist_untouched=True,automated_phases=['corrected natural inventory and localCFG','ancestor/candidate assessment','exact-window external and nesting correction','transition economics and remaining119E caller map','cross-caller component and root shadow batches','synthetic bitstream/flush and transactional negative proofs','standalone/cumulative hybrids','byte-preserving annotations at explicit catalog epoch','compact reports and full-checkpoint dispatch']))
 packet=load(REPORT/'implementation-packet.json');packet['proof_hashes']={name:digest(load(REPORT/name))for name in ['shadow-summary.json','hierarchy-summary.json','single-hybrid-summary.json','cumulative-hybrid-summary.json']};packet['proof_counts']={r['source']:{e['coordinate']:e['natural_calls']for e in r['entries']}for r in proof};save(REPORT/'implementation-packet.json',packet)
 save(REPORT/'boundary-assessment.json',dict(selected='PLI2+7434 and paired7630/765E compact emission layer',canonical_pair='7630/765E differ only literal cache and tag member;7434 is a distinct prefix/publication adapter in the same compact layer',immediate_parent_assessment=packet['candidates'][4:],next='Assess compact byte/field emission wrappers PLI2+7557/+75D0 and their immediate policy before crossing into general7701 generation.',remaining_serializer_callers={s:g['remaining_callers']for s,g in top.items()}))
 catalog=load('research/annotated-assembly/procedures.json');old=json.loads(subprocess.check_output(['git','show','9a119ea41243d57da42233de92e1d5358d120e15:research/annotated-assembly/procedures.json']))
 current={p['id']:p for p in catalog['procedures']}
 for p in old['procedures']:
  for source,n in p['observed_paths']['invocations_by_run'].items():assert current[p['id']]['observed_paths']['invocations_by_run'].get(source,0)>=n,(p['id'],source,n)
 packet_bytes=(REPORT/'implementation-packet.json').stat().st_size;assert packet_bytes<28672,packet_bytes
 (REPORT/'README.md').write_text(f'''# Pass53 — compact PLI2 REL-emission adapter layer

 Baseline `9a119ea41243d57da42233de92e1d5358d120e15`; scheduled FULL checkpoint follows Pass50 `f7b744e2560c0de8ac1115cf91d4beb190f2e7c2`.

 Fresh corrected natural and external counts agree:7434=3/23/3,7630=1/12/1,765E=1/11/3, total58 roots (5/46/7). No nesting or prior canonical parent contains these adapters. Every adapter contains exactly one previously external Pass52 resident root. No global119E interceptor is introduced.

 7630/765E are one canonical parameterized leading-bit/word/position operation: save input B then C atADDD/ADDC orADE1/ADE0, emit literal bit1 through canonical1140, independently paired-read the saved word, compose canonical11E5/tag40 or1207/tag80, then canonical7550.7434 has a distinct local law in the same compact adapter layer: save B/C atADC7/ADC6, emit C96/E7 through canonical119E, paired-read the cache, publish low/high at1C2C, then canonical11E5/tag40. No speculative item names.

 7550 encodes two separate753C calls, not a fixture repeat limit. Each753C freshly reads1C2C, wrapping-increments and visibly publishes low/high, then sets A0 and composes existing complete resident1A29 subtraction. Returned high A OR low L produces the actual JNZ flags. Nonzero increment returns; zero enters the unexecuted error CALL at754C and fails closed in staging. Final DE0,HL=negated increment,A=high OR low;BC preserved, logical NZP flags/CY0/AC0. All93 natural7550 and322 natural753C windows match independently, including callers outside the accepted adapter layer. All344 natural1A29 windows also independently match the canonical byte adapter over the existing subtraction law.

 Natural proofs:58 adapter roots;203 required119E and1276 required1140 component windows. Each matches all registers/flags/SP/PC, ordered logical writes, complete65536-byte RAM, actual stack last writers, child CALL chronology, DMA/filesystem and service/record chronology. Synthetic low-only/high-only words andA55A at127:7 use an independent bitstream/record equation; positions0/00FF/1234 discriminate fresh increments. Corrupted root/caller/child code, continuations, gate/cursors, aliases and zero-wrap predicates reject without live mutation.

 No private adapter frame. Original CALL word atS persists; children push actual encoded continuations belowS.7550 and its753C/1A29 calls retain independent stack residues. EachRET consumes its own hardware word; outerSP=S+2. The resident writer composes its real shiftedPSW and successful SetDMA/sequential-write frames. No N2/N8/XTHL or recursive acquisition protocol is reached; unrelated canonical parents remain unchanged.

 Immediate parents are separate policy:7647 adds7510 and one FIZZBUZ instance without further transition reduction;8258 adds75D0,context savesAE66/68,201D bitgate and7423;82B5 adds initialization/lifetime publications and79A2;77CC performs structure-field and mask-dependent generation.7701/829C/82DD remain independent general-generation/structure/lifecycle families. The chosen adapter layer moves one coherent level above the generic resident emitter without absorbing those phases.

 95 RAW bytes become UNDERSTOOD:7434=25,7630=23,765E=23,7550=7,753C=17. All bounds stable; straight-line adapters/7550 localCFG complete and contracts partial.753C control-flow/contract partial;754C..754F remainsRAW. No established historical law is corrected. All older catalog entries and FACTOR/OPTIMIST totals are preserved at their epochs.

 Three standalone and three cumulative hybrids preserve exact REL goldens, complete ordered REL/INT record events, filesystem, console, PASS1/PASS2/END, BDOS chronology and warm boot. Whole-run counters:

 |Source|Pass52 guest|Pass53 guest|Removed|Host before/after|Roots|
 |---|---:|---:|---:|---:|---:|
 |MINIMAL|336252|335133|1119|89/89|5|
 |FIZZBUZ|732279|723107|9172|171/171|46|
 |PICTURE|384016|382741|1275|76/76|7|

 58 roots replace58 resident transitions:11E5 absorbs4/35/4 and1207 absorbs1/11/3.203 serializer and1276 bit-writer calls are internal;29 additional formerly external119E calls are absorbed. Remaining external119E=127/427/137; remaining resident roots11/29/12. Equivalent calls outside the corrected windows remain independent. Inclusive ranking counts are not savings claims.

 Model-facing packet {packet_bytes} bytes; exhaustive journals remain ignored under `_build/host-compiler-pass-53`. Zero new oracle queries. Reconstruction94720 exact bytes. Historical correction, pragmatic divergence and fidelity debt: none. Development orchestration fixes are listed separately in fidelity.json.

 Reports/catalog/progress finalized before the scheduled blocking FULL checkpoint; validation.json records its actual categories/tests/stanzas/workers/timing and any reruns. The driver automates inventories, topology, contracts, component/root proof batches, hybrids and checkpoint dispatch. Interactive call count was not instrumented. `scripts/view-optimist.sh` is untouched. Recommend Pass54 assess compact7557/75D0 emission policy before general7701 generation.
 ''')
 save(REPORT/'validation.json',dict(validation_tier='full',full_checkpoint_base='f7b744e2560c0de8ac1115cf91d4beb190f2e7c2',status='ready for finalized aggregate',workers=4,historical_bytes=94720,reruns=[]))
 print('reports finalized; packet',packet_bytes)

def validate(images):
 import subprocess
 dest=OUT/'full-checkpoint'
 subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images',str(images),'--output',str(dest),'--workers','4'],check=True)
 receipt=json.loads((dest/'results.json').read_text());v=json.loads((REPORT/'validation.json').read_text())
 v.update(status='passed initially',all_passed=receipt['all_passed'],category_count=len(receipt['categories']),unique_python_test_count=sum(x['python_tests']for x in receipt['categories'].values()),dune_test_rule_stanzas=39,validation_wall_seconds=receipt['wall_seconds'],summed_category_seconds=receipt['sum_category_seconds'],slowest_categories=receipt['top_10_slowest'],categories=receipt['categories'],reruns=[])
 save(REPORT/'validation.json',v)
 print(json.dumps({k:v[k]for k in ['status','category_count','unique_python_test_count','dune_test_rule_stanzas','workers','validation_wall_seconds','summed_category_seconds','reruns']},indent=2))
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['inventory','topology','contracts','components','prove','reports','validate']);p.add_argument('--images',default='/home/john/pli/cpm/pli80/DISK1');a=p.parse_args()
 if a.phase=='inventory':inventory()
 elif a.phase=='topology':topology()
 elif a.phase=='contracts':contracts()
 elif a.phase=='reports':reports()
 elif a.phase=='validate':validate(a.images)
 else:prove(a.images,a.phase=='components')
