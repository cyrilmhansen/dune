#!/usr/bin/env python3
"""Deterministic valid-entry discovery and compact byte/field emission proof driver."""
import collections,json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_buffered_rel_emission_pass_52 import save,digest
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-54');REPORT=Path('research/host-compiler/pass-54')
def inventory():
 start=time.monotonic();raw=json.loads(Path('_build/host-compiler-pass-51/residual-map.json').read_text());entries=set();parents=set()
 for v in raw.values():
  ws=v['windows']
  for r in ws:
   if r['target'].startswith('PLI2.OVL+')and 0x7557<=int(r['target'].split('+')[1],16)<0x7630:
    entries.add(int(r['target'].split('+')[1],16));anc=[q for q in ws if q['call']<r['call']<r['ret']<=q['ret']]
    if anc:parents.add(max(anc,key=lambda q:q['call'])['target'])
 keys={f'PLI2.OVL+{x:04X}':(x,x+1)for x in entries|{0x73d0}}
 keys.update({k:(int(k.split('+')[1],16),int(k.split('+')[1],16)+1)for k in parents})
 full={};summary={};cfg={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,keys,include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8});full[source]=rows;summary[source]={}
  for key,rs in rows.items():
   own={w['origin']['offset']:[w['origin']['offset'],w['bytes'],w['disassembly']]for r in rs for w in r['own_witnesses']};cfg.setdefault(key,{}).update(own)
   summary[source][key]=dict(logical=len(rs),callers=dict(collections.Counter(coord(r['call']['origin'])for r in rs)),children=dict(collections.Counter('/'.join(c['target']for c in children_any(r))for r in rs)),entries_hash=digest([r['entry']['before']for r in rs]),returns_hash=digest([r['ret']['after']for r in rs]))
 save(OUT/'rows.json',full);save(OUT/'cfg.json',{k:sorted(v.values())for k,v in cfg.items()});save(REPORT/'inventory.json',summary)
 print(json.dumps(dict(discovered_entries=[f'{x:04X}'for x in sorted(entries)],immediate_parents=sorted(parents),inventory=summary,CFG={k:sorted(v.values())for k,v in cfg.items()},wall_seconds=round(time.monotonic()-start,3)),indent=2))
def helpers():
 full={};summary={};cfg={}
 keys={f'PLI2.OVL+{x:04X}':(x,x+1)for x in (0x746f,0x74c7,0x7510)}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,keys,include_nested_returns=True);full[source]=rows;summary[source]={}
  for key,rs in rows.items():
   own={w['origin']['offset']:[w['origin']['offset'],w['bytes'],w['disassembly']]for r in rs for w in r['own_witnesses']};cfg.setdefault(key,{}).update(own)
   summary[source][key]=dict(logical=len(rs),callers=dict(collections.Counter(coord(r['call']['origin'])for r in rs)),children=dict(collections.Counter('/'.join(c['target']for c in children_any(r))for r in rs)))
 save(OUT/'helper-rows.json',full);save(OUT/'helper-cfg.json',{k:sorted(v.values())for k,v in cfg.items()});save(REPORT/'helper-inventory.json',summary)
 print(json.dumps(dict(inventory=summary,CFG={k:sorted(v.values())for k,v in cfg.items()}),indent=2))

ENTRIES=[0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619]
HELPERS=[0x746f,0x74c7,0x7510]
BASE='3ea8fa04b3aee725a772f1365763306ea4ee4f62'
def topology():
 raw=json.loads(Path('_build/host-compiler-pass-51/residual-map.json').read_text());result={}
 for source,v in raw.items():
  ws=v['windows'];within=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
  native=v['roots']+[r for r in ws if r['target']in['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207','PLI2.OVL+7434','PLI2.OVL+7630','PLI2.OVL+765E']]
  pre=[r for r in native if not any(q is not r and within(r,q)for q in native)]
  members=[r for r in ws if r['target']in[f'PLI2.OVL+{x:04X}'for x in ENTRIES]and not any(within(r,q)for q in pre)]
  outer=[r for r in members if not any(q is not r and within(r,q)for q in members)]
  bits=[r for r in ws if r['target']=='PLI.COM+119E'and not any(within(r,q)for q in pre)]
  remaining=[r for r in bits if not any(within(r,q)for q in outer)]
  absorbed=[r for r in pre if any(within(r,q)for q in outer)]
  result[source]=dict(members={f'PLI2.OVL+{x:04X}':dict(logical=sum(r['target']==f'PLI2.OVL+{x:04X}'for r in ws),external=sum(r['target']==f'PLI2.OVL+{x:04X}'for r in outer))for x in ENTRIES},roots=len(outer),absorbed_native=dict(collections.Counter(r['target']for r in absorbed)),net_new_transitions=len(outer)-len(absorbed),serializer_before=len(bits),serializer_absorbed=len(bits)-len(remaining),serializer_remaining=len(remaining),remaining_callers=dict(collections.Counter(r['caller']for r in remaining)),logical_children=dict(collections.Counter(r['target']for r in ws if any(within(r,q)for q in outer)and r['target']in['PLI.COM+119E','PLI.COM+1140','PLI2.OVL+753C','PLI2.OVL+7550'])))
 save(REPORT/'topology-summary.json',result);print(json.dumps(result,indent=2))
def contracts():
 rows=json.loads((OUT/'rows.json').read_text());h=json.loads((OUT/'helper-rows.json').read_text())
 common=' Current-state bounded successful output:2029.bit0 clear,index<128,bit<8,nonzero wrapping position after each753C;immutable code/CALL word and nonalias scratch/stack/FCB/buffer/sentinel. Errors and unsupported aliases reject copied staging without live mutation. Canonical1140/119E/753C/7550 reused.'
 specs={
 0x746f:(0x74c7,'Byte carrier with fresh clear policy gate','Save C atADCC. Fresh LDA201D;RAR;JNC74C6 consumes actual bit0. RET preserves RAR flags and all other channels except HL=ADCC. Gate-set [747A,74C6) remainsRAW.',False),
 0x74c7:(0x7510,'Second byte carrier with fresh clear policy gate','Save C atADCF. Independently fresh LDA201D;RAR;JNC750F;RET with HL=ADCF. Gate-set [74D2,750F) remainsRAW.',False),
 0x7510:(0x7529,'Word carrier with fresh clear policy gate','Save B atADD1 then C atADD0. Fresh LDA201D;RAR;JNC7528. RET with HL=ADD0 and actual RAR flags. Gate-set [751D,7528) remainsRAW.',False),
 0x7557:(0x756d,'Zero-prefixed byte with one position publication','Save C atADD2. Set C0;CALL1140 at755D. Independently paired-read ADD2 (adjacent ADD3 also read);C=L,E8;CALL119E at7566. CALL753C at7569;RET actual child state.',True),
 0x756d:(0x75a7,'Combined byte-field carrier and emission policy','Save E atADD4 then C atADD3. Fresh saved C minusC2 then minus1 followed by SBB A forms equality mask; PUSH PSW. Independently saved E minus09 then minus1/SBB A forms second mask. POP B preserves first A/mask in B;C=B;ANA C;RAR;when CY1 set ADD4=1. Fresh saved E OR saved C to C;CALL746F at7598. Independently reread both carriers and OR again;CALL7557 at75A3. RET actual final state. Normalization requires C=C2 and E=09 from arithmetic, never invocation identity.',True),
 0x75a7:(0x75ce,'Guarded zero-prefixed byte with position publication','Save C atADD5. Fresh201D;RAR;JNC75BC. Gate-set [75B2,75BC) unsupported. C0 CALL1140 at75BE;independent paired-readADD5,C=L,E8 CALL119E at75C7;CALL753C at75CA;RET actual state.',False),
 0x75ce:(0x75f1,'Shifted field byte carrier and emission policy','Save E atADD7 then C atADD6. Fresh paired-readADD6;C=L;CALL746F at75D8. Independently paired-readADD7 includingADD8;C=L;CALL74C7 at75DF. Fresh saved E;three ADD A modulo256;fresh saved C OR shifted E;C=A;CALL7557 at75ED. RET actual final state. No modern field masks introduced.',True),
 0x75f1:(0x7619,'Two independently zero-prefixed cached word bytes','Save B atADD9 then C atADD8. C0 CALL1140 at75F9;paired-readADD8,A=L,C=A,E8 CALL119E at7603. Independently C0 CALL1140 at7608;paired-readADD8 again,A=H,C=A,E8 CALL119E at7612. CALL7550 at7615 for two independent753C operations;RET actual state. No tagged-word substitution.',True),
 0x7619:(0x7630,'Cached word carrier policy and two-byte emission','Save B atADDB then C atADDA. Fresh paired-readADDA toBC;CALL7510 at7624. Independently paired-readADDA again toBC;CALL75F1 at762C;RET actual child state.',True)}
 laws={f'PLI2.OVL+{x:04X}':dict(end=end,description=desc,completeness=['stable','complete'if complete else'partial','partial'],contract=law+common)for x,(end,desc,law,complete)in specs.items()}
 save(REPORT/'contract-laws-PLI2.OVL.json',laws)
 save(OUT/'annotation-rows-PLI2.OVL.json',{source:{key:(g[key]if key in g else h[source][key])for key in laws}for source,g in rows.items()})
 topology()
 cat={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
 packet=dict(task='PLI2_COMPACT_BYTE_FIELD_EMISSION_PASS_54',baseline=BASE,selected_entries=[f'PLI2.OVL+{x:04X}'for x in ENTRIES],entrypoint_discovery=dict(search_anchor='75D0',actual='75CE',interpretation='75D0 is third byte of LXI H,ADD7 at75CE, not an instruction boundary. Pass53825E CALL95D0 actually targets73D0 at runtime base2200; coordinate/report discovery, not behavior correction.'),laws=laws,topology=json.loads((REPORT/'topology-summary.json').read_text()),contracts={key:dict(hash=digest(cat[key]),completeness=cat[key]['completeness'])for key in ['PLI.COM+1140','PLI.COM+119E','PLI.COM+11E5','PLI.COM+1207','PLI.COM+1A29','PLI2.OVL+753C','PLI2.OVL+7550']},stack='Original CALL slotS retained;ordinary child CALL words belowS.756D PUSH PSW at757B later POP B carries first mask, not flags. No invented private frame;RET outerSP=S+2. Writer/service/position frames preserved canonically.',immediate_parents=dict(rejected=['78E9 adds independent7897 policy andADFF carrier;one byte child,no transition advantage','7903 addsAE00/AE01 type comparisons andADCA publication before73A7/75CE','793C copies indexedADAB/ADB3 channels before emission','7B1B addsA8/07 masks,B8 branch and7397 policy','7701 pointer-dependent general generation','8225 joins79E2/7A17/73D0/756D/7701','8072 and8145 independent register/context generation','793C/7B1B structure/index-dependent generation','7D05/7D47/7E05 pointer generation'],selected='756D/75CE absorb7557;7619 absorbs75F1. Other7557/75F1 calls and75A7 remain accepted compact roots. No climb beyond general-generation boundary.'),oracle_queries=0)
 save(REPORT/'implementation-packet.json',packet);print('packet', (REPORT/'implementation-packet.json').stat().st_size)
def prove(images,focused=False):
 import subprocess,tempfile,shutil
 OUT.mkdir(parents=True,exist_ok=True);start=time.monotonic()
 with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
  command=['dune','exec','bin/native_pli2_compact_emission.exe','--','--toolchain',str(images),'--output-dir',str(Path(tmp)/'results')]
  if focused:command+=['--family-only']
  with(OUT/'proof.log').open('w')as log:r=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((OUT/'proof.log').read_text()[-4000:])
  for f in(Path(tmp)/'results').glob('*.json'):
   if not focused or f.name in['component-shadows.json','natural-cases.json']:shutil.copyfile(f,OUT/f.name)
 save(OUT/'proof-timing.json',dict(all_passed=True,wall_seconds=round(time.monotonic()-start,3)));print('proof passed',round(time.monotonic()-start,3))
def reports():
 import subprocess
 load=lambda p:json.loads(Path(p).read_text())
 roots=load(OUT/'natural-cases.json')['sources'];post=load(OUT/'cumulative-hybrid-summary.json');single=load(OUT/'single-hybrid-summary.json');top=load(REPORT/'topology-summary.json');components=load(OUT/'component-shadows.json')
 proofs=[];hierarchy=[]
 for r,p in zip(roots,post['sources']):
  entries=[dict(coordinate=('PLI.COM'if e['offset']<0x2200 else'PLI2.OVL')+f"+{e['offset']:04X}",natural_calls=len(e['members']),all_full_states_matched=True,proof_hash=digest(e['members']),services=dict(collections.Counter(str(v['function'])for c in e['members']for v in c['service_details'])))for e in r['entries']]
  proofs.append(dict(source=r['source'],entries=entries))
  t=top[r['source']];hierarchy.append(dict(source=r['source'],roots=p['family_roots'],absorbed_native=t['absorbed_native'],logical_internal=t['logical_children'],serializer_absorbed=t['serializer_absorbed'],serializer_remaining=t['serializer_remaining'],remaining_callers=t['remaining_callers'],pre_guest=p['pre_guest_instructions'],post_guest=p['result']['actual_guest_instructions'],instructions_saved=p['guest_instructions_removed'],pre_host=sum(p['pre_transition_vector']),post_host=p['result']['host_transitions'],net_host_delta=t['net_new_transitions']))
 save(REPORT/'shadow-summary.json',dict(all_passed=True,sources=proofs,components=components,comparisons=['all registers/flags/SP/PC','ordered logical writes','65536 RAM bytes','final stack last writers','actual child CALL chronology','DMA/filesystem','service boundary state/record bytes/chronology'],negative_and_synthetic_tests=['CALL origin/root/caller/child code','continuation and cache/code/stack/sentinel aliases','writer gate/index/bit and fresh201D gate','position zero-wrap before mutation','independent byte/word/shifted-field bit equations','C2/09 normalization vs C2/08 and C3/09','high-only and zero values','index127 bit7 record flush byte equation']))
 save(REPORT/'hierarchy-summary.json',dict(sources=hierarchy,suppression='Exact corrected outer windows;756D/75CE absorb7557 and7619 absorbs75F1. Canonical writer/serializer/position children internal. Pass53/resident/acquisition roots remain enabled elsewhere.',economics='New roots25/148/27;no existing Runner roots contained. Serializer leaves35/191/38 would add264 boundaries;compact roots200 save64 compared with that inferior leaf design. Higher callers add general pointer/structure generation, not a compact emission adapter.'))
 save(REPORT/'single-hybrid-summary.json',single);save(REPORT/'cumulative-hybrid-summary.json',post)
 arch=load(REPORT/'archaeology-summary-PLI2.OVL.json')
 save(REPORT/'fidelity.json',dict(archaeological_scope_extension=True,historical_correction=None,implementation_correction=['Pass53 informal75D0 anchor corrected:operand byte at75CE;runtime95D0 call at825E targets73D0. Coordinate/report discovery only.','Development reused existing SBB-self mask helper with exact 8080 auxiliary carry;initial unbound helper name fixed before component proof.','Driver report/validation dispatch and focused-component copy selection corrected before aggregate validation;an unintended extra proof run was allowed to finish. Focused component runs preserve existing hybrid summaries.'],pragmatic_divergence=None,fidelity_debt=None,oracle_queries=0,RAW_to_UNDERSTOOD=arch,STRUCTURED_to_UNDERSTOOD={'PLI2.OVL+7557':22},cpu_runner_cpm_changes=False,shared_proof_schema_change=False,scripts_view_optimist_untouched=True,interactive_call_count='not instrumented',automated_phases=['valid entry discovery and immediate caller inventory','carrier helper cross-case inventory','corrected outer/nested windows and transition economics','component/root shadow batches and synthetic bit/record equations','standalone/cumulative hybrids','byte-preserving annotation generation with historical totals','compact reports/progress','incremental validation dispatch']))
 packet=load(REPORT/'implementation-packet.json');packet['proof_counts']={r['source']:{e['coordinate']:e['natural_calls']for e in r['entries']}for r in proofs};packet['proof_hashes']={n:digest(load(REPORT/n))for n in ['shadow-summary.json','hierarchy-summary.json','single-hybrid-summary.json','cumulative-hybrid-summary.json']};save(REPORT/'implementation-packet.json',packet)
 save(REPORT/'boundary-assessment.json',dict(selected=[f'PLI2.OVL+{x:04X}'for x in ENTRIES],candidate_correction=packet['entrypoint_discovery'],immediate_parent_assessment=packet['immediate_parents'],next='Assess general PLI2+7701 pointer-dependent generation as a separate semantic family;its seven/25/seven calls contain the dominant remaining PLI2 serializer classes7711/775A/777D/77A2. Also retain independent PLI0 emitter and lifecycle82A6/82E1/82F0 boundaries.',unsupported='201D gate-set carrier/75A7 error arms,753C zero-wrap,1140 write errors and arbitrary aliases remain outside bounded contracts.'))
 current={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};old=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))
 for p in old['procedures']:
  for source,n in p['observed_paths']['invocations_by_run'].items():assert current[p['id']]['observed_paths']['invocations_by_run'].get(source,0)>=n,(p['id'],source,n)
 size=(REPORT/'implementation-packet.json').stat().st_size;assert size<28672,size
 table='\n'.join(f"|{r['source']}|{r['pre_guest']}|{r['post_guest']}|{r['instructions_saved']}|{r['pre_host']}/{r['post_host']}|{r['roots']}|"for r in hierarchy)
 (REPORT/'README.md').write_text(f"""# Pass54 — compact PLI2 byte/field emission layer

 Baseline `{BASE}` is the Pass53 FULL checkpoint. Pass54 uses incremental validation.

 Actual entries in[7557,7630):7557,756D,75A7,75CE,75F1,7619.75D0 is the last operand byte of75CE LXI H,ADD7, not an entry. The Pass53825E runtime95D0 CALL denotes73D0, not75D0. This corrects an informal discovery coordinate, not historical behavior.

 Selected roots compose canonical119E/1140/753C/7550.7557 saves and rereads one byte, emits zero+8bits, then one position step.756D normalizes saved E to1 iff saved C=C2 and E=09 via two independent arithmetic masks, publishes a carrier, then emits their freshly reread OR.75CE publishes separate carriers, then emits saved C OR u8(saved E<<3).75A7 is the fresh201D-clear gated byte operation.75F1 emits independently reread low and high bytes, each zero+8bits, followed by two fresh position increments.7619 adds an independently read cached-word carrier before75F1. No LINK-80 item meanings are assumed.

 Carrier746F/74C7/7510 save C/C/BC then freshly reread201D and RAR;all natural calls take clear bit0. Their gate-set arms remainRAW. New contracts have stable bounds, partial contracts;localCFG is complete only for7557/756D/75CE/75F1/7619. Other alternative arms stayRAW.753C wrap/error and writer error scope remain excluded transactionally.

 All317 logical compact-entry shadows and223 carrier-helper shadows match registers/flags/SP/PC,ordered writes,64KiB RAM,derived stack last writers,child chronology,DMA/filesystem and record chronology. All200 outer roots match independently.264 serializer and2376 bit-writer component shadows pass. Synthetic bit equations exercise zero/high-only fields,C2/09 normalization discriminants and127:7 record flush. Original return words survive;756D PUSH PSW/POP B retains its first mask, distinct from flags. Child/service frames are canonical, with no invented frame.

 |Source|Pass53 guest|Pass54 guest|Removed|Host pre/post|Roots|
 |---|---:|---:|---:|---:|---:|
 {table}

 No formerly native Runner roots are absorbed:these operations were residual guest work.200 compact boundaries replace a hypothetical264 serializer-leaf boundaries, saving64 transitions versus leaf interception.756D/75CE internalize7557;7619 internalizes75F1. Remaining external119E=92/236/99. Immediate callers add general generation/structure/pointer lifetimes;7701 is deferred rather than widening merely to lower transitions.

 Standalone and cumulative hybrids preserve all three golden RELs,full REL/INT record and filesystem chronology,console/PASS1/PASS2/END markers,BDOS ordering/counts and warm boot. Exact hashes and actual counters are in hybrid summaries. Ranking intervals are never savings claims.

 RAW->UNDERSTOOD223 bytes;existing7557 STRUCTURED->UNDERSTOOD22 bytes. FACTOR/OPTIMIST historical totals retained. Zero oracle queries;bounded scope extension. Historical correction,pragmatic divergence and fidelity debt:none. Discovery/development fixes are separately recorded in fidelity.json.

 Packet{size} bytes;full journals remain ignored under`_build/host-compiler-pass-54`. Driver automates extraction,topology,proof batches,hybrids,annotations/reporting and incremental validation. Reports/catalog/progress are finalized before aggregate validation;validation.json records actual results. scripts/view-optimist.sh is untouched. Recommend Pass55 assess7701 as a separate pointer-dependent generation family;ordinary next full checkpoint remains approximately Pass56.
 """)
 save(REPORT/'validation.json',dict(validation_tier='incremental',full_checkpoint_base=BASE,status='ready for aggregate',workers=4,historical_bytes=94720,reruns=[]))
 print('reports finalized;packet',size)
def validate(images):
 import subprocess
 categories='pass54,pass53,pass52,pass51,emitter-unit,native-emitter-unit,word-emitter-unit,packet-continuation,V1,roundtrip-tests,roundtrip,dynamic-progress,diff-check'
 dest=OUT/'incremental-validation'
 subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images',str(images),'--output',str(dest),'--workers','4','--categories',categories],check=True)
 receipt=json.loads((dest/'results.json').read_text());v=json.loads((REPORT/'validation.json').read_text());v.update(status='passed initially',all_passed=receipt['all_passed'],category_count=len(receipt['categories']),unique_python_test_count=sum(x['python_tests']for x in receipt['categories'].values()),dune_test_rule_stanzas=39,validation_wall_seconds=receipt['wall_seconds'],summed_category_seconds=receipt['sum_category_seconds'],slowest_categories=receipt['top_10_slowest'],categories=receipt['categories']);save(REPORT/'validation.json',v)
 print(json.dumps({k:v[k]for k in ['status','category_count','unique_python_test_count','dune_test_rule_stanzas','workers','validation_wall_seconds','reruns']},indent=2))
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['inventory','helpers','topology','contracts','components','prove','reports','validate']);p.add_argument('--images',default='/home/john/pli/cpm/pli80/DISK1');a=p.parse_args()
 if a.phase in['components','prove']:prove(a.images,a.phase=='components')
 elif a.phase=='validate':validate(a.images)
 else:globals()[a.phase]()
