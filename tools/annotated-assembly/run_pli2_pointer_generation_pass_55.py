#!/usr/bin/env python3
"""Bounded pointer/length generation evidence; full journals remain ignored."""
import collections,json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_buffered_rel_emission_pass_52 import save,digest
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-55');REPORT=Path('research/host-compiler/pass-55')
BASE='ea72db3c376d5f19898e795193fa0e514fbe974f'
def inventory():
 full={};summary={};cfg={};start=time.monotonic()
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{'PLI2.OVL+7701':(0x7701,0x7702),'PLI2.OVL+8225':(0x8225,0x8226),'PLI2.OVL+8248':(0x8248,0x8249)},include_nested_returns=True);full[source]=rows
  rs=rows['PLI2.OVL+7701'];cases=[]
  for r in rs:
   own=r['own_witnesses'];cfg.update({w['origin']['offset']:[w['origin']['offset'],w['bytes'],w['disassembly']]for w in own})
   cases.append(dict(caller=coord(r['call']['origin']),call=r['call']['step_index'],ret=r['ret']['step_index'],entry=r['entry']['before'],output=r['ret']['after'],own_hash=digest(own),children=[c['target']for c in children_any(r)],trim_attempts=sum(w['origin']['offset']==0x7723 for w in own),trim_decrements=sum(w['origin']['offset']==0x7743 for w in own),loop_bytes=sum(w['origin']['offset']==0x77a2 for w in own),branches=dict(collections.Counter(f"{w['origin']['offset']:04X}:{w['control'].get('taken')}"for w in own if w['disassembly'].startswith('J'))),reads=[dict(offset=w['origin']['offset'],reads=w['reads'])for w in own if w['origin']['offset']in[0x7723,0x772d,0x775d,0x776f,0x7785,0x7791,0x779b,0x77a5,0x77a8]],writes=[dict(offset=w['origin']['offset'],writes=w['writes'])for w in own if w['writes']]))
  summary[source]=dict(logical=len(rs),callers=dict(collections.Counter(c['caller']for c in cases)),trim_counts=dict(collections.Counter(str(c['trim_decrements'])for c in cases)),loop_counts=dict(collections.Counter(str(c['loop_bytes'])for c in cases)),cases=cases)
 save(OUT/'rows.json',full);save(OUT/'cfg.json',sorted(cfg.values()));save(OUT/'natural-inventory.json',summary)
 save(REPORT/'inventory-summary.json',{s:{k:v for k,v in g.items()if k!='cases'}for s,g in summary.items()})
 print(json.dumps(dict(summary={s:{k:v for k,v in g.items()if k!='cases'}for s,g in summary.items()},CFG=sorted(cfg.values()),sample=summary['MINIMAL']['cases'][0],wall_seconds=round(time.monotonic()-start,3)),indent=2))


def topology():
 raw=json.loads(Path('_build/host-compiler-pass-51/residual-map.json').read_text());result={}
 for source,v in raw.items():
  ws=v['windows'];within=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
  coordinates=['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in [0x7434,0x7630,0x765e,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619]]
  native=v['roots']+[r for r in ws if r['target']in coordinates]
  pre=[r for r in native if not any(q is not r and within(r,q)for q in native)]
  members=[r for r in ws if r['target']=='PLI2.OVL+7701']
  outer=[r for r in members if not any(within(r,q)for q in pre+members if q is not r)]
  bits=[r for r in ws if r['target']=='PLI.COM+119E'and not any(within(r,q)for q in pre)]
  remaining=[r for r in bits if not any(within(r,q)for q in outer)]
  absorbed=[r for r in pre if any(within(r,q)for q in outer)]
  result[source]=dict(logical=len(members),external=len(outer),nested=len(members)-len(outer),absorbed_native=dict(collections.Counter(r['target']for r in absorbed)),net_new_transitions=len(outer)-len(absorbed),serializer_before=len(bits),serializer_absorbed=len(bits)-len(remaining),serializer_remaining=len(remaining),remaining_callers=dict(collections.Counter(r['caller']for r in remaining)),logical_children=dict(collections.Counter(r['target']for r in ws if any(within(r,q)for q in outer)and r['target']in['PLI.COM+119E','PLI.COM+1140','PLI.COM+11E5','PLI2.OVL+75F1','PLI2.OVL+753C','PLI2.OVL+7550'])))
 save(REPORT/'topology-summary.json',result);print(json.dumps(result,indent=2))
def contracts():
 rows=json.loads((OUT/'rows.json').read_text())
 law='Save B atADEB then C atADEA. Compose canonical75F1(BC=0);emit8C with119E E7. Fresh LHLD1C2C;subtract2 modulo65536;compose canonical11E5. PublishADEE=4. Repeatedly independently read ADEE and saved pointer,read byte[pointer+zeroextended ADEE];two arithmetic masks select decrement/retry iff byte=20H and ADEE!=0. PUSH PSW/POP B preserves first mask;ANA/RAR directly controls JNC. Decrement sharedADEE and retry;no fixed iteration schedule. IncrementADEE twice;five ADD A produceu8(ADEE<<5);serialize E3. Fresh201D and201C RAR gates must both have bit0 clear;set arms unsupported. Serialize3F,E8. PublishADEC=0. Fresh ADEE minus2 compared with memoryADEC;JC exits iff index>limit. Independently paired-readADEC and saved pointer each iteration;zeroextend index,read actual byte,publishADED;serializeE8. Independently reread201C and201D,ORA/RAR;bit0-set arm unsupported. Increment sharedADEC;JNZ from actual INR flags repeats;RET actual final state. Scanned k in0..4;encoded valuek+2;emitted bytes0..k inclusive, including one space for all-space field.'
 scope=' Bounded successful copied staging:nonwrapping BC field of five bytes,nonalias scratch/return/service/REL-buffer/FCB/sentinel;immutable instructions and hardware CALL;2029.bit0 clear,index<128,bit<8,each753C increment nonzero. Fresh mode bit0 gates clear at all historical reads. No source/caller/step/snapshot dispatch. Canonical75F1/11E5/119E/1140/7550/753C reused;no nested Runner. Error/mode/alias alternatives fail closed without live mutation.'
 laws={'PLI2.OVL+7701':dict(end=0x77bf,description='Bounded pointed-field trim, length and byte REL generation',completeness=['stable','partial','partial'],contract=law+scope)}
 save(REPORT/'contract-laws-PLI2.OVL.json',laws)
 save(OUT/'annotation-rows-PLI2.OVL.json',{source:{'PLI2.OVL+7701':g['PLI2.OVL+7701']}for source,g in rows.items()})
 # Static decrement/retry is directly deduced, not relabelled natural observation.
 static=[dict(origin=dict(image='PLI2.OVL',offset=o),bytes=b,disassembly=d,control=dict(kind='other'),evidence_class='DEDUCED STATIC UNOBSERVED')for o,b,d in [(0x7743,'21EEAD','LXI H,ADEEH'),(0x7746,'35','DCR M'),(0x7747,'C32399','JMP 9923H')]]
 save(OUT/'annotation-static-PLI2.OVL.json',{'PLI2.OVL+7701':static})
 topology()
 cat={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
 packet=dict(task='PLI2_POINTER_GENERATION_7701_PASS_55',baseline=BASE,selected='PLI2.OVL+7701',extent=[0x7701,0x77bf],laws=laws,topology=json.loads((REPORT/'topology-summary.json').read_text()),natural=json.loads((REPORT/'inventory-summary.json').read_text()),contracts={key:dict(hash=digest(cat[key]),completeness=cat[key]['completeness'])for key in ['PLI.COM+1140','PLI.COM+119E','PLI.COM+11E5','PLI.COM+1A29','PLI2.OVL+753C','PLI2.OVL+7550','PLI2.OVL+75F1']},static_trim=dict(bytes=7,evidence='DEDUCED instructions plus synthetic bit/loop equations;zero natural executions',predicate='ADEE!=0 AND fresh byte[pointer+ADEE]==20H',termination='strict decrease of4..0;zero prevents decrement;no artificial depth/iteration bound'),unsupported=dict(raw_regions=[[0x7764,0x776f],[0x7776,0x7779],[0x77b0,0x77b7]],modes='201C.bit0 or201D.bit0 set',other='writer errors,position zero-wrap,arbitrary aliases'),stack='Original CALL word preserved;ordinary child calls and writer/service frames derived.7733 PUSH PSW and773C POP B carry first equality mask. No private frame or snapshot residue.',parent='8244 is a CALL site in8225;8225 combines79E2/7A17/73D0/756D/7701,independent external-reference generation.8248 delegates to8225. Deferred;no root invented at8244.',oracle_queries=0)
 save(REPORT/'implementation-packet.json',packet);print('packet',(REPORT/'implementation-packet.json').stat().st_size)
def prove(images,focused=False):
 import subprocess,tempfile,shutil
 OUT.mkdir(parents=True,exist_ok=True);start=time.monotonic()
 with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
  command=['dune','exec','bin/native_pli2_pointer_generation.exe','--','--toolchain',str(images),'--output-dir',str(Path(tmp)/'results')]
  if focused:command+=['--family-only']
  with(OUT/'proof.log').open('w')as log:r=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((OUT/'proof.log').read_text()[-4000:])
  for f in(Path(tmp)/'results').glob('*.json'):
   if not focused or f.name in['component-shadows.json','natural-cases.json']:shutil.copyfile(f,OUT/f.name)
 save(OUT/'proof-timing.json',dict(all_passed=True,wall_seconds=round(time.monotonic()-start,3)));print('proof passed',round(time.monotonic()-start,3))

def loops():
 rows=json.loads((OUT/'rows.json').read_text());proof=json.loads((OUT/'natural-cases.json').read_text());out={};all_cases={}
 for source,g in rows.items():
  cases=[];proved=next(p for p in proof['sources']if p['source']==source)['entries'][0]['members']
  for r,c in zip(g['PLI2.OVL+7701'],proved):
   own=r['own_witnesses'];local=[(w['origin']['offset']+0x2200,v['address'],v['new_value'])for w in own if w['origin']['offset']not in[0x7733,0x77be]and w['control']['kind']!='call'for v in w['writes']]
   reconstructed=[(w[2],w[0],w[1])for w in c['journal']if w[4]=='logical'and 0x9901<=w[2]<0x99bf]
   assert local==reconstructed,(source,r['call']['step_index'])
   checkpoints=[w for w in own if w['origin']['offset']in[0x7723,0x772d,0x7732,0x773b,0x773e,0x773f,0x7740,0x7746,0x774a,0x7757,0x775d,0x776f,0x7785,0x778d,0x778e,0x7791,0x7797,0x779b,0x77a5,0x77ab,0x77ad,0x77ba,0x77bb]]
   cases.append(dict(call=r['call']['step_index'],input_pointer=r['entry']['before']['b']*256+r['entry']['before']['c'],pointed_bytes=[w['after']['a']for w in own if w['origin']['offset']==0x779b],scan_bytes=[w['after']['a']for w in own if w['origin']['offset']==0x772d],scan_offsets=[w['after']['l']for w in own if w['origin']['offset']==0x7723],modes=[w['after']['a']for w in own if w['origin']['offset']in[0x775d,0x776f]],position=next(w['after']['h']*256+w['after']['l']for w in own if w['origin']['offset']==0x7714),encoded=next(w['after']['c']for w in own if w['origin']['offset']==0x7757),checkpoint_hash=digest(checkpoints),ordered_local_writes_hash=digest(local),child_hash=digest([w for w in own if w['control']['kind']=='call'])))
  all_cases[source]=cases
  out[source]=dict(cases=len(cases),pointed_fields=dict(collections.Counter(bytes(c['pointed_bytes']).hex()for c in cases)),scan_offsets=dict(collections.Counter(str(c['scan_offsets'])for c in cases)),trim_counts=dict(collections.Counter(str(len(c['scan_bytes'])-1)for c in cases)),loop_counts=dict(collections.Counter(str(len(c['pointed_bytes']))for c in cases)),mode_classes=dict(collections.Counter(str(c['modes'])for c in cases)),encoded_fields=dict(collections.Counter(str(c['encoded'])for c in cases)),checkpoints_hash=digest(cases),local_chronology_matches=True)
 save(OUT/'loop-cases.json',all_cases);save(REPORT/'loop-summary.json',out)
 return out

def reports():
 import subprocess,shutil
 load=lambda p:json.loads(Path(p).read_text())
 roots=load(OUT/'natural-cases.json')['sources'];post=load(OUT/'cumulative-hybrid-summary.json');single=load(OUT/'single-hybrid-summary.json');top=load(REPORT/'topology-summary.json');components=load(OUT/'component-shadows.json');loops()
 proofs=[];hierarchy=[]
 for r,p in zip(roots,post['sources']):
  entries=[dict(coordinate=('PLI.COM'if e['offset']<0x2200 else'PLI2.OVL')+f"+{e['offset']:04X}",natural_calls=len(e['members']),all_full_states_matched=True,proof_hash=digest(e['members']),services=dict(collections.Counter(str(v['function'])for c in e['members']for v in c['service_details'])))for e in r['entries']]
  proofs.append(dict(source=r['source'],entries=entries));t=top[r['source']]
  assert p['result']['host_transitions']-sum(p['pre_transition_vector'])==t['net_new_transitions']
  hierarchy.append(dict(source=r['source'],roots=p['family_roots'],absorbed_native=t['absorbed_native'],logical_internal=t['logical_children'],serializer_absorbed=t['serializer_absorbed'],serializer_remaining=t['serializer_remaining'],remaining_callers=t['remaining_callers'],pre_guest=p['pre_guest_instructions'],post_guest=p['result']['actual_guest_instructions'],instructions_saved=p['guest_instructions_removed'],pre_host=sum(p['pre_transition_vector']),post_host=p['result']['host_transitions'],net_host_delta=t['net_new_transitions']))
 factor=load('_build/pass55-factor-1/natural-cases.json')['sources'][0]['entries'][0]['members']
 fsummary=dict(source='FACTOR',natural_calls=len(factor),all_full_states_matched=True,proof_hash=digest(factor),trim_counts=dict(collections.Counter(str(sum(w[2]==0x9946 for w in c['journal']))for c in factor)),loop_counts=dict(collections.Counter(str(sum(w[2]==0x999c for w in c['journal']))for c in factor)),components=load('_build/pass55-factor-1/component-shadows.json'),OPTIMIST='46 historical calls retained;source/corrected trace absent in current cheap capture infrastructure;no new campaign')
 save(REPORT/'shadow-summary.json',dict(all_passed=True,sources=proofs,components=components,cross_corpus=fsummary,comparisons=['all registers/flags/SP/PC','ordered logical writes','65536 RAM bytes','final stack last writers','actual child CALL chronology','DMA/filesystem','service boundary state/record bytes/chronology'],synthetic=['trim retries0/1/3/4','all-space retains byte0','21H and1FH nonspace discriminants','higher mode bits2/4 clearbit0','127:7 record flush with positionFFFD','mode-set,position-wrap,pointer/cache/stack/code/continuation alias rejection'],root_count=39))
 save(REPORT/'hierarchy-summary.json',dict(sources=hierarchy,suppression='Exact corrected outer7701 windows;internal75F1 and11E5 plus all canonical descendants. Equivalent operations elsewhere remain enabled.119E is not globally intercepted.'))
 save(REPORT/'single-hybrid-summary.json',single);save(REPORT/'cumulative-hybrid-summary.json',post)
 old=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/manifest.json']));current=load('research/annotated-assembly/manifest.json');oldim=next(i for i in old['images']if i['name']=='PLI2.OVL');curim=next(i for i in current['images']if i['name']=='PLI2.OVL')
 status=lambda im,a:next(s['status']for s in im['sections']if s['start_offset']<=a<s['end_offset'])
 promoted=collections.Counter(status(oldim,a)for a in range(0x7701,0x77bf)if status(curim,a)=='UNDERSTOOD'and status(oldim,a)!='UNDERSTOOD')
 save(REPORT/'fidelity.json',dict(archaeological_scope_extension=True,historical_correction=None,implementation_correction=['Development annotation renderer initially accepted only OBSERVED/RAW coordinate comments;added DEDUCED STATIC UNOBSERVED comment preservation before validation. No runtime or proof-schema change.','Development report extraction corrected serialized child-key lookup;focused test corrected runtime continuation fromA247 toA447. All fixed before aggregate validation.'],pragmatic_divergence=None,fidelity_debt=None,oracle_queries=0,promotions=dict(promoted),represented_total=169,static_trim_bytes=7,natural_trim_executions=0,unchanged_canonical_children=['75F1','11E5','119E','1140','7550','753C','1A29'],cpu_runner_cpm_changes=False,shared_proof_schema_change=False,scripts_view_optimist_untouched=True,interactive_call_count='not instrumented',automated_phases=['natural/caller/CFG inventory','trim/mode/length/loop grouping','corrected hierarchy and external serializer map','component/root shadow batches and synthetic equations','FACTOR cross-case proof','standalone/cumulative hybrids','byte-preserving annotations and historical total preservation','loop checkpoints/local chronology','compact reports/progress','incremental validation dispatch']))
 save(REPORT/'boundary-assessment.json',dict(selected='PLI2.OVL+7701',extent=[0x7701,0x77bf],immediate_caller='PLI2.OVL+8244 is CALL site in8225,not a root',deferred=['8225 joins79E2/7A17/73D0/756D/7701 as broader external-reference generation','8248 is adapter to8225;not automatically native','PLI0 emission and82A6/82E1/82F0 lifecycle remain separate'],next='Pass56 assess8225/8248 as one external-reference generation transaction;scheduled FULL checkpoint after next semantic success.',unsupported='201C/201D bit0-set mode arms,writer error,position zero-wrap,arbitrary aliases/nonwrapping pointer violations.'))
 packet=load(REPORT/'implementation-packet.json');packet['loops']=load(REPORT/'loop-summary.json');packet['proof_counts']={r['source']:{e['coordinate']:e['natural_calls']for e in r['entries']}for r in proofs};packet['cross_corpus']=fsummary;packet['promotions']=dict(promoted);packet['proof_hashes']={n:digest(load(REPORT/n))for n in ['shadow-summary.json','hierarchy-summary.json','single-hybrid-summary.json','cumulative-hybrid-summary.json']};save(REPORT/'implementation-packet.json',packet)
 cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};prior=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))
 for p in prior['procedures']:
  for source,n in p['observed_paths']['invocations_by_run'].items():assert cat[p['id']]['observed_paths']['invocations_by_run'].get(source,0)>=n,(p['id'],source,n)
 size=(REPORT/'implementation-packet.json').stat().st_size;assert size<28672,size
 table='\n'.join(f"|{r['source']}|{r['pre_guest']}|{r['post_guest']}|{r['instructions_saved']}|{r['pre_host']} → {r['post_host']}|{r['roots']}|"for r in hierarchy)
 (REPORT/'README.md').write_text(f"""# Pass55 — bounded PLI2 pointed-field REL generation

Baseline `{BASE}` is Pass54;FULL checkpoint remains Pass53. Validation is incremental.

Root PLI2.OVL+7701 has exact demonstrated envelope[7701,77BF),final77BE RET. Logical/external calls7/25/7,all from8244 in8225;no nested7701. FACTOR11 independently exact;OPTIMIST46 prior historical calls retained,with no cheap source/trace available. No source/caller/step/fixture dispatch.

BC is saved high then low atADEB/ADEA. Canonical75F1(BC0) emits two independently zero-prefixed zero bytes and performs two position publications.8C/7bits follows. Fresh1C2C minus2 modulo65536 goes to canonical tag40 emitter11E5. The pointer is independently reread for scan and each byte;pointed data is never snapshotted as a host string.

ADEE starts4. Two independent arithmetic masks,including PUSH PSW/POP B,select retry exactly when fresh byte[pointer+ADEE]=20H AND ADEE!=0. Decrement sharedADEE and repeat. Strict decrease terminates at0;all-space retains one byte. After two increments,encoded three-bit value is k+2;five ADD A put it in high bits. Natural k=4,retries0 in all39 primary and11 FACTOR calls. Synthetic retries0/1/3/4,21H/1FH discriminants prove the loop is algorithmic.

Fresh201D and201C RAR gates require bit0 clear;higher bits can differ. Emit3F/8bits. ADEC starts0;fresh length-minus2 comparison exits iff index>k. Each iteration independently paired-reads index and pointer,reads byte,publishesADED,serializes8bits,then independently rereads both modes before increment/JNZ. Natural loops5bytes each;synthetic loops1/2/4/5. No fixed iteration schedule.

The7-byte7743..774A decrement/retry arm is DEDUCED/STATIC/UNOBSERVED from exact instructions plus synthetic equations;zero natural executions are invented. Three mode arms[7764,776F),[7776,7779),[77B0,77B7) remainRAW/unsupported. Bounds stable;CFG partial;contract partial. RAW → UNDERSTOOD: 7 bytes; DECODED → UNDERSTOOD: 162 bytes; STRUCTURED → UNDERSTOOD: 0 bytes. No child algorithm duplicated or globally widened.

All39 primary roots and11 FACTOR roots independently match registers,flags,SP/PC,ordered writes,64KiB RAM,stack last writers,child CALL chronology,DMA/filesystem and record/service state. Primary507 serializer and3666 bit-writer components plus canonical position/word helper cross-cases pass. FACTOR143 serializer/1034 bit-writer shadows pass. Loop checkpoints retain historical flag/read/write/branch provenance and independently correlate ordered local publications. Original CALL slot survives;7733 PUSH PSW/773C POP B carries mask;child/service frames derive every surviving byte. No private frame invented.

|Source|Pass54 guest|Pass55 guest|Removed|Host pre → post|Roots|
|---|---:|---:|---:|---:|---:|
{table}

Each7701 replaces formerly external75F1 and11E5 roots:78 lower transitions become39 roots,net-7/-25/-7.56/200/56 formerly external serializers are absorbed;remaining36/36/43,chieflyPLI0 plus82A6/82E1/82F0 and finalizer126E. All logical internal serializers91/325/91 and bit-writers658/2350/658 correlate. Equivalent roots elsewhere remain enabled;119E is internal,never globally intercepted.

Root-only and cumulative hybrids preserve exact REL goldens,complete REL/INT record chronology,filesystem,console,PASS1/PASS2/END,BDOS order/counts and warm boot. Actual whole-run counters alone establish savings. Exact REL hashes and record sequences are retained in hybrid summaries.

Copied transactional preparation rejects unsupported mode/error/alias/continuation/code states before any live mutation. Pointer scope is nonwrapping five-byte nonalias carrier;historical scratch and shared writes remain visible. Synthetic127:7 flush validates emitted record bytes and chronology. Historical reconstruction remains94720 exact bytes.

Packet{size} bytes;full proof journals ignored under_build/host-compiler-pass-55. Driver automates10 repetitive phases;interactive-call count not instrumented. Zero historical oracle queries. Scope extension;historical correction,pragmatic divergence,fidelity debt:none. Development annotation comment-marker fix is separately recorded. FACTOR/OPTIMIST catalog totals preserved. Reports/catalog/progress final before aggregate;validation.json records actual receipt. scripts/view-optimist.sh untouched.

8244 is a call-site,not an entry.8225 combines independent79E2/7A17/73D0/756D families with7701;8248 wraps8225. Pass55 stays7701. Recommend Pass56 assess that broader external-reference transaction and run the scheduled FULL checkpoint after semantic success.
""")
 save(REPORT/'validation.json',dict(validation_tier='incremental',full_checkpoint_base='3ea8fa04b3aee725a772f1365763306ea4ee4f62',status='ready for aggregate',workers=4,historical_bytes=94720,reruns=[]))
 print('reports finalized;packet',size,'counters',hierarchy)

def validate(images):
 import subprocess
 categories='pass55,pass54,pass53,pass52,pass51,emitter-unit,native-emitter-unit,word-emitter-unit,packet-continuation,V1,roundtrip-tests,roundtrip,dynamic-progress,diff-check'
 dest=OUT/'incremental-validation'
 subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images',str(images),'--output',str(dest),'--workers','4','--categories',categories],check=True)
 receipt=json.loads((dest/'results.json').read_text());v=json.loads((REPORT/'validation.json').read_text());v.update(status='passed initially',all_passed=receipt['all_passed'],category_count=len(receipt['categories']),unique_python_test_count=sum(x['python_tests']for x in receipt['categories'].values()),dune_test_rule_stanzas=39,validation_wall_seconds=receipt['wall_seconds'],summed_category_seconds=receipt['sum_category_seconds'],slowest_categories=receipt['top_10_slowest'],categories=receipt['categories']);save(REPORT/'validation.json',v)
 print(json.dumps({k:v[k]for k in ['status','category_count','unique_python_test_count','dune_test_rule_stanzas','workers','validation_wall_seconds','reruns']},indent=2))
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['inventory','topology','contracts','components','prove','reports','validate']);p.add_argument('--images',default='/home/john/pli/cpm/pli80/DISK1');a=p.parse_args()
 if a.phase in['components','prove']:prove(a.images,a.phase=='components')
 elif a.phase=='validate':validate(a.images)
 else:globals()[a.phase]()
