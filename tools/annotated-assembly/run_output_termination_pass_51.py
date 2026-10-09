#!/usr/bin/env python3
"""Pass51 residual phase/candidate evidence from corrected historical windows."""
import bisect,collections,hashlib,json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_acquisition_reentry_pass_38 import CAPTURES,load,coord
OUT=Path('_build/host-compiler-pass-51');REPORT=Path('research/host-compiler/pass-51')
BASE='f7b744e2560c0de8ac1115cf91d4beb190f2e7c2'
def save(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,indent=2)+'\n')
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def inventory():
 start=time.monotonic();result={};raw={}
 native={'PLI1.OVL+'+k for k in ['0C75','0C1B','0A32','02F0','19F0','6619','6223','5929','2511','240A','23D2','23A0','80B7','7EC0','8048','7E5F','7D53','7C1B','7BBF','7B7A','7BA2','7AD5','7B64','7ABF','7A79','7E46','7E56','7AF0','7B49','7A93','7B13']}|{'PLI.COM+0EF6'}
 for source,path in CAPTURES.items():
  calls={};returns={};steps=[];events=[];local=[];software={};last=None
  for chunk in load(path/'event-witnesses.json')['chunks']:
   for e in load(path/'event-witnesses/chunks'/f"{chunk['id']:06d}.json")['events']:
    if e['type']=='instruction':
     w=e['witness'];last=w;steps.append(w['step_index']);origin=coord(w['origin'])
     if origin and origin.startswith('PLI1.OVL+')and 0x100<=w['origin']['offset']<0x13d:local.append(w)
     if w['control']['kind']=='call'and w['control']['taken']:
      calls[w['step_index']]=dict(call=w['step_index'],caller=origin,target=coord(w['target_origin']),sp=w['after']['sp'],continuation=w['call_return_address'],entry=w['after'])
    elif e['type']=='hardware_frame_return':returns[e['frame']['call_step']]=dict(ret=e['step_index'],output=last['after'])
    elif e['type']=='software_continuation_return':events.append(e)
    elif e['type']in ['bdos_call','bdos_resume','bdos_record','file_operation','host_effect']:events.append(e)
  windows=[dict(q,**returns[k])for k,q in calls.items()if k in returns]
  roots=[]
  for q in windows:
   if q['target']not in native:continue
   if roots and q['call']<roots[-1]['ret']:continue
   roots.append(q)
  count=lambda q:bisect.bisect_right(steps,q['ret'])-bisect.bisect_right(steps,q['call'])
  computed=len(steps)-sum(count(q)for q in roots)
  assert computed==dict(MINIMAL=380445,FIZZBUZ=838187,PICTURE=428026)[source],(source,computed)
  target=next(q for q in windows if q['caller']=='PLI1.OVL+011E')
  ancestors=[q for q in windows if q['call']<target['call']<target['ret']<q['ret']]
  near=[q for q in windows if q['caller']and q['caller'].startswith('PLI1.OVL+')and 0x100<=int(q['caller'].split('+')[1],16)<0x13d]
  ranked={}
  for q in windows:
   if any(r['call']<=q['call']<q['ret']<=r['ret']for r in roots):continue
   if not q['target']:continue
   inside=[r for r in roots if q['call']<r['call']<r['ret']<=q['ret']]
   residual=count(q)-sum(count(r)for r in inside)
   if residual<30:continue
   key=q['target'];v=ranked.setdefault(key,dict(logical=0,residual_inclusive=0,maximum_window=0,callers=collections.Counter(),native_descendants=collections.Counter(),samples=[]))
   v['logical']+=1;v['residual_inclusive']+=residual;v['maximum_window']=max(v['maximum_window'],residual);v['callers'][q['caller']]+=1;v['native_descendants'].update(r['target']for r in inside)
   if len(v['samples'])<3:v['samples'].append(dict(call=q['call'],ret=q['ret'],caller=q['caller'],residual=residual))
  near_summary=[]
  for q in near:
   inside=[r for r in roots if q['call']<r['call']<r['ret']<=q['ret']]
   near_summary.append(dict(q,residual=0 if q in roots else count(q)-sum(count(r)for r in inside),historical_body=count(q),native_descendants=dict(collections.Counter(r['target']for r in inside)),events_hash=digest([e for e in events if q['call']<e['step_index']<=q['ret']]),event_types=dict(collections.Counter(e['type']for e in events if q['call']<e['step_index']<=q['ret']))))
  raw[source]=dict(windows=windows,roots=roots,steps=steps,events=events,local=local)
  result[source]=dict(guest=computed,host=len(roots),around_011E=near_summary,ancestors=[dict(q,historical_body=count(q))for q in ancestors],residual_candidates=dict(sorted(ranked.items(),key=lambda kv:kv[1]['residual_inclusive'],reverse=True)[:25]),local_cfg=sorted({w['origin']['offset']:(w['origin']['offset'],w['bytes'],w['disassembly'])for w in local}.values()),event_examples={k:next((e for e in events if e['type']==k),None)for k in ['host_effect','bdos_call','bdos_record','file_operation']})
 save(OUT/'residual-map.json',raw);save(REPORT/'residual-phase-map.json',result)
 print(json.dumps({s:dict(guest=v['guest'],host=v['host'],around=[dict(caller=q['caller'],target=q['target'],call=q['call'],ret=q['ret'],residual=q['residual'],events=q['event_types'])for q in v['around_011E']],ancestors=[q['target']for q in v['ancestors']],ranking={k:dict(calls=q['logical'],residual=q['residual_inclusive'],callers=q['callers'],native=q['native_descendants'])for k,q in v['residual_candidates'].items()},local_cfg=v['local_cfg'],event_examples=v['event_examples'])for s,v in result.items()},indent=2))
 print('inventory seconds',round(time.monotonic()-start,3))
def output_candidates():
 raw=load(OUT/'residual-map.json');summary={};candidate_keys={'PLI.COM+'+k for k in ['0D09','1272','119E','1031','0611','0692']}
 for source,v in raw.items():
  events=v['events'];bs=[e for e in events if e['type']=='bdos_call'];summary[source]={}
  for key in candidate_keys:
   rows=[q for q in v['windows']if q['target']==key];cases=[]
   for q in rows:
    selected=[e for e in bs if q['call']<e['step_index']<=q['ret']]
    text=''.join(chr(e['state']['e'])for e in selected if e['function']==2)
    files=[dict(step=e['step_index'],operation=e['operation'],file=e.get('file'),record=e.get('record'))for e in events if e['type']in ['file_operation','bdos_record']and q['call']<e['step_index']<=q['ret']]
    cases.append(dict(call=q['call'],ret=q['ret'],caller=q['caller'],services=dict(collections.Counter(e['function']for e in selected)),console=text,files=files))
   summary[source][key]=dict(count=len(rows),callers=dict(collections.Counter(q['caller']for q in rows)),services=dict(collections.Counter(e['function']for e in bs if any(q['call']<e['step_index']<=q['ret']for q in rows))),cases=cases if key!='PLI.COM+119E'else cases[:3])
 save(REPORT/'output-candidates.json',summary)
 print(json.dumps({source:{key:value for key,value in group.items()if key in ['PLI.COM+0D09','PLI.COM+1272','PLI.COM+0611']}for source,group in summary.items()},indent=2))
def extract(keys):
 from check_selector02_pass_40 import gather_selected,children_any
 full={};cfg={};summary={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{k:(int(k.split('+')[1],16),int(k.split('+')[1],16)+1)for k in keys},include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8})
  full[source]=rows;summary[source]={}
  for key,rs in rows.items():
   cfg.setdefault(key,{})
   for r in rs:
    cfg[key].update({w['origin']['offset']:[w['origin']['offset'],w['bytes'],w['disassembly']]for w in r['own_witnesses']})
   summary[source][key]=[dict(call=r['call']['step_index'],caller=coord(r['call']['origin']),entry=r['entry']['before'],output=r['ret']['after'],children=[[c['callsite'],c['target']]for c in children_any(r)])for r in rs]
 save(OUT/'component-rows.json',full);save(OUT/'component-cfg.json',{k:sorted(v.values())for k,v in cfg.items()});save(OUT/'component-cases.json',summary)
 print(json.dumps(dict(counts={s:{k:len(v)for k,v in group.items()}for s,group in summary.items()},cfg={k:sorted(v.values())for k,v in cfg.items()}),indent=2))
def contracts():
 raw=load(OUT/'component-rows.json')
 laws={
 'PLI.COM+1272':dict(end=0x12ae,description='Bounded pending REL bit padding and file close',completeness=['stable','partial','partial'],contract='Fresh1D05 RAR must produceCY1; fresh2029 RAR CY0. Independently form zero-equality masks from fresh1D8A and1D8B through SUI00/ADIFF/SBB A; preserve first via PUSH PSW/POP B/MOV C,B, OR second and RAR. While either byte is nonzero, setC0 and compose canonical1140, then freshly retest both indices. No fixed padding count. Once both zero, BC1CE4 calls064C; return its actual state unchanged. Current index<128, bit<8, successful output/service guards and valid nonaliasing FCB/buffer/stack required. Unopened and suppressed-output alternatives remain RAW/unsupported; arbitrary failure/capacity behavior is not claimed.'),
 'PLI.COM+1140':dict(end=0x119e,description='Bounded REL bit append with successful full-record flush',completeness=['provisional','partial','partial'],contract='Retain previous bit-append law. Canonical host bit_write now additionally composes the required successful flush: C saved20B6; fresh2029.bit0=0; independently paired1D8A/1D8B reads supply low-byte offset and bit cursor. Shift buffer[1D0A+index] by ADD A; PUSH PSW retains shifted byte, independently read20B6 ANI1, POP B/MOV C,B/ORA C; fresh cursor reread selects destination. Increment/mask bit cursor; when zero advance byte cursor. Exactly128 selects BC1D0A ->02EE SetDMA; BC1CE4 ->0328 sequential-write; CPI00 must be zero; then HL1D8A/MVI M0 clears byte cursor. Preserve service-return BC/DE and CPI flags. Gate-set return and write-error alternative unsupported. No changes to existing canonical no-flush child scope.'),
 'PLI.COM+064C':dict(end=0x0670,description='Bounded saved-FCB close with default DMA restoration',completeness=['provisional','partial','partial'],contract='PUSH BC retains original FCB word; call02FE restores DMA0080H. LXI H0/DAD SP reads saved low/high FCB independently into DE; setC16; compose canonical19BB service gate and real BDOS close. CPIFF controls error branch; supported successful nonFF result skips error adapter, POP H consumes saved FCB and ordinary RET consumes original continuation. ReturnedA/BC/DE are actual service channels, HL=saved originalBC, comparison flags retained. Error adapter path unsupported.'),
 'PLI.COM+0328':dict(end=0x0338,description='Canonical sequential-write service wrapper at successful REL scope',completeness=['stable','complete','partial'],contract='Existing local law retained. Independently proved all current natural sequential-write wrapper cases: B->2066 then C->2065; paired LHLD2065/XCHG passes originalBC as DE; C21; canonical19BB guards and real staged BDOS sequential write. Actual record/FCB/DMA/file-service effects preserved, no copied oracle memory. Successful bounded filesystem scope; arbitrary write failure remains unsupported.'),
 'PLI.COM+02FE':dict(end=0x0305,description='Default DMA wrapper through canonical SetDMA',completeness=['stable','complete','partial'],contract='SetBC0080H; CALL02EE; ordinaryRET of exact child registers/flags. Canonical02EE publishes BC to2060 then205F, freshly rereads pointer, exchanges into DE and sets C26 before canonical19BB. No own logical writes; derived CALL residue only. Actual staged DMA service effects and successful guard scope inherited.')}
 save(REPORT/'contract-laws-PLI.COM.json',laws)
 save(OUT/'annotation-rows-PLI.COM.json',{source:{key:group[key]for key in laws}for source,group in raw.items()})
 # Fix initial display-only residual for already intercepted exact native windows.
 phase=load(REPORT/'residual-phase-map.json')
 rr=load(OUT/'residual-map.json')
 for source,v in phase.items():
  v.pop('event_examples',None)
  for row in v['around_011E']:
   if any(r['call']==row['call']for r in rr[source]['roots']):row['residual']=0
 save(REPORT/'residual-phase-map.json',phase)
 candidates=load(REPORT/'output-candidates.json')
 for source,group in candidates.items():
  for key,v in group.items():
   for c in v['cases']:
    if 'files' not in c:continue
    fs=c.pop('files');c['file_event_count']=len(fs);c['file_event_hash']=digest(fs)
    if key=='PLI.COM+1272':c['file_events']=fs
 save(REPORT/'output-candidates.json',candidates)
 packet=dict(task='RESIDUAL_OUTPUT_TERMINATION_PARENT_PASS_51',baseline=BASE,selected_root='PLI.COM+1272',logical_counts={source:1 for source in raw},outer_counts={source:1 for source in raw},root_rationale='One coherent pending REL record padding/flush and close operation; separate from console pass summaries, startup/open and PLI2 generation phase. No widening to mixed non-returning overlay/startup driver.',phases=['startup/compiler state and input/output file opening','canonical0C75 delimiter/input driver','canonical80B7 independent output then pointer statistics0611','console0D09 PASS summary','resident1272 pending REL padding/flush/close','separate END COMPILATION console and warm-boot driver'],laws=laws,cases={},contracts={},oracle_queries=0,stack_pattern='1272 has no persistent frame. Mask PSW at entrySP-2 is consumed into BC; each1140 hardware child uses S-2, its PSW S-4; flush wrappers/service CALL and BC/DE pushes derive deeper residue.064C hardware child atS-2 owns savedBC atS-4;02FE/02EE nestedCALLs restore defaultDMA; POP H consumes FCB carrier. Original root continuation atS is never written; RET12AD yieldsSP=S+2. No software continuation or recursion occurs in this root.',unsupported=['unopened output','suppressed-output arm','index>=128 or bit>=8','write/close errors','invalid BDOS guards','code/scratch/stack aliases'],native_descendants_absorbed={source:{}for source in raw})
 catalog={p['id']:p for p in load(Path('research/annotated-assembly/procedures.json'))['procedures']}
 for key in ['PLI.COM+02EE','PLI.COM+19BB','PLI.COM+1A0F']:
  packet['contracts'][key]=dict(hash=digest(catalog[key]),completeness=catalog[key]['completeness'])
 for source,group in raw.items():
  row=group['PLI.COM+1272'][0];calls=[w for w in row['own_witnesses']if w['control']['kind']=='call']
  ix=next(w['reads'][0]['value']for w in row['own_witnesses']if w['origin']['offset']==0x1287);bit=next(w['reads'][0]['value']for w in row['own_witnesses']if w['origin']['offset']==0x1290)
  packet['cases'][source]=dict(call=row['call']['step_index'],ret=row['ret']['step_index'],entry=row['entry']['before'],output=row['ret']['after'],indices=[ix,bit],padding_calls=sum(w['origin']['offset']==0x12a1 for w in calls),direct_child_pattern=['1140 repeated from current indices','064C once'],own_cfg_hash=digest([(w['origin']['offset'],w['bytes'])for w in row['own_witnesses']]),components={k:len(v)for k,v in group.items()})
 save(REPORT/'implementation-packet.json',packet)
 print('packet bytes', (REPORT/'implementation-packet.json').stat().st_size)
def prove(images,*,persist=False):
 import tempfile,subprocess,shutil
 start=time.monotonic();OUT.mkdir(exist_ok=True,parents=True)
 with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
  dest=Path(tmp)/'result'
  with(OUT/'root-proof.log').open('w')as log:
   r=subprocess.run(['dune','exec','bin/native_output_finalization_hybrids.exe','--','--toolchain',str(images),'--output-dir',str(dest)],stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((OUT/'root-proof.log').read_text()[-4000:])
  target=OUT/('validated-proof'if persist else 'fresh-proof');target.mkdir(exist_ok=True)
  for file in dest.glob('*.json'):shutil.copyfile(file,target/file.name)
 save(OUT/'proof-timing.json',dict(wall_seconds=round(time.monotonic()-start,3),all_passed=True))
 return target
def reports():
 proof=OUT/'validated-proof';packet=load(REPORT/'implementation-packet.json')
 roots=load(proof/'natural-cases.json')['sources'];post=load(proof/'cumulative-hybrid-summary.json')['sources']
 components=load(proof/'component-shadows.json')
 hierarchy={}
 for r in post:
  q=r['result'];source=q['source'];pre=r['pre_guest_instructions'];before=sum(r['pre_transition_vector'])
  assert (pre,before)==dict(MINIMAL=(380445,72),FIZZBUZ=(838187,95),PICTURE=(428026,56))[source]
  assert r['transition_vector']==[1]+r['pre_transition_vector']
  hierarchy[source]=dict(pre_guest=pre,post_guest=q['actual_guest_instructions'],guest_removed=r['guest_instructions_removed'],pre_host=before,post_host=q['host_transitions'],root_transitions=1,absorbed_descendants={},remaining_external_same_family='All non-finalizer bit output calls remain guest; 1272 has no remaining external call.',internal_0C75_0C1B_0A32_02F0=0)
 save(REPORT/'hierarchy-summary.json',hierarchy)
 compact=[]
 for group in roots:
  c=group['members'][0];j=c['journal']
  compact.append(dict(source=group['source'],caller=c['caller'],entry_step=c['entry_step'],return_step=c['return_step'],input=c['input'],output=c['output'],entry_memory_hash=c['entry_memory_sha256'],post_memory_hash=c['post_memory_sha256'],journal_hash=digest(j),ordered_logical_writes=sum(w[4]=='logical'for w in j),surviving_writer_cells=len({w[0]for w in j}),stack_writers=sorted({w[2]for w in j if w[4]=='compatibility'}),service_functions=[s['function']for s in c['service_details']],post_DMA=c['post_dma'],full_state='matched',direct_child_chronology='matched',N2_N8='not reached',internal_canonical_acquisition_parents='none'))
 save(REPORT/'shadow-summary.json',dict(root_shadows=3,all_passed=True,cases=compact,components=components,synthetic_padding_states=[[0,0],[127,7],[127,1],[1,0]],negatives=['wrong CALL origin','entry PC/register range','code corruption','continuation corruption','index128','bit8','output gate1','unopened file','guard/buffer alias','stack/scratch alias','returned flags','publication ordering','stack last writer','proof-source mismatch']))
 save(REPORT/'hybrid-summary.json',{n:load(proof/(n+'-hybrid-summary.json'))for n in ['single','cumulative']})
 save(REPORT/'parent-candidates.json',dict(selected='PLI.COM+1272',candidates=[dict(coordinate='PLI.COM+1272',logical_counts=[1,1,1],callers=['PLI.COM+02E3'],residual_ranking=[31192,44993,28581],purpose='REL pending record padding, flush and close',decision='selected coherent bounded finalization'),dict(coordinate='PLI.COM+0D09',logical_counts=[2,2,2],callers=['PLI0.OVL+01DA','PLI1.OVL+0135'],residual_ranking=[3640]*3,purpose='console PASS summaries',decision='separate console lifecycle, lower leverage'),dict(coordinate='PLI.COM+119E',logical_counts=[189,703,197],purpose='repeated bit-field output within compiler phases',decision='defer broader emission for Pass52'),dict(coordinate='PLI.COM+1031',logical_counts=[3,3,3],purpose='per-phase input/output opening and startup state',decision='exclude independent startup lifecycle'),dict(coordinate='PLI.COM+0692',logical_counts=[3,3,3],purpose='overlay file loading',decision='exclude independent loader family'),dict(coordinate='PLI1.OVL+011E',purpose='callsite in non-returning mixed startup sequence',decision='not an ordinary parent/root; do not intercept whole compiler phases')]))
 save(REPORT/'boundary-assessment.json',dict(next_recommended='Resident bit-field emission around PLI.COM+119E and its immediate caller wrappers',reason='Fresh189/703/197 logical calls have major residual leverage across result-file generation; assess one bounded buffered emission parent without absorbing the PLI2 compiler phase or startup loader.',deferred_console='PLI.COM+0D09 remains independently coherent console summary operation',finalizer_caller='COM+02E3 belongs to resident overlay/compiler-phase control; no upward widening',next_full_checkpoint='approximately Pass53; Pass50 remains current FULL baseline'))
 save(REPORT/'fidelity.json',dict(archaeological_scope_extension=True,historical_correction=None,implementation_correction=['OCaml alias record-label build fixes before proof','Overbroad provisional sentinel exclusion narrowed to derived active frame envelope; historicalFDFE guard retained','Annotation generator adapted to retain historical FACTOR callers outside current three capture labels'],catalog_epoch_maintenance='Pass46 hash assertions resolve immutable2fc80f0b catalog via historical_catalog_epoch.py; old facts remain unchanged.',pragmatic_divergence=None,fidelity_debt=None,oracle_queries=0,RAW_to_UNDERSTOOD=load(REPORT/'archaeology-summary-PLI.COM.json'),validation_tier='incremental',full_checkpoint_base=BASE,cpu_runner_cpm_changes=False,proof_schema_change=False,scripts_view_optimist_untouched=True,interactive_call_count='not instrumented',automated_phases=['fresh interval-union residual map','phase/event candidate correlation','all-natural component extraction and CFG','contract/packet generation','byte-preserving annotations','independent child and root shadows','rejection and synthetic state proofs','standalone and cumulative hybrids','hierarchy/report accounting','incremental aggregate dispatch']))
 table='\n'.join(f"| {source} | {v['pre_guest']} | {v['post_guest']} | {v['guest_removed']} | {v['pre_host']} | {v['post_host']} |"for source,v in hierarchy.items())
 (REPORT/'README.md').write_text("""# Pass51 — resident +1272 pending REL finalization

Baseline/full checkpoint `f7b744e2560c0de8ac1115cf91d4beb190f2e7c2`.
Fresh corrected ancestry shows +011E is a CALL site in non-returning PLI1 startup,
not an enclosing ordinary procedure. Separate startup/file-opening, canonical
+0C75 input driving, output/statistics, console PASS summary and resident REL
finalization lifecycles. +1272 is one coherent root per source, all from resident
+02E3. It is independent of console +0D09 and excludes startup +1031, overlay
loading +0692 and the PLI2 generation phase. No upward widening.

Fresh1D05 bit0 must be set and fresh2029 bit0 clear. At each iteration form two
independent zero-equality masks from fresh1D8A and1D8B through wrapping SUI00,
ADIFF and SBB A. Preserve the first through PSW/POP B/MOV C,B; OR and RAR decide
whether to call canonical +1140 with C0. The indices are reread after every child.
The canonical bit writer shifts the actual retained REL byte and appends C.bit0,
increments bit index modulo8, advances byte index and flushes exactly at128.
Compose canonical SetDMA with1D0A, sequential-write withFCB1CE4, require actual
successful status, and clear1D8A only after the service/CPI00. Termination follows
both indices becoming zero; observed padding counts665/961/609 are consequences
of entry indices44:7 /7:7 /51:7. Synthetic0:0,127:7,127:1,1:0 states distinguish
state-driven termination without guest/oracle queries.

Then +064C saves originalBC=1CE4 on the historical stack; +02FE restoresDMA0080
through canonical +02EE. Independently read the saved low/high word intoDE,
C16 invokes canonical +19BB and real staged BDOS close. CPIFF flags survive
POP H and RET. ReturnedA0/BC0010/DE1CE4/HL1CE4 andS0 Z0 AC0 P0 CY1 are actual
child/comparison channels. Original root continuation03E6 remains untouched;
RET12AD yields entrySP+2. Child CALLs, PSW and FCB saves derive all residue.
The deepest service frame is sixteen bytes below rootSP; the historical BDOS
sentinelFDFE is outside active frames. No recursion, N2/N8 or XTHL is reached in
this root, and canonical acquisition parents remain independent outside it.

New bounded contracts: +1272 (53 RAW bytes), +064C (23), +02FE (7).
Extend +1140 successful-flush and +0328 successful-service scopes with no new RAW
bytes for either. Existing bit arithmetic and resident service machinery remain
canonical. All five contracts remain partial in semantic/global scope; +02FE and
+0328 have complete local CFG, while finalizer/close/bit-writer sibling guards and
errors remain RAW. No arbitrary error, allocator, capacities or file failure law.

Independent shadows cover required +1140 children665/961/609, all +064C calls5
per source, all +0328 calls3/9/3 and all +02FE calls20 per source. Three root shadows
match registers/flags, SP/PC, all65536 RAM bytes, ordered logical writes, stack
last writers, child CALL chronology, DMA/filesystem and ordered service/record
state. Actual service order is26,21,26,16; final record indices1/5/1. Preparation
stages copied RAM/filesystem/DMA, validates the whole bounded operation and never
falls back after partial live mutation. Corruptions and unsupported scopes reject
without changing live state. Full compiler runs preserve console, filesystem,
INT/REL chronology, compiler milestones, warm boot and exact golden REL hashes.

The fresh post50 hierarchy has only +0C75, +80B7 and resident INT emitter external
native calls. All other canonical external root counts are zero. These roots
remain unchanged; the new +1272 absorbs zero already-native transitions. Actual
whole-run counts, not candidate inclusive windows, establish savings:

| Source | Pre51 guest | Post51 guest | Saved | Pre host | Post host |
|---|---:|---:|---:|---:|---:|
"""+table+"""

Compact packet, hashes and summaries are durable; full journals/snapshots stay
ignored under `_build/host-compiler-pass-51`. The deterministic driver batches
residual discovery, component CFG, contracts, packet, shadows, hybrids and final
validation. Pass46 catalog hash assertions now explicitly use their historical
epoch; no historical fact was corrected. Incremental receipt is validation.json;
Pass50 remains the FULL checkpoint. All94720 historical bytes reconstruct exactly.
Zero new oracle queries; bounded archaeology extension, no historical correction,
pragmatic divergence or fidelity debt. scripts/view-optimist.sh is untouched.
RecommendedPass52: rank the repeated resident bit-field emission parents around
+119E separately from the PLI2 compiler-generation family and console summaries.
""")
 save(REPORT/'validation.json',dict(validation_tier='incremental',full_checkpoint_base=BASE,status='ready for final aggregate',workers=4,historical_bytes=94720,reruns=[],planned_categories=['build','project','pass51','pass50','pass46','pass22','native-emitter-unit','emitter-unit','packet-continuation','V1','roundtrip-tests','roundtrip','dynamic-progress','diff-check']))
 print(json.dumps(hierarchy,indent=2))
def validate(images):
 import subprocess
 categories='pass51,pass50,pass46,pass22,native-emitter-unit,emitter-unit,packet-continuation,V1,roundtrip-tests,roundtrip,dynamic-progress,diff-check'
 dest=OUT/'incremental-validation'
 subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images',str(images),'--output',str(dest),'--workers','4','--categories',categories],check=True)
 receipt=load(dest/'results.json');v=load(REPORT/'validation.json')
 v.update(status='passed initially',all_passed=receipt['all_passed'],category_count=len(receipt['categories']),unique_python_test_count=sum(x['python_tests']for x in receipt['categories'].values()),dune_test_rule_stanzas=39,validation_wall_seconds=receipt['wall_seconds'],summed_category_seconds=receipt['sum_category_seconds'],slowest_categories=receipt['top_10_slowest'],categories=receipt['categories'],reruns=[])
 save(REPORT/'validation.json',v)
if __name__=='__main__':
 if sys.argv[1]=='inventory':inventory()

 elif sys.argv[1]=='output_candidates':output_candidates()
 elif sys.argv[1]=='extract':extract(sys.argv[2:])
 elif sys.argv[1]=='contracts':contracts()
 elif sys.argv[1]=='prove':prove(Path(sys.argv[2]),persist=True)
 elif sys.argv[1]=='reports':reports()
 elif sys.argv[1]=='validate':validate(Path(sys.argv[2]))
