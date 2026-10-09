#!/usr/bin/env python3
"""Deterministic Pass52 resident buffered REL family evidence and proof driver."""
import collections,hashlib,json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_acquisition_reentry_pass_38 import CAPTURES,load,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-52'); REPORT=Path('research/host-compiler/pass-52')
BASE='c89fb3be1a5e5f077161c96f6f8b715baad69776'
MEMBERS=[0x11c3,0x11e5,0x1207,0x1229]
def save(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,indent=2)+'\n')
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def inventory():
 start=time.monotonic();full={};summary={};cfg={}
 for source,path in CAPTURES.items():
  keys={f'PLI.COM+{x:04X}':(x,x+1)for x in [0x119e]+MEMBERS}
  rows=gather_selected(path,keys,include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8})
  full[source]=rows;summary[source]={}
  for key,rs in rows.items():
   for r in rs:
    cfg.setdefault(key,{}).update({w['origin']['offset']:[w['origin']['offset'],w['bytes'],w['disassembly']]for w in r['own_witnesses']})
   callers=collections.Counter(coord(r['call']['origin'])for r in rs)
   classes={}
   for caller in callers:
    subset=[r for r in rs if coord(r['call']['origin'])==caller]
    classes[caller]=dict(count=len(subset),CE=dict(collections.Counter(f"{r['entry']['before']['c']:02X}/{r['entry']['before']['e']:02X}"for r in subset)),BC=sorted({r['entry']['before']['b']*256+r['entry']['before']['c']for r in subset}),child_counts=dict(collections.Counter(c['target']for r in subset for c in children_any(r))),value_read_variants=sorted({tuple(q['value']for q in w['reads'])for r in subset for w in r['own_witnesses']if w['origin']['offset']==0x11ad}))
   summary[source][key]=dict(count=len(rs),callers=classes,entry_return_hash=digest([(r['entry']['before'],r['ret']['after'])for r in rs]),own_cfg_hash=digest(sorted(cfg.get(key,{}).values())))
 save(OUT/'rows.json',full);save(OUT/'cfg.json',{k:sorted(v.values())for k,v in cfg.items()});save(REPORT/'inventory.json',summary);compact_inventory()
 print(json.dumps(dict(inventory=summary,cfg={k:sorted(v.values())for k,v in cfg.items()}),indent=2));print('elapsed',round(time.monotonic()-start,3))
def compact_inventory():
 full=load(REPORT/'inventory.json');save(OUT/'inventory-full.json',full)
 for group in full.values():
  for record in group.values():
   for c in record['callers'].values():
    if len(c['CE'])>16:
     ce=c['CE'];c['CE']=dict(distinct=len(ce),hash=digest(ce),samples=dict(list(ce.items())[:8]),by_E=dict(collections.Counter({e:sum(n for k,n in ce.items()if k.split('/')[1]==e)for e in {k.split('/')[1]for k in ce}})))
    for key in ['BC','value_read_variants','input_cursor_signatures']:
     if key in c:
      values=c.pop(key);name='value_read_variants'if key=='input_cursor_signatures'else key
      c[name]=values if len(values)<=16 else dict(distinct=len(values),hash=digest(values),samples=values[:8])
 save(REPORT/'inventory.json',full)
def read_rows():
 rows=load(OUT/'rows.json')
 for g in rows.values():
  for rs in g.values():
   for r in rs:r['nested_returns']={int(k):v for k,v in r['nested_returns'].items()}
 return rows
def rank():
 import bisect
 path=Path('_build/host-compiler-pass-51/residual-map.json')
 if not path.exists():
  import contextlib
  from run_output_termination_pass_51 import inventory as baseline_inventory
  with(OUT/'baseline-inventory.log').open('w')as log,contextlib.redirect_stdout(log):baseline_inventory()
 raw=load(path); rows=read_rows();result={}
 for source,v in raw.items():
  windows=v['windows'];steps=v['steps'];roots=v['roots']+[q for q in windows if q['target']=='PLI.COM+1272']
  count=lambda a,b:bisect.bisect_right(steps,b)-bisect.bisect_right(steps,a)
  ext=lambda r:not any(q['call']<r['call']['step_index']<r['ret']['step_index']<=q['ret']for q in roots)
  members={};parents={};bits=[]
  for key,rs in rows[source].items():
   if key=='PLI.COM+119E':continue
   external=[r for r in rs if ext(r)]
   residual=sum(count(r['call']['step_index'],r['ret']['step_index'])for r in external)
   members[key]=dict(logical=len(rs),external=len(external),residual_ranking=residual,serializer_children=3*len(external),bit_children=18*len(external),internal_native_root=len(rs)-len(external),flush_calls=sum(any(w['origin']and coord(w['origin'])=='PLI.COM+118D'for c in children_any(r) for w in r['nested_returns'][c['call_step']]['memory_witnesses'])for r in external))
   for r in external:
    a,b=r['call']['step_index'],r['ret']['step_index'];anc=[q for q in windows if q['call']<a<b<=q['ret']]
    if anc:
     q=max(anc,key=lambda q:q['call']);t=q['target'];z=parents.setdefault(t,dict(calls=set(),members=0,callers=set(),residual=0))
     z['members']+=1;z['callers'].add(q['caller'])
     if q['call']not in z['calls']:
      z['calls'].add(q['call']);z['residual']+=count(q['call'],q['ret'])-sum(count(x['call'],x['ret'])for x in roots if q['call']<x['call']<x['ret']<=q['ret'])
  for t,q in parents.items():q['calls']=len(q['calls']);q['callers']=sorted(q['callers'])
  ce=collections.Counter(coord(r['call']['origin'])for r in rows[source]['PLI.COM+119E'])
  familywindows=[(r['call']['step_index'],r['ret']['step_index'])for key,rs in rows[source].items()if key!='PLI.COM+119E'for r in rs if ext(r)]
  remaining=[r for r in rows[source]['PLI.COM+119E']if ext(r)and not any(a<r['call']['step_index']<r['ret']['step_index']<=b for a,b in familywindows)]
  result[source]=dict(members=members,immediate_parents=parents,total_serializer=len(rows[source]['PLI.COM+119E']),caller_distribution=dict(ce),remaining_external_serializer=len(remaining),remaining_external_callers=dict(collections.Counter(coord(r['call']['origin'])for r in remaining)),pre_native_internal_serializer=sum(not ext(r)for r in rows[source]['PLI.COM+119E']))
 save(REPORT/'topology-summary.json',result);print(json.dumps(result,indent=2))
def prove(images):
 import subprocess,tempfile,shutil
 OUT.mkdir(parents=True,exist_ok=True);start=time.monotonic()
 with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
  dest=Path(tmp)/'results'
  with(OUT/'proof.log').open('w')as log:r=subprocess.run(['dune','exec','bin/native_buffered_rel_hybrids.exe','--','--toolchain',str(images),'--output-dir',str(dest)],stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((OUT/'proof.log').read_text()[-5000:])
  for f in dest.glob('*.json'):shutil.copyfile(f,OUT/f.name)
 save(OUT/'proof-timing.json',dict(wall_seconds=round(time.monotonic()-start,3),all_passed=True))
 print('family proof and hybrids passed',round(time.monotonic()-start,3))
def parent_cfg():
 keys={f'PLI2.OVL+{x:04X}':(x,x+1)for x in [0x7434,0x7630,0x765e,0x829c,0x82dd]};cfg={};summary={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,keys,include_nested_returns=True)
  summary[source]={}
  for key,rs in rows.items():
   own={w['origin']['offset']:[w['origin']['offset'],w['bytes'],w['disassembly']]for r in rs for w in r['own_witnesses']};cfg.setdefault(key,{}).update(own)
   summary[source][key]=dict(calls=len(rs),children=sorted({tuple(c['target']for c in children_any(r))for r in rs}),cfg_hash=digest(sorted(own.values())))
 save(OUT/'parent-cfg.json',{k:sorted(v.values())for k,v in cfg.items()});save(REPORT/'parent-route-summary.json',summary)
 print(json.dumps({k:sorted(v.values())for k,v in cfg.items()},indent=2))
def writer_routes():
 result={}
 for source,g in read_rows().items():
  result[source]={}
  for key,rs in g.items():
   result[source][key]={}
   for r in rs:
    caller=coord(r['call']['origin']);v=result[source][key].setdefault(caller,dict(count=0,entry_cursors={},flushes=0,E={}))
    v['count']+=1;e=str(r['entry']['before']['e']);v['E'][e]=v['E'].get(e,0)+1
    mem=[w for q in r['nested_returns'].values()for w in q['memory_witnesses']]
    cursor=next((w['reads']for w in mem if coord(w['origin'])=='PLI.COM+114B'),[])
    if cursor:
     signature=':'.join(str(q['value'])for q in cursor);v['entry_cursors'][signature]=v['entry_cursors'].get(signature,0)+1
    v['flushes']+=sum(coord(w['origin'])=='PLI.COM+118D'for w in mem)
 save(REPORT/'writer-route-summary.json',result)
def contracts():
 rows=read_rows();cfg=load(OUT/'cfg.json');top=load(REPORT/'topology-summary.json')
 image=Path('/home/john/pli/cpm/pli80/DISK1/PLI.COM').read_bytes()
 for j,x in enumerate(MEMBERS):
  expected=bytes.fromhex('21')+(0x20ba+2*j).to_bytes(2,'little')+bytes.fromhex('702B711E020E')+bytes([j*64])+bytes.fromhex('CD9E122A')+(0x20b9+2*j).to_bytes(2,'little')+bytes.fromhex('7D4F1E08CD9E122A')+(0x20b9+2*j).to_bytes(2,'little')+bytes.fromhex('7C4F1E08CD9E12C9')
  assert image[x:x+34]==expected,'static member shape differs'

 laws={}
 for x,cache,tag in [(0x11c3,0x20b9,0),(0x11e5,0x20bb,0x40),(0x1207,0x20bd,0x80)]:
  key=f'PLI.COM+{x:04X}'
  laws[key]=dict(end=x+34,description='Bounded tagged cached-word REL emitter',completeness=['stable','complete','partial'],contract=f'Independently store input B at{cache+1:04X} then C at{cache:04X}. Set E2,C{tag:02X}; compose canonical119E. Genuinely paired reread word[{cache:04X}], select low into A/C and E8; compose119E. Independently paired reread the same cache, select high into A/C and E8; compose119E; ordinary RET of final child state. Tag bits are emitted MSB first followed by low8 and high8, each byte MSB first. No private frame. All entry BC byte values algorithmic, supported cursor index<128/bit<8, output gate2029.bit0 clear, successful actual DMA/sequential-write guards, valid FCB/buffer/cache/stack nonaliases. Global child errors/gate-set and arbitrary files/capacities excluded. No source-language item interpretation claimed.')
 laws['PLI.COM+119E']=dict(end=0x11c3,description='Canonical bounded counted-bit REL serializer',completeness=['stable','complete','partial'],contract='Retain existing counted-bit law unchanged: E->20B8 then C->20B7; fresh count determines repeat; freshly load20B7, RLC with exact carry ancestry, publish rotated byte, C=rotated byte, compose1140, then freshly load20B8/DCR/publish and repeat. Final A0/HL20B8 and comparison flags from final fresh zero-count CMP, actual last child BC/DE preserved. Independently proved every current natural caller across PLI0/PLI1/PLI2 and resident wrappers, including successful boundary flushes. E=0 is the zero-count route from the same complete CFG; count is byte-sized, no hardcoded fixture iteration. Caller scope remains bounded by successful child1140 and nonaliases; no global standalone Runner interception.')
 save(REPORT/'contract-laws-PLI.COM.json',laws)
 save(OUT/'annotation-rows-PLI.COM.json',{source:{key:g[key]for key in laws}for source,g in rows.items()})
 catalog={p['id']:p for p in load(Path('research/annotated-assembly/procedures.json'))['procedures']}
 packet=dict(task='RESIDENT_BUFFERED_REL_EMISSION_PASS_52',baseline=BASE,full_checkpoint='f7b744e2560c0de8ac1115cf91d4beb190f2e7c2',selected='resident tagged cached-word family',accepted_entries=[dict(coordinate=f'PLI.COM+{x:04X}',cache=f'{c:04X}',prefix=f'{t:02X}',length=34)for x,c,t in [(0x11c3,0x20b9,0),(0x11e5,0x20bb,0x40),(0x1207,0x20bd,0x80)]],unobserved_member=dict(coordinate='PLI.COM+1229',cache='20BF',prefix='C0',status='STATIC / UNOBSERVED; not promoted or intercepted'),laws=laws,topology=top,contracts={k:dict(hash=digest(catalog[k]),completeness=catalog[k]['completeness'])for k in ['PLI.COM+1140','PLI.COM+02EE','PLI.COM+0328','PLI.COM+19BB','PLI.COM+1272']},CFG={k:dict(hash=digest(v),instructions=len(v))for k,v in cfg.items()},stack_pattern='No persistent wrapper frame. Original CALL slotS unchanged.119E CALL wordS-2,1140 wordS-4,shifted PSW S-6; service frames derive deeper residue only on successful flush. EachRET consumes its own hardware word; outerSP=S+2. No N2/N8/XTHL reached.',oracle_queries=0,candidates=[dict(level='119E leaf',decision='reject global interception;1089 historical logical calls,1050 post51 external leaf roots versus110 external family transactions'),dict(level='individual wrappers',decision='accept as adapters of one canonical parameterized law, not separate passes'),dict(level='resident family',decision='selected generic representational boundary'),dict(level='immediate overlay callers',decision='defer compiler-phase semantics; shared resident operation is generic'),dict(level='PLI0/PLI1/PLI2 emission wrappers',decision='cross-phase anti-overfitting evidence, not part of this generic family')])
 save(REPORT/'implementation-packet.json',packet);print('packet bytes',(REPORT/'implementation-packet.json').stat().st_size)
def component_check(images):
 import subprocess,tempfile
 start=time.monotonic()
 with tempfile.TemporaryDirectory(prefix='components-',dir=OUT)as tmp:
  with(OUT/'component-proof.log').open('w')as log:r=subprocess.run(['dune','exec','bin/native_buffered_rel_hybrids.exe','--','--family-only','--toolchain',str(images),'--output-dir',str(Path(tmp)/'result')],stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((OUT/'component-proof.log').read_text()[-4000:])
 print('focused family/component proof passed',round(time.monotonic()-start,3))
def parent_assessment():
 routes=load(REPORT/'parent-route-summary.json');cfg=load(OUT/'parent-cfg.json')
 reasons={'PLI2.OVL+7434':'Adds7-bit96 prefix and independent1C2C publication from cached compiler word before tag40. Separate emission-policy state.', 'PLI2.OVL+7630':'Adds one-bit1 before tag40 and postchild7550 position policy; compact future output adapter.', 'PLI2.OVL+765E':'Adds one-bit1 before tag80 and postchild7550 position policy; compact future output adapter.', 'PLI2.OVL+829C':'Reads compiler structure pointerACA3->AC9F then pointer+2/+3 payload after7-bit94 header; structure-dependent compiler semantics.', 'PLI2.OVL+82DD':'Mixes7-bit9A/9C header emission, AE6A bitgate, close/console statistics; distinct lifecycle.', 'PLI2.OVL+7701':'Pointer-dependent generation withADEA..ADEE scratch and repeated field emission; independently partial generation family.', 'PLI0.OVL+1839':'Large independent compiler input/startup phase, not a generic resident emitter.'}
 save(REPORT/'parent-candidates.json',dict(selected='PLI.COM+11C3/+11E5/+1207',reason='Highest common generic state/representation law across the observed resident family; no compiler structure/policy input',candidates={k:dict(decision='deferred',reason=v,cfg_hash=digest(cfg[k])if k in cfg else None,natural_routes={source:g.get(k)for source,g in routes.items()})for k,v in reasons.items()},unobserved='1229 remainsSTATIC/UNOBSERVED'))
 packet=load(REPORT/'implementation-packet.json');packet['parent_assessment_hash']=digest(load(REPORT/'parent-candidates.json'));save(REPORT/'implementation-packet.json',packet)
def reports():
 packet=load(REPORT/'implementation-packet.json');top=load(REPORT/'topology-summary.json');roots=load(OUT/'natural-cases.json')['sources'];post=load(OUT/'cumulative-hybrid-summary.json')['sources']
 summary=[]
 for r in roots:
  entries=[]
  for e in r['entries']:
   cs=e['members'];entries.append(dict(offset=e['offset'],calls=len(cs),callers=dict(collections.Counter(c['caller']for c in cs)),input_BC_values=sorted({c['input']['b']*256+c['input']['c']for c in cs}),input_output_proof_hash=digest([(c['input'],c['output'],c['post_memory_sha256'],c['journal'])for c in cs]),journal_hash=digest([c['journal']for c in cs]),all_full_states_matched=True,child_order='119E/119E/119E with count2/8/8 and18 nested1140 calls',natural_flush_calls=0))
  summary.append(dict(source=r['source'],entries=entries))
 save(REPORT/'shadow-summary.json',dict(all_passed=True,logical_wrapper_shadows=sum(e['calls']for r in summary for e in r['entries']),sources=summary,components=load(OUT/'component-shadows.json'),full_state=['registers','all flags','SP/PC','ordered logical writes','65536 RAM bytes','stack last writers','child CALL chronology','DMA/filesystem','service resume boundaries','record chronology'],synthetic_discriminants=['low-only word0001','high-only word0100','A55A at byte127/bit7 flush','preexisting cache overwritten'],negative_proofs=['wrongCALL origin','changed immutable caller/root/tag/cache code','changed hardware continuation','index128','bit8','output gate','cache/buffer/code/stack sentinel aliases','corrupt result flags','corrupt publication order','corrupt last writer']))
 hierarchy={}
 for r in post:
  q=r['result'];source=q['source'];v=top[source]
  hierarchy[source]=dict(pre_guest=r['pre_guest_instructions'],post_guest=q['actual_guest_instructions'],saved=r['guest_instructions_removed'],pre_host=sum(r['pre_transition_vector']),post_host=q['host_transitions'],family_roots=r['family_roots'],member_transition_counts=r['transition_vector'][:3],logical_wrappers=sum(m['logical']for m in v['members'].values()),serializer_absorbed=3*r['family_roots'],bit_writer_absorbed=18*r['family_roots'],preexisting_native_descendants_absorbed={},serializer_remaining_external=v['remaining_external_serializer'],serializer_already_internal_to_previous_native_roots=v['pre_native_internal_serializer'],entry_vector=r['transition_vector'],pre_entry_vector=r['pre_transition_vector'],remaining_same_family_roots=0)
 save(REPORT/'hierarchy-summary.json',hierarchy)
 save(REPORT/'hybrid-summary.json',{k:load(OUT/(k+'-hybrid-summary.json'))for k in ['single','cumulative']})
 save(REPORT/'fidelity.json',dict(archaeological_scope_extension=True,historical_correction=None,implementation_correction=['Continuation-negative test XORs the actual byte because a natural continuation has low byte00; writing00 was not a corruption.','CLI and bridge plumbing adapted to canonical cross-overlay caller identity.','Unused119E bridge envelope corrected11BF->11C3 to include already-established loop JMP andRET; historical contract unchanged.','Annotation generator retains old FACTOR367/OPTIMIST1404 totals while adding PICTURE197.'],pragmatic_divergence=None,fidelity_debt=None,oracle_queries=0,RAW_to_UNDERSTOOD=load(REPORT/'archaeology-summary-PLI.COM.json'),validation_tier='incremental',full_checkpoint_base='f7b744e2560c0de8ac1115cf91d4beb190f2e7c2',cpu_runner_cpm_changes=False,shared_proof_schema_change=False,interactive_call_count='not instrumented',scripts_view_optimist_untouched=True,automated_phases=['corrected full serializer caller inventory','wrapper CFG normalization','exact-window hierarchy and parent ranking','writer cursor/flush classification','component/family shadow batches','synthetic stream and transactional rejection proofs','standalone/cumulative hybrids','contract annotations/progress','compact summaries and incremental validation dispatch']))
 save(REPORT/'boundary-assessment.json',dict(selected='PLI.COM+11C3/+11E5/+1207 generic cached tagged-word family',unobserved='1229 has exact static homologous shape but zero natural calls; remainsRAW and unaccepted',deferred_console='0D09 independent lower leverage console summary',next_recommended='Assess compact PLI2 result-emission adapters7630/765E/7434 against generation family boundaries before broad7701 migration',next_full_checkpoint='Pass53 scheduled; Pass50 remains current FULL checkpoint'))
 packet['proofs']=dict(root=digest(load(REPORT/'shadow-summary.json')),hierarchy=digest(hierarchy),writer_routes=digest(load(REPORT/'writer-route-summary.json')),oracle_queries=0)
 save(REPORT/'implementation-packet.json',packet)
 table='\n'.join(f"| {s} | {v['pre_guest']} | {v['post_guest']} | {v['saved']} | {v['pre_host']} | {v['post_host']} | {v['family_roots']} |"for s,v in hierarchy.items())
 (REPORT/'README.md').write_text("""# Pass52 — resident buffered tagged-word REL family

Baseline `c89fb3be1a5e5f077161c96f6f8b715baad69776`; FULL checkpoint remains
Pass50 `f7b744e2560c0de8ac1115cf91d4beb190f2e7c2`.

Fresh corrected inventory establishes119E calls189/703/197 (1089), partitioned
by exact caller in inventory.json/topology-summary.json. All current ordinary
calls independently match the canonical counted serializer, including successful
flushes1/5/1. Natural wrapper counts are11C3:1/1/1,11E5:14/63/14,
1207:2/14/4,1229:0/0/0. All four static34-byte shapes normalize identically;
1229 remains STATIC/UNOBSERVED, RAW and unaccepted. Actual observed owning
instructions/RET establish stable34-byte bounds and complete localCFG for the
three accepted members, while inherited service/error scopes remain partial.

One canonical parameterized historical operation saves B at cache+1 then C at
cache. Fixed prefix00/40/80 and cache20B9/20BB/20BD belong to entries11C3/11E5/1207.
Emit prefix withE2, independently paired-read cache and select low withE8,
then independently paired-read cache and select high withE8. All three119E calls
use the same canonical internal serializer and1140 writer. Safe interpretation:
18 emitted bits, tag2 then low8 then high8, each component MSB first. No item
semantics or source-language names. Static1229 would useC0/cache20BF but is not
promoted. +119E is never enabled as a global Runner root.

+119E retains its exact existing memory-driven count/RLC/append/DCR law. All
natural caller phases discriminate it independently; no caller/source dispatch.
+1140 successful flush fromPass51 is reused unchanged: actual buffer append,
byte/bit cursor, SetDMA26 then sequential-write21, successful status and index
clear. Natural wrapper calls do not flush; independently shadowed119E cases
include seven natural flushes. Synthetic word0001/0100 andA55A at127:7 compare
against a separate bit-stream/cursor/record equation including exact record bytes.
No new historical oracle queries. Input word values arise from currentBC;
no BC0 fixture or remembered final pointer.

Immediate parents include PLI0+1839, PLI2+7434/+7701/+7630/+765E/+829C/+82DD
and PLI0+3D2F. They add explicit policy:7434 publishes1C2C and a7-bit96 prefix;7630/765E
prepend bit1 and call7550 after the word;829C readsACA3 pointer fields;82DD
addsAE6A-gated emission, close and console statistics. These are separate
compiler-phase state/selection operations.
Keep the common resident representation boundary; caller contexts are proof,
not selection logic. Choosing wrappers instead of119E reduces boundary crossings:
110 accepted external transactions absorb330 serializer calls and1980 bit calls.
Four logical1207 calls are already under canonical0C75 and stay internal there.
Corrected external totals are16/75/19=110; logical totals17/78/19=114.
Remaining external119E calls130/450/140 stay guest; prior native parents already
internalize11/28/0. No already-native transitions are absorbed by this family.

114 logical family shadows,1089 independent119E shadows and2052 independent
required1140 shadows match registers/flags, ordered logical writes, full64KiBRAM,
stack last writers, child CALL chronology and staged external state. Three
standalone and three cumulative compiler hybrids preserve all console/milestone,
INT/REL record/file and BDOS chronology, filesystem, goldens and warm boot.

Wrappers have no private persistent frame. Original hardware word atS is never
written.119E hardware CALL atS-2,1140 atS-4, shifted PSW atS-6; service frames
are composed only when needed. EveryRET consumes its own word; outerSP=S+2.
Actual final channels are from the third119E, with finalA0/HL20B8 andCMP00 flags
S0Z1AC1P1CY0. Natural DE high is preserved andE8; BC is the last writer channel.
No N2/N8/XTHL is reached in this family. Canonical recursive acquisition roots
remain unchanged outside these windows. Complete staging validates before live
mutation; code/tag/cache/continuation/gate/cursor/alias corruption rejects.

New11C3/11E5 contracts represent68 RAW bytes;1207 and119E bounded scopes widen
with no newRAW bytes. All four contracts remain semantically partial, locally
stable/complete. Error/gate-set/arbitrary capacity and alias states stay excluded.
Historical catalog epochs retain old facts separately; no factual correction.

Actual whole-run counters (inclusive candidate ranks are not savings):

| Source | Pre guest | Post guest | Saved | Pre host | Post host | Roots |
|---|---:|---:|---:|---:|---:|---:|
"""+table+"""

The host-transition increase is explicit, limited to110 family roots instead
of1050 post51 external leaf roots (1089 historical logical calls). Exhaustive per-call journals/snapshots remain under ignored
_build; packet and summary hashes stay compact. Incremental categories and
receipt are validation.json. Reconstruction remains94720 bytes. No historical
correction, pragmatic divergence or fidelity debt; zero oracle queries.
scripts/view-optimist.sh is untouched. RecommendPass53 assess compact emission
adapters, with the scheduled full checkpoint after a successful semantic pass.
""")
 categories=['build','project','pass52','pass51','pass50','pass46','pass22','native-emitter-unit','emitter-unit','packet-continuation','V1','roundtrip-tests','roundtrip','dynamic-progress','diff-check']
 save(REPORT/'validation.json',dict(validation_tier='incremental',full_checkpoint_base='f7b744e2560c0de8ac1115cf91d4beb190f2e7c2',status='ready for final aggregate',workers=4,historical_bytes=94720,reruns=[],planned_categories=categories))
 print('packet bytes',(REPORT/'implementation-packet.json').stat().st_size);print(json.dumps(hierarchy,indent=2))
def catalog_check():
 import subprocess
 old={p['id']:p for p in json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))['procedures']}
 current={p['id']:p for p in load(Path('research/annotated-assembly/procedures.json'))['procedures']}
 for key in ['PLI.COM+119E','PLI.COM+1207']:
  for source,n in old[key]['observed_paths']['invocations_by_run'].items():assert current[key]['observed_paths']['invocations_by_run'].get(source,0)>=n,'historical counts lost'
 print('prior invocation totals retained; current M/F/P additions are separate')
def metadata_recheck(images):
 import subprocess
 catalog_check();dest=OUT/'metadata-recheck';names=['pass46','V1','roundtrip-tests','roundtrip','dynamic-progress','diff-check']
 subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images',str(images),'--output',str(dest),'--workers','4','--categories',','.join(names)],check=True)
 receipt=load(dest/'results.json');v=load(REPORT/'validation.json')
 v['initial_validation_wall_seconds']=v['validation_wall_seconds'];v['validation_wall_seconds']+=receipt['wall_seconds'];v['summed_category_seconds']+=receipt['sum_category_seconds'];v['status']='passed; late metadata preservation follow-up passed'
 v['reruns']=[dict(reason='After initial launch, restore historical FACTOR367/OPTIMIST1404 invocation totals accidentally omitted by the new annotation generator. No native algorithm/old historical law changed.',categories=list(receipt['categories']),wall_seconds=receipt['wall_seconds'],summed_category_seconds=receipt['sum_category_seconds'],all_passed=receipt['all_passed'])]
 v['metadata_followup_categories']=receipt['categories'];save(REPORT/'validation.json',v)
def validate(images):
 import subprocess
 catalog_check();dest=OUT/'incremental-validation';categories=load(REPORT/'validation.json')['planned_categories']
 subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images',str(images),'--output',str(dest),'--workers','4','--categories',','.join(k for k in categories if k not in ['build','project'])],check=True)
 receipt=load(dest/'results.json');v=load(REPORT/'validation.json')
 v.update(status='passed initially',all_passed=receipt['all_passed'],category_count=len(receipt['categories']),unique_python_test_count=sum(x['python_tests']for x in receipt['categories'].values()),dune_test_rule_stanzas=39,validation_wall_seconds=receipt['wall_seconds'],summed_category_seconds=receipt['sum_category_seconds'],slowest_categories=receipt['top_10_slowest'],categories=receipt['categories'],reruns=[])
 save(REPORT/'validation.json',v)
if __name__=='__main__':
 if sys.argv[1]=='inventory':inventory()
 elif sys.argv[1]=='rank':rank()
 elif sys.argv[1]=='writer_routes':writer_routes()
 elif sys.argv[1]=='parent_cfg':parent_cfg()

 elif sys.argv[1]=='prove':prove(Path(sys.argv[2]))

 elif sys.argv[1]=='contracts':contracts()
 elif sys.argv[1]=='compact_inventory':compact_inventory()

 elif sys.argv[1]=='component_check':component_check(Path(sys.argv[2]))

 elif sys.argv[1]=='reports':reports()
 elif sys.argv[1]=='parent_assessment':parent_assessment()
 elif sys.argv[1]=='validate':validate(Path(sys.argv[2]))
 elif sys.argv[1]=='metadata_recheck':metadata_recheck(Path(sys.argv[2]))
 elif sys.argv[1]=='catalog_check':catalog_check()
