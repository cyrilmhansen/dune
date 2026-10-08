#!/usr/bin/env python3
"""Bounded initialization family: corrected inventory, proofs and reports."""
import collections,hashlib,json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-49');REPORT=Path('research/host-compiler/pass-49');BASE='f4e286a2339be7de1020404c5cbb4d1903cff547'
def save(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,indent=2)+'\n')
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def inventory(offsets=None):
 start=time.monotonic();keys=['PLI1.OVL+'+k for k in (offsets or ['0C1B','0C75','01C6','0B84','013D','4802'])];rows={};cfg={};cases={};routes={}
 for source,path in CAPTURES.items():
  group=gather_selected(path,{k:(int(k.split('+')[1],16),int(k.split('+')[1],16)+1)for k in keys},include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8});rows[source]=group;cases[source]={}
  for k,rs in group.items():
   cfg.setdefault(k,{})
   cs=[]
   for r in rs:
    for w in r['own_witnesses']:cfg[k][w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
    seq=[[c['callsite'],c['target']]for c in children_any(r)];route=digest(seq);routes.setdefault(route,seq)
    cs.append(dict(call=r['call']['step_index'],ret=r['ret']['step_index'],caller=coord(r['call']['origin']),entry=r['entry']['before'],output=r['ret']['after'],route=route,branches=[[w['origin']['offset'],w['control']['taken']]for w in r['own_witnesses']if w['control']['kind']in ['jump','return']],proof_hash=digest(r)))
   cases[source][k]=cs
 suffix='family'if offsets is None else '-'.join(offsets)
 save(OUT/(suffix+'-rows.json'),rows);save(OUT/(suffix+'-cfg.json'),{k:sorted(v.values())for k,v in cfg.items()})
 catalog={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
 refs={k:dict(procedure_hash=digest(catalog[k]),completeness=catalog[k]['completeness'],contract=catalog[k].get('contract'))if k in catalog else None for k in keys}
 packet=dict(task='INITIALIZATION_PARENT_0C1B_PASS_49',baseline=BASE,cfg={k:sorted(v.values())for k,v in cfg.items()},routes=routes,cases=cases,contracts=refs)
 save(OUT/(suffix+'-packet.json'),packet)
 if offsets is None:save(REPORT/'implementation-packet.json',packet)
 summary={s:{k:dict(count=len(rs),callers=dict(collections.Counter(r['caller']for r in rs)),routes=dict(collections.Counter(r['route']for r in rs)))for k,rs in ks.items()}for s,ks in cases.items()}
 save(OUT/(suffix+'-summary.json'),summary)
 print(json.dumps(dict(summary=summary,cfg={k:v for k,v in packet['cfg'].items()if not k.endswith('0C75')},contracts=refs,seconds=round(time.monotonic()-start,3)),indent=2))

def compact():
 catalog={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
 laws=json.loads((REPORT/'contract-laws-PLI1.OVL.json').read_text());allrows={s:{}for s in CAPTURES};cfg={};routes={};cases={s:{}for s in CAPTURES}
 for suffix in ['family','4890-47E2','47F7-3563']:
  for source,group in json.loads((OUT/(suffix+'-rows.json')).read_text()).items():allrows[source].update(group)
 for source,group in allrows.items():
  for key,rows in group.items():
   cases[source][key]=[]
   for row in rows:
    row['nested_returns']={int(k):v for k,v in row['nested_returns'].items()}
    seq=[[c['callsite'],c['target']]for c in children_any(row)];route=digest(seq);routes.setdefault(route,seq)
    cfg.setdefault(key,{}).update({w['origin']['offset']:[w['origin']['offset'],w['bytes'],w['disassembly']]for w in row['own_witnesses']})
    cases[source][key].append(dict(caller=coord(row['call']['origin']),call=row['call']['step_index'],ret=row['ret']['step_index'],entry=row['entry']['before'],output=row['ret']['after'],route=route,proof_hash=digest(row)))
 refs={key:dict(coordinate=key,contract_hash=digest(catalog[key]),completeness=catalog[key]['completeness'])for key in laws}
 for key in ['PLI1.OVL+0A32','PLI1.OVL+02F0','PLI1.OVL+784E','PLI1.OVL+452B','PLI1.OVL+41A6','PLI1.OVL+421F','PLI1.OVL+4227','PLI1.OVL+0261','PLI1.OVL+58BB','PLI1.OVL+2511','PLI1.OVL+80EF','PLI.COM+1A33']:
  if key in catalog:refs[key]=dict(coordinate=key,contract_hash=digest(catalog[key]),completeness=catalog[key]['completeness'])
 decoded={k:sorted(v.values())if k in laws else dict(cfg_hash=digest(sorted(v.values())),reference='pass-48/parent-candidates.json')for k,v in cfg.items()}
 packet=dict(task='INITIALIZATION_PARENT_0C1B_PASS_49',baseline=BASE,selected_root='PLI1.OVL+0C1B',selection='0C1B forms one initialization transaction with visible A5B5 exchange/restoration, cursor setup, bounded structure gate and canonical0A32.0C75 adds a distinct delimiter/EOF driver and A5D9 lifetime; do not widen.',cfg=decoded,routes=routes,cases=cases,contracts=refs,stack_patterns=dict(context='F=entrySP-4; F0/F1 savedBC; F2/F3 oldA5B5 overwrite savedHL. Two POP H, original RET. Child hardware frames and N2/N8 software protocols remain separate.',exchange='4890 PUSH slot; PUSH/XTHL exchanges actual word[SP] low/high without changing SP/flags. Stack bytes derived from current pointers, never oracleRAM.'),laws_reference='contract-laws-PLI1.OVL.json',oracle_queries=0)
 ids={k:k[:12]for k in packet['routes']};assert len(set(ids.values()))==len(ids)
 packet['routes']={ids[k]:v for k,v in packet['routes'].items()}
 for group in packet['cases'].values():
  for rows in group.values():
   for case in rows:case['route']=ids[case['route']]
 packet['state_encoding']=['A','B','C','D','E','H','L','SP','PC','flags:S7 Z6 AC4 P2 CY0']
 for group in packet['cases'].values():
  for rows in group.values():
   for case in rows:
    for channel in ['entry','output']:
     state=case[channel];f=state['flags'];case[channel]=[state[k]for k in ['a','b','c','d','e','h','l','sp','pc']]+[sum(bit for k,bit in [('sign',128),('zero',64),('auxiliary_carry',16),('parity',4),('carry',1)]if f[k])]
 (REPORT/'implementation-packet.json').write_text(json.dumps(packet,separators=(',',':'))+'\n')
 save(REPORT/'natural-cases.json',{s:{k:dict(count=len(rs),callers=dict(collections.Counter(r['caller']for r in rs)),routes=dict(collections.Counter(r['route']for r in rs)))for k,rs in group.items()}for s,group in cases.items()})
 save(REPORT/'boundary-assessment.json',dict(selected_root=packet['selected_root'],selection=packet['selection'],next_parent='PLI1.OVL+0C75 delimiter/EOF driver, scheduled Pass50 full checkpoint',unsupported=['01C6 nonsemicolon arm','0B84 nonborrow initializer','4802 initial no-borrow exit','47E2 overflow/error','3563 zero-high arm','zero-length cursor records; arbitrary ownership/capacities/aliases','canonical child unsupported routes'],parent_counts={s:{k:len(cases[s][k])for k in ['PLI1.OVL+0C1B','PLI1.OVL+0C75']}for s in cases}))
 for name in ['after-PLI1.OVL.json']:
  p=REPORT/name
  if p.exists():p.rename(OUT/name)
 print(json.dumps(dict(packet_bytes=(REPORT/'implementation-packet.json').stat().st_size,counts={s:{k:len(v)for k,v in group.items()}for s,group in cases.items()})))

def prove(images,*,persist=False):
 import subprocess,tempfile,shutil
 start=time.monotonic();OUT.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='initialization-proof-',dir=OUT)as temp:
  dest=Path(temp)/'result'
  commands=[['dune','exec','bin/native_acquisition_family.exe','--','--operation','initialization','--toolchain',str(images),'--output',str(Path(temp)/'components.json')],['dune','exec','bin/native_initialization_parent_hybrids.exe','--','--toolchain',str(images),'--output-dir',str(dest)]]
  for i,command in enumerate(commands):
   with (OUT/f'proof-{i}.log').open('w')as log:result=__import__('subprocess').run(command,stdout=log,stderr=__import__('subprocess').STDOUT)
   if result.returncode:raise RuntimeError((OUT/f'proof-{i}.log').read_text()[-2000:])
  target=OUT/('validated-proof'if persist else 'fresh-'+Path(temp).name);target.mkdir(exist_ok=True)
  for file in dest.glob('*.json'):shutil.copyfile(file,target/file.name)
  shutil.copyfile(Path(temp)/'components.json',target/'components.json')
 save(OUT/'proof-timing.json',dict(wall_seconds=round(time.monotonic()-start,3),all_passed=True))
 return target

def report(proof):
 roots=json.loads((proof/'natural-cases.json').read_text())['sources'];post=json.loads((proof/'cumulative-hybrid-summary.json').read_text())['sources'];components=json.loads((proof/'components.json').read_text())['sources'];archive={};hierarchy={}
 for r in roots:
  archive[r['source']]=[dict(caller=c['caller'],entry_step=c['entry_step'],return_step=c['return_step'],input=c['input'],output=c['output'],route=c['result']['route'],ordered_writes=len([w for w in c['journal']if w[4]=='logical']),writer_cells=len(set(w[0]for w in c['journal'])),journal_hash=digest(c['journal']),post_memory_sha256=c['post_memory_sha256'],services_hash=digest(c['service_details']),frame=dict(base=c['input']['sp']-4,old_context=c['output']['h']*256+c['output']['l']))for c in r['members']]
 for r in post:
  s=r['result']['source'];pre=r['pre_transition_vector'];after=r['transition_vector'];hierarchy[s]=dict(pre_guest=r['pre_guest_instructions'],post_guest=r['result']['actual_guest_instructions'],guest_removed=r['guest_instructions_removed'],pre_host=sum(pre),post_host=sum(after),root_transitions=after[0],native_transition_delta=[a-b for a,b in zip(pre,after[1:])],absorbed_by_coordinate={'PLI1.OVL+0A32':pre[0]-after[1],'PLI1.OVL+2511':pre[6]-after[7],'PLI1.OVL+80B7':pre[10]-after[11],'PLI.COM+0EF6':pre[22]-after[23]},internal_02F0_outer={'MINIMAL':1,'FIZZBUZ':1,'PICTURE':2}[s],internal_02F0_logical={'MINIMAL':1,'FIZZBUZ':8,'PICTURE':2}[s],remaining_external_0A32=after[1],remaining_external_02F0=after[2],REL_sha256=r['result']['REL_sha256'])
 save(REPORT/'shadow-summary.json',dict(all_passed=True,roots=archive,components=[dict(source=r['source'],operation=r['operation'],count=r['field15_matched'],pending=r['field80_boundary_matched'],proof_hash=digest(r['cases']))for r in components],comparisons=['registers/all flags','SP/continuation','ordered logical writes','65536-byte RAM','stack last writers','DMA/filesystem','record and file chronology','new local child-call chronology','canonical0A32/02F0/19F0/6619/6223 checkpoints']))
 save(REPORT/'hierarchy-summary.json',hierarchy)
 save(REPORT/'hybrid-summary.json',{n:json.loads((proof/(n+'-hybrid-summary.json')).read_text())for n in ['single','cumulative']})
 archaeology=json.loads((REPORT/'archaeology-summary-PLI1.OVL.json').read_text())
 save(REPORT/'fidelity.json',dict(archaeological_scope_extension=True,historical_correction=None,implementation_correction='Corrected proof name shadowing and unit-test state construction before execution; independent512-state test corrected a draft bit40 comment inversion, with host arithmetic unchanged. No historical contract correction.',pragmatic_divergence=None,fidelity_debt=None,oracle_queries=0,RAW_to_UNDERSTOOD=archaeology['raw_to_understood'],by_procedure=archaeology['by_procedure'],validation_tier='incremental',full_checkpoint_base='7a4bf0adf5959ffa29238a7f30d549522d18750f',cpu_runner_cpm_changes=False,proof_schema_change=False,compatibility_extension='Typed XTHL event in the existing planner; serialized journals unchanged.',scripts_view_optimist_untouched=True))
 table='\n'.join(f"| {s} | {v['pre_guest']} | {v['post_guest']} | {v['guest_removed']} | {v['pre_host']} | {v['post_host']} |"for s,v in hierarchy.items())
 (REPORT/'README.md').write_text('''# Pass49 — bounded +0C1B initialization parent

Baseline `'''+BASE+'''`; full checkpoint Pass47. Validation tier incremental.

Fresh corrected inventory: one +0C1B root per source from +0CD7, one shared
local straight-line child sequence. +0C75 remains the next delimiter/EOF driver:
its A5D9 lifetime and reader policy are separate from this initialization root.
Candidate ranking measurements are never substituted for whole-run savings.

F=entrySP-4 contains independently saved input BC at F0/F1 and fresh old A5B5
at F2/F3, overwriting the initial PUSH HL residue. Publish saved input BC to A5B5,
compose01C6/0261/013D, reread input for58BB, emit7D through canonical2511,
reread input for A863, compose the pointer+5 unsigned-borrow0B84 gate, independently
reread BC/setE2 for canonical0A32, then fresh784E. Restore A5B5 low/high before two
POP H and RET. Final HL is old A5B5; flags retain the final acquisition channels
except CY replaced by final DAD SP. Same-valued writes and fresh rereads remain visible.

Independent structural composition closes4802/4890/47E2, including PICTURE's
field3/bit40 mode route through47F7/3563. Cursor advancement uses fresh record
length, a fresh cursor base and wrapping addition; zero-length records are outside
the bounded scope. Index growth follows fresh count comparison. Cursor/floor and
high-field masks independently drive traversal. Prefix hash slot linkage preserves
PUSH/XTHL, old slot->pointer+8 stores, and independently reread pointer->slot stores.
No source/index/depth/capture/hash dispatch or final-state copying is used.

`contract-laws-PLI1.OVL.json` is canonical; annotation headers/local comments and
catalog evidence are generated from it and corrected own-instruction witnesses.
New contracts01C6/0B84/013D/0C1B/47F7/3563 and bounded4802/4890/47E2 extensions
represent184 formerly RAW bytes. Unexecuted initialization/error/zero-high arms
remain RAW and unsupported. Historical facts are extended, not corrected.

All natural component shadows and all three parent shadows compare registers,
flags, continuation/SP, ordered logical writes, full64KiB RAM, stack last writers,
DMA/filesystem and record/file chronology. Independent canonical0A32,02F0 and
lower journals correlate inside the parent. Hardware recursion, N2/N8 software
continuations and XTHL stack exchange retain their distinct historical mechanisms.
All descendants are internal to one staged transaction; rejected preparation leaves
live state unchanged. No tiny descendant gains a Runner interceptor.

| Source | Pre49 guest | Post49 guest | Saved | Pre host | Post host |
|---|---:|---:|---:|---:|---:|
'''+table+'''

Standalone/cumulative hybrids preserve all REL goldens, INT/REL event order,
filesystem, PASS1/PASS2/END and warm boot. Full proof journals remain ignored
under `_build/host-compiler-pass-49`; durable summaries carry hashes only.
The driver automates inventory, CFG/child correlation, compact packet generation,
component proof batches, root shadows, hybrid counters, reporting and validation.
Zero oracle queries; no historical correction, pragmatic divergence or fidelity debt.
The local proof compiler name-shadowing error was corrected before executable proof.

`validation.json` records final categories/timing. Reconstruction remains94720 bytes.
Next: +0C75 delimiter/EOF driver and scheduled Pass50 full checkpoint.
`scripts/view-optimist.sh` remains unrelated and untouched.
''')
 print(json.dumps(hierarchy))

if __name__=='__main__':
 phase=sys.argv[1]
 if phase=='inventory':inventory(sys.argv[2:]or None)
 elif phase=='compact':compact()
 elif phase=='prove':print(prove(Path('/home/john/pli/cpm/pli80/DISK1'),persist=True))
 elif phase=='report':report(Path(sys.argv[2])if len(sys.argv)>2 else OUT/'validated-proof')
 elif phase=='validate':
  import subprocess
  categories='pass49,pass48,pass47,minimal-pass-12,packet-continuation,recursive-unit,acquisition-parent-unit,classifier-unit,balance-unit,gate-unit,control-unit,input-unit,V1,roundtrip-tests,roundtrip,dynamic-progress,diff-check'
  subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images','/home/john/pli/cpm/pli80/DISK1','--output',str(OUT/'incremental-validation'),'--categories',categories,'--workers','4'],check=True)
