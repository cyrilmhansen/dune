#!/usr/bin/env python3
"""Exact natural indexed-policy discovery. Never dispatches native or runs FULL."""
import argparse,collections,hashlib,json,os,subprocess,time
from pathlib import Path
from check_selector02_pass_40 import load as witness_load,coord
OUT=Path('_build/host-compiler-pass-70');REPORT=Path('research/host-compiler/pass-70')
BASE='1da471c4cda0f614574506de81306cb1240a11cd'
IMAGES='/home/john/pli/cpm/pli80/DISK1';SOURCES=['MINIMAL','FIZZBUZ','PICTURE','FACTOR','OPTIMIST']
GOLDENS=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
def load(p):return json.loads(Path(p).read_text())
def save(p,x):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,sort_keys=True,indent=2)+'\n')
def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def extract():
 inventory={};roots=[]
 for source in SOURCES:
  inventory[source]=load(OUT/'capture'/f'{source}-capture-summary.json')
  for p in sorted((OUT/'capture').glob(f'{source}-*-witnesses.json')):
   entry=load(p.with_name(p.name.replace('-witnesses','-entry')));events=witness_load(p)['events'];ws=[e['witness']for e in events if e['type']=='instruction']
   own=[w for w in ws if w['origin'] and w['origin']['image']['name']=='PLI2.OVL' and (0x397f<=w['origin']['offset']<0x3b3c or 0x3b62<=w['origin']['offset']<0x3b70)]
   children=[]
   for w in own:
    if w['control']['kind']!='call':continue
    #382E consumes a caller argument and relocates its CALL word: actual RET reads govern ownership.
    ret=next(q for q in ws if q['step_index']>w['step_index'] and q['control']['kind']=='return' and q['control']['taken'] and q['after']['pc']==w['pc']+3 and q['after']['sp'] in [w['before']['sp'],w['before']['sp']+2])
    children.append(dict(callsite=coord(w['origin']),target=coord(w['target_origin']),call=w,ret=ret))
   last={}
   for w in ws:
    for v in w['writes']:
     if entry['entry']['sp']-512<=v['address']<=entry['entry']['sp']+1:last[str(v['address'])]=dict(writer=coord(w['origin']),step=w['step_index'],value=v['new_value'])
   roots.append(dict(source=source,entry=entry,exit=load(p.with_name(p.name.replace('-witnesses','-exit'))),own=own,children=children,ret=own[-1],selector=own[0]['reads'][0]['value'],instructions=len(ws),gateway_calls=[dict(callsite=coord(w['origin']),step=w['step_index'],input=w['after'])for w in ws if w['control']['kind']=='call'and coord(w.get('target_origin'))=='PLI2.OVL+1FB5'],stack_last_writers=last,journal_sha256=digest(ws),ordered_writes_sha256=digest([w['writes']for w in ws]),argument_consumption=[w for w in ws if coord(w['origin']) in ['PLI2.OVL+3836','PLI2.OVL+3837','PLI2.OVL+3838','PLI2.OVL+3839','PLI2.OVL+383A']],branch_journal_sha256=digest([w for w in ws if w['control']['kind']not in ['sequential','call','return']]),non_instruction_events=[e for e in events if e['type']!='instruction']))
 save(OUT/'inventory.json',inventory);save(OUT/'roots.json',roots)
 (OUT/'component-windows.txt').write_text(''.join(f"{r['source']} {r['own'][0]['step_index']} {r['ret']['step_index']}\n"for r in roots))
 return inventory,roots

def discovery(images=IMAGES,reuse=False):
 start=time.monotonic();OUT.mkdir(parents=True,exist_ok=True)
 if not os.environ.get('RUNES_HOST_IMAGES'):subprocess.run(['dune','build','bin/indexed_policy_capture.exe','bin/indexed_policy_frontend_proof.exe','bin/indexed_policy_components.exe'],check=True)
 if not reuse:
  dest=OUT/'capture';dest.mkdir(exist_ok=True)
  for p in dest.glob('*'):p.unlink()
  subprocess.run(['_build/default/bin/indexed_policy_capture.exe','--toolchain',images,'--output-dir',str(dest)],check=True)
 extract()
 subprocess.run(['_build/default/bin/indexed_policy_frontend_proof.exe','--images',images,'--seed',str(OUT/'capture/FIZZBUZ-1-entry.ram'),'--output',str(OUT/'frontend-proof.json')],check=True)
 subprocess.run(['_build/default/bin/indexed_policy_components.exe','--images',images,'--windows',str(OUT/'component-windows.txt'),'--output',str(OUT/'component-shadows.json')],check=True)
 save(OUT/'focused-timing.json',dict(wall_seconds=round(time.monotonic()-start,3),capture_reused=reuse,scope='components plus synthetic proof; natural capture separately executed'if reuse else'five-source capture, components and synthetic proof'))

def reports(images=IMAGES):
 inventory,roots=extract();data=Path(images,'PLI2.OVL').read_bytes();targets=[int.from_bytes(data[o:o+2],'little')for o in range(0x3b3c,0x3b62,2)]
 script='let c=open_in_bin "'+str(Path(images,'PLI2.OVL'))+'";;let b=Bytes.create(in_channel_length c);;really_input c b 0(Bytes.length b);;close_in c;;\nlet rec loop o e=if o<e then match I8080.Decode.decode b ~offset:o with Error _->failwith"decode"|Ok d->Printf.printf"%04X %s %s\\n"o(String.concat""(List.init d.length(fun i->Printf.sprintf"%02X"(Char.code(Bytes.get b(o+i))))))(I8080.Instr_format.format d.instr);loop(o+d.length)e;;\nloop 0x397f 0x3b3c;;loop 0x3b62 0x3b70;;'
 (OUT/'report-decode.ml').write_text(script)
 listing=subprocess.check_output(['ocaml','-I','_build/default/lib/i8080/.i8080.objs/byte','_build/default/lib/i8080/i8080.cma',str(OUT/'report-decode.ml')],text=True)
 observed={w['origin']['offset']for r in roots for w in r['own']};cfg=[]
 for line in listing.splitlines():
  o,b,d=line.split(' ',2);cfg.append(dict(offset=int(o,16),bytes=b,decoded=d,evidence='OBSERVED discovery only'if int(o,16)in observed else'STATIC UNOBSERVED; no arm contract'))
 assert sum(len(bytes.fromhex(q['bytes']))for q in cfg)==459
 assert all(t-0x2200 in {q['offset']for q in cfg}for t in targets)
 save(REPORT/'cfg.json',cfg)
 save(REPORT/'natural-inventory.json',{s:dict(roots=inventory[s]['roots'],REL_sha256=inventory[s]['REL_sha256'],filesystem_sha256=inventory[s]['filesystem_sha256'],callers={k:v for k,v in inventory[s]['callsite_counts'].items()if k.endswith('->PLI2.OVL+397F')},overlapping_hardware_entries={k:v for k,v in inventory[s]['global_calls'].items()if 0x397f<=int(k.split('+')[1],16)<0x3b70},helper_global_calls={k:inventory[s]['global_calls'].get(k,0)for k in ['PLI2.OVL+373C','PLI2.OVL+3790','PLI2.OVL+8386','PLI2.OVL+382E','PLI2.OVL+7B99','PLI2.OVL+1FB5','PLI2.OVL+18B3']})for s in SOURCES})
 compact=[]
 for r in roots:
  compact.append(dict(source=r['source'],selector=r['selector'],entry={k:v for k,v in r['entry'].items()if k not in ['prefix','unmatched_hardware_call_observations']}|dict(prefix_sha256=digest(r['entry']['prefix']),unmatched_hardware_call_observations_sha256=digest(r['entry']['unmatched_hardware_call_observations'])),exit=r['exit'],instructions=r['instructions'],own=r['own'],children=[dict(callsite=c['callsite'],target=c['target'],input=c['call']['after'],output=c['ret']['after'],call_stack_writes=c['call']['writes'],return_site=coord(c['ret']['origin']),return_reads=c['ret']['reads'])for c in r['children']],gateway_calls=r['gateway_calls'],stack_last_writers=r['stack_last_writers'],journal_sha256=r['journal_sha256'],ordered_writes_sha256=r['ordered_writes_sha256'],event_counts=dict(collections.Counter(e['type']for e in r['non_instruction_events'])),record_events=[e for e in r['non_instruction_events']if e['type']=='bdos_record']))
 save(REPORT/'ownership.json',compact)
 save(REPORT/'stack-argument-proof.json',[dict(source=r['source'],argument_consumption=r['argument_consumption'],branch_journal_sha256=r['branch_journal_sha256'])for r in roots])
 law=dict(extent_assessment=['397F','3B70'],instruction_ranges=[['397F','3B3C'],['3B62','3B70']],instruction_bytes=459,table_extent=['3B3C','3B62'],table_bytes=38,table_entries=19,targets=[f'{t-0x2200:04X}'for t in targets],frontend='fresh LHLD AD0A/AD0B; C=L; B=0; HL=5D3C; DAD B twice; E=byte[HL]; INX H; D=byte[HL]; XCHG; PCHL with unchanged SP',natural_selector=15,natural_arm='3ACC',common_tail='fresh LHLD AD0A; H=0; BC=579B; DAD B; A=byte[HL]; AD06=A; RET; NZPA inherited, CY from DAD',return_law='original hardware CALL continuation645A; final SP=entrySP+2',children={'373C':'unclosed compact adapter: fresh AD0C low -> CALL1FB5 at3740 then371B; gateway naturally required','3790':'canonical Pass68 bounded mapped-word operation','8386':'RAW compact candidate [8386,838E): SUB A; SUB L; L=A; A=0; SBB H; H=A; RET; byte arithmetic forms word negation, flags from high SBB','382E':'RAW policy [382E,38B1) orientation; POP D consumes CALL word, POP B consumes caller PUSH, PUSH D relocates continuation; general child law unclosed','7B99':'canonical Pass58 indexed transfer/emission'},contract_status='not closed: naturally required broad1FB5',following_3B70='distinct body excluded',frontend_proof_is_not_arm_proof=True)
 save(REPORT/'dispatch-law.json',law);save(REPORT/'component-shadows.json',load(OUT/'component-shadows.json'))
 front=load(OUT/'frontend-proof.json');save(REPORT/'synthetic-summary.json',dict(scope=front['scope'],frontend_cases=len(front['cases']),tail_cases=front['tail_cases'],all_passed=front['all_passed'],checkpoint_sha256=digest(front),selector_domain='0..18 table frontend only;19 concrete out-of-table observation, never accepted native'))
 natural=sum(len(bytes.fromhex(q['bytes']))for q in cfg if q['offset']in observed)
 promotions={'RAW -> UNDERSTOOD':0,'DECODED -> UNDERSTOOD':0,'STRUCTURED -> UNDERSTOOD':0}
 save(REPORT/'knowledge-accounting.json',dict(root_envelope_bytes=497,root_instruction_bytes=459,natural_observed_discovery_bytes=natural,static_unobserved_discovery_bytes=459-natural,table_data_bytes=38,natural_table_bytes=2,promotions=promotions,new_contracts=[],new_native_roots=[]))
 save(REPORT/'semantic-extraction.json',dict(historical_root='PLI2.OVL+397F',semantic_inputs=['fresh selector AD0A','selected-arm state including fresh AD0D low'],semantic_outputs=['selected policy effects still delegated to unresolved children','AD06 byte from fresh selector-indexed vector579B'],shared_historical_state=['AD0A/AD0B','AD0D/AD0E','AD06','stack continuation and pushed argument'],historical_mechanism=['indexed little-endian19-word PCHL table','unchanged SP at dispatch','PUSH B argument consumed by382E','common vector publication and hardware RET'],candidate_modern_operation=None,confidence={'frontend_and_natural_arm':'OBSERVED FIZZBUZ/OPTIMIST','unused_arms':'STATIC UNOBSERVED','complete_policy':'not established; broad1FB5'},mir_relevance=None))
 save(REPORT/'implementation-packet.json',dict(task='RUNES_PLI2_INDEXED_POLICY_397F_PASS_70',baseline=BASE,outcome='discovery-only; natural closure blocked atPLI2.OVL+1FB5',law=law,inventory=load(REPORT/'natural-inventory.json'),proofs=load(REPORT/'synthetic-summary.json'),components=load(REPORT/'component-shadows.json'),journals={r['source']:r['journal_sha256']for r in roots},promotions=promotions,runtime_changes=False,oracle_queries=0,current_full='Pass67',next_full='approximately Pass72'))
 save(REPORT/'next-boundaries.json',dict(ranking=[dict(coordinate='PLI2.OVL+1FB5',reason='actual repeated substantive blocker; study independently with a carefully scoped gateway problem'),dict(coordinate='PLI2.OVL+382E',reason='independent compact-to-medium generation/stack-argument policy candidate; establish child graph before migration'),dict(coordinate='PLI2.OVL+18B3',reason='large unrelated traversal deferred; count alone does not justify priority')],parent_callsite='PLI2.OVL+4257; enclosing handler is not inferred from adjacency',excluded=['PLI2.OVL+3E36']))
 selection=load(OUT/'historical-full-selection.json');certified=set(load('research/host-compiler/pass-67/validation-full-initial.json')['selected_categories']);assert certified<=set(selection['selected_categories']) and len(selection['selected_categories'])==101
 save(REPORT/'historical-full-selection-proof.json',dict(executed=False,selected_category_count=101,all_98_certified_Pass67_categories_preserved=True,selected_categories=selection['selected_categories']))
 save(REPORT/'validation-rationale.json',dict(build='mandatory project build, including proof-only executables',project='mandatory project unit suite; no runtime modification',pass70='new exhaustive natural/discovery and local CPU/component proof',**{'diff-check':'patch whitespace integrity','validation-runner-tests':'new category registration and selection preservation'}))

def validate(images=IMAGES):
 tmp=OUT/'tmp';tmp.mkdir(parents=True,exist_ok=True)
 subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--categories','pass70,diff-check,validation-runner-tests','--images',images,'--output',str(OUT/'validation'),'--workers','4'],env={**os.environ,'TMPDIR':str(tmp.resolve())},check=True)
 receipt=load(OUT/'validation/results.json');receipt.update(historical_full_executed=False,full_trigger_fired=False,historical_bytes=94720,reruns=([dict(reason='driver attempted Dune build inside read-only parallel category; honor RUNES_HOST_IMAGES',scope='complete five-category aggregate',initial_receipt='validation-initial.json')]if (REPORT/'validation-initial.json').exists()else []),dune_stanzas=39);save(REPORT/'validation.json',receipt)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['discovery','reports','validate']);p.add_argument('--images',default=IMAGES);p.add_argument('--reuse-capture',action='store_true');a=p.parse_args()
 if a.phase=='discovery':discovery(a.images,a.reuse_capture)
 elif a.phase=='reports':reports(a.images)
 else:validate(a.images)
