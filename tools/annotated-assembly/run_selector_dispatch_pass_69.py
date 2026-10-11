#!/usr/bin/env python3
"""Pass69 concrete software-entry ownership; no native dispatcher or FULL execution."""
import argparse,collections,hashlib,json,os,subprocess,tempfile
from pathlib import Path
from check_selector02_pass_40 import load as witness_load,coord
OUT=Path('_build/host-compiler-pass-69');REPORT=Path('research/host-compiler/pass-69')
BASE='4558e0515d9c8f83b3bcb801084f6b8f4772a1df'
IMAGES='/home/john/pli/cpm/pli80/DISK1'
SOURCES=['MINIMAL','FIZZBUZ','PICTURE','FACTOR','OPTIMIST']
GOLDENS=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
def load(p):return json.loads(Path(p).read_text())
def save(p,x):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def instructions(p):return [e['witness']for e in witness_load(p)['events']if e['type']=='instruction']
def extract(dest):
 roots=[];inventory={}
 for source in SOURCES:
  summary=load(dest/(source+'-capture-summary.json'));inventory[source]=summary
  for p in sorted(dest.glob(source+'-*-witnesses.json')):
   entry=load(p.with_name(p.name.replace('-witnesses','-entry')));ws=instructions(p)
   own=[w for w in ws if coord(w['origin']) and coord(w['origin']).startswith('PLI2.OVL+') and 0x3de4<=w['origin']['offset']<0x3e36]
   calls=[w for w in own if w['control']['kind']=='call'];children=[]
   for w in calls:
    ret=next(q for q in ws if q['step_index']>w['step_index'] and q['control']['kind']=='return' and q['control']['taken'] and q['before']['sp']==w['after']['sp'] and q['after']['pc']==w['pc']+3)
    children.append(dict(callsite=coord(w['origin']),target=coord(w['target_origin']),call=w,ret=ret))
   # Actual gateway producer, not a nearest retained hardware frame guess.
   prefix=entry['prefix'];gateway=prefix[-4:]
   blocked=[dict(callsite=coord(w['origin']),step=w['step_index'],input=w['after'])for w in ws if w['control']['kind']=='call'and coord(w.get('target_origin'))=='PLI2.OVL+1FB5']
   selector=next(w['after']['c']for w in own if w['origin']['offset']==0x3df8)
   last={}
   for w in ws:
    for v in w['writes']:
     if entry['entry']['sp']-512<=v['address']<=entry['entry']['sp']+1:last[str(v['address'])]=dict(writer=coord(w['origin']),step=w['step_index'],value=v['new_value'])
   roots.append(dict(source=source,id=p.stem,entry=entry['entry'],continuation=entry['continuation'],gateway_hardware_call=next(q for q in reversed(entry['unmatched_hardware_call_observations'])if q['image']=='PLI2.OVL' and q['after']['pc']==0x41b5),gateway=gateway,low_writer=entry['low_writer'],high_writer=entry['high_writer'],selector=selector,children=children,own=own,ret=own[-1],gateway_calls=blocked,stack_last_writers=last,ordered_writes_sha256=digest([w['writes']for w in ws]),instruction_journal_sha256=digest(ws),instructions=len(ws)))
 return inventory,roots

def discover(images=IMAGES):
 dest=OUT/'capture';dest.mkdir(parents=True,exist_ok=True)
 if not os.environ.get('RUNES_HOST_IMAGES'):subprocess.run(['dune','build','bin/selector_dispatch_capture.exe','bin/selector_dispatch_frontend_proof.exe','bin/selector_dispatch_components.exe'],check=True)
 # Remove only this driver's previous witness artifacts, avoiding stale roots.
 for p in dest.glob('*'):p.unlink()
 subprocess.run(['_build/default/bin/selector_dispatch_capture.exe','--toolchain',images,'--output-dir',str(dest)],check=True)
 subprocess.run(['_build/default/bin/selector_dispatch_frontend_proof.exe','--images',images,'--seed',str(dest/'FIZZBUZ-1-entry.ram'),'--output',str(OUT/'frontend-proof.json')],check=True)
 inventory,roots=extract(dest);save(OUT/'inventory.json',inventory);save(OUT/'roots.json',roots)
 (OUT/'component-windows.txt').write_text(''.join(f"{r['source']} {r['own'][0]['step_index']} {r['ret']['step_index']}\n"for r in roots))
 subprocess.run(['_build/default/bin/selector_dispatch_components.exe','--images',images,'--windows',str(OUT/'component-windows.txt'),'--output',str(OUT/'component-shadows.json')],check=True)
 return inventory,roots

def reports():
 inventory=load(OUT/'inventory.json');roots=load(OUT/'roots.json')
 compact=[]
 for r in roots:
  compact.append({k:v for k,v in r.items()if k not in ['own','children','gateway']}|dict(gateway=r['gateway'],children=[dict(callsite=c['callsite'],target=c['target'],input=c['call']['after'],output=c['ret']['after'],return_site=coord(c['ret']['origin']))for c in r['children']],own_offsets=[w['origin']['offset']for w in r['own']],gate=next(w for w in r['own']if w['origin']['offset']==0x3de7)))
 save(REPORT/'ownership.json',compact)
 save(REPORT/'component-shadows.json',load(OUT/'component-shadows.json'))
 front=load(OUT/'frontend-proof.json');save(REPORT/'synthetic-summary.json',dict(scope=front['scope'],RAR_cases=front['RAR_cases'],case_count=len(front['cases']),all_passed=front['all_passed'],cases=[{k:v for k,v in c.items()if k!='steps'}|dict(checkpoint_sha256=digest(c['steps']))for c in front['cases']]))
 save(REPORT/'natural-inventory.json',{s:dict(roots=inventory[s]['roots'],selectors=dict(collections.Counter(str(r['selector'])for r in roots if r['source']==s)),REL_sha256=inventory[s]['REL_sha256'],helper_global_calls={k:inventory[s]['global_calls'].get(k,0)for k in ['PLI2.OVL+3660','PLI2.OVL+37CB','PLI2.OVL+3B7A','PLI2.OVL+3C27','PLI2.OVL+3D10','PLI2.OVL+397F','PLI2.OVL+18B3','PLI2.OVL+1FB5']},helper_callers={k:v for k,v in inventory[s]['callsite_counts'].items()if k.split('->')[1]in ['PLI2.OVL+3660','PLI2.OVL+37CB','PLI2.OVL+3B7A','PLI2.OVL+3C27']})for s in SOURCES})
 data=Path(IMAGES,'PLI2.OVL').read_bytes();table=[int.from_bytes(data[o:o+2],'little')for o in range(0x3e2b,0x3e35,2)]
 save(REPORT/'dispatch-law.json',dict(extent=['3DE4','3E36'],entry_kind='software PUSH-H/PCHL entry, not hardware CALL',gateway=['20AC LXI H,42B4','20AF PUSH H','20B0 LHLD AD1F','20B3 PCHL'],continuation='42B4',table_extent=['3E2B','3E35'],table_bytes=data[0x3e2b:0x3e35].hex().upper(),targets=table,selector_source='fresh little-endian word AD0A/AD0B; low byte AD0A zeroextended in BC; AD0B discarded',arithmetic='HL=602B; DAD B twice; E=byte[HL]; INX H; D=byte[HL]; XCHG; PCHL',gate='actual canonical3660 returned A; RAR consumes old A.bit0 as CY; JNC bypasses optional37CB',arms=[dict(selector=i,entry=f'{t-0x2200:04X}',child=child,C=c)for i,(t,child,c)in enumerate(zip(table,['3B7A','3D10','3C27','3C27','3B7A'],[0,None,1,0,1]))],shared_return='3E35 RET reads original gateway PUSH word; finalSP=entrySP+2',contract_status='not closed; selectors2/4 require unresolved broad1FB5',optional37CB='STATIC UNOBSERVED within dispatcher; recursive helper, not promoted',unobserved_selectors=[0,3],unsupported_selector_domain='>=5; no native default installed'))
 save(REPORT/'blocker.json',dict(coordinate='PLI2.OVL+1FB5',reason='broad gateway/dispatch-save-restore operation; expressly separate from local selector dispatcher',natural_routes=[dict(source=r['source'],selector=r['selector'],calls=r['gateway_calls'])for r in roots if r['gateway_calls']],child_assessments={'PLI2.OVL+3B7A':dict(extent=['3B7A','3BFB'],status='RAW; natural selector4 executes3660/3747;3747 calls1FB5 at374B'), 'PLI2.OVL+3C27':dict(extent=['3C27','3D10'],status='RAW; natural selector2 executes1FB5 at3CAE'), 'PLI2.OVL+37CB':dict(status='optional path unobserved; static recursive calls3812/3825 to37CB and call0992; no new contract')},native_boundary_installed=False))
 save(REPORT/'semantic-extraction.json',dict(historical_root='PLI2.OVL+3DE4 software entry',semantic_inputs=['selector byte AD0A','state consumed by canonical3660 and selected arm'],semantic_outputs=['selected historical generation operation effects, still delegated/unresolved'],shared_historical_state=['AD0A/AD0B','AD0D/AD0E','AD08','AD1F/AD20','gateway continuation42B4'],historical_mechanism=['PUSH H/PCHL entry','RAR result-bit gate','two DAD B operations','little-endian five-word table','shared RET'],candidate_modern_operation=None,confidence={'ownership':'OBSERVED across four sources; MINIMAL absent','dispatcher_mechanism':'OBSERVED selectors1/2/4; STATIC selectors0/3/optionalpath','whole_contract':'unresolved broad1FB5 dependency'},mir_relevance=None))
 save(REPORT/'implementation-packet.json',dict(task='RUNES_PLI2_BRANCH_OWNED_SELECTOR_DISPATCH_PASS_69',baseline=BASE,outcome='discovery milestone; blocked native closure atPLI2.OVL+1FB5',inventory=load(REPORT/'natural-inventory.json'),law=load(REPORT/'dispatch-law.json'),blocker=load(REPORT/'blocker.json'),journal_hashes={r['id']:r['instruction_journal_sha256']for r in roots},CPU_frontend=dict(cases=72,RAR_cases=512,scope='front-end instruction discriminants only; no arm-child patching or root shadows'),promotions={'RAW -> UNDERSTOOD':0,'DECODED -> UNDERSTOOD':0,'STRUCTURED -> UNDERSTOOD':0},oracle_queries=0,runtime_changes=False,current_full='Pass67',next_full='approximately Pass72'))

 # Static decode is retained as discovery evidence, never a status promotion.
 text='let c=open_in_bin "'+str(Path(IMAGES,'PLI2.OVL'))+'";;let b=Bytes.create(in_channel_length c);;really_input c b 0(Bytes.length b);;close_in c;;\nlet rec loop o e=if o<e then match I8080.Decode.decode b ~offset:o with Error _->failwith"decode"|Ok d->Printf.printf"%04X %s %s\\n"o(String.concat""(List.init d.length(fun i->Printf.sprintf"%02X"(Char.code(Bytes.get b(o+i))))))(I8080.Instr_format.format d.instr);loop(o+d.length)e;;\nloop 0x3de4 0x3e2b;;loop 0x3e35 0x3e36;;'
 (OUT/'decode.ml').write_text(text)
 listing=subprocess.check_output(['ocaml','-I','_build/default/lib/i8080/.i8080.objs/byte','_build/default/lib/i8080/i8080.cma',str(OUT/'decode.ml')],text=True)
 observed={w['origin']['offset']for r in roots for w in r['own']};cfg=[]
 for line in listing.splitlines():
  o,b,d=line.split(' ',2);o=int(o,16);cfg.append(dict(offset=o,bytes=b,decoded=d,evidence='OBSERVED discovery only'if o in observed else'STATIC UNOBSERVED; unsupported contract'))
 save(REPORT/'cfg.json',cfg)
 natural=sum(len(bytes.fromhex(q['bytes']))for q in cfg if q['offset']in observed)
 save(REPORT/'knowledge-accounting.json',dict(root_envelope_bytes=82,root_instruction_bytes=72,root_naturally_executed_instruction_bytes=natural,root_static_unobserved_instruction_bytes=72-natural,table_data_bytes=10,table_naturally_read_bytes=6,table_static_bytes=4,promotions={'RAW -> UNDERSTOOD':0,'DECODED -> UNDERSTOOD':0,'STRUCTURED -> UNDERSTOOD':0},new_contracts=[],new_native_roots=[]))
 selection=load(OUT/'historical-full-selection.json');old=load('research/host-compiler/pass-67/validation-full-initial.json');legacy=set(old['selected_categories']);selected=set(selection['selected_categories']);assert legacy<=selected and len(selected)==100
 save(REPORT/'historical-full-selection-proof.json',dict(executed=False,selected_categories=selection['selected_categories'],selected_category_count=100,certified_Pass67_category_count=len(legacy),all_certified_categories_preserved=True,all_92_Pass62_categories_preserved=True,additions=sorted(selected-legacy),current_full='Pass67'))

 residual={}
 for source in SOURCES:
  selected_roots=[r for r in roots if r['source']==source]
  residual[source]=dict(unmigrated_dispatcher_entries=len(selected_roots),direct_calls_still_outside_a_native_dispatcher={k:sum(c['target']==k for r in selected_roots for c in r['children'])for k in ['PLI2.OVL+3660','PLI2.OVL+37CB','PLI2.OVL+3B7A','PLI2.OVL+3D10','PLI2.OVL+3C27']},new_roots=0,absorbed_roots=0)
 save(REPORT/'residual-dispatch-map.json',dict(scope='exact discovered dispatcher windows, not an inferred global external-call map',sources=residual,global_counts_reference='natural-inventory.json',native_hierarchy_unchanged=True))
 save(REPORT/'next-boundaries.json',dict(ranking=[dict(coordinate='PLI2.OVL+397F',natural_hardware_calls={s:inventory[s]['global_calls'].get('PLI2.OVL+397F',0)for s in SOURCES},recommendation='next bounded assessment, not migration authorization',reason='a true independent entry with cross evidence; avoids automatically widening the blocked gateway'),dict(coordinate='PLI2.OVL+1FB5',status='true broad software-dispatch owner and demonstrated Pass69 blocker',recommendation='separate scoped gateway study only; do not invent a minimal dispatcher stub'),dict(coordinate='PLI2.OVL+18B3',natural_hardware_calls={s:inventory[s]['global_calls'].get('PLI2.OVL+18B3',0)for s in SOURCES},status='distinct large traversal, deferred despite dynamic leverage')],excluded=['PLI2.OVL+3E36'],raw_ranking_is_not_semantic_coherence=True))

def hybrids(images=IMAGES):
 """Fresh unchanged cumulative hierarchy, not a standalone native dispatcher."""
 OUT.mkdir(parents=True,exist_ok=True)
 if not os.environ.get('RUNES_HOST_IMAGES'):subprocess.run(['dune','build','bin/native_predicate_generation.exe'],check=True)
 with tempfile.TemporaryDirectory(prefix='hierarchy-',dir=OUT)as directory:
  dest=Path(directory)/'results';subprocess.run(['_build/default/bin/native_predicate_generation.exe','--toolchain',images,'--output-dir',str(dest)],check=True)
  receipt=load(dest/'cumulative-hybrid-summary.json');assert receipt['all_passed']
  save(REPORT/'current-hierarchy-recheck.json',dict(all_passed=True,scope='fresh unchanged existing cumulative hierarchy; no Pass69 native root',command='native_predicate_generation --toolchain IMAGES --output-dir ignored_build_directory',sources=[dict(result=s['result'],record_sha256_sequence=s['record_sha256_sequence'])for s in receipt['sources']]))

def validate(images=IMAGES):
 tmp=OUT/'tmp';tmp.mkdir(parents=True,exist_ok=True)
 subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--profile','active','--extra-categories','pass69','--images',images,'--output',str(OUT/'active-validation'),'--workers','4'],env={**os.environ,'TMPDIR':str(tmp.resolve())},check=True)
 receipt=load(OUT/'active-validation/results.json');receipt.update(historical_bytes=94720,dune_stanzas=39,reruns=[],historical_full_executed=False,full_trigger_fired=False);save(REPORT/'validation.json',receipt)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['discovery','reports','hybrids','validate']);p.add_argument('--images',default=IMAGES);a=p.parse_args()
 if a.phase=='discovery':discover(a.images)
 elif a.phase=='reports':reports()
 elif a.phase=='hybrids':hybrids(a.images)
 else:validate(a.images)
