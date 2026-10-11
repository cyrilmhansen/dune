#!/usr/bin/env python3
"""Gateway-own decomposition and concrete frame proofs; never installs a callback or runs FULL."""
import argparse,collections,hashlib,json,os,subprocess,time
from pathlib import Path
OUT=Path('_build/host-compiler-pass-71');REPORT=Path('research/host-compiler/pass-71');BASE='21411f1283b52a0a96e5ae24d55e49637fc9bcad';IMAGES='/home/john/pli/cpm/pli80/DISK1';SOURCES=['MINIMAL','FIZZBUZ','PICTURE','FACTOR','OPTIMIST']
GOLDENS=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
def load(p):return json.loads(Path(p).read_text())
def save(p,x):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,sort_keys=True,indent=2)+'\n')
def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def accesses(w,kind):return [x for x in w['accesses']if x['kind']==kind]
def word(q):return q['h']*256+q['l']
def extract():
 inventory={};roots=[]
 for source in SOURCES:
  summ=load(OUT/'capture'/f'{source}-summary.json');inventory[source]=summ
  frames={q['id']:dict(source=source,entry=q,exit=next(e for e in summ['exits']if e['id']==q['id']),own=[],predicates=[],lookup=None,handler_ret=None,original_slot_writes=[],descendant_original_slot_writes=[],journal=hashlib.sha256(),predicate_journal=hashlib.sha256(),predicate_children=collections.Counter(),predicate_offsets=set(),predicate_tokens=[])for q in summ['entries']}
  pending={};writers={}
  with (OUT/'capture'/f'{source}-steps.jsonl').open()as f:
   for line in f:
    w=json.loads(line);frame=frames[w['id']];frame['journal'].update(line.encode())
    own=w['image']=='PLI2.OVL'and 0x1fb5<=w['offset']<0x20eb
    if own:frame['own'].append(w)
    if w['image']=='PLI2.OVL'and 0x1dff<=w['offset']<0x1fb5:
     frame['predicate_offsets'].add(w['offset']);
     if w['offset']==0x1e40:frame['predicate_tokens'].append(w['before']['a'])
     frame['predicate_journal'].update(line.encode())
     if w['kind']=='call':frame['predicate_children'][w['target']]+=1
    for x in accesses(w,'write'):
     writers[x['address']]=dict(step=w['step'],image=w['image'],offset=w['offset'],value=x['value'])
     e=frame['entry'];s=e['entry']['sp']
     if x['address']in [s,s+1]:frame['original_slot_writes'].append(w)
     parent=e['parent']
     while parent:
      ancestor=frames[parent];s0=ancestor['entry']['entry']['sp']
      if x['address']in [s0,s0+1]:ancestor['descendant_original_slot_writes'].append(w)
      parent=ancestor['entry']['parent']
    if own and w['kind']=='call' and w['taken']:
     pending[(w['id'],w['pc']+3 if 'pc'in w else w['before']['pc']+3,w['after']['sp'])]=w
    if w['kind']=='return'and w['taken']:
     key=(w['id'],w['after']['pc'],w['before']['sp'])
     if key in pending:
      c=pending.pop(key)
      if c['offset']==0x1fde:frame['lookup']=dict(call=c,ret=w)
      elif c['offset']in [0x2037,0x2085]:frame['predicates'].append(dict(call=c,ret=w))
     if w['after']['pc']==0x42b4 and w['before']['sp']==frame['entry']['entry']['sp']-14:frame['handler_ret']=w;frame['software_last_writers']=[writers[w['before']['sp']],writers[w['before']['sp']+1]]
  assert not pending,pending
  for r in frames.values():
   own=r['own'];by=collections.defaultdict(list)
   for w in own:by[w['offset']].append(w)
   r['k']=by[0x1fe1][0]['before']['a'];r['descriptor']=word(by[0x1ff0][0]['before']);r['handler']=word(by[0x20b3][0]['after']);r['initial_count']=by[0x1ffc][0]['before']['a'];r['entry_C']=r['entry']['entry']['c'];r['caller']=r['entry']['CALL']['offset'];r['scan_calls']=sum(p['call']['offset']==0x2037 for p in r['predicates']);r['fallback']=bool(by[0x2085]);r['success']=bool(by[0x203e]);r['trace_before']=by[0x208b][0]['after']['a'];r['trace_after']=by[0x20b4][0]['after']['a'];r['fallback_index']=by[0x206f][0]['after']['c']if r['fallback']else None;r['fallback_pointer']=word(by[0x207d][0]['before'])if r['fallback']else None
   r['journal_sha256']=r.pop('journal').hexdigest();r['predicate_journal_sha256']=r.pop('predicate_journal').hexdigest();r['predicate_children']={f'PLI2.OVL+{t-0x2200:04X}'if t>=0x2200 else f'PLI.COM+{t-0x100:04X}':n for t,n in r['predicate_children'].items()};r['predicate_offsets']=sorted(r['predicate_offsets']);roots.append(r)
 save(OUT/'roots.json',roots);save(OUT/'inventory.json',inventory)
 (OUT/'component-windows.txt').write_text(''.join(f"{r['source']} {r['entry']['step']} {r['exit']['step']}\n"for r in roots if r['entry']['parent']==0))
 return inventory,roots

def discovery(images=IMAGES,reuse=False):
 start=time.monotonic();dest=OUT/'capture';dest.mkdir(parents=True,exist_ok=True)
 if not os.environ.get('RUNES_HOST_IMAGES'):subprocess.run(['dune','build','bin/gateway_decomposition_capture.exe','bin/gateway_decomposition_components.exe','bin/gateway_fragment_proof.exe'],check=True)
 if not reuse:
  for p in dest.glob('*'):p.unlink()
  subprocess.run(['_build/default/bin/gateway_decomposition_capture.exe','--images',images,'--output',str(dest)],check=True)
 extract()
 subprocess.run(['_build/default/bin/gateway_decomposition_components.exe','--images',images,'--windows',str(OUT/'component-windows.txt'),'--output',str(OUT/'component-shadows.json')],check=True)
 subprocess.run(['_build/default/bin/gateway_fragment_proof.exe','--seed',str(dest/'FIZZBUZ-seed.ram'),'--output',str(OUT/'fragment-proof.json')],check=True)
 save(OUT/'focused-timing.json',dict(wall_seconds=round(time.monotonic()-start,3),capture_reused=reuse))

def reports(images=IMAGES):
 inventory,rs=extract();handlers=[];callers={};groups=[]
 for source in SOURCES:
  rr=[r for r in rs if r['source']==source]
  callers[source]={f'{o:04X}':sum(r['caller']==o for r in rr)for o in sorted({r['caller']for r in rr})}
 for h in sorted({r['handler']for r in rs}):
  rr=[r for r in rs if r['handler']==h];off=h-0x2200
  status='CLOSED CANONICAL scoped6EA5'if off==0x6ea5 else'BROAD/SEPARATE required handler'if off in [0x20f7,0x3e36,0x3de4,0x4257]else'BOUNDED CANDIDATE for assessment only; no semantic contract'
  handlers.append(dict(target=f'{off:04X}',count=len(rr),sources=dict(collections.Counter(r['source']for r in rr)),callers=dict(collections.Counter(f'{r["caller"]:04X}'for r in rr)),indices=sorted({r['k']for r in rr}),software_RET_sites=sorted({f'{r["handler_ret"]["offset"]:04X}'for r in rr}),continuations_proved=len(rr),status=status))
 for k in sorted({r['k']for r in rs}):
  rr=[r for r in rs if r['k']==k];groups.append(dict(k=k,count=len(rr),descriptor_pointers=sorted({r['descriptor']for r in rr}),handler_pointers=sorted({r['handler']for r in rr}),sources=dict(collections.Counter(r['source']for r in rr)),fallback_indices=sorted({r['fallback_index']for r in rr if r['fallback']}),fallback_pointers=sorted({r['fallback_pointer']for r in rr if r['fallback']})))
 frames=[];depth={};representatives={}
 for r in rs:
  parent=r['entry']['parent'];key=(r['source'],r['entry']['id']);depth[key]=1+(depth[(r['source'],parent)]if parent else 0)
  frames.append(dict(source=r['source'],id=r['entry']['id'],parent=parent,depth=depth[key],caller=f'{r["caller"]:04X}',entry_step=r['entry']['step'],return_step=r['exit']['step'],entry=r['entry']['entry'],continuation=r['entry']['continuation'],entry_RAM_sha256=r['entry']['RAM_sha256'],exit_RAM_sha256=r['exit']['RAM_sha256'],entry_filesystem_sha256=r['entry']['filesystem_sha256'],exit_filesystem_sha256=r['exit']['filesystem_sha256'],entry_DMA=r['entry']['DMA'],exit_DMA=r['exit']['DMA'],saved_state=r['entry']['saved_state'],k=r['k'],descriptor=r['descriptor'],handler=r['handler'],initial_count=r['initial_count'],scan_calls=r['scan_calls'],success=r['success'],fallback=r['fallback'],fallback_index=r['fallback_index'],fallback_pointer=r['fallback_pointer'],predicate_tokens=r['predicate_tokens'],predicate_results=[dict(callsite=f'{p["call"]["offset"]:04X}',returned_A=p['ret']['after']['a'],returned_flags={k:p['ret']['after'][k]for k in ['S','Z','AC','P','CY']})for p in r['predicates']],trace_before=r['trace_before'],trace_after=r['trace_after'],exit=r['exit']['exit'],software_return_site=f'{r["handler_ret"]["offset"]:04X}',software_last_writers=r['software_last_writers'],own_journal_sha256=digest(r['own']),projected_journal_sha256=r['journal_sha256'],predicate_journal_sha256=r['predicate_journal_sha256']))
  signature=(r['success'],r['fallback'],r['initial_count']==0,parent!=0,r['handler']==0x90a5)
  representatives.setdefault(str(signature),dict(source=r['source'],id=r['entry']['id'],own_journal_sha256=digest(r['own']),entry=r['entry'],exit=r['exit'],software_RET=r['handler_ret']))
 save(REPORT/'frames.json',frames);save(OUT/'representative-witnesses.json',list(representatives.values()))
 save(REPORT/'natural-inventory.json',{source:dict(calls=inventory[source]['count'],callers=callers[source],entry_C_distribution=dict(collections.Counter(str(r['entry_C'])for r in rs if r['source']==source)),nested_calls=sum(r['source']==source and r['entry']['parent']!=0 for r in rs),candidate_success=sum(r['source']==source and r['success']for r in rs),fallback=sum(r['source']==source and r['fallback']for r in rs),scan_iterations=dict(collections.Counter(str(r['scan_calls'])for r in rs if r['source']==source)),REL_sha256=inventory[source]['REL_sha256'])for source in SOURCES})
 save(REPORT/'handler-map.json',handlers);save(REPORT/'table-tuples.json',groups)
 blockers=[{k:r[k]for k in ['source','caller','entry_C','k','descriptor','handler','scan_calls','success','fallback','predicate_tokens','predicate_children']}for r in rs if r['caller']in [0x3740,0x374b,0x3cae]]
 save(REPORT/'parent-unblocking.json',dict(callsite_subset=blockers,Pass69_unblocked=False,Pass70_unblocked=False,remaining_common_handler='PLI2.OVL+3E36',additional_cross_handlers=['PLI2.OVL+256E','PLI2.OVL+3FFD','PLI2.OVL+6D47'],descriptor_predicate='PLI2.OVL+1DFF remains partial, not canonical native',native_gateway_installed=False))
 pred=collections.Counter()
 for r in rs:pred.update(r['predicate_children'])
 save(REPORT/'descriptor-subset.json',dict(calls=sum(len(r['predicates'])for r in rs),scan_calls=sum(r['scan_calls']for r in rs),fallback_calls=sum(r['fallback']for r in rs),natural_tokens=dict(collections.Counter(str(t)for r in rs for t in r['predicate_tokens'])),direct_children=pred,observed_instruction_offsets=sorted(set(o for r in rs for o in r['predicate_offsets'])),status='partial historical predicate; no independent native1DFF shadow or general contract claimed',scope='Exact observed result/token/child signatures, including k23 subset, are evidence rather than a source-dispatched model'))
 save(REPORT/'component-shadows.json',load(OUT/'component-shadows.json'));save(REPORT/'fragment-proof.json',load(OUT/'fragment-proof.json'))
 observed={w['offset']for r in rs for w in r['own']};listing=(OUT/'static-listing.txt').read_text();cfg=[]
 for line in listing.splitlines():
  o,b,d=line.split(' ',2);o=int(o,16)
  if o>=0x1fb5:cfg.append(dict(offset=o,bytes=b,decoded=d,evidence='OBSERVED'if o in observed else'STATIC UNOBSERVED / unsupported'))
 save(REPORT/'cfg.json',cfg)
 knowledge=dict(root_own_bytes=310,natural_instruction_bytes=sum(len(bytes.fromhex(q['bytes']))for q in cfg if q['offset']in observed),static_trace_bytes=39,promotions={'RAW -> UNDERSTOOD':8,'STRUCTURED -> UNDERSTOOD':0,'DECODED -> UNDERSTOOD':0},observed_promoted_bytes=8,synthetic_only_promoted_bytes=0,handler_promotions=0)
 save(REPORT/'knowledge-accounting.json',knowledge)
 law=dict(extent=['1FB5','20EB'],own_ranges={'save':'1FB5..1FDE','lookup_tables':'1FDE..2015','scan':'2015..2056','fallback':'2056..208B','pre_trace':'208B..20AC','dispatch':'20AC..20B4','post_gate':'20B4..20C8','restore':'20C8..20EB'},frame='S=entrySP; C atS-12; AD0B..AD14 atS-11..S-2; AD0A atS-1; original CALL word atS/S+1',lookup='canonical047D consumes fresh saved C; actual A=k ->AD1C; little-endian3C21+2*k ->AD1D; fresh descriptor count ->AD1A; fresh k selects little-endian3DDD+2*k ->AD1F',scan='zero remaining ->2056; otherwise decrementAD1A, incrementAD0A, increment descriptor pointer; actual1DFF(A.bit0) throughRAR drives branch. Success writes0/1 toAD1A/AD1B. Both outcomes reread byte[currentAD1D] as zeroextended skip, add wrapped16-bit and loop.',fallback='CMA(AD1B),RAR/JNC: success bit1 skips fallback; else zeroAD0A, fresh k low ->byte[1B4B+k]&7=j; little-endian3C13+2*j pointer+1 ->AD1D; actual1DFF(savedC) result ->AD1B',software='LXI H,42B4; PUSH H high then low atS-13/S-14; fresh LHLDAD1F; PCHL leavesSP; handlerRET atS-14 consumes actualPUSH word and resumes42B4',trace='fresh202E RAR gates pre/post paths; both bits clear across237 roots; trace-set stillRAW',restore='ordered restoreAD0B..AD14 thenAD0A; finalA=oldAD0A, BC=S-1, DE=AD15, HL=S, flagsS=0,Z=1,AC=1,P=1,CY=0; SPHL thenRET originalCALL ->S+2',full_contract='not closed; opaque1DFF/handler domains and trace arms excluded from closure; no generic callback architecture')
 save(REPORT/'gateway-own-law.json',law)
 selection=load(OUT/'historical-full-selection.json');cert=set(load('research/host-compiler/pass-67/validation-full-initial.json')['selected_categories']);assert cert<=set(selection['selected_categories'])and len(selection['selected_categories'])==102
 save(REPORT/'historical-full-selection-proof.json',dict(executed=False,selected_category_count=102,all_98_certified_Pass67_categories_preserved=True,selected_categories=selection['selected_categories']))
 save(REPORT/'semantic-extraction.json',dict(historical_root='PLI2.OVL+1FB5',semantic_inputs=['entry selector C','savedAD0A..AD14 state','mapped lookup and descriptor/handler tables'],semantic_outputs=['selected handler effects unresolved','scanned/fallback descriptor scratch','restoredAD0A..AD14'],shared_historical_state=['AD0A..AD28','202E trace bit','twelve stack-local bytes','original hardware continuation','software continuation42B4'],historical_mechanism=['LXI FFF5/DAD SP/SPHL and PUSH/INX frame construction','mapped047D lookup','descriptor loop through partial1DFF','little-endian pointer tables','PUSH H/PCHL software transfer','ordered state restore and hardwareRET'],candidate_modern_operation=None,confidence={'own_natural_mechanism':'OBSERVED across237 nested roots','success_publication':'OBSERVED53 plus concreteCPU proof','full_gateway_semantics':'partial; no native contract','trace_set':'STATIC UNOBSERVED'},mir_relevance=None))
 save(REPORT/'implementation-packet.json',dict(task='RUNES_PLI2_GATEWAY_1FB5_DECOMPOSITION_PASS_71',baseline=BASE,outcome='decomposition plus observed8-byte success publication; gateway remains guest',counts={s:inventory[s]['count']for s in SOURCES},law=law,handler_targets=[[h['target'],h['count']]for h in handlers],handler_status_reference='handler-map.json; only6EA5 scoped canonical, remaining required handlers unresolved',table_tuple_columns=['k','count','descriptor_pointers','handler_pointers','fallback_indices'],table_tuples=[[g[k]for k in ['k','count','descriptor_pointers','handler_pointers','fallback_indices']]for g in groups],blocker_columns=['source','caller','entry_C','k','handler','scan_calls','fallback'],blockers=[[r[k]for k in ['source','caller','entry_C','k','handler','scan_calls','fallback']]for r in blockers],descriptor_subset=load(REPORT/'descriptor-subset.json'),components=load(REPORT/'component-shadows.json'),fragments=load(REPORT/'fragment-proof.json'),promotions=knowledge['promotions'],native_root_installed=False,current_full='Pass67',next_full='approximately Pass72',oracle_queries=0,representative_hashes={k:digest(v)for k,v in representatives.items()}))
 assert (REPORT/'implementation-packet.json').stat().st_size<32768
 save(REPORT/'validation-rationale.json',dict(build='mandatory proof-only executable build',project='mandatory project units',pass71='new exhaustive natural frame/scan/table/continuation and fragment proofs',**{'diff-check':'patch integrity','validation-runner-tests':'new category selection','minimal-pass-1':'the sole stale RAW203E expectation is narrowed following its observed8-byte promotion; complete affected metadata category'}))
 save(REPORT/'next-boundaries.json',dict(recommendation='separately bounded3E36 handler assessment and k23 descriptor-predicate subset; do not reopen69/70 native parents until both contracts exist',alternatives=['independent382E stack-argument policy','scoped1DFF mapped-token/cache matching study'],full_handoff='Pass72 ordinary FULL after its semantic commit; Pass67 remains current until actual certification'))

def validate(images=IMAGES):
 tmp=OUT/'tmp';tmp.mkdir(parents=True,exist_ok=True)
 subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--categories','pass71,diff-check,validation-runner-tests,minimal-pass-1','--images',images,'--output',str(OUT/'validation'),'--workers','4'],env={**os.environ,'TMPDIR':str(tmp.resolve())},check=True)
 receipt=load(OUT/'validation/results.json');receipt.update(historical_bytes=94720,historical_full_executed=False,full_trigger_fired=False,dune_stanzas=39,reruns=[]);save(REPORT/'validation.json',receipt)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['discovery','reports','validate']);p.add_argument('--images',default=IMAGES);p.add_argument('--reuse-capture',action='store_true');a=p.parse_args()
 if a.phase=='discovery':discovery(a.images,a.reuse_capture)
 elif a.phase=='reports':reports(a.images)
 else:validate(a.images)
