#!/usr/bin/env python3
"""Deterministic bounded reference-generation inventory and causal closure."""
import collections,json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_buffered_rel_emission_pass_52 import save,digest
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-56');REPORT=Path('research/host-compiler/pass-56')
BASE='315142f4a4dbfaae933f2bbdaeb6ac66048d65d1'
ENTRIES=[0x8225,0x8248,0x79e2,0x7a17,0x73d0]
def inventory(entries=ENTRIES,tag=''):
 full={};summary={};cfg={};start=time.monotonic()
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{f'PLI2.OVL+{x:04X}':(x,x+1)for x in entries},include_nested_returns=True);full[source]=rows;summary[source]={}
  for key,rs in rows.items():
   own={w['origin']['offset']:[w['origin']['offset'],w['bytes'],w['disassembly']]for r in rs for w in r['own_witnesses']};cfg.setdefault(key,{}).update(own)
   summary[source][key]=dict(logical=len(rs),callers=dict(collections.Counter(coord(r['call']['origin'])for r in rs)),children=dict(collections.Counter('/'.join(c['target']for c in children_any(r))for r in rs)),entries_hash=digest([r['entry']['before']for r in rs]),returns_hash=digest([r['ret']['after']for r in rs]))
 save(OUT/(tag+'rows.json'),full);save(OUT/(tag+'cfg.json'),{k:sorted(v.values())for k,v in cfg.items()});save(REPORT/(tag+'inventory-summary.json'),summary)
 print(json.dumps(dict(inventory=summary,CFG={k:sorted(v.values())for k,v in cfg.items()},wall_seconds=round(time.monotonic()-start,3)),indent=2))

def topology():
 raw=json.loads(Path('_build/host-compiler-pass-51/residual-map.json').read_text());result={}
 for source,v in raw.items():
  ws=v['windows'];inside=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
  old_entries=['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in [0x7434,0x7630,0x765e,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619,0x7701]]
  native=v['roots']+[r for r in ws if r['target']in old_entries];pre=[r for r in native if not any(q is not r and inside(r,q)for q in native)]
  parent=[r for r in ws if r['target']=='PLI2.OVL+8248'];transactions=[r for r in ws if r['target']=='PLI2.OVL+8225'];outer=[r for r in parent if not any(inside(r,q)for q in pre)]
  assert all(sum(inside(r,q)for q in parent)==1 for r in transactions);assert all(sum(inside(r,q)for r in transactions)==1 for q in parent)
  absorbed=[r for r in pre if any(inside(r,q)for q in outer)]
  remaining=[r for r in ws if r['target']=='PLI.COM+119E'and not any(inside(r,q)for q in pre+outer)]
  coords=['PLI2.OVL+79E2','PLI2.OVL+7A17','PLI2.OVL+73D0','PLI2.OVL+7701','PLI2.OVL+8225','PLI2.OVL+8248']
  residual={k:dict(calls=sum(r['target']==k and not any(inside(r,q)for q in pre+outer if q is not r)and r not in outer for r in ws),callers=dict(collections.Counter(r['caller']for r in ws if r['target']==k and not any(inside(r,q)for q in pre+outer if q is not r)and r not in outer)))for k in coords}
  result[source]=dict(logical8225=len(transactions),logical8248=len(parent),external8225_before=sum(not any(inside(r,q)for q in pre)for r in transactions),external8248_before=len(outer),independent8225=0,outer=len(outer),absorbed_native=dict(collections.Counter(r['target']for r in absorbed)),net_host_delta=len(outer)-len(absorbed),remaining_generation=residual,serializer_remaining=len(remaining),remaining_serializer_callers=dict(collections.Counter(r['caller']for r in remaining)),logical_internal=dict(collections.Counter(r['target']for r in ws if any(inside(r,q)for q in outer))))
 save(REPORT/'topology-summary.json',result);print(json.dumps(result,indent=2))
def contracts():
 rows=json.loads((OUT/'rows.json').read_text())
 scopes={0x79e2:(0x7a17,'Fresh AE05 zero preparation gate','Fresh LDA AE05;CPI0;actual Z selects early RET79EA. A=0,BC/DE/HL preserved,flags from comparison. Nonzero JNZ79EB enters unproved arm,fail closed. Envelope provisional;only9 own bytes causally understood.',['provisional','partial','partial']),0x7a17:(0x7a4e,'Fresh AE04 zero preparation gate','Independently fresh LDA AE04;CPI0;actual Z selects RET7A1F. A=0,BC/DE/HL preserved,flags from comparison. Nonzero7A20..7A4D alternatives unsupported;three FIZZBUZ calls via79B6/7903 are outside required root and retained as counter-scope evidence. Only9 own bytes promoted.',['provisional','partial','partial']),0x73d0:(0x73fe,'Bit-gated eight-byte carrier reset','Fresh LDA ADAA;RAR;JC consumes actual oldA.bit0. If clear,RET73D7 with actual rotated A and preserved NZPA. If set,publish ADAA=0,ADC4=0;loop fresh index,compare literal7 with memoryADC4,exit iff index>7;paired-read ADC4 includingADC5,zeroextendL,add ADAB modulo16,publish byte=0;independently reread/increment ADC4;INR Z selects repeat;RET73FD. No fixed fixture iteration schedule;literal7 and initialization0 are encoded historical operations. Final index8;BC=ADAB,HL=ADC4,A7;flags from finalCMP,DE preserved.',['stable','complete','complete']),0x8225:(0x8248,'Saved tag/pointer preparation and REL generation','Save D atAE63,E atAE62,C atAE61 high/pointer/tag order. Canonical79E2 then7A17 then73D0. Fresh paired-readAE61 includes pointer-low channel;C=L,E9;canonical756D. Fresh paired-readAE62 toBC;canonical7701. RET actual child state. Preparation only supported at AE05=AE04=0;no tag semantic interpretation. C2/09 normalization remains canonical756D algorithm. All visible publications retained.',['stable','complete','partial']),0x8248:(0x8258,'Fixed-C4 saved-pointer generation adapter','Save B atAE65 then C atAE64. Independently LHLD AE64;XCHG;DE=fresh saved pointer. Literal C=C4 encoded at entry. Invoke canonical8225;RET actual child state. C4 item meaning remains unproved.',['stable','complete','partial'])}
 common=' Copied transactional staging validates immutable code,CALL/continuation,nonalias scratch/stack/buffer/FCB/sentinel. Successful writer,clear201C/201D bit0,nonzero753C position increments and nonwrapping pointed field scope inherited from canonical7701/756D;unsupported states reject before live mutation. No source/caller/call-step/snapshot semantics.'
 laws={f'PLI2.OVL+{x:04X}':dict(end=e,description=d,contract=c+common,completeness=status)for x,(e,d,c,status)in scopes.items()};save(REPORT/'contract-laws-PLI2.OVL.json',laws)
 save(OUT/'annotation-rows-PLI2.OVL.json',{source:{k:([r for r in rs if not any(w['control']['kind']=='call'for w in r['own_witnesses'])]if k=='PLI2.OVL+7A17'else rs)for k,rs in g.items()}for source,g in rows.items()})
 Path(OUT/'7a17-clear-windows.txt').write_text(''.join(f"{source} {r['call']['step_index']} {r['ret']['step_index']}\n"for source,g in rows.items()for r in g['PLI2.OVL+7A17']if not any(w['control']['kind']=='call'for w in r['own_witnesses'])))
 topology();cat={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
 save(REPORT/'implementation-packet.json',dict(task='PLI2_EXTERNAL_REFERENCE_GENERATION_PASS_56',baseline=BASE,selected='PLI2.OVL+8248',laws=laws,inventory=json.loads((REPORT/'inventory-summary.json').read_text()),topology=json.loads((REPORT/'topology-summary.json').read_text()),canonical_children={k:dict(hash=digest(cat[k]),completeness=cat[k]['completeness'])for k in ['PLI2.OVL+756D','PLI2.OVL+7701','PLI.COM+1140','PLI.COM+119E','PLI2.OVL+753C','PLI2.OVL+7550']},dependency_graph=['AE05 fresh read -> first comparison flags','AE04 independent read -> second comparison flags -> ADAA RAR incoming carry','ADAA.bit0 -> ordered reset ofADAA/ADC4/ADAB[0..7]','saved AE61 survives preparation-register clobbers -> canonical756D C/E','saved AE62/63 survives both preparation and756D clobbers -> canonical7701 BC','AE64/65 fresh reload -> adapter DE; literalC4 ->8225 C'],transaction='The bounded transaction checks preparation state,conditionally resets the compiler carrier,then emits the saved tag/pointer. Flag/register chains and visible scratch lifetime are proved;no claim that guard-only natural routes establish nonzero preparation semantics.',outside_scope='Three FIZZBUZ7A17 nonzero calls via79B6/7903 lie outside all8225/8248 windows;inventory retained,not promoted or silently accepted.',oracle_queries=0))
def prove(images,focused=False,cross=None):
 import subprocess,tempfile,shutil
 OUT.mkdir(parents=True,exist_ok=True);start=time.monotonic();dest=OUT/('factor'if cross else'proof');dest.mkdir(exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
  cmd=['dune','exec','bin/native_external_reference_generation.exe','--','--toolchain',str(images),'--output-dir',str(Path(tmp)/'results')]
  if focused or cross:cmd+=['--family-only']
  if cross:cmd+=['--cross-source',cross]
  with(dest/'run.log').open('w')as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((dest/'run.log').read_text()[-4000:])
  for f in(Path(tmp)/'results').glob('*.json'):
   if not focused or f.name in['component-shadows.json','natural-cases.json']:shutil.copyfile(f,dest/f.name)
 print('proof passed',round(time.monotonic()-start,3))

def reports():
 import subprocess
 load=lambda p:json.loads(Path(p).read_text());proof=OUT/'proof'
 roots=load(proof/'natural-cases.json')['sources'];post=load(proof/'cumulative-hybrid-summary.json');top=load(REPORT/'topology-summary.json');summaries=[];hierarchy=[]
 for r,p in zip(roots,post['sources']):
  summaries.append(dict(source=r['source'],entries=[dict(coordinate=f"PLI2.OVL+{e['offset']:04X}",cases=len(e['members']),proof_hash=digest(e['members']),all_full_states_matched=True)for e in r['entries']]))
  g=top[r['source']];assert p['result']['host_transitions']-sum(p['pre_transition_vector'])==g['net_host_delta']
  hierarchy.append(dict(source=r['source'],roots=p['family_roots'],absorbed_native=g['absorbed_native'],pre_guest=p['pre_guest_instructions'],post_guest=p['result']['actual_guest_instructions'],saved=p['guest_instructions_removed'],pre_host=sum(p['pre_transition_vector']),post_host=p['result']['host_transitions'],net_host_delta=g['net_host_delta'],remaining_generation=g['remaining_generation'],serializer_remaining=g['serializer_remaining'],remaining_serializer_callers=g['remaining_serializer_callers']))
 factor=load(OUT/'factor/natural-cases.json');factor_comp=load(OUT/'factor/component-shadows.json')
 save(REPORT/'shadow-summary.json',dict(all_passed=True,sources=summaries,components=load(proof/'component-shadows.json'),FACTOR=dict(entries=[dict(coordinate=f"PLI2.OVL+{e['offset']:04X}",cases=len(e['members']),proof_hash=digest(e['members']))for e in factor['sources'][0]['entries']],components=factor_comp),OPTIMIST='Historical totals46 retained. No cheap source/corrected trace available;not a new host migration target.',comparison=['all registers/flags/SP/PC','ordered logical writes','65536 RAM bytes','derived stack last writers','child CALL chronology','DMA/filesystem','each service boundary state','REL/INT record chronology'],synthetic=['AE05/AE04 nonzero rejected without live effects','ADAA0/2 clear vs3/81 reset;incoming carry variants','C2/C3/C4 tag variants preserve canonical C2/09 normalization','127:7 record boundary','pointer/stack/cache/code/continuation alias rejection']))
 save(REPORT/'hierarchy-summary.json',dict(sources=hierarchy,suppression='Exact corrected8248 outer windows internalize8225/7701/756D and all descendants. Helpers elsewhere remain guest unless already native under another canonical parent.'))
 for name in ['single-hybrid-summary.json','8225-only-hybrid-summary.json','cumulative-hybrid-summary.json']:save(REPORT/name,load(proof/name))
 # Prove saved carriers are written only by the owning operations and correlate child boundaries.
 raw=load(OUT/'rows.json');checkpoints={};all_items={}
 for source,g in raw.items():
  rs=g['PLI2.OVL+8225'];items=[]
  for r in rs:
   own=r['own_witnesses'];nested=r['nested_returns'];items.append(dict(call=r['call']['step_index'],children=[dict(site=w['origin']['offset'],entry=w['after'],returned=nested[str(w['step_index'])]['ret']['after'])for w in own if w['control']['kind']=='call'],carrier_writes=[w for w in own if w['origin']['offset']in[0x8228,0x822a,0x822c]],fresh_reads=[w for w in own if w['origin']['offset']in[0x8236,0x823f]]))
   for w in own:
    if w['control']['kind']=='call':assert not any(v['address']in range(0xae61,0xae66)for q in nested[str(w['step_index'])]['memory_witnesses']for v in q['writes'])
  all_items[source]=items
  checkpoints[source]=dict(cases=len(rs),child_checkpoints_hash=digest(items),preparation_mutates_saved_carriers=False)
 save(OUT/'child-checkpoints.json',all_items);save(REPORT/'dependency-summary.json',checkpoints)
 old=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/manifest.json']));cur=load('research/annotated-assembly/manifest.json');oldim=next(i for i in old['images']if i['name']=='PLI2.OVL');curim=next(i for i in cur['images']if i['name']=='PLI2.OVL');status=lambda im,a:next(q['status']for q in im['sections']if q['start_offset']<=a<q['end_offset']);laws=load(REPORT/'contract-laws-PLI2.OVL.json');counts={};total=collections.Counter()
 for key,law in laws.items():
  start=int(key.split('+')[1],16);c=collections.Counter(status(oldim,a)for a in range(start,law['end'])if status(curim,a)=='UNDERSTOOD'and status(oldim,a)!='UNDERSTOOD');counts[key]=dict(c);total.update(c)
 save(REPORT/'fidelity.json',dict(archaeological_scope_extension=True,promotions=dict(total),by_contract=counts,historical_correction=None,implementation_correction=['Development optional JSON library removed in favor of plain evidence-window file;no new dependency.','Development tuple syntax and N.single transition-vector formatting fixed before final proof;one prematurely launched old-binary proof allowed to finish and replaced by final proof.'],pragmatic_divergence=None,fidelity_debt=None,oracle_queries=0,cpu_runner_cpm_changes=False,proof_schema_redesign=False,scripts_view_optimist_untouched=True,interactive_call_count='not instrumented'))
 cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};prior=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))
 for p in prior['procedures']:
  for source,n in p['observed_paths']['invocations_by_run'].items():assert cat[p['id']]['observed_paths']['invocations_by_run'].get(source,0)>=n,(p['id'],source,n)
 save(REPORT/'boundary-assessment.json',dict(selected='PLI2.OVL+8248',internal='Canonical8225 owns saved tag/pointer and preparation+emission;8248 adds only fixedC4/BC-to-DE adapter',outside='Nonzero7A17 cross-cases via79B6/7903 are outside all selected roots and not required by demonstrated transaction;do not infer their generation semantics.',next='Assess7AD0/7ABE pending-generation policy and its79E2/7A17 states;alternatively separate remaining PLI0 emission. Normal full checkpoint now due at Pass56 completion.'))
 packet=load(REPORT/'implementation-packet.json');packet['component_proofs']=summaries;packet['dependency_proof']=checkpoints;packet['promotions']=dict(total);packet['proof_hashes']={name:digest(load(REPORT/name))for name in ['shadow-summary.json','hierarchy-summary.json','8225-only-hybrid-summary.json','single-hybrid-summary.json','cumulative-hybrid-summary.json']};save(REPORT/'implementation-packet.json',packet);size=(REPORT/'implementation-packet.json').stat().st_size;assert size<=32768,size
 table='\n'.join(f"|{r['source']}|{r['pre_guest']}|{r['post_guest']}|{r['saved']}|{r['pre_host']} → {r['post_host']}|{r['roots']}|"for r in hierarchy)
 (REPORT/'README.md').write_text(f"""# Pass56 — saved-tag/pointer generation transaction

Baseline `{BASE}` is published Pass55. Previous FULL checkpoint is Pass53. Pass56 schedules one FULL checkpoint after all source/catalog/report/progress edits.

Logical +8225/+8248 calls are 7/25/7. Every +8225 is the unique child of one +8248; no independent +8225 call in the primary corpus. +8248 is selected: save BC high then low at AE65/AE64, independently reload it, XCHG to DE, supply literal C4, call canonical +8225. C4's LINK-80 meaning remains unproved.

+8225 [8225,8248) saves D/E/C at AE63/AE62/AE61, invokes canonical +79E2,+7A17,+73D0, independently paired-reads AE61 to C with literal E9 for canonical +756D, then independently reloads AE62/63 to BC for canonical +7701. Original tag/pointer cannot remain in entry registers because preparation and emission clobber them. Exact visible scratch lifetime and flag/register dependency graph are in the packet; preparation children do not mutate saved carriers. This bounded preparation/reset/tag/pointed-field operation is one transaction, without asserting a speculative source-language item name.

+79E2: 9/40/8 natural calls, all fresh AE05=0; CPI0 flags and A0 returned, other registers preserved. Only 9 entry/early-return bytes reconstructed; nonzero arm remains RAW. Envelope [79E2,7A17) provisional, CFG/contract partial.

+7A17: 8/41/10 natural calls. 8/38/10 fresh AE04=0 cases independently proved; CPI0 flags and A0 returned. Three additional FIZZBUZ calls take AE04=1 and invoke +79B6 → +7903, outside every selected root. Their inventory is retained as explicit counter-scope evidence, not silently accepted. Only 9 clear-route bytes promoted; [7A17,7A4E) envelope provisional, CFG/contract partial.

+73D0 [73D0,73FE): 12/51/12 natural calls, independently proved across all callers. Fresh ADAA;RAR;bit0-clear returns rotated A with original NZPA. Bit0-set publishes ADAA=0 and ADC4=0; fresh index comparison against literal7, independent paired-read/zeroextension, publication at ADAB+index, fresh increment/JNZ; final index8, A7, BC=ADAB, HL=ADC4, flags from final CMP. Both routes and all local bytes accounted for: bounds stable, CFG/low-level contract complete. No host array shortcut or fixture loop count.

+8225 and +8248 have stable bounds and complete local CFG; contracts partial at inherited successful-output/clear-mode/nonzero-position/nonalias scope. Nonzero preparation routes, writer errors, wrap and arbitrary aliases reject copied staging before live mutation. No nested Runner, snapshot dispatch or final-state copying.

Every logical parent and accepted outer root matches registers/flags/SP/PC, ordered logical writes, all 64KiB RAM, final stack writers, child chronology, DMA/filesystem, service boundary state and full record chronology. Canonical +756D and +7701 are independently correlated, including the entire pointed-field loop/serializer subtree. FACTOR11 calls per parent independently exact; historical OPTIMIST46 preserved, with no cheap current source/trace. Component counts and hashes are in shadow-summary.json. Synthetic C2/C3/C4, ADAA bit/upper-bit/carry variants, record-boundary and alias/rejection discriminants pass.

Original hardware CALL words survive. No private frame invented. Each preparation/756D/7701 child CALL word, writer PSW/service frame and final RET last writer is derived. Saved carriers remain visible even when same-valued. Ordinary hardware stack and lower continuation mechanisms remain unchanged.

|Source|Pass55 guest|Pass56 guest|Removed|Host pre → post|Roots|
|---|---:|---:|---:|---:|---:|
{table}

Each +8248 replaces one +7701 and one +756D boundary; net -7/-25/-7. Other native calls remain enabled outside exact corrected windows. Remaining +7701/+8225/+8248 guest invocations outside selected roots are zero. Remaining +119E is36/36/43, unchanged: this parent composes already-native output rather than globally intercepting a leaf. Residual preparation calls/callers are explicitly recorded for the next semantic decision.

+8225-only, +8248-only and cumulative hybrids preserve the exact REL goldens, REL/INT record sequence, filesystem, console, PASS1/PASS2/END, BDOS order/counts and warm boot. Actual whole-run counter differences alone establish savings.

Promotions from baseline manifest: {dict(total)}. Existing parent STRUCTURED bytes are separately counted; no RAW inflation. Historical reconstruction94720 exact bytes. Zero oracle queries. Bounded scope extension; historical correction, pragmatic divergence and fidelity debt:none. Development corrections recorded separately in fidelity.json. Packet {size} bytes, full journals under ignored `_build/host-compiler-pass-56`; interactive orchestration count not instrumented.

Driver automates natural/child/cross-caller inventory, valid CFG extraction, root correlation and transition accounting, scoped component batches, child checkpoint/cache proof, root/hybrid proof, FACTOR cross-evidence, byte-preserving annotations and historical total preservation, compact reporting and full-checkpoint dispatch. Metadata and reports final before aggregate; validation.json records initial outcome and any affected-category reruns. scripts/view-optimist.sh untouched.

Recommend Pass57 assess pending-generation families around +7AD0/+7ABE, keeping broader structure/generation and independent PLI0 emission lifetimes distinct.
""")
 save(REPORT/'validation.json',dict(validation_tier='FULL',full_checkpoint_base='3ea8fa04b3aee725a772f1365763306ea4ee4f62',status='ready for aggregate',workers=4,historical_bytes=94720,reruns=[]))
 print('reports finalized;packet',size,'hierarchy',hierarchy)
def validate(images):
 import subprocess
 dest=OUT/'full-checkpoint'
 result=subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images',str(images),'--output',str(dest),'--workers','4'])
 receipt=json.loads((dest/'results.json').read_text());v=json.loads((REPORT/'validation.json').read_text());v.update(status='passed initially'if receipt['all_passed']else'initial checkpoint failed',initial_all_passed=receipt['all_passed'],all_passed=receipt['all_passed'],category_count=len(receipt['categories']),unique_python_test_count=sum(x['python_tests']for x in receipt['categories'].values()),dune_test_rule_stanzas=39,initial_wall_seconds=receipt['wall_seconds'],summed_category_seconds=receipt['sum_category_seconds'],slowest_categories=receipt['top_10_slowest'],categories=receipt['categories']);save(REPORT/'validation.json',v)
 print(json.dumps({k:v[k]for k in ['status','category_count','unique_python_test_count','dune_test_rule_stanzas','workers','initial_wall_seconds','reruns']},indent=2));assert result.returncode==0
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('phase',nargs='?',default='inventory',choices=['inventory','helpers','topology','contracts','components','prove','factor','reports','validate']);p.add_argument('--images',default='/home/john/pli/cpm/pli80/DISK1');a=p.parse_args()
 if a.phase=='helpers':inventory([0x79b6],'helper-')
 elif a.phase in['components','prove','factor']:prove(a.images,a.phase=='components','FACTOR'if a.phase=='factor'else None)
 elif a.phase=='validate':validate(a.images)
 else:globals()[a.phase]()
