#!/usr/bin/env python3
"""Deterministic carrier classification, clear and emission proof."""
import collections,json,sys,subprocess
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_buffered_rel_emission_pass_52 import save,digest
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-59');REPORT=Path('research/host-compiler/pass-59')
BASE='3cd5b72edd2a5bf7456b3370c10f8de6705e16fe'
ENTRIES=[0x7b1b,0x7314,0x7365]
def load(p):return json.loads(Path(p).read_text())
def discovery():
 full={};cfg={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{f'PLI2.OVL+{x:04X}':(x,x+1)for x in ENTRIES},include_nested_returns=True);full[source]=rows
  for k,rs in rows.items():
   cfg.setdefault(k,{})
   for r in rs:
    for w in r['own_witnesses']:cfg[k][w['origin']['offset']]=[w['origin']['offset'],w['bytes'],w['disassembly']]
 save(OUT/'rows.json',full);save(OUT/'cfg.json',{k:sorted(v.values())for k,v in cfg.items()})
 inventory()
def inventory():
 raw=load(OUT/'rows.json');summary={}
 for g in raw.values():
  for rs in g.values():
   for r in rs:r['nested_returns']={int(k):v for k,v in r['nested_returns'].items()}
 for source,g in raw.items():
  summary[source]={k:dict(calls=len(rs),callers=dict(collections.Counter(coord(r['call']['origin'])for r in rs)),pairs=dict(collections.Counter(f"{r['entry']['before']['c']:02X}/{r['entry']['before']['e']:02X}"for r in rs)),returns=dict(collections.Counter(coord(r['ret']['origin'])for r in rs)),children=dict(collections.Counter('/'.join(c['target']for c in children_any(r))for r in rs)))for k,rs in g.items()}
 save(REPORT/'inventory-summary.json',summary);print(json.dumps(summary,indent=2))
def prove(images='/home/john/pli/cpm/pli80/DISK1',focused=False):
 import subprocess,tempfile,shutil
 dest=OUT/'proof';dest.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
  cmd=['dune','exec','bin/native_carrier_clear_emission.exe','--','--toolchain',str(images),'--output-dir',str(Path(tmp)/'results')]
  if focused:cmd+=['--family-only']
  with(dest/'run.log').open('w')as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((dest/'run.log').read_text()[-4000:])
  for f in(Path(tmp)/'results').glob('*.json'):
   if not focused or f.name in ['component-shadows.json','natural-cases.json']:shutil.copyfile(f,dest/f.name)
 print('proof passed')
def topology():
 raw=load('_build/host-compiler-pass-51/residual-map.json');result={}
 inside=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
 for source,v in raw.items():
  ws=v['windows'];coords=['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in[0x7434,0x7630,0x765e,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619,0x7701,0x8248,0x7ae4,0x7b99]]
  prior=v['roots']+[r for r in ws if r['target']in coords];pre=[r for r in prior if not any(q is not r and inside(r,q)for q in prior)]
  parents=[r for r in ws if r['target']=='PLI2.OVL+7B1B'];outer=[r for r in parents if not any(inside(r,q)for q in pre)];absorbed=[r for r in pre if any(inside(r,q)for q in outer)]
  residual={k:dict(calls=len(rs:=[r for r in ws if r['target']==k and r not in outer and not any(q is not r and inside(r,q)for q in pre+outer)]),callers=dict(collections.Counter(r['caller']for r in rs)))for k in['PLI2.OVL+7314','PLI2.OVL+7365','PLI2.OVL+7AE4','PLI2.OVL+7B1B','PLI2.OVL+7B99','PLI.COM+119E']}
  result[source]=dict(logical=len(parents),external=len(outer),callers=dict(collections.Counter(r['caller']for r in parents)),absorbed=dict(collections.Counter(r['target']for r in absorbed)),net_host_delta=len(outer)-len(absorbed),remaining=residual,logical_internal=dict(collections.Counter(r['target']for r in ws if any(inside(r,q)for q in outer))))
 save(REPORT/'topology-summary.json',result)
def contracts():
 raw=load(OUT/'rows.json');laws={
 'PLI2.OVL+7B1B':dict(end=0x7b79,description='Carrier-pair classification, optional index7 clear and component-field emission',contract='Save E atAE0D then C atAE0C. Fresh AE0C SUI A8/SUI1/SBB A yields FF exactly when equalA8,else00;PUSH PSW. Independently freshAE0D SUI7/SUI1/SBB A yields equality7 mask;POP B,MOV C,B transports firstmask;ANA C,RAR converts conjunction intoCY with exact flags/stack residue. Nonconjunction: freshAE0C CPIB8;unless equalB8 literalC7 canonical7397. Special conjunction:canonical79E2 atzeroAE05;E0/C7 canonical7365;RAR,ifCY1 RET7B47;otherwiseE0/C7 canonical7314,JMP7B5F (skip7397). Tail:pairedfreshAE0C/0D,C=L canonical746F;pairedfreshAE0D/0E,C=L canonical74C7;freshAE0D OR freshAE0C,C=A canonical7557;RET. Normalnatural,syntheticB8 skip andspecialearly/construction routes independently scoped. No retainedhost carrier copies;child outputs consumed. Bounded current canonicalchildren;code/stack/sentinel nonalias,201D clear,successfuloutput,nonwrapposition;specialrequiresAE05zero. Special25bytes STATIC UNOBSERVED,notnaturalcoverage.',completeness=['stable','complete','partial']),
 'PLI2.OVL+7314':dict(end=0x7338,description='Indexed carrier-present and value publication',contract='Scope C0..7,Ebyte. Save E atADBC thenC atADBB;publishADAA=1. PUSH H carryingADAA;freshpairedADBB/ADBC,zeroextendL;POP B,INX B toADAB,DAD B;publish1 atADAB+C. IndependentpairedADBB/ADBC zeroextendL,BC=ADB3,DAD;freshLDAADBC thenpublishatADB3+C. ReturnactualDAD CY,preservedNZPA,sourceaddressPUSH residue;nochildren. Exactwidths,orderedwrites/freshreads;boundedindices andnonaliasstack/sentinel.',completeness=['stable','complete','partial']),
 'PLI2.OVL+7365':dict(end=0x7397,description='Gated indexed carrier-value equality mask',contract='ScopeC0..7,Ebyte. SaveE atADC1 thenC atADC0. Fresh202B RAR:ifCY1 literalA0 RET7374 preservingRAR flags. Otherwise pairedADC0/ADC1 zeroextendL,BCADAB,DAD,freshMOV A,M,RAR:ifCY0 literalA0 RET7385 preservingflags. Otherwise independentpairedADC0/ADC1 zeroextendL,BCADB3,DAD,freshLDAADC1,SUBfreshM,SUI1,SBB A =>FF exactlysavedE equalsfreshADB3[C],otherwise00;RET7396 withmaskarithmeticflags. Nochildren;partialbounded index/nonalias scope. Firstgate literalreturn3bytes STATIC UNOBSERVED,synthetically proved;naturalPICTURE12falsecarrier/4comparisoncases.',completeness=['stable','complete','partial'])}
 save(REPORT/'contract-laws-PLI2.OVL.json',laws);save(OUT/'annotation-rows-PLI2.OVL.json',raw)
 b=Path('/home/john/pli/cpm/pli80/DISK1/PLI2.OVL').read_bytes();static={}
 specs={'PLI2.OVL+7B1B':[(0x7b39,3,'CALL 9BE2H'),(0x7b3c,2,'MVI E,00H'),(0x7b3e,2,'MVI C,07H'),(0x7b40,3,'CALL 9565H'),(0x7b43,1,'RAR'),(0x7b44,3,'JNC 9D48H'),(0x7b47,1,'RET'),(0x7b48,2,'MVI E,00H'),(0x7b4a,2,'MVI C,07H'),(0x7b4c,3,'CALL 9514H'),(0x7b4f,3,'JMP 9D5FH')], 'PLI2.OVL+7365':[(0x7372,2,'MVI A,00H'),(0x7374,1,'RET')]}
 for k,rs in specs.items():
  static[k]=[]
  for off,size,d in rs:
   control=dict(kind='call'if d.startswith('CALL')else'jump'if d.startswith(('JNC','JMP'))else'return'if d=='RET'else'ordinary');target=None
   if d.startswith('CALL'):
    runtime=int.from_bytes(b[off+1:off+3],'little');control.update(target=runtime);target=dict(image=dict(name='PLI2.OVL'),offset=runtime-0x2200)
   static[k].append(dict(origin=dict(image=dict(name='PLI2.OVL'),offset=off),target_origin=target,bytes=b[off:off+size].hex().upper(),disassembly=d,control=control,evidence_class='DEDUCED STATIC UNOBSERVED'))
 save(OUT/'annotation-static-PLI2.OVL.json',static);topology()
def cross():
 import tempfile,shutil
 with tempfile.TemporaryDirectory(prefix='factor-',dir=OUT)as t:
  subprocess.run(['_build/default/bin/native_carrier_clear_emission.exe','--toolchain','/home/john/pli/cpm/pli80/DISK1','--output-dir',str(Path(t)/'proof'),'--family-only','--cross-source','FACTOR'],check=True)
  shutil.copyfile(Path(t)/'proof/natural-cases.json',OUT/'factor-natural-cases.json')
 cross_summary()
def cross_summary():
 r=load(OUT/'factor-natural-cases.json')['sources'][0];summary={}
 for e in r['entries']:
  summary[f"PLI2.OVL+{e['offset']:04X}"]=dict(calls=len(e['members']),pairs=dict(collections.Counter(f"{c['input']['c']:02X}/{c['input']['e']:02X}"for c in e['members'])),proof_hash=digest(e['members']),independent_full_state_shadow=True)
 frames={};path=Path('_build/resident-emission-review/rel-invocations.jsonl')
 if path.exists():
  for line in path.open():
   for f in json.loads(line)['caller_frames']:
    if f['target']=='PLI2.OVL+7B1B':frames[f['call_step']]=f
 save(REPORT/'cross-evidence.json',dict(FACTOR=summary,OPTIMIST=dict(historical_emission_ancestor_windows=len(frames),parent_state_available=False,full_state_shadow=False,description='Existing buffered-emission journal has3 distinct7B1B ancestors;noentryABI/C/E orcompletecallinventory inferred. No newtracecampaign.')))
def reports():
 raw=load(OUT/'rows.json');nat=load(OUT/'proof/natural-cases.json');post=load(OUT/'proof/cumulative-hybrid-summary.json');top=load(REPORT/'topology-summary.json');laws=load(REPORT/'contract-laws-PLI2.OVL.json');points={};summaries=[];hierarchy=[]
 for r,h in zip(nat['sources'],post['sources']):
  source=r['source'];g=top[source];assert h['result']['host_transitions']-sum(h['pre_transition_vector'])==g['net_host_delta']
  summaries.append(dict(source=source,entries=[dict(coordinate=f"PLI2.OVL+{e['offset']:04X}",cases=len(e['members']),proof_hash=digest(e['members']))for e in r['entries']]))
  hierarchy.append(dict(source=source,roots=g['external'],absorbed=g['absorbed'],pre_guest=h['pre_guest_instructions'],post_guest=h['result']['actual_guest_instructions'],saved=h['guest_instructions_removed'],pre_host=sum(h['pre_transition_vector']),post_host=h['result']['host_transitions'],net_host_delta=g['net_host_delta'],remaining=g['remaining']))
  points[source]=[]
  for k,rs in raw[source].items():
   for z in rs:
    z['nested_returns']={int(k):v for k,v in z['nested_returns'].items()};own={w['origin']['offset']:w for w in z['own_witnesses']};entry=z['entry']['before'];C,E=entry['c'],entry['e']
    if k.endswith('7B1B'):
     assert C!=0xa8
     m1=255 if C==0xa8 else 0;m2=255 if E==7 else 0
     for site,m in [(0x7b28,m1),(0x7b31,m2)]:assert own[site]['after']['a']==m and own[site]['after']['flags']==dict(sign=m>=128,zero=m==0,parity=True,auxiliary_carry=m==0,carry=m==255)
     psw=0x87 if m1 else 0x56;assert[(w['address'],w['new_value'])for w in own[0x7b29]['writes']]==[(entry['sp']-1,m1),(entry['sp']-2,psw)]
     assert own[0x7b32]['after']['b']==m1 and own[0x7b32]['after']['c']==psw
     assert own[0x7b34]['after']['a']==m1&m2;assert own[0x7b35]['after']['flags']['carry']==bool(m1&m2)
     assert not own[0x7b35]['after']['flags']['carry'];assert own[0x7b5c]['before']['c']==7
     assert own[0x7b63]['before']['c']==C and own[0x7b6a]['before']['c']==E and own[0x7b75]['before']['c']==C|E
     for site,addresses in [(0x7b21,[0xae0c]),(0x7b2a,[0xae0d]),(0x7b52,[0xae0c]),(0x7b5f,[0xae0c,0xae0d]),(0x7b66,[0xae0d,0xae0e]),(0x7b6d,[0xae0d]),(0x7b73,[0xae0c])]:assert[x['address']for x in own[site]['reads']]==addresses
     for site in [0x7b5c,0x7b63,0x7b6a,0x7b75]:
      child=z['nested_returns'][own[site]['step_index']];assert not any(w['address']in[0xae0c,0xae0d,0xae0e]for q in child['memory_witnesses']for w in q['writes'])
    if k.endswith('7314'):
     writes=[(w['address'],w['new_value'])for site in [0x7317,0x7319,0x731d,0x7328,0x7336]for w in own[site]['writes']];assert writes==[(0xadbc,E),(0xadbb,C),(0xadaa,1),(0xadab+C,1),(0xadb3+C,E)]
     assert [w['new_value']for w in own[0x731f]['writes']]==[0xad,0xaa]
    if k.endswith('7365') and 0x7395 in own:
     value=own[0x7392]['reads'][0]['value'];mask=255 if E==value else 0;assert own[0x7395]['after']['a']==mask
    points[source].append(dict(coordinate=k,call=z['call']['step_index'],children=children_any(z),own=list(own.values())))
  save(OUT/('checkpoints-'+source+'.json'),points[source])
 save(REPORT/'shadow-summary.json',dict(all_passed=True,sources=summaries,components=load(OUT/'proof/component-shadows.json'),checkpoints={k:digest(v)for k,v in points.items()},comparison=['registers/flags/SP/PC','orderedwrites/full65536RAM','stacklastwriters','childCALLchronology','DMA/filesystem/record/servicechronology'],natural_special_cases=0,natural_B8_cases=0,synthetic=['A8/E7 early RET','A8/E7 publication and tail with gate0/1','A8/E5 normal','B8/E7 andB8/E5 skip','80/98/B0 normal','cursor127:7','exactPSW high/low','rejectedcode/continuation/stack/sentinel/nonzeroAE05']))
 save(REPORT/'hierarchy-summary.json',dict(sources=hierarchy,suppression='Only exact7B1B windows;no globalserializer/helperinterception.'))
 for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:save(REPORT/name,load(OUT/'proof'/name))
 old=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/manifest.json']));cur=load('research/annotated-assembly/manifest.json');image=lambda x:next(i for i in x['images']if i['name']=='PLI2.OVL');status=lambda im,a:next(q['status']for q in im['sections']if q['start_offset']<=a<q['end_offset']);total=collections.Counter();counts={}
 for k,law in laws.items():
  c=collections.Counter(status(image(old),a)for a in range(int(k.split('+')[1],16),law['end'])if status(image(cur),a)=='UNDERSTOOD'and status(image(old),a)!='UNDERSTOOD');counts[k]=dict(c);total.update(c)
 save(REPORT/'fidelity.json',dict(archaeological_scope_extension=True,promotions=dict(total),by_contract=counts,historical_correction=None,implementation_correction=['Development7314 draft corrected INX B andexact7337RET before firstshadow.','SyntheticearlyRET expectation corrected:maskFF hasCY1,RAR returnsFF,not7F.','Output-only negative fixtures excluded from non-output7314/7365.'],pragmatic_divergence=None,fidelity_debt=None,oracle_queries=0,static_unobserved_bytes={'7B1B_special':25,'7365_first_gate':3},cpu_runner_cpm_changes=False,shared_schema_changes=False))
 boundary=dict(selected='PLI2.OVL+7B1B',extent=[0x7b1b,0x7b79],overlapping_entries='No naturally called overlappingentry withinbody.',special='ExactCALLs79E2/7365/7314;validhelperentries establishedfromnaturalCALLs. ParentA8/E7 remainsSTATIC UNOBSERVED withboundedsyntheticproof;AE05nonzero rejected.',B8='Zero naturalprimaryandFACTOR cases;syntheticboundedskip accepted.',sibling='7B99 preparesselectors andcopiesindexedbanks;7B1B classifiesbytepair,optionallyclearsliteralindex7,andemitsORfield. Sharedrepresentation helpers;differentABI/stateeffect/lifetime,notmerged.',broader='7E05 separateAE36/37,ADAA,202B,7314/multiplefieldpolicy;notabsorbed.',next='Assess7E05 broadercarrier-generationpolicy forPass60.')
 save(REPORT/'boundary-assessment.json',boundary)
 semantic=dict(historical_root='PLI2.OVL+7B1B',semantic_inputs=['primary carrier field C','secondary field E','current carrier flags/values for special policy','buffered output position'],semantic_outputs=['normal nonB8 clearscarrier7','component fields and C OR E byte emitted','special mayreturnearly orpublishcarrier7 beforeemission'],shared_historical_state=['AE0C/AE0D andpairedAE0E channel','ADAA/ADAB/ADB3 indexedstate','ADBB/ADBC,ADC0/ADC1 helperscratch','AE05/202B gates andemissionbuffers/position'],historical_mechanism=['SUI/SUI/SBB equalitymasks','PUSH PSW/POP B/MOV C,B maskcarrier','ANA/RAR carryconversion','literalindex7 clear','pairedfreshreads,individualcanonicalhelpers andexactCALL/PUSH residue'],candidate_modern_operation='Classify carrier fields, apply optional carrier policy and emit components',confidence=dict(normal='OBSERVED primaryandFACTOR',special_and_B8='DEDUCED STATIC UNOBSERVED/synthetic',modern_description='HYPOTHESIS'),mir_relevance='Documentationonly;futurestatefulcarrierpolicy concept,no MIR interface orfaithful-code refactor.')
 save(REPORT/'semantic-extraction.json',semantic);cross_summary()
 cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};prior=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))
 for p in prior['procedures']:
  for source,n in p['observed_paths']['invocations_by_run'].items():assert cat[p['id']]['observed_paths']['invocations_by_run'].get(source,0)>=n
 packet=dict(task='PLI2_CARRIER_CLEAR_EMISSION_7B1B_PASS_59',baseline=BASE,boundary=boundary,laws=laws,inventory=load(REPORT/'inventory-summary.json'),cross=load(REPORT/'cross-evidence.json'),topology=top,proofs=summaries,checkpoint_hashes={k:digest(v)for k,v in points.items()},promotions=dict(total),canonical_children={k:dict(contract_hash=digest(cat[k]),completeness=cat[k]['completeness'])for k in ['PLI2.OVL+7397','PLI2.OVL+746F','PLI2.OVL+74C7','PLI2.OVL+7557','PLI2.OVL+79E2','PLI.COM+119E','PLI.COM+1140']},oracle_queries=0)
 save(REPORT/'implementation-packet.json',packet);size=(REPORT/'implementation-packet.json').stat().st_size;assert size<=28672
 table='\n'.join(f"|{h['source']}|{h['pre_guest']} → {h['post_guest']}|{h['saved']}|{h['pre_host']} → {h['post_host']}|{h['roots']}|"for h in hierarchy)
 (REPORT/'README.md').write_text(f"""# Pass59 — carrier clear and field emission

Baseline `{BASE}` is published Pass58. Previous FULL checkpoint: Pass56. This pass schedules one final FULL checkpoint after semantic completion.

## Scope and evidence

+7B1B has exact hypothesized envelope `[7B1B,7B79)`, RET +7B78. Natural primary counts are 0/10/0, all FIZZBUZ; callers +31E7 ×1, +36FA/+3701/+420C ×3 each. C/E distribution: B0/07 ×1, 80/07 ×3, 98/07 ×3, B0/05 ×3. FACTOR contributes one independently shadowed B0/06 case. An existing OPTIMIST emission journal contains three distinct parent ancestors, without a full parent ABI/proof; no C/E or complete count is inferred from it. Neither primary nor FACTOR cases uses A8 or B8.

## Faithful law

Save E at AE0D, then C at AE0C. Independently fresh C and E reads feed `SUI literal; SUI 1; SBB A`: the masks are FF exactly for equality with A8 and 7 respectively, otherwise zero. First-mask PUSH PSW writes A high then packed flags low below entry SP. POP B transports that mask without restoring flags; MOV C,B, ANA C and RAR produce the conjunction in CY. Natural cases have CY=0 and continue at +7B52.

Fresh saved C is compared with B8. All natural cases call canonical +7397 with literal C=7, clearing ADAB[7]. B8 skips the clear; bounded synthetic cases prove that branch without claiming natural coverage. Tail calls canonical +746F with freshly paired-read C, +74C7 with independently paired-read E, then +7557 with fresh E OR fresh C. Paired E also reads adjacent AE0E. Children do not modify the saved carriers on the natural routes. Entry high halves and flags are actual channels until historical instructions overwrite them.

The special A8/E7 block is 25 bytes of DEDUCED / STATIC / UNOBSERVED evidence. Exact targets are +79E2, +7365 and +7314. Accepted synthetic scope requires AE05=0 for canonical +79E2. +7365 is passed C=7,E=0. Its returned mask undergoes RAR: CY=1 returns early at +7B47; FF with incoming CY=1 remains FF. Otherwise canonical +7314 publishes the carrier and zero value, then enters the tail without +7397. Nonzero AE05 and inherited unsupported states reject staging; no arbitrary pending-generation behavior is invented.

## Required helpers

+7314 `[7314,7338)`: primary natural counts 8/33/9, plus FACTOR 12. Save E/C at ADBC/ADBB, publish ADAA=1, PUSH the ADAA address, fresh C zero extension, POP B and INX B to ADAB, publish ADAB[C]=1. Independently reread C and E and publish ADB3[C]=E. Exact PUSH residue, DAD carry and preserved NZPA are retained.

+7365 `[7365,7397)`: primary counts 0/0/16. Fresh 202B low bit gates a literal-zero return. Otherwise fresh ADAB[C] low bit gates another literal-zero return. The final route compares fresh saved E with fresh ADB3[C] through SUB/SUI/SBB, returning FF for equality and zero otherwise. PICTURE has 12 carrier-clear returns and four comparison returns. The three-byte first-gate return is STATIC / UNOBSERVED and synthetically exercised. Helpers have independent natural full-state shadows and bounded index scope 0..7.

## Proof, hierarchy and leverage

All ten primary roots, the FACTOR root, 50 primary +7314 cases and 16 +7365 cases independently shadow registers, flags, SP/PC, ordered writes, full 64 KiB RAM, stack last writers, child chronology and DMA/filesystem/record/service state. Natural arithmetic/read/write checkpoints remain under ignored `_build/host-compiler-pass-59`. Synthetic A8/E7 early/publication outcomes, A8/E5, B8/E5/E7, record-boundary output and rejected aliases/code/continuation/states pass. No private frame or final RAM copying is introduced.

|Source|Pass58 → Pass59 guest|Removed|Host before → after|Roots|
|---|---:|---:|---:|---:|
{table}

Only exact accepted +7B1B windows absorb lower roots. Standalone/cumulative hybrids preserve exact REL hashes, full REL/INT chronology, filesystem, console, compiler milestones, BDOS order/counts and warm boot. Residual maps and absorption by coordinate are in hierarchy-summary.json. Guest savings come solely from whole-run counters.

Promotions: {dict(total)}. +7B1B 94 bytes includes 25 static special bytes; +7314 36 bytes; +7365 50 bytes includes three static first-gate bytes. Bounds stable, local CFG complete, contracts partial over supported state/index/child/alias scopes. Unsupported error, position-wrap, writer and pending routes fail closed in copied transactions. Existing historical FACTOR/OPTIMIST totals are preserved.

Oracle queries: zero. Exact reconstruction: 94720 bytes. No historical correction, pragmatic divergence or fidelity debt. Development implementation/test corrections are recorded separately in fidelity.json. Semantic extraction documents behavior separately from the historical scratch, mask, PSW, carry and CALL mechanisms; no MIR API or refactor.

Packet: {size} bytes. Driver phases automate inventory, route grouping, valid extents, component/root proofs, checkpoint equations, cross-evidence, hierarchy, hybrids, reports, semantic extraction and full-checkpoint dispatch. Interactive call count is not instrumented. Final validation.json records category/test/stanza/worker counts, timing and any reruns.

+7B99 is a distinct indexed-copy/preparation transaction with different ABI and callers; it remains canonical and separate. +7E05 is not absorbed. Recommended Pass60: assess that broader carrier-generation policy. scripts/view-optimist.sh is untouched.
""")
 save(REPORT/'validation.json',dict(validation_tier='FULL',previous_full_checkpoint='7bd9ca0a11984e7f618293bb2ab4f2c0d4b79314',status='ready for final checkpoint',reruns=[],historical_bytes=94720))
def validate():
 dest=OUT/'full-checkpoint'
 r=subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images','/home/john/pli/cpm/pli80/DISK1','--output',str(dest),'--workers','4'])
 receipt=load(dest/'results.json');v=load(REPORT/'validation.json');v.update(status='passed initially'if receipt['all_passed']else'initial checkpoint failed',initial_all_passed=receipt['all_passed'],all_passed=receipt['all_passed'],category_count=len(receipt['categories']),categories=receipt['categories'],distinct_python_test_count=sum(q['python_tests']for q in receipt['categories'].values()),dune_test_stanza_count=39,workers=4,initial_wall_seconds=receipt['wall_seconds'],summed_category_seconds=receipt['sum_category_seconds'],slowest_categories=receipt['top_10_slowest']);save(REPORT/'validation.json',v);assert r.returncode==0
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['discovery','inventory','topology','contracts','cross','components','prove','reports','validate']);a=p.parse_args()
 if a.phase in ['components','prove']:prove(focused=a.phase=='components')
 else:globals()[a.phase]()
