#!/usr/bin/env python3
"""Deterministic indexed-carrier transfer discovery and proof."""
import collections,json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_buffered_rel_emission_pass_52 import save,digest
from check_acquisition_reentry_pass_38 import CAPTURES,coord
from check_selector02_pass_40 import gather_selected,children_any
OUT=Path('_build/host-compiler-pass-58');REPORT=Path('research/host-compiler/pass-58')
BASE='2c9bd0a2afa951080eaf57e2f73b797a1e0b1e13'
def discovery():
 full={};cfg={};summary={}
 for source,path in CAPTURES.items():
  rows=gather_selected(path,{f'PLI2.OVL+{x:04X}':(x,x+1)for x in [0x7b99,0x793c,0x7b1b]},include_nested_returns=True);full[source]=rows;summary[source]={}
  for k,rs in rows.items():
   own={w['origin']['offset']:[w['origin']['offset'],w['bytes'],w['disassembly']]for r in rs for w in r['own_witnesses']};cfg.setdefault(k,{}).update(own)
   summary[source][k]=dict(calls=len(rs),callers=dict(collections.Counter(coord(r['call']['origin'])for r in rs)),pairs=dict(collections.Counter(f"{r['entry']['before']['c']}/{r['entry']['before']['e']}"for r in rs)),children=dict(collections.Counter('/'.join(c['target']for c in children_any(r))for r in rs)))
 save(OUT/'rows.json',full);save(OUT/'cfg.json',{k:sorted(v.values())for k,v in cfg.items()});save(REPORT/'inventory-summary.json',summary)
 print(json.dumps(dict(inventory=summary,cfg={k:sorted(v.values())for k,v in cfg.items()}),indent=2))
def prove(images='/home/john/pli/cpm/pli80/DISK1',focused=False):
 import subprocess,tempfile,shutil
 dest=OUT/'proof';dest.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='proof-',dir=OUT)as tmp:
  cmd=['dune','exec','bin/native_indexed_carrier_transfer.exe','--','--toolchain',str(images),'--output-dir',str(Path(tmp)/'results')]
  if focused:cmd+=['--family-only']
  with(dest/'run.log').open('w')as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((dest/'run.log').read_text()[-4000:])
  for f in(Path(tmp)/'results').glob('*.json'):
   if not focused or f.name in ['component-shadows.json','natural-cases.json']:shutil.copyfile(f,dest/f.name)
 print('proof passed')
def topology():
 raw=json.loads(Path('_build/host-compiler-pass-51/residual-map.json').read_text());result={}
 inside=lambda r,q:q['call']<r['call']<r['ret']<=q['ret']
 for source,v in raw.items():
  ws=v['windows'];prior=v['roots']+[r for r in ws if r['target']in['PLI.COM+1272','PLI.COM+11C3','PLI.COM+11E5','PLI.COM+1207']+[f'PLI2.OVL+{x:04X}'for x in[0x7434,0x7630,0x765e,0x7557,0x756d,0x75a7,0x75ce,0x75f1,0x7619,0x7701,0x8248,0x7ae4]]]
  pre=[r for r in prior if not any(q is not r and inside(r,q)for q in prior)]
  parents=[r for r in ws if r['target']=='PLI2.OVL+7B99'];outer=[r for r in parents if not any(inside(r,q)for q in pre)]
  absorbed=[r for r in pre if any(inside(r,q)for q in outer)]
  residual={k:dict(calls=len(rs:=[r for r in ws if r['target']==k and r not in outer and not any(q is not r and inside(r,q)for q in pre+outer)]),callers=dict(collections.Counter(r['caller']for r in rs)))for k in['PLI2.OVL+79E2','PLI2.OVL+7A17','PLI2.OVL+73D0','PLI2.OVL+7AE4','PLI2.OVL+7B99','PLI2.OVL+793C','PLI.COM+119E']}
  result[source]=dict(logical=len(parents),external=len(outer),callers=dict(collections.Counter(r['caller']for r in parents)),absorbed=dict(collections.Counter(r['target']for r in absorbed)),net_host_delta=len(outer)-len(absorbed),remaining=residual,logical_internal=dict(collections.Counter(r['target']for r in ws if any(inside(r,q)for q in outer))))
 save(REPORT/'topology-summary.json',result);print(json.dumps(result,indent=2))
def contracts():
 raw=json.loads((OUT/'rows.json').read_text());laws={
 'PLI2.OVL+793C':dict(end=0x79a2,description='Indexed two-carrier transfer and derived byte emission',contract='Save E atAE03 then C atAE02. FreshAE03 CPI6. Equal6:pairedAE02,zeroextendL,ADAB+index,publish0. Otherwise:pairedAE03 zeroextend,ADAB+source,PUSH H;independentAE02 zeroextend,destination;POP D;freshLDAX D thenMOV M,A. BOTH routes join796B:repeat address-carrier PUSH/POP sequence withADB3 andpublish freshsource byte. C40 canonical746F;freshAE02 intoC canonical74C7;freshAE03 intoC canonical74C7;freshAE02 ADD A three times,ORI40,ORA freshAE03;C=A,canonical7557. ADD arithmetic flags,notRLC. Encodedbyte=u8(C*8)OR40ORE for scopedindices0..7. Same-index writes retained. Successful children,nonwrap position,clear201D/nonalias immutablecode/stack/sentinel scope;copied transaction rejects unsupported routes before live mutation.',completeness=['stable','complete','partial']),
 'PLI2.OVL+7B99':dict(end=0x7bb2,description='Saved selector/index preparation and carrier-transfer transaction',contract='Save lowE atAE11 then lowC atAE10. Fresh pairedAE10/AE11 toC;canonical7AE4. Independently reread AE10/AE11 toC,thenAE11/AE12 toHL;XCHG intoDE;canonical793C. No invisible retained entry locals replace reads. D/high word from freshAE12 is an actual channel although793C savesonly lowE. Return actual child state;originalCALL andallchild PUSH/CALL residue preserved. Scope C/E indices0..7,inherited bounded7AE4/emission states;copiedstaging validatescomplete route beforelive mutation.',completeness=['stable','complete','partial'])}
 save(REPORT/'contract-laws-PLI2.OVL.json',laws);save(OUT/'annotation-rows-PLI2.OVL.json',{source:{k:g[k]for k in laws}for source,g in raw.items()})
 b=Path('/home/john/pli/cpm/pli80/DISK1/PLI2.OVL').read_bytes();static=[]
 for off,size,d in [(0x794a,3,'LHLD AE02H'),(0x794d,2,'MVI H,00H'),(0x794f,3,'LXI B,ADABH'),(0x7952,1,'DAD B'),(0x7953,2,'MVI M,00H'),(0x7955,3,'JMP 9B6BH')]:static.append(dict(origin=dict(image=dict(name='PLI2.OVL'),offset=off),bytes=b[off:off+size].hex().upper(),disassembly=d,control=dict(kind='jump'if off==0x7955 else'ordinary'),evidence_class='DEDUCED STATIC UNOBSERVED'))
 save(OUT/'annotation-static-PLI2.OVL.json',{'PLI2.OVL+793C':static});topology()
def reports():
 import subprocess
 load=lambda p:json.loads(Path(p).read_text());raw=load(OUT/'rows.json');laws=load(REPORT/'contract-laws-PLI2.OVL.json');proof=OUT/'proof';nat=load(proof/'natural-cases.json');post=load(proof/'cumulative-hybrid-summary.json');top=load(REPORT/'topology-summary.json');shadows=[];hierarchy=[];checkpoint_hashes={}
 for r,h in zip(nat['sources'],post['sources']):
  source=r['source'];g=top[source];assert h['result']['host_transitions']-sum(h['pre_transition_vector'])==g['net_host_delta'];shadows.append(dict(source=source,entries=[dict(coordinate=f"PLI2.OVL+{e['offset']:04X}",cases=len(e['members']),proof_hash=digest(e['members']))for e in r['entries']]))
  hierarchy.append(dict(source=source,roots=g['external'],absorbed=g['absorbed'],pre_guest=h['pre_guest_instructions'],post_guest=h['result']['actual_guest_instructions'],saved=h['guest_instructions_removed'],pre_host=sum(h['pre_transition_vector']),post_host=h['result']['host_transitions'],net_host_delta=g['net_host_delta'],remaining=g['remaining']))
  points=[]
  for k in laws:
   for z in raw[source][k]:
    z['nested_returns']={int(k):v for k,v in z['nested_returns'].items()};own=z['own_witnesses']
    if k.endswith('7B99'):
     # Every carrier write in preparation is retained; prove saved root carrier noninterference.
     w=next(w for w in own if w['origin']['offset']==0x7ba3);n=z['nested_returns'][w['step_index']];assert not any(q['address']in[0xae10,0xae11,0xae12]for w in n['memory_witnesses']for q in w['writes'])
    else:
     # ADD A independently produces every flag; ORI/ORA clear CY and AC.
     for w in own:
      if w['origin']['offset']in[0x7994,0x7995,0x7996]:
       old=w['before']['a'];v=(old*2)&255;assert w['after']['a']==v;assert w['after']['flags']==dict(sign=v>=128,zero=v==0,parity=v.bit_count()%2==0,auxiliary_carry=(old&15)*2>15,carry=old*2>255)
     final=next(w for w in own if w['origin']['offset']==0x799d);assert final['after']['c']==((z['entry']['before']['c']<<3)&255)|0x40|z['entry']['before']['e']
    points.append(dict(coordinate=k,call=z['call']['step_index'],children=children_any(z),local_memory=[dict(site=w['origin']['offset'],before=w['before'],after=w['after'],reads=w['reads'],writes=w['writes'])for w in own if w['reads']or w['writes']],stack_pushes=[w for w in own if w['disassembly']=='PUSH H']))
  save(OUT/('checkpoints-'+source+'.json'),points);checkpoint_hashes[source]=digest(points)
 save(REPORT/'shadow-summary.json',dict(all_passed=True,sources=shadows,components=load(proof/'component-shadows.json'),checkpoint_hashes=checkpoint_hashes,comparison=['allregs/flags/SP/PC','orderedlogicalwrites','65536 RAMbytes','derivedstacklastwriters','childCALLchronology','DMA/filesystem','record/servicechronology'],synthetic=['E6 clearsADAB destination butcopiesADB3 source','non6 two freshcopies','same-index publications retained','index0/1/4/5/6/7','cursor127:7','index8/sentinel/stack/code/continuation rejection'],natural_E6_cases=0))
 save(REPORT/'hierarchy-summary.json',dict(sources=hierarchy,suppression='Exact corrected7B99 windows internalize7AE4 and793C plus outputchildren;identical operationselsewhere remainenabled.'))
 for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:save(REPORT/name,load(proof/name))
 old=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/manifest.json']));cur=load('research/annotated-assembly/manifest.json');image=lambda x:next(i for i in x['images']if i['name']=='PLI2.OVL');status=lambda im,a:next(q['status']for q in im['sections']if q['start_offset']<=a<q['end_offset']);counts={};total=collections.Counter()
 for k,law in laws.items():
  c=collections.Counter(status(image(old),a)for a in range(int(k.split('+')[1],16),law['end'])if status(image(cur),a)=='UNDERSTOOD'and status(image(old),a)!='UNDERSTOOD');counts[k]=dict(c);total.update(c)
 save(REPORT/'fidelity.json',dict(archaeological_scope_extension=True,promotions=dict(total),by_contract=counts,historical_correction=None,implementation_correction=['Annotation generator ORI comment rule added;static witness class spelling corrected before final rendering/verification.'],hypothesis_resolution=['Actual opcode87 isADD A,notRLC.','E6 JMP796B enters commonsecondcarrier copy,not emission.'],pragmatic_divergence=None,fidelity_debt=None,oracle_queries=0,scripts_view_optimist_untouched=True))
 boundary=dict(selected='PLI2.OVL+7B99',extent=[0x7b99,0x7bb2],child_extent=[0x793c,0x79a2],overlapping_entries='No naturally called overlappingentry in eitherbody.',sibling='7B1B has C=80/98/B0 andsmallE,clear7397 plus differentpackedfield;distinctinput/transfer operation,notmerged.',broader='7E05 remains separate AE36/37,ADAA/202B policy and7314transform;notpartofPass58.',next='Assess7B1B compact carrier-clear/emission sibling before broader7E05 generation.')
 save(REPORT/'boundary-assessment.json',boundary)
 semantic=dict(historical_root='PLI2.OVL+7B99',semantic_inputs=['destination indexC','source indexE orspecialvalue6','two carrier bytebanks','fresh pending-preparation state','current bufferedoutputposition'],semantic_outputs=['ADAB destination clearedwhenE6,otherwisecopied','ADB3 destination copiedonbothbranches','derivedrepresentation byte emitted andpositionpublished'],shared_historical_state=['AE10/AE11 savedC/E;pairedAE12 channel','AE02/AE03 indices','ADAB/ADB3 banks andpendingAE04/05/06','emissioncaches,1C2C,RELbuffer/cursor'],historical_mechanism=['absolute scratch carriers andfreshpairedLHLD','MVI H0 zeroextension thenDAD','PUSH H/POP D temporarysourceaddress','ADD A three times thenORI40/ORA savedE','exact CALL/service/PUSH stackresidue'],candidate_modern_operation='Prepare, transfer indexed carriers and emit a derived byte',confidence=dict(semantic_inputs='OBSERVED with0..7 boundedindexscope',semantic_outputs='OBSERVED non6;DEDUCED/static/synthetic E6',shared_historical_state='OBSERVED',historical_mechanism='OBSERVED/DEDUCED',candidate_modern_operation='HYPOTHESIS descriptive'),mir_relevance='Documents future stateful transfer/emission concepts only;no MIR API orfaithful-code refactor.')
 save(REPORT/'semantic-extraction.json',semantic)
 cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};prior=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))
 for p in prior['procedures']:
  for source,n in p['observed_paths']['invocations_by_run'].items():assert cat[p['id']]['observed_paths']['invocations_by_run'].get(source,0)>=n
 packet=dict(task='PLI2_INDEXED_CARRIER_TRANSFER_7B99_PASS_58',baseline=BASE,selected=boundary,laws=laws,inventory=load(REPORT/'inventory-summary.json'),topology=top,proofs=shadows,checkpoints=checkpoint_hashes,promotions=dict(total),canonical_children={k:dict(hash=digest(cat[k]),completeness=cat[k]['completeness'])for k in['PLI2.OVL+7AE4','PLI2.OVL+746F','PLI2.OVL+74C7','PLI2.OVL+7557','PLI2.OVL+753C','PLI.COM+119E','PLI.COM+1140']},E6='Zero natural cases. Exact14bytes staticallydecoded;synthetic destinationclear pluscommonsecondcopy equationandPUSHchronology proved. No globalcapacityclaim.',oracle_queries=0)
 save(REPORT/'implementation-packet.json',packet);size=(REPORT/'implementation-packet.json').stat().st_size;assert size<=28672
 table='\n'.join(f"|{h['source']}|{h['pre_guest']}|{h['post_guest']}|{h['saved']}|{h['pre_host']} → {h['post_host']}|{h['roots']}|"for h in hierarchy)
 (REPORT/'README.md').write_text(f"""# Pass58 — indexed carrier transfer and emission

Baseline: `{BASE}` (published Pass57). The current FULL checkpoint remains Pass56. This pass uses incremental validation.

Actual CALL/RET ownership establishes +7B99 `[7B99,7BB2)` (25 bytes) and +793C `[793C,79A2)` (102 bytes). No naturally called overlapping entry was found. Both have natural counts MINIMAL/FIZZBUZ/PICTURE = 0/10/0. FIZZBUZ root callers are +3AE8 ×1, +36F3 ×3, +3708 ×3 and +4205 ×3. All ten +793C calls originate at +7BAE. C/E pairs are 7/4 ×4, 5/7 ×3 and 4/7 ×3. There are no natural E=6 cases.

+7B99 saves low E at AE11, then low C at AE10. It freshly reads AE10/AE11 and passes L as C to canonical +7AE4. Preparation does not modify AE10/AE11/AE12 on these natural routes. Independent fresh reads then restore C from AE10 and DE from AE11/AE12 before canonical +793C. D comes from fresh AE12, rather than entry D; +793C consumes low E. All shared carrier writes remain visible.

+793C saves E at AE03, then C at AE02, and compares fresh AE03 with 6. The non6 route copies ADAB[E] to ADAB[C]. The E=6 route clears ADAB[C] and jumps to the common second transfer. Both routes copy ADB3[E] to ADB3[C]. Source addresses are formed from fresh paired reads and zero extension, pushed through the hardware stack, and recovered into DE; destination addresses and source bytes are independently acquired. Same-index writes remain observable. Supported indices 0..7 are an explicit bounded scope, not a claim about global table capacity.

Emission calls canonical +746F with C=40H, +74C7 with freshly reread saved C, +74C7 with freshly reread saved E, and +7557 with the derived field. Actual opcode 87 is ADD A: three additions, ORI 40H and ORA fresh AE03 yield `u8(C*8) OR 40H OR E`. Intermediate arithmetic flags are independently checked; the logical operations clear carry. No speculative REL item name is assigned.

The 14-byte E=6 block is DEDUCED / STATIC / UNOBSERVED from exact instructions, with synthetic destination-clear, common second-copy and source-address PUSH equations. Synthetic cases also cover self-copies, indices 0/1/4/5/6/7, cursor 127:7, and unsupported index/sentinel/stack/code/continuation rejection. All ten natural +793C components and +7B99 roots independently shadow registers, flags, SP/PC, ordered writes, full 64 KiB RAM, stack last writers, child/service/record chronology, DMA and filesystem. Checkpoint journals and hashes preserve the internal stages under ignored `_build/host-compiler-pass-58`.

No private frame is invented. Historical PUSH/POP carriers, child CALL words, service frames and the original RET derive surviving stack bytes. Both bounds are stable and local control flow is complete; contracts remain partial. Out-of-range indices, unsupported pending states, writer errors, position wrap, modes and aliases reject copied staging before live mutation. Canonical +7AE4 and emission children are reused internally without nested Runner transitions.

| Source | Pass57 guest | Pass58 guest | Removed | Host before → after | Roots |
|---|---:|---:|---:|---:|---:|
{table}

FIZZBUZ absorbs ten +7AE4 and ten +7557 roots, replacing them with ten +7B99 roots. Equivalent calls outside exact root windows remain enabled. Remaining external +119E counts are 36/36/43; remaining +7AE4 calls are 2/11/1, all under the separate +7E05 caller context. Standalone and cumulative hybrids preserve the exact REL goldens, REL/INT record chronology, filesystem, console, compiler markers, BDOS chronology/counts and warm boot.

RAW → UNDERSTOOD: +793C 102 bytes (including the 14 static/synthetic bytes), +7B99 25 bytes; total 127. DECODED/STRUCTURED promotions: zero. Historical reconstruction remains exactly 94720 bytes. Oracle queries: zero. Historical correction, pragmatic divergence and fidelity debt: none. The ADD and E=6 findings resolve supplied hypotheses, rather than correcting established contracts. Annotation development repairs are recorded in fidelity.json. Existing FACTOR/OPTIMIST historical totals are preserved; no additional natural coverage is claimed.

The packet is {size} bytes. The deterministic driver handles inventory, route grouping, ownership, child checkpoints, component/root proofs, hybrids, hierarchy, residual maps, compact reports, semantic extraction and incremental validation. Interactive call count is not instrumented. The final validation receipt records category counts, test counts and timing.

semantic-extraction.json separates proved indexed-transfer/emission behavior from scratch addresses, paired reads, zero-extension, PUSH/POP carriers, field arithmetic and exact stack residue. It introduces no MIR API or faithful-code refactor.

+7B1B has a distinct input ABI and clear/emission operation and is deferred. +7E05 remains a broader generation family. Recommended Pass59 boundary: assess +7B1B before widening into +7E05. scripts/view-optimist.sh is untouched.
""")
 save(REPORT/'validation.json',dict(validation_tier='INCREMENTAL',full_checkpoint_base='7bd9ca0a11984e7f618293bb2ab4f2c0d4b79314',status='ready for aggregate',reruns=[],historical_bytes=94720));print('packet',size)
def validate():
 import subprocess
 dest=OUT/'incremental-validation';categories='pass58,pass57,pass56,pass54,pass53,pass52,pass24,packet-continuation,V1,roundtrip,roundtrip-tests,dynamic-progress,diff-check'
 r=subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images','/home/john/pli/cpm/pli80/DISK1','--output',str(dest),'--workers','4','--categories',categories]);receipt=json.loads((dest/'results.json').read_text());v=json.loads((REPORT/'validation.json').read_text());v.update(status='passed initially'if receipt['all_passed']else'initial validation failed',initial_all_passed=receipt['all_passed'],all_passed=receipt['all_passed'],categories=receipt['categories'],category_count=len(receipt['categories']),python_test_count=sum(q['python_tests']for q in receipt['categories'].values()),dune_test_rule_stanzas=39,workers=4,wall_seconds=receipt['wall_seconds'],summed_category_seconds=receipt['sum_category_seconds']);save(REPORT/'validation.json',v);assert r.returncode==0
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['discovery','topology','contracts','components','prove','reports','validate']);a=p.parse_args()
 if a.phase in ['components','prove']:prove(focused=a.phase=='components')
 else:globals()[a.phase]()
