#!/usr/bin/env python3
"""Scoped whole-gateway proof; generic dispatch and FULL epochs are untouched."""
import argparse, collections, hashlib, json, os, subprocess, time
from pathlib import Path
import run_gateway_decomposition_pass_71 as g
BASE='b453ca783051b1f969646791001781cf785e4bde'
OUT=Path('_build/host-compiler-pass-73');REPORT=Path('research/host-compiler/pass-73')
IMAGES='/home/john/pli/cpm/pli80/DISK1'
load=g.load;save=g.save;digest=g.digest

def extract():
 g.OUT=OUT
 inventory,roots=g.extract();rs=[r for r in roots if r['k']==23]
 assert len(roots)==237 and len(rs)==28
 assert all(r['descriptor']==0x57c6 and r['handler']==0x6036 and r['initial_count']==2 for r in rs)
 assert all(r['entry']['parent'] and not r['original_slot_writes']and not r['descendant_original_slot_writes']for r in rs)
 (OUT/'k23-windows.txt').write_text(''.join(f"{r['source']} {r['entry']['step']-1} {r['exit']['step']+1}\n"for r in rs))
 return inventory,roots,rs

def prove(images=IMAGES):
 start=time.monotonic();OUT.mkdir(parents=True,exist_ok=True);(OUT/'capture').mkdir(exist_ok=True)
 if not os.environ.get('RUNES_HOST_IMAGES'):subprocess.run(['dune','build','bin/k23_handler_capture.exe','bin/k23_gateway_proof.exe'],check=True)
 subprocess.run(['_build/default/bin/k23_handler_capture.exe','--images',str(images),'--output',str(OUT/'capture')],check=True)
 extract()
 subprocess.run(['_build/default/bin/k23_gateway_proof.exe','--images',str(images),'--windows',str(OUT/'k23-windows.txt'),'--output',str(OUT/'components.json')],check=True)
 save(OUT/'focused-proof-timing.json',dict(wall_seconds=round(time.monotonic()-start,3),all_passed=True))

def reports():
 inventory,roots,rs=extract();REPORT.mkdir(parents=True,exist_ok=True)
 prior=load('research/host-compiler/pass-71/frames.json');depth={(r['source'],r['id']):r['depth']for r in prior}
 rows=[]
 for r in rs:
  e=r['entry'];s=e['entry']['sp'];x=r['exit']['exit']
  assert x['a']==e['saved_state'][0]and x['b']*256+x['c']==s-1 and x['d']*256+x['e']==0xad15 and x['h']*256+x['l']==s and x['sp']==s+2
  assert {k:x[k]for k in ['S','Z','AC','P','CY']}==dict(S=False,Z=True,AC=True,P=True,CY=False)
  rows.append(dict(source=r['source'],id=e['id'],parent=e['parent'],depth=depth[(r['source'],e['id'])],caller=f"PLI2.OVL+{r['caller']:04X}",entry=e['entry'],exit=x,continuation=e['continuation'],entry_C=r['entry_C'],k=r['k'],descriptor=r['descriptor'],handler=r['handler'],scan_calls=r['scan_calls'],success=r['success'],fallback=r['fallback'],fallback_index=r['fallback_index'],fallback_pointer=r['fallback_pointer'],predicate_tokens=r['predicate_tokens'],predicates=[dict(callsite=f"{p['call']['offset']:04X}",input=p['call']['after'],output=p['ret']['after'])for p in r['predicates']],software_RET=r['handler_ret'],software_last_writers=r['software_last_writers'],entry_RAM_sha256=e['RAM_sha256'],exit_RAM_sha256=r['exit']['RAM_sha256'],filesystem_before=e['filesystem_sha256'],filesystem_after=r['exit']['filesystem_sha256'],DMA_before=e['DMA'],DMA_after=r['exit']['DMA'],projected_journal_sha256=r['journal_sha256'],own_journal_sha256=digest(r['own']),saved_state=e['saved_state'],hardware_CALL=e['CALL'],table_reads=[dict(offset=w['offset'],reads=g.accesses(w,'read'))for w in r['own']if w['offset']in[0x1fec,0x1fee,0x2009,0x200b,0x206e,0x2077,0x2079]],handler_path='AD0A_one_mapped_word_tag2A'if r['success']else'AD0A_zero_mapped_byte',frame_SP_checkpoints=[[w['offset'],w['before']['sp'],w['after']['sp']]for w in r['own']if w['offset']in[0x1fb9,0x1fbb,0x1fbc,0x1fbf,0x1fc8,0x20af,0x20ca,0x20d4,0x20e9,0x20ea]],frame_stack_accesses=[[w['offset'],a['kind'],a['address'],a['value']]for w in r['own']for a in w['accesses']if s-64<=a['address']<=s+1],full_own_frame_journal_sha256=digest(r['own'])))
 save(REPORT/'natural-inventory.json',rows)
 cp=load(OUT/'components.json');syn=cp.pop('synthetic_cases');save(REPORT/'component-shadows.json',cp)
 save(REPORT/'synthetic-summary.json',dict(cases=len(syn),all_passed=all(q['all_passed']for q in syn),routes=sorted({q['route']for q in syn}),aggregate_sha256=digest(syn),journals=str(OUT/'components.json')))
 observed={w['offset']for r in rs for w in r['own']}
 cfg=[{**q,'evidence':'OBSERVED'if q['offset']in observed else'STATIC UNOBSERVED unsupported trace'}for q in load('research/host-compiler/pass-71/cfg.json')]
 save(REPORT/'cfg.json',cfg)
 law='Scoped k23 composition: actual saved-C canonical047D result23; actual descriptor pointer3C21+2*k=57C6, count2; handler pointer3DDD+2*k=6036. Twelve-byte ordered frame retains C, AD0B..AD14 and AD0A with temporary PUSH/POP writes. Scan advances fresh AD1D, consumes canonical1DFF actual A/flags throughRAR, publishes0/1 on success and performs shared fresh record skip. Failed scans freshly select j=byte[1B4B+k]&7 and fallback pointer3C13+2*j+1; supported canonical predicate family is05/69-mismatch/FB-first-use. Exact PUSH42B4/freshAD1F/PCHL is represented by canonical3E36 and consumption of the pushed word, without a CALL frame. Both fresh202E trace gates require bit0 clear. Ordered restore and SPHL precede original hardwareRET. Final registers/flags derive from the DCR/DAD restore instructions. Other indices/descriptors/handlers/trace and unsupported canonical child domains reject staged state. No global native gateway root.'
 save(REPORT/'contract-laws-PLI2.OVL.json',{'PLI2.OVL+1FB5':dict(end=0x20eb,description='Scoped k23 gateway composition law',contract=law,completeness=['stable','partial','partial'])})
 save(REPORT/'semantic-extraction.json',dict(historical_root='PLI2.OVL+1FB5',semantic_inputs=['entry C and saved AD0A..AD14','actual mapped lookup, descriptor and handler tables','scoped k23 predicate and3E36 child domains','trace bit0 clear, original hardware continuation'],semantic_outputs=['actual selected handler effects','ordered restoration of saved AD0A..AD14','persistent shared AD1x scratch effects','instruction-derived returned registers/flags'],shared_historical_state=['12-byte mutable stack frame','AD1A..AD26','3C21/3DDD/3C13 and1B4B tables'],historical_mechanism=['canonical047D result indexes independent pointer tables','actual canonical1DFF result drives scan/fallback','PUSH42B4/PCHL/softwareRET then original hardwareRET','exact fresh reads, flags and ordered writes'],candidate_modern_operation='HYPOTHESIS: scoped descriptor-driven generation composition',confidence='High for the supported representation-level law; generic native installation not enabled.',mir_relevance='Separate descriptor selection and child composition from historical frame/table/flag mechanisms. Documentation only.'))
 save(REPORT/'parent-unblocking.json',dict(state_defined_k23_prerequisites_proved=True,native_gateway_installed=False,Pass69_native_unblocked=False,Pass70_native_unblocked=False,cases=load('research/host-compiler/pass-71/parent-unblocking.json')['callsite_subset'],remaining=['generic proof dispatcher has all-invocations replacement assumption; no partial-coordinate installation in this pass','k123/256E, k33/3FFD, k216/6D47 cross-source domains remain separate']))
 counts={s:sum(r['source']==s for r in rs)for s in g.SOURCES}
 packet=dict(baseline=BASE,full_epoch='Pass72',outcome='Complete scoped composition law; gateway remains guest',extent=[0x1fb5,0x20eb],counts=counts,nested_roots=28,paths=dict(collections.Counter('success'if r['success']else'fallback'for r in rs)),law=law,software_continuation=0x42b4,own_observed_bytes=sum(len(bytes.fromhex(q['bytes']))for q in cfg if q['evidence']=='OBSERVED'),unsupported_trace_bytes=39,components=cp,synthetic_summary=load(REPORT/'synthetic-summary.json'),oracle_queries=0,historical_bytes=94720,installation_boundary={'file':'lib/pli80/native_dispatch.ml','reason':'All invocations at an installed coordinate must match oracles, and guest execution anywhere inside its extent is rejected. k23 accepts only28/237 calls. No generic dispatch change made.'},counter_baseline={'MINIMAL':[294362,92],'FIZZBUZ':[557928,215],'PICTURE':[339572,78]},savings=0,native_roots_added=0,full_trigger=False)
 save(REPORT/'implementation-packet.json',packet);assert (REPORT/'implementation-packet.json').stat().st_size<28672
 save(REPORT/'focused-proof-timing.json',load(OUT/'focused-proof-timing.json'))
 print('Reports:',counts,'packet',(REPORT/'implementation-packet.json').stat().st_size)

def validate(images=IMAGES):
 (OUT/'tmp').mkdir(exist_ok=True)
 subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--categories','pass73,diff-check,validation-runner-tests','--images',str(images),'--output',str(OUT/'validation'),'--workers','4'],env={**os.environ,'TMPDIR':str((OUT/'tmp').resolve())},check=True)
 save(REPORT/'validation.json',load(OUT/'validation/results.json'))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['prove','reports','validate']);p.add_argument('--images',default=IMAGES);a=p.parse_args()
 {'prove':prove,'reports':lambda _:reports(),'validate':validate}[a.phase](a.images)
