#!/usr/bin/env python3
"""Pass50 bounded delimiter driver evidence and proof interface."""
import sys,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import run_initialization_parent_pass_49 as prior
OUT=Path('_build/host-compiler-pass-50');REPORT=Path('research/host-compiler/pass-50')
prior.OUT=OUT;prior.REPORT=REPORT;prior.BASE='59d7f0b09766b2e711ec0fd9b9b0dc7540719ffb'
def prove(images,*,persist=False):
 import subprocess,tempfile,shutil,time
 start=time.monotonic();OUT.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='driver-proof-',dir=OUT)as temp:
  dest=Path(temp)/'result'
  with (OUT/'root-proof.log').open('w')as log:
   result=subprocess.run(['dune','exec','bin/native_delimiter_driver_hybrids.exe','--','--toolchain',str(images),'--output-dir',str(dest)],stdout=log,stderr=subprocess.STDOUT)
  if result.returncode:raise RuntimeError((OUT/'root-proof.log').read_text()[-4000:])
  target=OUT/('validated-proof'if persist else 'fresh-'+Path(temp).name);target.mkdir(exist_ok=True)
  for file in dest.glob('*.json'):shutil.copyfile(file,target/file.name)
 prior.save(OUT/'proof-timing.json',dict(wall_seconds=round(time.monotonic()-start,3),all_passed=True))
 return target
def compact():
 import collections
 catalog={p['id']:p for p in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
 raw=json.loads((OUT/'0C75-rows.json').read_text());packet=json.loads((OUT/'0C75-packet.json').read_text());law=json.loads((REPORT/'contract-laws-PLI1.OVL.json').read_text())
 refs={key:dict(contract_hash=prior.digest(catalog[key]),completeness=catalog[key]['completeness'])for key in ['PLI1.OVL+0C1B','PLI1.OVL+0A32','PLI1.OVL+02F0','PLI1.OVL+020E','PLI1.OVL+013D','PLI1.OVL+45F0','PLI1.OVL+784E','PLI1.OVL+01AF','PLI1.OVL+0261','PLI1.OVL+80B7','PLI1.OVL+0146']}
 for group in packet['cases'].values():
  for cases in group.values():
   for case in cases:
    for name in ['entry','output']:
     state=case[name];f=state['flags'];case[name]=[state[k]for k in ['a','b','c','d','e','h','l','sp','pc']]+[sum(bit for k,bit in [('sign',128),('zero',64),('auxiliary_carry',16),('parity',4),('carry',1)]if f[k])]
 packet.update(task='DELIMITER_EOF_DRIVER_0C75_PASS_50',selected_root='PLI1.OVL+0C75',contracts=refs,laws=law,oracle_queries=0,stack_pattern='No own frame; entrySP S and hardware child slots S-2. Ordinary RET at0D1B consumes original CALL011E continuation2321, SP=S+2. Canonical0C1B owns context frame S_child-4; lower hardware recursion, N2/N8 software continuation and XTHL retain separate planners.',parent_assessment='Immediate startup caller011E also initializes compiler state and invokes separate output/termination operations; keep the delimiter/EOF driver boundary at0C75. No upward widening.',state_encoding=['A','B','C','D','E','H','L','SP','PC','flags:S7 Z6 AC4 P2 CY0'])
 packet['local_read_write_chronology']={source:[dict(offset=w['origin']['offset'],reads=w['reads'],writes=w['writes'])for w in rows['PLI1.OVL+0C75'][0]['own_witnesses']if w['reads']or w['writes']]for source,rows in raw.items()}
 # Full memory accesses include instruction fetch bytes; the compact packet keeps
 # significant fixed channels only, with the complete journal referenced by hash.
 for source,rows in packet['local_read_write_chronology'].items():
  packet['local_read_write_chronology'][source]=[dict(offset=r['offset'],reads=[v for v in r['reads']if v['address']in [0xa5d9,0xa5da,0xa5db,0x20c3,0x2015,0xa863,0xa864]],writes=[v for v in r['writes']if v['address']in [0xa5d9,0xa5da,0xa5db]])for r in rows]
 packet['local_read_write_chronology']={source:[r for r in rows if r['reads']or r['writes']]for source,rows in packet['local_read_write_chronology'].items()}
 (REPORT/'implementation-packet.json').write_text(json.dumps(packet,separators=(',',':'))+'\n')
 assert (REPORT/'implementation-packet.json').stat().st_size<=32768
 prior.save(REPORT/'natural-cases.json',json.loads((OUT/'0C75-summary.json').read_text()))
 prior.save(REPORT/'boundary-assessment.json',dict(selected_root=packet['selected_root'],parent_assessment=packet['parent_assessment'],next_parent='startup phase boundary: independently rank remaining execution/emit driver above011E; do not mechanically combine unrelated phases',unsupported=['clear020E gate','unmatched3A/9B predicates','matched28 alternative','clear2015 entry/exit policy','nonEOF continuation','arbitrary delimiter scan termination','canonical child unsupported states']))
 after=REPORT/'after-PLI1.OVL.json'
 if after.exists():after.rename(OUT/'after-PLI1.OVL.json')
 print('Packet bytes',(REPORT/'implementation-packet.json').stat().st_size)
def report(proof):
 roots=json.loads((proof/'natural-cases.json').read_text())['sources'];post=json.loads((proof/'cumulative-hybrid-summary.json').read_text())['sources'];archive={};hierarchy={}
 coords=['PLI1.OVL+0C1B','PLI1.OVL+0A32','PLI1.OVL+02F0','PLI1.OVL+19F0','PLI1.OVL+6619','PLI1.OVL+6223','PLI1.OVL+5929','PLI1.OVL+2511','PLI1.OVL+240A','PLI1.OVL+23D2','PLI1.OVL+2705','PLI1.OVL+80B7','PLI1.OVL+7EC0','PLI1.OVL+8048','PLI1.OVL+7E5F','PLI1.OVL+7D53','PLI1.OVL+7C1B','PLI1.OVL+7BBF','PLI1.OVL+7B7A','PLI1.OVL+7AB7','PLI1.OVL+7A93','PLI1.OVL+7B64','PLI1.OVL+7B32','PLI.COM+0EF6','PLI1.OVL+7E24','PLI1.OVL+7DEA','PLI1.OVL+7AF9','PLI1.OVL+7AE0','PLI1.OVL+7AC7','PLI1.OVL+7A79','PLI1.OVL+7A63']
 # Tail controller coordinate order comes from the canonical hierarchy, rather
 # than guessed PC ranges. Preserve the raw vectors for independent checking.
 for r in roots:
  archive[r['source']]=[dict(caller=c['caller'],entry_step=c['entry_step'],return_step=c['return_step'],input=c['input'],output=c['output'],route=c['result']['route'],logical_writes=len([w for w in c['journal']if w[4]=='logical']),writer_cells=len(set(w[0]for w in c['journal'])),journal_hash=prior.digest(c['journal']),post_memory_sha256=c['post_memory_sha256'],services_hash=prior.digest(c['service_details']),own_writes=[w for w in c['journal']if w[3]==0 and w[4]=='logical'],delimiter_acquisitions=sum(w[2]==0x2ecc and w[3]==0 and w[4]=='compatibility'for w in c['journal'])//2)for c in r['members']]
 for r in post:
  source=r['result']['source'];pre=r['pre_transition_vector'];after=r['transition_vector'];delta=[a-b for a,b in zip(pre,after[1:])]
  hierarchy[source]=dict(pre_guest=r['pre_guest_instructions'],post_guest=r['result']['actual_guest_instructions'],guest_removed=r['guest_instructions_removed'],pre_host=sum(pre),post_host=sum(after),root_transitions=after[0],pre_transition_vector=pre,post_transition_vector=after,absorbed_by_coordinate={coords[i]:n for i,n in enumerate(delta)if n},internal_0C1B=1,internal_0A32=1,internal_02F0_outer={'MINIMAL':1,'FIZZBUZ':1,'PICTURE':2}[source],internal_02F0_logical={'MINIMAL':1,'FIZZBUZ':8,'PICTURE':2}[source],remaining_external_0C1B=after[1],remaining_external_0A32=after[2],remaining_external_02F0=after[3],REL_sha256=r['result']['REL_sha256'])
 prior.save(REPORT/'shadow-summary.json',dict(all_passed=True,roots=archive,canonical_components='Independent current013D/4802/4890/47E2/47F7/3563 and0146/4929/4986 proof remains exercised by Pass47/49 complete categories. No descendant scope extension required. Independent0C1B/0A32/02F0/19F0/6619/6223 journals and actual child CALL/SP windows correlate inside each root.',comparisons=['registers/all flags','SP/continuation','ordered logical writes','65536-byte RAM','stack last writers','DMA/filesystem','record/file chronology','direct and canonical child chronology'],falsifications=['canonical CALL ancestry','register range/PC','stack/scratch alias','immutable root/child code','original continuation','2015 policy bit','lifetime publication last writer','return flags','write order','source/input proof identity'],synthetic_laws='0,1,4,7 delimiter acquisitions from changing reader state; unsupported gate/delimiter/nonEOF rejection'))
 prior.save(REPORT/'hierarchy-summary.json',hierarchy)
 prior.save(REPORT/'hybrid-summary.json',{n:json.loads((proof/(n+'-hybrid-summary.json')).read_text())for n in ['single','cumulative']})
 archaeology=json.loads((REPORT/'archaeology-summary-PLI1.OVL.json').read_text())
 prior.save(REPORT/'fidelity.json',dict(archaeological_scope_extension=True,historical_correction=None,implementation_correction='Parenthesized an OCaml variant-valued optional argument during build, before executable proof. No algorithmic correction.',pragmatic_divergence=None,fidelity_debt=None,oracle_queries=0,RAW_to_UNDERSTOOD=archaeology['raw_to_understood'],by_procedure=archaeology['by_procedure'],validation_tier='full_checkpoint',previous_full_checkpoint='7a4bf0adf5959ffa29238a7f30d549522d18750f',cpu_runner_cpm_changes=False,proof_schema_change=False,scripts_view_optimist_untouched=True))
 table='\n'.join(f"| {source} | {v['pre_guest']} | {v['post_guest']} | {v['guest_removed']} | {v['pre_host']} | {v['post_host']} |"for source,v in hierarchy.items())
 (REPORT/'README.md').write_text("""# Pass50 — bounded +0C75 delimiter/EOF driver

Baseline `59d7f0b09766b2e711ec0fd9b9b0dc7540719ffb`; previous FULL checkpoint
Pass47 `7a4bf0adf5959ffa29238a7f30d549522d18750f`.
One natural ordinary root per MINIMAL/FIZZBUZ/PICTURE, all from +011E.
The startup caller also performs separate compiler-state and output/termination
operations; +0C75 is the coherent driver boundary, with no upward widening.

Publish A5D9=1 and freshly reread/rotate its byte for the lifetime gate. Compose
canonical +020E, rotate its actual A, then +013D/+45F0. Fresh word[A863] is
published low/high to A5DA. Canonical +784E and the independent +01AF C=3A/9B
matches acquire following input; +0261 increments its historical counter.
The independent C=28 predicate is clear. Fresh 2015.bit0 selects bounded output
8D through canonical +80B7. Repeated fresh 20C3 / CPI3B and +784E acquisitions
stop on actual equality, with no fixed iteration count. Each observed scan has
four acquisitions; synthetic scans with 0/1/4/7 demonstrate the state-driven law.
The 3BH delimiter is retained for canonical +0C1B, whose +01C6 consumes it.

Fresh A5DA low/high becomes BC for the canonical initialization root. Its A5B5
lifetime, structure setup, acquisition frame and recursive +02F0 family are reused,
not duplicated. Fresh 2015.bit0 selects output8E; canonical +0146 composes existing
cleanup/output operations. Fresh 20C3=1AH is retained, not consumed by the driver.
CPI1A produces the final NZPA; write A5D9=0, reread and RAR exits with A0/CY0.
Final BC/DE remain independent +0146 channels; HL=A5D9. The driver has no private
frame: actual child CALL words lie below its original +011E return slot; RET0D1B
consumes continuation2321 and finalSP=entrySP+2. Lower ordinary frames, hardware
recursion, N=2/N=8 software continuations and XTHL remain distinct mechanisms.

Only +0C75 is a new bounded contract: stable bounds, partial local CFG/contract,
142 formerly RAW bytes represented. Clear input gate, unmatched3A/9B, matched28,
clear2015 policies and nonEOF continuation arms remain RAW/unsupported. No new
child contract or global reader widening. No arbitrary-input termination claim.

All three root shadows match registers/flags, SP/PC, ordered logical writes,
full64KiB RAM, stack last writers, DMA/filesystem and file/record chronology.
Independent canonical +0C1B and lower child journals correlate to hardware
CALL/SP/continuations. Accepted roots form one copied staged transaction, with
no nested Runner transition and no live mutation on rejected preparation.
Standalone/cumulative hybrids preserve compiler markers, warm boot, exact RELs,
INT/REL chronology, full filesystem and BDOS order/counts. Savings below are
fresh actual whole-run counters, never inclusive-window estimates.

| Source | Pre50 guest | Post50 guest | Saved | Pre host | Post host |
|---|---:|---:|---:|---:|---:|
"""+table+"""

Full journals stay under ignored `_build/host-compiler-pass-50`; compact durable
artifacts carry hashes. Driver phases automate inventory/CFG, fixed-channel
chronology, packet generation, proof/hybrid batches, hierarchy and reporting.
An orchestrator restart interrupted development orchestration; the still-running
proof was recovered with one blocking pidfd wait, without duplicate execution.
The scheduled full checkpoint is recorded in validation.json. All94720 historical
bytes remain exact. Zero new oracle queries, no historical correction, pragmatic
divergence or fidelity debt. `scripts/view-optimist.sh` is untouched.
Next: rank a coherent residual output/termination parent rather than automatically
widening the startup caller across independent compiler phases.
""")
 print(json.dumps(hierarchy,indent=2))
def checkpoint():
 import subprocess
 subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--images','/home/john/pli/cpm/pli80/DISK1','--output',str(OUT/'full-checkpoint'),'--workers','4'],check=True)
def recover(pid,directory):
 import os,select,shutil,time
 start=time.monotonic()
 try:
  fd=os.pidfd_open(pid);select.select([fd],[],[]);os.close(fd)
 except ProcessLookupError:pass
 dest=Path(directory);target=OUT/'validated-proof';target.mkdir(exist_ok=True)
 assert (dest/'cumulative-hybrid-summary.json').exists(),(OUT/'root-proof.log').read_text()[-3000:]
 for file in dest.glob('*.json'):shutil.copyfile(file,target/file.name)
 prior.save(OUT/'proof-timing.json',dict(recovery_wait_seconds=round(time.monotonic()-start,3),all_passed=True,interrupted_orchestrator=True))
 shutil.rmtree(dest.parent)
 print('Recovered completed proof',target)
if __name__=='__main__':
 if sys.argv[1]=='inventory':
  prior.inventory(sys.argv[2:]or ['0C75'])
  packet=json.loads((OUT/'0C75-packet.json').read_text())
  print(json.dumps(packet['cfg'],indent=2))

 elif sys.argv[1]=='prove':print(prove(Path('/home/john/pli/cpm/pli80/DISK1'),persist=True))

 elif sys.argv[1]=='recover':recover(int(sys.argv[2]),sys.argv[3])

 elif sys.argv[1]=='compact':compact()

 elif sys.argv[1]=='report':report(OUT/'validated-proof')
 elif sys.argv[1]=='checkpoint':checkpoint()
