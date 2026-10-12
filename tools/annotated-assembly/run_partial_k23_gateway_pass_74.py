#!/usr/bin/env python3
"""State-defined mixed gateway installation; FULL always external/list-only."""
import argparse,json,os,shutil,subprocess,time,hashlib
from pathlib import Path
OUT=Path('_build/host-compiler-pass-74');REPORT=Path('research/host-compiler/pass-74')
BASE='4f496a99c1fc7a4bb8bcb2b670a6c425193647b3';IMAGES='/home/john/pli/cpm/pli80/DISK1'
load=lambda p:json.loads(Path(p).read_text())
def save(p,q):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(q,sort_keys=True,indent=2)+'\n')
def prove(images=IMAGES):
 start=time.monotonic();OUT.mkdir(parents=True,exist_ok=True)
 if not os.environ.get('RUNES_HOST_IMAGES'):subprocess.run(['dune','build','bin/native_k23_gateway.exe','test/native_dispatch_partial.exe'],check=True)
 subprocess.run(['_build/default/test/native_dispatch_partial.exe'],check=True)
 dest=OUT/'proof'
 if dest.exists():shutil.rmtree(dest)
 subprocess.run(['_build/default/bin/native_k23_gateway.exe','--toolchain',str(images),'--output-dir',str(dest)],check=True)
 save(OUT/'focused-proof-timing.json',dict(all_passed=True,wall_seconds=round(time.monotonic()-start,3)))
def reports():
 REPORT.mkdir(parents=True,exist_ok=True)
 for n in ['single-hybrid-summary.json','cumulative-hybrid-summary.json','component-shadows.json']:
  save(REPORT/n,load(OUT/'proof'/n))
 rows=load(OUT/'proof/natural-cases.json')['sources']
 save(REPORT/'natural-shadow-summary.json',[dict(source=r['source'],accepted_roots=len(r['entries'][0]['members']),roots=[dict(caller=c['caller'],input=c['input'],output=c['output'],entry_RAM_sha256=c['entry_memory_sha256'],post_RAM_sha256=c['post_memory_sha256'],ordered_journal_sha256=hashlib.sha256(json.dumps(c['journal']).encode()).hexdigest(),services=c['service_details'])for c in r['entries'][0]['members']])for r in rows])
 save(REPORT/'focused-proof-timing.json',load(OUT/'focused-proof-timing.json'))
 sel=load(OUT/'historical-full-selection.json');assert len(sel['selected_categories'])==105
 cert=load('research/host-compiler/pass-72/validation-full.json');assert set(cert['selected_categories'])<=set(sel['selected_categories'])
 save(REPORT/'historical-full-selection-proof.json',dict(executed=False,selected_category_count=105,certified_Pass72_subset=True,selected_categories=sel['selected_categories']))
 command='python3 tools/annotated-assembly/run_host_compiler_regressions.py --profile historical-full --images /home/john/pli/cpm/pli80/DISK1 --output _build/host-compiler-pass-74/full-validation --workers 4'
 save(REPORT/'full-checkpoint-handoff.json',dict(status='pending_external_execution',semantic_commit='PENDING_UNTIL_COMMIT',baseline=BASE,last_certified_full='Pass72',profile='historical-full',selected_category_count=105,workers=4,historical_bytes=94720,command=command,trigger='Material shared proof interpretation extension: opt-in oracle sequencing and guest-frame ownership. Strict defaults remain unchanged; this does not waive early FULL.'))
 save(REPORT/'semantic-extraction.json',dict(historical_root='PLI2.OVL+1FB5',semantic_inputs=['Actual entry C, canonical047D result, historical memory and hardware CALL ancestry'],semantic_outputs=['Same canonical Pass73 k23 composition effects; other indices remain concrete guest executions'],shared_historical_state=['Original gateway frame and both continuations','Shared AD1x scratch and canonical child state'],historical_mechanism=['Existing Pass73 staged faithful law, unchanged','Read-only copied canonical lookup determines eligibility','Opt-in declined hardware-frame tracking, no oracle consumed on decline'],candidate_modern_operation=None,confidence='Bounded representation-level migration; no general gateway or source-language interpretation.',mir_relevance='Installation infrastructure is distinct from unchanged historical semantic law. No MIR/API design.'))
 packet=dict(baseline=BASE,scope='Canonical lookup index23 and trace202E.bit0 clear claim eligibility. Other indices or trace-set are Inapplicable; code/ABI/frame or eligible preparation/child-domain failures propagate, never fallback.',strict_default_preserved=True,native_boundary='PLI2.OVL+1FB5',shared_FULL_trigger=True,FULL_pending=True,current_FULL='Pass72',own_bytes_promoted=0,oracle_queries=0,historical_bytes=94720,standalone=load(REPORT/'single-hybrid-summary.json'),cumulative=load(REPORT/'cumulative-hybrid-summary.json'),future='Pass69/70 state-defined k23 prerequisite removed; four cross-source k123/256E,k33/3FFD,k216/6D47 dependencies remain. Separate382E remains an independent candidate.')
 save(REPORT/'implementation-packet.json',packet);assert (REPORT/'implementation-packet.json').stat().st_size<28672

def validate(images=IMAGES):
 (OUT/'tmp').mkdir(exist_ok=True)
 subprocess.run(['python3','tools/annotated-assembly/run_host_compiler_regressions.py','--categories','pass74,diff-check,validation-runner-tests','--images',str(images),'--output',str(OUT/'validation'),'--workers','4'],env={**os.environ,'TMPDIR':str((OUT/'tmp').resolve())},check=True)
 save(REPORT/'validation.json',load(OUT/'validation/results.json'))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['prove','reports','validate']);p.add_argument('--images',default=IMAGES);a=p.parse_args();{'prove':prove,'reports':lambda _:reports(),'validate':validate}[a.phase](a.images)
