"""Bounded paired publication; synthetic early return is never marked observed."""
import os,runpy,json
from pathlib import Path
os.environ['RUNES_ANNOTATION_PASS']='62';os.environ['RUNES_ANNOTATION_BASE']='a409348e69e69e6760a0defc9b275ec1d30393c0'
runpy.run_path(str(Path(__file__).with_name('update_buffered_rel_annotations_pass_52.py')),run_name='__main__')
r=Path('research/annotated-assembly');c=json.loads((r/'procedures.json').read_text());law=json.loads(Path('research/host-compiler/pass-62/contract-laws-PLI2.OVL.json').read_text())['PLI2.OVL+7338'];p=next(p for p in c['procedures']if p['id']=='PLI2.OVL+7338')
p['contract']=law['contract'];p['memory_state']=['ADBF=D then ADBE=E then ADBD=C; independently paired-read ADBE/ADBF and ADBD/ADBE.','Canonical7314 scratch ADBB/ADBC and indexed ADAB/ADB3 tables do not overlap saved carriers for accepted indices.','Original hardware CALL word; PSW below entrySP transported into BC; child CALL/PUSH residues retained.']
groups=[(0x7338,'Save D/E/C at descending ADBF/ADBE/ADBD; flags preserved. Fresh C CPI6; early RET7348 is DEDUCED STATIC UNOBSERVED synthetic CPU proof.'),(0x7349,'Paired rereads select saved C and saved D; canonical7314 publishes(C,D).'),(0x7355,'Fresh saved C INR modulo256 with CY preserved; paired saved E/D. PUSHPSW, move savedE, POPB then MOVC,B transports incremented selector with exact stack/register channels.'),(0x7361,'Canonical7314 publishes(C+1,E); final RET7364 consumes original continuation.')]
p['blocks']=[dict(offset=o,pseudocode=[t])for o,t in groups];p['pseudocode']='; '.join(t for _,t in groups);p['unresolved_paths']=['Only C0..5 paired publications and C6 early return are accepted; C>=7 fails before live mutation because both child indices must be supported.','Code/caller/continuation/scratch/table/stack/sentinel aliases reject; higher compiler meaning unproved.'];p['returns']['sites_description']='OBSERVED RET7364; DEDUCED STATIC UNOBSERVED early RET7348. Exact extent45bytes.'
factor=Path('_build/host-compiler-pass-62/factor-natural-cases.json')
if factor.exists():
 g=json.loads(factor.read_text())['sources'][0];e=next(e for e in g['entries']if e['offset']==0x7338);p['observed_paths']['invocations_by_run']['FACTOR']=max(p['observed_paths']['invocations_by_run'].get('FACTOR',0),len(e['members']))
 for caller in sorted({m['caller']for m in e['members']}):
  row=next((r for r in p['callers']if r['coordinate']==caller),None)
  if row is None:row=dict(coordinate=caller,counts_by_run={});p['callers'].append(row)
  row['counts_by_run']['FACTOR']=max(row['counts_by_run'].get('FACTOR',0),sum(m['caller']==caller for m in e['members']))
(r/'procedures.json').write_text(json.dumps(c,indent=2)+'\n')
from decompilation_annotations import render
render(r)
