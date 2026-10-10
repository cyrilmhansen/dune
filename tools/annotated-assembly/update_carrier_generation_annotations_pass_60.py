"""Exact carrier generation annotation: natural and static evidence stay distinct."""
import os,runpy,json
from pathlib import Path
os.environ['RUNES_ANNOTATION_PASS']='60';os.environ['RUNES_ANNOTATION_BASE']='a3ca60c886833e1bdae92e1334504c9acd5fabd8'
pairs=json.loads(Path('_build/host-compiler-pass-60/proof/synthetic-helper-pairs.json').read_text());matches={p['coordinate']:{k:v for k,v in p.items()if k!='coordinate'}for p in pairs}
Path('_build/host-compiler-pass-60/annotation-static-matches-PLI2.OVL.json').write_text(json.dumps(matches,indent=2)+'\n')
runpy.run_path(str(Path(__file__).with_name('update_buffered_rel_annotations_pass_52.py')),run_name='__main__')
r=Path('research/annotated-assembly');c=json.loads((r/'procedures.json').read_text());laws=json.loads(Path('research/host-compiler/pass-60/contract-laws-PLI2.OVL.json').read_text())
groups={
'PLI2.OVL+7E05':[(0x7e05,'Save E at AE37 then C at AE36; paired fresh C supplies canonical 7AE4.'),(0x7e12,'Fresh C!=6 arithmetic mask; ANA ADAA; PUSH PSW; fresh 202B complement; POP B mask transport; ANA/RAR gate.'),(0x7e2a,'STATIC UNOBSERVED: fresh ADAB[C] activity; fresh ADB3[C] to AE38, compare fresh E. Equal returns; modulo +1/-1 calls 7DC3/7DE4.'),(0x7e73,'STATIC UNOBSERVED: AE39=0; scan 0..7, activity first, exclude index6, compare fresh relation value; match canonical793C, else publish increment and retry.'),(0x7eba,'Fresh independent C/E paired reads feed7314; fresh pair C feeds75CE(C6); fresh E feeds75A7; RET.')],
'PLI2.OVL+7DC3':[(0x7dc3,'STATIC UNOBSERVED: save C; paired reread=>DE;75CE literalC4; fresh C6 early return; otherwise fresh ADB3[C] increment, RET.')],
'PLI2.OVL+7DE4':[(0x7de4,'STATIC UNOBSERVED: save C; paired reread=>DE;75CE literalC5; fresh C6 early return; otherwise fresh ADB3[C] decrement, RET.')]}
factor=json.loads(Path('_build/host-compiler-pass-60/factor-natural-cases.json').read_text())['sources'][0]
for p in c['procedures']:
 if p['id']not in laws:continue
 p['blocks']=[dict(offset=o,pseudocode=[t])for o,t in groups[p['id']]];p['pseudocode']='; '.join(t for o,t in groups[p['id']]);p['contract']=laws[p['id']]['contract']
 p['memory_state']=['AE36/37 destination/relation; independent paired reads retain adjacent high byte. AE38 direct relation scratch; AE39 loop index.','ADAA/202B low-bit gate; ADAB activity and ADB3 value banks. No entry table snapshot.','AE34/35 adjustment carriers; stack PSW mask transport and ordinary child CALL residue. No private frame.']
 if p['id']=='PLI2.OVL+7DC3':
  p['memory_state']=['AE34 saved C; paired read includes adjacent AE35 before XCHG passes the actual DE word.','ADB3[C] is freshly read after canonical75CE; INR publishes one byte unless fresh C equals6.','Ordinary child CALL and original RET residue; no private frame.'];p['returns']['sites_description']='DEDUCED STATIC UNOBSERVED RETs +7DD8/+7DE3; synthetic CALL/RET ancestry retained.'
 if p['id']=='PLI2.OVL+7DE4':
  p['memory_state']=['AE35 saved C; paired read includes adjacent AE36 before XCHG passes the actual DE word.','ADB3[C] is freshly read after canonical75CE; DCR publishes one byte unless fresh C equals6.','Ordinary child CALL and original RET residue; no private frame.'];p['returns']['sites_description']='DEDUCED STATIC UNOBSERVED RETs +7DF9/+7E04; synthetic CALL/RET ancestry retained.'
 p['unresolved_paths']=['C outside0..7 and unsupported canonical child/output/pending states reject staging. Position wrap, writer errors, aliases excluded.','All direct/search/adjustment alternatives remain DEDUCED STATIC UNOBSERVED; synthetic instruction comparisons do not constitute natural coverage.','General source-language carrier semantics remain unproved.']
 e=next(e for e in factor['entries']if f"PLI2.OVL+{e['offset']:04X}"==p['id']);p['observed_paths']['invocations_by_run']['FACTOR']=len(e['members'])
 for caller in sorted({m['caller']for m in e['members']}):
  row=next((r for r in p['callers']if r['coordinate']==caller),None)
  if row is None:row=dict(coordinate=caller,counts_by_run={});p['callers'].append(row)
  row['counts_by_run']['FACTOR']=sum(m['caller']==caller for m in e['members'])
 for child in p['direct_callees']:
  if child['callsite_offset']in {w['origin']['offset']for w in json.loads(Path('_build/host-compiler-pass-60/annotation-static-PLI2.OVL.json').read_text()).get(p['id'],[])}:child['evidence_status']='STATIC / UNOBSERVED'
 p['observed_paths']['description']+=' Primary natural 7E05 routes use C7, gate clear; FACTOR independently shadowed. Helpers have zero primary/FACTOR natural calls. Synthetic alternatives remain STATIC UNOBSERVED.'
(r/'procedures.json').write_text(json.dumps(c,indent=2)+'\n')
from decompilation_annotations import render
render(r)
