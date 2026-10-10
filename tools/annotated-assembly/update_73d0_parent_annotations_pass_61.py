"""Natural true-parent annotations; unexecuted listing arm stays RAW."""
import os,runpy,json
from pathlib import Path
os.environ['RUNES_ANNOTATION_PASS']='61';os.environ['RUNES_ANNOTATION_BASE']='d19ce2f2012109802f968630b4cec45716b6a807'
runpy.run_path(str(Path(__file__).with_name('update_buffered_rel_annotations_pass_52.py')),run_name='__main__')
r=Path('research/annotated-assembly');c=json.loads((r/'procedures.json').read_text());laws=json.loads(Path('research/host-compiler/pass-61/contract-laws-PLI2.OVL.json').read_text())
groups={
 'PLI2.OVL+7423':[(0x7423,'HL=FFFF; publish L then H at ADA6/7; return preserving flags and all other registers.')],
 'PLI2.OVL+79A2':[(0x79a2,'Zero AE04, then AE05, then AE06; final HL=AE06; flags preserved; independent79AF excluded.')],
 'PLI2.OVL+742A':[(0x742a,'Canonical73D0 reset, then canonical7423 literal publication; freshly LHLD1C2C; original RET.')],
 'PLI2.OVL+8258':[(0x8258,'Save high B atAE67 then low C atAE66; canonical73D0.'),(0x8261,'Capture freshly read1C2C toAE68/69; reread saved input, add1 modulo65536, canonical7434.'),(0x8270,'Fresh201D RAR; bit0-clear jumps to8288. Set arm8277..8288 remains STATIC UNOBSERVED RAW unsupported.'),(0x8288,'Independent pairedAE68 reads before7630 and7434. First emits captured position and increments; second republishes captured position. Canonical7423 FFFF publication, RET.')],
 'PLI2.OVL+82B5':[(0x82b5,'ADAA=1 then canonical73D0; wordADA8=0; BC0 canonical7434; canonical7423.'),(0x82cc,'ZeroADC9 thenADCA thenAE6A; canonical79A2 zeroes AE04/05/06; originalRET.')]}
factor_path=Path('_build/host-compiler-pass-61/factor-natural-cases.json')
factor=json.loads(factor_path.read_text())['sources'][0]if factor_path.exists()else None
for p in c['procedures']:
 if p['id']not in laws:continue
 p['blocks']=[dict(offset=o,pseudocode=[t])for o,t in groups[p['id']]];p['pseudocode']='; '.join(t for _,t in groups[p['id']]);p['contract']=laws[p['id']]['contract']
 p['memory_state']=['ADA6/7 literalFFFF publication; ADA8/9 wordzero; ADAA/ADAB reset delegated to canonical73D0.','AE66/67 saved BC;AE68/69 captured1C2C, independently reread;201D fresh bit0 gate.','ADC9/ADCA/AE6A and AE04..AE06 orderedzero publications. No private frame; child hardwareCALLs below originalSP.']
 if p['id']=='PLI2.OVL+7423':p['memory_state']=['ADA6/ADA7 receive low FF then high FF; HL=FFFF.','Original hardware return word unchanged; no child or private frame; all flags preserved.']
 if p['id']=='PLI2.OVL+79A2':p['memory_state']=['AE04 then AE05 then AE06 receive zero, including same-valued writes; final HL=AE06.','Original hardware return word unchanged; no child or private frame; all flags preserved.']
 p['unresolved_paths']=['Unsupported canonical child/output states, writer errors, position wrap and code/stack/sentinel aliases reject staging. Higher compiler meaning unproved.']if p['id']not in ['PLI2.OVL+7423','PLI2.OVL+79A2']else['No unaccounted local instructions or branches; code/continuation/stack/sentinel nonalias scope enforced. Higher compiler meaning unproved.']
 if p['id']=='PLI2.OVL+8258':
  p['unresolved_paths']+=['201D-set arm8277..8288 is STATIC UNOBSERVED RAW: CALL745A, BC94E5 resident03F4, freshsavedposition resident0466. No fabricated natural coverage; unsupported.']
  p['observed_paths']['description']+=' All primary natural calls take the201D-clear branch. Numerical extent68bytes;represented51bytes,not the17-byte listing arm.'
 if factor:
  e=next(e for e in factor['entries']if f"PLI2.OVL+{e['offset']:04X}"==p['id']);p['observed_paths']['invocations_by_run']['FACTOR']=max(p['observed_paths']['invocations_by_run'].get('FACTOR',0),len(e['members']))
  for caller in sorted({m['caller']for m in e['members']}):
   row=next((r for r in p['callers']if r['coordinate']==caller),None)
   if row is None:row=dict(coordinate=caller,counts_by_run={});p['callers'].append(row)
   row['counts_by_run']['FACTOR']=max(row['counts_by_run'].get('FACTOR',0),sum(m['caller']==caller for m in e['members']))
(r/'procedures.json').write_text(json.dumps(c,indent=2)+'\n')
from decompilation_annotations import render
render(r)
