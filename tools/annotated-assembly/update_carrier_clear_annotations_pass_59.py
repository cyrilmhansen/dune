"""Exact carrier classification annotations; synthetic paths remain unobserved."""
import os,runpy,json
from pathlib import Path
os.environ['RUNES_ANNOTATION_PASS']='59';os.environ['RUNES_ANNOTATION_BASE']='3cd5b72edd2a5bf7456b3370c10f8de6705e16fe'
runpy.run_path(str(Path(__file__).with_name('update_buffered_rel_annotations_pass_52.py')),run_name='__main__')
r=Path('research/annotated-assembly');c=json.loads((r/'procedures.json').read_text());laws=json.loads(Path('research/host-compiler/pass-59/contract-laws-PLI2.OVL.json').read_text())
groups={
 'PLI2.OVL+7B1B':[(0x7b1b,'save E atAE0D thenC atAE0C'),(0x7b21,'freshC equalityA8 mask;PUSH PSW;freshE equality7 mask;POP B,MOV C,B;ANA C,RAR setsCY=conjunction'),(0x7b39,'STATIC UNOBSERVED: zeroAE05 canonical79E2;E0/C7 canonical7365;RAR;CY1 earlyRET,elsecanonical7314 andJMP tail'),(0x7b52,'freshC CPIB8;unless equal literalC7 canonical7397'),(0x7b5f,'freshpairedC canonical746F;independentfreshpairedE canonical74C7'),(0x7b6d,'freshE ORfreshC;C=result canonical7557;RET')],
 'PLI2.OVL+7314':[(0x7314,'saveE/C;publishADAA1;PUSH H addresscarrier'),(0x7320,'freshC zeroextend;POP B,INX toADAB;publish1 atADAB+C'),(0x732a,'independentfreshC zeroextend;freshE publishedatADB3+C;RET')],
 'PLI2.OVL+7365':[(0x7365,'saveE/C;fresh202B RAR;gate-set literalA0 RET isSTATIC UNOBSERVED'),(0x7375,'freshC zeroextend,ADAB+C;freshcarrier RAR;clear returnsA0 preservingflags'),(0x7386,'freshC zeroextend,ADB3+C;freshE SUBcarrier/SUI1/SBB A equalitymask;RET')]}
for p in c['procedures']:
 if p['id']not in laws:continue
 p['blocks']=[dict(offset=o,pseudocode=[t])for o,t in groups[p['id']]];p['pseudocode']='; '.join(t for o,t in groups[p['id']]);p['contract']=laws[p['id']]['contract']
 p['memory_state']=['AE0C/AE0D savedC/E;pairedreadAE0D also acquires adjacentAE0E,retaineduntilchildclobber.','ADBB/ADBC andADC0/ADC1 helperC/E carriers;ADAA sharedpresentbyte,ADAB/ADB3 indexedbytes.','F=entrySP;PUSH PSW highA thenlowPSW belowF;POP B transportsmask,doesnotrestoreflags;actualchildCALLresidueandRETderived.']
 p['unresolved_paths']=['Generalaliases,indicesoutside0..7 forindexedchildren,unsupportedemission/pendingstates,positionwrap/writeerrorsrejectcopiedstaging.','Parent specialA8/E7 andB8 skip havezero naturalprimarycalls;acceptedonlyexplicitstatic/synthetic scope.','7365 firstgate return isSTATIC UNOBSERVED;sharedstate meanings beyond representationremainunproved.']
for p in c['procedures']:
 if p['id']=='PLI2.OVL+7314':p['memory_state']=['ADBB=saved input C;ADBC=saved input E;paired LHLD independently reads both bytes.','ADAA=present publication;ADAB[C]=1 thenADB3[C]=fresh saved E.','F=entrySP;PUSH H carries ADAA address high/low below F;POP B then INX B derives ADAB;NZPA preserved and final CY comes from second DAD.']
 if p['id']=='PLI2.OVL+7365':p['memory_state']=['ADC0=saved input C;ADC1=saved input E;paired LHLD independently reads both bytes before H is zeroed.','202B low-bit gate;ADAB[C] low-bit gate;freshADB3[C] value for equality.','F=entrySP;no private frame;original hardware CALL word retained,RET preserves actual literal-zero or subtraction-mask flags.']
factor=json.loads(Path('_build/host-compiler-pass-59/factor-natural-cases.json').read_text())['sources'][0]
for p in c['procedures']:
 if p['id']not in laws:continue
 e=next(e for e in factor['entries']if f"PLI2.OVL+{e['offset']:04X}"==p['id']);p['observed_paths']['invocations_by_run']['FACTOR']=len(e['members'])
 for caller in sorted({m['caller']for m in e['members']}):
  row=next((r for r in p['callers']if r['coordinate']==caller),None)
  if row is None:row=dict(coordinate=caller,counts_by_run={});p['callers'].append(row)
  row['counts_by_run']['FACTOR']=sum(m['caller']==caller for m in e['members'])
 p['observed_paths']['description']+=' FACTOR full-state shadows independently retained;OPTIMIST emission ancestor evidence is not a parent ABI proof or total inventory.'
 p['unresolved_paths']=['Unsupported child/output/pending states,position wrap,writer errors andcode/stack/sentinel aliases excluded.','Source-language semantic purpose remainsunproved.']
 if p['id']=='PLI2.OVL+7B1B':p['unresolved_paths'].append('A8/E7 special andB8 skip havezero naturalprimary/FACTOR executions;boundedstatic/synthetic scope only. SpecialAE05nonzero unsupported.')
 if p['id']=='PLI2.OVL+7365':p['unresolved_paths'].append('Firstgate literal-zero return remainsSTATIC UNOBSERVED withsyntheticproof;Cindicesoutside0..7 unsupported.')
 if p['id']=='PLI2.OVL+7314':p['unresolved_paths'].append('Cindicesoutside0..7 unsupported;Eisbytevalue,notassumedindex.')
(r/'procedures.json').write_text(json.dumps(c,indent=2)+'\n')
from decompilation_annotations import render
render(r)
