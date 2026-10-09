"""Pass57 scoped annotations; preserve byte identity and historical inventories."""
import os,runpy,json
from pathlib import Path
os.environ['RUNES_ANNOTATION_PASS']='57';os.environ['RUNES_ANNOTATION_BASE']='7bd9ca0a11984e7f618293bb2ab4f2c0d4b79314'
runpy.run_path(str(Path(__file__).with_name('update_buffered_rel_annotations_pass_52.py')),run_name='__main__')
r=Path('research/annotated-assembly');cat=json.loads((r/'procedures.json').read_text());laws=json.loads(Path('research/host-compiler/pass-57/contract-laws-PLI2.OVL.json').read_text())
blocks={
'7903':[(0x7903,'publish E atAE01 then C atAE00;fresh E equality6 mask ->ADCA'),(0x7914,'fresh C comparisonC1;conditional fresh maskRAR excludes C1/E6 arm'),(0x7929,'fresh E paired reload;canonical73A7 clears adjacent carrier bytes'),(0x7930,'independent savedC and savedE paired reloads;canonical75CE field emission')],
'7A17':[(0x7a17,'freshAE04 CPI0 selects clear earlyRET'),(0x7a20,'independent freshAE04 CPI1;other nonzero arm unsupported'),(0x7a28,'canonical fixedC5/E4 emission,then freshAE05 CPI2;equal2 arm unsupported'),(0x7a38,'visibleAE04 zero publication followed by fresh wrappingDCR AE06;DCR NZPA,CPI2 carry surviveRET')],
'7AE4':[(0x7ae4,'publish selectorC atAE0A'),(0x7ae8,'fresh pairedAE0A/AE0B reload,C=low;seven gate'),(0x7aef,'independent pairedAE0A/AE0B reload,C=low;four gate'),(0x7af6,'freshAE0A CPI5;equal drains fresh pendingAE04 gate;RET actual channels')],
'73A7':[(0x73a7,'save indexC atADC3;freshCPI6;unobserved equal6 earlyRET staysRAW'),(0x73b4,'fresh pairedADC3/ADC4,C=low;canonical7397'),(0x73bb,'independent freshADC3 increment,C=result;canonical7397')],
'7397':[(0x7397,'save indexC atADC2;fresh pairedADC2/ADC3,discardH;publish0 atADAB+index;DAD carry retained')],
'79B6':[(0x79b6,'literal E4,C C5;canonical7903')],
'7AC4':[(0x7ac4,'save C atAE08;freshCPI7;onlyequal invokes freshAE05 gate')],
'7AD4':[(0x7ad4,'save C atAE09;freshCPI4;onlyequal invokes freshAE04 gate')]}
for p in cat['procedures']:
 if p['id']not in laws:continue
 key=p['id'].split('+')[1];p['contract']=laws[p['id']]['contract'];p['unresolved_paths']=['Unsupported AE05 nonzero,AE04 other-than0/1,AE05=2 drain,7903 C1/E6 and73A7 index6 earlyRET remain unaccepted as applicable.','Inherited output errors,position wrap,mode and alias alternatives remain unsupported;higher-level item meaning unproved.'];p['blocks']=[dict(offset=o,pseudocode=[t])for o,t in blocks[key]];p['pseudocode']='; '.join(t for o,t in blocks[key]);p['memory_state']=['AE08/AE09/AE0A are separately published selector carriers; pairedAE0A reload also reads adjacentAE0B beforeH discarded.','AE04 is independently fresh pending gate;AE05 is separate fresh gate;AE06 decremented only after fixedC5/E4 emission andAE04 clear.','AE00/AE01 savedC/E;ADCA equality6 mask;ADC2/ADC3 saved byte indices;ADAB carrier.','F=entrySP;original CALL word survives;child CALL traffic belowF has actual last-writer provenance.']
(r/'procedures.json').write_text(json.dumps(cat,indent=2)+'\n')
ev=json.loads((r/'evidence.json').read_text())
for q in ev['seeds']:
 if q['id']in laws:q['behavioral_contract']=laws[q['id']]['contract'];q['unresolved']='; '.join(next(p['unresolved_paths']for p in cat['procedures']if p['id']==q['id']))
(r/'evidence.json').write_text(json.dumps(ev,indent=2)+'\n')
from decompilation_annotations import render
render(r)
