"""Byte-exact indexed-carrier contracts; synthetic E6 scope remains unobserved."""
import os,runpy,json
from pathlib import Path
os.environ['RUNES_ANNOTATION_PASS']='58';os.environ['RUNES_ANNOTATION_BASE']='2c9bd0a2afa951080eaf57e2f73b797a1e0b1e13'
runpy.run_path(str(Path(__file__).with_name('update_buffered_rel_annotations_pass_52.py')),run_name='__main__')
r=Path('research/annotated-assembly');c=json.loads((r/'procedures.json').read_text());laws=json.loads(Path('research/host-compiler/pass-58/contract-laws-PLI2.OVL.json').read_text())
groups={
'PLI2.OVL+793C':[(0x793c,'save E atAE03 then C atAE02;freshAE03 CPI6'),(0x794a,'DEDUCED/UNOBSERVED: equal6 clears ADAB[savedC];JMP joins796B,not emission'),(0x7958,'non6:form source ADAB+freshE,PUSH H;independent destination ADAB+freshC;POP D;copy fresh byte'),(0x796b,'common:form source ADB3+freshE,PUSH H;independent destination ADB3+freshC;POP D;copy freshbyte'),(0x797e,'literalC40 canonical746F;fresh savedC andsavedE each canonical74C7'),(0x7991,'fresh savedC;ADD A three times;ORI40;ORA freshsavedE;canonical7557;RET')],
'PLI2.OVL+7B99':[(0x7b99,'save E atAE11 then C atAE10'),(0x7b9f,'fresh pairedAE10/11,C=low;canonical7AE4'),(0x7ba6,'independent pairedAE10/11,C=low;fresh pairedAE11/12,XCHG toDE;canonical793C;RET')]}
for p in c['procedures']:
 if p['id']not in laws:continue
 p['blocks']=[dict(offset=o,pseudocode=[t])for o,t in groups[p['id']]];p['pseudocode']='; '.join(t for o,t in groups[p['id']]);p['memory_state']=['AE10/AE11 saved root lowC/E;fresh pairedAE11 also readsAE12 intoD before child.','AE02/AE03 saved transfer indices;both pairedread neighbor channels preserved until explicitzeroextension.','ADAB..ADB2 andADB3..ADBA are bounded eight-byte carriers;indices0..7 scope,not an inferred globalcapacity.','F=entrySP;actual PUSH H source-address high/low slots belowF,POP D retains residue;childCALL/serviceframes independently derived.'];p['unresolved_paths']=['Indices outside0..7,unsupported childmodes/errors/positionwrap andscratch/stack/sentinel aliases excluded.','E6 branch is DEDUCED/UNOBSERVED from exactbytes plus synthetic equation tests;zero natural E6 calls.','Source-language/LINK-80 item semantics remainunproved.'];p['contract']=laws[p['id']]['contract']
(r/'procedures.json').write_text(json.dumps(c,indent=2)+'\n')
from decompilation_annotations import render
render(r)
