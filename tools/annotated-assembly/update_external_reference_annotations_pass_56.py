"""Byte-preserving Pass56 scoped preparation and saved-pointer contracts."""
import os,runpy,json
from pathlib import Path
os.environ['RUNES_ANNOTATION_PASS']='56'
os.environ['RUNES_ANNOTATION_BASE']='315142f4a4dbfaae933f2bbdaeb6ac66048d65d1'
runpy.run_path(str(Path(__file__).with_name('update_buffered_rel_annotations_pass_52.py')),run_name='__main__')
root=Path('research/annotated-assembly');path=root/'procedures.json';cat=json.loads(path.read_text());laws=json.loads(Path('research/host-compiler/pass-56/contract-laws-PLI2.OVL.json').read_text())
for p in cat['procedures']:
 if p['id']not in laws:continue
 p['contract']=laws[p['id']]['contract'];p['semantic_hypothesis']=None
 memories={
 'PLI2.OVL+79E2':['AE05 is a freshly read one-byte preparation gate; no writes on supported zero route.'],
 'PLI2.OVL+7A17':['AE04 is independently freshly read one-byte preparation gate; no writes on supported zero route.'],
 'PLI2.OVL+73D0':['ADAA is a one-byte bit0 reset gate, published zero only on set route.','ADC4 is a one-byte index initialized zero, ending8; paired LHLD also freshly reads ADC5 before H is discarded.','ADAB..ADB2 are eight contiguous bytes published zero in increasing index order.'],
 'PLI2.OVL+8225':['AE61 is saved input C; paired reload also freshly reads AE62 before H is discarded by tag argument transfer.','AE62/AE63 is saved input DE little-endian; high then low writes, independently fresh paired reload before7701.','Preparation children and756D do not write these carriers on the proved scope.'],
 'PLI2.OVL+8248':['AE64/AE65 is saved input BC little-endian; high then low stores followed by independent paired reload and XCHG.']}
 p['memory_state']=memories[p['id']]+['F=entrySP;original hardware return word at F survives;child CALL/save/service traffic below F is derived operation by operation.']
 groups={
 'PLI2.OVL+73D0':[(0x73d0,'fresh ADAA;RAR;bit0-clear returns actual rotated A;set branches to reset'),(0x73d8,'publish ADAA=0,ADC4=0'),(0x73e2,'fresh index;literal7 CMP index;JC exits iff index>7'),(0x73eb,'independently paired-read ADC4/ADC5;zeroextend low;publish byte[ADAB+index]=0'),(0x73f6,'fresh ADC4 increment;INR Z controls JNZ;final comparison flags survive RET')],
 'PLI2.OVL+8225':[(0x8225,'save D/E/C atAE63/AE62/AE61 in exact order'),(0x822d,'canonical freshAE05 gate,independentAE04 gate,and conditional indexed reset'),(0x8236,'freshly reread saved tag plus adjacent pointer-low;C=tag,E9;canonical756D'),(0x823f,'freshly reread saved pointer;BC=word[AE62];canonical7701;RET actual child state')],
 'PLI2.OVL+8248':[(0x8248,'save BC high then low;fresh reload;XCHG toDE;literalC4;canonical8225;RET')]}
 if p['id']in groups:
  p['blocks']=[dict(offset=o,pseudocode=[text])for o,text in groups[p['id']]];p['pseudocode']='; '.join(text for o,text in groups[p['id']])
 p['unresolved_paths']=['NonzeroAE05/AE04 generation arms remain RAW/unsupported. C4 and higher-level REL item meaning unproved.','Child writer error,position wrap,and arbitrary aliases remain outside accumulated bounded contracts.']if p['id']!='PLI2.OVL+73D0'else ['Low-level indexed reset is complete; source-language role of carrier remains unproved.']
# Distinguish total observed inventory from the clear-route proof subset.
inventory=json.loads(Path('research/host-compiler/pass-56/inventory-summary.json').read_text())
q=next(p for p in cat['procedures']if p['id']=='PLI2.OVL+7A17')
q['observed_paths']['invocations_by_run']={source:g[q['id']]['logical']for source,g in inventory.items()}
q['observed_paths']['description']='All natural calls8/41/10 inventoried;independent shadow covers AE04-zero8/38/10. Three FIZZBUZ nonzero calls are OBSERVED outside the supported scope,not promoted. Only9 clear-route bytes represented.'
callers={}
for source,g in inventory.items():
 for site,n in g[q['id']]['callers'].items():callers.setdefault(site,{})[source]=n
q['callers']=[dict(coordinate=site,counts_by_run=counts)for site,counts in sorted(callers.items())]
path.write_text(json.dumps(cat,indent=2)+'\n')
evpath=root/'evidence.json';ev=json.loads(evpath.read_text())
for q in ev['seeds']:
 if q['id']in laws:q['behavioral_contract']=laws[q['id']]['contract'];q['unresolved']='; '.join(next(p['unresolved_paths']for p in cat['procedures']if p['id']==q['id']))
evpath.write_text(json.dumps(ev,indent=2)+'\n')
from decompilation_annotations import render
render(root)
