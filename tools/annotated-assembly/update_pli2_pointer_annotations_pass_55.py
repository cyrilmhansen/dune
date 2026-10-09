"""Pass55 byte-preserving bounded pointer-generation annotation epoch."""
import os,runpy
from pathlib import Path
os.environ['RUNES_ANNOTATION_PASS']='55'
os.environ['RUNES_ANNOTATION_BASE']='ea72db3c376d5f19898e795193fa0e514fbe974f'
runpy.run_path(str(Path(__file__).with_name('update_buffered_rel_annotations_pass_52.py')),run_name='__main__')
import json
root=Path('research/annotated-assembly');path=root/'procedures.json';cat=json.loads(path.read_text());p=next(p for p in cat['procedures']if p['id']=='PLI2.OVL+7701')
p['unresolved_paths']=['Mode-bit0-set arms[7764,776F),[7776,7779),[77B0,77B7) remain RAW / STATIC / UNOBSERVED; no inferred item semantics.','Writer failure,753C zero-wrap and arbitrary alias/nonwrapping pointer violations remain unsupported.','Seven-byte decrement/retry at7743 is DEDUCED / STATIC / UNOBSERVED with synthetic proof; not naturally executed.']
p['contract']=json.loads(Path('research/host-compiler/pass-55/contract-laws-PLI2.OVL.json').read_text())[p['id']]['contract']
p['blocks']=[dict(offset=o,pseudocode=[text])for o,text in[
(0x7701,'save BC pointer high then low;75F1(0);119E(8C,7);fresh1C2C minus2;canonical tag40 word'),
(0x771e,'ADEE=4;while ADEE!=0 and fresh byte[fresh pointer+ADEE]==20H: decrement sharedADEE and retry;independent masks via PSW/B carrier'),
(0x7743,'DEDUCED STATIC UNOBSERVED: LXI H,ADEE;DCR M;JMP7723. Natural executions0;synthetic retries prove state-driven decrement'),
(0x774a,'ADEE+=2;five byte doublings;119E(ADEE shifted5,3)'),
(0x775d,'fresh201D then201C RAR bit0 gates;set alternatives RAW/unsupported'),
(0x7779,'119E(3F,8);ADEC=0'),
(0x7785,'fresh ADEE minus2;CMP memoryADEC;JC exits only when index>limit'),
(0x7791,'independently fresh index and pointer;read pointed byte;publishADED;119E(byte,8)'),
(0x77a5,'fresh201C OR fresh201D;RAR bit0;set console/mode operation remains RAW,meaning unclaimed'),
(0x77b7,'increment sharedADEC;actual INR Z controls JNZ;RET consumes original CALL word')]]
p['pseudocode']='; '.join(b['pseudocode'][0]for b in p['blocks']);path.write_text(json.dumps(cat,indent=2)+'\n')
evpath=root/'evidence.json';ev=json.loads(evpath.read_text());seed=next(e for e in ev['seeds']if e['id']==p['id']);seed['unresolved']='; '.join(p['unresolved_paths']);seed['behavioral_contract']=p['contract'];evpath.write_text(json.dumps(ev,indent=2)+'\n')
from decompilation_annotations import render
render(Path('research/annotated-assembly'))
