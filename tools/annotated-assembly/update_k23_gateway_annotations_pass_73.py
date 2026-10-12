#!/usr/bin/env python3
"""Update only the gateway's proved own ranges and reviewed header."""
import json,re,subprocess
from pathlib import Path
from decompilation_annotations import header_lines
from run_k23_gateway_composition_pass_73 import REPORT,BASE,load
root=Path('research/annotated-assembly')
def original(name):return json.loads(subprocess.check_output(['git','show',BASE+':'+str(root/name)]))
def save(path,q):path.write_text(json.dumps(q,indent=2)+'\n')
cfg=load(REPORT/'cfg.json');observed={q['offset']for q in cfg if q['evidence']=='OBSERVED'}
assert sum(len(bytes.fromhex(q['bytes']))for q in cfg if q['offset']in observed)==271
law=load(REPORT/'contract-laws-PLI2.OVL.json')['PLI2.OVL+1FB5']['contract']
cat=original('procedures.json');p=next(p for p in cat['procedures']if p['id']=='PLI2.OVL+1FB5')
p['contract']=law;p['contract_scope']='Pass73 executable staged law for actual k23/57C6/count2/6036 with canonical predicate/handler domains, clear trace gates, full frame/alias guards. No native gateway installed; other state-defined scopes unsupported.'
p['unresolved_paths']=['Both trace-set regions remain RAW / STATIC / UNOBSERVED.','Other k/descriptor/handler domains and unsupported canonical child routes are excluded.','Generic proof dispatcher requires all invocations at an installed coordinate; k23 covers28/237. No shared dispatcher redesign or native gateway installation.']
p['observed_paths']['description']='Pass73: 28 full staged k23 shadows in five sources, all nested; 17 candidate successes and11 fallback routes. All271 gateway-own trace-clear bytes causally represented, with partial general contract. Original237-call inventory is retained.'
p['pseudocode']='Save exact twelve-byte mutable frame; actual047D result23 selects real descriptor/handler tables; actual scoped1DFF results drive candidate/fallback; compose canonical3E36 through PUSH42B4/PCHL/softwareRET; trace-clear restore then original hardwareRET. Reject all unsupported routes before live mutation.'
p['evidence_refs']=list(dict.fromkeys(p['evidence_refs']+['../host-compiler/pass-73/natural-inventory.json','../host-compiler/pass-73/component-shadows.json','../host-compiler/pass-73/contract-laws-PLI2.OVL.json']))
save(root/'procedures.json',cat)
asm=root/'PLI2.asm';text=subprocess.check_output(['git','show',BASE+':'+str(asm)],text=True);text=re.sub(r'; @procedure-v1 PLI2.OVL\+1FB5.*?; @end-procedure-v1 PLI2.OVL\+1FB5','\n'.join(header_lines(p)),text,flags=re.S)
m=original('manifest.json');im=next(i for i in m['images']if i['name']=='PLI2.OVL');promoted=0
for sec in im['sections']:
 if 0x1fb5<=sec['start_offset'] and sec['end_offset']<=0x20eb and sec['status']=='STRUCTURED':
  assert all(q['offset']in observed for q in cfg if sec['start_offset']<=q['offset']<sec['end_offset'])
  a,b=sec['start_offset'],sec['end_offset'];text=text.replace(f'; SECTION [{a:04X},{b:04X}) STRUCTURED',f'; SECTION [{a:04X},{b:04X}) UNDERSTOOD');sec['status']='UNDERSTOOD';promoted+=sec['length']
assert promoted==263
asm.write_text(text);save(root/'manifest.json',m)
e=original('evidence.json');seed=next(s for s in e['seeds']if s['id']=='PLI2.OVL+1FB5')
seed['behavioral_contract']=law;seed['behavioral_contract_ranges']=[[s['start_offset'],s['end_offset']]for s in im['sections']if s['status']=='UNDERSTOOD'and 0x1fb5<=s['start_offset']and s['end_offset']<=0x20eb]
seed['unresolved']='Pass73 k23 subset is staged and fully shadowed; other predicate/handler/trace routes remain unsupported. No native root installed.'
seed['pass73_evidence']=dict(report='../host-compiler/pass-73/natural-inventory.json',scoped_roots=28,native_root_installed=False)
save(root/'evidence.json',e)
save(REPORT/'knowledge-accounting.json',dict(promotions={'RAW -> UNDERSTOOD':0,'DECODED -> UNDERSTOOD':0,'STRUCTURED -> UNDERSTOOD':263},observed=263,synthetic_only_promotions=0,root_own_bytes=310,represented=271,unsupported_trace_bytes=39))
