"""Scoped Pass72 rendering; preserve every unrelated reviewed catalog header."""
import hashlib, json, os, re, subprocess
from pathlib import Path
from decompilation_annotations import render
from run_k23_handler_pass_72 import BASE, OUT, REPORT, LAWS, IMAGES, load, save

subprocess.run(['python3','tools/annotated-assembly/update_buffered_rel_annotations_pass_52.py',IMAGES,'PLI2.OVL'],
               env={**os.environ,'RUNES_ANNOTATION_PASS':'72','RUNES_ANNOTATION_BASE':BASE},check=True)
r=Path('research/annotated-assembly')
cat=load(r/'procedures.json');ev=load(r/'evidence.json');roles=load(r/'data-roles.json')
baseline=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))
prior={p['id']:p for p in baseline['procedures']}
changed={f'PLI2.OVL+{o:04X}'for o in LAWS}
for i,p in enumerate(cat['procedures']):
    if p['id'] not in changed and p['id'] in prior:cat['procedures'][i]=prior[p['id']]
by={p['id']:p for p in cat['procedures']}
for key in changed:
    p=by[key]
    p['contract_scope']='Pass72 state-defined scoped software handler or bounded direct helper. Exact concrete CPU and canonical child shadows; staged full transaction, supported child domains, code/stack/table/scratch/sentinel guards. No caller/source/ordinal dispatch.'
    p['unresolved_paths']=['Compiler/source-language meaning remains unproved; inherited canonical child unsupported domains remain excluded.']
    p['evidence_refs']=list(dict.fromkeys(p['evidence_refs']+['../host-compiler/pass-72/natural-handler-inventory.json','../host-compiler/pass-72/stack-proof.json','../host-compiler/pass-72/cfg.json']))
p=by['PLI2.OVL+3E36']
p['observed_paths']['description']='OBSERVED software PUSH-H/PCHL windows in all five sources; 11 AD0A=0 mapped-byte and 17 AD0A=1 mapped-word paths. Synthetic-only byte-zero/word paths are separately DEDUCED/UNOBSERVED.'
p['inputs']='Fresh AD0A, independent AD0C/AD0B mapped channels, AD08 bit predicate, AD58 adjacent read channel, output/generation state; software entry from exact gateway prefix, fresh AD1F=6036, original software continuation42B4 and bounded children.'
p['outputs']='Actual selected canonical child registers/flags, ordered scratch/table/output writes and hardware child CALL residue; software RET consumes gateway PUSH42B4, final SP=entrySP+2 and PC=42B4.'
p['returns']['convention']='Software PUSH-H/PCHL entry, not hardware CALL. Gateway20AF writes B4/42; PCHL20B3 leaves SP unchanged; RET3EF5 consumes that same word.'
p['memory_state']=['AD0A fresh path selector; AD0C independent mapped input; AD58 saved selector only on AD0A=1 arm.','Software continuation at entrySP written by gateway20AF, child CALL frames below it; no private handler frame.']
p['unresolved_paths']+=['AD0A=0 mapped047D result other than10 calls broad1FB5; unobserved and unsupported.','AD0A outside0/1 and selector1 actual3660 bit set through7E75 remain static unsupported.','Gateway1FB5 and descriptor1DFF remain guest; no scoped gateway-native chain claimed.']
p['local_comments']['3EF5']='Consume gateway20AF PUSH-H software continuation42B4; SP+=2; preserve actual last child registers and flags.'
p['blocks'] += [dict(offset=0x3e4a,pseudocode=['Consume actual3660 A.bit0 through RAR. Clear selects fresh052C word/XCHG/C4 ->8072; set selects fresh04FF byte and exact zero/nonzero child path.']),dict(offset=0x3eba,pseudocode=['Fresh AD0A CPI1; supported1 publishes fresh AD0C toAD58. Actual3660 bit clear selects fresh pairedAD58 low ->7BCC.']),dict(offset=0x3ef5,pseudocode=['RET consumes gateway software continuation, not an invented hardware CALL.'])]
for c in p['callers']:c['transfer_kind']='PCHL'
seed=next(s for s in ev['seeds']if s['id']==p['id'])
seed['matched_return_sample']=None
seed['software_return_sample']=load(OUT/'software-return-sample.json')
for c in seed['observed_callers']:c.update(bytes='E9',transfer_kind='PCHL')
p=by['PLI2.OVL+1DFF']
p['observed_paths']['description']='Historical invocation totals retain prior evidence; Pass72 independently proves only the state-defined k23 subset: MINIMAL3/FIZZBUZ27/PICTURE1/FACTOR6/OPTIMIST13. Other old descriptor paths are not promoted by those counts.'
p['inputs']='C cursor; AD1C=23, AD1D pointer57C7/count1/token05,57C9/count3/token69 or3BF3/count1/tokenFB; actual mapped tables and bounded0992 termination domain.'
p['outputs']='Actual A0 mismatch or A1 exhausted-count result with instruction-derived flags; AD21/22/23/25/26 and AD0B/positions/cache writes, exact PSW and child CALL residue. No output/service effects in this subset.'
p['unresolved_paths']=['Only k23 descriptor subset is executable:69 matching beyond its first literal is excluded.','Repeated-cache and ED..FA/FC..FF paths, other descriptor families and arbitrary nonterminating marker walks remain unsupported.','No global native1DFF root or native1FB5 gateway installed.']
p['blocks'] += [dict(offset=0x1e43,pseudocode=['Decrement fresh cursor, PUSH PSW, increment processed count; POP B carries cursor to positions[processed].']),dict(offset=0x1f98,pseudocode=['First FB cache use publishes processed position toslot0; canonical0992 returns actual new cursor; zero remaining count returns1.'])]
# The generic authoring utility preserves historical instruction witnesses. They
# are not all new semantic proof: keep unproved prior STRUCTURED bytes unchanged.
man=load(r/'manifest.json')
oldman=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/manifest.json']))
im=next(x for x in man['images']if x['name']=='PLI2.OVL')
oldim=next(x for x in oldman['images']if x['name']=='PLI2.OVL')
oldstatus={a:s['status']for s in oldim['sections']for a in range(s['start_offset'],s['end_offset'])}
allowed={a for q in load(REPORT/'cfg.json')if q['evidence']!='STATIC UNOBSERVED unsupported'for a in range(q['offset'],q['offset']+len(bytes.fromhex(q['bytes'])))}
image=Path(IMAGES,'PLI2.OVL').read_bytes();sections=[]
for section in im['sections']:
    a,b=section['start_offset'],section['end_offset'];start=a
    def status(o):return oldstatus[o]if section['status']=='UNDERSTOOD'and o not in allowed and oldstatus[o]!='UNDERSTOOD'else section['status']
    for end in range(a+1,b+1):
        if end==b or status(end)!=status(start):
            q={**section,'start_offset':start,'end_offset':end,'length':end-start,
               'runtime_start':start+im['runtime_base'],'runtime_end':end+im['runtime_base'],'status':status(start)}
            q['original_sha256']=q['reassembled_sha256']=hashlib.sha256(image[start:end]).hexdigest()
            sections.append(q);start=end
im['sections']=sections
starts={q['start_offset']:q for q in sections}
source=r/im['source'];lines=[]
for line in source.read_text().splitlines():
    if line.startswith('; SECTION '):continue
    match=re.match(r'PLI2_([0-9A-F]{4}): (?!EQU)',line)
    if match and int(match[1],16)in starts:
        q=starts[int(match[1],16)];lines.append(f"; SECTION [{q['start_offset']:04X},{q['end_offset']:04X}) {q['status']}")
    lines.append(line)
source.write_text('\n'.join(lines)+'\n')
for key in changed:
    p=by[key]
    p['observed_paths']['represented_bytes']=sum(q['length']for q in sections if q['status']=='UNDERSTOOD'and p['start_offset']<=q['start_offset']and q['end_offset']<=p['end_offset'])
predicate=next(s for s in ev['seeds']if s['id']=='PLI2.OVL+1DFF')
predicate['behavioral_contract_ranges']=[[q['start_offset'],q['end_offset']]for q in sections if q['status']=='UNDERSTOOD'and 0x1dff<=q['start_offset']and q['end_offset']<=0x1fb5]
p=by['PLI2.OVL+3E36']
for name,address,width,law in [('handler_saved_selector',0xad58,2,'AD58 saved selector, AD59 independently read adjacent channel; only low becomes C.'),('tag2A_saved_word',0xae12,2,'B saved at AE13 then C at AE12, fresh word reread after preparation and tag emission.'),('tag2A_mapped_selector',0xae14,2,'C saved at AE14, independent paired AE14/AE15 acquisition; low forwarded to052C.')]:
    ident='PLI2.OVL:'+name
    if not any(q['id']==ident for q in roles['roles']):
        roles['roles'].append(dict(id=ident,image='PLI2.OVL',image_sha256=p['image_sha256'],name=name,runtime_address=address,width=width,role=law,scope='Bounded Pass72 software handler and direct adapters.'))
    if ident not in p['data_role_ids']:p['data_role_ids'].append(ident)
# Ordinary helper RETURN comments remain hardware; only3EF5 is software.
for file,data in [('procedures.json',cat),('evidence.json',ev),('data-roles.json',roles),('manifest.json',man)]:
    (r/file).write_text(json.dumps(data,indent=2)+'\n')
render(r)
