"""Reviewed mutable hardware-stack storage and bounded descendant scopes."""
import json,subprocess
from pathlib import Path
from decompilation_annotations import render
from run_predicate_generation_pass_68 import REPORT,LAWS,BASE
r=Path('research/annotated-assembly');cat=json.loads((r/'procedures.json').read_text());roles=json.loads((r/'data-roles.json').read_text());entries={p['id']:p for p in cat['procedures']}
for o in LAWS:
 p=entries[f'PLI2.OVL+{o:04X}'];p['contract_scope']='Independently shadowed Pass68 natural and explicitly DEDUCED concrete-CPU routes. Unsupported branches reject transactionally; fixed scratch/code/table/stack/sentinel exclusions and inherited canonical child domains. No source/caller/ordinal dispatch.'
 p['unresolved_paths']=['Compiler/source-language meaning remains unproved.']
 if o==0x3d10:
  p['inputs']='Fresh AD08/AD0B/AD0C/AD0D/AD0E, two-level mapped byte/word channels, original hardware CALL word, safe mutable three-byte stack storage and supported generation/emission state.'
  p['outputs']='Actual registers/flags from the selected canonical child path, then historical POP H from mutable local bytes. Original hardware RET to caller continuation; final SP=entrySP+2. Full output/service chronology and ordered scratch/stack/table publications.'
  p['returns']['convention']='DCX SP; PUSH H creates frameSP=entrySP-3. INX SP; POP H reads entrySP-2/-1, which are local-word low/high on the observed route. RET consumes untouched original entrySP word.'
  p['unresolved_paths']+=['First predicate clear requires unresolved 1FB5 gateway; unsupported and unobserved in all five natural sources.','Changed-second-predicate branches 3D62/3D9B remain unsupported; 83DC is only a statically decoded child on that excluded arm.','Natural word route and DEDUCED mapped-byte zero/nonzero routes supported only within bounded canonical child domains.']
  p['blocks']+= [dict(offset=0x3d20,pseudocode=['Consume actual 3660 A.bit0 through RAR; select mapped local byte or mapped local word.']),dict(offset=0x3d6f,pseudocode=['Fresh AD0D low ->3790. Write actual returned HL low/high at entrySP-2/-1; reread separately for C4 generation.']),dict(offset=0x3de1,pseudocode=['INX SP; POP H consumes mutable local bytes; RET original hardware continuation.'])]
 elif o==0x3790:p['unresolved_paths']+=['Negative byte extension through actual CALL target839B remains static unsupported.']
 elif o==0x7897:p['unresolved_paths']+=['Matched immutable selector-table routes remain unsupported; literal22/32 supported no-match scans and bit0-clear return.']
 elif o==0x785c:p['unresolved_paths']+=['201D listing-set route remains unsupported.']
 elif o==0x77cc:p['unresolved_paths']+=['Types11H/10H pointer-generation calls78B2/78DB remain unsupported.']
 elif o==0x7b02:p['unresolved_paths']+=['E9/7413 alternate emission remains unsupported.']
 p['evidence_refs']=list(dict.fromkeys(p['evidence_refs']+['../host-compiler/pass-68/natural-inventory.json','../host-compiler/pass-68/stack-proof.json','../host-compiler/pass-68/cfg.json']))
# Preserve the already-reviewed V1 surface of the pre-existing class lookup.
old=json.loads(subprocess.check_output(['git','show',BASE+':research/annotated-assembly/procedures.json']))
prior=next(p for p in old['procedures']if p['id']=='PLI2.OVL+047D')
for field in ['inputs','outputs','memory_state','local_comments','pseudocode','blocks']:
 entries['PLI2.OVL+047D'][field]=prior[field]
for name,address,width,meaning in [('predicate_handler_state',0xad0b,4,'Fresh independent mapped selectors at AD0B/AD0C/AD0D/AD0E; adjacent LHLD channels are retained.'),('structure_emission_state',0xadf3,12,'Saved pointer, fresh target+2/+3, pointed-word sum, position snapshot and selector scan intermediates.'),('saved_tag22_word',0xae19,3,'Saved B/C word and independently saved mapped selector for tag22 composition.'),('saved_tag32_word',0xae25,3,'Synthetic-only saved B/C word and independently saved mapped selector for tag32 composition.')]:
 ident='PLI2.OVL:'+name;p=entries['PLI2.OVL+3D10']
 if not any(q['id']==ident for q in roles['roles']):roles['roles'].append(dict(id=ident,image='PLI2.OVL',image_sha256=p['image_sha256'],name=name,runtime_address=address,width=width,role=meaning,scope='Bounded Pass68 predicate handler and required descendants.'))
 if ident not in p['data_role_ids']:p['data_role_ids'].append(ident)
(r/'procedures.json').write_text(json.dumps(cat,indent=2)+'\n');(r/'data-roles.json').write_text(json.dumps(roles,indent=2)+'\n');render(r)
