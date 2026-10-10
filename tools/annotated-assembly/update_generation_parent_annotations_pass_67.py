"""Reviewed software-continuation and mapped-word provenance; no byte rewriting."""
import collections,json
from pathlib import Path
from decompilation_annotations import render
from run_generation_parent_discovery_pass_67 import REPORT,OUT,LAWS
r=Path('research/annotated-assembly');cat=json.loads((r/'procedures.json').read_text());ev=json.loads((r/'evidence.json').read_text());roles=json.loads((r/'data-roles.json').read_text());entries={p['id']:p for p in cat['procedures']};seeds={s['id']:s for s in ev['seeds']}
for offset in LAWS:
 key=f'PLI2.OVL+{offset:04X}';p=entries[key]
 p['contract_scope']='Exact historical byte/register operations at the explicitly bounded Pass67 domains; fixed scratch/table/code/stack/sentinel exclusions and canonical child supported states. No inferred table capacity or compiler meaning.'
 p['unresolved_paths']=['Higher compiler/source-language meaning remains unproved.']
 p['inputs']='Actual input channels, fresh byte-addressed state and supported canonical child domains; exact immutable code/continuation, safe stack and nonalias carriers. Byte index zero-extension does not assert a source-level table capacity.'
 p['memory_state']=['All numeric addresses remain runtime memory, not host arrays. Writes, independent paired reads, PSW carriers and actual child CALL residue are retained.']
 if offset==0x6ea5:
  p['inputs']='PCHL selected from fresh word AD1F=90A5 after gateway20AC/20AF/20B0; actual PUSH-H continuation42B4 at entrySP. Fresh lowAD0C mapped selector and canonical generation/output state; supported0400-clear mapped words, child/mode/position/alias/code scopes.'
  p['outputs']='Actual final8248 returned registers/flags; software RET6F18 consumes42B4, finalSP=entrySP+2. Local publications AD9F/ADA2/ADA4/ADA0 and canonical child effects.'
  p['returns']['convention']='Explicit PUSH H software continuation42B4, entered by PCHL without a hardware CALL; RET6F18 consumes the original slot, SP+=2.'
  p['returns']['sites_description']='RET6F18 to gateway20B4; child CALL frames are separate hardware continuations.'
  p['memory_state']+=['AD0C/AD0D paired source; ABFD..AC01 mapped acquisition scratch; AD9F clear; ADA2 word; ADA4 mask; ADA0 position word.','entrySP slot was written high42 then lowB4 by20AF PUSH H. PCHL writes no stack bytes. Child writes remain below that slot; original software word unchanged.']
  p['unresolved_paths']+=['0400-nonzero recursive1FB5 arms6ECA..6ED1 and6EEF..6EF8 remain RAW / STATIC / UNOBSERVED / unsupported. Both accepted final bit80 routes are naturally observed across primary/cross evidence.','Arbitrary pending/error/position/output/alias states outside canonical children reject staging.']
  p['blocks']=[dict(offset=o,pseudocode=[s])for o,s in [(0x6ea5,'ClearAD9F; fresh lowAD0C ->mapped052C; publish actual word toADA2.'),(0x6eb4,'Mask0400 through8350; actual1A29 subtraction and OR/ADI/SBB mask ->ADA4; supported carry-clear skips independent recursive gateway.'),(0x6ed1,'FreshADA2 ->DE,C2 ->canonical8072. Canonical742A reset/publication/read ->ADA0. LiteralDE0,C0 ->canonical8072.'),(0x6ee8,'FreshADA4 RAR must be clear.8357 freshly masksADA2 low/high with80; actual1A29/OR flags select8F69 or8F6E.'),(0x6f09,'Nonzero bit80 route selects literal8F69 ->canonical8248; independent of primary-only8F6E route.'),(0x6f12,'Zero bit80 route selects literal8F6E ->canonical8248. Both return through actual software slot at6F18.')]]
  p['local_comments']['6F18']='consume explicit PUSH-H software continuation42B4; SP+=2; preserve final canonical8248 registers/flags'
  seed=seeds[key];sample=seed['matched_return_sample'];own=json.loads((REPORT/'ownership-map.json').read_text())['MINIMAL'][0]
  seed['software_return_sample']=dict(kind='pass67_push_h_pchl',gateway=own['gateway'],entry=json.loads((OUT/'rows.json').read_text())['MINIMAL'][key][0]['entry'],relation='OBSERVED PUSH-H/PCHL software window, distinct from N2/N8 argument-consuming continuations',call=sample['call'],writer=own['gateway'][1],ret=sample['ret'],original_slot=own['entry_SP'],continuation=0x42b4)
  seed['matched_return_sample']=None
  for c in seed['observed_callers']:c['bytes']='E9';c['transfer_kind']='PCHL'
 elif offset==0x8350:
  p['unresolved_paths']+=['Static834D prefix falls into this CALL-selected shared tail, but is not migrated or asserted as a new understood entry.']
 p['pseudocode']='; '.join(b['pseudocode'][0]for b in p['blocks'])
 for source in ['FACTOR','OPTIMIST']:
  groups=json.loads((OUT/'proof'/(source+'-natural-cases.json')).read_text())['sources'][0]['entries'];g=next(g for g in groups if g['offset']==offset);p['observed_paths']['invocations_by_run'][source]=len(g['members'])
  counts={c['coordinate']:c['counts_by_run']for c in p['callers']}
  for c,n in collections.Counter(q['caller']for q in g['members']).items():counts.setdefault(c,{})[source]=n
  p['callers']=[dict(coordinate=c,counts_by_run=v)for c,v in sorted(counts.items())]
  if offset==0x6ea5:
   ins=json.loads((OUT/'proof'/(source+'-natural-instruction-witnesses.json')).read_text());ins=[w for w in ins if w['owner']==key];by=collections.defaultdict(list)
   for w in ins:by[w['offset']].append(w['step_index'])
   for q in seeds[key]['instructions']:
    steps=by[q['offset']]
    if steps:q['runs'].append(dict(run=source,execution_count=len(steps),first_step=min(steps),last_step=max(steps)))
  p['evidence_refs']=list(dict.fromkeys(p['evidence_refs']+['../host-compiler/pass-67/ownership-map.json','../host-compiler/pass-67/cross-evidence.json']))
for name,address,width,role in [('paired_handler_word',0xada2,2,'Actual mapped word; fresh DE acquisition for first8072 and later pointed mask.'),('paired_handler_gate',0xada4,1,'Published0400 nonzero mask; independently reread after paired operations.'),('paired_handler_position',0xada0,2,'Actual742A returned fresh1C2C, published low then high.'),('mapped_word_selector',0xac01,1,'Saved low selector independently reread for the two byte lookups.'),('mapped_word_components',0xabff,2,'Low C atABFF, high E atAC00; paired read and shift/OR composition.')]:
 p=entries['PLI2.OVL+6EA5'];ident='PLI2.OVL:'+name
 if not any(q['id']==ident for q in roles['roles']):roles['roles'].append(dict(id=ident,image='PLI2.OVL',image_sha256=p['image_sha256'],name=name,runtime_address=address,width=width,role=role,scope='Pass67 bounded software handler and mapped-word descendants.'))
 if ident not in p['data_role_ids']:p['data_role_ids'].append(ident)
for name,value in [('procedures',cat),('evidence',ev),('data-roles',roles)]: (r/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
render(r)
