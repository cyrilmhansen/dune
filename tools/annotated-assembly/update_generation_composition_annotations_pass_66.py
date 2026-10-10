"""Reviewed Pass66 carrier provenance and local composition blocks, byte-preserving."""
import collections,json
from pathlib import Path
from decompilation_annotations import render
r=Path('research/annotated-assembly');cat=json.loads((r/'procedures.json').read_text());roles=json.loads((r/'data-roles.json').read_text());p=next(p for p in cat['procedures']if p['id']=='PLI2.OVL+8072')
p['inputs']='C/D/E byte carriers; fresh saved selector4 chooses canonical7A17. Entire required canonical7ED6/7338/75CE/7619 domain, exact code/CALL/continuation, supported indices/output/position/pending routes and stack/scratch/sentinel nonalias. State-driven; no source/caller/ordinal dispatch.'
p['memory_state']=['AE44=C, AE45=E, AE46=D; entry writes D then E then C.','All six parent LHLD acquisitions read low then high independently, including adjacent E in AE44 word.','No private frame. Original hardware CALL word persists at entrySP; nested CALL residue remains below it. Canonical child scratch/table/output effects are inherited.']
p['blocks']=[dict(offset=o,pseudocode=[s])for o,s in[(0x8072,'Publish D->AE46,E->AE45,C->AE44 in order. Fresh selector CPI4 selects7A17 when equal.'),(0x8085,'Fresh wordAE44 sets C=L; independent wordAE45 XCHG restores E/D. Call canonical7ED6.'),(0x8090,'RAR actual child A: CY=oldA.bit0, A=(oldCY<<7)|(oldA>>1), NZPA preserved. Success CYset RET8094; clear continues.'),(0x8095,'Fallback only: independently reacquire C fromAE44 and DE fromAE45; canonical7338 publishes adjacent relation pair.'),(0x80a0,'Fresh wordAE44 XCHG ->DE, E=savedC,D=adjacent savedE; C=1; canonical75CE emits the selector field.'),(0x80a9,'Independent wordAE45 ->BC=savedE low/savedD high; canonical7619; return final child registers/flags throughRET80B1.')]]
p['pseudocode']='; '.join(b['pseudocode'][0]for b in p['blocks']);p['unresolved_paths']=['All primary and cross natural roots take fallback. Success RET8094 independently concreteCPU proved but DEDUCED STATIC UNOBSERVED.','Arbitrary pending/error/output/position/index/alias domains outside canonical children remain unsupported and reject before mutation.','Higher compiler/source-language meaning remains HYPOTHESIS. +80B2 following operation is separate and unmigrated.']
p['returns']['sites_description']='Natural RET80B1; synthetic-only success RET8094 consumes actual original CALL word.'
for name,address,width,role in [('composition_saved_selector',0xae44,1,'Input C, freshly reread for predicate and lower operation arguments.'),('composition_saved_relation',0xae45,2,'E low/D high input word saved high-to-low; independently reread for7ED6,7338,7619.')]:
 ident='PLI2.OVL:'+name
 if not any(q['id']==ident for q in roles['roles']):roles['roles'].append(dict(id=ident,image='PLI2.OVL',image_sha256=p['image_sha256'],name=name,runtime_address=address,width=width,role=role,scope='Pass66 +8072 bounded generation composition.'))
 if ident not in p['data_role_ids']:p['data_role_ids'].append(ident)
for source in ['FACTOR','OPTIMIST']:
 rows=json.loads((Path('_build/host-compiler-pass-66')/(source+'-natural-cases.json')).read_text())['sources'][0]['entries'][0]['members'];p['observed_paths']['invocations_by_run'][source]=len(rows)
 counts={c['coordinate']:c['counts_by_run']for c in p['callers']}
 for c,n in collections.Counter(q['caller']for q in rows).items():counts.setdefault(c,{})[source]=n
 p['callers']=[dict(coordinate=c,counts_by_run=ns)for c,ns in sorted(counts.items())]
 p['evidence_refs']=list(dict.fromkeys(p['evidence_refs']+['../host-compiler/pass-66/cross-evidence.json']))
(r/'data-roles.json').write_text(json.dumps(roles,indent=2)+'\n');(r/'procedures.json').write_text(json.dumps(cat,indent=2)+'\n');render(r)
