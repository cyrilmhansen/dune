"""Reviewed low-level Pass65 names, blocks and completeness; preserves bytes."""
import json
from pathlib import Path
from decompilation_annotations import render
r=Path('research/annotated-assembly');cat=json.loads((r/'procedures.json').read_text());roles=json.loads((r/'data-roles.json').read_text());by={p['id']:p for p in cat['procedures']};root=by['PLI2.OVL+7ED6']
root['inputs']='Entry C0..7 andD/Ebytes; active nonreserved paths C0..5 for adjacent indices. Fresh202B/ADAA bit0 gates, ADAB/ADB3 indexed state. Exact own/child/CALL code and original continuation; canonical child output/position/gate domains; scratch/table/stack/sentinel nonalias. No source/caller/ordinal dispatch.'
root['memory_state']=['AE3A=C,AE3B=E,AE3C=D saved in reverse address order; fresh paired reads retain adjacent channels.','AE3D scanindex0..8,AE3E/F current adjacent-table word,AE40/41 splitD/E,AE42/43 candidateindices initializedFF and retained across iterations.','202B/ADAA bit0 gates; ADAB[C]/ADAB[C+1] activity; ADB3[C]/ADB3[C+1] adjacent word and per-index values.','Ordinary CALL808D continuation A290 atentrySP; PUSH H/POP H address carriers and canonical childCALLs below it.']
root['blocks']=[dict(offset=o,pseudocode=[s])for o,s in[(0x7ed6,'Save D,E,C atAE3C/B/A; fresh202B.bit0set ->A0; freshADAA.bit0clear ->A0; freshC==6 ->A0; preserve producingflags.'),(0x7efd,'Independently reread/zeroextendC. PUSH ADAB+C; readADAB+C+1; POP H; ANA firstactivity,RAR conjoinedbit0.'),(0x7f15,'Fresh ADB3[C]<<8 through83B4; freshADB3[C+1] OR through8398; publish wordAE3E. Canonical1A43 and83D2 compare freshsavedDE-current against3.'),(0x7f49,'If forward distance0..2: independently compare freshwords eachiteration;7D47 emits/increments adjacent relation; increment wordAE3E until equality,returnA1.'),(0x7f6f,'Otherwise independently test reverse distance0..2;7D85 emits/decrements adjacent relation andwordAE3E until equality,returnA1. Far values fall through.'),(0x7fa7,'SavedD ->AE40, savedE ->AE41; independent7365(C,D),RAR match ->7E05(C+1,E); else7365(C+1,E),RAR match ->7E05(C,D); returnA1.'),(0x7fee,'AE42/43=FF,AE3D=0. Fresh7 CMP index:scan0..7;skip6.8015 tests(index,D);802B tests(index,E) andexcludessecondcandidate==savedC. Candidatepublicationspersist.'),(0x8042,'FreshcandidateOR,RLC,RAR tests oldbit7. Bothvalid ->793C(C,first),freshC INR ->793C(C+1,second); returnA1.'),(0x8068,'INR freshAE3D publishesindex beforebackedge;index8 fails7 CMP andreturnsA0 withactualcomparisonflags.')]]
root['pseudocode']='; '.join(b['pseudocode'][0]for b in root['blocks']);root['unresolved_paths']=['Compiler-level meaning remains unproved; representation-level policy only.','Primary17early-gate andonePICTURE failedscan areOBSERVED. Otherrepresentedpaths/helpers independentlyoriginal-CPUproved DEDUCED STATIC UNOBSERVED.','ActiveC7,unsupported canonical output/pending modes,errors,positionwrap and code/scratch/table/stack/sentinel aliases rejected before live mutation.']
for name,address,width,text in [('policy_saved_selector',0xae3a,1,'Fresh saved C for paired/index policy.'),('policy_saved_relation_pair',0xae3b,2,'Little-endian E low/D high save.'),('policy_scan_index',0xae3d,1,'Published scan index0..8,skip6.'),('policy_current_word',0xae3e,2,'Freshly formed adjacent-table word,independently reread during bounded adjustment.'),('policy_split_relations',0xae40,2,'Saved D atAE40,E atAE41 for independent predicate calls.'),('policy_candidate_indices',0xae42,2,'FF sentinels;independent successful candidates persist across iterations.')]:
 ident='PLI2.OVL:'+name
 if not any(q['id']==ident for q in roles['roles']):roles['roles'].append(dict(id=ident,image='PLI2.OVL',image_sha256=root['image_sha256'],name=name,runtime_address=address,width=width,role=text,scope='Bounded Pass65 +7ED6 generation relation policy.'))
 if ident not in root['data_role_ids']:root['data_role_ids'].append(ident)
# Preserve primary counts and add independently shadowed natural cross-source calls.
for source in ['FACTOR','OPTIMIST']:
 path=Path('_build/host-compiler-pass-65')/(source+'-natural-cases.json')
 for e in json.loads(path.read_text())['sources'][0]['entries']:
  key=f"PLI2.OVL+{e['offset']:04X}"
  if key not in ['PLI2.OVL+7ED6','PLI2.OVL+7D47','PLI2.OVL+7D85','PLI2.OVL+8398','PLI2.OVL+83B4','PLI2.OVL+83D2']:continue
  p=by[key];p['observed_paths']['invocations_by_run'][source]=len(e['members'])
  counts={c['coordinate']:c['counts_by_run']for c in p['callers']}
  from collections import Counter
  for c,n in Counter(q['caller']for q in e['members']).items():counts.setdefault(c,{})[source]=n
  p['callers']=[dict(coordinate=c,counts_by_run=ns)for c,ns in sorted(counts.items())]
  p['evidence_refs']=list(dict.fromkeys(p['evidence_refs']+['../host-compiler/pass-65/cross-evidence.json','../host-compiler/pass-65/cross-instruction-evidence.json']))
for p in cat['procedures']:
 if p['id']in ['PLI2.OVL+7D47','PLI2.OVL+7D85','PLI2.OVL+8398','PLI2.OVL+83B4','PLI2.OVL+83D2']:
  p['unresolved_paths']=['Required bounded routes independently concreteCPU proved; arbitrary output/error/alias states excluded.','Natural primary/cross-helper counts are recorded; independently traced cross instructions are OBSERVED. Remaining synthetic-only instructions are DEDUCED STATIC UNOBSERVED.']
  for c in p['direct_callees']:c['evidence_status']='DEDUCED STATIC UNOBSERVED'if not p['observed_paths']['invocations_by_run'].get('PICTURE',0)else'OBSERVED'
by['PLI2.OVL+83B4']['unresolved_paths'].append('Preceding83B0 prefix falls into83B4 statically; no natural CALL83B0 in the primary inventory. Prefix remains RAW and outside this accepted entry.')
(r/'data-roles.json').write_text(json.dumps(roles,indent=2)+'\n');(r/'procedures.json').write_text(json.dumps(cat,indent=2)+'\n');render(r)
