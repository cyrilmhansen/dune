#!/usr/bin/env python3
"""Only the observed eight-byte success publication and its owning header."""
import collections,json,re,subprocess
from pathlib import Path
from decompilation_annotations import header_lines
from run_gateway_decomposition_pass_71 import OUT,REPORT,load,save,SOURCES,BASE
root=Path('research/annotated-assembly');rs=load(OUT/'roots.json');
def original(name):return json.loads(subprocess.check_output(['git','show',BASE+':'+str(root/name)]))
def durable(name,x):(root/name).write_text(json.dumps(x,indent=2)+'\n')
cat=original('procedures.json');p=next(x for x in cat['procedures']if x['id']=='PLI2.OVL+1FB5')
p['completeness']={'bounds':'stable','control_flow':'partial','contract':'partial'}
p['observed_paths']={'invocations_by_run':{s:sum(r['source']==s for r in rs)for s in SOURCES},'represented_bytes':271,'description':'Pass71: 237 independently nested hardware windows and software handler returns; 53 candidate successes; both trace gates clear. Native gateway and opaque descriptor/handler contracts remain unclosed.'}
p['callers']=[dict(coordinate=f'PLI2.OVL+{o:04X}',counts_by_run={s:sum(r['source']==s and r['caller']==o for r in rs)for s in SOURCES if any(r['source']==s and r['caller']==o for r in rs)})for o in sorted({r['caller']for r in rs})]
p['unresolved_paths']=['Trace-set paths 2092..20AC and20BB..20C8 remain RAW / STATIC / UNOBSERVED.','1DFF remains a partial descriptor predicate without a canonical native contract; natural observed token/result signatures do not establish its arbitrary domain.','47 natural handler targets; only6EA5 has a demonstrated scoped software-handler canonical contract here. No callback architecture or native gateway is installed.']
p['contract']='Gateway-own observations: reserve twelve bytes; save C atS-12, AD0B..AD14 atS-11..S-2 and AD0A atS-1. Canonical047D consumes saved C; returned A selects descriptor/handler pointers. Candidate1DFF returned A.bit0 drives RAR; success publishes AD1A=0 then AD1B=1 with flags preserved, followed by shared descriptor skip. Fallback selects low3 bits of byte[1B4B+k], then publishes fallback pointer+1 and actual1DFF result. PUSH42B4/PCHL invokes selected opaque handler. Trace-clear own restore reads saved state, finalA=oldAD0A, BC=S-1, DE=AD15, HL=S, RET original CALL, SP=S+2. Full descriptor and handler semantics remain delegated/unclosed; no executable native parent contract.'
p['contract_scope']='Observed gateway-own state and concrete continuation mechanics; only203E..2046 gains UNDERSTOOD status. Opaque predicates/handlers and trace-set branches are not closed.'
p['pseudocode']='Save twelve-byte local state; canonical047D selects descriptor/handler tables; scan actual1DFF results, publishing success or selecting fallback; PUSH42B4/PCHL actual handler; trace-clear restore and original hardware RET. Unresolved child semantics remain explicit.'
p['local_comments'].update({'203E':'HL = AD1AH; flags preserved','2041':'byte[candidates_remaining (AD1AH)] = 00H; same-valued writes retained; flags preserved','2043':'HL = (HL+1)&FFFF; flags preserved','2044':'byte[candidate_success_byte (AD1BH)] = 01H; flags preserved'})
p['blocks']=[x for x in p['blocks']if x['offset']!=0x203e]
p['blocks'].append(dict(offset=0x203e,pseudocode=['OBSERVED candidate success: AD1A=0 then AD1B=1; all flags preserved; shared skip follows.']))
for b in p['blocks']:
 if b['offset']==0x2046:b['pseudocode']=['Both success and failure use the fresh descriptor record byte as the skip amount; loop back to remaining count.']
p['evidence_refs']=list(dict.fromkeys(p['evidence_refs']+['../host-compiler/pass-71/natural-inventory.json','../host-compiler/pass-71/frames.json','../host-compiler/pass-71/fragment-proof.json']))
durable('procedures.json',cat)
asm=root/'PLI2.asm';text=asm.read_text();text=re.sub(r'; @procedure-v1 PLI2.OVL\+1FB5.*?; @end-procedure-v1 PLI2.OVL\+1FB5','\n'.join(header_lines(p)),text,flags=re.S)
start=text.index('; SECTION [203E,2046)');end=text.index('; SECTION [2046,2092)',start)
text=text[:start]+''' ; SECTION [203E,2046) UNDERSTOOD
; @block-pseudo 203E
; pseudo:
; | OBSERVED candidate success: AD1A=0 then AD1B=1; all flags preserved; shared skip follows.
PLI2_203E: LXI H,0AD1AH ; HL = AD1AH; flags preserved ; +203E runtime=423EH OBSERVED
PLI2_2040: EQU 04240H ; +2040 runtime=4240H coordinate-only label
PLI2_2041: MVI M,00H ; byte[candidates_remaining (AD1AH)] = 00H; same-valued writes retained; flags preserved ; +2041 runtime=4241H OBSERVED
PLI2_2043: INX H ; HL = (HL+1)&FFFF; flags preserved ; +2043 runtime=4243H OBSERVED
PLI2_2044: MVI M,01H ; byte[candidate_success_byte (AD1BH)] = 01H; flags preserved ; +2044 runtime=4244H OBSERVED
'''.lstrip()+text[end:]
# No global render: preserve every other reviewed header and local annotation.
text=text.replace('; | observed failure: skip by record byte','; | Both success and failure use the fresh descriptor record byte as the skip amount; loop back to remaining count.')
asm.write_text(text)
m=original('manifest.json');im=next(q for q in m['images']if q['name']=='PLI2.OVL');sec=next(q for q in im['sections']if q['start_offset']==0x203e);sec['status']='UNDERSTOOD'
im['coordinate_only_labels']=sorted(set(im['coordinate_only_labels'])|{0x2040});durable('manifest.json',m)
e=original('evidence.json');seed=next(q for q in e['seeds']if q['id']=='PLI2.OVL+1FB5');seed['unresolved']='Pass71: both trace-set arms unobserved; 1DFF and47 selected handler semantics remain partial/unclosed except contained canonical6EA5.';seed['pass71_evidence']={'report':'../host-compiler/pass-71/frames.json','success_calls':53,'native_root_installed':False}
for off in [0x203e,0x2041,0x2043,0x2044]:
 ws=[w for r in rs for w in r['own']if w['offset']==off];w=ws[0];ins=dict(offset=off,bytes=w['bytes'],decoded=w['decoded'],runtime_pc=w['before']['pc'],runs=[dict(run='Pass71:'+s,execution_count=sum(r['source']==s and r['success']for r in rs),first_step=min(q['step']for r in rs if r['source']==s for q in r['own']if q['offset']==off),last_step=max(q['step']for r in rs if r['source']==s for q in r['own']if q['offset']==off))for s in SOURCES if any(r['source']==s and r['success']for r in rs)])
 if not any(q['offset']==off for q in seed['instructions']):seed['instructions'].append(ins)
seed['instructions'].sort(key=lambda q:q['offset']);seed['behavioral_contract']='Only bounded observed block[203E,2046): LXI H,AD1A; byte[AD1A]=0; INX H; byte[AD1B]=1, in order, same-valued writes retained, all flags preserved, other registers and RAM unchanged. Gateway predicate/handler semantics remain partial and this is not a procedure entry or executable native gateway.';seed['behavioral_contract_ranges']=[[0x203e,0x2046]];durable('evidence.json',e)
save(REPORT/'success-publication-law.json',dict(extent=['203E','2046'],owning_procedure='PLI2.OVL+1FB5',not_a_procedure_entry=True,law='HL=AD1A; byte[AD1A]=0; INX H; byte[AD1B]=1; ordered writes including same values; registers exceptHL and all flags preserved',natural_calls=53,RAW_to_UNDERSTOOD=8))
