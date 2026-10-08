"""Narrow byte-preserving annotation update for proved Pass45 table/repeat routes."""
import json,re,hashlib,sys
from pathlib import Path
from collections import Counter
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_acquisition_reentry_pass_38 import coord
r=Path('research/annotated-assembly');REPORT=Path('research/host-compiler/pass-45')
image=Path(sys.argv[1],'PLI1.OVL').read_bytes()
cat=json.loads((r/'procedures.json').read_text());ev=json.loads((r/'evidence.json').read_text());man=json.loads((r/'manifest.json').read_text());im=next(i for i in man['images']if i['name']=='PLI1.OVL')
data=json.loads(Path('_build/host-compiler-pass-45/closed-rows.json').read_text())
prior=next(p for p in cat['procedures']if p['id']=='PLI1.OVL+654E')
contract='Retain Pass38 clear-repeat route. PUSH H twice supplies F0..F3. Call64F2 then repeatedly fresh Search57B7(base7969); RAR, exit on CYclear. FoundA935 is zero-based matching table offset, saved at F0. Acquire784E; save freshA635 at F1/F2 and freshA631 at F3. Independent64F2; freshF3 ->A632, freshA631 ->A633, freshsavedpointer ->A637/A638, freshA635 ->A639/A63A. Require unsigned5>=freshF0; call bounded345E; RAR requiresCYclear. Three wrappingADD A operations multiply freshF0 by8; PUSH PSW retains result while fresh239A executes; POP B/MOV C,B thenADD C forms newF0. Publish A628=24,A62B=1,A62E=0 in order. FreshF0 lowC andDE7972 invoke complete local25A9, which freshly selects tablebyte and composes bounded2511. Repeat Search against fresh20C3, without fixed iterations or arbitrary termination guarantee. Natural three cases have one founditeration and a secondnotfound search as consequence of sharedstate changes. TwoPOP H restoreinheritedHL, retain finalSearch/RAR state andRET originalcontinuation. Active scratch/code/table/stack nonalias discipline and child bounded scopes inherited.'
meta={0x25a9:(0x25c0,'Fresh indexed byte-table adapter composing bounded2511',('stable','complete','complete'),
 'Save inputD atA65A beforeE atA659 andC atA658. Fresh pairedA658/A659 read; zeroextend onlyL andXCHG. FreshpairedA659/A65A reload saved tablebase. DAD D selects u16(base+savedlowC), CY=wordoverflow, NZPApreserved. Read selectedbyte intoC preservingB,A,DE. CALL25BC bounded2511; return exactchildstate throughoriginalhardwarecontinuation. No localPUSH or privateframe; childCALL residue derived. Alllocalbytes/CFG covered bythreeFIZZBUZ calls; globally bounded bycanonical2511 childdomain, tableaddress nonalias required.',
 ['Native support inherits bounded2511 domain; no capacity/ownership assumptions.'],[(0x25a9,['save DE highthenlow;saveC;freshpaired rereads;zeroextendsavedC;', 'selectedC=byte[u16(savedDE+savedC)];2511();RET childstate;'])]),
 0x654e:(prior['end_offset'],prior['description'],('provisional','partial','partial'),contract,
 ['Offset>5 subtraction arm65A1 and transform-set65AE..65C4 remainRAW/unobserved; arbitrary pointerchain/search termination and inherited childunsupported domains remainunproved.'],[(0x654e,['PUSH H twice;64F2();']), (0x6553,['Search57B7(7969);RAR;ifCYclear:restoreinheritedHL andRET;', 'freshmatchedA935 ->F0;784E();save freshpointer/index;64F2();']), (0x657b,['fresh frame/shared channels ->A632/A633 andA637/A639;', 'require5>=F0;345E();RAR;requireCYclear;']), (0x65c5,['freshF0*8 viaADD sequence;PSW;fresh239A;ADD savedoffset;', 'publish selector/auxiliary channels;25A9(freshF0,7972);repeat freshSearch;']), (0x65f6,['POP H twice;return finalpredicate state;'])])}
def meaning(w):
 d=w['disassembly'];op,_,arg=d.partition(' ');arg=arg.replace('H','H');off=w['origin']['offset']
 if op=='CALL':return 'push following PC; invoke '+coord(w['target_origin'])+'; child state/effects at the explicitly scoped contract'
 if op=='PCHL':return 'PC=HL from freshly selected little-endian jump-table word; no new CALL word or stack frame'
 if op=='ADD':return 'A=u8(A+fresh '+arg+'); exact byte addition flags; independent channels retained'
 if op=='RET':return 'consume original hardware return word; SP=entry_SP+2; preserve final path flags and registers'
 if op=='CMA':return 'A=bitwise complement of A; all flags preserved'
 if op=='RAR':return 'A=(incoming_CY<<7)|(old_A>>1); CY=old_A.bit0; NZPA preserved'
 if op in ['JNC','JNZ','JZ','JC','JMP']:return {'JNC':'if CY=0','JNZ':'if Z=0','JZ':'if Z=1','JC':'if CY=1','JMP':'unconditionally'}[op]+': PC='+arg+'; flags preserved'
 if op=='LXI':return arg.split(',')[0]+' pair = literal '+arg.split(',')[1]+'; flags preserved'
 if op=='LHLD':return 'HL=fresh little_endian_word['+arg+']; low then high read; flags preserved'
 if op=='SHLD':return 'byte['+arg+']=L then byte[address+1]=H; flags preserved'
 if op=='LDAX':return 'A=fresh byte['+arg+' pair]; flags preserved'
 if op=='LDA':return 'A=fresh byte['+arg+']; flags preserved'
 if op=='STA':return 'unconditionally publish A to byte['+arg+']; flags preserved'
 if op=='MVI':return ('byte[HL]'if arg.split(',')[0]=='M'else arg.split(',')[0])+'='+arg.split(',')[1]+'; flags preserved'
 if op=='MOV':
  x,y=arg.split(',');return ('byte[HL]'if x=='M'else x)+'='+('fresh byte[HL]'if y=='M'else y)+'; flags preserved'
 if op=='DAD':return 'HL=u16(HL+'+arg+'); only CY changes to word overflow'
 if op in ['INX','DCX']:return arg+'=u16('+arg+(' +1'if op=='INX'else' -1')+'); flags preserved'
 if op=='DCR':return arg+'=u8('+arg+'-1); NZPA from decrement; CY preserved'
 if op=='CMP':return 'flags=unsigned byte comparison A against '+arg+'; operands preserved'
 if op=='INR':return arg+'=u8('+arg+'+1); NZPA from byte increment; CY preserved'
 if op=='CPI':return 'flags=unsigned byte comparison A-'+arg+'; A preserved'
 if op=='SUB':return 'A=u8(A - fresh byte[HL]); exact subtraction NZPA/CY; operands remain distinct channels'
 if op=='SUI':return 'A=u8(A-'+arg+'); arithmetic flags; CY=borrow of this subtraction only'
 if op=='ADI':return 'A=u8(A+'+arg+'); arithmetic flags; adjusted byte remains a distinct result'
 if op=='SBB':return 'A=old_CY?FFH:00H for self subtraction; exact S/Z/AC/P/CY arithmetic flags'
 if op=='ANI':return 'A=A AND '+arg+'; Intel8080 logical flags/CY0'
 if op=='ANA':return 'A=A AND '+arg+'; Intel8080 logical flags/CY0'
 if op=='DCX'and arg=='SP':return 'SP=u16(SP-1); flags preserved'
 if op=='ORA':return 'A=A OR '+arg+'; logical flags; CY=0'
 if op=='XCHG':return 'exchange DE and HL; flags preserved'
 if op=='PUSH':return 'write high then low '+arg+' below SP; SP-=2; preserve flags; compatibility residue retained'
 if op=='POP':return 'read low then high into '+arg+' pair; SP+=2; flags preserved; residue remains'
 raise ValueError(d)
new={};facts={}
for start,(end,desc,complete,contract,unresolved,blocks)in meta.items():
 key=f'PLI1.OVL+{start:04X}';groups={s:g[key]for s,g in data.items()};rs=sum(groups.values(),[]);ws={w['origin']['offset']:w for a in rs for w in a['own_witnesses']};facts.update(ws)
 callers={}
 for s,rows in groups.items():
  for c,n in Counter(coord(a['call']['origin'])for a in rows).items():callers.setdefault(c,{})[s]=n
 direct={w['origin']['offset']:dict(callsite_offset=w['origin']['offset'],coordinate=coord(w['target_origin']),runtime_address=w['control']['target'])for w in ws.values()if w['control']['kind']=='call'}
 p=dict(id=key,image='PLI1.OVL',image_sha256=im['sha256'],stable_label=f'PLI1_{start:04X}',runtime_entry=start+0x2200,start_offset=start,end_offset=end,length=end-start,byte_status_at_entry='UNDERSTOOD',description=desc,completeness=dict(zip(['bounds','control_flow','contract'],complete)),observed_paths=dict(invocations_by_run={s:len(a)for s,a in groups.items()},represented_bytes=sum(len(bytes.fromhex(w['bytes']))for w in ws.values()),description='OBSERVED corrected ordinary CALL/return windows independently retained for MINIMAL/FIZZBUZ/PICTURE; union of own bytes excludes child bodies.'),unresolved_paths=unresolved,
 inputs='Actual entry registers and selected shared byte-addressed memory; child scopes inherited; executable code, selected scratch/publications/read carriers and active return/save slots nonaliasing where their operation requires it. No table capacity or ownership assumption.',
 outputs='Path-specific A/BC/DE/HL and flags as documented below and in correlated natural cases; SP=entry_SP+2; PC=original CALL continuation.',clobbers='Path-specific A/BC/DE/HL/flags; local scratch/publications stated below; delegated child effects; proven CALL/PUSH stack residue.',memory_state=['All numerical addresses denote historical runtime bytes, not separate host arrays.','F=entry_SP; original hardware CALL word at F; body CALL/save traffic below F; preserved per-invocation last writers.'],data_role_ids=[],callers=[dict(coordinate=c,counts_by_run=ns)for c,ns in sorted(callers.items())],returns=dict(convention='ordinary hardware CALL word; original slot unchanged; SP after RET=entry_SP+2',observed_file_offsets=sorted({a['ret']['origin']['offset']for a in rs}),sites_description='; '.join(sorted({coord(a['ret']['origin'])for a in rs}))),direct_callees=list(direct.values()),overlapping_entries=[],contract_scope='Bounded accumulated-natural routes and exact represented local operations; delegated partial/opaque children and unexecuted local arms are not silently implemented.',contract=contract,semantic_hypothesis=None,pseudocode='; '.join(t for o,ts in blocks for t in ts),evidence_refs=[f'evidence.json#seeds/{key}','../host-compiler/pass-45/README.md','../host-compiler/pass-45/table-repeat-cases.json'],blocks=[dict(offset=o,pseudocode=ts)for o,ts in blocks],local_comments={f'{o:04X}':meaning(w)for o,w in sorted(ws.items())})
 new[key]=p;cat['procedures']=[q for q in cat['procedures']if q['id']!=key];cat['procedures'].append(p)
 instructions=[]
 for o,w in sorted(ws.items()):
  ins=dict(offset=o,runtime_pc=o+0x2200,bytes=w['bytes'],decoded=w['disassembly'],runs=[])
  for s,rows in groups.items():
   hits=[q for a in rows for q in a['own_witnesses']if q['origin']['offset']==o]
   if hits:ins['runs'].append(dict(run=s,execution_count=len(hits),first_step=min(q['step_index']for q in hits),last_step=max(q['step_index']for q in hits)))
  instructions.append(ins)
 first=rs[0];ev['seeds']=[q for q in ev['seeds']if q['id']!=key];ev['seeds'].append(dict(id=key,image='PLI1.OVL',image_sha256=im['sha256'],start_offset=start,end_offset=end,description=desc,inputs_and_effects=p['inputs']+'; '+p['outputs'],downstream_helpers_runtime='; '.join(c['coordinate']for c in direct.values()),unresolved='; '.join(unresolved),instructions=instructions,observed_callers=[dict(run=s,image='PLI1.OVL',offset=int(c.split('+')[1],16),bytes=image[int(c.split('+')[1],16):int(c.split('+')[1],16)+3].hex().upper(),execution_count=n,first_step=min(a['call']['step_index']for a in groups[s]if coord(a['call']['origin'])==c))for c,ns in callers.items()for s,n in ns.items()],observed_return_offsets=p['returns']['observed_file_offsets'],matched_return_sample=dict(relation='OBSERVED corrected original CALL word/RET ancestry',call=first['call'],ret=first['ret']),behavioral_contract=contract))
# Split only affected RAW source rows/sections. Existing semantics and labels survive.
promoted={o+i for o,w in facts.items()for i in range(len(bytes.fromhex(w['bytes'])))}
sections=[]
boundaries={v for p in new.values()for v in [p['start_offset'],p['end_offset']]}
for sec in im['sections']:
 cuts=sorted({sec['start_offset'],sec['end_offset']}|{v for v in boundaries if sec['start_offset']<v<sec['end_offset']}|{a for a in promoted if sec['start_offset']<=a<=sec['end_offset']}|{a+1 for a in promoted if sec['start_offset']<=a+1<=sec['end_offset']})
 chunks=[]
 for a,b in zip(cuts,cuts[1:]):
  status='UNDERSTOOD'if a in promoted else sec['status']
  if chunks and chunks[-1][2]==status and a not in boundaries:chunks[-1]=(chunks[-1][0],b,status)
  else:chunks.append((a,b,status))
 for a,b,status in chunks:
  x=dict(sec,start_offset=a,end_offset=b,length=b-a,runtime_start=a+0x2200,runtime_end=b+0x2200,status=status,original_sha256=hashlib.sha256(image[a:b]).hexdigest(),reassembled_sha256=hashlib.sha256(image[a:b]).hexdigest())
  x['evidence_refs']=[f"evidence.json#seeds/{s['id']}"for s in ev['seeds']if s['image']=='PLI1.OVL'and s['start_offset']<=a and b<=s['end_offset']]
  sections.append(x)
im['sections']=sections;starts={s['start_offset']:s for s in sections};oldtext=(r/'PLI1.asm').read_text();result=[];oldlabels=set();keptlabels=set();source_lines=oldtext.splitlines()
for line in source_lines:
 if line.startswith('; SECTION '):continue
 match=re.match(r'PLI1_([0-9A-F]{4}): DB (.*?) ;',line)
 if match:
  a=int(match[1],16);oldlabels.add(a);raw=match[2].split(',');b=a+len(raw)
  if not any(x in promoted for x in range(a,b))and not any(a<x<b for x in starts):
   if a in starts:s=starts[a];result.append(f"; SECTION [{a:04X},{s['end_offset']:04X}) {s['status']}")
   result.append(line);keptlabels.add(a);continue
  pos=a
  while pos<b:
   if pos in promoted and pos not in facts:pos+=1;continue
   if pos in starts:s=starts[pos];result.append(f"; SECTION [{pos:04X},{s['end_offset']:04X}) {s['status']}")
   if pos in facts:
    w=facts[pos];statement=re.sub(r'\b([A-F][0-9A-F]*)H\b',r'0\1H',w['disassembly']);result.append(f'PLI1_{pos:04X}: {statement} ; +{pos:04X} runtime={pos+0x2200:04X}H OBSERVED');keptlabels.add(pos);pos+=len(bytes.fromhex(w['bytes']))
   else:
    end=min([b]+[x for x in starts if pos<x<b]+[x for x in facts if pos<x<b]);statement=','.join(f'0{v:02X}H'for v in image[pos:end]);result.append(f'PLI1_{pos:04X}: DB {statement} ; +{pos:04X} runtime={pos+0x2200:04X}H RAW');keptlabels.add(pos);pos=end
  continue
 match=re.match(r'PLI1_([0-9A-F]{4}):',line)
 if match:
  a=int(match[1],16)
  if a in starts:s=starts[a];result.append(f"; SECTION [{a:04X},{s['end_offset']:04X}) {s['status']}")
 result.append(line)
missing=oldlabels-keptlabels
for a in sorted(missing):
 result.insert(len(result)-1,f'PLI1_{a:04X}: EQU 0{a+0x2200:04X}H ; +{a:04X} runtime={a+0x2200:04X}H coordinate-only preserved label')
im['coordinate_only_labels']=sorted(set(im.get('coordinate_only_labels',[]))|missing)
(r/'PLI1.asm').write_text('\n'.join(result)+'\n')
for name,x in [('procedures',cat),('evidence',ev),('manifest',man)]: (r/(name+'.json')).write_text(json.dumps(x,indent=2)+'\n')
prior=json.loads((REPORT/'after.json').read_text());prior.update(new);(REPORT/'after.json').write_text(json.dumps(prior,indent=2)+'\n')
print('new hypotheses',len(new),'RAW -> UNDERSTOOD bytes',len(promoted))
