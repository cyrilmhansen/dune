"""Byte-preserving Pass46 bounded parent/family annotations from canonical laws."""
import json,re,hashlib,sys,subprocess
from pathlib import Path
from collections import Counter
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_acquisition_reentry_pass_38 import coord
r=Path('research/annotated-assembly');REPORT=Path('research/host-compiler/pass-46')
image=Path(sys.argv[1],'PLI1.OVL').read_bytes()
cat=json.loads((r/'procedures.json').read_text());ev=json.loads((r/'evidence.json').read_text());man=json.loads((r/'manifest.json').read_text());im=next(i for i in man['images']if i['name']=='PLI1.OVL')
data=json.loads(Path('_build/host-compiler-pass-46/annotation-rows.json').read_text())
laws=json.loads((REPORT/'contract-laws.json').read_text())
meta={int(k.split('+')[1],16):(v['end'],v['description'],v['completeness'],v['contract'],['Scope is the independently shadowed Pass46 routes; sibling RAW arms, arbitrary aliases and inherited child unsupported states remain excluded.'],[(int(k.split('+')[1],16),[v['contract']])])for k,v in laws.items()}
base='bba1b42d60b88461c637f15418605e38d89184ff';baseline=lambda name:json.loads(subprocess.check_output(['git','show',base+':research/annotated-assembly/'+name+'.json']));old={p['id']:p for p in baseline('procedures')['procedures']};oldseeds={p['id']:p for p in baseline('evidence')['seeds']}
if not (REPORT/'before.json').exists():(REPORT/'before.json').write_text(json.dumps({k:old.get(k)for k in laws},indent=2)+'\n')
raw_before={a for sec in next(i for i in baseline('manifest')['images']if i['name']=='PLI1.OVL')['sections']if sec['status']=='RAW'for a in range(sec['start_offset'],sec['end_offset'])}
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
 outputs='Path-specific A/BC/DE/HL and flags as documented below and in correlated natural cases; SP=entry_SP+2; PC=original CALL continuation.',clobbers='Path-specific A/BC/DE/HL/flags; local scratch/publications stated below; delegated child effects; proven CALL/PUSH stack residue.',memory_state=['All numerical addresses denote historical runtime bytes, not separate host arrays.','F=entry_SP; original hardware CALL word at F; body CALL/save traffic below F; preserved per-invocation last writers.'],data_role_ids=[],callers=[dict(coordinate=c,counts_by_run=ns)for c,ns in sorted(callers.items())],returns=dict(convention='ordinary hardware CALL word; original slot unchanged; SP after RET=entry_SP+2',observed_file_offsets=sorted({a['ret']['origin']['offset']for a in rs}),sites_description='; '.join(sorted({coord(a['ret']['origin'])for a in rs}))),direct_callees=list(direct.values()),overlapping_entries=[],contract_scope='Bounded accumulated-natural routes and exact represented local operations; delegated partial/opaque children and unexecuted local arms are not silently implemented.',contract=contract,semantic_hypothesis=None,pseudocode='; '.join(t for o,ts in blocks for t in ts),evidence_refs=[f'evidence.json#seeds/{key}','../host-compiler/pass-46/README.md','../host-compiler/pass-46/natural-cases.json'],blocks=[dict(offset=o,pseudocode=ts)for o,ts in blocks],local_comments={f'{o:04X}':meaning(w)for o,w in sorted(ws.items())})
 if key in old:
  prior=old[key];p['contract']='Previous bounded contract retained: '+prior['contract']+' Pass46 extension: '+contract
  p['contract_scope']=prior['contract_scope']+'; additionally the exact Pass46 family/root states and nonalias scopes.'
  p['unresolved_paths']=list(dict.fromkeys(prior['unresolved_paths']+unresolved))
  p['local_comments']={**p['local_comments'],**prior.get('local_comments',{})}
  p['blocks']=prior.get('blocks',[])+[b for b in p['blocks']if b['offset']not in {q['offset']for q in prior.get('blocks',[])}]
  p['pseudocode']=prior.get('pseudocode','')+'; Pass46: '+p['pseudocode']
  p['data_role_ids']=prior.get('data_role_ids',[])
  if key=='PLI1.OVL+6708':
   p['returns']=prior['returns'];p['outputs']='Exact path-specific registers/flags; consume eight caller bytes separately from original continuation, copied continuation at entrySP+8; final SP=entrySP+10 and PC=original continuation.'
  p['evidence_refs']=list(dict.fromkeys(prior.get('evidence_refs',[])+p['evidence_refs']))
  p['direct_callees']=list({q['callsite_offset']:q for q in prior['direct_callees']+p['direct_callees']}.values())
 new[key]=p;cat['procedures']=[q for q in cat['procedures']if q['id']!=key];cat['procedures'].append(p)
 instructions=[]
 for o,w in sorted(ws.items()):
  ins=dict(offset=o,runtime_pc=o+0x2200,bytes=w['bytes'],decoded=w['disassembly'],runs=[])
  for s,rows in groups.items():
   hits=[q for a in rows for q in a['own_witnesses']if q['origin']['offset']==o]
   if hits:ins['runs'].append(dict(run=s,execution_count=len(hits),first_step=min(q['step_index']for q in hits),last_step=max(q['step_index']for q in hits)))
  instructions.append(ins)
 first=rs[0];ev['seeds']=[q for q in ev['seeds']if q['id']!=key];ev['seeds'].append(dict(id=key,image='PLI1.OVL',image_sha256=im['sha256'],start_offset=start,end_offset=end,description=desc,inputs_and_effects=p['inputs']+'; '+p['outputs'],downstream_helpers_runtime='; '.join(c['coordinate']for c in direct.values()),unresolved='; '.join(unresolved),instructions=instructions,observed_callers=[dict(run=s,image='PLI1.OVL',offset=int(c.split('+')[1],16),bytes=image[int(c.split('+')[1],16):int(c.split('+')[1],16)+3].hex().upper(),execution_count=n,first_step=min(a['call']['step_index']for a in groups[s]if coord(a['call']['origin'])==c))for c,ns in callers.items()for s,n in ns.items()],observed_return_offsets=p['returns']['observed_file_offsets'],matched_return_sample=dict(relation='OBSERVED corrected original CALL word/RET ancestry',call=first['call'],ret=first['ret']),behavioral_contract=contract))
for key,p in new.items():
 if key not in oldseeds:continue
 seed=next(q for q in ev['seeds']if q['id']==key);prior=oldseeds[key]
 instructions={q['offset']:q for q in prior['instructions']}
 for q in seed['instructions']:
  if q['offset'] in instructions:
   previous=instructions[q['offset']];runs={v['run']:v for v in previous['runs']}
   for v in q['runs']:
    if v['run']in runs:
     z=runs[v['run']];runs[v['run']]=dict(v,execution_count=max(z['execution_count'],v['execution_count']),first_step=min(z['first_step'],v['first_step']),last_step=max(z['last_step'],v['last_step']))
    else:runs[v['run']]=v
   q=dict(q,runs=list(runs.values()))
  instructions[q['offset']]=q
 seed['instructions']=[instructions[o]for o in sorted(instructions)]
 seed['behavioral_contract']=p['contract']
 if prior.get('software_return_sample'):seed['software_return_sample']=prior['software_return_sample'];seed['matched_return_sample']=None
 p['observed_paths']['represented_bytes']=sum(len(bytes.fromhex(q['bytes']))for q in instructions.values())
 seed['observed_callers']=prior.get('observed_callers',[])+[q for q in seed['observed_callers']if (q['run'],q['offset'])not in {(v['run'],v['offset'])for v in prior.get('observed_callers',[])}]
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
for key,container,name in [('procedures',cat,'procedures'),('seeds',ev,'evidence')]:
 values={q['id']:q for q in container[key]};ordered=[q['id']for q in baseline(name)[key]];container[key]=[values.pop(k)for k in ordered if k in values]+[values[k]for k in sorted(values)]
for name,x in [('procedures',cat),('evidence',ev),('manifest',man)]: (r/(name+'.json')).write_text(json.dumps(x,indent=2)+'\n')
(REPORT/'after.json').write_text(json.dumps(new,indent=2)+'\n')
counts={k:len({a for o,w in facts.items()if p['start_offset']<=o<p['end_offset']for a in range(o,o+len(bytes.fromhex(w['bytes'])))if a in raw_before})for k,p in new.items()};(REPORT/'archaeology-summary.json').write_text(json.dumps(dict(raw_to_understood=len(promoted&raw_before),by_procedure=counts,new_contracts=[k for k in new if k not in old],extended_contracts=[k for k in new if k in old]),indent=2)+'\n');print('hypotheses',len(new),'RAW -> UNDERSTOOD bytes',len(promoted&raw_before))
