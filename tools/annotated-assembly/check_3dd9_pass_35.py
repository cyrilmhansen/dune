"""Bounded natural shared-pointer gate and immediately required local laws.

No native implementation: branch selection always derives from machine state.
Opaque +3A76 is retained as a child, not replaced by an observed-output law.
"""
from check_6223_pass_32 import (ROOT,CAPTURES,gather,coord,require,pair,load,one,
 identity,body,child,chronology,summarize,rotate,verify_return,counts)
from check_60e5_pass_33 import ats,val,writes
from check_240a_pass_30 import cmp
from check_5a46_pass_34 import stack_proof
import hashlib,json
REPORT=ROOT/'research/host-compiler/pass-35'
ENTRIES=[0x3dd9,0x3c8a,0x415e,0x387f,0x3558]
BOUNDS={f'PLI1.OVL+{x:04X}':(x,x+1)for x in ENTRIES}
FILES=['natural-cases','route-distribution','state-transition','dependency-assessment','work-packet']
def psw(f):
 return 2|int(f['sign'])*128|int(f['zero'])*64|int(f['auxiliary_carry'])*16|int(f['parity'])*4|int(f['carry'])
def stack(r):
 for w in body(r):
  if w['disassembly'].startswith('PUSH '):
   reg=w['disassembly'][5:];s=w['before'];v= (s['a']<<8)|psw(s['flags']) if reg=='PSW'else pair(s,*{'B':('b','c'),'D':('d','e'),'H':('h','l')}[reg])
   require([(q['address'],q['new_value'])for q in w['writes']]==[(s['sp']-1,v>>8),(s['sp']-2,v&255)],'register-derived PUSH high then low including exact PSW reserved bit')
 return [dict(writer=q['writer'],relative_address=q['relative_address'],value=q['value'],overwritten_writers=sorted(set(q['overwritten_writers'])),overwrite_chronology_sha256=hashlib.sha256(json.dumps(q['overwritten_writers']).encode()).hexdigest())for q in stack_proof(r)]
def validate_data_writers(r):
 for w in r['own_witnesses']:
  if not w['writes']or w['control']['kind']=='call'or w['disassembly'].startswith('PUSH'):continue
  op,_,arg=w['disassembly'].partition(' ');before=w['before'];hl=pair(before,'h','l')
  if op=='SHLD':
   a=int(arg[:-1],16);expected=[(a,before['l']),((a+1)&65535,before['h'])]
  elif op=='STA':expected=[(int(arg[:-1],16),before['a'])]
  elif op=='MOV':
   require(arg.startswith('M,'),'only reviewed direct memory publication');expected=[(hl,before[arg[2:].lower()])]
  elif op=='MVI':
   require(arg.startswith('M,'),'only reviewed direct immediate publication');expected=[(hl,int(arg[2:-1],16))]
  else:raise ValueError('unreviewed logical writer '+w['disassembly'])
  require([(q['address'],q['new_value'])for q in w['writes']]==expected,'exact nonstack writer source/address and low/high order')
def single_child(r,w):
 return child(dict(r,own_witnesses=[q for q in r['own_witnesses']if q['origin']['offset']!=w['origin']['offset']or q['step_index']==w['step_index']]),w['origin']['offset'])
def children(r):return [single_child(r,w)for w in r['own_witnesses']if w['control']['kind']=='call']
def compact_child(c):
 return {k:c[k]for k in ['callsite','target','call_step','return_step','entry','output','cpu_memory_write_count','cpu_memory_write_chronology_sha256']}
def arithmetic(w):
 """Independent reviewed byte arithmetic equations, not CPU instruction execution."""
 op,_,arg=w['disassembly'].partition(' ');a=w['before']['a'];f=w['before']['flags'];b=None
 if op in ('CPI','SUI','ADI'):b=int(arg[:-1],16)
 elif op in ('CMP','SUB','ANA','ORA'):b=w['reads'][0]['value']if arg=='M'else w['before'][arg.lower()]
 elif op=='SBB':require(arg=='A','reviewed self-SBB only');b=a+int(f['carry'])
 if op in ('CPI','CMP','SUB','SUI','SBB'):
  result=(a-b)&255;flags=dict(sign=result>=128,zero=result==0,auxiliary_carry=(not f['carry'])if op=='SBB'else(a&15)>=(b&15),parity=result.bit_count()%2==0,carry=a<b)
 elif op=='ADI':
  result=(a+b)&255;flags=dict(sign=result>=128,zero=result==0,auxiliary_carry=(a&15)+(b&15)>15,parity=result.bit_count()%2==0,carry=a+b>255)
 elif op in ('ANA','ORA'):
  result=a&b if op=='ANA'else a|b;flags=dict(sign=result>=128,zero=result==0,auxiliary_carry=bool((a|b)&8)if op=='ANA'else False,parity=result.bit_count()%2==0,carry=False)
 elif op=='ANI':
  b=int(arg[:-1],16);result=a&b;flags=dict(sign=result>=128,zero=result==0,auxiliary_carry=bool((a|b)&8),parity=result.bit_count()%2==0,carry=False)
 else:return
 require(w['after']['flags']==flags,'actual immediate flag producer '+w['disassembly'])
 require(w['after']['a']==(a if op in ('CMP','CPI')else result),'arithmetic result distinct from retained CMP operand')
def validate_leaf(r):
 ws=r['own_witnesses'];q=child(r,0x3558);v=q['output']['a'];setbit=bool(v&128);out=r['ret']['after']
 for w in ws:arithmetic(w)
 require([w['disassembly']for w in ws]==['CALL 63A6H','ANI 80H','SUI 80H','SUI 01H','SBB A','RET'],'complete immutable mask graph')
 require(out['a']==(255 if setbit else 0),'3558 mask derives from fresh field bit7, not observed constant zero')
 expected=cmp(0,1)if setbit else cmp(0,0)
 require(out['flags']==expected,'self SBB final flags independent of returned helper flags')
 require(pair(out,'b','c')==3 and pair(out,'h','l')==pair(q['output'],'h','l')and pair(out,'d','e')==pair(r['entry']['before'],'d','e'),'complete41A6 returned pointer ABI retained')
 require(not writes(ws),'leaf no data writes')
 return dict(field=v,bit7=setbit,result=out['a'],flags=out['flags'])
def validate_bound_test(r):
 ws=r['own_witnesses'];e=r['entry']['before'];p=pair(e,'b','c');end=pair(e,'d','e');q=child(r,0x388f)
 require([(x['address'],x['value'])for x in writes(ws)[:4]]==[(0xa6e0,e['d']),(0xa6df,e['e']),(0xa6de,e['b']),(0xa6dd,e['c'])],'387F end high/low then cursor high/low writes')
 require(q['entry']['b']==0xa6 and q['entry']['c']==0xdd and pair(q['entry'],'d','e')==0xa6df,'resident subtraction actual scratch addresses')
 require(not q['output']['flags']['carry']and p<=end and one(ws,0x3892)['control']['taken'],'observed bounded pointer<=end selects field read')
 require(one(ws,0x3898)['after']['l']==(p&255)and pair(one(ws,0x389b)['before'],'h','l')==p,'fresh saved pointer restoration')
 f=child(r,0x389e)['output']['a'];require(f!=0x70 and not one(ws,0x38a3)['control']['taken'],'observed field!=70; alternate field arm remains unobserved')
 out=r['ret']['after'];require(out['a']==0 and out['flags']==cmp(f,0x70),'literal zero does not recompute field comparison flags')
 require(pair(out,'b','c')==p and pair(out,'d','e')==0xa6e0 and pair(out,'h','l')==(p+2)&65535,'bound-test ABI from resident/field helpers')
 return dict(pointer=p,end=end,field=f,result=0,flags=out['flags'])
def validate_select(r):
 ws=r['own_witnesses'];q=child(r,0x415e);v=q['output']['a'];a=one(ws,0x416a)['before']['a'];b=one(ws,0x416a)['reads'][0]['value']
 require(one(ws,0x416a)['after']['flags']==cmp(a,b)and a==b and one(ws,0x416b)['control']['taken'],'415E saved C==fresh A6E2 selects unadjusted field')
 require([(x['address'],x['value'])for x in writes(ws)]==[(0xa75f,v),(0xa628,v)],'field -> cache then freshly reloaded field -> indexed channel0')
 out=r['ret']['after'];require(out['a']==v and out['flags']==cmp(a,b)and pair(out,'h','l')==0xa6e2 and pair(out,'b','c')==pair(q['output'],'b','c')and pair(out,'d','e')==pair(q['output'],'d','e'),'selection ABI flags from comparison, not field')
 return dict(field=v,saved_C=a,comparison_byte=b,result=v)
def validate_frame(r):
 ws=r['own_witnesses'];e=r['entry']['before'];S=e['sp'];F=S-6;q=child(r,0x3c95);out=r['ret']['after']
 require(e['c']==0,'bounded natural frame route input zero; no arbitrary-index law')
 require(one(ws,0x3c90)['after']['h']==q['entry']['b']and one(ws,0x3c90)['after']['l']==q['entry']['c'],'opaque3A76 receives fresh A635 pointer in BC')
 require([(x['address'],x['value'])for x in writes(ws)]==[(0xa628,0x15),(0xa62e,0),(F+1,one(ws,0x3ca2)['after']['a']),(F+4,0),(F+5,0)],'six-byte frame writes plus two independent indexed publications')
 require(one(ws,0x3cb9)['reads'][0]['address']==F and one(ws,0x3cb9)['reads'][0]['value']==0 and one(ws,0x3cba)['control']['taken'],'literal0 CMP saved input0 skips unobserved positive-count body')
 require(out['a']==0 and pair(out,'h','l')==0 and pair(out,'d','e')==0 and pair(out,'b','c')==pair(q['output'],'b','c')and out['flags']==cmp(0,0),'3C8A zero-route ABI; BC is opaque child result, not fixed tuple')
 require(r['ret']['before']['sp']==S,'three POP D discard exactly six-byte frame')
 return dict(frame_base=F,frame_length=6,saved_input=e['c'],child=compact_child(q),local_writes=writes(ws),result_word=0,BC=pair(out,'b','c'))
def validate_root(r):
 ws=r['own_witnesses'];e=r['entry']['before'];out=r['ret']['after'];cs=children(r)
 for w in ws:arithmetic(w)
 for w in ws:
  if w['disassembly']=='RAR':rotate(w)
 require([(q['address'],q['new_value'])for o in [0x3ddc,0x3dde]for q in one(ws,o)['writes']]==[(0xa755,e['e']),(0xa754,e['c'])],'input E first then C saved independently')
 base=pair(one(ws,0x3ddf)['after'],'h','l');first=pair(one(ws,0x3de6)['after'],'h','l');last=pair(one(ws,0x3e01)['after'],'h','l');idx=one(ws,0x3df3)['after']['l']
 require([q['address']for q in one(ws,0x3df3)['reads']]==[0xa6ca,0xa6cb],'paired index/base-neighbor read')
 require(pair(one(ws,0x3de9)['after'],'h','l')==base,'fresh second base lookup')
 require([q['address']for o in [0x3de2,0x3de4]for q in one(ws,o)['reads']]==[base,base+1],'first low/high pointer lookup')
 freshbase=pair(one(ws,0x3dfa)['after'],'h','l');slot=(freshbase+2*idx)&65535
 require([q['address']for o in [0x3dfe,0x3e00]for q in one(ws,o)['reads']]==[slot,(slot+1)&65535],'indexed pointer from independently fresh base/index')
 require(pair(one(ws,0x3df0)['before'],'h','l')==first and pair(one(ws,0x3e02)['before'],'h','l')==last,'saved first/last pointer publications remain distinct')
 field=child(r,0x3e05)['output']['a'];mask=255 if field==2 or idx!=0 else 0
 require(one(ws,0x3e19)['before']['a']==mask,'initial state gate: field2 OR nonzero index mask')
 require(one(ws,0x3e1a)['control']['taken']==(not bool(mask&1)),'initial RAR/JNC polarity')
 require(mask==0 and e['c']==0 and idx==0 and first==last,'demonstrated bypass/zero-input/single-pointer scope')
 publish=e['e']!=0;require(one(ws,0x3f48)['control']['taken']==(not publish),'E==0 skips publication preparation independently of final A')
 pubs=[]
 if publish:
  c=child(r,0x3f55);require(c['entry']['c']==one(ws,0x3f51)['after']['l']==e['c'],'fresh saved C ->3C8A')
  require(pair(c['output'],'h','l')==pair(one(ws,0x3f58)['before'],'h','l')==0,'save returned frame word independently from pointer')
  dest=pair(one(ws,0x3f61)['after'],'h','l');ptr=pair(one(ws,0x3f65)['after'],'h','l')
  require([(q['address'],q['new_value'])for o in [0x3f6a,0x3f6c]for q in one(ws,o)['writes']]==[(dest,ptr&255),(dest+1,ptr>>8)],'PUSH destination / fresh pointer / POP destination / low-high republish')
  b=child(r,0x3f71);stop=b['output']['a'];require(b['entry']['c']==one(ws,0x3f6d)['after']['l'],'fresh AE32 -> Balance_scan; returned A -> saved A75E')
  require(one(ws,0x3f74)['writes'][0]['new_value']==stop,'direct balance returned A publication')
  # Every channel rereads its own carrier; equality is never used as provenance.
  for off,read_off,val_off in [(0x3f82,0x3f7a,0x3f7e),(0x3f91,0x3f8d,0x3f8c),(0x3fa0,0x3f9c,0x3f9b)]:
   c=child(r,off);require(c['entry']['c']==one(ws,read_off)['after']['l']==stop,'fresh saved stop cursor per publication')
   value=one(ws,val_off)['after']['l']if val_off==0x3f7e else one(ws,val_off)['after']['e'];require(c['entry']['e']==value,'distinct selected channel value')
   pubs.append(dict(callsite=hex(off),position=stop,value=value))
  fresh=child(r,0x3fb7)['output']['a'];require(one(ws,0x3fba)['after']['a']==(fresh+1)&255 and child(r,0x3fc0)['entry']['e']==(fresh+1)&255,'fresh239A A then wrapping INR -> mapped-byte channel')
  require(child(r,0x3fcb)['entry']['c']==one(ws,0x3fc3)['after']['l']and pair(child(r,0x3fcb)['entry'],'d','e')==pair(one(ws,0x3fc7)['after'],'h','l'),'independent cursor and fresh working pointer -> mapped-word channel')
  require(one(ws,0x3fdb)['control']['taken']and one(ws,0x400e)['control']['taken'],'natural pointer equality and saved word0 select common publication; opaque alternatives excluded')
  for off,pos_off,value_off in [(0x405c,0x4054,0x4058),(0x4067,0x405f,0x4063),(0x4072,0x406a,0x406e)]:
   c=child(r,off);require(c['entry']['c']==one(ws,pos_off)['after']['l']and pair(c['entry'],'d','e')==pair(one(ws,value_off)['after'],'h','l'),'three independently fresh AE32/source paired channels')
   pubs.append(dict(callsite=hex(off),position=c['entry']['c'],value=c['entry']['e']))
 require(one(ws,0x4078)['writes'][0]['new_value']==0,'counter initialization after optional publication')
 scans=[];tests=ats(ws,0x4089);require(len(tests)==2 and not tests[0]['control']['taken']and tests[1]['control']['taken'],'natural one-record traversal with separate unsigned terminal comparison')
 for w in ats(ws,0x4086):
  c=single_child(r,w);i=pair(c['output'],'b','c');end=last
  require(c['output']['flags']['carry']==(end<i),'termination is fresh unsigned last-scan subtraction')
 c=child(r,0x4092);require(c['output']['a']==0 and not one(ws,0x4097)['control']['taken'],'fresh fieldmask0 -> pointer test')
 bound=child(r,0x40a3);require(pair(bound['entry'],'b','c')==first and pair(bound['entry'],'d','e')==last,'fresh current/end arguments to387F')
 require(bound['output']['a']==0 and not one(ws,0x40b8)['control']['taken'],'returned bound-test0 OR equal-pointermaskFF; RAR tests bit0, not child carry')
 gate=child(r,0x40c1);require(gate['output']['a']==0 and one(ws,0x40c5)['control']['taken'],'field bit7 mask0 -> skip counter increment body')
 size=one(ws,0x40e4)['reads'][0]['value'];pointer=pair(one(ws,0x40e7)['after'],'h','l');nextp=(pointer+size)&65535
 require(size>0 and pair(one(ws,0x40eb)['before'],'h','l')==nextp and last<nextp,'fresh record-size byte plus independently fresh working pointer; natural increasing one-step termination')
 require(one(ws,0x40f6)['control']['taken']==(e['e']!=1),'only exact E1 takes postcheck; E2 is distinct from E1')
 if e['e']==1:require(not one(ws,0x40fe)['control']['taken']and one(ws,0x4108)['control']['taken'],'E1 field!=40 then saved C==counter -> common tail')
 counter=one(ws,0x4133)['after']['a'];saved=one(ws,0x4136)['reads'][0]['value'];diff=(counter-saved)&255
 require(saved==e['c']and one(ws,0x4137)['writes'][0]['new_value']==diff,'fresh counter minus fresh saved C -> A631 publication')
 restored=pair(one(ws,0x413d)['before'],'h','l');require(restored==first,'restore saved first pointer; not arbitrary incoming A863')
 f=child(r,0x4140)['output']['a'];finalmask=255 if f==6 and diff!=0 else 0
 require(one(ws,0x4153)['after']['a']==finalmask and one(ws,0x4155)['control']['taken']==(not bool(finalmask&1)),'final field6 AND nonzero difference selects diagnostic bypass')
 require(finalmask==0 and out['a']==1 and out['flags']==one(ws,0x4153)['after']['flags'],'literal1 preserves ANA/RAR flags; returned A not a recomputed condition flag')
 require(out['flags']==dict(sign=False,zero=True,auxiliary_carry=False,parity=True,carry=False),'natural mask0 flags remain distinct from returned1')
 require(pair(out,'b','c')==0 and pair(out,'d','e')==0xa75d and pair(out,'h','l')==(first+3)&65535,'natural final BC from masks; DE from final resident pointer subtraction; HL from restored pointer+3')
 return dict(route='E0_scan_only'if not publish else'E1_publication_scan_postcheck'if e['e']==1 else'E_other_publication_scan',C=e['c'],E=e['e'],base=base,index=idx,discarded_index_neighbor=one(ws,0x3df3)['after']['h'],first_pointer=first,selected_slot=slot,last_pointer=last,initial_field=field,initial_mask=mask,publications=pubs,scan=dict(pointer=pointer,size=size,next_pointer=nextp,field_control=c['output']['a'],bound_test_A=bound['output']['a'],field_bit7_mask=gate['output']['a']),counter=counter,difference=diff,final_field=f,final_mask=finalmask,returned_A=out['a'],flags=out['flags'],local_writes=writes(ws),children=[compact_child(c)for c in cs])
def analyze(source,capture,images,rows=None):
 rows=gather(capture,BOUNDS,include_nested_returns=True)if rows is None else rows
 image=(images/'PLI1.OVL').read_bytes();resident=(images/'PLI.COM').read_bytes();idx=load(capture/'event-witnesses.json');require(idx['run_id'].split(':')[0]==source,'selected run identity')
 for rs in rows.values():
  for r in rs:
   verify_return(r['call'],r['ret'],r['relation'])
   validate_data_writers(r)
   for w in body(r):
    name=w['origin']['image']['name'];raw=bytes.fromhex(w['bytes']);off=w['origin']['offset'];original=image if name=='PLI1.OVL'else resident
    require(name in ('PLI1.OVL','PLI.COM')and original[off:off+len(raw)]==raw and w['runtime_pc']==off+(0x2200 if name=='PLI1.OVL'else 0x100),'immutable canonical historical bytes, not runtime-PC-only identity')
   require(r['ret']['after']['sp']==r['entry']['before']['sp']+2,'ordinary no-argument cleanup return')
 roots=[identity(r)|dict(law=validate_root(r),stack=stack(r),chronology={k:v for k,v in chronology(r).items()if k!='final_stack_writers'})for r in rows['PLI1.OVL+3DD9']]
 funcs={0x3c8a:validate_frame,0x415e:validate_select,0x387f:validate_bound_test,0x3558:validate_leaf}
 deps={f'PLI1.OVL+{x:04X}':[identity(r)|dict(law=f(r),stack=stack(r),chronology={k:v for k,v in chronology(r).items()if k!='final_stack_writers'})for r in rows[f'PLI1.OVL+{x:04X}']]for x,f in funcs.items()}
 return dict(source=source,capture=str(capture.relative_to(ROOT)),run_id=idx['run_id'],capture_sha256=hashlib.sha256((capture/'event-witnesses.json').read_bytes()).hexdigest(),image_sha256=hashlib.sha256(image).hexdigest(),structure={k:summarize(rs)for k,rs in rows.items()},roots=roots,dependencies=deps)
def derive(analyses,rows_by_source,images):
 # A compact cognitive packet. Full projections remain ignored.
 blocks={w['origin']['offset']:w for g in rows_by_source.values()for r in g['PLI1.OVL+3DD9']for w in r['own_witnesses']}
 targets={coord(w['target_origin'])for w in blocks.values()if w['control']['kind']=='call'}
 catalog={p['id']:{k:p.get(k)for k in ['id','start_offset','end_offset','completeness','contract','unresolved_paths']}for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']if p['id']in targets}
 # Freeze the contracts that existed before this reconstruction.
 if (REPORT/'before.json').exists():
  for k,v in load(REPORT/'before.json').items():
   if k in targets:catalog[k]=None if v is None else {q:v.get(q)for q in ['id','start_offset','end_offset','completeness','contract','unresolved_paths']}
 packet=dict(baseline_commit='14639b52931391c188d2cbbcf1c16844c61162f8',target='PLI1.OVL+3DD9',image_sha256=hashlib.sha256((images/'PLI1.OVL').read_bytes()).hexdigest(),blocks=[dict(offset=o,bytes=w['bytes'],decoded=w['disassembly'])for o,w in sorted(blocks.items())],direct_contracts={k:catalog.get(k)for k in sorted(targets)},sources=[dict(source=a['source'],structure=a['structure']['PLI1.OVL+3DD9'],cases=[{k:r[k]for k in ['caller','call_step','entry_step','return_step','return_coordinate','entry','output','stack']}|dict(branches=[dict(offset=w['origin']['offset'],A=w['before']['a'],flags=w['before']['flags'],taken=w['control']['taken'])for w in rs['own_witnesses']if w['control']['kind']=='jump'],writes=r['law']['local_writes'],children=r['law']['children'])for r,rs in zip(a['roots'],rows_by_source[a['source']]['PLI1.OVL+3DD9'])])for a in analyses])
 return {'natural-cases':dict(sources=[{k:a[k]for k in ['source','capture','run_id','capture_sha256','image_sha256','structure']}|dict(cases=[{k:r[k]for k in ['caller','call_step','entry_step','return_step','return_coordinate','entry','output']}for r in a['roots']])for a in analyses]),'route-distribution':dict(sources=[dict(source=a['source'],routes=counts(r['law']['route']for r in a['roots']),CE=counts(f"{r['law']['C']:02X}/{r['law']['E']:02X}"for r in a['roots']),initial_fields=counts(str(r['law']['initial_field'])for r in a['roots']),scan_sizes=counts(str(r['law']['scan']['size'])for r in a['roots']),returns=counts(str(r['output']['a'])for r in a['roots']),leaf_fields=counts(str(r['law']['field'])for r in a['dependencies']['PLI1.OVL+3558']))for a in analyses]),'state-transition':dict(sources=[dict(source=a['source'],cases=[dict(call_step=r['call_step'],law={k:v for k,v in r['law'].items()if k not in ('children','local_writes')},ordered_children=[dict(callsite=c['callsite'],target=c['target'],call_step=c['call_step'],return_step=c['return_step'])for c in r['law']['children']],chronology=r['chronology'])for r in a['roots']])for a in analyses]),'dependency-assessment':dict(sources=[dict(source=a['source'],cases=a['dependencies'])for a in analyses]),'work-packet':packet}
if __name__=='__main__':
 import argparse
 from pathlib import Path
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True);args=p.parse_args()
 rows={s:gather(c,BOUNDS,include_nested_returns=True)for s,c in CAPTURES.items()};actual=derive([analyze(s,c,args.images,rows[s])for s,c in CAPTURES.items()],rows,args.images)
 args.output_dir.mkdir(parents=True,exist_ok=True)
 for n,d in actual.items():(args.output_dir/(n+'.json')).write_text(json.dumps(d,separators=(',',':'))+'\n')
