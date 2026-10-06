"""State-derived bounded acquisition/reentry contracts; no native replacement."""
from check_small_gates_pass_37 import (ROOT,CAPTURES,gather,coord,require,pair,load,one,identity,body,children,compact_child,stack,chronology,summarize,rotate,verify_return,counts,ats,val,writes,cmp,arithmetic,validate_data_writers)
from check_60e5_pass_33 import validate_leaf as pass33_leaf
from check_6223_pass_32 import child
from pathlib import Path
import json,hashlib
REPORT=ROOT/'research/host-compiler/pass-38'
ENTRIES=[0x506e,0x500f,0x4f54,0x4f2a,0x4cd4,0x2308,0x6619,0x65f9,0x654e,0x64f2,0x6477,0x640d,0x6314,0x625d,0x4cc2,0x4ce1,0x3304,0x23b9,0x4c4c,0x31fb,0x2705,0x329f]
BOUNDS={f'PLI1.OVL+{x:04X}':(x,x+1)for x in ENTRIES}
SPINE=[0x6619,0x65f9,0x654e,0x64f2,0x6477,0x640d,0x6314,0x625d]
def delegated(out,childout,**override):
 require(out==dict(childout,sp=out['sp'],pc=out['pc'],**override),'exact delegated state with explicit local overrides')
def validate(r):
 ws=r['own_witnesses'];e=r['entry']['before'];out=r['ret']['after'];k=r['entry_key'];cs=children(r)
 for w in ws:
  arithmetic(w)
  op,_,arg=w['disassembly'].partition(' ')
  if op in ('LDA','LHLD'):
   address=int(arg[:-1],16);expected=[address]if op=='LDA'else[address,(address+1)&65535]
   require([q['address']for q in w['reads']]==expected,'literal-address read chronology, including discarded neighboring bytes')
  elif w['reads']and (arg.endswith(',M')or arg=='M')and op in ('MOV','CMP','ADD','SUB'):
   require([q['address']for q in w['reads']]==[pair(w['before'],'h','l')],'memory operand uses actual pre-instruction carrier, not equal-valued provenance')
  if w['disassembly']=='RAR':rotate(w)
  if w['disassembly'].startswith('ADD '):
   b=w['reads'][0]['value']if w['disassembly']=='ADD M'else w['before'][w['disassembly'][-1].lower()];a=w['before']['a'];n=(a+b)&255
   require(w['after']['a']==n and w['after']['flags']==dict(sign=n>=128,zero=n==0,auxiliary_carry=(a&15)+(b&15)>15,parity=n.bit_count()%2==0,carry=a+b>255),'wrapping ADD result/flags independently derived')
 if k.endswith('500F'):
  law=pass33_leaf(r);require([c['target']for c in cs]==['PLI1.OVL+4F54','PLI1.OVL+2308','PLI1.OVL+2511','PLI1.OVL+4CD4'],'reuse exact Pass33 child chronology')
  f=e['sp']-1;require(one(ws,0x500f)['after']['b']==e['c']and one(ws,0x5010)['writes'][0]['address']==f and one(ws,0x5010)['writes'][0]['new_value']==e['c'],'one-byte private input originates MOV B,C/PUSH B/INX SP')
  rd=one(ws,0x5019)['reads'][0];pub=one(ws,0x501c)['writes'][0];require(rd['address']==0xa630 and pub['address']==0xa62e and pub['new_value']==rd['value'],'fresh A630 copied before independent C0 classifier wrapper')
  require(cs[1]['target']=='PLI1.OVL+2308'and cs[2]['entry']['c']==law['adjusted_C'],'2308 internally sets zero index; historical wrapping sum input for2511')
  return dict(law,route=law['path'],copy_A630=rd['value'],returned_A=out['a'],children=[compact_child(c)for c in cs])
 if k.endswith('506E'):
  S=e['sp'];F=S-8;require(e['c']==1,'only observed C1 dispatch; no index snapshot whitelist')
  require(one(ws,0x5073)['after']['sp']==S-7 and one(ws,0x5076)['after']['sp']==F,'three PUSH H and two one-byte saved arguments establish F=S-8')
  require(one(ws,0x507f)['writes'][0]['address']==F+2 and one(ws,0x5081)['writes'][0]['address']==F+3,'saved original pointer word in frame2/3')
  saved=pair(one(ws,0x5077)['after'],'h','l');require(cs[0]['entry']['c']==1 and cs[0]['target']=='PLI1.OVL+81F1','complete one-byte countdown before dispatch')
  require([c['target']for c in cs]==['PLI1.OVL+81F1','PLI1.OVL+500F','PLI1.OVL+4F2A'],'selected jump-table child chronology')
  for o in [0x508d,0x509f,0x56ea]:require(one(ws,o)['reads'][0]['address']==F+1 and one(ws,o)['reads'][0]['value']==e['e'],'each comparison freshly reads saved E, not an output register')
  lo=one(ws,0x50af)['reads'][0];hi=one(ws,0x50b1)['reads'][0];slot=(0x789f+2*e['e'])&65535;target=lo['value']+256*hi['value']
  require((lo['address'],hi['address'],target)==(slot,slot+1,0x75bb),'two historical DADs select actual jump-table word to53BB')
  require(one(ws,0x50b3)['control']['target']==target and cs[1]['entry']['c']==0xcf,'PCHL is a transfer, not fabricated CALL or direct53BB invocation')
  require(one(ws,0x5703)['writes'][0]['new_value']==saved&255 and one(ws,0x5703)['writes'][1]['new_value']==saved>>8,'restore original pointer low/high before result reread')
  require(val(one(ws,0x5706),0xa932)==out['a'],'final A comes from fresh A932 read, not4F2A returned A')
  require(pair(out,'h','l')==pair(e,'h','l')and pair(out,'d','e')==F+3 and pair(out,'b','c')==pair(cs[-1]['output'],'b','c')and out['flags']==dict(cmp(0x20,e['e']),carry=F+2>65535),'four POP H restore inherited HL; DE frame high-byte address; BC finalchild; NZPA final32-vs-savedE comparison and CY finalDADSP')
  return dict(route='saved_E_table53BB',frame_base=F,input_C=e['c'],saved_E=e['e'],saved_pointer=saved,jump_slot=slot,jump_target=target,returned_A=out['a'],children=[compact_child(c)for c in cs])
 if k.endswith('4F54'):
  require([c['target']for c in cs]==['PLI1.OVL+4CC2','PLI1.OVL+6619','PLI1.OVL+4CE1','PLI1.OVL+6619','PLI1.OVL+3304'],'first matched28 gate, first reentry, matched2C gate, second reentry, substantial final3304')
  require(all(not one(ws,o)['control']['taken']for o in [0x4f58,0x4f62]),'both actual RAR bit0 gates permit child calls')
  require(all(c['output']['a']&1 for c in [cs[0],cs[2]]),'independent pre-acquisition matches select both passes')
  delegated(out,cs[-1]['output'],a=1)
  return dict(route='both_match_gates_then_two_reentries',gate_masks=[cs[0]['output']['a'],cs[2]['output']['a']],final_child_A=cs[-1]['output']['a'],literal_return_A=1,children=[compact_child(c)for c in cs])
 if k.endswith('23B9'):
  require([(q['address'],q['value'])for q in writes(ws)]==[(0xa651,e['e']),(0xa650,e['c'])],'save E first then C')
  require(out['a']==max(e['c'],e['e'])and out['flags']==cmp(e['e'],e['c'])and pair(out,'h','l')==0xa650 and all(out[q]==e[q]for q in 'bcde'),'unsigned cached maximum, flags E-C independent of selected A')
  return dict(route='E_ge_C'if e['e']>=e['c']else'C_gt_E',C=e['c'],E=e['e'],result=out['a'])
 if k.endswith('2308')or k.endswith('4C4C'):
  expected='PLI1.OVL+22CB'if k.endswith('2308')else'PLI1.OVL+240A'
  require(len(cs)==1 and cs[0]['target']==expected and cs[0]['entry']['c']==0,'literal zero-index wrapper, fresh state selected by established child')
  delegated(out,cs[0]['output']);require(not writes(ws),'wrapper no local nonstack writes')
  return dict(route='C0_delegate',child_result=out['a'],children=[compact_child(cs[0])])
 if k[-4:]in ['4CC2','4CE1','4CD4']:
  want={'4CC2':0x28,'4CE1':0x2c,'4CD4':0x29}[k[-4:]];require(len(cs)==1 and cs[0]['target']=='PLI1.OVL+01AF'and cs[0]['entry']['c']==want,'independent selector-match/acquisition request')
  lastrotate=next(w for w in ws if w['disassembly']=='RAR');v=rotate(lastrotate);require(v['flags']['carry'],'only natural selector match returns bit0 set')
  branch=next(w for w in ws if w['control']['kind']=='jump');require(branch['control']['taken']==(k.endswith('4CD4')),'exact JNC/JC polarity')
  delegated(out,lastrotate['after'],**({}if k.endswith('4CD4')else dict(a=1)))
  return dict(route='matched_selector_then_acquisition',requested=want,child_result=cs[0]['output']['a'],rotate=v,children=[compact_child(cs[0])])
 if k.endswith('4F2A'):
  selector=val(one(ws,0x4f2a),0xa628);require(selector&0x14==0x14 and not one(ws,0x4f31)['control']['taken'],'14 mask condition permits normalization')
  require([c['target']for c in cs]==['PLI1.OVL+23B9','PLI1.OVL+4C4C'],'cached max then existing240A wrapper')
  paired=[one(ws,o)['reads']for o in [0x4f34,0x4f38]];require([[q['address']for q in rd]for rd in paired]==[[0xa62f,0xa630],[0xa630,0xa631]],'overlapping carriers each genuinely read both bytes')
  require(cs[0]['entry']['c']==paired[0][0]['value']and pair(cs[0]['entry'],'d','e')==paired[1][0]['value']+256*paired[1][1]['value'],'low bytes select max, neighboring bytes discarded for arguments')
  pub=one(ws,0x4f3f)['writes'][0];require((pub['address'],pub['new_value'])==(0xa62e,cs[0]['output']['a']),'max result published independently')
  d=val(one(ws,0x4f45),0xa62d);src=one(ws,0x4f48)['reads'][0];extra=one(ws,0x4f4c)['reads'][0];new=(d-src['value']+extra['value'])&255
  require(src['address']==0xa630 and extra['address']==0xa62e and one(ws,0x4f4d)['writes'][0]['new_value']==new,'fresh wrapping subtraction then fresh max addition publishes A62B')
  delegated(out,cs[-1]['output']);return dict(route='mask14_normalize_then240A',selector=selector,C=cs[0]['entry']['c'],E=cs[0]['entry']['e'],max_result=pub['new_value'],fresh_A62D=d,fresh_A630=src['value'],new_A62B=new,children=[compact_child(c)for c in cs])
 if k.endswith('31FB'):
  targets=['7A93','7AA9','7ABF','7A79','7B7A','7A93','7AA9','7ABF','7A79'];require([c['target']for c in cs]==['PLI1.OVL+'+x for x in targets],'two independent four-channel acquisitions with balance between')
  position=val(one(ws,0x31fb),0xae32);require(one(ws,0x31fe)['writes'][0]['new_value']==position,'fresh AE32 saved to A667')
  for i,c in enumerate(cs):
   carrier=one(ws,[0x3201,0x320b,0x3215,0x321f,0x3229,0x3234,0x323e,0x3248,0x3252][i]);require([q['address']for q in carrier['reads']]==[0xa667,0xa668],'independent genuine paired saved-position reread for every channel')
   expected=position if i<5 else (cs[4]['output']['a']-1)&255;require(carrier['reads'][0]['value']==expected and c['entry']['c']==expected,'fresh low position argument; high genuinely read, discarded')
  for i,o,address in [(0,0x3208,0xa62a),(1,0x3212,0xa62d),(2,0x321c,0xa630),(5,0x323b,0xa629),(6,0x3245,0xa62c),(7,0x324f,0xa62f)]:require(one(ws,o)['writes'][0]['address']==address and one(ws,o)['writes'][0]['new_value']==cs[i]['output']['a'],'distinct scalar channel publication')
  for i,o,address in [(3,0x3226,0xa63f),(8,0x3259,0xa63d)]:require([(q['address'],q['new_value'])for q in one(ws,o)['writes']]==[(address,cs[i]['output']['l']),(address+1,cs[i]['output']['h'])],'selected mapped-word low/high publication')
  dec=one(ws,0x3230);n=(cs[4]['output']['a']-1)&255;require(dec['after']['a']==n and dec['after']['flags']==dict(sign=n>=128,zero=n==0,auxiliary_carry=cs[4]['output']['a']&15!=0,parity=n.bit_count()%2==0,carry=cs[4]['output']['flags']['carry']),'DCR returned balance cursor before second group')
  require(one(ws,0x3231)['writes'][0]['new_value']==n,'publish decremented cursor, not original input')
  delegated(out,cs[-1]['output'],h=0xa6,l=0x34);require(one(ws,0x325f)['writes'][0]['new_value']==1,'final literal1 at A634 without recomputing flags')
  require(out['flags']==dict(dec['after']['flags'],carry=False),'NZPA/AC from DCR, CY final mapped-word lookup')
  return dict(route='two_fresh_four_channel_groups',first_position=position,balance_stop=cs[4]['output']['a'],second_position=n,children=[compact_child(c)for c in cs])
 if k.endswith('2705'):
  selector=val(one(ws,0x2705),0xa628);require(selector!=0x16 and one(ws,0x270a)['control']['taken'],'natural16-mismatch gate only')
  delegated(out,e,a=selector,flags=cmp(selector,0x16));require(not cs and not writes(ws),'mismatch leaf has no writes or calls')
  return dict(route='selector_not16',selector=selector)
 if k.endswith('329F'):
  rd=[one(ws,o)['reads']for o in [0x329f,0x32a3]];require([[q['address']for q in a]for a in rd]==[[0xa62c,0xa62d],[0xa62d,0xa62e]],'two independent overlapping paired field reads')
  require(len(cs)==1 and cs[0]['target']=='PLI1.OVL+23B9'and cs[0]['entry']['c']==rd[0][0]['value']and pair(cs[0]['entry'],'d','e')==rd[1][0]['value']+256*rd[1][1]['value'],'fresh low C and genuine neighboring-byte DE')
  require([(q['address'],q['value'])for q in writes(ws)]==[(0xa62b,cs[0]['output']['a']),(0xa62e,0)],'max publication before unconditional extra-zero publication')
  delegated(out,cs[0]['output'],h=0xa6,l=0x2e)
  return dict(route='fresh_max_then_extra_zero',C=rd[0][0]['value'],E=rd[1][0]['value'],neighbor=rd[1][1]['value'],maximum=out['a'],children=[compact_child(cs[0])])
 if k.endswith('3304'):
  require([c['target']for c in cs[:3]]==['PLI1.OVL+31FB','PLI1.OVL+30C1','PLI1.OVL+2705']and [c['target']for c in cs[-2:]]==['PLI1.OVL+2705','PLI1.OVL+329F'],'substantial delegated sequence with two independent selector comparisons')
  require(one(ws,0x331d)['writes'][0]['new_value']==2,'A634 publication is local literal2, not child result')
  delegated(out,cs[-1]['output']);return dict(route='substantial_delegated3304',children=[compact_child(c)for c in cs],scope='Observed interface only; child algorithms not reconstructed; not native-ready')
 if int(k[-4:],16)in SPINE:
  # Only the required clear-repeat route is promoted. Independent654E loops remain delegated.
  if k.endswith('654E')and len(cs)>2:return dict(route='independent_substantial654E_loop',scope='Outside required4F54 scope; unpromoted and not reconstructed',children=[compact_child(c)for c in cs])
  for w in ws:
   if w['control']['kind']=='jump':
    require(w['control']['taken']==(w['disassembly'].startswith('JNC')),'required clear-bit skip, including literal-match predicates and finite table miss')
  if k.endswith('625D'):
   require([c['target']for c in cs]==['PLI1.OVL+01AF','PLI1.OVL+6223','PLI1.OVL+01AF'],'A934.bit0 clear, requested28 mismatch, actual CALL6223, reset then requestedF9 mismatch')
   require(cs[0]['entry']['c']==0x28 and cs[-1]['entry']['c']==0xf9 and cs[0]['output']['a']==0 and cs[-1]['output']['a']==0,'two fresh independent unmatched selector probes around parent reentry')
   require([(q['address'],q['value'])for q in writes(ws)]==[(0xa934,0)],'reset A934 AFTER actual6223 return')
  expected=cs[-1]['output']if k.endswith('6314')else next(w for w in reversed(ws)if w['disassembly']=='RAR')['after']
  if k.endswith('654E'):expected=dict(expected,h=e['h'],l=e['l'])
  delegated(out,expected)
  return dict(route='clear_repeat_spine',children=[compact_child(c)for c in cs],branches=[[w['origin']['offset'],w['before']['a'],w['before']['flags'],w['control']['taken']]for w in ws if w['control']['kind']=='jump'])
 raise ValueError(k)
def analyze(source,capture,images,rows):
 raws={n:(images/n).read_bytes()for n in ['PLI1.OVL','PLI.COM']};cases={}
 for k,rs in rows.items():
  cases[k]=[]
  for r in rs:
   verify_return(r['call'],r['ret'],r['relation']);validate_data_writers(r)
   for w in body(r):
    name=w['origin']['image']['name'];o=w['origin']['offset'];b=bytes.fromhex(w['bytes']);require(name in raws and raws[name][o:o+len(b)]==b and w['runtime_pc']==o+(0x2200 if name=='PLI1.OVL'else 0x100),'immutable canonical image/offset bytes')
   require(r['ret']['after']['sp']==r['entry']['before']['sp']+2,'original ordinary hardware CALL continuation')
   cases[k].append(identity(r)|dict(law=validate(r),stack=stack(r),chronology=chronology(r)))
 return dict(source=source,structure={k:summarize(v)for k,v in rows.items()},cases=cases)
def reentries(rows):
 existing=load(ROOT/'research/host-compiler/pass-32/natural-roots.json');prior={r['call_step']:r for s in existing['sources']for r in s['roots']};result=[]
 for source,g in rows.items():
  for root in g['PLI1.OVL+4F54']:
   rs=[]
   for site in [0x4f5b,0x4f65]:
    c=child(root,site);chain=[];lower=c['call_step'];upper=c['return_step']
    for offset in SPINE:
     matches=[r for r in g[f'PLI1.OVL+{offset:04X}']if lower<=r['call']['step_index']and r['ret']['step_index']<=upper]
     require(len(matches)==1,'one corrected child on each required indirect spine, not a Cartesian pairing')
     r=matches[0];require(r['call']['step_index']==lower if not chain else lower<r['call']['step_index'],'actual nested CALL ancestry')
     chain.append(identity(r));lower=r['call']['step_index'];upper=r['ret']['step_index']
    direct=child(r,0x6273);record=prior[direct['call_step']];require(record['entry']==dict(direct['entry'])and record['output']==direct['output']and record['caller']=='PLI1.OVL+6273','reuse Pass32 corrected6223 identity exactly')
    require([q['caller']for q in chain]==[f'PLI1.OVL+{x:04X}'for x in [site,0x6619,0x65f9,0x6550,0x64f2,0x6478,0x640e,0x63c9]],'exact nine-edge indirect spine')
    gate=child(root,0x4f54 if site==0x4f5b else 0x4f5e);gatebody=root['nested_returns'][gate['call_step']]['memory_witnesses'];read=one(gatebody,0x01b6)['reads'][0]
    selector_writers=[dict(step=w['step_index'],writer=coord(w['origin']),value=q['new_value'])for w in gatebody for q in w['writes']if q['address']==0x20c3]
    require(read['address']==0x20c3 and read['value']==(0x28 if site==0x4f5b else 0x2c),'distinct requested-selector matches precede acquisitions')
    after=selector_writers[-1]['value'];require(after== (1 if site==0x4f5b else 2),'actual next-selector writer, not gate returned1')
    require(gate['return_step']<c['call_step']<direct['call_step']<direct['return_step']<c['return_step'],'acquisition then descendantCALL thenreturn then independentpostcheck')
    rs.append(dict(root_child_site=site,matching_selector=read['value'],selector_writers=selector_writers,next_selector=after,spine_calls=[[q['caller'],q['call_step'],q['return_step'],q['entry']['sp']]for q in chain],reentry={q:record[q]for q in ['call_step','return_step','route','predicate','local_predicate','value_flow']},child_return_A=c['output']['a']))
   require(rs[0]['spine_calls'][0][2]<rs[1]['spine_calls'][0][1],'first complete reentry returns before second is invoked')
   result.append(dict(source=source,root_call=root['call']['step_index'],reentries=rs))
 return result

def derive(rows,analyses):
 return dict(sources=[dict(source=a['source'],structure={k:{q:v[q]for q in ['calls','callers','returns','own_instruction_occurrences','represented_bytes']}for k,v in a['structure'].items()},routes={k:counts(r['law']['route']for r in rs)for k,rs in a['cases'].items()},root_values={k:[dict(call_step=r['call_step'],values={q:v for q,v in r['law'].items()if q not in ['children','branches']},output=r['output'],write_order_sha256=r['chronology']['cpu_nonstack_writes_sha256'])for r in a['cases'][k]]for k in ['PLI1.OVL+506E','PLI1.OVL+500F','PLI1.OVL+4F54','PLI1.OVL+4F2A']})for a in analyses],reentries=reentries(rows))

def build_packet(rows,catalog):
 cfg={};routes={};patterns={};writers=[];cases=[];contracts={};sources=list(rows);callers=[]
 for source,g in rows.items():
  for key,rs in g.items():
   old={q[0]:q for q in cfg.get(key,[])}
   for r in rs:
    if key.endswith('654E')and len(children(r))>2:continue
    for w in r['own_witnesses']:
     o=w['origin']['offset'];raw=bytes.fromhex(w['bytes']);kind=w['control']['kind'];succ=[o+len(raw)]
     if kind=='return':succ=['outer_return']
     elif kind=='jump'and len(raw)==3:succ=[raw[1]+256*raw[2]-0x2200]+([]if w['disassembly'].startswith('JMP ')else[o+len(raw)])
     elif w['disassembly']=='PCHL':succ=['word[789F+2*saved_E] selected53BB']
     elif kind=='call':succ=[coord(w['target_origin']),o+len(raw)]
     old[o]=[o,w['bytes'],w['disassembly'],succ]
   cfg[key]=[old[o]for o in sorted(old)]
   for r in rs:
    cs=children(r)
    for c in cs:
     k=c['target'];p=catalog.get(k);contracts[k]=None if p is None else dict(id=k,sha256=hashlib.sha256(json.dumps(p,sort_keys=True).encode()).hexdigest(),completeness=p['completeness'])
    if key not in ['PLI1.OVL+506E','PLI1.OVL+500F','PLI1.OVL+4F54']:continue
    own=r['own_witnesses'];S=r['entry']['before']['sp'];st=stack(r)
    layout=lambda a:['SP',a-S]if S-9<=a<S else a
    route=dict(entry=key,branches=[[w['origin']['offset'],w['control']['taken']]for w in own if w['control']['kind']=='jump'],write_layout=[[w['origin']['offset'],layout(q['address'])]for w in own for q in w['writes']if w['control']['kind']!='call'and not w['disassembly'].startswith('PUSH')],children=[[c['callsite'],c['target']]for c in cs])
    rid='r'+hashlib.sha256(json.dumps(route,sort_keys=True).encode()).hexdigest()[:8];pat=[]
    for q in st:
     if q['writer']not in writers:writers.append(q['writer'])
     # Full overwrite chronology is rederivable and hash-checked outside the view.
     pat.append([q['relative_address'],writers.index(q['writer'])])
    pid='s'+hashlib.sha256(json.dumps(pat).encode()).hexdigest()[:8]
    vals=lambda z:[z[k]for k in ['a','b','c','d','e','h','l','sp','pc']]+[int(z['flags']['sign'])*128+int(z['flags']['zero'])*64+int(z['flags']['auxiliary_carry'])*16+int(z['flags']['parity'])*4+int(z['flags']['carry'])]
    states=[vals(r['entry']['before']),vals(r['ret']['after'])];wv=[q['value']for q in writes(own)];sv=[q['value']for q in st]
    routes.setdefault(rid,route|dict(base_abi=states,base_write_values=wv));patterns.setdefault(pid,dict(writers=pat,base_values=sv))
    delta=lambda a,b:[[i,v]for i,v in enumerate(a)if b[i]!=v]
    caller=coord(r['call']['origin'])
    if caller not in callers:callers.append(caller)
    partial_io=[[c['entry']['a'],pair(c['entry'],'b','c'),pair(c['entry'],'d','e'),c['output']['a'],pair(c['output'],'b','c'),pair(c['output'],'d','e'),pair(c['output'],'h','l'),vals(c['output'])[-1]]for c in cs if catalog.get(c['target'],{}).get('completeness',{}).get('contract')!='complete']
    cases.append([sources.index(source),callers.index(caller),r['call']['step_index'],r['ret']['step_index'],rid,pid,delta(states[0],routes[rid]['base_abi'][0]),delta(states[1],routes[rid]['base_abi'][1]),delta(wv,routes[rid]['base_write_values']),delta(sv,patterns[pid]['base_values']),partial_io,chronology(r)['stack_writes_sha256']])
 return dict(baseline='280f491cc0c56af8b953944e95b7673263d434c0',schema='compact-target-work-packet-v2',sources=sources,callers=callers,abi_columns=['A','B','C','D','E','H','L','SP','PC','SZAPC_bits'],case_columns=['source','caller','call','return','route','stack','entry_deltas','return_deltas','write_deltas','stack_deltas','partial_child_io','full_stack_chronology_hash'],partial_io_columns=['entryA','entryBC','entryDE','returnA','returnBC','returnDE','returnHL','returnSZAPC'],cfg=cfg,routes=routes,stack_writers=writers,stack_patterns=patterns,contracts=contracts,cases=cases,counts={s:{k:len(v)for k,v in g.items()}for s,g in rows.items()})
def encode_full_proof(rows,analyses):
 """Intern each factual instruction once; overlapping windows refer to its step."""
 pools={s:{}for s in rows}
 def walk(source,x):
  if isinstance(x,dict):
   if 'disassembly'in x and 'step_index'in x and 'before'in x:
    k=str(x['step_index']);pool=pools[source]
    if k in pool:require(pool[k]==x,'one canonical factual witness per source/step')
    else:pool[k]=x
    return ['$w',x['step_index']]
   return {k:walk(source,v)for k,v in x.items()}
  if isinstance(x,list):return [walk(source,v)for v in x]
  return x
 refs={s:walk(s,g)for s,g in rows.items()}
 return (json.dumps(dict(schema='interned-natural-proof-v1',witnesses=pools,rows=refs,analyses=analyses),separators=(',',':'))+'\n').encode()
