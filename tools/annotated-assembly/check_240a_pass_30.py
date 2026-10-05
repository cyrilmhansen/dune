"""Bounded accumulated-natural evidence, retaining actual CALL/return correlations."""
from collections import Counter
from pathlib import Path
import hashlib
from check_minimal_pass_2 import at,coord,load,pair,require
from check_minimal_pass_3 import gather
from procedure_evidence_packet import verify_return,ROOT
BOUNDS={'PLI1.OVL+240A':(0x240a,0x24f1),'PLI1.OVL+23A0':(0x23a0,0x23b8),'PLI1.OVL+23D2':(0x23d2,0x240a),'PLI1.OVL+2511':(0x2511,0x252b)}
CAPTURES={'MINIMAL':ROOT/'_build/minimal-baseline/capture','FIZZBUZ':ROOT/'_build/evidence-packet-cross-run/fizzbuz-capture','PICTURE':ROOT/'_build/discriminator-pass-15/selected-capture'}
FILES=['natural-paths','selector-distribution','23a0-cases','publication-correlations']
def counter(xs):return dict(sorted(Counter(xs).items()))
def one(ws,off):
 xs=at(ws,off);require(len(xs)==1,f'exact one +{off:04X}');return xs[0]
def cmp(a,b):
 r=(a-b)&255
 return dict(sign=r>=128,zero=r==0,auxiliary_carry=(a&15)>=(b&15),parity=r.bit_count()%2==0,carry=a<b)
def identity(r):return dict(caller=coord(r['call']['origin']),call_step=r['call']['step_index'],entry_step=r['entry']['step_index'],return_step=r['ret']['step_index'],input=r['entry']['before'],output=r['ret']['after'])
def entry_cells(capture,source):
 """Observed RAM cells only, not an inferred CPU snapshot or provenance model.

 Track all CPU and factual host writes in the relevant address set. Reads check
 continuity. An entry value must have an earlier observed access; no initial zero
 or image/path assumption fills missing evidence. Last writer identifies an actual
 event/address, never source-language ownership.
 """
 values,writer={},{};entries={};index=load(capture/'event-witnesses.json')
 require(index['run_id'].split(':')[0]==source,'selected run identity')
 def tracked(a):return 0xa628<=a<=0xa83a or a in (0xae32,0xae33)
 def remember(a,v,ref,old=None):
  if not tracked(a):return
  if old is not None and a in values:require(values[a]==old,f'write continuity {a:04X}')
  values[a]=v;writer[a]=ref
 for chunk in index['chunks']:
  for e in load(capture/'event-witnesses/chunks'/f"{chunk['id']:06d}.json")['events']:
   if e['type']=='host_effect'and e['effect']['kind']=='memory_write':
    w=e['effect'];remember(w['address'],w['new_value'],dict(step=e['step_index'],host_cause=w['cause']),w['old_value'])
   if e['type']!='instruction':continue
   w=e['witness']
   for q in w['reads']:
    a=q['address'];v=q['value']
    if tracked(a):
     if a in values:require(values[a]==v,f'read continuity {a:04X}')
     values[a]=v
   for q in w['writes']:remember(q['address'],q['new_value'],dict(step=w['step_index'],coordinate=coord(w['origin'])),q['old_value'])
   if w['control']['kind']=='call'and w['control']['taken']and coord(w.get('target_origin'))=='PLI1.OVL+240A':
    i=w['after']['c'];addresses=[0xa628+i,0xa62b+i,0xa62e+i,0xa642,0xa643,0xa63b+2*i,0xa63c+2*i,0xae32,0xae33]
    require(all(a in values for a in addresses),'missing observed entry cell')
    entries[w['step_index']]={a:dict(value=values[a],last_writer=writer.get(a))for a in addresses}
 return index['run_id'],entries

def minimum(r,image):
 ws=r['own_witnesses'];entry=r['entry']['before'];out=r['ret']['after'];c,e=entry['c'],entry['e'];ge=c>=e
 require(one(ws,0x23ac)['after']['flags']==cmp(c,e),'exact CMP flags')
 require(one(ws,0x23ad)['control']['taken']==ge,'JNC polarity')
 require(out['a']==min(c,e)and out['flags']==cmp(c,e),'minimum/returned flags separate')
 require(out['h']*256+out['l']==0xa64f,'HL retains compare pointer')
 require(all(out[k]==entry[k]for k in 'bcde'),'BC/DE preserved')
 writes=[(q['address'],q['new_value'])for w in ws for q in w['writes']]
 require(writes==[(0xa64f,e),(0xa64e,c)],'right then left cache order')
 return identity(r)|dict(path='C>=E'if ge else'C<E',C=c,E=e,result=out['a'],comparison_flags=cmp(c,e),return_coordinate=coord(r['ret']['origin']),writes=[list(q)for q in writes])

def publication(r):
 ws=r['own_witnesses'];i=r['entry']['before']['c'];channels=[]
 require([w['origin']['offset']for w in ws if w['control']['kind']=='call']==[0x23e4,0x23f5,0x2406],'three independent channels/order')
 for name,base,read,pos,site,child_map,dest in [
  ('control',0xa628,0x23df,0x23e0,0x23e4,0x7b22,0xac73),
  ('primary',0xa62b,0x23f0,0x23f1,0x23f5,0x7b3d,0xad08),
  ('secondary',0xa62e,0x2401,0x2402,0x2406,0x7b58,0xad9d)]:
  rd=one(ws,read)['reads'][0];carrier=one(ws,pos);call=one(ws,site);nested=r['nested_returns'][call['step_index']];verify_return(call,nested['ret'],nested['relation']);body=nested['memory_witnesses']
  require(rd['address']==base+i,'indexed source address')
  require([q['address']for q in carrier['reads']]==[0xae32,0xae33],'fresh position carrier')
  position=carrier['reads'][0]['value'];value=rd['value'];mapping=one(body,child_map)['reads'][0];index=mapping['value']
  require(mapping['address']==0xaa1f+position,'fresh map address')
  require(call['before']['c']==position and call['before']['e']==value,'actual setter arguments')
  writes=[q for w in body for q in w['writes']];selected=[q for q in writes if q['address']==dest+index]
  require(len(selected)==1 and selected[0]['new_value']==value,'unconditional selected publication')
  channels.append(dict(channel=name,source_address=base+i,source_value=value,source_read_step=one(ws,read)['step_index'],position=position,position_read_step=carrier['step_index'],discarded_position_neighbor=carrier['reads'][1]['value'],call_step=call['step_index'],callsite=f'PLI1.OVL+{site:04X}',map_address=mapping['address'],map_index=index,destination=dest+index,publication_step=next(w['step_index']for w in body if any(q['address']==dest+index for q in w['writes'])),output=nested['ret']['after'],writes=[[q['address'],q['new_value']]for q in writes]))
 out=r['ret']['after'];last=channels[-1]['output'];require(out==dict(last,sp=out['sp'],pc=out['pc']),'final setter ABI delegated')
 require(out['flags']==dict(r['entry']['before']['flags'],carry=False),'NZPA preserved/CY clear')
 require(out['a']==channels[-1]['source_value']and out['b']==0 and out['c']==channels[-1]['map_index'],'final A/BC')
 require(pair(out,'h','l')==channels[-1]['destination']and out['d']==r['entry']['before']['d']and out['e']==channels[-1]['source_value'],'final HL/DE channels')
 return identity(r)|dict(index=i,channels=channels)

def analyze_source(source,capture,images,rows=None):
 image=(images/'PLI1.OVL').read_bytes()
 if rows is None:rows=gather(capture,BOUNDS,include_nested_returns=True)
 run_id,entries=entry_cells(capture,source);mins=[];publications=[];naturals=[]
 for key,rs in rows.items():
  for r in rs:
   verify_return(r['call'],r['ret'],r['relation'])
   for w in r['own_witnesses']:
    require(w['origin']['image']['name']=='PLI1.OVL','canonical image')
    off=w['origin']['offset'];require(bytes.fromhex(w['bytes'])==image[off:off+len(bytes.fromhex(w['bytes']))],'exact historical instruction')
 for r in rows['PLI1.OVL+23A0']:mins.append(minimum(r,image))
 for r in rows['PLI1.OVL+23D2']:publications.append(publication(r))
 pub_by_step={p['entry_step']:p for p in publications};min_by_call={p['call_step']:p for p in mins}
 for r in rows['PLI1.OVL+240A']:
  ws=r['own_witnesses'];i=r['entry']['before']['c'];cells=entries[r['call']['step_index']];sel=one(ws,0x2417)['reads'][0]['value'];special=sel==0x15
  require(sel==cells[0xa628+i]['value'],'entry selector')
  branches=[dict(coordinate=coord(w['origin']),step=w['step_index'],taken=w['control']['taken'],producer=coord(ws[j-1]['origin']),flags=w['before']['flags'])for j,w in enumerate(ws)if w['control']['kind']=='jump'and w['bytes'][0:2]!='C3']
  require(one(ws,0x241a)['control']['taken']==(not special),'selector15 inequality')
  child_min=None
  if special:
   call=one(ws,0x242b);child_min=min_by_call[call['step_index']];require(call['before']['c']==cells[0xa642]['value']and call['before']['e']==cells[0xa62b+i]['value'],'limiter/right args')
   rewrite=one(ws,0x2437)['writes'][0];require(rewrite['address']==0xa62b+i and rewrite['new_value']==child_min['result'],'minimum rewrite')
   extra=one(ws,0x2441)['reads'][0]['value'];require(extra==0 and one(ws,0x2444)['control']['taken'],'only observed extra zero path')
  else:
   require(sel not in (0x16,0x19),'new selector arm needs separate interpretation')
   require(one(ws,0x2464)['control']['taken']and one(ws,0x24ac)['control']['taken'],'default comparisons skip both RAW arms')
  expected=[0x242b,0x24e6,0x24ed]if special else[0x24e6,0x24ed]
  require([w['origin']['offset']for w in ws if w['control']['kind']=='call']==expected,'exact direct chronology')
  low=one(ws,0x24df)['reads'][0];high=one(ws,0x24e1)['reads'][0];word=low['value']+256*high['value'];require([low['address'],high['address']]==[0xa63b+2*i,0xa63c+2*i],'pointer addresses')
  require(word==cells[low['address']]['value']+256*cells[high['address']]['value'],'pointer unchanged before selection')
  carrier=one(ws,0x24e2);call=one(ws,0x24e6);child=r['nested_returns'][call['step_index']];verify_return(call,child['ret'],child['relation']);body=child['memory_witnesses']
  pos=carrier['reads'][0]['value'];require(call['before']['c']==pos and pair(call['before'],'d','e')==word,'word publication arguments')
  mapping=one(body,0x7b01)['reads'][0];j=mapping['value'];require(mapping['address']==0xaa1f+pos,'fresh word map')
  writes=[q for w in body for q in w['writes']];dest=0xab49+2*j
  require([(q['address'],q['new_value'])for q in writes][-2:]==[(dest,word&255),(dest+1,word>>8)],'low then high word publication')
  final_call=one(ws,0x24ed);pub=pub_by_step[final_call['step_index']+1];require(pub['index']==i,'fresh saved index to publisher')
  require(r['ret']['after']==dict(pub['output'],sp=r['ret']['after']['sp'],pc=r['ret']['after']['pc']),'240A return delegated23D2')
  destinations=[dest,dest+1]+[c['destination']for c in pub['channels']]
  protected=set([0xa652,0xa653,0xa64e,0xa64f,0xa628+i,0xa62b+i,0xa62e+i,0xa63b+2*i,0xa63c+2*i,0xae32,0xae33,r['entry']['before']['sp'],r['entry']['before']['sp']+1])
  protected.update(range(r['entry']['before']['sp']-6,r['entry']['before']['sp']+2))
  protected.update(range(0xae3e,0xae47))
  maps={mapping['address']}|{c['map_address']for c in pub['channels']}
  require(not(set(destinations)&(protected|maps)),'publication/source/cache/map/stack alias')
  require(len(set(destinations))==len(destinations),'selected destination channels alias')
  naturals.append(identity(r)|dict(index=i,path='selector15_extra0'if special else'default_not15_16_19',selector=sel,entry_cells={f'{a:04X}':v for a,v in cells.items()},branches=branches,minimum=child_min,
   pointer=dict(low_address=low['address'],high_address=high['address'],word=word),word_publication=dict(position=pos,position_read_step=carrier['step_index'],neighbor=carrier['reads'][1]['value'],call_step=call['step_index'],map_address=mapping['address'],map_index=j,destination=dest,writes=[[q['address'],q['new_value']]for q in writes],output=child['ret']['after']),byte_publication_entry=pub['entry_step'],channels=pub['channels'],local_writes=[[q['address'],q['new_value']]for w in ws for q in w['writes']]))
 summary={key:dict(calls=len(rs),callers=counter(coord(r['call']['origin'])for r in rs),return_sites=counter(coord(r['ret']['origin'])for r in rs),own_coordinates=sorted({w['origin']['offset']for r in rs for w in r['own_witnesses']}),own_occurrences=sum(len(r['own_witnesses'])for r in rs),represented_bytes=len({w['origin']['offset']+n for r in rs for w in r['own_witnesses']for n in range(len(bytes.fromhex(w['bytes'])))}),direct_call_sites=counter(coord(w['origin'])for r in rs for w in r['own_witnesses']if w['control']['kind']=='call'))for key,rs in rows.items()}
 return dict(source=source,capture=str(capture.relative_to(ROOT)),run_id=run_id,image_sha256=hashlib.sha256(image).hexdigest(),structure=summary,naturals=naturals,minimum_cases=mins,publication_cases=publications)

def derive(analyses):
 result={n:{'sources':[]}for n in FILES}
 for a in analyses:
  source=a['source'];cs=a['naturals']
  compact=[]
  for c in cs:
   q={k:v for k,v in c.items()if k not in ('minimum','channels')}
   q['minimum_call_step']=c['minimum']['call_step']if c['minimum']else None
   compact.append(q)
  result['natural-paths']['sources'].append({k:a[k]for k in ['source','capture','run_id','image_sha256','structure']}|dict(cases=compact))
  result['selector-distribution']['sources'].append(dict(source=source,index_distribution=counter(str(c['index'])for c in cs),selector_hex_distribution=counter(f"{c['selector']:02X}"for c in cs),paths=counter(c['path']for c in cs),minimum_paths=counter(c['path']for c in a['minimum_cases']),minimum_caller_paths=counter(c['caller']+'/'+c['path']for c in a['minimum_cases'])))
  result['23a0-cases']['sources'].append(dict(source=source,cases=a['minimum_cases']))
  result['publication-correlations']['sources'].append(dict(source=source,cases=a['publication_cases']))
 return result

if __name__ == '__main__':
 import argparse,json
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--images',type=Path,required=True)
 parser.add_argument('--output-dir',type=Path,required=True)
 args=parser.parse_args()
 analyses=[analyze_source(s,p,args.images)for s,p in CAPTURES.items()]
 args.output_dir.mkdir(parents=True,exist_ok=True)
 for name,document in derive(analyses).items():
  (args.output_dir/(name+'.json')).write_text(json.dumps(document,indent=2)+'\n')
 print({a['source']:{k:v['calls']for k,v in a['structure'].items()}for a in analyses})
