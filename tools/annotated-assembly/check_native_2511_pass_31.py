"""Compact independent durable projection of the four native operation proofs."""
import hashlib,json
from collections import Counter
from pathlib import Path
from check_240a_pass_30 import BOUNDS,CAPTURES
from check_minimal_pass_2 import coord,load
from check_minimal_pass_3 import gather
from procedure_evidence_packet import ROOT
REPORT=ROOT/'research/host-compiler/pass-31'
ENTRIES={'minimum':'PLI1.OVL+23A0','publish':'PLI1.OVL+23D2','adapt':'PLI1.OVL+240A','saved':'PLI1.OVL+2511'}
EXTRA={'PLI1.OVL+80CA':(0x80ca,0x80ef),'PLI1.OVL+80EF':(0x80ef,0x810b)}
def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def compact(raw):
 sources=[]
 for group in raw['sources']:
  cases=[]
  for c in group['members']:
   stack=[a-c['input']['sp']for a,v,w,d,k in c['journal']if a>=0xaec0]
   cases.append(dict(caller=c['caller'],entry_step=c['entry_step'],return_step=c['return_step'],
    input_C=c['input']['c'],input_E=c['input']['e'],selector=c['result']['selector'],route=c['result']['route'],return_A=c['output']['a'],
    children=[[q['site'],q['input']['c'],q['input']['e'],q['output']['a']]for q in c['children']],
    stack_lowest_relative_address=min(stack,default=0),proof_sha256=digest(c)))
  sources.append(dict(source=group['source'],operation=group['operation'],count=len(cases),callers=dict(sorted(Counter(c['caller']for c in cases).items())),
   paths=dict(sorted(Counter(c['route']for c in cases).items())),cases=cases))
 return dict(proof_digest='SHA256 canonical sorted-key JSON of the complete fresh case: every register/flag, entry/post RAM and filesystem hashes, DMA, ordered journal with writer/depth/kind, child machine states and service effects.',sources=sources,all_passed=raw['all_passed'])
def boundary(rows):
 return {source:{key:dict(calls=len(rs),callers=dict(sorted(Counter(coord(r['call']['origin'])for r in rs).items())),
  own_occurrences=sum(len(r['own_witnesses'])for r in rs),inclusive_memory_instruction_occurrences=sum(len(r['own_witnesses'])+sum(len(q['memory_witnesses'])for q in r['nested_returns'].values())for r in rs),
  direct_targets=dict(sorted(Counter(coord(w.get('target_origin'))for r in rs for w in r['own_witnesses']if w['control']['kind']=='call'and w['control']['taken']).items())))for key,rs in targets.items()if key in EXTRA}for source,targets in rows.items()}

def enclosing_parents(capture, roots):
 """Nearest *corrected ordinary window*, not inferred procedure/basic-block ownership."""
 from procedure_evidence_packet import verify_return
 calls={};closed=[];last=None
 index=load(capture/'event-witnesses.json')
 for chunk in index['chunks']:
  events=load(capture/'event-witnesses/chunks'/f"{chunk['id']:06d}.json")['events']
  for event in events:
   if event['type']=='instruction':
    last=event['witness']
    if last['control']['kind']=='call'and last['control']['taken']:calls[last['step_index']]=last
   elif event['type']=='hardware_frame_return':
    call=calls.pop(event['frame']['call_step']);verify_return(call,last,event)
    closed.append((call['step_index'],last['step_index'],call['after']['sp'],coord(call.get('target_origin'))))
 native={ENTRIES[k]for k in ENTRIES}|{'PLI1.OVL+'+x for x in ['80B7','7EC0','8048','7E5F','7D53','7C1B','7BBF','7B7A','7BA2','7AD5','7B64','7ABF','7A79','7E46','7E56','7AF0','7B49','7A93','7B13']}|{'PLI.COM+0EF6'}
 candidates=['PLI1.OVL+'+x for x in ['80CA','80EF','58BB','5929','6223','0D6E','256C','25A9']]
 leverage={}
 for key in candidates:
  windows=[q for q in closed if q[3]==key];inclusive=residual=0
  for a,b,sp,_ in windows:
   inclusive+=b-a
   intervals=sorted((x+1,y)for x,y,s,k in closed if k in native and a<x and y<b)
   union=[]
   for x,y in intervals:
    if union and x<=union[-1][1]+1:union[-1]=(union[-1][0],max(y,union[-1][1]))
    else:union.append((x,y))
   residual+=b-a-sum(y-x+1 for x,y in union)
  leverage[key]=dict(ordinary_windows=len(windows),historical_instruction_occurrences=inclusive,residual_guest_instruction_occurrences_with_current_native_descendants=residual)
 result={}
 for c in roots:
  parents=[q for q in closed if q[0]<c['entry_step']-1 and q[1]>c['return_step']and q[2]>=c['input']['sp']+2]
  if not parents:continue
  a,b,sp,key=max(parents,key=lambda q:q[0]);q=result.setdefault(key,dict(contained_2511_roots=0,ordinary_parent_windows={},absorbed_2511_instruction_occurrences=0))
  q['contained_2511_roots']+=1;q['ordinary_parent_windows'][a]=b-a;q['absorbed_2511_instruction_occurrences']+=c['return_step']-c['entry_step']+1
 for q in result.values():q['ordinary_parent_window_count']=len(q['ordinary_parent_windows']);q['inclusive_instruction_occurrences']=sum(q.pop('ordinary_parent_windows').values())
 return dict(nearest_enclosing_windows=dict(sorted(result.items())),candidate_residual_leverage=leverage)
