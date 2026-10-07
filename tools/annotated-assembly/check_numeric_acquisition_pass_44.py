"""Rederive the bounded numeric law from corrected historical witnesses.
Only the required window inventory selects proof cases; no native semantics use it.
"""
from check_acquisition_pass_41 import *
def derive_numeric(rows,call_steps):
 selected=[q for q in rows['FIZZBUZ']['PLI.COM+1376']if q['call']['step_index']in call_steps]
 require(len(selected)==len(call_steps),'required inventory coverage')
 readers={q['call']['step_index']:q for q in rows['FIZZBUZ']['PLI.COM+12AE']};appends={q['call']['step_index']:q for q in rows['FIZZBUZ']['PLI.COM+1627']}
 cases=[];facts={}
 for q in selected:
  ws=local_proof(q);cs=children_any(q);prefix=[];reads=[];acc=0
  for child in cs:
   if child['target']=='PLI.COM+1627':
    law=mask_result(appends[child['call_step']]);require(law['width']==len(prefix)and law['old_accumulator']==acc,'fresh numeric prefix/accumulator');prefix.append(law['context']);acc=law['result']
   if child['target']=='PLI.COM+12AE':reads.append(indexed_reader(readers[child['call_step']]))
  require(all(0x30<=x<=0x39 for x in prefix),'actual numeric digit bytes');require(reads[-1]['value']==0x29,'retained natural following byte');require(len(prefix)==len(reads),'append precedes each following read')
  require(val(one(ws,0x13ad),0x20c1)==prefix[0],'initial context is first digit, not selector');require(one(ws,0x13e7)['writes'][0]['new_value']==2,'digit-selected selector02 publication')
  require(one(ws,0x154b)['before']['a']==0x7f and one(ws,0x154b)['before']['flags']==dict(sign=False,zero=True,auxiliary_carry=True,parity=True,carry=True),'final false digit/CMA/RAR flags independent of returnedA')
  out=q['ret']['after'];delegated(out,q['entry']['before'],a=0x7f,b=0,c=0x29,h=0x20,l=0x8f,flags=dict(sign=False,zero=True,auxiliary_carry=True,parity=True,carry=True))
  cases.append(dict(source='FIZZBUZ',caller=coord(q['call']['origin']),call_step=q['call']['step_index'],entry_step=q['entry']['step_index'],return_step=q['ret']['step_index'],entry=q['entry']['before'],output=out,initial_context=prefix[0],prefix=prefix,width=len(prefix),accumulator=acc,following_context=reads[-1]['value'],selector=2,reads=reads,children=[dict(site=c['callsite'],target=c['target'],entry=c['entry'],output=c['output'])for c in cs],writes=writes(ws),stack=stack_extended(q)))
  for w in ws:facts[w['origin']['offset']]=w
 return cases
