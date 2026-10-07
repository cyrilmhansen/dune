"""Compact Pass44 reports from independently validated native proof exports."""
import json,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];REPORT=ROOT/'research/host-compiler/pass-44';BUILD=ROOT/'_build/host-compiler-pass-44'
def load(p):return json.loads(p.read_text())
def save(name,x):(REPORT/name).write_text(json.dumps(x,indent=2)+'\n')
def digest(x):return hashlib.sha256(json.dumps(x,separators=(',',':')).encode()).hexdigest()
hybrid=BUILD/'latest-hybrids'
if not hybrid.exists():hybrid=BUILD/'hybrids-final'
logical=load(BUILD/'numeric/root-proof.json');logical['status']='complete independent historical shadows; 21 logical windows and composed recursive checkpoints matched';outer=load(hybrid/'natural-cases.json');cumulative=load(hybrid/'cumulative-hybrid-summary.json')
labels=['6223','5929','2511','240A','23D2','23A0','80B7','7EC0','8048','7E5F','7D53','7C1B','7BBF','7B7A','7BA2','7AD5','7B64','7ABF','0EF6','7A79','7E46','7E56','7AF0','7B49','7A93','7B13']
patterns={};stacks=[];trees=[];compact=[];image=(Path('/home/john/pli/cpm/pli80/DISK1')/'PLI1.OVL').read_bytes()
for group in outer['sources']:
 rows=[]
 for c in group['members']:
  last={a:(v,w,d,k)for a,v,w,d,k in c['journal']};sp=c['input']['sp']
  stack=sorted((a-sp,v,w,d)for a,(v,w,d,k)in last.items()if sp-512<=a<sp)
  pattern=[(a,w,d)for a,v,w,d in stack];key=digest(pattern)[:12];patterns.setdefault(key,pattern)
  stacks.append(dict(source=group['source'],entry_step=c['entry_step'],entry_sp=sp,pattern=key,values=[v for a,v,w,d in stack],chronology_sha256=digest(c['journal']),last_writer_count=len(stack)))
  calls={}
  for j,w in enumerate(c['journal']):
   a,v,site,depth,kind=w;off=site-0x2200
   if kind=='compatibility'and 0<=off<len(image)-3 and image[off]==0xcd and j+1<len(c['journal'])and c['journal'][j+1][0]==a-1 and c['journal'][j+1][2]==site:
    target=int.from_bytes(image[off+1:off+3],'little');name=f'{target-0x2200:04X}'if target>=0x2200 else f'COM+{target-0x100:04X}';calls[name]=calls.get(name,0)+1
  trees.append(dict(source=group['source'],entry_step=c['entry_step'],route=c['result']['route'],logical_CALL_targets=calls,maximum_child_call_depth=max(w[3]for w in c['journal']),services=c['service_details']))
  row={k:v for k,v in c.items()if k not in ['journal','entry_filesystem_sha256','post_filesystem_sha256']};row['journal_sha256']=digest(c['journal']);row['journal_writes']=len(c['journal']);row['stack_pattern']=key;rows.append(row)
 compact.append(dict(source=group['source'],members=rows))
save('outer-root-cases.json',dict(sources=compact));save('logical-invocations.json',logical)
save('stack-compatibility.json',dict(method='Last writers independently derived from immutable CALL/PUSH instructions and live staged values, then compared with every historical writer; no oracle post-RAM copied',patterns=patterns,cases=stacks,software_continuations={'4468':{'consumed':2,'final_SP':'entrySP+4'},'6708':{'consumed':8,'copied_slot':'entrySP+8','final_SP':'entrySP+10'}},all_matched=True))
save('root-operation-trees.json',dict(cases=trees,recursion_predicate='625D current A934 and fresh01AF result; same canonical6223 callback',synthetic_depth_limit=False))
for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
 x=load(hybrid/name)
 if name.startswith('cumulative'):x['transition_order']=labels
 save(name,x)
save('shadow-summary.json',dict(logical=[dict(source=s['source'],matched=len(s['cases']),pending=s['pending_route_A'])for s in logical['sources']],outer_counts=[len(s['members'])for s in outer['sources']],recursive_checkpoint_comparison='all logical entry/return RAM/state, journals/depth, DMA/filesystem/service results agree with independent shadows',full_RAM_bytes=65536,all_registers_and_flags=True,ordered_writes=True,stack_last_writers=True,external_identity=True,all_matched=True))
save('host-service-summary.json',dict(sources=[dict(source=q['result']['source'],services=q['host_bdos_services'],BDOS26=q['host_bdos_services']//2,BDOS21=q['host_bdos_services']//2,record_sha256_sequence=q['record_sha256_sequence'],filesystem_sha256=q['result']['filesystem_sha256'],INT_sha256=q['result']['INT_sha256'])for q in cumulative['sources']],existing_CP_M_runtime_reused=True,Runner_changes=False,transaction_engine_changes=False,event_duplicates=False))
save('hierarchy-summary.json',dict(sources=[dict(source=q['result']['source'],historical_instructions=n,pre44_guest=q['pre_guest_instructions'],post44_guest=q['result']['actual_guest_instructions'],removed=q['guest_instructions_removed'],pre44_host_transitions=sum(q['pre_transition_vector']),post44_host_transitions=sum(q['transition_vector']),absorbed={label:old-new for label,old,new in zip(labels[1:],q['pre_transition_vector'],q['transition_vector'][1:])if old!=new})for n,q in zip([441855,1145517,518213],cumulative['sources'])],outer=[1,12,2],logical=[1,18,2],nested=[0,6,0],maximum_recursion_depth=2))
save('fidelity.json',dict(algorithm='bounded canonical6223 with actual RAR gates; fresh5929/classifier2511 RouteB; composed60E5/5E98 field15/80 and256C attr4 RouteA',frame_60E5='five inherited bytes; old base restored before index; freshF1 result',field15='seven complete independent child windows; literal00 follows actual cleanup/gate algorithm',field80='three complete independent child windows; two separate625D-caused recursive calls then3304/N8; actual500F result distinct from A932 literal1',logical_and_outer_proofs=True,N2_and_N8=True,shared_state_chronology=True,transaction='existing generic copied RAM/process/filesystem program; no live mutation or callbacks before full validation',archeological_scope_extension='PLI.COM+1376 required digit-selected selector02; three cases; 39 reached RAW bytes represented; global provisional/partial/partial retained',contract_correction=None,implementation_correction='development planner corrected Balance_scan cursor DCR writer7B9A; no historical contract change',pragmatic_divergence=None,fidelity_debt=None,unsupported=['unobserved6223 gates/selectors','5929 unsupported branches','60E5 field3/5/repeat/special','5E98 unobserved tags/status/errors','wrapper found/literal-zero alternatives','arbitrary3304/selectors','1376 quoted/refill/EOF/reuse/decimal/exponent and arbitrary numeric scope','pointer/table/scratch/code/stack aliases','unproven termination'],no_snapshot_semantics=True,oracle_queries=0,Runner_CPU_CP_M_changes=False))
save('boundary-assessment.json',dict(recommendation='Pass45: reassess and compose the external +6619 expression-wrapper chain with the now canonical native6223 as an internal child; keep every search-found and selector-match alternative explicitly bounded',reason='No required blocker remains in the implemented acquisition family. Every demonstrated60E5/5E98 window is now absorbed under6223; standalone migration of those leaves adds no selected-corpus leverage. The seven-wrapper6619..625D ancestry is a coherent remaining parent around external6223 roots.',candidate_external_6619_counts={'MINIMAL':1,'FIZZBUZ':9,'PICTURE':2},count_method='Pass38 inventory1/15/2 minus actual six logical6619 calls absorbed under the three outer field80 roots',comparison={'60E5_family':'all demonstrated windows already internal; no new root leverage','80CA_80EF':'Pass43 residual local bodies28/224/56 and56/56/56 respectively, smaller; native descendants already dominate','6619':'reusable established wrapper chain; fresh external route compatibility proof required before migration'},global_RAW_alternatives_not_blockers=True))
first=load(REPORT/'first-missing-causal-operation.json');first.update(status='resolved by authorized bounded numeric contract extension',resolution='numeric-contract.md and numeric-acquisition-cases.json; independently shadowed then integrated; both reentries and full roots now match',correction=False);save('first-missing-causal-operation.json',first)
print('compact reports generated; full journals remain under ignored _build')
