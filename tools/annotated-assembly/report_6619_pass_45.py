"""Compact durable reports from independent Pass45 shadows and actual hybrids."""
import hashlib,json,re,subprocess,sys
from pathlib import Path
REPORT=Path('research/host-compiler/pass-45')
def load(p):return json.loads(Path(p).read_text())
def save(n,v):(REPORT/n).write_text(json.dumps(v,indent=2)+'\n')
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def report(proof_dir):
 p=Path(proof_dir);natural=load(p/'natural-cases.json');shadow=load(p/'shadow-summary.json');single=load(p/'single-hybrid-summary.json');cumulative=load(p/'cumulative-hybrid-summary.json')
 labels=['6619','6223','5929','2511','240A','23D2','23A0','80B7','7EC0','8048','7E5F','7D53','7C1B','7BBF','7B7A','7BA2','7AD5','7B64','7ABF','0EF6','7A79','7E46','7E56','7AF0','7B49','7A93','7B13']
 cases=[];hierarchy=[]
 for g,h in zip(natural['sources'],cumulative['sources']):
  members=[]
  for c in g['members']:
   j=c.pop('journal');members.append(c|{'journal_sha256':digest(j),'write_count':len(j),'logical_write_count':sum(w[4]=='logical'for w in j),'stack_last_writer_count':len({w[0]for w in j if w[4]!='logical'}),'stack_derivation':'historical CALL/PUSH/frame and N2/N8 writers, no post-RAM copy'})
  cases.append({'source':g['source'],'members':members})
  before=h['pre_transition_vector'];after=h['transition_vector']
  assert len(before)+1==len(after)
  hierarchy.append({'source':g['source'],'pre_guest_instructions':h['pre_guest_instructions'],'post_guest_instructions':h['result']['actual_guest_instructions'],'guest_instructions_removed':h['guest_instructions_removed'],'pre_host_transitions':sum(before),'post_host_transitions':sum(after),'wrapper_roots':after[0],'descendant_roots_absorbed':{labels[i+1]:a-b for i,(a,b)in enumerate(zip(before,after[1:]))if a!=b},'pre_vector':before,'post_vector':after,'nested_services':sum(len(c['service_details'])for c in members)})
 save('natural-cases.json',{'sources':cases,'all_passed':True})
 save('shadow-summary.json',shadow);save('single-hybrid-summary.json',single);save('cumulative-hybrid-summary.json',cumulative)
 save('hierarchy-summary.json',{'sources':hierarchy,'controller_order':labels,'logical6223_inside_wrapper':[1,18,2],'absorbed6223_roots':[1,12,2],'root_window_method':'corrected ordinary CALL/return ancestry; union/exclusion, no inclusive-window savings'})
 cat=load('research/annotated-assembly/procedures.json')['procedures'];view=load(REPORT/'implementation-packet.json')
 coords={v['id']for v in view['contracts']}|{'PLI1.OVL+25A9'}
 view['contracts']=[{'id':c['id'],'sha256':digest(c),'completeness':c['completeness']}for c in cat if c['id']in coords]
 view['root_proof']={'external':[1,9,2],'logical':[1,15,2],'internal6223':[1,18,2],'evidence':'shadow-summary.json','hybrids':'cumulative-hybrid-summary.json'}
 data=json.dumps(view,separators=(',',':'))+'\n';assert len(data.encode())<=32768;(REPORT/'implementation-packet.json').write_text(data)
 save('fidelity.json',{'archaeological_scope_extension':{'2259':'six natural cases, bounded new classifier/mask contract','345E':'three natural cases, bounded independent state transformation','25A9':'three natural cases, complete local indexed adapter with bounded2511 child','654E':'three found/repeat paths added; prior clear path remains valid'},'raw_to_understood':{'2259':38,'345E':72,'25A9':23,'654E':124},'historical_correction':None,'pragmatic_divergence':None,'fidelity_debt':None,'oracle_queries':0,'fresh_reads':'scratch carriers, selector, table offset, independent classifier, pointer/frame and search channels remain fresh','repeat_termination':'actual fresh57B7 result after canonical2511 state changes; no iteration/cycle/recursion limit','stack':'real inherited two-word frame; logical frame writes; CALL/PUSH last writers derived from current state and code; exact SP/PC; N2/N8 preserved inside canonical6223','transaction':'one generic Apply_host_program per accepted outer6619; nested operations and services internal; rejected preparations leave live state untouched','proof':['all18 logical6619 windows','all12 externalroots','all21 internal6223 checkpoints','ordered logicalwrites','full65536RAM','flags/SP/PC','stack lastwriters','DMA/filesystem/records/fileevents'],'unsupported':['6314/640D/6477 search-found alternatives','654E offset>5 subtraction arm','654E transform-set arm','wrapper selector-match alternatives','canonical6223 and2511 inherited exclusions','code/scratch/stack/table alias violations'],'Runner_changes':None,'CPU_changes':None,'CPM_changes':None})
 save('boundary-assessment.json',{'status':'bounded6619 native composition proven','next_recommendation':'Reassess +663C and its +6619/postcheck composition as the next coherent parent; compare actual remaining callers before migration. Keep other wrapper search/selector alternatives explicit.','reason':'All demonstrated external6223 roots now internal to6619; independently migrating acquisition leaves adds no leverage. All external6619 calls arise at663E.','checkpoint_base':'430b75bb82187216731f26588b3bfb48e6fed435','next_full_checkpoint':'by approximately Pass47 unless a systemic trigger occurs','globally_RAW_alternatives_not_causal_blockers':True})
 save('efficiency.json',{'packet_bytes':len(data.encode()),'oracle_queries':0,'driver_phases':['fresh hierarchy/route extraction','repeat-prefix/state projections','all2259 and345E independent inventory','all25A9 and654E independent inventory','aggregate incremental validation'],'generation_seconds':load(REPORT/'topology-summary.json')['generation_seconds'],'full_evidence_location':'ignored _build/host-compiler-pass-45','interactive_calls_this_continuation':'recorded in final validation report'})
 (REPORT/'README.md').write_text('''# Pass45: bounded native +6619 wrapper composition

Baseline full checkpoint: `430b75bb82187216731f26588b3bfb48e6fed435`.

The canonical `Pli80_host.Acquisition_family` now exposes +6619, +654E and
+25A9 alongside the previously reconstructed acquisition operations. The thin
bridge uses the existing copied RAM/process/filesystem host-program transaction.
Canonical Pass44 +6223 executes internally with its N=2/N=8 continuations.
There are no new independent Runner roots for the constituent wrappers/leaves.

Fresh corrected logical +6619 counts are 1/15/2; six FIZZBUZ windows already
belong to native +6223. The external roots are 1/9/2, all called from +663E.
Nine roots use clear-repeat scope and three FIZZBUZ roots use the newly proved
+654E search-found route. All 18 logical windows and all 12 external roots match
registers/flags, SP/PC, ordered logical writes, full64KiB RAM, derived stack last
writers, DMA/filesystem and output/service chronology. Internal +6223 checkpoints
independently match all 1/18/2 logical calls; their Runner root count is zero.

+57B7 searches the zero-terminated byte table at7969 against fresh20C3. Its
matched zero-based offset A935 is saved atF0. Fresh acquisition, independent
+64F2, pointer/index channel publications and bounded +345E follow. A fresh
classifier result plus wrapping8*F0 selects the byte through +25A9; that adapter
saves DE high then low and C, genuinely rereads both scratch carriers, and calls
canonical +2511 with byte[savedDE+zeroextendedC]. The loop searches again against
fresh20C3. The three natural cases each terminate after one found iteration and
a second not-found search because of actual shared-state changes, never a fixed
iteration schedule. Two POP H restore the inherited HL; final predicate flags
and A remain independent outputs.

New bounded descendants +2259 (five FIZZBUZ plus one PICTURE), +345E (three
FIZZBUZ), and +25A9 (three FIZZBUZ) are independently shadowed. +2259 and +345E
remain provisional/partial/partial. +25A9 has complete linear local control and
contract, with native support inheriting bounded +2511. +654E remains globally
provisional/partial/partial: offsets above5, transform-set and unrelated wrapper
alternatives are explicitly unsupported. This extends previously RAW scope;
it corrects no established historical fact. RAW-to-UNDERSTOOD gains are
38/72/23/124 bytes, totaling257. No historical oracle queries, runtime changes,
pragmatic divergence or fidelity debt.

Standalone and cumulative hybrids preserve exact INT/REL records, filesystem,
PASS1/PASS2/END COMPILATION and warm boot. Actual cumulative guest counters are
424898/995583/495210, removing426/10323/852 from the Pass44 baseline. Host
transitions are125/388/148 versus125/445/148. Counts come from whole execution,
not summed overlapping windows. See hierarchy-summary.json for absorption by
coordinate and cumulative-hybrid-summary.json for the exact REL hashes.

The deterministic driver regenerates compact topology and contract evidence;
`--validate` runs the selected incremental categories through the existing timed
regression runner. Exhaustive journals stay ignored under_build. Durable cases
retain hashes and counts rather than copied memory snapshots. Packet size stays
below32KiB. The exact reconstruction remains94720 bytes. Validation details and
elapsed times are in validation.json. The unrelated scripts/view-optimist.sh is
untouched. Final commit/push status is reported separately after validation.
''')
 print(json.dumps({'roots':[1,9,2],'logical':[1,15,2],'packet_bytes':len(data.encode()),'savings':[h['guest_instructions_removed']for h in hierarchy],'host_transitions':[h['post_host_transitions']for h in hierarchy]}))
if __name__=='__main__':report(sys.argv[1])
