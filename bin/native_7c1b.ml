[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path text=let c=open_out path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_string c text;output_char c '\n')
let array f xs="["^String.concat","(List.map f xs)^"]"
let state(s:Runner.state_snapshot)=Printf.sprintf"{\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"sp\":%d,\"pc\":%d,\"flags\":{\"sign\":%b,\"zero\":%b,\"auxiliary_carry\":%b,\"parity\":%b,\"carry\":%b}}"s.a s.b s.c s.d s.e s.h s.l s.sp s.pc s.sign s.zero s.auxiliary_carry s.parity s.carry
module R=Pli80_host.Recursive_mapped
let writes ws=array(fun(w:R.write)->Printf.sprintf"{\"address\":%d,\"value\":%d,\"writer\":%d,\"depth\":%d,\"phase\":%S}"w.address w.value w.writer w.depth w.phase)ws
let helper=function
 |R.Mapping(site,q)->Printf.sprintf"{\"site\":%d,\"kind\":\"mapping\",\"position\":%d,\"index\":%d,\"mapped\":%d}"site q.position q.index q.byte
 |R.Attribute(site,q)->Printf.sprintf"{\"site\":%d,\"kind\":\"attribute\",\"position\":%d,\"index\":%d,\"mapped\":%d,\"packed\":%d,\"low3\":%d}"site q.mapped.position q.mapped.index q.mapped.byte q.packed_byte q.low3
 |R.Auxiliary_read(site,q)|R.Auxiliary_write(site,q)as h->Printf.sprintf"{\"site\":%d,\"kind\":%S,\"position\":%d,\"index\":%d,\"address\":%d,\"value\":%d,\"discarded_high\":%d}"site (match h with R.Auxiliary_read _->"auxiliary_read"|_->"auxiliary_write")q.position q.index q.address q.value q.discarded_high
 |R.Packed(site,q)->Printf.sprintf"{\"site\":%d,\"kind\":\"packed\",\"position\":%d,\"word\":%d,\"shifted_word\":%d,\"counter\":%d,\"shifts\":%d,\"fresh_index\":%d}"site q.position q.initial_word q.shifted_word q.counter q.shifts q.fresh_index
 |R.Balance(site,q)->Printf.sprintf"{\"site\":%d,\"kind\":\"balance\",\"start\":%d,\"stop\":%d,\"iterations\":%s}"site q.start_cursor q.stop_cursor(array(fun(i:Pli80_host.Balance_scan.iteration)->Printf.sprintf"{\"cursor\":%d,\"index\":%d,\"mapped\":%d,\"packed\":%d,\"attribute\":%d,\"before\":%d,\"sum\":%d,\"after\":%d}"i.cursor i.lookup.mapped.index i.lookup.mapped.byte i.lookup.packed_byte i.lookup.low3 i.balance_before i.temporary_sum i.balance_after)q.iterations)
let rec tree(n:R.node)=Printf.sprintf"{\"frame\":%d,\"depth\":%d,\"position\":%d,\"entry_HL\":%d,\"entry_DE\":%d,\"entry_SP\":%d,\"initial_frame\":%s,\"mapped\":%d,\"path\":%S,\"children\":%s,\"helpers\":%s,\"final_frame\":%s,\"returned_A\":%d,\"return_site\":%d}"n.frame n.depth n.entry.position n.entry.hl n.entry.de n.entry.sp(array string_of_int n.initial_frame)n.mapped n.path(array tree n.children)(array helper n.helpers)(array string_of_int n.final_frame)n.returned.a n.return_site
let case(c:Pli80.Native_7c1b.case)=Printf.sprintf"{\"caller\":%S,\"entry_step\":%d,\"return_step\":%d,\"parent_entry_step\":%s,\"input\":%s,\"output\":%s,\"entry_memory_sha256\":%S,\"final_memory_sha256\":%S,\"logical_writes_sha256\":%S,\"tree\":%s,\"writes\":%s,\"compatibility_writes\":%s,\"final_writers\":%s}"c.caller c.entry_step c.return_step(match c.parent_entry_step with None->"null"|Some n->string_of_int n)(state c.input)(state c.output)c.entry_memory_sha256 c.final_memory_sha256 c.logical_writes_sha256(tree c.result.tree)(writes c.result.writes)(array(fun(a,v)->Printf.sprintf"[%d,%d]"a v)c.compatibility_writes)(array(fun(q:Pli80.Recursive_mapped_bridge.residue)->Printf.sprintf"{\"address\":%d,\"value\":%d,\"writer\":%d,\"depth\":%d,\"kind\":%S}"q.address q.value q.writer q.depth q.kind)c.final_writers)
let goldens=["MINIMAL",256,"7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119";"FIZZBUZ",768,"68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203";"PICTURE",256,"c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1"]
let summary name count(r:Pli80.Experiment.result)=
 let _,size,sha=List.find(fun(n,_,_)->n=name)goldens in
 let rel=match r.rel_bytes with Some b->b|_->failwith"No REL"in
 let marker text=List.exists(fun(m:Pli80.Console_capture.message)->m.text=text)r.console_messages in
 if Bytes.length rel<>size || Pli80.Experiment.sha256_hex rel<>sha || not(marker"NO ERROR(S) IN PASS 1"&&marker"NO ERROR(S) IN PASS 2"&&marker"END  COMPILATION")||r.run.termination<>Runner.Warm_boot then failwith("Bad compilation oracle:"^name);
 Printf.sprintf"{\"source\":%S,\"invocations\":%d,\"REL_size\":%d,\"REL_sha256\":%S,\"PASS1\":true,\"PASS2\":true,\"END_COMPILATION\":true,\"termination\":\"warm_boot\",\"actual_guest_instructions\":%d,\"actual_guest_t_states\":%d,\"host_transitions\":%d}"name count size sha r.run.steps r.run.t_states r.run.host_transitions
let ()=
 let toolchain=ref""and output=ref""in
 Arg.parse["--toolchain",Arg.Set_string toolchain,"DISK1";"--output-dir",Arg.Set_string output,"new ignored output directory"](fun _->failwith"Unexpected argument")"pli80-native-7c1b";
 if !toolchain=""|| !output=""||Sys.file_exists !output then failwith"Require toolchain and new output directory";
 Unix.mkdir !output 0o755;
 let proofs=ref[]and cases=ref[]and summaries=ref[]in
 List.iter(fun(name,_,_)->
  let image n=read(Filename.concat !toolchain n)in
  let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read("examples/pli80/"^name^".PLI"));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  match Pli80.Native_7c1b.shadow input with Error _->failwith"7C1B shadow failed"|Ok(v,r)->
   let word=match Pli80.Native_7bbf.shadow input with Ok(v,_)->v|_->failwith"7BBF shadow failed"in
   let balance=match Pli80.Native_7b7a.shadow input with Ok(v,_)->v|_->failwith"7B7A shadow failed"in
   proofs:=(name,input,v,word,balance)::!proofs;
   let cs=Pli80.Native_7c1b.cases v in
   cases:=Printf.sprintf"{\"source\":%S,\"members\":%s}"name(array case cs)::!cases;
   summaries:=summary name(List.length cs)r::!summaries;
   Printf.printf"%s: %d recursive shadows passed; %d roots\n%!"name(List.length cs)(List.length(Pli80.Native_7c1b.roots v)))goldens;
 write(Filename.concat !output"recursive-cases.json")("{\"sources\":"^array Fun.id(List.rev !cases)^"}");
 write(Filename.concat !output"shadow-summary.json")("{\"sources\":"^array Fun.id(List.rev !summaries)^",\"all_passed\":true}");
 let singles=List.map(fun(name,(input:Pli80.Experiment.input),v,_,_)->
  (match Pli80.Native_7c1b.hybrid v {input with max_steps=input.max_steps+1}with exception Failure _->()|_->failwith"Input proof mismatch accepted");
  (match Pli80.Native_7c1b.hybrid v {input with source_bytes=Bytes.empty}with exception Failure _->()|_->failwith"Source proof mismatch accepted");
  match Pli80.Native_7c1b.hybrid v input with Ok([count],r)->Printf.printf"%s +7C1B-only: %d roots\n%!"name count;summary name count r|_->failwith"Single hybrid failed")(List.rev !proofs)in
 write(Filename.concat !output"single-hybrid-summary.json")("{\"sources\":"^array Fun.id singles^",\"no_fallback\":true}");
 let cumulative=List.map(fun(name,(input:Pli80.Experiment.input),v,word,balance)->
  (match Pli80.Native_7c1b.cumulative v word balance {input with source_bytes=Bytes.empty}with exception Failure _->()|_->failwith"Cumulative source proof mismatch accepted");
  match Pli80.Native_7c1b.cumulative v word balance input with
  |Ok([roots;words;balances],r)->
   let records=array(fun(n,i,sha)->Printf.sprintf"{\"file\":%S,\"record\":%d,\"sha256\":%S}"n i sha)(Pli80.Native_7c1b.record_summaries v)in
   Printf.printf"%s cumulative: %d roots + %d external word + %d external balance\n%!"name roots words balances;
   Printf.sprintf"{\"result\":%s,\"native_7C1B_roots\":%d,\"external_native_7BBF\":%d,\"external_native_7B7A\":%d,\"all_entry_resume_memory_states_match\":true,\"INT_REL_records_match\":true,\"no_historical_replaced_body_execution\":true,\"record_oracles\":%s}"(summary name roots r)roots words balances records
  |_->failwith"Cumulative hybrid failed")(List.rev !proofs)in
 write(Filename.concat !output"cumulative-hybrid-summary.json")("{\"sources\":"^array Fun.id cumulative^",\"no_fallback\":true}")
