[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path text=let c=open_out path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_string c text;output_char c '\n')
let array f xs="["^String.concat","(List.map f xs)^"]"
let state(s:Runner.state_snapshot)=Printf.sprintf"{\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"sp\":%d,\"pc\":%d,\"flags\":{\"sign\":%b,\"zero\":%b,\"auxiliary_carry\":%b,\"parity\":%b,\"carry\":%b}}"s.a s.b s.c s.d s.e s.h s.l s.sp s.pc s.sign s.zero s.auxiliary_carry s.parity s.carry
module B=Pli80.Attribute_auxiliary_bridge
module N=Pli80.Native_attribute_auxiliary
let writes ws=array(fun(w:Pli80_host.Mapped_lookup.write)->Printf.sprintf"{\"address\":%d,\"value\":%d,\"phase\":%S}"w.address w.value w.phase)ws
let result=function
 |B.High q->Printf.sprintf"{\"byte_index\":%d,\"address\":%d,\"packed_byte\":%d,\"after_mask\":%d,\"shifts\":%s,\"shift_carries\":%s,\"high3\":%d,\"discarded_ae48\":%d}"q.byte_index q.address q.packed_byte q.after_mask(array string_of_int q.shifts)(array string_of_bool q.shift_carries)q.high3 q.discarded_ae48
 |B.Secondary q->Printf.sprintf"{\"position\":%d,\"index\":%d,\"address\":%d,\"value\":%d,\"discarded_high\":%d}"q.position q.index q.address q.value q.discarded_high
let case(c:N.case)=Printf.sprintf"{\"caller\":%S,\"entry_step\":%d,\"return_step\":%d,\"parent_entry_step\":%s,\"input\":%s,\"output\":%s,\"entry_memory_sha256\":%S,\"final_memory_sha256\":%S,\"logical_writes_sha256\":%S,\"result\":%s,\"writes\":%s,\"compatibility_writes\":%s,\"entry_scratch\":%s}"c.caller c.entry_step c.return_step(match c.parent_entry_step with None->"null"|Some n->string_of_int n)(state c.input)(state c.output)c.entry_memory_sha256 c.final_memory_sha256 c.logical_writes_sha256(result c.result)(writes c.writes)(array(fun(a,v)->Printf.sprintf"[%d,%d]"a v)c.compatibility_writes)(array(fun(a,v)->Printf.sprintf"[%d,%d]"a v)c.entry_scratch)
let goldens=["MINIMAL",256,"7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119";"FIZZBUZ",768,"68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203";"PICTURE",256,"c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1"]
let summary name count(r:Pli80.Experiment.result)=
 let _,size,sha=List.find(fun(n,_,_)->n=name)goldens in
 let rel=match r.rel_bytes with Some b->b|_->failwith"No REL"in
 let marker text=List.exists(fun(m:Pli80.Console_capture.message)->m.text=text)r.console_messages in
 if Bytes.length rel<>size || Pli80.Experiment.sha256_hex rel<>sha || not(marker"NO ERROR(S) IN PASS 1"&&marker"NO ERROR(S) IN PASS 2"&&marker"END  COMPILATION")||r.run.termination<>Runner.Warm_boot then failwith("Bad compilation oracle:"^name);
 Printf.sprintf"{\"source\":%S,\"invocations\":%d,\"REL_size\":%d,\"REL_sha256\":%S,\"PASS1\":true,\"PASS2\":true,\"END_COMPILATION\":true,\"termination\":\"warm_boot\",\"actual_guest_instructions\":%d,\"actual_guest_t_states\":%d,\"host_transitions\":%d}"name count size sha r.run.steps r.run.t_states r.run.host_transitions
let ()=
 let toolchain=ref""and output=ref""in
 Arg.parse["--toolchain",Arg.Set_string toolchain,"DISK1";"--output-dir",Arg.Set_string output,"new ignored output directory"](fun _->failwith"Unexpected argument")"pli80-native-attribute-auxiliary";
 if !toolchain=""|| !output=""||Sys.file_exists !output then failwith"Require toolchain and new output directory";
 Unix.mkdir !output 0o755;
 let proofs=ref[]and highs=ref[]and secondaries=ref[]and summaries=ref[]in
 List.iter(fun(name,_,_)->
  let image n=read(Filename.concat !toolchain n)in
  let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read("examples/pli80/"^name^".PLI"));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  match N.shadow input with Error _->failwith"Attribute/auxiliary shadows failed"|Ok(v,r)->
   let publication=match Pli80.Native_mapped_publication.shadow input with Ok(v,_)->v|_->failwith"Publication shadows failed"in
   let recursive=match Pli80.Native_7c1b.shadow input with Ok(v,_)->v|_->failwith"Recursive shadows failed"in
   let word=match Pli80.Native_7bbf.shadow input with Ok(v,_)->v|_->failwith"Packed shadows failed"in
   let balance=match Pli80.Native_7b7a.shadow input with Ok(v,_)->v|_->failwith"Balance shadows failed"in
   proofs:=(name,input,v,publication,recursive,word,balance)::!proofs;
   highs:=Printf.sprintf"{\"source\":%S,\"members\":%s}"name(array case(N.high_attributes v))::!highs;
   secondaries:=Printf.sprintf"{\"source\":%S,\"members\":%s}"name(array case(N.second_auxiliaries v))::!secondaries;
   summaries:=summary name(List.length(N.cases v))r::!summaries;
   Printf.printf"%s: %d high-attribute + %d second-auxiliary shadows passed\n%!"name(List.length(N.high_attributes v))(List.length(N.second_auxiliaries v)))goldens;
 write(Filename.concat !output"high-attribute-cases.json")("{\"sources\":"^array Fun.id(List.rev !highs)^"}");
 write(Filename.concat !output"second-auxiliary-cases.json")("{\"sources\":"^array Fun.id(List.rev !secondaries)^"}");
 write(Filename.concat !output"shadow-summary.json")("{\"sources\":"^array Fun.id(List.rev !summaries)^",\"all_passed\":true}");
 let singles=List.map(fun(name,(input:Pli80.Experiment.input),v,_,_,_,_)->
  (match N.single B.High_attribute v {input with max_steps=input.max_steps+1}with exception Failure _->()|_->failwith"Input proof mismatch accepted");
  (match N.single B.Second_auxiliary v {input with source_bytes=Bytes.empty}with exception Failure _->()|_->failwith"Source proof mismatch accepted");
  let single operation label=match N.single operation v input with
   |Ok([count],r)->Printf.printf"%s %s-only: %d\n%!"name label count;summary name count r
   |_->failwith"Single hybrid failed"in
  Printf.sprintf"{\"source\":%S,\"high_attribute\":%s,\"second_auxiliary\":%s}"name(single B.High_attribute "+7B64")(single B.Second_auxiliary "+7ABF")
 )(List.rev !proofs)in
 write(Filename.concat !output"single-hybrid-summary.json")("{\"sources\":"^array Fun.id singles^",\"no_fallback\":true}");
 let cumulative=List.map(fun(name,input,v,publication,recursive,word,balance)->
  (match N.cumulative v publication recursive word balance {input with source_bytes=Bytes.empty}with exception Failure _->()|_->failwith"Cumulative source mismatch accepted");
  (match N.controller ~exclude_entry_steps:[-1] B.High_attribute v input with exception Failure _->()|_->failwith"Invalid exclusion accepted");
  match N.cumulative v publication recursive word balance input with
  |Ok([roots;words;balances;recycles;pubs;highs;secondaries],r)->
   let records=array(fun(n,i,sha)->Printf.sprintf"{\"file\":%S,\"record\":%d,\"sha256\":%S}"n i sha)(N.record_summaries v)in
   let rec walk(t:Pli80_host.Recursive_mapped.node)=t::List.concat_map walk t.children in
   let nodes=List.concat_map(fun(c:Pli80.Native_7c1b.case)->walk c.result.tree)(Pli80.Native_7c1b.roots recursive)in
   let helpers=List.concat_map(fun(t:Pli80_host.Recursive_mapped.node)->t.helpers)nodes in
   let packed=List.length(List.filter(function Pli80_host.Recursive_mapped.Packed _->true|_->false)helpers)
   and balanced=List.length(List.filter(function Pli80_host.Recursive_mapped.Balance _->true|_->false)helpers)in
   Printf.printf"%s cumulative: %d roots + %d packed + %d balance + %d recycle + %d publication + %d high + %d secondary\n%!"name roots words balances recycles pubs highs secondaries;
   Printf.sprintf"{\"result\":%s,\"native_7C1B_roots\":%d,\"external_native_7BBF\":%d,\"external_native_7B7A\":%d,\"native_7BA2\":%d,\"external_native_7AD5\":%d,\"native_7B64\":%d,\"native_7ABF\":%d,\"logical_7AD5_inside_7BA2\":%d,\"logical_Packed_inside_7C1B\":%d,\"logical_Balance_inside_7C1B\":%d,\"logical_7C1B_nodes\":%d,\"all_entry_resume_memory_states_match\":true,\"INT_REL_records_match\":true,\"no_historical_replaced_body_execution\":true,\"record_oracles\":%s}"(summary name roots r)roots words balances recycles pubs highs secondaries recycles packed balanced(List.length nodes)records
  |_->failwith"Cumulative failed")(List.rev !proofs)in
 write(Filename.concat !output"cumulative-hybrid-summary.json")("{\"sources\":"^array Fun.id cumulative^",\"no_fallback\":true}")
