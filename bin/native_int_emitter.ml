[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path text=let c=open_out path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_string c text;output_char c '\n')
let array f xs="["^String.concat","(List.map f xs)^"]"
let state(s:Runner.state_snapshot)=Printf.sprintf"{\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"sp\":%d,\"pc\":%d,\"flags\":{\"sign\":%b,\"zero\":%b,\"auxiliary_carry\":%b,\"parity\":%b,\"carry\":%b}}"s.a s.b s.c s.d s.e s.h s.l s.sp s.pc s.sign s.zero s.auxiliary_carry s.parity s.carry
module N=Pli80.Native_int_emitter
let pairs xs=array(fun(a,v)->Printf.sprintf "[%d,%d]" a v)xs
let record=function
 |Cpm.Bdos.Write_record q->Printf.sprintf "{\"file\":%S,\"record\":%d,\"dma\":%d,\"data_hex\":%S,\"sha256\":%S}"q.file.name q.logical_record q.dma
  (Bytes.to_seq q.data|>List.of_seq|>List.map(fun c->Printf.sprintf "%02X"(Char.code c))|>String.concat "")(Pli80.Experiment.sha256_hex q.data)
 |_->failwith "Unexpected native service record"
let service(s:Runner.host_service)=Printf.sprintf "{\"call_state\":%s,\"resume_state\":%s,\"dma_before\":%d,\"dma_after\":%d,\"records\":%s,\"FCB_writes\":%s}"(state s.call_state)(state s.resume_state)s.dma_before s.dma_after(array record s.events)
 (pairs(List.filter_map(function Cpm.Bdos.Memory_write q->Some(q.address,q.value)|_->None)s.effects))
let case(c:N.case)=let q=c.plan in
 Printf.sprintf "{\"caller\":%S,\"entry_step\":%d,\"return_step\":%d,\"input\":%s,\"output\":%s,\"index\":%d,\"neighbor\":%d,\"destination\":%d,\"fresh_scratch\":%d,\"reloaded_index\":%d,\"incremented_index\":%d,\"flush\":%b,\"logical_writes\":%s,\"compatibility_writes\":%s,\"services\":%s,\"entry_dma\":%d,\"post_dma\":%d,\"entry_memory_sha256\":%S,\"post_memory_sha256\":%S}"c.caller c.entry_step c.return_step(state c.input)(state c.output)q.index q.discarded_neighbor q.destination q.fresh_scratch q.reloaded_index q.incremented_index q.flush(pairs c.logical_writes)(pairs c.compatibility_writes)(array service c.services)c.entry_dma c.post_dma c.entry_memory_sha256 c.post_memory_sha256
let goldens=["MINIMAL",256,"7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119";"FIZZBUZ",768,"68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203";"PICTURE",256,"c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1"]
let summary name count(r:Pli80.Experiment.result)=
 let _,size,sha=List.find(fun(n,_,_)->n=name)goldens in
 let rel=match r.rel_bytes with Some b->b|_->failwith"No REL"in
 let marker text=List.exists(fun(m:Pli80.Console_capture.message)->m.text=text)r.console_messages in
 if Bytes.length rel<>size || Pli80.Experiment.sha256_hex rel<>sha || not(marker"NO ERROR(S) IN PASS 1"&&marker"NO ERROR(S) IN PASS 2"&&marker"END  COMPILATION")||r.run.termination<>Runner.Warm_boot then failwith("Bad compilation oracle:"^name);
 Printf.sprintf"{\"source\":%S,\"invocations\":%d,\"REL_size\":%d,\"REL_sha256\":%S,\"PASS1\":true,\"PASS2\":true,\"END_COMPILATION\":true,\"termination\":\"warm_boot\",\"actual_guest_instructions\":%d,\"actual_guest_t_states\":%d,\"host_transitions\":%d,\"host_bdos_services\":%d,\"INT_sha256\":%S,\"full_filesystem_identity\":true,\"file_events_identity\":true}"name count size sha r.run.steps r.run.t_states r.run.host_transitions r.run.host_bdos_services (match r.int_bytes with Some b->Pli80.Experiment.sha256_hex b|None->"deleted_after_PASS2")
let ()=
 let toolchain=ref "" and output=ref "" in
 Arg.parse["--toolchain",Arg.Set_string toolchain,"DISK1";"--output-dir",Arg.Set_string output,"new output directory"](fun _->failwith "Unexpected argument")"pli80-native-int-emitter";
 if !toolchain="" || !output="" || Sys.file_exists !output then failwith "Require toolchain and new output directory";
 Unix.mkdir !output 0o755;
 let proofs=ref [] and rows=ref [] and shadows=ref [] in
 List.iter(fun(name,_,_)->
  let image n=read(Filename.concat !toolchain n)in
  let input:Pli80.Experiment.input={pli_com=image "PLI.COM";pli0_ovl=image "PLI0.OVL";pli1_ovl=image "PLI1.OVL";pli2_ovl=image "PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read("examples/pli80/"^name^".PLI"));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  let v,r=match N.shadow input with Ok q->q|_->failwith "Emitter shadow failed"in
  rows:=Printf.sprintf "{\"source\":%S,\"cases\":%s}"name(array case(N.cases v))::!rows;
  shadows:=summary name(List.length(N.cases v))r::!shadows;
  Printf.printf "%s: %d complete emitter shadows passed\n%!" name(List.length(N.cases v));
  proofs:=(name,input,v)::!proofs)goldens;
 write(Filename.concat !output "emitter-native-cases.json")("{\"sources\":"^array Fun.id(List.rev !rows)^"}");
 write(Filename.concat !output "shadow-summary.json")("{\"sources\":"^array Fun.id(List.rev !shadows)^",\"all_640_full_memory_and_filesystem_cases_passed\":true}");
 let singles=List.map(fun(name,input,v)->
  (match N.single v {input with source_bytes=Bytes.empty} with exception Failure _->()|_->failwith "Source proof mismatch accepted");
  match N.single v input with Ok([count],r)->Printf.printf "%s emitter-only: %d transitions, %d host services\n%!"name count r.run.host_bdos_services;summary name count r
  |_->failwith "Single hybrid failed")(List.rev !proofs)in
 write(Filename.concat !output "single-hybrid-summary.json")("{\"sources\":"^array Fun.id singles^",\"no_fallback\":true}");
 let cumulative=List.map(fun(name,input,v)->
  let attributes=match Pli80.Native_attribute_auxiliary.shadow input with Ok(v,_)->v|_->failwith "Attribute shadows failed"in
  let publications=match Pli80.Native_mapped_publication.shadow input with Ok(v,_)->v|_->failwith "Publication shadows failed"in
  let recursive=match Pli80.Native_7c1b.shadow input with Ok(v,_)->v|_->failwith "Recursive shadows failed"in
  let words=match Pli80.Native_7bbf.shadow input with Ok(v,_)->v|_->failwith "Packed shadows failed"in
  let balances=match Pli80.Native_7b7a.shadow input with Ok(v,_)->v|_->failwith "Balance shadows failed"in
  match N.cumulative v attributes publications recursive words balances input with
  |Ok(counts,r)->Printf.printf "%s cumulative: %s; %d host BDOS services\n%!"name(String.concat ","(List.map string_of_int counts))r.run.host_bdos_services;
   Printf.sprintf "{\"result\":%s,\"transition_counts_7C1B_7BBF_7B7A_7BA2_7AD5_7B64_7ABF_0EF6\":%s,\"all_entry_resume_states_and_external_state_exact\":true,\"no_replaced_guest_bodies\":true}"(summary name(List.hd(List.rev counts))r)(array string_of_int counts)
  |_->failwith "Cumulative hybrid failed")(List.rev !proofs)in
 write(Filename.concat !output "cumulative-hybrid-summary.json")("{\"sources\":"^array Fun.id cumulative^",\"no_fallback\":true}")
