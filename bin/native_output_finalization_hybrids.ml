[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path text=let c=open_out path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_string c text;output_char c '\n')
let array f xs="["^String.concat","(List.map f xs)^"]"
let state(s:Runner.state_snapshot)=Printf.sprintf"{\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"sp\":%d,\"pc\":%d,\"flags\":{\"sign\":%b,\"zero\":%b,\"auxiliary_carry\":%b,\"parity\":%b,\"carry\":%b}}"s.a s.b s.c s.d s.e s.h s.l s.sp s.pc s.sign s.zero s.auxiliary_carry s.parity s.carry
module B=Pli80.Acquisition_family_bridge
module N=Pli80.Native_resident_output
module D=Pli80.Native_delimiter_driver
module I=Pli80.Native_initialization_parent
module A=Pli80.Native_acquisition_frame
module Q=Pli80.Native_recursive_parent
module P=Pli80.Native_selection_parent
module W=Pli80.Native_wrapper_acquisition
module R=Pli80.Native_reentrant_acquisition
let journal js=array(fun(w:B.write)->Printf.sprintf"[%d,%d,%d,%d,%S]"w.address w.value w.writer w.depth w.kind)js
let service(s:Runner.host_service)=
 let records=List.filter_map(function Cpm.Bdos.Write_record q->Some(Printf.sprintf"{\"file\":%S,\"record\":%d,\"data_sha256\":%S}"q.file.name q.logical_record(Pli80.Experiment.sha256_hex q.data))|_->None)s.events in
 Printf.sprintf"{\"function\":%d,\"call_state\":%s,\"resume_state\":%s,\"dma_before\":%d,\"dma_after\":%d,\"records\":%s,\"FCB_before_sha256\":%S,\"FCB_after_sha256\":%S}"
  s.call_state.c(state s.call_state)(state s.resume_state)s.dma_before s.dma_after(array Fun.id records)
  (Pli80.Experiment.sha256_hex(Bytes.sub s.memory_before 0x1ca2 36))(Pli80.Experiment.sha256_hex(Bytes.sub s.memory_after 0x1ca2 36))
let case(c:N.case)=Printf.sprintf"{\"caller\":%S,\"entry_step\":%d,\"return_step\":%d,\"input\":%s,\"output\":%s,\"entry_memory_sha256\":%S,\"post_memory_sha256\":%S,\"entry_filesystem_sha256\":%S,\"post_filesystem_sha256\":%S,\"entry_dma\":%d,\"post_dma\":%d,\"result\":%s,\"journal\":%s,\"service_details\":%s}"
 c.caller c.entry_step c.return_step(state c.input)(state c.output)c.entry_memory_sha256 c.post_memory_sha256 "retained-in-proof" "retained-in-proof" c.entry_dma c.post_dma(Printf.sprintf"{\"route\":%S}"c.route)(journal c.prepared.journal)(array service c.services)
let goldens=["MINIMAL",256,"7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119";"FIZZBUZ",768,"68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203";"PICTURE",256,"c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1"]
let summary name count(r:Pli80.Experiment.result)=
 let _,size,sha=List.find(fun(n,_,_)->n=name)goldens in
 let rel=match r.rel_bytes with Some b->b|_->failwith"No REL"in
 let marker text=List.exists(fun(m:Pli80.Console_capture.message)->m.text=text)r.console_messages in
 if Bytes.length rel<>size || Pli80.Experiment.sha256_hex rel<>sha || not(marker"NO ERROR(S) IN PASS 1"&&marker"NO ERROR(S) IN PASS 2"&&marker"END  COMPILATION")||r.run.termination<>Runner.Warm_boot then failwith("Bad compilation oracle:"^name);
 Printf.sprintf"{\"source\":%S,\"invocations\":%d,\"REL_size\":%d,\"REL_sha256\":%S,\"PASS1\":true,\"PASS2\":true,\"END_COMPILATION\":true,\"termination\":\"warm_boot\",\"actual_guest_instructions\":%d,\"actual_guest_t_states\":%d,\"host_transitions\":%d,\"INT_sha256\":%s,\"filesystem_sha256\":%S}"name count size sha r.run.steps r.run.t_states r.run.host_transitions(match r.int_bytes with None->"null"|Some b->Printf.sprintf"%S"(Pli80.Experiment.sha256_hex b))(N.filesystem_hash r.filesystem)
let ()=
 let toolchain=ref "" and output=ref "" in
 Arg.parse["--toolchain",Arg.Set_string toolchain,"DISK1";"--output-dir",Arg.Set_string output,"new output directory"](fun _->failwith"Unexpected argument")"native publication primitives";
 if !toolchain=""|| !output=""||Sys.file_exists !output then failwith"Require toolchain and new output directory";
 Unix.mkdir !output 0o755;
 let gate_cases=ref[]and shadows=ref[]and singles=ref[]and cumulatives=ref[]and components=ref[]in
 List.iter(fun(name,_,_)->
  let image n=read(Filename.concat !toolchain n)in
  let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read("examples/pli80/"^name^".PLI"));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  let v=match N.shadow input with Ok q->q|_->failwith"shadow"in
  Printf.printf"%s shadows %d\n%!"name(List.length(N.cases v));
  let child_counts=List.map(fun op->let n,_,_=Pli80.Native_acquisition_family.shadow (B.Resident_reader op) input in
   Printf.sprintf"[%d,%d]"(fst(Pli80_host.Resident_reader.bounds op))n)Pli80_host.Resident_reader.[Close;Write_record;Default_dma]in
  let bit_proof=match N.shadow ~offset:0x1140 input with Ok q->q|_->failwith"REL bit writer proof"in
  components:=Printf.sprintf"{\"source\":%S,\"bit_writer_required_shadows\":%d,\"service_wrapper_shadows\":%s}"name(List.length(N.cases bit_proof))(array Fun.id child_counts)::!components;
  gate_cases:=Printf.sprintf"{\"source\":%S,\"members\":%s}"name(array case(N.cases v))::!gate_cases;
  shadows:=summary name(List.length v.cases)v.historical::!shadows;
  (match N.single v input with Ok([count],r)->singles:=summary name count r::!singles|_->failwith"single");
  (match N.single v {input with source_bytes=Bytes.empty}with exception Failure _->()|_->failwith"source proof accepted");
  let first=(List.hd(N.cases v)).entry_step in
  (match N.controller ~exclude_entry_steps:[first;first]v input with exception Failure _->()|_->failwith"duplicate exclusion");
  (match N.controller ~exclude_entry_steps:[-1]v input with exception Failure _->()|_->failwith"unknown exclusion");
  (match N.run v input[N.controller ~exclude_entry_steps:[first]v input]with exception Failure _->()|_->failwith"unexpected invocation");
  (match N.run v input[N.controller v input;N.controller v input]with exception Failure _->()|_->failwith"duplicate root");
  let corrupted change={v with Q.cases=List.map(fun(c:N.case)->if c.entry_step=first then change c else c)(N.cases v)}in
  let bad_flags=corrupted(fun c->{c with output={c.output with carry=not c.output.carry}})in
  (match N.single bad_flags input with exception Failure _->()|_->failwith"changed return flags accepted");
  let bad_writer=corrupted(fun c->{c with prepared={c.prepared with journal=List.map(fun(w:B.write)->if w.writer=0x138f then {w with writer=0x1380}else w)c.prepared.journal}})in
  (match N.single bad_writer input with exception Failure _->()|_->failwith"changed context frame writer accepted");
  let bad_order=corrupted(fun c->{c with prepared={c.prepared with logical_writes=List.rev c.prepared.logical_writes}})in
  (match N.single bad_order input with exception Failure _->()|_->failwith"changed publication order accepted");
  let driver=match D.shadow input with Ok q->q|_->failwith"0C75 proof"in
  let saved=match Pli80.Native_attribute_gate.shadow Pli80.Attribute_gate_bridge.Saved input with Ok(v,_)->v|_->failwith"80B7 proof"in
  let emitter=match Pli80.Native_int_emitter.shadow input with Ok(v,_)->v|_->failwith"INT emitter"in
  (* Fresh post50 inventory proves every other canonical external root count is
     zero. Their host hierarchy remains composed under D, whose own independent
     child checkpoints validate it. Register only the three live pre51 roots. *)
  let make_controllers with_parent=
   let windows=(if with_parent then List.map(fun(c:N.case)->c.entry_step,c.return_step)(N.cases v)else [])@List.map(fun(c:D.case)->c.entry_step,c.return_step)(D.cases driver)in
   let saved_exclusions=List.filter_map(fun(c:Pli80.Native_attribute_gate.case)->if List.exists(fun(a,b)->a<c.entry_step&&c.entry_step<b)windows then Some c.entry_step else None)(Pli80.Native_attribute_gate.cases saved)in
   let windows=windows@List.map(fun(c:Pli80.Native_attribute_gate.case)->c.entry_step,c.return_step)(Pli80.Native_attribute_gate.cases saved)in
   let emitter_exclusions=List.filter_map(fun(c:Pli80.Native_int_emitter.case)->if List.exists(fun(a,b)->a<c.entry_step&&c.entry_step<b)windows then Some c.entry_step else None)(Pli80.Native_int_emitter.cases emitter)in
   (if with_parent then[N.controller v input]else[])@[D.controller driver input;Pli80.Native_attribute_gate.controller ~exclude_entry_steps:saved_exclusions saved input;Pli80.Native_int_emitter.controller ~exclude_entry_steps:emitter_exclusions emitter input]in
  let pre_counts,pre=match N.run v input(make_controllers false)with Ok q->q|_->failwith"pre-Pass47 baseline"in
  let controllers=make_controllers true in
  match N.run v input controllers with
  |Ok(counts,r)->Printf.printf"%s cumulative %s; services %d\n%!"name(String.concat","(List.map string_of_int counts))r.run.host_bdos_services;
   cumulatives:=Printf.sprintf"{\"result\":%s,\"transition_vector\":%s,\"host_bdos_services\":%d,\"pre_guest_instructions\":%d,\"pre_transition_vector\":%s,\"guest_instructions_removed\":%d,\"record_sha256_sequence\":%s}"(summary name(List.fold_left(+)0 counts)r)(array string_of_int counts)r.run.host_bdos_services pre.run.steps(array string_of_int pre_counts)(pre.run.steps-r.run.steps)(array(fun(n,i,sha)->Printf.sprintf"[%S,%d,%S]"n i sha)(N.record_summaries v))::!cumulatives
  |_->failwith"cumulative")goldens;
 List.iter(fun(n,xs)->write(Filename.concat !output n)("{\"sources\":"^array Fun.id(List.rev xs)^",\"all_passed\":true}"))[
 "component-shadows.json",!components;"natural-cases.json",!gate_cases;"shadow-summary.json",!shadows;"single-hybrid-summary.json",!singles;"cumulative-hybrid-summary.json",!cumulatives]
