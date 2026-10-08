[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path text=let c=open_out path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_string c text;output_char c '\n')
let array f xs="["^String.concat","(List.map f xs)^"]"
let state(s:Runner.state_snapshot)=Printf.sprintf"{\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"sp\":%d,\"pc\":%d,\"flags\":{\"sign\":%b,\"zero\":%b,\"auxiliary_carry\":%b,\"parity\":%b,\"carry\":%b}}"s.a s.b s.c s.d s.e s.h s.l s.sp s.pc s.sign s.zero s.auxiliary_carry s.parity s.carry
module B=Pli80.Acquisition_family_bridge
module N=Pli80.Native_selection_parent
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
 let gate_cases=ref[]and shadows=ref[]and singles=ref[]and cumulatives=ref[]in
 List.iter(fun(name,_,_)->
  let image n=read(Filename.concat !toolchain n)in
  let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read("examples/pli80/"^name^".PLI"));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  let v=match N.shadow input with Ok q->q|_->failwith"shadow"in
  Printf.printf"%s shadows %d\n%!"name(List.length(N.cases v));
  gate_cases:=Printf.sprintf"{\"source\":%S,\"members\":%s}"name(array case(N.cases v))::!gate_cases;
  shadows:=summary name(List.length v.cases)v.historical::!shadows;
  (match N.single v input with Ok([count],r)->singles:=summary name count r::!singles|_->failwith"single");
  (match N.single v {input with source_bytes=Bytes.empty}with exception Failure _->()|_->failwith"source proof accepted");
  let first=(List.hd(N.cases v)).entry_step in
  (match N.controller ~exclude_entry_steps:[first;first]v input with exception Failure _->()|_->failwith"duplicate exclusion");
  (match N.controller ~exclude_entry_steps:[-1]v input with exception Failure _->()|_->failwith"unknown exclusion");
  (match N.run v input[N.controller ~exclude_entry_steps:[first]v input]with exception Failure _->()|_->failwith"unexpected invocation");
  (match N.run v input[N.controller v input;N.controller v input]with exception Failure _->()|_->failwith"duplicate root");
  let corrupted change={v with N.cases=List.map(fun(c:N.case)->if c.entry_step=first then change c else c)(N.cases v)}in
  let bad_flags=corrupted(fun c->{c with output={c.output with carry=not c.output.carry}})in
  (match N.single bad_flags input with exception Failure _->()|_->failwith"changed return flags accepted");
  let bad_order=corrupted(fun c->{c with prepared={c.prepared with logical_writes=List.rev c.prepared.logical_writes}})in
  (match N.single bad_order input with exception Failure _->()|_->failwith"changed publication order accepted");
  let wrapper=match W.shadow input with Ok q->q|_->failwith"6619 proof"in
  let reentrant=match R.shadow input with Ok v->v|_->failwith"6223 proof"in
  let parent=match Pli80.Native_acquisition_parent.shadow input with Ok(v,_)->v|_->failwith"acquisition parent"in
  let proofs=List.map(fun op->let p,_=match Pli80.Native_state_adaptation.shadow op input with Ok q->q|_->failwith"adaptation"in op,p)
   [Pli80.State_adaptation_bridge.Saved;Adapt;Publish;Minimum]in
  let oldgate=match Pli80.Native_attribute_gate.shadow Pli80.Attribute_gate_bridge.Gate input with Ok(v,_)->v|_->failwith"old gate"in
  let oldsaved=match Pli80.Native_attribute_gate.shadow Pli80.Attribute_gate_bridge.Saved input with Ok(v,_)->v|_->failwith"old saved"in
  let inputs=match Pli80.Native_input_processing.shadow input with Ok(v,_)->v|_->failwith"inputs"in
  let controls=match Pli80.Native_mapped_control.shadow input with Ok(v,_)->v|_->failwith"controls"in
  let publication=match Pli80.Native_range_publication.shadow input with Ok(v,_)->v|_->failwith"publication"in
  let new_publications=match Pli80.Native_publication_primitives.shadow input with Ok(v,_)->v|_->failwith"new publications"in
  let range=match Pli80.Native_range_processing.shadow input with Ok(v,_)->v|_->failwith"range"in
  let words=match Pli80.Native_word_emitters.shadow input with Ok(v,_)->v|_->failwith"words"in
  let emitter=match Pli80.Native_int_emitter.shadow input with Ok(v,_)->v|_->failwith"emitter"in
  let attributes=match Pli80.Native_attribute_auxiliary.shadow input with Ok(v,_)->v|_->failwith"attributes"in
  let publications=match Pli80.Native_mapped_publication.shadow input with Ok(v,_)->v|_->failwith"publications"in
  let recursive=match Pli80.Native_7c1b.shadow input with Ok(v,_)->v|_->failwith"recursive"in
  let packed=match Pli80.Native_7bbf.shadow input with Ok(v,_)->v|_->failwith"packed"in
  let balances=match Pli80.Native_7b7a.shadow input with Ok(v,_)->v|_->failwith"balances"in
  let make_controllers with_parent=
  let windows=if with_parent then List.map(fun(c:N.case)->c.entry_step,c.return_step)(N.cases v)else []in
  let wrapper_exclusions=List.filter_map(fun(c:W.case)->if List.exists(fun(a,b)->a<c.entry_step&&c.entry_step<b)windows then Some c.entry_step else None)(W.cases wrapper)in
  let wrapper_controller=W.controller ~exclude_entry_steps:wrapper_exclusions wrapper input in
  let windows=windows@List.map(fun(c:W.case)->c.entry_step,c.return_step)(W.cases wrapper)in
  let reentrant_exclusions=List.filter_map(fun(c:R.case)->if List.exists(fun(a,b)->a<c.entry_step&&c.entry_step<b)windows then Some c.entry_step else None)(R.cases reentrant)in
  let outer_controllers=(if with_parent then[N.controller v input]else[])@[wrapper_controller;R.controller ~exclude_entry_steps:reentrant_exclusions reentrant input]in
  let windows=windows@List.map(fun(c:R.case)->c.entry_step,c.return_step)(R.cases reentrant)in
  let parent_exclusions=List.filter_map(fun(c:Pli80.Native_acquisition_parent.case)->if List.exists(fun(a,b)->a<c.entry_step&&c.entry_step<b)windows then Some c.entry_step else None)(Pli80.Native_acquisition_parent.cases parent)in
  let parent_controller=Pli80.Native_acquisition_parent.controller ~exclude_entry_steps:parent_exclusions parent input in
  let windows=windows@List.map(fun(c:Pli80.Native_acquisition_parent.case)->c.entry_step,c.return_step)(Pli80.Native_acquisition_parent.cases parent)in
  let extra=ref windows in
  let controllers=ref(outer_controllers@[parent_controller])in
  List.iter(fun op->let p=List.assoc op proofs in
   let exclusions=List.filter_map(fun(c:Pli80.Native_state_adaptation.case)->if List.exists(fun(a,b)->a<c.entry_step&&c.entry_step<b)!extra then Some c.entry_step else None)(Pli80.Native_state_adaptation.cases p)in
   controllers:= !controllers@[Pli80.Native_state_adaptation.controller ~exclude_entry_steps:exclusions p input];
   extra:= !extra@List.map(fun(c:Pli80.Native_state_adaptation.case)->c.entry_step,c.return_step)(Pli80.Native_state_adaptation.cases p))[Pli80.State_adaptation_bridge.Saved;Adapt;Publish;Minimum];
  let oldcontrollers p=
   let cases=Pli80.Native_attribute_gate.cases p in
   let exclusions=List.filter_map(fun(c:Pli80.Native_attribute_gate.case)->if List.exists(fun(a,b)->a<c.entry_step&&c.entry_step<b)!extra then Some c.entry_step else None)cases in
   let controller=Pli80.Native_attribute_gate.controller ~exclude_entry_steps:exclusions p input in
   extra:= !extra@List.map(fun(c:Pli80.Native_attribute_gate.case)->c.entry_step,c.return_step)cases;controller in
  let saved_controller=oldcontrollers oldsaved in
  let gate_controller=oldcontrollers oldgate in
  controllers:= !controllers@[saved_controller;gate_controller];
  !controllers@Pli80.Native_input_processing.controllers ~exclude_windows:!extra inputs controls publication new_publications range words emitter attributes publications recursive packed balances input in
  let pre_counts,pre=match N.run v input(make_controllers false)with Ok q->q|_->failwith"pre-Pass46 baseline"in
  let controllers=make_controllers true in
  match N.run v input controllers with
  |Ok(counts,r)->Printf.printf"%s cumulative %s; services %d\n%!"name(String.concat","(List.map string_of_int counts))r.run.host_bdos_services;
   cumulatives:=Printf.sprintf"{\"result\":%s,\"transition_vector\":%s,\"host_bdos_services\":%d,\"pre_guest_instructions\":%d,\"pre_transition_vector\":%s,\"guest_instructions_removed\":%d,\"record_sha256_sequence\":%s}"(summary name(List.fold_left(+)0 counts)r)(array string_of_int counts)r.run.host_bdos_services pre.run.steps(array string_of_int pre_counts)(pre.run.steps-r.run.steps)(array(fun(n,i,sha)->Printf.sprintf"[%S,%d,%S]"n i sha)(N.record_summaries v))::!cumulatives
  |_->failwith"cumulative")goldens;
 List.iter(fun(n,xs)->write(Filename.concat !output n)("{\"sources\":"^array Fun.id(List.rev xs)^",\"all_passed\":true}"))[
 "natural-cases.json",!gate_cases;"shadow-summary.json",!shadows;"single-hybrid-summary.json",!singles;"cumulative-hybrid-summary.json",!cumulatives]
