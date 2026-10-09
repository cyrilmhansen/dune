[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path text=let c=open_out path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_string c text;output_char c '\n')
let array f xs="["^String.concat","(List.map f xs)^"]"
let state(s:Runner.state_snapshot)=Printf.sprintf"{\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"sp\":%d,\"pc\":%d,\"flags\":{\"sign\":%b,\"zero\":%b,\"auxiliary_carry\":%b,\"parity\":%b,\"carry\":%b}}"s.a s.b s.c s.d s.e s.h s.l s.sp s.pc s.sign s.zero s.auxiliary_carry s.parity s.carry
module B=Pli80.Acquisition_family_bridge
module N=Pli80.Native_resident_output
module D=Pli80.Native_delimiter_driver
module Q=Pli80.Native_recursive_parent
let journal js=array(fun(w:B.write)->Printf.sprintf"[%d,%d,%d,%d,%S]"w.address w.value w.writer w.depth w.kind)js
let service(s:Runner.host_service)=
 let records=List.filter_map(function Cpm.Bdos.Write_record q->Some(Printf.sprintf"{\"file\":%S,\"record\":%d,\"data_sha256\":%S}"q.file.name q.logical_record(Pli80.Experiment.sha256_hex q.data))|_->None)s.events in
 Printf.sprintf"{\"function\":%d,\"call_state\":%s,\"resume_state\":%s,\"dma_before\":%d,\"dma_after\":%d,\"records\":%s,\"FCB_before_sha256\":%S,\"FCB_after_sha256\":%S}"
  s.call_state.c(state s.call_state)(state s.resume_state)s.dma_before s.dma_after(array Fun.id records)
  (Pli80.Experiment.sha256_hex(Bytes.sub s.memory_before 0x1ce4 36))(Pli80.Experiment.sha256_hex(Bytes.sub s.memory_after 0x1ce4 36))
let case(c:N.case)=Printf.sprintf"{\"caller\":%S,\"entry_step\":%d,\"return_step\":%d,\"input\":%s,\"output\":%s,\"entry_memory_sha256\":%S,\"post_memory_sha256\":%S,\"entry_filesystem_sha256\":%S,\"post_filesystem_sha256\":%S,\"entry_dma\":%d,\"post_dma\":%d,\"result\":%s,\"journal\":%s,\"service_details\":%s}"
 c.caller c.entry_step c.return_step(state c.input)(state c.output)c.entry_memory_sha256 c.post_memory_sha256 "retained-in-proof" "retained-in-proof" c.entry_dma c.post_dma(Printf.sprintf"{\"route\":%S}"c.route)(journal c.prepared.journal)(array service c.services)
let goldens=["MINIMAL",256,"7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119";"FIZZBUZ",768,"68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203";"PICTURE",256,"c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1"]
let summary name count(r:Pli80.Experiment.result)=
 let _,size,sha=List.find(fun(n,_,_)->n=name)goldens in
 let rel=match r.rel_bytes with Some b->b|_->failwith"No REL"in
 let marker text=List.exists(fun(m:Pli80.Console_capture.message)->m.text=text)r.console_messages in
 if Bytes.length rel<>size || Pli80.Experiment.sha256_hex rel<>sha || not(marker"NO ERROR(S) IN PASS 1"&&marker"NO ERROR(S) IN PASS 2"&&marker"END  COMPILATION")||r.run.termination<>Runner.Warm_boot then failwith("Bad compilation oracle:"^name);
 Printf.sprintf"{\"source\":%S,\"invocations\":%d,\"REL_size\":%d,\"REL_sha256\":%S,\"PASS1\":true,\"PASS2\":true,\"END_COMPILATION\":true,\"termination\":\"warm_boot\",\"actual_guest_instructions\":%d,\"actual_guest_t_states\":%d,\"host_transitions\":%d,\"INT_sha256\":%s,\"filesystem_sha256\":%S}"name count size sha r.run.steps r.run.t_states r.run.host_transitions(match r.int_bytes with None->"null"|Some b->Printf.sprintf"%S"(Pli80.Experiment.sha256_hex b))(N.filesystem_hash r.filesystem)
let members=[0x8248;0x8225]
let ()=
 let toolchain=ref "" and output=ref "" and focused=ref false and cross=ref "" in
 Arg.parse["--cross-source",Arg.Set_string cross,"optional natural cross-source proof";"--family-only",Arg.Set focused,"focused component proof";"--toolchain",Arg.Set_string toolchain,"DISK1";"--output-dir",Arg.Set_string output,"new output directory"](fun _->failwith"Unexpected argument")"buffered REL family";
 if !toolchain=""|| !output=""||Sys.file_exists !output then failwith"Require new output directory";
 Unix.mkdir !output 0o755;
 let roots=ref[]and singles=ref[]and transaction_singles=ref[]and cumulatives=ref[]and components=ref[]in
 List.iter(fun(name,_,_)->
  let image n=read(Filename.concat !toolchain n)in
  let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read("examples/pli80/"^name^".PLI"));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  let family=List.map(fun offset->offset,(match N.shadow ~offset input with Ok q->q|_->failwith"family shadow"))members in

  let windows=List.concat_map(fun(_,v)->List.map(fun(c:N.case)->c.entry_step,c.return_step)(N.cases v))family in
  let serializer=match N.shadow ~offset:0x119e ~within:windows ~run_negatives:false input with Ok q->q|_->failwith"serializer proof"in
  let helpers=List.map(fun offset->
   let within=if !cross<>""then windows else if offset=0x7a17 then Bytes.to_string(read "_build/host-compiler-pass-56/7a17-clear-windows.txt")|>String.split_on_char '\n'|>List.filter_map(fun line->match String.split_on_char ' ' line with [source;a;b]when source=name->Some(int_of_string a,int_of_string b)|_->None)else[]in
   offset,(match N.shadow ~offset ~within input with Ok q->q|_->failwith"helper proof"))[0x79e2;0x7a17;0x73d0;0x756d;0x7701]in
  let bits=match N.shadow ~offset:0x1140 ~within:windows ~run_negatives:false input with Ok q->q|_->failwith"bit child proof"in
  components:=Printf.sprintf"{\"source\":%S,\"serializer_shadows\":%d,\"bit_writer_shadows\":%d,\"all_passed\":true}"name(List.length(N.cases serializer))(List.length(N.cases bits))::!components;
  roots:=Printf.sprintf"{\"source\":%S,\"entries\":%s}"name(array(fun(offset,v)->Printf.sprintf"{\"offset\":%d,\"members\":%s}"offset(array case(N.cases v)))(family@helpers))::!roots;
  if not !focused then(
  let offset,v=List.hd family in
  let first=(List.hd(N.cases v)).entry_step in
  let corrupted change={v with Q.cases=List.map(fun(c:N.case)->if c.entry_step=first then change c else c)(N.cases v)}in
  let fails proof=match N.single ~offset proof input with exception Failure _->()|_->failwith"corrupt family proof accepted"in
  fails(corrupted(fun c->{c with output={c.output with carry=not c.output.carry}}));
  fails(corrupted(fun c->{c with prepared={c.prepared with logical_writes=List.rev c.prepared.logical_writes}}));
  fails(corrupted(fun c->{c with prepared={c.prepared with journal=List.map(fun(w:B.write)->if w.kind="compatibility"then{w with writer=w.writer+1}else w)c.prepared.journal}}));
  let driver=match D.shadow input with Ok q->q|_->failwith"0C75 proof"in
  let finalizer=match N.shadow input with Ok q->q|_->failwith"1272 proof"in
  let saved=match Pli80.Native_attribute_gate.shadow Pli80.Attribute_gate_bridge.Saved input with Ok(v,_)->v|_->failwith"80B7 proof"in
  let emitter=match Pli80.Native_int_emitter.shadow input with Ok(v,_)->v|_->failwith"INT emitter"in
  let inside windows(c:N.case)=List.exists(fun(a,b)->a<c.entry_step&&c.return_step<b)windows in
  let acquisition_windows=List.map(fun(c:D.case)->c.entry_step,c.return_step)(D.cases driver)in
  let controllers exclusions=List.map(fun(offset,v)->N.controller ~offset ~exclude_entry_steps:(List.filter_map(fun c->if inside exclusions c then Some c.entry_step else None)(N.cases v))v input)family in
  let reference=snd(List.hd family)in
  let transaction=List.assoc 0x8225 family in
  let transaction_counts,transaction_result=match N.single ~offset:0x8225 transaction input with Ok q->q|_->failwith"8225-only hybrid"in
  transaction_singles:=Printf.sprintf"{\"result\":%s,\"roots\":%d}"(summary name(List.fold_left(+)0 transaction_counts)transaction_result)(List.fold_left(+)0 transaction_counts)::!transaction_singles;
  let single_counts,single=match N.run reference input(controllers windows)with Ok q->q|_->failwith"standalone family"in
  singles:=Printf.sprintf"{\"result\":%s,\"transition_vector\":%s}"(summary name(List.fold_left(+)0 single_counts)single)(array string_of_int single_counts)::!singles;
  let saved_windows=List.map(fun(c:Pli80.Native_attribute_gate.case)->c.entry_step,c.return_step)(Pli80.Native_attribute_gate.cases saved)in
  let saved_exclusions=List.filter_map(fun(c:Pli80.Native_attribute_gate.case)->if List.exists(fun(a,b)->a<c.entry_step&&c.entry_step<b)acquisition_windows then Some c.entry_step else None)(Pli80.Native_attribute_gate.cases saved)in
  let emitter_exclusions=List.filter_map(fun(c:Pli80.Native_int_emitter.case)->if List.exists(fun(a,b)->a<c.entry_step&&c.entry_step<b)(acquisition_windows@saved_windows)then Some c.entry_step else None)(Pli80.Native_int_emitter.cases emitter)in
  let compact=List.map(fun offset->offset,(match N.shadow ~offset input with Ok q->q|_->failwith"Pass54 compact proof"))[0x7557;0x756d;0x75a7;0x75ce;0x75f1;0x7619]in
  let compact_windows=List.concat_map(fun(_,v)->List.map(fun(c:N.case)->c.entry_step,c.return_step)(N.cases v))compact in
  let compact_controllers exclusions=List.map(fun(offset,v)->N.controller ~offset ~exclude_entry_steps:(List.filter_map(fun c->if inside exclusions c then Some c.entry_step else None)(N.cases v))v input)compact in
  let previous=List.map(fun offset->offset,(match N.shadow ~offset input with Ok q->q|_->failwith"Pass53 proof"))[0x7434;0x7630;0x765e]in
  let previous_windows=List.concat_map(fun(_,v)->List.map(fun(c:N.case)->c.entry_step,c.return_step)(N.cases v))previous in
  let previous_controllers exclusions=List.map(fun(offset,v)->N.controller ~offset ~exclude_entry_steps:(List.filter_map(fun c->if inside exclusions c then Some c.entry_step else None)(N.cases v))v input)previous in
  let resident=List.map(fun offset->offset,(match N.shadow ~offset input with Ok q->q|_->failwith"resident proof"))[0x11c3;0x11e5;0x1207]in
  let resident_controllers exclusions=List.map(fun(offset,v)->N.controller ~offset ~exclude_entry_steps:(List.filter_map(fun c->if inside exclusions c then Some c.entry_step else None)(N.cases v))v input)resident in
  let lower()=[N.controller finalizer input;D.controller driver input;Pli80.Native_attribute_gate.controller ~exclude_entry_steps:saved_exclusions saved input;Pli80.Native_int_emitter.controller ~exclude_entry_steps:emitter_exclusions emitter input]in
  let pointer=match N.shadow ~offset:0x7701 input with Ok q->q|_->failwith"Pass55 pointer proof"in
  let pointer_windows=List.map(fun(c:N.case)->c.entry_step,c.return_step)(N.cases pointer)in
  let pointer_controller exclusions=N.controller ~offset:0x7701 ~exclude_entry_steps:(List.filter_map(fun c->if inside exclusions c then Some c.entry_step else None)(N.cases pointer))pointer input in
  let pre_counts,pre=match N.run reference input(pointer_controller acquisition_windows::compact_controllers(acquisition_windows@compact_windows@pointer_windows)@previous_controllers(acquisition_windows@compact_windows@pointer_windows)@resident_controllers(acquisition_windows@previous_windows@compact_windows@pointer_windows)@lower())with Ok q->q|_->failwith"Pass52 baseline"in
  let post_counts,post=match N.run reference input(controllers(acquisition_windows@windows)@ [pointer_controller(acquisition_windows@windows)]@compact_controllers(acquisition_windows@compact_windows@windows@pointer_windows)@previous_controllers(acquisition_windows@compact_windows@windows@pointer_windows)@resident_controllers(acquisition_windows@previous_windows@compact_windows@windows@pointer_windows)@lower())with Ok q->q|_->failwith"cumulative family"in
  let accepted=List.fold_left(+)0(List.filteri(fun i _->i<2)post_counts)in
  Printf.printf"%s family %s guest %d -> %d\n%!"name(String.concat","(List.map string_of_int post_counts))pre.run.steps post.run.steps;
  cumulatives:=Printf.sprintf"{\"result\":%s,\"transition_vector\":%s,\"pre_transition_vector\":%s,\"pre_guest_instructions\":%d,\"guest_instructions_removed\":%d,\"family_roots\":%d,\"record_sha256_sequence\":%s}"(summary name accepted post)(array string_of_int post_counts)(array string_of_int pre_counts)pre.run.steps(pre.run.steps-post.run.steps)accepted(array(fun(n,i,sha)->Printf.sprintf"[%S,%d,%S]"n i sha)(N.record_summaries reference))::!cumulatives
 ) )(if !cross=""then goldens else[!cross,0,""]);
 List.iter(fun(n,xs)->write(Filename.concat !output n)("{\"sources\":"^array Fun.id(List.rev xs)^",\"all_passed\":true}"))[
 "8225-only-hybrid-summary.json",!transaction_singles;"component-shadows.json",!components;"natural-cases.json",!roots;"single-hybrid-summary.json",!singles;"cumulative-hybrid-summary.json",!cumulatives]
