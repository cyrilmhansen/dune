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
let case_with_snapshot (v:N.result)(c:N.case)=
 let ram=(List.assoc c.entry_step v.Q.snapshots).Q.entry_memory in
 let byte a=Char.code(Bytes.get ram a)in
 let region a n=array string_of_int(List.init n(fun i->byte(a+i)))in
 let text=case c in String.sub text 0(String.length text-1)^Printf.sprintf",\"entry_shared_state\":{\"202B\":%d,\"ADAA\":%d,\"ADAB\":%s,\"ADB3\":%s,\"AE3A_AE43\":%s}}"(byte 0x202b)(byte 0xadaa)(region 0xadab 8)(region 0xadb3 8)(region 0xae3a 10)
let goldens=["MINIMAL",256,"7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119";"FIZZBUZ",768,"68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203";"PICTURE",256,"c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1"]
let summary name count(r:Pli80.Experiment.result)=
 let _,size,sha=List.find(fun(n,_,_)->n=name)goldens in
 let rel=match r.rel_bytes with Some b->b|_->failwith"No REL"in
 let marker text=List.exists(fun(m:Pli80.Console_capture.message)->m.text=text)r.console_messages in
 if Bytes.length rel<>size || Pli80.Experiment.sha256_hex rel<>sha || not(marker"NO ERROR(S) IN PASS 1"&&marker"NO ERROR(S) IN PASS 2"&&marker"END  COMPILATION")||r.run.termination<>Runner.Warm_boot then failwith("Bad compilation oracle:"^name);
 Printf.sprintf"{\"source\":%S,\"invocations\":%d,\"REL_size\":%d,\"REL_sha256\":%S,\"PASS1\":true,\"PASS2\":true,\"END_COMPILATION\":true,\"termination\":\"warm_boot\",\"actual_guest_instructions\":%d,\"actual_guest_t_states\":%d,\"host_transitions\":%d,\"INT_sha256\":%s,\"filesystem_sha256\":%S}"name count size sha r.run.steps r.run.t_states r.run.host_transitions(match r.int_bytes with None->"null"|Some b->Printf.sprintf"%S"(Pli80.Experiment.sha256_hex b))(N.filesystem_hash r.filesystem)
let members=[0x7ed6]
let ()=
 let toolchain=ref "" and output=ref "" and focused=ref false and cross=ref "" in
 Arg.parse["--cross-source",Arg.Set_string cross,"optional natural cross-source proof";"--family-only",Arg.Set focused,"focused component proof";"--toolchain",Arg.Set_string toolchain,"DISK1";"--output-dir",Arg.Set_string output,"new output directory"](fun _->failwith"Unexpected argument")"Resident output lifecycle";
 if !toolchain=""|| !output=""||Sys.file_exists !output then failwith"Require new output directory";
 Unix.mkdir !output 0o755;
 let roots=ref[]and singles=ref[]and cumulatives=ref[]and components=ref[]in
 List.iter(fun(name,_,_)->
  let image n=read(Filename.concat !toolchain n)in
  let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read(let path="examples/pli80/"^name^".PLI"in if Sys.file_exists path then path else Filename.concat !toolchain(name^".PLI")));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  let family=List.map(fun offset->offset,(match N.shadow ~offset input with Ok q->q|_->failwith"family shadow"))members in

  let windows=List.concat_map(fun(_,v)->List.map(fun(c:N.case)->c.entry_step,c.return_step)(N.cases v))family in
  let helpers=List.map(fun offset->offset,(match N.shadow ~offset ~within:(if List.mem offset[0x7d47;0x7d85;0x8398;0x83b4;0x83d2]then[]else windows) ~run_negatives:false input with Ok q->q|_->failwith"canonical resident proof"))[0x7365;0x7e05;0x793c;0x7d47;0x7d85;0x8398;0x83b4;0x83d2]in
  components:=Printf.sprintf"{\"source\":%S,\"canonical_resident_shadows\":%d,\"all_passed\":true}"name(List.length(N.cases(snd(List.hd helpers))))::!components;
  roots:=Printf.sprintf"{\"source\":%S,\"entries\":%s}"name(array(fun(offset,v)->Printf.sprintf"{\"offset\":%d,\"members\":%s}"offset(array(case_with_snapshot v)(N.cases v)))(family@helpers))::!roots;
  if not !focused then(
  let offset,v=List.hd family in
  if N.cases v<>[]then(
  let first=(List.hd(N.cases v)).entry_step in
  let corrupted change={v with Q.cases=List.map(fun(c:N.case)->if c.entry_step=first then change c else c)(N.cases v)}in
  let fails proof=match N.single ~offset proof input with exception Failure _->()|_->failwith"corrupt family proof accepted"in
  fails(corrupted(fun c->{c with output={c.output with carry=not c.output.carry}}));
  );
  let driver=match D.shadow input with Ok q->q|_->failwith"0C75 proof"in
  let finalizer=match N.shadow input with Ok q->q|_->failwith"1272 proof"in
  let saved=match Pli80.Native_attribute_gate.shadow Pli80.Attribute_gate_bridge.Saved input with Ok(v,_)->v|_->failwith"80B7 proof"in
  let emitter=match Pli80.Native_int_emitter.shadow input with Ok(v,_)->v|_->failwith"INT emitter"in
  let inside windows(c:N.case)=List.exists(fun(a,b)->a<c.entry_step&&c.return_step<b)windows in
  let acquisition_windows=List.map(fun(c:D.case)->c.entry_step,c.return_step)(D.cases driver)in
  let controllers exclusions=List.map(fun(offset,v)->N.controller ~offset ~exclude_entry_steps:(List.filter_map(fun c->if inside exclusions c then Some c.entry_step else None)(N.cases v))v input)family in
  let reference=snd(List.hd family)in
  let transfer=match N.shadow ~offset:0x7b99 input with Ok q->q|_->failwith"Pass58 proof"in
  let pending=match N.shadow ~offset:0x7ae4 input with Ok q->q|_->failwith"Pass57 proof"in
  let established=match N.shadow ~offset:0x8248 input with Ok q->q|_->failwith"Pass56 proof"in
  let single_counts,single=match N.run reference input(controllers windows)with Ok q->q|_->failwith"standalone family"in
  singles:=Printf.sprintf"{\"result\":%s,\"transition_vector\":%s}"(summary name(List.fold_left(+)0 single_counts)single)(array string_of_int single_counts)::!singles;
  let saved_windows=List.map(fun(c:Pli80.Native_attribute_gate.case)->c.entry_step,c.return_step)(Pli80.Native_attribute_gate.cases saved)in
  let saved_exclusions=List.filter_map(fun(c:Pli80.Native_attribute_gate.case)->if List.exists(fun(a,b)->a<c.entry_step&&c.entry_step<b)acquisition_windows then Some c.entry_step else None)(Pli80.Native_attribute_gate.cases saved)in
  let emitter_exclusions=List.filter_map(fun(c:Pli80.Native_int_emitter.case)->if List.exists(fun(a,b)->a<c.entry_step&&c.entry_step<b)(acquisition_windows@saved_windows)then Some c.entry_step else None)(Pli80.Native_int_emitter.cases emitter)in
  let compact=List.map(fun offset->offset,(match N.shadow ~offset input with Ok q->q|_->failwith"Pass54 compact proof"))[0x7557;0x756d;0x75a7;0x75ce;0x75f1;0x7619]in
  let previous=List.map(fun offset->offset,(match N.shadow ~offset input with Ok q->q|_->failwith"Pass53 proof"))[0x7434;0x7630;0x765e]in
  let resident=List.map(fun offset->offset,(match N.shadow ~offset input with Ok q->q|_->failwith"resident proof"))[0x11c3;0x11e5;0x1207]in
  let lower()=[N.controller finalizer input;D.controller driver input;Pli80.Native_attribute_gate.controller ~exclude_entry_steps:saved_exclusions saved input;Pli80.Native_int_emitter.controller ~exclude_entry_steps:emitter_exclusions emitter input]in
  let pointer=match N.shadow ~offset:0x7701 input with Ok q->q|_->failwith"Pass55 pointer proof"in
  let clear=match N.shadow ~offset:0x7b1b input with Ok q->q|_->failwith"Pass59 proof"in
  let carrier=match N.shadow ~offset:0x7e05 input with Ok q->q|_->failwith"Pass60 proof"in
  let pass61=List.map(fun offset->offset,(match N.shadow ~offset input with Ok q->q|_->failwith"Pass61 proof"))[0x742a;0x8258;0x82b5]in
  let paired=match N.shadow ~offset:0x7338 input with Ok q->q|_->failwith"Pass62 proof"in
  let structure=match N.shadow ~offset:0x829c input with Ok q->q|_->failwith"Pass63 proof"in
  let lifecycle=match N.shadow ~offset:0x82dd input with Ok q->q|_->failwith"Pass64 proof"in
  let prior=[0x82dd,lifecycle;0x829c,structure;0x7338,paired]@pass61@[0x7e05,carrier;0x7b1b,clear;0x7b99,transfer;0x7ae4,pending;0x8248,established;0x7701,pointer]@compact@previous@resident in
  let prior_windows=List.concat_map(fun(_,v)->List.map(fun(c:N.case)->c.entry_step,c.return_step)(N.cases v))prior in
  let prior_controllers exclusions=List.map(fun(offset,v)->N.controller ~offset ~exclude_entry_steps:(List.filter_map(fun c->if inside exclusions c then Some c.entry_step else None)(N.cases v))v input)prior in
  let pre_counts,pre=match N.run reference input(prior_controllers(acquisition_windows@prior_windows)@lower())with Ok q->q|_->failwith"Pass63 baseline"in
  let post_counts,post=match N.run reference input(controllers(acquisition_windows@windows)@prior_controllers(acquisition_windows@prior_windows@windows)@lower())with Ok q->q|_->failwith"cumulative family"in
  let accepted=List.fold_left(+)0(List.filteri(fun i _->i<List.length members)post_counts)in
  Printf.printf"%s family %s guest %d -> %d\n%!"name(String.concat","(List.map string_of_int post_counts))pre.run.steps post.run.steps;
  cumulatives:=Printf.sprintf"{\"result\":%s,\"transition_vector\":%s,\"pre_transition_vector\":%s,\"pre_guest_instructions\":%d,\"guest_instructions_removed\":%d,\"family_roots\":%d,\"record_sha256_sequence\":%s}"(summary name accepted post)(array string_of_int post_counts)(array string_of_int pre_counts)pre.run.steps(pre.run.steps-post.run.steps)accepted(array(fun(n,i,sha)->Printf.sprintf"[%S,%d,%S]"n i sha)(N.record_summaries reference))::!cumulatives
 ) )(if !cross=""then goldens else[!cross,0,""]);
 List.iter(fun(n,xs)->write(Filename.concat !output n)("{\"sources\":"^array Fun.id(List.rev xs)^",\"all_passed\":true}"))[
 "component-shadows.json",!components;"natural-cases.json",!roots;"single-hybrid-summary.json",!singles;"cumulative-hybrid-summary.json",!cumulatives];
 write(Filename.concat !output "natural-instruction-witnesses.json")(array Fun.id(List.rev !N.policy_natural_instructions));
 write(Filename.concat !output "synthetic-checkpoints.json")("{\"cases\":"^array Fun.id(List.rev !N.carrier_synthetic_proofs)^",\"all_passed\":true}");
 write(Filename.concat !output "synthetic-helper-pairs.json")(array(fun(offset,call,ret)->Printf.sprintf"{\"coordinate\":\"PLI2.OVL+%04X\",\"relation\":\"DEDUCED STATIC UNOBSERVED synthetic original CALL/RET ancestry\",\"call\":%s,\"ret\":%s}"offset call ret)(List.rev !N.carrier_synthetic_pairs))
