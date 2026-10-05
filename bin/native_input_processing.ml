[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path text=let c=open_out path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_string c text;output_char c '\n')
let array f xs="["^String.concat","(List.map f xs)^"]"
let state(s:Runner.state_snapshot)=Printf.sprintf"{\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"sp\":%d,\"pc\":%d,\"flags\":{\"sign\":%b,\"zero\":%b,\"auxiliary_carry\":%b,\"parity\":%b,\"carry\":%b}}"s.a s.b s.c s.d s.e s.h s.l s.sp s.pc s.sign s.zero s.auxiliary_carry s.parity s.carry
module B=Pli80.Input_processing_bridge
module N=Pli80.Native_input_processing
let writes ws=array(fun(w:Pli80_host.Mapped_lookup.write)->Printf.sprintf"{\"address\":%d,\"value\":%d,\"phase\":%S}"w.address w.value w.phase)ws
let result(q:Pli80_host.Input_processing.result)=Printf.sprintf"{\"route\":%S,\"input\":%d,\"gate\":%s,\"rotated_gate\":%s,\"emitted\":%s,\"channels\":%s}"q.route q.input
 (match q.gate with None->"null"|Some n->string_of_int n)(match q.rotated_gate with None->"null"|Some n->string_of_int n)(match q.emitted with None->"null"|Some n->string_of_int n)
 (array(fun(c:Pli80_host.Input_processing.channel)->Printf.sprintf"{\"name\":%S,\"predecessor\":%d,\"position\":%d,\"value\":%d}"c.name c.predecessor c.position c.value)q.channels)
let journal js=array(fun(w:B.write)->Printf.sprintf"{\"address\":%d,\"value\":%d,\"writer\":%d,\"depth\":%d,\"kind\":%S}"w.address w.value w.writer w.depth w.kind)js
let child(c:B.child)=Printf.sprintf"{\"site\":%d,\"input\":%s,\"output\":%s}"c.site(state c.input)(state c.output)
let case(c:N.case)=Printf.sprintf"{\"caller\":%S,\"entry_step\":%d,\"return_step\":%d,\"input\":%s,\"output\":%s,\"entry_memory_sha256\":%S,\"post_memory_sha256\":%S,\"entry_filesystem_sha256\":%S,\"post_filesystem_sha256\":%S,\"entry_dma\":%d,\"post_dma\":%d,\"result\":%s,\"journal\":%s,\"children\":%s,\"service_functions\":%s,\"range_path\":%s,\"entry_cells\":%s}"
 c.caller c.entry_step c.return_step(state c.input)(state c.output)c.entry_memory_sha256 c.post_memory_sha256 c.entry_filesystem_sha256 c.post_filesystem_sha256 c.entry_dma c.post_dma(result c.prepared.result)(journal c.prepared.journal)(array child c.prepared.children)
 (array(fun(s:Runner.host_service)->string_of_int s.call_state.c)c.services)
 (match c.prepared.range with None->"null"|Some p->Printf.sprintf"%S"p.result.path)
 (array(fun(a,v)->Printf.sprintf"[%d,%d]"a v)c.entry_cells)
module C=Pli80.Native_mapped_control
let control_case(c:C.case)=
 let q=match c.result with Pli80.Mapped_control_bridge.Read_result q|Publish_result q->q in
 Printf.sprintf"{\"operation\":%S,\"caller\":%S,\"entry_step\":%d,\"return_step\":%d,\"input\":%s,\"output\":%s,\"position\":%d,\"index\":%d,\"address\":%d,\"value\":%d,\"discarded_high\":%d,\"writes\":%s,\"entry_memory_sha256\":%S,\"post_memory_sha256\":%S}"
 (match c.result with Read_result _->"read"|Publish_result _->"publish")c.caller c.entry_step c.return_step(state c.input)(state c.output)q.position q.index q.address q.value q.discarded_high(writes c.writes)c.entry_memory_sha256 c.final_memory_sha256
let goldens=["MINIMAL",256,"7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119";"FIZZBUZ",768,"68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203";"PICTURE",256,"c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1"]
let summary name count(r:Pli80.Experiment.result)=
 let _,size,sha=List.find(fun(n,_,_)->n=name)goldens in
 let rel=match r.rel_bytes with Some b->b|_->failwith"No REL"in
 let marker text=List.exists(fun(m:Pli80.Console_capture.message)->m.text=text)r.console_messages in
 if Bytes.length rel<>size || Pli80.Experiment.sha256_hex rel<>sha || not(marker"NO ERROR(S) IN PASS 1"&&marker"NO ERROR(S) IN PASS 2"&&marker"END  COMPILATION")||r.run.termination<>Runner.Warm_boot then failwith("Bad compilation oracle:"^name);
 Printf.sprintf"{\"source\":%S,\"invocations\":%d,\"REL_size\":%d,\"REL_sha256\":%S,\"PASS1\":true,\"PASS2\":true,\"END_COMPILATION\":true,\"termination\":\"warm_boot\",\"actual_guest_instructions\":%d,\"actual_guest_t_states\":%d,\"host_transitions\":%d}"name count size sha r.run.steps r.run.t_states r.run.host_transitions
let ()=
 let toolchain=ref "" and output=ref "" in
 Arg.parse["--toolchain",Arg.Set_string toolchain,"DISK1";"--output-dir",Arg.Set_string output,"new output directory"](fun _->failwith"Unexpected argument")"native publication primitives";
 if !toolchain=""|| !output=""||Sys.file_exists !output then failwith"Require toolchain and new output directory";
 Unix.mkdir !output 0o755;
 let control_cases=ref[]and control_singles=ref[]in
 let root_cases=ref[]and shadows=ref[]and singles=ref[]and cumulatives=ref[]in
 List.iter(fun(name,_,_)->
  let image n=read(Filename.concat !toolchain n)in
  let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read("examples/pli80/"^name^".PLI"));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  let controls=match C.shadow input with Ok(v,_)->v|_->failwith"control shadows"in
  control_cases:=Printf.sprintf"{\"source\":%S,\"members\":%s}"name(array control_case(C.cases controls))::!control_cases;
  List.iter(fun op->
   (match C.single op controls {input with source_bytes=Bytes.empty}with exception Failure _->()|_->failwith"Control source mismatch accepted");
   match C.single op controls input with Ok([count],r)->control_singles:=Printf.sprintf"{\"operation\":%S,\"result\":%s}"(if op=Pli80.Mapped_control_bridge.Read then"read"else"publish")(summary name count r)::!control_singles|_->failwith"control single")[Pli80.Mapped_control_bridge.Read;Publish];
  let v,r=match N.shadow input with Ok q->q|_->failwith"publication shadows"in
  Printf.printf"%s shadows %d\n%!"name(List.length(N.cases v));
  root_cases:=Printf.sprintf"{\"source\":%S,\"members\":%s}"name(array case(N.cases v))::!root_cases;
  shadows:=summary name(List.length(N.cases v))r::!shadows;
  (match N.single v {input with source_bytes=Bytes.empty}with exception Failure _->()|_->failwith"Source mismatch accepted");
  (match N.single v input with Ok([count],r)->singles:=summary name count r::!singles|_->failwith"single");
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
  match N.cumulative v controls publication new_publications range words emitter attributes publications recursive packed balances input with
  |Ok(counts,r)->Printf.printf"%s cumulative %s; services %d\n%!"name(String.concat","(List.map string_of_int counts))r.run.host_bdos_services;
   cumulatives:=Printf.sprintf"{\"result\":%s,\"transition_vector\":%s,\"host_bdos_services\":%d,\"record_sha256_sequence\":%s}"(summary name(List.fold_left(+)0 counts)r)(array string_of_int counts)r.run.host_bdos_services(array(fun(n,i,sha)->Printf.sprintf"[%S,%d,%S]"n i sha)(N.record_summaries v))::!cumulatives
  |_->failwith"cumulative")goldens;
 List.iter(fun(n,xs)->write(Filename.concat !output n)("{\"sources\":"^array Fun.id(List.rev xs)^",\"all_passed\":true}"))[
 "control-cases.json",!control_cases;"control-single-hybrid-summary.json",!control_singles;"natural-cases.json",!root_cases;"shadow-summary.json",!shadows;"single-hybrid-summary.json",!singles;"cumulative-hybrid-summary.json",!cumulatives]
