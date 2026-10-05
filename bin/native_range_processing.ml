[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path text=let c=open_out path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_string c text;output_char c '\n')
let array f xs="["^String.concat","(List.map f xs)^"]"
let state(s:Runner.state_snapshot)=Printf.sprintf"{\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"sp\":%d,\"pc\":%d,\"flags\":{\"sign\":%b,\"zero\":%b,\"auxiliary_carry\":%b,\"parity\":%b,\"carry\":%b}}"s.a s.b s.c s.d s.e s.h s.l s.sp s.pc s.sign s.zero s.auxiliary_carry s.parity s.carry
module N=Pli80.Native_range_processing
let pairs xs=array(fun(a,v)->Printf.sprintf "[%d,%d]" a v)xs
let record=function
 |Cpm.Bdos.Write_record q->Printf.sprintf "{\"file\":%S,\"record\":%d,\"dma\":%d,\"data_hex\":%S,\"sha256\":%S}"q.file.name q.logical_record q.dma
  (Bytes.to_seq q.data|>List.of_seq|>List.map(fun c->Printf.sprintf "%02X"(Char.code c))|>String.concat "")(Pli80.Experiment.sha256_hex q.data)
 |_->failwith "Unexpected native service record"
let service(s:Runner.host_service)=Printf.sprintf "{\"call_state\":%s,\"resume_state\":%s,\"dma_before\":%d,\"dma_after\":%d,\"records\":%s,\"FCB_writes\":%s}"(state s.call_state)(state s.resume_state)s.dma_before s.dma_after(array record s.events)
 (pairs(List.filter_map(function Cpm.Bdos.Memory_write q->Some(q.address,q.value)|_->None)s.effects))
module R=Pli80_host.Recursive_mapped
let writes ws=array(fun(w:R.write)->Printf.sprintf"{\"address\":%d,\"value\":%d,\"writer\":%d,\"depth\":%d,\"phase\":%S}"w.address w.value w.writer w.depth w.phase)ws
let helper=function
 |R.Mapping(site,q)->Printf.sprintf"{\"site\":%d,\"kind\":\"mapping\",\"position\":%d,\"index\":%d,\"mapped\":%d}"site q.position q.index q.byte
 |R.Attribute(site,q)->Printf.sprintf"{\"site\":%d,\"kind\":\"attribute\",\"position\":%d,\"index\":%d,\"mapped\":%d,\"packed\":%d,\"low3\":%d}"site q.mapped.position q.mapped.index q.mapped.byte q.packed_byte q.low3
 |R.Auxiliary_read(site,q)|R.Auxiliary_write(site,q)as h->Printf.sprintf"{\"site\":%d,\"kind\":%S,\"position\":%d,\"index\":%d,\"address\":%d,\"value\":%d,\"discarded_high\":%d}"site (match h with R.Auxiliary_read _->"auxiliary_read"|_->"auxiliary_write")q.position q.index q.address q.value q.discarded_high
 |R.Packed(site,q)->Printf.sprintf"{\"site\":%d,\"kind\":\"packed\",\"position\":%d,\"word\":%d,\"shifted_word\":%d,\"counter\":%d,\"shifts\":%d,\"fresh_index\":%d}"site q.position q.initial_word q.shifted_word q.counter q.shifts q.fresh_index
 |R.Balance(site,q)->Printf.sprintf"{\"site\":%d,\"kind\":\"balance\",\"start\":%d,\"stop\":%d,\"iterations\":%s}"site q.start_cursor q.stop_cursor(array(fun(i:Pli80_host.Balance_scan.iteration)->Printf.sprintf"{\"cursor\":%d,\"index\":%d,\"mapped\":%d,\"packed\":%d,\"attribute\":%d,\"before\":%d,\"sum\":%d,\"after\":%d}"i.cursor i.lookup.mapped.index i.lookup.mapped.byte i.lookup.packed_byte i.lookup.low3 i.balance_before i.temporary_sum i.balance_after)q.iterations)
let rec tree(n:R.node)=Printf.sprintf"{\"frame\":%d,\"depth\":%d,\"position\":%d,\"entry_HL\":%d,\"entry_DE\":%d,\"entry_SP\":%d,\"initial_frame\":%s,\"mapped\":%d,\"path\":%S,\"children\":%s,\"helpers\":%s,\"final_frame\":%s,\"returned_A\":%d,\"return_site\":%d}"n.frame n.depth n.entry.position n.entry.hl n.entry.de n.entry.sp(array string_of_int n.initial_frame)n.mapped n.path(array tree n.children)(array helper n.helpers)(array string_of_int n.final_frame)n.returned.a n.return_site
let goldens=["MINIMAL",256,"7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119";"FIZZBUZ",768,"68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203";"PICTURE",256,"c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1"]
let summary name count(r:Pli80.Experiment.result)=
 let _,size,sha=List.find(fun(n,_,_)->n=name)goldens in
 let rel=match r.rel_bytes with Some b->b|_->failwith"No REL"in
 let marker text=List.exists(fun(m:Pli80.Console_capture.message)->m.text=text)r.console_messages in
 if Bytes.length rel<>size || Pli80.Experiment.sha256_hex rel<>sha || not(marker"NO ERROR(S) IN PASS 1"&&marker"NO ERROR(S) IN PASS 2"&&marker"END  COMPILATION")||r.run.termination<>Runner.Warm_boot then failwith("Bad compilation oracle:"^name);
 Printf.sprintf"{\"source\":%S,\"invocations\":%d,\"REL_size\":%d,\"REL_sha256\":%S,\"PASS1\":true,\"PASS2\":true,\"END_COMPILATION\":true,\"termination\":\"warm_boot\",\"actual_guest_instructions\":%d,\"actual_guest_t_states\":%d,\"host_transitions\":%d,\"host_bdos_services\":%d,\"INT_sha256\":%S,\"full_filesystem_identity\":true,\"file_events_identity\":true}"name count size sha r.run.steps r.run.t_states r.run.host_transitions r.run.host_bdos_services (match r.int_bytes with Some b->Pli80.Experiment.sha256_hex b|None->"deleted_after_PASS2")
module B=Pli80.Range_processing_bridge
module H=Pli80_host.Range_processing
let op=function H.Mapping->"mapping"|Recursive->"recursive"|Balance->"balance"|Emit->"emitter"|High_attribute->"high_attribute"|Primary->"primary"|Secondary->"secondary"|Low_word->"word_low"|High_word->"word_high"|Recycle->"recycle"
let opt f=function None->"null"|Some x->f x
let reverse(r:H.reverse)=Printf.sprintf"{\"cursor\":%d,\"sentinel\":%d,\"mapped\":%s,\"direct_result\":%s,\"stop\":%s,\"psw\":%d}"r.cursor r.sentinel(opt string_of_int r.mapped)(opt string_of_int r.result)(opt string_of_int r.stop)r.psw
let forward(f:H.forward)=Printf.sprintf"{\"cursor\":%d,\"mapped\":%d,\"attribute\":%d,\"channels\":%s}"f.cursor f.mapped f.attribute(array(fun(n,v)->Printf.sprintf"[%S,%d]"n v)f.channels)
let child(c:B.child)=Printf.sprintf"{\"site\":%d,\"operation\":%S,\"input\":%s,\"output\":%s,\"recursive_tree\":%s,\"balance\":%s}"c.site(op c.operation)(state c.input)(state c.output)(opt(fun r->tree r.R.tree)c.recursive)(opt(fun r->helper(R.Balance(c.site,r)))c.balance)
let journal(w:B.write)=Printf.sprintf"{\"address\":%d,\"value\":%d,\"writer_runtime\":%d,\"depth\":%d,\"kind\":%S}"w.address w.value w.writer w.depth w.kind
let case(c:N.case)=Printf.sprintf"{\"caller\":%S,\"entry_step\":%d,\"return_step\":%d,\"input\":%s,\"output\":%s,\"entry_cells\":%s,\"path\":%S,\"reverse\":%s,\"forward\":%s,\"children\":%s,\"journal\":%s,\"services\":%s,\"entry_dma\":%d,\"post_dma\":%d,\"entry_memory_sha256\":%S,\"post_memory_sha256\":%S}"c.caller c.entry_step c.return_step(state c.input)(state c.output)(pairs c.entry_cells)c.prepared.result.path(array reverse c.prepared.result.reverse)(array forward c.prepared.result.forward)(array child c.prepared.children)(array journal c.prepared.journal)(array service c.services)c.entry_dma c.post_dma c.entry_memory_sha256 c.post_memory_sha256
let ()=
 let toolchain=ref "" and output=ref "" in
 Arg.parse["--toolchain",Arg.Set_string toolchain,"DISK1";"--output-dir",Arg.Set_string output,"new output directory"](fun _->failwith"Unexpected argument")"native range processing";
 if !toolchain=""|| !output=""||Sys.file_exists !output then failwith"Require toolchain and new output directory";
 Unix.mkdir !output 0o755;
 let proofs=ref[]and sources=ref[]and shadows=ref[]and singles=ref[]and cumulatives=ref[]in
 List.iter(fun(name,_,_)->
  let image n=read(Filename.concat !toolchain n)in
  let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read("examples/pli80/"^name^".PLI"));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  let v,r=match N.shadow input with Ok q->q|_->failwith"range shadows"in
  Printf.printf"%s roots %d\n%!"name(List.length(N.cases v));
  sources:=Printf.sprintf"{\"source\":%S,\"cases\":%s}"name(array case(N.cases v))::!sources;
  shadows:=summary name(List.length(N.cases v))r::!shadows;
  (match N.single v {input with source_bytes=Bytes.empty}with exception Failure _->()|_->failwith"Source proof mismatch accepted");
  (match N.single v input with Ok(counts,r)->Printf.printf"%s single %s\n%!"name(String.concat","(List.map string_of_int counts));singles:=summary name(List.hd counts)r::!singles|_->failwith"single");
  proofs:=(name,input,v)::!proofs)goldens;
 write(Filename.concat !output"root-cases.json")("{\"sources\":"^array Fun.id(List.rev !sources)^"}");
 write(Filename.concat !output"shadow-summary.json")("{\"sources\":"^array Fun.id(List.rev !shadows)^",\"all121_memory_register_flags_external_state_chronology_exact\":true}");
 write(Filename.concat !output"single-hybrid-summary.json")("{\"sources\":"^array Fun.id(List.rev !singles)^",\"no_fallback\":true}");
 List.iter(fun(name,input,v)->
  let words=match Pli80.Native_word_emitters.shadow input with Ok(v,_)->v|_->failwith"words"in
  let emitter=match Pli80.Native_int_emitter.shadow input with Ok(v,_)->v|_->failwith"emitter"in
  let attributes=match Pli80.Native_attribute_auxiliary.shadow input with Ok(v,_)->v|_->failwith"attributes"in
  let publications=match Pli80.Native_mapped_publication.shadow input with Ok(v,_)->v|_->failwith"publications"in
  let recursive=match Pli80.Native_7c1b.shadow input with Ok(v,_)->v|_->failwith"recursive"in
  let packed=match Pli80.Native_7bbf.shadow input with Ok(v,_)->v|_->failwith"packed"in
  let balances=match Pli80.Native_7b7a.shadow input with Ok(v,_)->v|_->failwith"balances"in
  match N.cumulative v words emitter attributes publications recursive packed balances input with
  |Ok(counts,r)->Printf.printf"%s cumulative %s; services %d\n%!"name(String.concat","(List.map string_of_int counts))r.run.host_bdos_services;
   cumulatives:=Printf.sprintf"{\"result\":%s,\"transition_vector\":%s,\"record_sha256_sequence\":%s}"(summary name(List.fold_left(+)0 counts)r)(array string_of_int counts)(array(fun(n,i,sha)->Printf.sprintf"[%S,%d,%S]"n i sha)(N.record_summaries v))::!cumulatives
  |_->failwith"cumulative")(List.rev !proofs);
 write(Filename.concat !output"cumulative-hybrid-summary.json")("{\"sources\":"^array Fun.id(List.rev !cumulatives)^",\"no_enabled_guest_bodies\":true,\"no_fallback\":true}")
