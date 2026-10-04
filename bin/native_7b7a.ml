[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path text=let c=open_out path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_string c text;output_char c '\n')
let array f xs="["^String.concat","(List.map f xs)^"]"
let state(s:Runner.state_snapshot)=Printf.sprintf"{\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"sp\":%d,\"pc\":%d,\"flags\":{\"sign\":%b,\"zero\":%b,\"auxiliary_carry\":%b,\"parity\":%b,\"carry\":%b}}"s.a s.b s.c s.d s.e s.h s.l s.sp s.pc s.sign s.zero s.auxiliary_carry s.parity s.carry
let iteration(i:Pli80_host.Balance_scan.iteration)=let a=i.lookup in Printf.sprintf"{\"cursor\":%d,\"index\":%d,\"mapped_byte\":%d,\"packed_byte\":%d,\"attribute\":%d,\"discarded_AE37\":%d,\"discarded_AE38\":%d,\"balance_before\":%d,\"temporary_sum\":%d,\"balance_after\":%d,\"cursor_wrapped\":%b}"i.cursor a.mapped.index a.mapped.byte a.packed_byte a.low3 a.mapped.discarded_ae37 a.discarded_ae38 i.balance_before i.temporary_sum i.balance_after i.cursor_wrapped
let case(c:Pli80.Native_7b7a.case)=Printf.sprintf"{\"caller\":%S,\"entry_step\":%d,\"return_step\":%d,\"input\":%s,\"output\":%s,\"entry_memory_sha256\":%S,\"final_memory_sha256\":%S,\"logical_writes_sha256\":%S,\"iterations\":%s,\"writes\":%s,\"compatibility_writes\":%s}"c.caller c.entry_step c.return_step(state c.input)(state c.output)c.entry_memory_sha256 c.final_memory_sha256 c.logical_writes_sha256(array iteration c.result.iterations)(array(fun(w:Pli80_host.Mapped_lookup.write)->Printf.sprintf"{\"address\":%d,\"value\":%d,\"phase\":%S}"w.address w.value w.phase)c.result.writes)(array(fun(a,v)->Printf.sprintf"[%d,%d]"a v)c.compatibility_writes)
let goldens=["MINIMAL",256,"7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119";"FIZZBUZ",768,"68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203";"PICTURE",256,"c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1"]
let summary name count(r:Pli80.Experiment.result)=
 let _,size,sha=List.find(fun(n,_,_)->n=name)goldens in
 let rel=match r.rel_bytes with Some b->b|_->failwith"No REL"in
 let marker text=List.exists(fun(m:Pli80.Console_capture.message)->m.text=text)r.console_messages in
 if Bytes.length rel<>size || Pli80.Experiment.sha256_hex rel<>sha || not(marker"NO ERROR(S) IN PASS 1"&&marker"NO ERROR(S) IN PASS 2"&&marker"END  COMPILATION")||r.run.termination<>Runner.Warm_boot then failwith("Bad compilation oracle:"^name);
 Printf.sprintf"{\"source\":%S,\"invocations\":%d,\"REL_size\":%d,\"REL_sha256\":%S,\"PASS1\":true,\"PASS2\":true,\"END_COMPILATION\":true,\"termination\":\"warm_boot\",\"actual_guest_instructions\":%d,\"actual_guest_t_states\":%d,\"host_transitions\":%d}"name count size sha r.run.steps r.run.t_states r.run.host_transitions
let ()=
 let toolchain=ref""and output=ref""in
 Arg.parse["--toolchain",Arg.Set_string toolchain,"DISK1";"--output-dir",Arg.Set_string output,"new ignored output directory"](fun _->failwith"Unexpected argument")"pli80-native-7b7a";
 if !toolchain="" || !output="" || Sys.file_exists !output then failwith"Require toolchain and new output directory";
 Unix.mkdir !output 0o755;
 let cases=ref[]and summaries=ref[]and proofs=ref[]in
 List.iter(fun(name,_,_)->
  let image n=read(Filename.concat !toolchain n)in
  let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read("examples/pli80/"^name^".PLI"));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  match Pli80.Native_7b7a.shadow input with Error _->failwith"Shadow failed"|Ok(token,r)->
   let word=match Pli80.Native_7bbf.shadow input with Ok(t,_)->t|_->failwith"7BBF shadow failed"in
   proofs:=(name,input,token,word)::!proofs;
   let cs=Pli80.Native_7b7a.cases token in
   cases:=Printf.sprintf"{\"source\":%S,\"members\":%s}"name(array case cs)::!cases;
   summaries:=summary name(List.length cs)r::!summaries;
   Printf.printf"%s: %d balance shadows passed full memory, registers/flags, logical writes and residue writers\n%!"name(List.length cs))goldens;
 write(Filename.concat !output "balance-scan-cases.json")("{\"sources\":"^array Fun.id(List.rev !cases)^"}");
 write(Filename.concat !output "shadow-summary.json")("{\"sources\":"^array Fun.id(List.rev !summaries)^",\"all_passed\":true}");
 List.iter(fun(_,(input:Pli80.Experiment.input),token,word)->
  let changed={input with max_steps=input.max_steps+1}in
  (match Pli80.Native_7b7a.hybrid token changed with exception Failure _->()|_->failwith"Proof input mismatch accepted");
  (match Pli80.Native_7b7a.cumulative token word changed with exception Failure _->()|_->failwith"Cumulative input mismatch accepted"))!proofs;
 let singles=List.map(fun(name,input,token,_)->match Pli80.Native_7b7a.hybrid token input with
  |Error _->failwith"Single hybrid failed"|Ok(count,r)->Printf.printf"%s +7B7A-only: %d exact replacements\n%!"name count;summary name count r)(List.rev !proofs)in
 write(Filename.concat !output "single-hybrid-summary.json")("{\"sources\":"^array Fun.id singles^",\"no_fallback\":true}");
 let cumulative=List.map(fun(name,input,token,word)->match Pli80.Native_7b7a.cumulative token word input with
  |Error _->failwith"Cumulative hybrid failed"|Ok((words,balances),r)->
   Printf.printf"%s cumulative: %d word + %d balance replacements; exact full-state and INT/REL records\n%!"name words balances;
   let records=array(fun(n,i,sha)->Printf.sprintf"{\"file\":%S,\"record\":%d,\"sha256\":%S}"n i sha)(Pli80.Native_7b7a.record_summaries token)in
   Printf.sprintf"{\"result\":%s,\"native_7BBF\":%d,\"native_7B7A\":%d,\"all_entry_resume_memory_states_match\":true,\"INT_REL_records_match\":true,\"no_historical_replaced_body_execution\":true,\"record_oracles\":%s}"(summary name balances r)words balances records)(List.rev !proofs)in
 write(Filename.concat !output "cumulative-hybrid-summary.json")("{\"sources\":"^array Fun.id cumulative^",\"no_fallback\":true}")
