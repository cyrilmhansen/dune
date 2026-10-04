[@@@warning "-4-40-41-42"]
let read path = let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)
  (fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path text = let c=open_out path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_string c text;output_char c '\n')
let array f xs="["^String.concat ","(List.map f xs)^"]"
let state (s:Runner.state_snapshot)=Printf.sprintf
  "{\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"sp\":%d,\"pc\":%d,\"flags\":{\"sign\":%b,\"zero\":%b,\"auxiliary_carry\":%b,\"parity\":%b,\"carry\":%b}}"
  s.a s.b s.c s.d s.e s.h s.l s.sp s.pc s.sign s.zero s.auxiliary_carry s.parity s.carry
let case (c:Pli80.Native_7bbf.case)=
  let r=c.result in Printf.sprintf
    "{\"entry_step\":%d,\"return_step\":%d,\"input\":%s,\"output\":%s,\"position\":%d,\"initial_index\":%d,\"fresh_index\":%d,\"initial_word\":%d,\"shifted_word\":%d,\"counter\":%d,\"shifts\":%d,\"auxiliary_address\":%d,\"discarded_AE39\":%d,\"publication_word\":%d,\"entry_memory_sha256\":%S,\"final_memory_sha256\":%S,\"logical_writes_sha256\":%S,\"writes\":%s,\"compatibility_writes\":%s,\"all_registers_flags_match\":true,\"full_memory_match\":true,\"logical_order_match\":true,\"residue_latest_writers_match\":true}"
    c.entry_step c.return_step (state c.input)(state c.output)r.position r.initial_index r.fresh_index r.initial_word r.shifted_word r.counter r.shifts r.auxiliary_address r.discarded_ae39 r.publication_word c.entry_memory_sha256 c.final_memory_sha256 c.logical_writes_sha256
    (array(fun(w:Pli80_host.Packed_scan.write)->Printf.sprintf"{\"address\":%d,\"value\":%d,\"phase\":%S}"w.address w.value w.phase)r.writes)
    (array(fun(a,v)->Printf.sprintf"[%d,%d]"a v)c.compatibility_writes)
let goldens=["MINIMAL",3,256,"7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119";
  "FIZZBUZ",21,768,"68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203";
  "PICTURE",3,256,"c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1"]
let summary name count (r:Pli80.Experiment.result) =
  let rel=match r.rel_bytes with Some b->b|None->failwith"No REL output" in
  let expected=List.find(fun(n,_,_,_)->n=name)goldens in
  let _,n,size,hash=expected in
  if not(count=n && Bytes.length rel=size && Pli80.Experiment.sha256_hex rel=hash) then failwith("REL golden/count mismatch: "^name);
  let marker text=List.exists(fun(m:Pli80.Console_capture.message)->m.text=text)r.console_messages in
  if not(marker"NO ERROR(S) IN PASS 1" && marker"NO ERROR(S) IN PASS 2" && marker"END  COMPILATION" && r.run.termination=Runner.Warm_boot) then failwith("Compilation markers/termination mismatch: "^name);
  Printf.sprintf"{\"source\":%S,\"invocations\":%d,\"REL_size\":%d,\"REL_sha256\":%S,\"PASS1\":true,\"PASS2\":true,\"END_COMPILATION\":true,\"termination\":\"warm_boot\",\"native_interceptions\":%d,\"actual_guest_instructions\":%d,\"actual_guest_t_states\":%d}"name count size hash r.run.host_transitions r.run.steps r.run.t_states
let () =
  let toolchain=ref""and output=ref"" in
  Arg.parse ["--toolchain",Arg.Set_string toolchain,"historical DISK1";"--output-dir",Arg.Set_string output,"unused ignored output directory"](fun _->failwith"Unexpected argument")"pli80-native-7bbf";
  if !toolchain="" || !output="" then failwith"--toolchain and --output-dir required";
  if Sys.file_exists !output then failwith"Refusing existing output directory";
  Unix.mkdir !output 0o755;
  let image name=read(Filename.concat !toolchain name) in
  let cases=ref [] and summaries=ref [] and proofs=ref [] in
  List.iter(fun(name,_,_,_)->
    let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";
      source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true (read("examples/pli80/"^name^".PLI"));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000} in
    match Pli80.Native_7bbf.shadow input with
    |Error _->failwith("Historical shadow failed: "^name)
    |Ok(token,r)->let cs=Pli80.Native_7bbf.cases token in proofs:=(name,input,token)::!proofs;summaries:=summary name(List.length cs)r::!summaries;cases:=(Printf.sprintf"{\"source\":%S,\"members\":%s}"name(array case cs))::!cases;
      Printf.printf"%s shadow: %d full-memory/register/flag/order comparisons passed\n%!"name(List.length cs))goldens;
  write(Filename.concat !output "native-cases.json")( "{\"sources\":"^array Fun.id(List.rev !cases)^"}");
  write(Filename.concat !output "shadow-summary.json")("{\"sources\":"^array Fun.id(List.rev !summaries)^",\"total\":27,\"all_passed\":true}");
  (* Gate: all three historical runs and all27 full-memory shadows completed
     before the first call of hybrid(), which requires an opaque proof token. *)
  List.iter(fun(_,(input:Pli80.Experiment.input),token)->
    (match Pli80.Native_7bbf.hybrid token {input with max_steps=input.max_steps+1} with
     |exception Failure message when message="Native7BBF: shadow proof belongs to another input"->()
     |_->failwith"Changed hybrid input was not rejected");
    let intercept ~origin:_ ~step_index:_ _=Runner.Continue_guest_execution in
    List.iter(fun(structure,witnesses,analysis)->
      match Pli80.Experiment.run ~intercept ~structure ~event_witnesses:witnesses ~analysis input with
      |Error Pli80.Experiment.Interception_requires_execution_only->()
      |_->failwith"Unsupported hybrid analysis mode accepted")
      [true,false,Pli80.Experiment.Execution;false,true,Pli80.Experiment.Execution;false,false,Pli80.Experiment.Path])!proofs;
  let hybrids=List.map(fun(name,input,token)->
    match Pli80.Native_7bbf.hybrid token input with
    |Error _->failwith("Hybrid failed: "^name)
    |Ok(count,r)->Printf.printf"%s hybrid: %d native replacements; exact REL and all INT/REL records passed\n%!"name count;
      let records=array(fun(n,i,sha)->Printf.sprintf"{\"file\":%S,\"record\":%d,\"sha256\":%S}"n i sha)(Pli80.Native_7bbf.record_summaries token) in
      Printf.sprintf"{\"result\":%s,\"all_entry_and_resume_states_match\":true,\"all_record_bytes_match\":true,\"record_oracles\":%s}"(summary name count r)records)(List.rev !proofs) in
  write(Filename.concat !output "hybrid-summary.json")("{\"sources\":"^array Fun.id hybrids^",\"total_native_replacements\":27,\"no_fallback\":true}")
