[@@@warning "-4-40-41-42"]
module N=Pli80.Native_reentrant_acquisition
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let array f xs="["^String.concat","(List.map f xs)^"]"
let state(s:Runner.state_snapshot)=Printf.sprintf"{\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"sp\":%d,\"pc\":%d,\"flags\":{\"sign\":%b,\"zero\":%b,\"auxiliary_carry\":%b,\"parity\":%b,\"carry\":%b}}"s.a s.b s.c s.d s.e s.h s.l s.sp s.pc s.sign s.zero s.auxiliary_carry s.parity s.carry
let ()=
 let toolchain=ref""and output=ref""in
 Arg.parse["--toolchain",Arg.Set_string toolchain,"DISK1";"--output",Arg.Set_string output,"development proof JSON"](fun _->failwith"argument")"partial +6223 implementation proof";
 if !toolchain=""|| !output=""then failwith"arguments required";
 let reports=List.map(fun name->
  let image n=read(Filename.concat !toolchain n)in
  let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read("examples/pli80/"^name^".PLI"));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  let p=match N.shadow input with Ok q->q|_->failwith"historical run"in
  Printf.printf"%s: matched %d; acquisition-family pending %d\n%!"name(List.length p.cases)(List.length p.pending);
  Printf.sprintf"{\"source\":%S,\"matched_route_B\":%d,\"pending_route_A\":%d,\"cases\":%s}"
   name(List.length(List.filter(fun(c:N.case)->c.route=Pli80_host.Reentrant_acquisition.Route_b)p.cases))(List.length p.pending)
   (array(fun(c:N.case)->Printf.sprintf"{\"caller\":%S,\"entry_step\":%d,\"return_step\":%d,\"route\":%S,\"input\":%s,\"output\":%s,\"entry_memory_sha256\":%S,\"post_memory_sha256\":%S,\"stack_cells\":%d,\"logical_writes\":%d}"
    c.caller c.entry_step c.return_step(Pli80_host.Reentrant_acquisition.name c.route)(state c.input)(state c.output)c.entry_memory_sha256 c.post_memory_sha256 c.stack_cells c.logical_writes)p.cases))["MINIMAL";"FIZZBUZ";"PICTURE"]in
 let ch=open_out !output in Fun.protect ~finally:(fun()->close_out ch)(fun()->output_string ch("{\"status\":\"partial development proof; no hybrid controller enabled\",\"sources\":"^array Fun.id reports^"}\n"))
