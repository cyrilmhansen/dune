[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path text=let c=open_out path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_string c text;output_char c '\n')
let array f xs="["^String.concat","(List.map f xs)^"]"
let state(s:Runner.state_snapshot)=Printf.sprintf"{\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"sp\":%d,\"pc\":%d,\"flags\":{\"sign\":%b,\"zero\":%b,\"auxiliary_carry\":%b,\"parity\":%b,\"carry\":%b}}"s.a s.b s.c s.d s.e s.h s.l s.sp s.pc s.sign s.zero s.auxiliary_carry s.parity s.carry
let hex bytes=Bytes.to_seq bytes|>List.of_seq|>List.map(fun c->Printf.sprintf"%02X"(Char.code c))|>String.concat""
let sha=Pli80.Experiment.sha256_hex
let ()=
 let toolchain=ref""and output=ref""in
 Arg.parse["--toolchain",Arg.Set_string toolchain,"historical DISK1";"--output-dir",Arg.Set_string output,"new ignored directory"](fun _->failwith"Unexpected argument")"pli80-int-emitter-audit";
 if !toolchain=""|| !output=""||Sys.file_exists !output then failwith"Require toolchain and new output directory";
 Unix.mkdir !output 0o755;
 let sources=List.map(fun(name,size,golden)->
  let image n=read(Filename.concat !toolchain n)in
  let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read("examples/pli80/"^name^".PLI"));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  let previous=ref None and active=ref None and rows=ref[]and bdos=ref[]and origin=ref Analysis.Execution_map.Unknown in
  let coordinate=function Analysis.Execution_map.Image_byte{image;offset}->Printf.sprintf"%s+%04X"image.name offset|_->"runtime0005"in
  let on_guest_step ~step_index ~before ~after step=previous:=Some(step_index,coordinate !origin,before,after,step)in
  let on_before_instruction ~origin:o ~step_index boundary=
   origin:=o;let s=boundary.Runner.state in
   let m=boundary.read_memory in
   (match !active,!previous with
    |Some(entry,caller,(before:Runner.state_snapshot),ram),Some(ret_step,_,_,after,step)when I8080.Step.pc_before step=0x102c && s=after->
     if I8080.Step.control_flow step<>I8080.Step.Return{target=Some s.pc;taken=true}||s.sp<>before.sp+2 then failwith"Emitter outer RET identity";
     let old=Char.code(Bytes.get ram 0x1e0c)in
     let path=if old=127 then(if s.a=0 then"flush_success"else"flush_error")else"non_flush"in
     rows:=Printf.sprintf"{\"entry_step\":%d,\"return_step\":%d,\"caller\":%S,\"input\":%s,\"output\":%s,\"entry_index\":%d,\"neighbor_1E0D\":%d,\"buffer_address\":%d,\"old_buffer_byte\":%d,\"new_buffer_byte\":%d,\"resulting_index\":%d,\"path\":%S,\"entry_memory_sha256\":%S,\"post_memory_sha256\":%S,\"buffer_after_hex\":%S}"entry ret_step caller(state before)(state s)old(Char.code(Bytes.get ram 0x1e0d))(0x1d8c+old)(Char.code(Bytes.get ram(0x1d8c+old)))(m(0x1d8c+old))(m 0x1e0c)path(sha ram)(sha(boundary.copy_memory()))(hex(Bytes.init 128(fun i->Char.chr(m(0x1d8c+i)))))::!rows;active:=None
    |_->());
   if s.pc=0xff6 then(
    if coordinate o<>"PLI.COM+0EF6"|| !active<>None then failwith"Invalid emitter entry";
    let caller=match !previous with Some(_,site,(before:Runner.state_snapshot),after,step)when after=s&&I8080.Step.control_flow step=I8080.Step.Call{target=0xff6;taken=true}&&before.sp=s.sp+2->site|_->failwith"No actual emitter CALL"in
    active:=Some(step_index,caller,s,boundary.copy_memory()));
   if s.pc=5 && !active<>None then bdos:=Printf.sprintf"{\"step\":%d,\"post_host_state\":%s,\"index\":%d,\"buffer_hex\":%S,\"FCB_hex\":%S}"step_index(state s)(m 0x1e0c)(hex(Bytes.init 128(fun i->Char.chr(m(0x1d8c+i)))))(hex(Bytes.init 36(fun i->Char.chr(m(0x1ca2+i)))))::!bdos in
  match Pli80.Experiment.run ~analysis:Pli80.Experiment.Execution ~on_before_instruction ~on_guest_step input with
  |Error _->failwith"Historical audit run failed"|Ok r->
   if !active<>None||r.run.host_transitions<>0||r.run.termination<>Runner.Warm_boot then failwith"Incomplete historical audit";
   let rel=Option.get r.rel_bytes in
   if Bytes.length rel<>size||sha rel<>golden then failwith"Golden REL mismatch";
   List.iter(fun text->if not(List.exists(fun(m:Pli80.Console_capture.message)->m.text=text)r.console_messages)then failwith"Missing marker")["NO ERROR(S) IN PASS 1";"NO ERROR(S) IN PASS 2";"END  COMPILATION"];
   Printf.printf"%s:%d complete emitter snapshots\n%!"name(List.length !rows);
   Printf.sprintf"{\"source\":%S,\"REL_size\":%d,\"REL_sha256\":%S,\"actual_guest_instructions\":%d,\"PASS1_PASS2_END_warm_boot\":true,\"cases\":%s,\"BDOS_post_boundaries\":%s}"name size golden r.run.steps(array Fun.id(List.rev !rows))(array Fun.id(List.rev !bdos))
 ) ["MINIMAL",256,"7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119";"FIZZBUZ",768,"68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203";"PICTURE",256,"c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1"]in
 write(Filename.concat !output"snapshots.json")("{\"sources\":"^array Fun.id sources^"}")
