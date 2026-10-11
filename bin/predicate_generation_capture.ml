[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path text=let c=open_out_bin path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_string c text)
module E=Analysis.Event_witness
let ()=
 let toolchain=ref""and output=ref""in Arg.parse["--toolchain",Arg.Set_string toolchain,"images";"--output-dir",Arg.Set_string output,"existing ignored output"]ignore"bounded concrete inventory";
 List.iter(fun name->
 let image n=read(Filename.concat !toolchain n)in
 let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read(let p="examples/pli80/"^name^".PLI"in if Sys.file_exists p then p else Filename.concat !toolchain(name^".PLI")));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
 let origin_at ~pc ~fetched=
 let base,bytes,label=if pc>=0x2200 then 0x2200,input.pli2_ovl,"PLI2"else 0x100,input.pli_com,"PLI"in
 let off=pc-base in if off>=0&&off+Bytes.length fetched<=Bytes.length bytes&&Bytes.sub bytes off(Bytes.length fetched)=fetched then Some{E.image={Cpm.Filesystem.drive=0;user=0;name=label^(if base=0x2200 then".OVL"else".COM")};offset=off}else None in
 let active=ref None and count=ref 0 and boundary=ref None and global=Hashtbl.create 128 in
 let last_dispatch=ref "null" and root_dispatches=ref []in
 let on_before_instruction ~origin ~step_index:_ (b:Runner.instruction_boundary)=
 boundary:=Some(origin,b);
 if b.state.pc=0x5f10 && !active<>None then write(Filename.concat !output(Printf.sprintf"%s-%d-entry.ram"name !count))(b.copy_memory()|>Bytes.to_string) in
 let on_guest_step ~step_index ~(before:Runner.state_snapshot) ~(after:Runner.state_snapshot) step=
 let is_pli2=match fst(Option.get !boundary)with Analysis.Execution_map.Image_byte q->q.image.name="PLI2.OVL"|_->false in
 if is_pli2&&I8080.Step.fetched_bytes step=Bytes.of_string"\xe9"then last_dispatch:=Printf.sprintf"{\"step\":%d,\"pc\":%d,\"target\":%d,\"SP\":%d}"step_index before.pc after.pc before.sp;
 (match I8080.Step.control_flow step with Call{target;taken=true}when is_pli2&&target>=0x2200->let o=target-0x2200 in Hashtbl.replace global o(1+Option.value ~default:0(Hashtbl.find_opt global o))|_->());
 (match I8080.Step.control_flow step,!active with Call{target=0x5f10;taken=true},None when is_pli2->
  let ew=E.create ~run_id:(name^"-3D10-"^string_of_int !count)~origin_at in active:=Some(ew,before.Runner.pc+3,after.sp);root_dispatches:= !last_dispatch::!root_dispatches;incr count
 |_->());
 (match !active with None->()|Some(ew,resume,sp)->E.observe_step ew ~step_index ~before ~after step;
  match I8080.Step.control_flow step with Return{taken=true;target=Some pc}when pc=resume&&before.sp=sp&&after.sp=sp+2->
  let b=Buffer.create 4096 in E.write_json ~output:(Buffer.add_string b)ew;write(Filename.concat !output(Printf.sprintf"%s-%d-witnesses.json"name !count))(Buffer.contents b);active:=None|_->())in
 let result=match Pli80.Experiment.run ~on_before_instruction ~on_guest_step ~analysis:Pli80.Experiment.Execution input with Ok q->q|Error _->failwith"capture execution"in
 if !active<>None then failwith"unresolved root return";
 let counts=Hashtbl.fold(fun o n xs->Printf.sprintf"\"PLI2.OVL+%04X\":%d"o n::xs)global[]|>List.sort String.compare in
 let rel=Option.get result.rel_bytes in
 write(Filename.concat !output(name^"-capture-summary.json"))(Printf.sprintf"{\"source\":%S,\"roots\":%d,\"REL_sha256\":%S,\"guest_instructions\":%d,\"filesystem_sha256\":%S,\"global_calls\":{%s},\"prior_software_dispatch\":[%s]}"name !count(Pli80.Experiment.sha256_hex rel)result.run.steps(Pli80.Native_resident_output.filesystem_hash result.filesystem)(String.concat","counts)(String.concat","(List.rev !root_dispatches)));
 Printf.printf"%s roots %d\n%!"name !count
 ) ["MINIMAL";"FIZZBUZ";"PICTURE";"FACTOR";"OPTIMIST"]
