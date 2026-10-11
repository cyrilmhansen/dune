[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path text=let c=open_out_bin path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_string c text)
module E=Analysis.Event_witness
let ()=
 let toolchain=ref""and output=ref""in Arg.parse["--toolchain",Arg.Set_string toolchain,"images";"--output-dir",Arg.Set_string output,"existing ignored output"]ignore"bounded concrete inventory";
 List.iter(fun name->
 let image n=read(Filename.concat !toolchain n)in
 let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read(let p="examples/pli80/"^name^".PLI"in if Sys.file_exists p then p else Filename.concat !toolchain(name^".PLI")));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
 let boundary=ref None in
 let origin_at ~pc ~fetched=
 let current,b=Option.get !boundary in
 let key,off=if pc=b.Runner.state.pc then (match current with Analysis.Execution_map.Image_byte q->Some q.image,q.offset|_->None,0)
 else if pc<0x2200 then Some{Cpm.Filesystem.drive=0;user=0;name="PLI.COM"},pc-0x100
 else (match current with Analysis.Execution_map.Image_byte q when q.image.name<>"PLI.COM"->Some q.image,pc-0x2200|_->None,0)in
 match key with None->None|Some key->
 let bytes=match key.name with "PLI.COM"->input.pli_com|"PLI0.OVL"->input.pli0_ovl|"PLI1.OVL"->input.pli1_ovl|"PLI2.OVL"->input.pli2_ovl|_->Bytes.empty in
 if off>=0&&off+Bytes.length fetched<=Bytes.length bytes&&Bytes.sub bytes off(Bytes.length fetched)=fetched then Some{E.image=key;offset=off}else None in
 let state (q:Runner.state_snapshot)=Printf.sprintf "{\"pc\":%d,\"sp\":%d,\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"sign\":%b,\"zero\":%b,\"auxiliary_carry\":%b,\"parity\":%b,\"carry\":%b}" q.pc q.sp q.a q.b q.c q.d q.e q.h q.l q.sign q.zero q.auxiliary_carry q.parity q.carry in
 let recent=ref [] and writers=Hashtbl.create 128 and frames=ref [] and pending=ref None in
 let root_sp=ref 0 and root_resume=ref 0 in
 let active=ref None and count=ref 0 and global=Hashtbl.create 128 in
 let callers=Hashtbl.create 128 in
 let on_before_instruction ~origin ~step_index:_ (b:Runner.instruction_boundary)=
 boundary:=Some(origin,b);
 if b.state.pc=0x5b7f && !active=None && (match origin with Analysis.Execution_map.Image_byte q->q.image.name="PLI2.OVL"|_->false) then (
 let sp=b.state.sp in
 root_sp:=sp;root_resume:=b.read_memory sp+256*b.read_memory(sp+1);
 let writer a=Option.value ~default:"null"(Hashtbl.find_opt writers a)in
 pending:=Some(Printf.sprintf "{\"entry\":%s,\"entry_RAM_sha256\":%S,\"entry_filesystem_sha256\":%S,\"entry_DMA\":%d,\"continuation\":%d,\"low_writer\":%s,\"high_writer\":%s,\"unmatched_hardware_call_observations\":[%s],\"prefix\":[%s]}" (state b.state)(Pli80.Experiment.sha256_hex(b.copy_memory()))(Pli80.Native_resident_output.filesystem_hash(b.copy_filesystem()))b.dma(b.read_memory sp+256*b.read_memory(sp+1))(writer sp)(writer(sp+1))(String.concat "," (List.rev_map snd !frames))(String.concat ","(List.rev !recent)));
 write(Filename.concat !output(Printf.sprintf"%s-%d-entry.ram"name (!count+1)))(b.copy_memory()|>Bytes.to_string)); in
 let on_guest_step ~step_index ~(before:Runner.state_snapshot) ~(after:Runner.state_snapshot) step=
 let is_pli2=match fst(Option.get !boundary)with Analysis.Execution_map.Image_byte q->q.image.name="PLI2.OVL"|_->false in

 (match I8080.Step.control_flow step with Call{target;taken=true}when is_pli2&&target>=0x2200->let o=target-0x2200 in Hashtbl.replace global o(1+Option.value ~default:0(Hashtbl.find_opt global o)); let key=Printf.sprintf"PLI2.OVL+%04X->PLI2.OVL+%04X"(before.pc-0x2200)o in Hashtbl.replace callers key(1+Option.value ~default:0(Hashtbl.find_opt callers key))|_->());
 let bytes=I8080.Step.fetched_bytes step in
 let hex=String.concat ""(List.init(Bytes.length bytes)(fun i->Printf.sprintf"%02X"(Char.code(Bytes.get bytes i))))in
 let origin=match fst(Option.get !boundary)with Analysis.Execution_map.Image_byte q->q.image.name|_->"unknown"in
 let accesses=String.concat","(List.map(function I8080.Step.Read{address;value}->Printf.sprintf"{\"kind\":\"read\",\"address\":%d,\"value\":%d}"address value|I8080.Step.Write{address;value}->Printf.sprintf"{\"kind\":\"write\",\"address\":%d,\"value\":%d}"address value)(I8080.Step.memory_accesses step))in
 let record=Printf.sprintf"{\"step\":%d,\"image\":%S,\"bytes\":%S,\"instruction\":%S,\"before\":%s,\"after\":%s,\"accesses\":[%s]}"step_index origin hex (I8080.Instr_format.format(I8080.Step.decoded step).instr)(state before)(state after)accesses in
 (match I8080.Step.control_flow step with
 |Call{taken=true;_}->frames:=(after.sp,record)::!frames
 |Return{taken=true;_}->frames:=List.filter(fun (sp,_)->sp<>before.sp)!frames
 |_->());
 List.iter(function I8080.Step.Write{address;value}when address>=0xf000->Hashtbl.replace writers address (Printf.sprintf"{\"value\":%d,\"instruction\":%s}"value record)|_->())(I8080.Step.memory_accesses step);
 (match !pending,!active with Some evidence,None when is_pli2->
 let ew=E.create ~run_id:(name^"-397F-"^string_of_int !count)~origin_at in active:=Some(ew,evidence);pending:=None;incr count|_->());
 (match !active with None->()|Some(ew,evidence)->E.observe_step ew ~step_index ~before ~after step;
 if before.sp= !root_sp && after.pc= !root_resume && (match I8080.Step.control_flow step with Return{taken=true;_}->true|_->false) then (
 let b=Buffer.create 4096 in E.write_json ~output:(Buffer.add_string b)ew;
 write(Filename.concat !output(Printf.sprintf"%s-%d-witnesses.json"name !count))(Buffer.contents b);
 write(Filename.concat !output(Printf.sprintf"%s-%d-entry.json"name !count))evidence;
 let _,view=Option.get !boundary in
 write(Filename.concat !output(Printf.sprintf"%s-%d-exit.json"name !count))(Printf.sprintf"{\"state\":%s,\"RAM_sha256\":%S,\"filesystem_sha256\":%S,\"DMA\":%d}"(state after)(Pli80.Experiment.sha256_hex(view.copy_memory()))(Pli80.Native_resident_output.filesystem_hash(view.copy_filesystem()))view.dma);active:=None));
 recent:=record::(let rec take n xs=if n=0 then []else match xs with []->[]|x::rest->x::take(n-1)rest in take 95 !recent) in
 let on_bdos_record ~step_index event=match !active with None->()|Some(ew,_)->E.observe_bdos_record ew ~step_index event in
 let result=match Pli80.Experiment.run ~on_bdos_record ~on_before_instruction ~on_guest_step ~analysis:Pli80.Experiment.Execution input with Ok q->q|Error _->failwith"capture execution"in
 if !active<>None then failwith"unresolved root return";
 let counts=Hashtbl.fold(fun o n xs->Printf.sprintf"\"PLI2.OVL+%04X\":%d"o n::xs)global[]|>List.sort String.compare in
 let rel=Option.get result.rel_bytes in
 let callsites=Hashtbl.fold(fun k n xs->Printf.sprintf"%S:%d"k n::xs)callers[]|>List.sort String.compare in
 write(Filename.concat !output(name^"-capture-summary.json"))(Printf.sprintf"{\"source\":%S,\"roots\":%d,\"REL_sha256\":%S,\"guest_instructions\":%d,\"filesystem_sha256\":%S,\"global_calls\":{%s},\"callsite_counts\":{%s}}"name !count(Pli80.Experiment.sha256_hex rel)result.run.steps(Pli80.Native_resident_output.filesystem_hash result.filesystem)(String.concat","counts)(String.concat","callsites));
 Printf.printf"%s roots %d\n%!"name !count
 ) ["MINIMAL";"FIZZBUZ";"PICTURE";"FACTOR";"OPTIMIST"]
