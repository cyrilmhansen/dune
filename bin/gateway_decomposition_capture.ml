[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path text=let c=open_out_bin path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_string c text)
let hex b=String.concat""(List.init(Bytes.length b)(fun i->Printf.sprintf"%02X"(Char.code(Bytes.get b i))))
let state(q:Runner.state_snapshot)=Printf.sprintf"{\"pc\":%d,\"sp\":%d,\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"S\":%b,\"Z\":%b,\"AC\":%b,\"P\":%b,\"CY\":%b}"q.pc q.sp q.a q.b q.c q.d q.e q.h q.l q.sign q.zero q.auxiliary_carry q.parity q.carry
let ()=
 let images=ref""and output=ref""in Arg.parse["--images",Arg.Set_string images,"images";"--output",Arg.Set_string output,"existing directory"]ignore"gateway-only observational capture; no shared schema changes";
 List.iter(fun name->
 let image n=read(Filename.concat !images n)in
 let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read(let p="examples/pli80/"^name^".PLI"in if Sys.file_exists p then p else Filename.concat !images(name^".PLI")));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
 let channel=open_out(Filename.concat !output(name^"-steps.jsonl"))in
 let boundary=ref None and frames=ref []and count=ref 0 and entries=ref []and exits=ref []and previous=ref"null"in
 let origin_name=function Analysis.Execution_map.Image_byte q->q.image.name|_->"unknown"in
 let on_before_instruction ~origin ~step_index(b:Runner.instruction_boundary)=
 boundary:=Some(origin,b);
 if origin_name origin="PLI2.OVL" && b.state.pc=0x41b5 then(
 incr count;let sp=b.state.sp in let resume=b.read_memory sp+256*b.read_memory(sp+1)in
 let saved=String.concat","(List.init 11(fun i->string_of_int(b.read_memory(0xad0a+i))))in
 let id= !count and parent=match !frames with []->0|(id,_,_)::_->id in
 entries:=Printf.sprintf"{\"id\":%d,\"parent\":%d,\"step\":%d,\"entry\":%s,\"continuation\":%d,\"saved_state\":[%s],\"CALL\":%s,\"RAM_sha256\":%S,\"filesystem_sha256\":%S,\"DMA\":%d}"id parent step_index(state b.state)resume saved !previous(Pli80.Experiment.sha256_hex(b.copy_memory()))(Pli80.Native_resident_output.filesystem_hash(b.copy_filesystem()))b.dma::!entries;
 if id=1 then write(Filename.concat !output(name^"-seed.ram"))(Bytes.to_string(b.copy_memory()));
 frames:=(id,sp,resume)::!frames)in
 let on_guest_step ~step_index ~(before:Runner.state_snapshot) ~(after:Runner.state_snapshot) step=
 let origin,b=Option.get !boundary in let image=origin_name origin in let off=match origin with Analysis.Execution_map.Image_byte q->q.offset|_-> -1 in
 let flow=I8080.Step.control_flow step in
 let kind,taken,target=match flow with Sequential->"sequential",true,after.pc|Call{target;taken}->"call",taken,target|Return{taken;_}->"return",taken,after.pc|Jump{target;taken;_}->"jump",taken,target|_->"other",true,after.pc in
 let accesses=String.concat","(List.map(function I8080.Step.Read{address;value}->Printf.sprintf"{\"kind\":\"read\",\"address\":%d,\"value\":%d}"address value|Write{address;value}->Printf.sprintf"{\"kind\":\"write\",\"address\":%d,\"value\":%d}"address value)(I8080.Step.memory_accesses step))in
 let id=match !frames with []->0|(id,_,_)::_->id in
 let record=Printf.sprintf"{\"id\":%d,\"step\":%d,\"image\":%S,\"offset\":%d,\"bytes\":%S,\"decoded\":%S,\"before\":%s,\"after\":%s,\"kind\":%S,\"taken\":%b,\"target\":%d,\"accesses\":[%s]}"id step_index image off(hex(I8080.Step.fetched_bytes step))(I8080.Instr_format.format(I8080.Step.decoded step).instr)(state before)(state after)kind taken target accesses in
 let own=image="PLI2.OVL"&&off>=0x1fb5&&off<0x20eb in
 let predicate=image="PLI2.OVL"&&off>=0x1dff&&off<0x1fb5 in
 let writes=List.exists(function I8080.Step.Write _->true|_->false)(I8080.Step.memory_accesses step)in
 if id<>0&&(own||predicate||writes||kind<>"sequential")then output_string channel(record^"\n");
 previous:=record;
 match !frames with (id,sp,resume)::rest when kind="return"&&taken&&before.sp=sp&&after.pc=resume->
 exits:=Printf.sprintf"{\"id\":%d,\"step\":%d,\"exit\":%s,\"RAM_sha256\":%S,\"filesystem_sha256\":%S,\"DMA\":%d}"id step_index(state after)(Pli80.Experiment.sha256_hex(b.copy_memory()))(Pli80.Native_resident_output.filesystem_hash(b.copy_filesystem()))b.dma::!exits;frames:=rest
 |_->()in
 let result=match Pli80.Experiment.run ~on_before_instruction ~on_guest_step ~analysis:Pli80.Experiment.Execution input with Ok q->q|Error _->failwith"capture"in close_out channel;if !frames<>[]then failwith"unreturned gateway";
 write(Filename.concat !output(name^"-summary.json"))(Printf.sprintf"{\"source\":%S,\"count\":%d,\"entries\":[%s],\"exits\":[%s],\"REL_sha256\":%S,\"filesystem_sha256\":%S}"name !count(String.concat","(List.rev !entries))(String.concat","(List.rev !exits))(Pli80.Experiment.sha256_hex(Option.get result.rel_bytes))(Pli80.Native_resident_output.filesystem_hash result.filesystem));
 Printf.printf"%s gateway calls=%d\n%!"name !count
 )["MINIMAL";"FIZZBUZ";"PICTURE";"FACTOR";"OPTIMIST"]
