[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path b=let c=open_out_bin path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_bytes c b)
let state(q:Runner.state_snapshot)=Printf.sprintf"{\"pc\":%d,\"sp\":%d,\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"S\":%b,\"Z\":%b,\"AC\":%b,\"P\":%b,\"CY\":%b}"q.pc q.sp q.a q.b q.c q.d q.e q.h q.l q.sign q.zero q.auxiliary_carry q.parity q.carry
let hex b=String.concat""(List.init(Bytes.length b)(fun i->Printf.sprintf"%02X"(Char.code(Bytes.get b i))))
let ()=
 let images=ref""and output=ref""in
 Arg.parse["--images",Arg.Set_string images,"historical images";"--output",Arg.Set_string output,"ignored output directory"]ignore"Capture only the two natural FACTOR k123 software-handler windows";
 let image n=read(Filename.concat !images n)in
 let source=let p="examples/pli80/FACTOR.PLI"in read(if Sys.file_exists p then p else Filename.concat !images"FACTOR.PLI")in
 let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name="FACTOR.PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true source;module_name="FACTOR";command_tail=Bytes.of_string" FACTOR";max_steps=10_000_000}in
 let channel=open_out(Filename.concat !output"handler-steps.jsonl")in
 let metadata=open_out(Filename.concat !output"handler-boundaries.jsonl")in
 let boundary=ref None and active=ref 0 and count=ref 0 and service_events=ref 0 and transfer=ref"null"in
 let origin_name=function Analysis.Execution_map.Image_byte q->q.image.name|_->"unknown"in
 let on_before_instruction ~origin ~step_index(b:Runner.instruction_boundary)=
  boundary:=Some(origin,b);
  if origin_name origin="PLI2.OVL"&&b.state.pc=0x476e then(
   if !active<>0 then failwith"nested k123 handler";
   incr count;active:= !count;service_events:=0;
   write(Filename.concat !output(Printf.sprintf"case-%d-entry.ram" !active))(b.copy_memory());
   Printf.fprintf metadata"{\"case\":%d,\"boundary\":\"entry\",\"step\":%d,\"state\":%s,\"RAM_sha256\":%S,\"filesystem_sha256\":%S,\"DMA\":%d,\"transfer\":%s}\n%!" !active step_index(state b.state)(Pli80.Experiment.sha256_hex(b.copy_memory()))(Pli80.Native_resident_output.filesystem_hash(b.copy_filesystem()))b.dma !transfer);
  if !active<>0&&origin_name origin="PLI2.OVL"&&b.state.pc=0x4778 then(
   write(Filename.concat !output(Printf.sprintf"case-%d-tail.ram" !active))(b.copy_memory());
   Printf.fprintf metadata"{\"case\":%d,\"boundary\":\"tail\",\"step\":%d,\"state\":%s,\"RAM_sha256\":%S,\"filesystem_sha256\":%S,\"DMA\":%d}\n%!" !active step_index(state b.state)(Pli80.Experiment.sha256_hex(b.copy_memory()))(Pli80.Native_resident_output.filesystem_hash(b.copy_filesystem()))b.dma)in
 let on_guest_step ~step_index ~(before:Runner.state_snapshot) ~(after:Runner.state_snapshot) step=
  let origin,b=Option.get !boundary in let image=origin_name origin in let off=match origin with Analysis.Execution_map.Image_byte q->q.offset|_-> -1 in
  let flow=I8080.Step.control_flow step in
  let kind,taken,target=match flow with Sequential->"sequential",true,after.pc|Call{target;taken}->"call",taken,target|Return{taken;_}->"return",taken,after.pc|Jump{target;taken;_}->"jump",taken,target|_->"other",true,after.pc in
  let bytes=hex(I8080.Step.fetched_bytes step)in
  let accesses=String.concat","(List.map(function I8080.Step.Read{address;value}->Printf.sprintf"{\"kind\":\"read\",\"address\":%d,\"value\":%d}"address value|Write{address;value}->Printf.sprintf"{\"kind\":\"write\",\"address\":%d,\"value\":%d}"address value)(I8080.Step.memory_accesses step))in
  if image="PLI2.OVL"&&off=0x20b3 then transfer:=Printf.sprintf"{\"step\":%d,\"image\":%S,\"offset\":%d,\"bytes\":%S,\"before\":%s,\"after\":%s}"step_index image off bytes(state before)(state after);
  if !active<>0 then(
   Printf.fprintf channel"{\"case\":%d,\"step\":%d,\"image\":%S,\"offset\":%d,\"bytes\":%S,\"decoded\":%S,\"before\":%s,\"after\":%s,\"kind\":%S,\"taken\":%b,\"target\":%d,\"accesses\":[%s]}\n" !active step_index image off bytes(I8080.Instr_format.format(I8080.Step.decoded step).instr)(state before)(state after)kind taken target accesses;
   if image="PLI2.OVL"&&off=0x259a then(
    if kind<>"return"||after.pc<>0x42b4 then failwith"k123 software return changed";
    write(Filename.concat !output(Printf.sprintf"case-%d-exit.ram" !active))(b.copy_memory());
    Printf.fprintf metadata"{\"case\":%d,\"boundary\":\"exit\",\"step\":%d,\"state\":%s,\"RAM_sha256\":%S,\"filesystem_sha256\":%S,\"DMA\":%d,\"service_events\":%d}\n%!" !active step_index(state after)(Pli80.Experiment.sha256_hex(b.copy_memory()))(Pli80.Native_resident_output.filesystem_hash(b.copy_filesystem()))b.dma !service_events;
    active:=0))in
 let on_bdos_record ~step_index:_ _=if !active<>0 then incr service_events in
 let result=match Pli80.Experiment.run ~analysis:Execution ~on_before_instruction ~on_guest_step ~on_bdos_record input with Ok q->q|Error _->failwith"FACTOR concrete capture"in
 close_out channel;close_out metadata;
 if !count<>2|| !active<>0 then failwith"expected two complete natural k123 handler windows";
 let rel=Option.get result.rel_bytes in
 write(Filename.concat !output"FACTOR.rel")rel;
 Printf.printf"FACTOR k123 handler windows=%d REL=%s\n%!" !count(Pli80.Experiment.sha256_hex rel)
