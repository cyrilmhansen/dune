[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let write path b=let c=open_out_bin path in Fun.protect ~finally:(fun()->close_out c)(fun()->output_bytes c b)
let state(q:Runner.state_snapshot)=Printf.sprintf"{\"pc\":%d,\"sp\":%d,\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"S\":%b,\"Z\":%b,\"AC\":%b,\"P\":%b,\"CY\":%b}"q.pc q.sp q.a q.b q.c q.d q.e q.h q.l q.sign q.zero q.auxiliary_carry q.parity q.carry
let hex b=String.concat""(List.init(Bytes.length b)(fun i->Printf.sprintf"%02X"(Char.code(Bytes.get b i))))
let ()=
 let images=ref""and output=ref""and name=ref"FACTOR"in
 Arg.parse["--source",Arg.Set_string name,"inventory source";"--images",Arg.Set_string images,"historical images";"--output",Arg.Set_string output,"ignored output directory"]ignore"Capture eligible k123 gateways and audit the five-source mixed scope";
 let image n=read(Filename.concat !images n)in
 let source=let p=("examples/pli80/"^ !name^".PLI")in read(if Sys.file_exists p then p else Filename.concat !images(!name^".PLI"))in
 let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name= !name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true source;module_name= !name;command_tail=Bytes.of_string(" "^ !name);max_steps=10_000_000}in
 let channel=open_out(Filename.concat !output"gateway-steps.jsonl")in
 let metadata=open_out(Filename.concat !output"gateway-boundaries.jsonl")in
 let previous : Pli80.Native_dispatch.previous option ref=ref None in
 let bridge=Pli80.Acquisition_family_bridge.create_with_images ~pli_com:input.pli_com ~pli0:input.pli0_ovl ~pli1:input.pli1_ovl ~pli2:input.pli2_ovl in
 let audit=open_out(Filename.concat !output "inventory.jsonl")in
 let boundary=ref None and active=ref 0 and count=ref 0 and service_events=ref 0 in
 let origin_name=function Analysis.Execution_map.Image_byte q->q.image.name|_->"unknown"in
 let on_before_instruction ~origin ~step_index(b:Runner.instruction_boundary)=
  boundary:=Some(origin,b);
  if origin_name origin="PLI2.OVL"&&b.state.pc=0x41b5 then(
   let q=b.state in
   let flags:Pli80_host.Recursive_mapped.flags={sign=q.sign;zero=q.zero;auxiliary_carry=q.auxiliary_carry;parity=q.parity;carry=q.carry}in
   let entry:Pli80_host.K123_child_7d05_front.state={pc=q.pc;sp=q.sp;a=q.a;bc=q.b*256+q.c;de=q.d*256+q.e;hl=q.h*256+q.l;flags}in
   let original=b.copy_memory() and files=b.copy_filesystem() and dma=b.dma in
   let ram=Pli80_host.State.of_bytes original in
   let k123=Pli80_host.K123_gateway_transaction.eligible ram ~pli2:input.pli2_ovl ~pli_com:input.pli_com ~call_site:(Option.get !previous).before.pc ~entry in
   let k23=Pli80.Acquisition_family_bridge.k23_applicability bridge (Option.get !previous) ~origin b=Pli80.Native_dispatch.Eligible in
   let call=Pli80.Acquisition_family_bridge.verify_call bridge (Pli2_output 0x1fb5) (Option.get !previous) ~entry:q in
   Printf.fprintf audit "{\"source\":%S,\"step\":%d,\"k23\":%b,\"k123\":%b,\"entry\":%s,\"RAM_sha256\":%S}\n%!" !name step_index k23 k123(state q)(Pli80.Experiment.sha256_hex(b.copy_memory()));
   ignore call;
   if b.copy_memory()<>original || b.dma<>dma || not(Cpm.Filesystem.equal files(b.copy_filesystem())) then failwith"scope mutated live state";
   if k123 then(
   if !active<>0 then failwith"nested k123 handler";
   incr count;active:= !count;service_events:=0;
   write(Filename.concat !output(Printf.sprintf"case-%d-entry.ram" !active))(b.copy_memory());
   Printf.fprintf metadata"{\"case\":%d,\"boundary\":\"entry\",\"step\":%d,\"state\":%s,\"RAM_sha256\":%S,\"filesystem_sha256\":%S,\"DMA\":%d,\"call_site\":%d}\n%!" !active step_index(state b.state)(Pli80.Experiment.sha256_hex(b.copy_memory()))(Pli80.Native_resident_output.filesystem_hash(b.copy_filesystem()))b.dma (Option.get !previous).before.pc));
  () in
 let on_guest_step ~step_index ~(before:Runner.state_snapshot) ~(after:Runner.state_snapshot) step=
  let origin,b=Option.get !boundary in let image=origin_name origin in let off=match origin with Analysis.Execution_map.Image_byte q->q.offset|_-> -1 in
  let flow=I8080.Step.control_flow step in
  let kind,taken,target=match flow with Sequential->"sequential",true,after.pc|Call{target;taken}->"call",taken,target|Return{taken;_}->"return",taken,after.pc|Jump{target;taken;_}->"jump",taken,target|_->"other",true,after.pc in
  let bytes=hex(I8080.Step.fetched_bytes step)in
  let accesses=String.concat","(List.map(function I8080.Step.Read{address;value}->Printf.sprintf"{\"kind\":\"read\",\"address\":%d,\"value\":%d}"address value|Write{address;value}->Printf.sprintf"{\"kind\":\"write\",\"address\":%d,\"value\":%d}"address value)(I8080.Step.memory_accesses step))in
  if !active<>0 then(
   Printf.fprintf channel"{\"case\":%d,\"step\":%d,\"image\":%S,\"offset\":%d,\"bytes\":%S,\"decoded\":%S,\"before\":%s,\"after\":%s,\"kind\":%S,\"taken\":%b,\"target\":%d,\"accesses\":[%s]}\n" !active step_index image off bytes(I8080.Instr_format.format(I8080.Step.decoded step).instr)(state before)(state after)kind taken target accesses;
   if image="PLI2.OVL"&&off=0x20ea then(
    if kind<>"return" then failwith"gateway hardware return changed";
    write(Filename.concat !output(Printf.sprintf"case-%d-exit.ram" !active))(b.copy_memory());
    Printf.fprintf metadata"{\"case\":%d,\"boundary\":\"exit\",\"step\":%d,\"state\":%s,\"RAM_sha256\":%S,\"filesystem_sha256\":%S,\"DMA\":%d,\"service_events\":%d}\n%!" !active step_index(state after)(Pli80.Experiment.sha256_hex(b.copy_memory()))(Pli80.Native_resident_output.filesystem_hash(b.copy_filesystem()))b.dma !service_events;
    active:=0));
  previous:=Some{Pli80.Native_dispatch.origin;before;after;step}in
 let on_bdos_record ~step_index:_ _=if !active<>0 then incr service_events in
 let result=match Pli80.Experiment.run ~analysis:Execution ~on_before_instruction ~on_guest_step ~on_bdos_record input with Ok q->q|Error _->failwith"FACTOR concrete capture"in
 close_out channel;close_out metadata;close_out audit;
 if !active<>0 then failwith"incomplete gateway capture";
 let rel=Option.get result.rel_bytes in
 write(Filename.concat !output(!name^".rel"))rel;
 Printf.printf"k123 gateway windows=%d REL=%s\n%!" !count(Pli80.Experiment.sha256_hex rel)
