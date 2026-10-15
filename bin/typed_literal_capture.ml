[@@@warning "-4-40-41-42"]
module E=Pli80.Experiment
let read p=let c=open_in_bin p in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let hex b=String.concat""(List.init(Bytes.length b)(fun i->Printf.sprintf"%02x"(Char.code(Bytes.get b i))))
let state(q:Runner.state_snapshot)=Printf.sprintf"{\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"pc\":%d,\"sp\":%d,\"flags\":{\"sign\":%b,\"zero\":%b,\"auxiliary_carry\":%b,\"parity\":%b,\"carry\":%b}}"q.a q.b q.c q.d q.e q.h q.l q.pc q.sp q.sign q.zero q.auxiliary_carry q.parity q.carry
let replay ?(record_reads=false) ?(stack_delta=10) ~out ~path (q:Runner.state_snapshot) ram =
 let module S=I8080.State in let module F=I8080.Flags in
 let memory=I8080.Memory.create()in I8080.Memory.load memory ~address:0 ram;
 let st=S.create()in
 List.iter(fun(fn,v)->fn st v)[S.set_a,q.a;S.set_b,q.b;S.set_c,q.c;S.set_d,q.d;S.set_e,q.e;S.set_h,q.h;S.set_l,q.l;S.set_pc,q.pc;S.set_sp,q.sp];
 let f=S.flags st in List.iter(fun(fn,v)->fn f v)[F.set_sign,q.sign;F.set_zero,q.zero;F.set_auxiliary_carry,q.auxiliary_carry;F.set_parity,q.parity;F.set_carry,q.carry];
 let ret=Char.code(Bytes.get ram q.sp)lor(Char.code(Bytes.get ram(q.sp+1))lsl 8)in
 let cpu=I8080.Cpu.create ~state:st ~bus:(I8080.Bus.create memory)in
 let n=ref 0 and writes=ref[]and journal=ref[]in
 while S.pc st<>ret do
  if !n>5000 then failwith"Pass109 bounded E02 replay did not return";
  let step=match I8080.Cpu.step cpu with Ok q->q|_->failwith"Pass109 replay CPU error"in
  incr n;if record_reads then List.iter(fun access->journal:=access::!journal)(I8080.Step.memory_accesses step);List.iter(function I8080.Step.Write w->writes:=(w.address,w.value)::!writes|_->())(I8080.Step.memory_accesses step)
 done;
 if S.sp st<>q.sp+stack_delta then failwith"actual replay continuation geometry";
 let after:Runner.state_snapshot={a=S.a st;b=S.b st;c=S.c st;d=S.d st;e=S.e st;h=S.h st;l=S.l st;pc=S.pc st;sp=S.sp st;sign=F.sign f;zero=F.zero f;auxiliary_carry=F.auxiliary_carry f;parity=F.parity f;carry=F.carry f}in
 let ram=I8080.Memory.read_range memory ~address:0 ~length:65536 in
 let c=open_out_bin(Filename.concat out(path^"-replay.ram"))in output_bytes c ram;close_out c;
 let c=open_out(Filename.concat out(path^"-replay.json"))in
 Printf.fprintf c"{\"state\":%s,\"instructions\":%d,\"writes\":[%s],\"RAM_sha256\":%S}\n"(state after) !n
  (String.concat","(List.map(fun(a,v)->Printf.sprintf"[%d,%d]"a v)(List.rev !writes)))(E.sha256_hex ram);close_out c;
 if record_reads then(let c=open_out(Filename.concat out(path^"-accesses.json"))in
 output_string c("["^String.concat","(List.map(function I8080.Step.Read w->Printf.sprintf"[\"R\",%d,%d]"w.address w.value|Write w->Printf.sprintf"[\"W\",%d,%d]"w.address w.value)(List.rev !journal))^"]\n");close_out c)
let ()=
 let images=ref""and out=ref""and declaration=ref false and mod_result=ref false in Arg.parse["--mod-result",Arg.Set mod_result,"capture MOD result and comparison windows";"--declaration",Arg.Set declaration,"capture declaration-to-expression instructions";"--images",Arg.Set_string images,"images";"--output",Arg.Set_string out,"isolated directory"]ignore"Read-only typed literal capture";
 let image n=read(Filename.concat !images n)in
 let source=E.prepare_source ~normalize:true(read"examples/pli80/FIZZBUZ.PLI")in
 let c=open_out(Filename.concat !out"events.jsonl")in
 let ramfile p b=let f=open_out_bin p in output_bytes f b;close_out f in
 let current=ref None and active=ref (if !declaration then 550000 else 0) and counter=ref 0 in
 let name=function Analysis.Execution_map.Image_byte q->q.image.name,q.offset|_->"",-1 in
 let on_before_instruction ~origin ~step_index(b:Runner.instruction_boundary)=
  let image,off=name origin in current:=Some(image,off,b);
  if image="PLI.COM"&&off=0x1376&&b.read_memory 0x20c1=0x31 then active:=max !active 8000;
  if (!mod_result&&image="PLI1.OVL"&&List.mem off[0x4f2a;0x53c3;0x345e;0x65aa])||(!declaration&&((image="PLI0.OVL"&&List.mem off[0x0ae4;0x142d])||(image="PLI1.OVL"&&List.mem off[0x30c1;0x330a])))||(image="PLI.COM"&&List.mem off[0x1376;0x154b])||(image="PLI1.OVL"&&List.mem off[0x6708;0x6726;0x6c4e;0x6c9f;0x2988;0x2b14;0x2c52])then(
   incr counter;let path=Printf.sprintf"checkpoint-%d.ram" !counter in
   ramfile(Filename.concat !out path)(b.copy_memory());
   if image="PLI1.OVL"&&off=0x6708&&b.state.e=2 then replay ~out:!out ~path b.state(b.copy_memory());
   if !declaration&&((image="PLI0.OVL"&&off=0x0ae4)||(image="PLI1.OVL"&&off=0x30c1))then replay ~record_reads:true ~stack_delta:2 ~out:!out ~path b.state(b.copy_memory());
   if !mod_result&&image="PLI1.OVL"&&List.mem off[0x4f2a;0x345e]then replay ~record_reads:true ~stack_delta:2 ~out:!out ~path b.state(b.copy_memory());
   Printf.fprintf c"{\"kind\":\"checkpoint\",\"step\":%d,\"image\":%S,\"offset\":%d,\"state\":%s,\"ram\":%S,\"RAM_sha256\":%S}\n"step_index image off(state b.state)path(E.sha256_hex(b.copy_memory())))in
 let on_guest_step ~step_index ~before ~after step=
  let image,off,_=Option.get !current in
  let accesses=I8080.Step.memory_accesses step in
  let interesting a=(a>=0x1e8e&&a<=0x1f0d)||(a>=0x20c1&&a<=0x20c9)||a=0x1c58||(a>=0xa9da&&a<=0xa9e3)||(a>=0xa947&&a<=0xa949)||(a>=0xa628&&a<=0xa646)||a=0xa863||a=0xa864||(a>=0xfba8&&a<=0xfbb3)||(a>=0xfbfe&&a<0xfd7e) in
  let flow=I8080.Step.control_flow step in
  if List.exists(function I8080.Step.Read q->q.address>=0xfbfe&&q.address<0xfd7e|_->false)accesses then active:=max !active 128;
  if List.exists(function I8080.Step.Read q->q.address>=0x1e8e&&q.address<=0x1f0d|_->false)accesses then active:=max !active 64;
  if !active>0||List.exists(function I8080.Step.Read q->interesting q.address|Write q->interesting q.address)accesses||
    (image="PLI1.OVL"&&List.mem off[0x6708;0x671f;0x6726;0x6c4b;0x6c9c;0x2985;0x2af4;0x2b11;0x2b13;0x2b8e;0x2b90])then(
   let ac=String.concat","(List.map(function I8080.Step.Read q->Printf.sprintf"[\"R\",%d,%d]"q.address q.value|Write q->Printf.sprintf"[\"W\",%d,%d]"q.address q.value)accesses)in
   Printf.fprintf c"{\"kind\":\"step\",\"step\":%d,\"image\":%S,\"offset\":%d,\"before\":%s,\"after\":%s,\"instruction\":%S,\"bytes\":%S,\"accesses\":[%s],\"call_or_ret\":%b}\n"step_index image off(state before)(state after)(I8080.Instr_format.format(I8080.Step.decoded step).instr)(hex(I8080.Step.fetched_bytes step))ac(match flow with Call _|Return _->true|_->false));
  if !active>0 then decr active in
 let on_bdos_record ~step_index event=match event with
 |Cpm.Bdos.Read_record q->Printf.fprintf c"{\"kind\":\"record_read\",\"file\":%S,\"step\":%d,\"record\":%d,\"dma\":%d,\"data\":%S}\n"q.file.name step_index q.logical_record q.dma(hex q.data)
 |_->()in
 let input:E.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name="FIZZBUZ.PLI";source_bytes=source;module_name="FIZZBUZ";command_tail=Bytes.of_string" FIZZBUZ";max_steps=10_000_000}in
 let result=match E.run ~analysis:Execution ~on_before_instruction ~on_guest_step ~on_bdos_record input with Ok q->q|_->failwith"capture"in
 close_out c;
 let f=open_out(Filename.concat !out"identity.json")in Printf.fprintf f"{\"source_sha256\":%S,\"REL_sha256\":%S,\"checkpoints\":%d,\"PLI_COM_SHA256\":%S,\"PLI1_SHA256\":%S}\n"(E.sha256_hex source)(E.sha256_hex(Option.get result.rel_bytes)) !counter(E.sha256_hex(image"PLI.COM"))(E.sha256_hex(image"PLI1.OVL"));close_out f;
 ramfile(Filename.concat !out"source.bin")source
