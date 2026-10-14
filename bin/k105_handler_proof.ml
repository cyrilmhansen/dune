[@@@warning "-4-40-41-42"]
module E=Pli80.Experiment
module B=Pli80.Acquisition_family_bridge
module P=Pli80.K105_handler
let need b s=if not b then failwith("Pass96: "^s)
let read p=let c=open_in_bin p in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let snapshot st : Runner.state_snapshot=
 let module S=I8080.State in let module F=I8080.Flags in let f=S.flags st in
 {a=S.a st;b=S.b st;c=S.c st;d=S.d st;e=S.e st;h=S.h st;l=S.l st;sp=S.sp st;pc=S.pc st;sign=F.sign f;zero=F.zero f;auxiliary_carry=F.auxiliary_carry f;parity=F.parity f;carry=F.carry f}
let state_json (s:Runner.state_snapshot)=
 let psw=2 lor(if s.sign then 128 else 0)lor(if s.zero then 64 else 0)lor(if s.auxiliary_carry then 16 else 0)lor(if s.parity then 4 else 0)lor(if s.carry then 1 else 0)in
 Printf.sprintf "[%d,%d,%d,%d,%d,%d,%d]" s.pc s.sp s.a(s.b*256+s.c)(s.d*256+s.e)(s.h*256+s.l)psw
let carrier_synthetic images=
 let module M=I8080.Memory in let module T=I8080.State in
 let image=read(Filename.concat images "PLI2.OVL")in
 List.iter(fun bc->List.iter(fun psw->List.iter(fun sp->
  let m=M.create()in M.load m ~address:0x2200 image;
  M.write m sp 0;M.write m(sp+1)1;M.write m 0xadf1(bc land 255);M.write m 0xadf2(bc lsr 8);
  let t=T.create()in T.set_pc t 0x99bf;T.set_sp t sp;T.set_bc t bc;T.set_a t 0x71;T.set_de t 0x1234;T.set_hl t 0x4321;
  I8080.Flags.restore_from_psw_byte(T.flags t)psw;
  let input=snapshot t in let host=Pli80_host.State.of_bytes(M.read_range m ~address:0 ~length:65536)in
  let writes=ref[]and reads=ref[]in
  let q=P.carrier host ~entry:(Pli80.Acquisition_parent_bridge.logical input)
   ~observe_read:(fun site address value->reads:=(site,address,value)::!reads)
   ~write:(fun _ address value->Pli80_host.State.write host address value;writes:=(address,value)::!writes)in
  let cpu=I8080.Cpu.create ~state:t ~bus:(I8080.Bus.create m)in let cpu_writes=ref[]and cpu_reads=ref[]in
  for _=1 to 7 do let pc=T.pc t in match I8080.Cpu.step cpu with Error _->failwith"carrier CPU"|Ok step->
   List.iter(function I8080.Step.Write w->cpu_writes:=(w.address,w.value)::!cpu_writes
    |I8080.Step.Read r when pc<>0x99cb->cpu_reads:=(pc,r.address,r.value)::!cpu_reads|_->())(I8080.Step.memory_accesses step)done;
  need(snapshot t=Pli80.Acquisition_parent_bridge.machine input q(sp+2)0x100)"carrier inherited flags/registers/RET";
  need(M.read_range m ~address:0 ~length:65536=Pli80_host.State.copy host&& !writes= !cpu_writes&& !reads= !cpu_reads)"carrier fresh pair/same-valued writes/fullRAM"
 )[0xb240;0xfff0])[2;0xd7])[0;1;0x80ff;0xffff];16
let ()=
 let images=ref""and output=ref""in Arg.parse["--images",Arg.Set_string images,"images";"--output",Arg.Set_string output,"proof JSON"]ignore"selector15 parent natural CPU/service shadows";
 let synthetic_count=carrier_synthetic !images in
 let declined=ref[] and inventory=ref[]in
 let results=ref[]and goldens=ref[]and reads=ref[]and host_reads=ref[]in
 List.iter(fun name->
  let image n=read(Filename.concat !images n)in
  let inp:E.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=E.prepare_source ~normalize:true(read(let p="examples/pli80/"^name^".PLI"in if Sys.file_exists p then p else Filename.concat !images(name^".PLI")));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  let bridge=B.create_with_images ~pli_com:inp.pli_com ~pli0:inp.pli0_ovl ~pli1:inp.pli1_ovl ~pli2:inp.pli2_ovl in
  let previous=ref None and origin=ref Analysis.Execution_map.Unknown and active=ref None and count=ref 0 and records=ref[]and observed=ref None and latest=Hashtbl.create 128 and entry_hash=ref""in
  let on_bdos_record ~step_index:_ ev=if !active<>None then records:=ev::!records in
  let on_guest_step ~step_index:_ ~before ~after step=
   previous:=Some(before,after,step);
   List.iter(function I8080.Step.Write w->Hashtbl.replace latest w.address(before.Runner.pc,w.value)|_->())(I8080.Step.memory_accesses step);
   match !active with None->()|Some(_,_,_,_,writes,steps)->
    incr steps;
    List.iter(function I8080.Step.Read w when List.mem before.Runner.pc[0x4552;0x455a;0x4471;0x43d1;0x43df;0x43b2;0x43c6;0x43c9;0x43cc;0x43ec;0x38fa;0x448f;0x4491;0x99c5;0x99cb;0x4499;0x44a0;0x44a1;0x4561;0x9f37;0x9f3f;0x9f0d;0x9f18;0x9f1f;0x9f28;0x9f30;0x9f46]->reads:=(before.pc,w.address,w.value)::!reads|_->())(I8080.Step.memory_accesses step);
    List.iter(function I8080.Step.Write w->writes:=(w.address,w.value,before.pc)::!writes|_->())(I8080.Step.memory_accesses step)in
  let on_before_instruction ~origin:o ~step_index:_ (b:Runner.instruction_boundary)=
   origin:=o;
   (match !observed with Some sp when b.state.pc=0x42b4&&b.state.sp=sp+2->observed:=None|_->());
   if !observed<>None&&b.state.pc=0x41b5 then(
    let before,after,step=Option.get !previous in
    let route=B.gateway_route bridge {Pli80.Native_dispatch.before;after;step;origin=B.origin"PLI2.OVL"(before.pc-0x2200)} ~origin:o b in
    inventory:=Printf.sprintf"{\"source\":%S,\"call_site\":%d,\"C\":%d,\"route\":%S}"name before.pc b.state.c(match route with B.K23->"k23"|K123->"k123"|Guest->"guest")::!inventory);
   (match !active with Some(entry,site,p,preview,writes,steps)when b.state.pc=0x42b4&&b.state.sp=entry.Runner.sp+2->
    let ret_before,_,ret_step=Option.get !previous in
    need(ret_before.Runner.pc=0x4561&&I8080.Step.control_flow ret_step=I8080.Step.Return{target=Some 0x42b4;taken=true})"actual software RET";
    need(List.rev !reads=List.rev !host_reads)"direct owned read-site/value chronology";
    need(b.state=p.B.state)"registers flags PC/SP";need(b.copy_memory()=preview.Runner.memory)"full64KiB RAM";
    need(b.dma=preview.dma&&Cpm.Filesystem.equal(b.copy_filesystem())preview.filesystem)"DMA/filesystem";
    let cpu=List.rev !writes in
    need(List.map(fun(a,v,_)->a,v)cpu=List.map(fun(w:B.write)->w.address,w.value)p.journal)"complete ordered writes";
    List.iter2(fun(_,_,writer)(w:B.write)->need(w.writer=(-1)||w.writer=writer)"available last writers")cpu p.journal;
    need(List.rev !records=List.concat_map(fun(s:Runner.host_service)->s.events)preview.services)"service/record chronology";
    results:=Printf.sprintf"{\"source\":%S,\"selector\":%d,\"instructions\":%d,\"writes\":%d,\"services\":%d,\"entry_SP\":%d,\"exit_SP\":%d,\"PC\":%d,\"input_vector\":%s,\"output_vector\":%s,\"entry_RAM_sha256\":%S,\"post_RAM_sha256\":%S,\"direct_reads\":%d,\"full_state_RAM_ordered_writes_services\":true}"name(Char.code(Bytes.get(preview.Runner.memory)0xad0a)) !steps(List.length !writes)(List.length preview.services)entry.sp b.state.sp b.state.pc(state_json entry)(state_json b.state) !entry_hash(E.sha256_hex preview.memory)(List.length !reads)::!results;
    incr count;active:=None|_->());
   if o=B.origin"PLI2.OVL"0x2352 then(
    let before,after,step=Option.get !previous in
    (* Software ownership is established by the actual PUSH/PCHL writers. *)
    if before.Runner.pc=0x42b3 then(
     need(after=b.state&&I8080.Step.control_flow step=I8080.Step.Jump{target=0x4552;taken=true})"actual PCHL";
     need(before.sp=b.state.sp&&before.h*256+before.l=0x4552)"PCHL retains software stack";
     observed:=Some b.state.sp;
     need(Hashtbl.find latest b.state.sp=(0x42af,0xb4)&&Hashtbl.find latest(b.state.sp+1)=(0x42af,0x42))"actual PUSH42B4 last writers";
     let ram=b.copy_memory()and files=b.copy_filesystem()and dma=b.dma in
     List.iter(fun edits->
      let corrupt=Bytes.copy ram in List.iter(fun(address,value)->Bytes.set corrupt address(Char.chr value))edits;
      let view={b with Runner.copy_memory=(fun()->Bytes.copy corrupt);read_memory=(fun a->Char.code(Bytes.get corrupt a));
       preview_host_program=(fun p->b.preview_host_program{p with effects=List.map(fun(address,value)->Runner.Memory_write(address,value))edits@p.effects})}in
      let rejected=try ignore(P.prepare bridge view);false with Invalid_argument _->true in
      need rejected "negative code/continuation/selector/pointer";
      need(b.copy_memory()=ram)"negative mutation"
     )[[0x4552,0];[b.state.sp,0];[0x38f8,0];[0xad0d,101];[0x2155,0xf1;0x2156,0xad]];
     entry_hash:=E.sha256_hex ram;
     reads:=[];host_reads:=[];
     let result=Some(P.prepare ~observe_read:(fun s a v->host_reads:=(s,a,v)::!host_reads) bridge b)in
     need(b.copy_memory()=ram&&b.dma=dma&&Cpm.Filesystem.equal(b.copy_filesystem())files)"staging mutated live state";
     match result with None->()|Some p->
     let preview=match b.preview_host_program p.program with Ok r->r|Error e->failwith e in
     records:=[];active:=Some(b.state,before.pc,p,preview,ref[],ref 0)))in
  let r=match E.run ~analysis:Execution ~on_before_instruction ~on_guest_step ~on_bdos_record inp with Ok q->q|_->failwith"concrete run"in
  need(!count=(if name="OPTIMIST"then 3 else 0)&& !active=None)"natural3DE4 proof count";
  goldens:=Printf.sprintf"{\"source\":%S,\"REL_sha256\":%S,\"INT_sha256\":%s}"name(E.sha256_hex(Option.get r.rel_bytes))(match r.int_bytes with None->"null"|Some b->Printf.sprintf"%S"(E.sha256_hex b))::!goldens;
  Printf.printf"%s dispatcher guest golden REL=%s\n%!"name(E.sha256_hex(Option.get r.rel_bytes))
 ) ["MINIMAL";"FIZZBUZ";"PICTURE";"FACTOR";"OPTIMIST"];
 let c=open_out !output in Fun.protect ~finally:(fun()->close_out c)(fun()->Printf.fprintf c"{\"cases\":[%s],\"goldens\":[%s],\"all_passed\":true,\"native_roots\":0,\"declined\":[%s],\"gateway_inventory\":[%s],\"synthetic_carrier_cases\":%d}\n"(String.concat","(List.rev !results))(String.concat","(List.rev !goldens))(String.concat","(List.rev !declined))(String.concat","(List.rev !inventory))synthetic_count)
