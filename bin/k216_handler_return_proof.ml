[@@@warning "-4-40-41-42"]
module E=Pli80.Experiment
module B=Pli80.Acquisition_family_bridge
module P=Pli80.K216_handler_return
let need b s=if not b then failwith("Pass91: "^s)
let read p=let c=open_in_bin p in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let snapshot st : Runner.state_snapshot=
 let module S=I8080.State in let module F=I8080.Flags in let f=S.flags st in
 {a=S.a st;b=S.b st;c=S.c st;d=S.d st;e=S.e st;h=S.h st;l=S.l st;sp=S.sp st;pc=S.pc st;sign=F.sign f;zero=F.zero f;auxiliary_carry=F.auxiliary_carry f;parity=F.parity f;carry=F.carry f}
let state_json (s:Runner.state_snapshot)=
 let psw=2 lor(if s.sign then 128 else 0)lor(if s.zero then 64 else 0)lor(if s.auxiliary_carry then 16 else 0)lor(if s.parity then 4 else 0)lor(if s.carry then 1 else 0)in
 Printf.sprintf "[%d,%d,%d,%d,%d,%d,%d]" s.pc s.sp s.a(s.b*256+s.c)(s.d*256+s.e)(s.h*256+s.l)psw
let arithmetic_synthetic images=
 let module M=I8080.Memory in let module S=I8080.State in
 let image=read(Filename.concat images "PLI2.OVL")in let count=ref 0 in
 List.iter(fun value->List.iter(fun psw->
  let memory=M.create()in M.load memory ~address:0x2200 image;M.write memory 0xad0a value;
  M.write memory 0xff00 0;M.write memory 0xff01 1;
  let state=S.create()in S.set_pc state 0x8a21;S.set_sp state 0xff00;S.set_a state 0x77;
  S.set_bc state 0x1234;S.set_de state 0x5678;S.set_hl state 0x9876;
  I8080.Flags.restore_from_psw_byte(S.flags state)psw;
  let before=snapshot state in let host=Pli80_host.State.of_bytes(M.read_range memory ~address:0 ~length:65536)in
  let reads=ref[]in let expected=P.scale host ~entry:(Pli80.Acquisition_parent_bridge.logical before)~observe_read:(fun s a v->reads:=(s,a,v)::!reads)in
  let input=M.read_range memory ~address:0 ~length:65536 in let cpu=I8080.Cpu.create ~state ~bus:(I8080.Bus.create memory)in
  let cpu_reads=ref[]in
  for _=1 to 6 do let pc=S.pc state in(match I8080.Cpu.step cpu with Ok step->List.iter(function I8080.Step.Read x when pc<>0x8a2a->cpu_reads:=(pc,x.address,x.value)::!cpu_reads|_->())(I8080.Step.memory_accesses step)|_->failwith "scale CPU")done;
  need(snapshot state=Pli80.Acquisition_parent_bridge.machine before expected 0xff02 0x100)"ADD arithmetic/flags/RET";
  need(!reads= !cpu_reads)"fresh scale reads";need(input=M.read_range memory ~address:0 ~length:65536)"scale full RAM";incr count
 )[2;3;0xd6;0xd7])[0;1;3;4;31;51;52;63;64;127;128;255];!count
let ()=
 let images=ref""and output=ref""in Arg.parse["--images",Arg.Set_string images,"images";"--output",Arg.Set_string output,"proof JSON"]ignore"selector15 parent natural CPU/service shadows";
 let synthetic_count=arithmetic_synthetic !images in
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
    List.iter(function I8080.Step.Read w when List.mem before.Runner.pc[0x8a21;0x8a29;0x8a2a;0x8f59;0x8992;0x899d;0x899f]->reads:=(before.pc,w.address,w.value)::!reads|_->())(I8080.Step.memory_accesses step);
    List.iter(function I8080.Step.Write w->writes:=(w.address,w.value,before.pc)::!writes|_->())(I8080.Step.memory_accesses step)in
  let on_before_instruction ~origin:o ~step_index:_ (b:Runner.instruction_boundary)=
   origin:=o;
   (match !observed with Some sp when b.state.pc=0x42b4&&b.state.sp=sp+2->observed:=None|_->());
   (match !active with Some((entry:Runner.state_snapshot),site,p,preview,writes,steps)when b.state.pc=p.B.state.pc&&b.state.sp=p.state.sp->
    need(List.rev !reads=List.rev !host_reads)"direct owned read-site/value chronology";
    need(b.state=p.B.state)"registers flags PC/SP";need(b.copy_memory()=preview.Runner.memory)"full64KiB RAM";
    need(b.dma=preview.dma&&Cpm.Filesystem.equal(b.copy_filesystem())preview.filesystem)"DMA/filesystem";
    let cpu=List.rev !writes in
    need(List.map(fun(a,v,_)->a,v)cpu=List.map(fun(w:B.write)->w.address,w.value)p.journal)"complete ordered writes";
    List.iter2(fun(_,_,writer)(w:B.write)->need(w.writer=(-1)||w.writer=writer)"available last writers")cpu p.journal;
    need(List.rev !records=List.concat_map(fun(s:Runner.host_service)->s.events)preview.services)"service/record chronology";
    results:=Printf.sprintf"{\"source\":%S,\"selector\":%d,\"instructions\":%d,\"writes\":%d,\"services\":%d,\"entry_SP\":%d,\"exit_SP\":%d,\"PC\":%d,\"input_vector\":%s,\"output_vector\":%s,\"entry_RAM_sha256\":%S,\"post_RAM_sha256\":%S,\"direct_reads\":%d,\"full_state_RAM_ordered_writes_services\":true}"name(Char.code(Bytes.get(preview.Runner.memory)0xad0a)) !steps(List.length !writes)(List.length preview.services)entry.sp b.state.sp b.state.pc(state_json entry)(state_json b.state) !entry_hash(E.sha256_hex preview.memory)(List.length !reads)::!results;
    incr count;active:=None|_->());
   if o=B.origin"PLI2.OVL"0x6d4a||o=B.origin"PLI2.OVL"0x6792 then(
    let before,after,step=Option.get !previous in
    (* This pass intentionally owns only the +397F natural argument calls. *)
    if before.Runner.pc=0x8a20||before.pc=0x8f47 then(
     let is_front=before.pc=0x8f47 in
     let prepare=if is_front then P.front else P.prepare in
     need(after=b.state&&(if is_front then I8080.Step.control_flow step=I8080.Step.Call{target=0x8992;taken=true}else I8080.Step.control_flow step=I8080.Step.Return{target=Some 0x8f4a;taken=true}))"actual6792 CALL/RET";
     need(Hashtbl.find latest(b.state.sp+(if is_front then 2 else 0))=(0x42af,0xb4)&&Hashtbl.find latest(b.state.sp+(if is_front then 3 else 1))=(0x42af,0x42))"preserved software continuation";
     let ram=b.copy_memory()and files=b.copy_filesystem()and dma=b.dma in
     List.iter(fun(address,value)->
      let corrupt=Bytes.copy ram in Bytes.set corrupt address(Char.chr value);
      let view={b with Runner.copy_memory=(fun()->Bytes.copy corrupt);read_memory=(fun a->Char.code(Bytes.get corrupt a));
       preview_host_program=(fun p->b.preview_host_program{p with effects=Runner.Memory_write(address,value)::p.effects})}in
      let rejected=try ignore(prepare bridge view);false with Invalid_argument _->true in
      need rejected "negative code/continuation/selector/pointer";
      need(b.copy_memory()=ram)"negative mutation"
     )[b.state.pc,0;b.state.sp,0];
     entry_hash:=E.sha256_hex ram;
     reads:=[];host_reads:=[];
     let result=Some(prepare ~observe_read:(fun s a v->host_reads:=(s,a,v)::!host_reads) bridge b)in
     need(b.copy_memory()=ram&&b.dma=dma&&Cpm.Filesystem.equal(b.copy_filesystem())files)"staging mutated live state";
     match result with None->()|Some p->
     let preview=match b.preview_host_program p.program with Ok r->r|Error e->failwith e in
     records:=[];active:=Some(b.state,before.pc,p,preview,ref[],ref 0)))in
  let r=match E.run ~analysis:Execution ~on_before_instruction ~on_guest_step ~on_bdos_record inp with Ok q->q|_->failwith"concrete run"in
  need(!count=(if name="OPTIMIST"then 2 else 0)&& !active=None)"natural3DE4 proof count";
  goldens:=Printf.sprintf"{\"source\":%S,\"REL_sha256\":%S,\"INT_sha256\":%s}"name(E.sha256_hex(Option.get r.rel_bytes))(match r.int_bytes with None->"null"|Some b->Printf.sprintf"%S"(E.sha256_hex b))::!goldens;
  Printf.printf"%s dispatcher guest golden REL=%s\n%!"name(E.sha256_hex(Option.get r.rel_bytes))
 ) ["MINIMAL";"FIZZBUZ";"PICTURE";"FACTOR";"OPTIMIST"];
 let c=open_out !output in Fun.protect ~finally:(fun()->close_out c)(fun()->Printf.fprintf c"{\"cases\":[%s],\"goldens\":[%s],\"all_passed\":true,\"native_roots\":0,\"declined\":[%s],\"gateway_inventory\":[%s],\"synthetic_scale_cases\":%d}\n"(String.concat","(List.rev !results))(String.concat","(List.rev !goldens))(String.concat","(List.rev !declined))(String.concat","(List.rev !inventory))synthetic_count)
