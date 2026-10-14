[@@@warning "-4-40-41-42"]
module E=Pli80.Experiment
module B=Pli80.Acquisition_family_bridge
module P=Pli80.Indexed_parent_397f
module Leaf=Pli80.Stack_argument_382e
let need b s=if not b then failwith("Pass89: "^s)
let read p=let c=open_in_bin p in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let snapshot st : Runner.state_snapshot=
 let module S=I8080.State in let module F=I8080.Flags in let f=S.flags st in
 {a=S.a st;b=S.b st;c=S.c st;d=S.d st;e=S.e st;h=S.h st;l=S.l st;sp=S.sp st;pc=S.pc st;sign=F.sign f;zero=F.zero f;auxiliary_carry=F.auxiliary_carry f;parity=F.parity f;carry=F.carry f}
let synthetic images =
 let module M=I8080.Memory in let module S=I8080.State in
 let image=read(Filename.concat images "PLI2.OVL")in
 let count=ref 0 in
 List.iter(fun value->List.iter(fun psw->
  let memory=M.create()in M.load memory ~address:0x2200 image;
  M.write memory 0xff00 0;M.write memory 0xff01 1;
  let state=S.create()in S.set_pc state 0xa586;S.set_sp state 0xff00;S.set_hl state value;
  S.set_a state 0x91;S.set_bc state 0x1234;S.set_de state 0x5678;
  I8080.Flags.restore_from_psw_byte(S.flags state)psw;
  let before=snapshot state in
  let expected=Leaf.negation(Pli80.Acquisition_parent_bridge.logical before)in
  let cpu=I8080.Cpu.create ~state ~bus:(I8080.Bus.create memory)in
  let input=M.read_range memory ~address:0 ~length:65536 in
  for _=1 to 7 do match I8080.Cpu.step cpu with Ok _->()|_->failwith "negation CPU"done;
  need(snapshot state=Pli80.Acquisition_parent_bridge.machine before expected 0xff02 0x100)"synthetic SUB/SBB flags/RET";
  need(input=M.read_range memory ~address:0 ~length:65536)"synthetic leaf RAM";incr count
 )[2;0x13;0x46;0xd7])[0;1;15;16;127;128;255;256;257;4095;4096;32767;32768;65280;65534;65535];
 !count
let predicate_synthetic images=
 let module M=I8080.Memory in let module S=I8080.State in
 let image=read(Filename.concat images "PLI2.OVL")in
 let count=ref 0 in
 List.iter(fun value->List.iter(fun psw->
  let memory=M.create()in M.load memory ~address:0x2200 image;
  M.write memory 0xff00 0;M.write memory 0xff01 1;
  let state=S.create()in S.set_pc state 0x5886;S.set_sp state 0xff00;S.set_a state value;
  S.set_bc state 0x1234;S.set_de state 0x5678;S.set_hl state 0x9876;
  I8080.Flags.restore_from_psw_byte(S.flags state)psw;
  let before=snapshot state in let expected=P.less_eight(Pli80.Acquisition_parent_bridge.logical before)in
  let cpu=I8080.Cpu.create ~state ~bus:(I8080.Bus.create memory)in
  let input=M.read_range memory ~address:0 ~length:65536 in
  for _=1 to 3 do match I8080.Cpu.step cpu with Ok _->()|_->failwith "predicate CPU"done;
  need(snapshot state=Pli80.Acquisition_parent_bridge.machine before expected 0xff02 0x100)"SUI8/SBB A flags";
  need(input=M.read_range memory ~address:0 ~length:65536)"predicate leaf RAM";incr count
 )[2;0x13;0x46;0xd7])[0;1;7;8;9;15;128;255];!count
let ()=
 let images=ref""and output=ref""in Arg.parse["--images",Arg.Set_string images,"images";"--output",Arg.Set_string output,"proof JSON"]ignore"selector15 parent natural CPU/service shadows";
 let synthetic_count=synthetic !images in let predicate_count=predicate_synthetic !images in
 let results=ref[]and goldens=ref[]and reads=ref[]and host_reads=ref[]in
 List.iter(fun name->
  let image n=read(Filename.concat !images n)in
  let inp:E.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=E.prepare_source ~normalize:true(read(let p="examples/pli80/"^name^".PLI"in if Sys.file_exists p then p else Filename.concat !images(name^".PLI")));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  let bridge=B.create_with_images ~pli_com:inp.pli_com ~pli0:inp.pli0_ovl ~pli1:inp.pli1_ovl ~pli2:inp.pli2_ovl in
  let previous=ref None and origin=ref Analysis.Execution_map.Unknown and active=ref None and count=ref 0 and records=ref[]in
  let on_bdos_record ~step_index:_ ev=if !active<>None then records:=ev::!records in
  let on_guest_step ~step_index:_ ~before ~after step=
   previous:=Some(before,after,step);
   match !active with None->()|Some(_,_,_,_,writes,steps)->
    incr steps;
    List.iter(function I8080.Step.Read w when List.mem before.Runner.pc[0x5b7f;0x5b8a;0x5b8c;0x593c;0x5875;0x587f;0x5889;0x5925;0x5946;0x5cd2;0x5d62;0x5d6b;0x5d6f]->reads:=(before.pc,w.address,w.value)::!reads|_->())(I8080.Step.memory_accesses step);
    List.iter(function I8080.Step.Write w->writes:=(w.address,w.value,before.pc)::!writes|_->())(I8080.Step.memory_accesses step)in
  let on_before_instruction ~origin:o ~step_index:_ (b:Runner.instruction_boundary)=
   origin:=o;
   if !active<>None&&b.state.pc=0x41b5 then(
    let before,after,step=Option.get !previous in
    if before.Runner.pc=0x5940 then need(B.gateway_route bridge {Pli80.Native_dispatch.before;after;step;origin=B.origin"PLI2.OVL"0x3740} ~origin:o b=B.K23)"actual nested gateway applicability");
   (match !active with Some(entry,site,p,preview,writes,steps)when b.state.pc=site+3&&b.state.sp=entry.Runner.sp+2->
    need(List.rev !reads=List.rev !host_reads)"direct owned read-site/value chronology";
    need(b.state=p.B.state)"registers flags PC/SP";need(b.copy_memory()=preview.Runner.memory)"full64KiB RAM";
    need(b.dma=preview.dma&&Cpm.Filesystem.equal(b.copy_filesystem())preview.filesystem)"DMA/filesystem";
    let expected=List.map(fun(w:B.write)->w.address,w.value,w.writer)p.journal in
    if List.rev !writes<>expected then(
     let rec show i xs ys=match xs,ys with x::xt,y::yt when x=y->show(i+1)xt yt|_->Printf.eprintf"write mismatch %s index%d lengths%d/%d\n"name i(List.length !writes)(List.length expected);List.iter(fun(a,v,w)->Printf.eprintf"CPU %04X %02X %04X\n"a v w)(List.filteri(fun j _->j<8)xs);List.iter(fun(a,v,w)->Printf.eprintf"HOST %04X %02X %04X\n"a v w)(List.filteri(fun j _->j<8)ys)in show 0(List.rev !writes)expected);
    need(List.rev !writes=expected)"all ordered writes/last writer";
    need(List.rev !records=List.concat_map(fun(s:Runner.host_service)->s.events)preview.services)"service/record chronology";
    results:=Printf.sprintf"{\"source\":%S,\"instructions\":%d,\"writes\":%d,\"services\":%d,\"entry_SP\":%d,\"exit_SP\":%d,\"PC\":%d,\"full_state_RAM_ordered_writes_services\":true}"name !steps(List.length !writes)(List.length preview.services)entry.sp b.state.sp b.state.pc::!results;
    incr count;active:=None|_->());
   if o=B.origin"PLI2.OVL"0x397f then(
    let before,after,step=Option.get !previous in
    (* This pass intentionally owns only the +397F natural argument calls. *)
    if before.Runner.pc=0x6457 then(
     need(after=b.state&&I8080.Step.control_flow step=I8080.Step.Call{target=0x5b7f;taken=true})"actual CALL";
     let ram=b.copy_memory()and files=b.copy_filesystem()and dma=b.dma in
     reads:=[];host_reads:=[];
     List.iter(fun(address,value)->
      let corrupt=Bytes.copy ram in Bytes.set corrupt address(Char.chr value);
      let view={b with Runner.copy_memory=(fun()->Bytes.copy corrupt);read_memory=(fun a->Char.code(Bytes.get corrupt a))}in
      let rejected=try ignore(P.prepare bridge ~call_site:before.pc view);false with Invalid_argument _->true in
      need rejected "negative code/selector guard";need(b.copy_memory()=ram)"negative guard live mutation"
     )[0xad0a,14;0x5b7f,0];
     let p=P.prepare ~observe_read:(fun s a v->if s<>0xa58d then host_reads:=(s,a,v)::!host_reads) bridge ~call_site:before.pc b in
     need(b.copy_memory()=ram&&b.dma=dma&&Cpm.Filesystem.equal(b.copy_filesystem())files)"staging mutated live state";
     let preview=match b.preview_host_program p.program with Ok r->r|Error e->failwith e in
     records:=[];active:=Some(b.state,before.pc,p,preview,ref[],ref 0)))in
  let r=match E.run ~analysis:Execution ~on_before_instruction ~on_guest_step ~on_bdos_record inp with Ok q->q|_->failwith"concrete run"in
  need(!count=(if List.mem name["FIZZBUZ";"OPTIMIST"]then 1 else 0)&& !active=None)"natural397F proof count";
  goldens:=Printf.sprintf"{\"source\":%S,\"REL_sha256\":%S}"name(E.sha256_hex(Option.get r.rel_bytes))::!goldens;
  Printf.printf"%s 397F proved REL=%s\n%!"name(E.sha256_hex(Option.get r.rel_bytes))
 ) ["MINIMAL";"FIZZBUZ";"PICTURE";"FACTOR";"OPTIMIST"];
 let c=open_out !output in Fun.protect ~finally:(fun()->close_out c)(fun()->Printf.fprintf c"{\"cases\":[%s],\"goldens\":[%s],\"all_passed\":true,\"native_roots\":0,\"synthetic_negation_cases\":%d,\"synthetic_predicate_cases\":%d}\n"(String.concat","(List.rev !results))(String.concat","(List.rev !goldens))synthetic_count predicate_count)
