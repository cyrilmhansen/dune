[@@@warning "-4-40-41-42"]
module E=Pli80.Experiment
module B=Pli80.Acquisition_family_bridge
module P=Pli80.K216_selected_hierarchy
let need b s=if not b then failwith("Pass101: "^s)
let read p=let c=open_in_bin p in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let snapshot st : Runner.state_snapshot=
 let module S=I8080.State in let module F=I8080.Flags in let f=S.flags st in
 {a=S.a st;b=S.b st;c=S.c st;d=S.d st;e=S.e st;h=S.h st;l=S.l st;sp=S.sp st;pc=S.pc st;sign=F.sign f;zero=F.zero f;auxiliary_carry=F.auxiliary_carry f;parity=F.parity f;carry=F.carry f}
let state_json (s:Runner.state_snapshot)=
 let psw=2 lor(if s.sign then 128 else 0)lor(if s.zero then 64 else 0)lor(if s.auxiliary_carry then 16 else 0)lor(if s.parity then 4 else 0)lor(if s.carry then 1 else 0)in
 Printf.sprintf "[%d,%d,%d,%d,%d,%d,%d]" s.pc s.sp s.a(s.b*256+s.c)(s.d*256+s.e)(s.h*256+s.l)psw
let ()=
 let child=ref false and selected=ref false in
 let images=ref""and output=ref""in Arg.parse["--child",Arg.Set child,"667A child";"--selected",Arg.Set selected,"6792 selected";"--images",Arg.Set_string images,"images";"--output",Arg.Set_string output,"proof JSON"]ignore"selector15 parent natural CPU/service shadows";
 let synthetic_count=ref 0 in
 let declined=ref[] and inventory=ref[]in
 let results=ref[]and goldens=ref[]and reads=ref[]and host_reads=ref[]in
 List.iter(fun name->
  let image n=read(Filename.concat !images n)in
  let inp:E.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=E.prepare_source ~normalize:true(read(let p="examples/pli80/"^name^".PLI"in if Sys.file_exists p then p else Filename.concat !images(name^".PLI")));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  let bridge=B.create_with_images ~pli_com:inp.pli_com ~pli0:inp.pli0_ovl ~pli1:inp.pli1_ovl ~pli2:inp.pli2_ovl in
  let delegated=ref None in
  let previous=ref None and origin=ref Analysis.Execution_map.Unknown and active=ref None and count=ref 0 and records=ref[]and observed=ref None and latest=Hashtbl.create 128 and entry_hash=ref""in
  let on_bdos_record ~step_index:_ ev=if !active<>None then records:=ev::!records in
  let on_guest_step ~step_index:_ ~before ~after step=
   previous:=Some(before,after,step);
   List.iter(function I8080.Step.Write w->Hashtbl.replace latest w.address(before.Runner.pc,w.value)|_->())(I8080.Step.memory_accesses step);
   match !active with None->()|Some(_,_,_,_,writes,steps)->
    incr steps;
    List.iter(function I8080.Step.Read w when !delegated=None&&((before.Runner.pc>=0x3fff&&before.pc<=0x42ea)||List.mem before.pc[0x8926;0x892a;0x8884;0x8890;0x43b2;0x43c6;0x43c9;0x43cc;0x8898;0x889e;0x889f;0x8931;0x8992;0x899d;0x899f;0x8a20])->reads:=(before.pc,w.address,w.value)::!reads|_->())(I8080.Step.memory_accesses step);
    List.iter(function I8080.Step.Write w->writes:=(w.address,w.value,before.pc)::!writes|_->())(I8080.Step.memory_accesses step)in
  let on_before_instruction ~origin:o ~step_index:_ (b:Runner.instruction_boundary)=
   origin:=o;
   if !active<>None then(
    if b.state.pc=0x44ea then delegated:=Some b.state.sp;
    match !delegated with Some sp when b.state.pc=0x42b4&&b.state.sp=sp+2->delegated:=None|_->());
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
   let target=if !selected then 0x6792 else if !child then 0x667a else 0x6726 in
   if o=B.origin"PLI2.OVL"target then(
    let before,after,step=Option.get !previous in
    let word a=b.read_memory a lor(b.read_memory(a+1)lsl 8)in
    if !child&&(word b.state.sp<>0x8931||word(b.state.sp+2)<>0x89e1||word(b.state.sp+4)<>0x8f4a||word(b.state.sp+6)<>0x42b4)then(
     let ram=b.copy_memory()in
     let rejected=try ignore(P.prepare ~child:true bridge b);false with Invalid_argument text->List.mem text["k216 nested front: hardware/software ancestry";"k216 nested front: 667A hardware continuation"]in
     need(rejected&&b.copy_memory()=ram)"other667A ancestry remains excluded";
     declined:=Printf.sprintf"{\"source\":%S,\"SP\":%d,\"reason\":\"outside selected k216 hardware ancestry\"}"name b.state.sp::!declined
    )else if before.Runner.pc=(if !selected then 0x8f47 else if !child then 0x892e else 0x89de) then(
     let prepare=if !selected then P.selected else P.prepare ~child:!child in
     need(after=b.state&&I8080.Step.control_flow step=I8080.Step.Call{target=b.state.pc;taken=true})"actual hardware CALL ancestry";
     let ram=b.copy_memory()and files=b.copy_filesystem()and dma=b.dma in
     List.iter(fun(address,value)->
      let corrupt=Bytes.copy ram in Bytes.set corrupt address(Char.chr value);
      let view={b with Runner.copy_memory=(fun()->Bytes.copy corrupt);read_memory=(fun a->Char.code(Bytes.get corrupt a));
       preview_host_program=(fun p->b.preview_host_program{p with effects=Runner.Memory_write(address,value)::p.effects})}in
      let rejected=try ignore(prepare bridge view);false with Invalid_argument _->true in
      need rejected "negative code/continuation/selector/pointer";
      need(b.copy_memory()=ram)"negative mutation"
     )[b.state.pc,0];
     entry_hash:=E.sha256_hex ram;
     reads:=[];host_reads:=[];
     let result=Some((if !selected then P.selected else P.prepare ~child:!child) ~observe_read:(fun s a v->host_reads:=(s,a,v)::!host_reads) bridge b)in
     need(b.copy_memory()=ram&&b.dma=dma&&Cpm.Filesystem.equal(b.copy_filesystem())files)"staging mutated live state";
     match result with None->()|Some p->
     let preview=match b.preview_host_program p.program with Ok r->r|Error e->failwith e in
     records:=[];active:=Some(b.state,before.pc,p,preview,ref[],ref 0)))in
  let r=match E.run ~analysis:Execution ~on_before_instruction ~on_guest_step ~on_bdos_record inp with Ok q->q|_->failwith"concrete run"in
  need(!active=None)"closed interval";
  need(!count=(if name="OPTIMIST"then 1 else 0))"required OPTIMIST interval";
  need(r.run.host_transitions=0)"proof-only experiment";
  goldens:=Printf.sprintf"{\"source\":%S,\"REL_sha256\":%S,\"INT_sha256\":%s}"name(E.sha256_hex(Option.get r.rel_bytes))(match r.int_bytes with None->"null"|Some b->Printf.sprintf"%S"(E.sha256_hex b))::!goldens;
  Printf.printf"%s dispatcher guest golden REL=%s\n%!"name(E.sha256_hex(Option.get r.rel_bytes))
 ) ["MINIMAL";"FIZZBUZ";"PICTURE";"FACTOR";"OPTIMIST"];
 let c=open_out !output in Fun.protect ~finally:(fun()->close_out c)(fun()->Printf.fprintf c"{\"cases\":[%s],\"goldens\":[%s],\"all_passed\":true,\"native_roots\":0,\"declined\":[%s],\"gateway_inventory\":[%s],\"synthetic_scale_cases\":%d}\n"(String.concat","(List.rev !results))(String.concat","(List.rev !goldens))(String.concat","(List.rev !declined))(String.concat","(List.rev !inventory))!synthetic_count)
