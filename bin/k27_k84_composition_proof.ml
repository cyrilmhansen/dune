[@@@warning "-4-40-41-42"]
module E=Pli80.Experiment
module B=Pli80.Acquisition_family_bridge
module P=Pli80.K27_k84_composition
let need b s=if not b then failwith("Pass99: "^s)
let read p=let c=open_in_bin p in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let snapshot st : Runner.state_snapshot=
 let module S=I8080.State in let module F=I8080.Flags in let f=S.flags st in
 {a=S.a st;b=S.b st;c=S.c st;d=S.d st;e=S.e st;h=S.h st;l=S.l st;sp=S.sp st;pc=S.pc st;sign=F.sign f;zero=F.zero f;auxiliary_carry=F.auxiliary_carry f;parity=F.parity f;carry=F.carry f}
let state_json (s:Runner.state_snapshot)=
 let psw=2 lor(if s.sign then 128 else 0)lor(if s.zero then 64 else 0)lor(if s.auxiliary_carry then 16 else 0)lor(if s.parity then 4 else 0)lor(if s.carry then 1 else 0)in
 Printf.sprintf "[%d,%d,%d,%d,%d,%d,%d]" s.pc s.sp s.a(s.b*256+s.c)(s.d*256+s.e)(s.h*256+s.l)psw
let counter_synthetic images=
 let module M=I8080.Memory in let module T=I8080.State in
 let image=read(Filename.concat images "PLI2.OVL")in
 List.iter(fun value->List.iter(fun psw->List.iter(fun sp->
  let m=M.create()in M.load m ~address:0x2200 image;
  M.write m sp 0;M.write m(sp+1)1;M.write m 0xae06 value;M.write m 0xae04((value+1)land 255);
  let t=T.create()in T.set_pc t 0x9bd7;T.set_sp t sp;T.set_bc t 0x1234;T.set_a t 0x71;T.set_de t 0x5678;T.set_hl t 0x4321;
  I8080.Flags.restore_from_psw_byte(T.flags t)psw;
  let input=snapshot t in let host=Pli80_host.State.of_bytes(M.read_range m ~address:0 ~length:65536)in let writes=ref[]and reads=ref[]in
  let q=P.counter host ~entry:(Pli80.Acquisition_parent_bridge.logical input)
   ~observe_read:(fun site address value->reads:=(site,address,value)::!reads)
   ~write:(fun _ address value->Pli80_host.State.write host address value;writes:=(address,value)::!writes)in
  let cpu=I8080.Cpu.create ~state:t ~bus:(I8080.Bus.create m)in let cpu_writes=ref[]and cpu_reads=ref[]in
  for _=1 to 5 do let pc=T.pc t in match I8080.Cpu.step cpu with Error _->failwith"counter CPU"|Ok step->
   List.iter(function I8080.Step.Write w->cpu_writes:=(w.address,w.value)::!cpu_writes
    |I8080.Step.Read r when pc<>0x9be1->cpu_reads:=(pc,r.address,r.value)::!cpu_reads|_->())(I8080.Step.memory_accesses step)done;
  need(snapshot t=Pli80.Acquisition_parent_bridge.machine input q(sp+2)0x100)"INR inherited CY/registers/RET";
  need(M.read_range m ~address:0 ~length:65536=Pli80_host.State.copy host&& !writes= !cpu_writes&& !reads= !cpu_reads)"counter wrap/AC/same-valued writes/fullRAM"
 )[0xb240;0xfff0])[2;0xd7])[0;15;127;255];16
let ()=
 let prefix=ref false and complete=ref false in
 let images=ref""and output=ref""in Arg.parse["--complete",Arg.Unit(fun()->prefix:=true;complete:=true),"complete k27 software handler";"--prefix",Arg.Set prefix,"composed k27 prefix";"--images",Arg.Set_string images,"images";"--output",Arg.Set_string output,"proof JSON"]ignore"selector15 parent natural CPU/service shadows";
 let synthetic_count=if !prefix then counter_synthetic !images else 0 in
 let declined=ref[] and inventory=ref[]in
 let results=ref[]and goldens=ref[]and reads=ref[]and host_reads=ref[]in
 List.iter(fun name->
  let image n=read(Filename.concat !images n)in
  let inp:E.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=E.prepare_source ~normalize:true(read(let p="examples/pli80/"^name^".PLI"in if Sys.file_exists p then p else Filename.concat !images(name^".PLI")));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  let bridge=B.create_with_images ~pli_com:inp.pli_com ~pli0:inp.pli0_ovl ~pli1:inp.pli1_ovl ~pli2:inp.pli2_ovl in
  let delegated=ref false in
  let previous=ref None and origin=ref Analysis.Execution_map.Unknown and active=ref None and count=ref 0 and records=ref[]and observed=ref None and latest=Hashtbl.create 128 and entry_hash=ref""in
  let on_bdos_record ~step_index:_ ev=if !active<>None then records:=ev::!records in
  let on_guest_step ~step_index:_ ~before ~after step=
   previous:=Some(before,after,step);
   List.iter(function I8080.Step.Write w->Hashtbl.replace latest w.address(before.Runner.pc,w.value)|_->())(I8080.Step.memory_accesses step);
   match !active with None->()|Some(_,_,_,_,writes,steps)->
    incr steps;
    List.iter(function I8080.Step.Read w when not !delegated&&
     (if !prefix then (before.Runner.pc>=0x3fff&&before.pc<=0x42ea)||List.mem before.pc[0x44eb;0x44f8;0x4525;0x43b2;0x43c6;0x43c9;0x43cc;0x452f;0x9bd7;0x9be1;0x5875;0x587f;0x5889;0x9ca3;0x9bc2;0x9bcb;0x9cb8;0x9cc3;0xa2b9;0xa2c6;0xa2cf;0x454c;0x4551]
      else List.mem before.Runner.pc[0x6516;0x6489;0x64aa;0x64b2;0x64be;0x64bf;0x64c0;0x64fa;0x5952;0x589f;0x58a9;0x58b3;0x593b;0x595c;0x6505;0x6507;0x6514;0x6515;0x596b;0x6539])->reads:=(before.pc,w.address,w.value)::!reads|_->())(I8080.Step.memory_accesses step);
    List.iter(function I8080.Step.Write w->writes:=(w.address,w.value,before.pc)::!writes|_->())(I8080.Step.memory_accesses step)in
  let on_before_instruction ~origin:o ~step_index:_ (b:Runner.instruction_boundary)=
   origin:=o;
   (match !active with Some(entry,_,_,_,_,_)->
     if !prefix then(
      if b.state.pc=0x4552||b.state.pc=0x6516 then delegated:=true;
      if b.state.pc=0x42b4&&b.state.sp=entry.Runner.sp-15 then delegated:=false
     )else(
      if b.state.pc=0x41b5&&(let before,_,_=Option.get !previous in before.Runner.pc=0x5956)then delegated:=true;
      if b.state.pc=0x5959&&b.state.sp=entry.Runner.sp-7 then delegated:=false)
    |_->());
   (match !active with Some(entry,site,p,preview,writes,steps)when b.state.pc=p.B.state.pc&&b.state.sp=p.state.sp&&
    (not !prefix|| !complete||(let before,_,_=Option.get !previous in before.Runner.pc=0x4533))->
    need(List.rev !reads=List.rev !host_reads)"direct owned read-site/value chronology";
    need(b.state=p.B.state)"registers flags PC/SP";need(b.copy_memory()=preview.Runner.memory)"full64KiB RAM";
    need(b.dma=preview.dma&&Cpm.Filesystem.equal(b.copy_filesystem())preview.filesystem)"DMA/filesystem";
    let cpu=List.rev !writes in
    need(List.map(fun(a,v,_)->a,v)cpu=List.map(fun(w:B.write)->w.address,w.value)p.journal)"complete ordered writes";
    List.iter2(fun(_,_,writer)(w:B.write)->need(w.writer=(-1)||w.writer=writer)"available last writers")cpu p.journal;
    need(List.rev !records=List.concat_map(fun(s:Runner.host_service)->s.events)preview.services)"service/record chronology";
    results:=Printf.sprintf"{\"source\":%S,\"selector\":%d,\"instructions\":%d,\"writes\":%d,\"services\":%d,\"entry_SP\":%d,\"exit_SP\":%d,\"PC\":%d,\"input_vector\":%s,\"output_vector\":%s,\"entry_RAM_sha256\":%S,\"post_RAM_sha256\":%S,\"direct_reads\":%d,\"full_state_RAM_ordered_writes_services\":true}"name(Char.code(Bytes.get(preview.Runner.memory)0xad0a)) !steps(List.length !writes)(List.length preview.services)entry.sp b.state.sp b.state.pc(state_json entry)(state_json b.state) !entry_hash(E.sha256_hex preview.memory)(List.length !reads)::!results;
    incr count;active:=None|_->());
   if o=B.origin"PLI2.OVL"(if !prefix then 0x22ea else 0x4316) then(
    let before,after,step=Option.get !previous in
    let prepare=if !prefix then P.prefix ~complete:!complete else Pli80.K84_handler.prepare in
    if not !prefix&&b.read_memory 0xad0a<>1 then(
     let ram=b.copy_memory()in
     let rejected=try ignore(prepare bridge b);false with Invalid_argument text->text="selected k84: unsupported non1 software selector"in
     need(rejected&&ram=b.copy_memory())"other k84 branch remains excluded";
     declined:=Printf.sprintf"{\"source\":%S,\"reason\":\"non1 software selector\"}"name::!declined
    )else if before.Runner.pc=0x42b3 then(
     need(after=b.state&&I8080.Step.control_flow step=I8080.Step.Jump{target=b.state.pc;taken=true})"actual software PCHL";
     need(Hashtbl.find latest b.state.sp=(0x42af,0xb4)&&Hashtbl.find latest(b.state.sp+1)=(0x42af,0x42))"actual software continuation last writers";
     let ram=b.copy_memory()and files=b.copy_filesystem()and dma=b.dma in
     List.iter(fun edits->
      let corrupt=Bytes.copy ram in List.iter(fun(address,value)->Bytes.set corrupt address(Char.chr value))edits;
      let view={b with Runner.copy_memory=(fun()->Bytes.copy corrupt);read_memory=(fun a->Char.code(Bytes.get corrupt a));
       preview_host_program=(fun p->b.preview_host_program{p with effects=List.map(fun(address,value)->Runner.Memory_write(address,value))edits@p.effects})}in
      let rejected=try ignore(prepare bridge view);false with Invalid_argument _->true in
      need rejected "negative code/continuation/selector/pointer";
      need(b.copy_memory()=ram)"negative mutation"
     )[[b.state.pc,0];[b.state.sp,0]];
     entry_hash:=E.sha256_hex ram;
     reads:=[];host_reads:=[];
     let result=Some((if !prefix then P.prefix ~complete:!complete else Pli80.K84_handler.prepare) ~observe_read:(fun s a v->host_reads:=(s,a,v)::!host_reads) bridge b)in
     need(b.copy_memory()=ram&&b.dma=dma&&Cpm.Filesystem.equal(b.copy_filesystem())files)"staging mutated live state";
     match result with None->()|Some p->
     let preview=match b.preview_host_program p.program with Ok r->r|Error e->failwith e in
     records:=[];active:=Some(b.state,before.pc,p,preview,ref[],ref 0)))in
  let r=match E.run ~analysis:Execution ~on_before_instruction ~on_guest_step ~on_bdos_record inp with Ok q->q|_->failwith"concrete run"in
  need(r.run.host_transitions=0)"proof-only experiment";
  need(!count=(if name="OPTIMIST"then 3 else 0)&& !active=None)"natural3DE4 proof count";
  goldens:=Printf.sprintf"{\"source\":%S,\"REL_sha256\":%S,\"INT_sha256\":%s}"name(E.sha256_hex(Option.get r.rel_bytes))(match r.int_bytes with None->"null"|Some b->Printf.sprintf"%S"(E.sha256_hex b))::!goldens;
  Printf.printf"%s dispatcher guest golden REL=%s\n%!"name(E.sha256_hex(Option.get r.rel_bytes))
 ) ["MINIMAL";"FIZZBUZ";"PICTURE";"FACTOR";"OPTIMIST"];
 let c=open_out !output in Fun.protect ~finally:(fun()->close_out c)(fun()->Printf.fprintf c"{\"cases\":[%s],\"goldens\":[%s],\"all_passed\":true,\"native_roots\":0,\"declined\":[%s],\"gateway_inventory\":[%s],\"synthetic_counter_cases\":%d}\n"(String.concat","(List.rev !results))(String.concat","(List.rev !goldens))(String.concat","(List.rev !declined))(String.concat","(List.rev !inventory))synthetic_count)
