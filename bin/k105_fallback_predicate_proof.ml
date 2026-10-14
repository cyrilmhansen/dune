[@@@warning "-4-40-41-42"]
module E=Pli80.Experiment
module B=Pli80.Acquisition_family_bridge
module P=Pli80.Scanned_gateway_dependencies
let need b s=if not b then failwith("Pass97: "^s)
let read p=let c=open_in_bin p in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let snapshot st : Runner.state_snapshot=
 let module S=I8080.State in let module F=I8080.Flags in let f=S.flags st in
 {a=S.a st;b=S.b st;c=S.c st;d=S.d st;e=S.e st;h=S.h st;l=S.l st;sp=S.sp st;pc=S.pc st;sign=F.sign f;zero=F.zero f;auxiliary_carry=F.auxiliary_carry f;parity=F.parity f;carry=F.carry f}
let state_json (s:Runner.state_snapshot)=
 let psw=2 lor(if s.sign then 128 else 0)lor(if s.zero then 64 else 0)lor(if s.auxiliary_carry then 16 else 0)lor(if s.parity then 4 else 0)lor(if s.carry then 1 else 0)in
 Printf.sprintf "[%d,%d,%d,%d,%d,%d,%d]" s.pc s.sp s.a(s.b*256+s.c)(s.d*256+s.e)(s.h*256+s.l)psw
let index (bridge:B.t)(boundary:Runner.instruction_boundary)=
 let module F=Pli80_host.Acquisition_family in
 let impossible _=failwith "gateway lookup unexpected child"in
 let q=F.run(F.Pli2_output 0x047d)(Pli80_host.State.of_bytes(boundary.copy_memory())) ~entry:(Pli80.Acquisition_parent_bridge.logical boundary.state)
  ~write:(fun ~site:_ ~address:_ ~value:_->())~compatibility:impossible ~adjust:(fun ~site:_ ~delta:_->impossible())~sp:(fun()->boundary.state.sp)~guard_field:(fun _ _->impossible())~native:(fun ~site:_ ~target:_ _->impossible())~follow_spine:false~software:(fun ~site:_ ~consumed:_->impossible())in
 ignore bridge;q.returned.a
let synthetic bridge (boundary:Runner.instruction_boundary)=
 let module M=I8080.Memory in let module T=I8080.State in
 List.iter(fun carry->List.iter(fun stale->
  let ram=boundary.copy_memory()in Bytes.set ram 0xad15(Char.chr stale);
  let input={boundary.state with Runner.carry;auxiliary_carry=not carry}in
  let view={boundary with Runner.state=input;copy_memory=(fun()->Bytes.copy ram);read_memory=(fun a->Char.code(Bytes.get ram a));
   preview_host_program=(fun p->boundary.preview_host_program{p with effects=Runner.Memory_write(0xad15,stale)::p.effects})}in
  let p=P.predicate ~k105_fallback:true bridge ~call_site:0x4285 view in
  let expected=match view.preview_host_program p.program with Ok r->r|Error e->failwith e in
  let m=M.create()in M.load m ~address:0 ram;
  let t=T.create()in T.set_a t input.a;T.set_bc t(input.b*256+input.c);T.set_de t(input.d*256+input.e);T.set_hl t(input.h*256+input.l);T.set_sp t input.sp;T.set_pc t input.pc;
  I8080.Flags.restore_from_psw_byte(T.flags t)(2 lor(if input.sign then 128 else 0)lor(if input.zero then 64 else 0)lor(if input.parity then 4 else 0)lor(if input.auxiliary_carry then 16 else 0)lor(if input.carry then 1 else 0));
  let cpu=I8080.Cpu.create ~state:t ~bus:(I8080.Bus.create m)in let writes=ref[]and steps=ref 0 in
  while T.pc t<>p.state.pc||T.sp t<>p.state.sp do
   need(!steps<1000)"synthetic termination";incr steps;
   match I8080.Cpu.step cpu with Error _->failwith"synthetic CPU"|Ok step->List.iter(function I8080.Step.Write w->writes:=(w.address,w.value)::!writes|_->())(I8080.Step.memory_accesses step)
  done;
  need(snapshot t=p.state&&M.read_range m ~address:0 ~length:65536=expected.memory)"synthetic full CPU/RAM";
  need(List.rev !writes=List.map(fun(w:B.write)->w.address,w.value)p.journal)"synthetic ordered writes"
 )[0;255])[false;true];4
let ()=
 let images=ref""and output=ref""in Arg.parse["--images",Arg.Set_string images,"images";"--output",Arg.Set_string output,"proof JSON"]ignore"selector15 parent natural CPU/service shadows";
 let synthetic_count=ref 0 in
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
    List.iter(function I8080.Step.Read w when before.Runner.pc>=0x3fff&&before.pc<=0x41b4->reads:=(before.pc,w.address,w.value)::!reads|_->())(I8080.Step.memory_accesses step);
    List.iter(function I8080.Step.Write w->writes:=(w.address,w.value,before.pc)::!writes|_->())(I8080.Step.memory_accesses step)in
  let on_before_instruction ~origin:o ~step_index:_ (b:Runner.instruction_boundary)=
   origin:=o;
   if o=B.origin"PLI2.OVL"0x1fb5&&index bridge b=105 then(
    let word addr=b.read_memory addr lor(b.read_memory(addr+1)lsl 8)in
    let k=index bridge b in let descriptor=word(0x3c21+2*k)and handler=word(0x3ddd+2*k)in
    let j=b.read_memory(0x1b4b+k)land 7 in let base=word(0x3c13+2*j)in
    inventory:=Printf.sprintf"{\"index\":%d,\"entry_RAM_sha256\":%S,\"input_vector\":%s,\"descriptor\":%d,\"handler\":%d,\"count\":%d,\"fallback_index\":%d,\"fallback_table_word\":%d,\"fallback_record\":%d}"
      k(E.sha256_hex(b.copy_memory()))(state_json b.state)descriptor handler(b.read_memory descriptor)j base(base+1)::!inventory);
   (match !observed with Some sp when b.state.pc=0x42b4&&b.state.sp=sp+2->observed:=None|_->());
   if !observed<>None&&b.state.pc=0x41b5 then(
    let before,after,step=Option.get !previous in
    let route=B.gateway_route bridge {Pli80.Native_dispatch.before;after;step;origin=B.origin"PLI2.OVL"(before.pc-0x2200)} ~origin:o b in
    inventory:=Printf.sprintf"{\"source\":%S,\"call_site\":%d,\"C\":%d,\"route\":%S}"name before.pc b.state.c(match route with B.K23->"k23"|K123->"k123"|Guest->"guest")::!inventory);
   (match !active with Some(entry,site,p,preview,writes,steps)when b.state.pc=p.B.state.pc&&b.state.sp=entry.Runner.sp+2->
    need(List.rev !reads=List.rev !host_reads)"direct owned read-site/value chronology";
    need(b.state=p.B.state)"registers flags PC/SP";need(b.copy_memory()=preview.Runner.memory)"full64KiB RAM";
    need(b.dma=preview.dma&&Cpm.Filesystem.equal(b.copy_filesystem())preview.filesystem)"DMA/filesystem";
    let cpu=List.rev !writes in
    need(List.map(fun(a,v,_)->a,v)cpu=List.map(fun(w:B.write)->w.address,w.value)p.journal)"complete ordered writes";
    List.iter2(fun(_,_,writer)(w:B.write)->need(w.writer=(-1)||w.writer=writer)"available last writers")cpu p.journal;
    need(List.rev !records=List.concat_map(fun(s:Runner.host_service)->s.events)preview.services)"service/record chronology";
    results:=Printf.sprintf"{\"source\":%S,\"selector\":%d,\"instructions\":%d,\"writes\":%d,\"services\":%d,\"entry_SP\":%d,\"exit_SP\":%d,\"PC\":%d,\"input_vector\":%s,\"output_vector\":%s,\"entry_RAM_sha256\":%S,\"post_RAM_sha256\":%S,\"direct_reads\":%d,\"full_state_RAM_ordered_writes_services\":true}"name(Char.code(Bytes.get(preview.Runner.memory)0xad0a)) !steps(List.length !writes)(List.length preview.services)entry.Runner.sp b.state.sp b.state.pc(state_json entry)(state_json b.state) !entry_hash(E.sha256_hex preview.memory)(List.length !reads)::!results;
    incr count;active:=None|_->());
   if o=B.origin"PLI2.OVL"0x1dff&&b.read_memory 0xad1c=105 then(
    let before,after,step=Option.get !previous in
    (* Ownership follows the real fallback CALL, not a recorded ordinal. *)
    if before.Runner.pc=0x4285 then(
     let prepare=P.predicate ~k105_fallback:true ~call_site:before.pc in
     need(after=b.state&&I8080.Step.control_flow step=I8080.Step.Call{target=0x3fff;taken=true})"actualpredicate CALL";
     let ram=b.copy_memory()and files=b.copy_filesystem()and dma=b.dma in
     List.iter(fun(address,value)->
      let corrupt=Bytes.copy ram in Bytes.set corrupt address(Char.chr value);
      let view={b with Runner.copy_memory=(fun()->Bytes.copy corrupt);read_memory=(fun a->Char.code(Bytes.get corrupt a));
       preview_host_program=(fun p->b.preview_host_program{p with effects=Runner.Memory_write(address,value)::p.effects})}in
      let rejected=try ignore(prepare bridge view);false with P.Outside_scope _|Invalid_argument _->true in
      need rejected "negative code/continuation/selector/pointer";
      need(b.copy_memory()=ram)"negative mutation"
     )[0x3fff,0;b.state.sp,0;0xad1c,33;0xad1d,0;0x3bf7,0xfb-1;0x1bb4,3];
     synthetic_count:= !synthetic_count+synthetic bridge b;
     entry_hash:=E.sha256_hex ram;
     reads:=[];host_reads:=[];
     let result=Some(prepare ~observe_read:(fun s a v->host_reads:=(s,a,v)::!host_reads) bridge b)in
     need(b.copy_memory()=ram&&b.dma=dma&&Cpm.Filesystem.equal(b.copy_filesystem())files)"staging mutated live state";
     match result with None->()|Some p->
     let preview=match b.preview_host_program p.program with Ok r->r|Error e->failwith e in
     records:=[];active:=Some(b.state,before.pc,p,preview,ref[],ref 0)))in
  let r=match E.run ~analysis:Execution ~on_before_instruction ~on_guest_step ~on_bdos_record inp with Ok q->q|_->failwith"concrete run"in
  need(r.run.host_transitions=0)"proof-only experiment unexpectedly installed root";
  need(!count=(if name="OPTIMIST"then 3 else 0)&& !active=None)"natural3DE4 proof count";
  goldens:=Printf.sprintf"{\"source\":%S,\"REL_sha256\":%S,\"INT_sha256\":%s}"name(E.sha256_hex(Option.get r.rel_bytes))(match r.int_bytes with None->"null"|Some b->Printf.sprintf"%S"(E.sha256_hex b))::!goldens;
  Printf.printf"%s dispatcher guest golden REL=%s\n%!"name(E.sha256_hex(Option.get r.rel_bytes))
 ) ["MINIMAL";"FIZZBUZ";"PICTURE";"FACTOR";"OPTIMIST"];
 let c=open_out !output in Fun.protect ~finally:(fun()->close_out c)(fun()->Printf.fprintf c"{\"cases\":[%s],\"goldens\":[%s],\"all_passed\":true,\"native_roots\":0,\"declined\":[%s],\"gateway_inventory\":[%s],\"synthetic_cache_cases\":%d}\n"(String.concat","(List.rev !results))(String.concat","(List.rev !goldens))(String.concat","(List.rev !declined))(String.concat","(List.rev !inventory))!synthetic_count)
