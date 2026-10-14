[@@@warning "-4-40-41-42"]
module E=Pli80.Experiment
module B=Pli80.Acquisition_family_bridge
module P=Pli80.Scanned_gateway_dependencies
let need b s=if not b then failwith("Pass98: "^s)
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
let ()=
 let images=ref""and output=ref""in Arg.parse["--images",Arg.Set_string images,"images";"--output",Arg.Set_string output,"proof JSON"]ignore"selector15 parent natural CPU/service shadows";
 let synthetic_count=0 in
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
    List.iter(function I8080.Step.Read w when before.Runner.pc>=0x3fff&&before.pc<=0x42ea&&before.sp>=(let e,_,_,_,_,_=Option.get !active in e.Runner.sp-16)->reads:=(before.pc,w.address,w.value)::!reads|_->())(I8080.Step.memory_accesses step);
    List.iter(function I8080.Step.Write w->writes:=(w.address,w.value,before.pc)::!writes|_->())(I8080.Step.memory_accesses step)in
  let on_before_instruction ~origin:o ~step_index:_ (b:Runner.instruction_boundary)=
   origin:=o;
   (match !observed with Some sp when b.state.pc=0x42b4&&b.state.sp=sp+2->observed:=None|_->());
   if !observed<>None&&b.state.pc=0x41b5 then(
    let before,after,step=Option.get !previous in
    let route=B.gateway_route bridge {Pli80.Native_dispatch.before;after;step;origin=B.origin"PLI2.OVL"(before.pc-0x2200)} ~origin:o b in
    inventory:=Printf.sprintf"{\"source\":%S,\"call_site\":%d,\"C\":%d,\"route\":%S}"name before.pc b.state.c(match route with B.K23->"k23"|K123->"k123"|Guest->"guest")::!inventory);
   (match !active with Some(entry,site,p,preview,writes,steps)when b.state.pc=p.B.state.pc&&b.state.sp=entry.Runner.sp+2->
    if !reads<> !host_reads then(
     let rec diff i xs ys=match xs,ys with x::xt,y::yt when x=y->diff(i+1)xt yt|_->Printf.eprintf"read mismatch index%d lengths%d/%d state=%b RAM=%b\n"i(List.length !reads)(List.length !host_reads)(b.state=p.B.state)(b.copy_memory()=preview.Runner.memory);List.iter(fun(s,a,v)->Printf.eprintf"CPU %04X %04X %02X\n"s a v)(List.filteri(fun j _->j<8)xs);List.iter(fun(s,a,v)->Printf.eprintf"HOST %04X %04X %02X\n"s a v)(List.filteri(fun j _->j<8)ys)in diff 0(List.rev !reads)(List.rev !host_reads));
    need(List.rev !reads=List.rev !host_reads)"direct owned read-site/value chronology";
    need(b.state=p.B.state)"registers flags PC/SP";need(b.copy_memory()=preview.Runner.memory)"full64KiB RAM";
    need(b.dma=preview.dma&&Cpm.Filesystem.equal(b.copy_filesystem())preview.filesystem)"DMA/filesystem";
    let cpu=List.rev !writes in
    need(List.map(fun(a,v,_)->a,v)cpu=List.map(fun(w:B.write)->w.address,w.value)p.journal)"complete ordered writes";
    List.iter2(fun(_,_,writer)(w:B.write)->need(w.writer=(-1)||w.writer=writer)"available last writers")cpu p.journal;
    need(List.rev !records=List.concat_map(fun(s:Runner.host_service)->s.events)preview.services)"service/record chronology";
    results:=Printf.sprintf"{\"source\":%S,\"selector\":%d,\"instructions\":%d,\"writes\":%d,\"services\":%d,\"entry_SP\":%d,\"exit_SP\":%d,\"PC\":%d,\"input_vector\":%s,\"output_vector\":%s,\"entry_RAM_sha256\":%S,\"post_RAM_sha256\":%S,\"direct_reads\":%d,\"full_state_RAM_ordered_writes_services\":true}"name(Char.code(Bytes.get(preview.Runner.memory)0xad0a)) !steps(List.length !writes)(List.length preview.services)entry.Runner.sp b.state.sp b.state.pc(state_json entry)(state_json b.state) !entry_hash(E.sha256_hex preview.memory)(List.length !reads)::!results;
    incr count;active:=None|_->());
   if o=B.origin"PLI2.OVL"0x1fb5&&index bridge b=105 then(
    let before,after,step=Option.get !previous in
    (* The immutable entry state selects k105 before any expected result is inspected. *)
    if I8080.Step.control_flow step=I8080.Step.Call{target=0x41b5;taken=true}then(
     let prepare=P.gateway105 ~call_site:before.pc in
     need(after=b.state&&I8080.Step.control_flow step=I8080.Step.Call{target=0x41b5;taken=true})"actualpredicate CALL";
     need(P.eligible105 bridge ~call_site:before.pc b)"complete copied eligibility";
     let ram=b.copy_memory()and files=b.copy_filesystem()and dma=b.dma in
     List.iter(fun edits->
      let corrupt=Bytes.copy ram in List.iter(fun(address,value)->Bytes.set corrupt address(Char.chr value))edits;
      let view={b with Runner.copy_memory=(fun()->Bytes.copy corrupt);read_memory=(fun a->Char.code(Bytes.get corrupt a));
       preview_host_program=(fun p->b.preview_host_program{p with effects=List.map(fun(address,value)->Runner.Memory_write(address,value))edits@p.effects})}in
      let rejected=not(P.eligible105 bridge ~call_site:before.pc view)in
      need rejected "negative code/continuation/selector/pointer";
      need(b.copy_memory()=ram)"negative mutation"
     )[[0x41b5,0];[b.state.sp,0];[0x202e,1];[0x3cf3,0];[0x3eaf,0];[0x434f,1];[0x3c17,0];[0x3bf7,0xfa];[0x201d,1];[0x2155,0x15;0x2156,0xad]];
     let corrupt=Bytes.copy ram in Bytes.set corrupt 0x38f8 '\000';
     let view={b with Runner.copy_memory=(fun()->Bytes.copy corrupt);read_memory=(fun a->Char.code(Bytes.get corrupt a));preview_host_program=(fun p->b.preview_host_program{p with effects=Runner.Memory_write(0x38f8,0)::p.effects})}in
     let propagated=try ignore(P.eligible105 bridge ~call_site:before.pc view);false with Invalid_argument _->true in
     need propagated "unexpected late child proof error must propagate";need(b.copy_memory()=ram)"proof error changed live RAM";
     need(P.eligible105 bridge ~call_site:before.pc b)"same-boundary recovery";
     let other={b with Runner.state={b.state with c=103}}in
     need(not(P.eligible105 bridge ~call_site:before.pc other))"unsupported index decline";

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
 let c=open_out !output in Fun.protect ~finally:(fun()->close_out c)(fun()->Printf.fprintf c"{\"cases\":[%s],\"goldens\":[%s],\"all_passed\":true,\"native_roots\":0,\"declined\":[%s],\"gateway_inventory\":[%s],\"synthetic_RAR_cases\":%d}\n"(String.concat","(List.rev !results))(String.concat","(List.rev !goldens))(String.concat","(List.rev !declined))(String.concat","(List.rev !inventory))synthetic_count)
