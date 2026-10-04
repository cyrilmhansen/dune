[@@@warning "-4-40-41-42"]
module R=Pli80_host.Mapped_publication
module B=Mapped_publication_bridge
type case={caller:string;entry_step:int;return_step:int;parent_entry_step:int option;
  input:Runner.state_snapshot;output:Runner.state_snapshot;result:R.result;
  writes:Pli80_host.Mapped_lookup.write list;entry_scratch:(int*int)list;
  entry_memory_sha256:string;final_memory_sha256:string;logical_writes_sha256:string;
  compatibility_writes:(int*int)list}
type validated={cases:case list;snapshots:(int*bytes*bytes)list;records:(string*int*bytes)list;input_digest:string}
let cases v=v.cases
let require b message=if not b then failwith("Native mapped publication: "^message)
let shadow input =
 let bridge=B.create ~pli1:input.Experiment.pli1_ovl in
 let active=ref[]and previous=ref None and current_origin=ref Analysis.Execution_map.Unknown in
 let cases=ref[]and snapshots=ref[]and records=ref[]in
 let on_bdos_record ~step_index:_=function Cpm.Bdos.Write_record{file;logical_record;data;_}->records:=(file.name,logical_record,Bytes.copy data)::!records|_->()in
 let on_guest_step ~step_index:_ ~(before:Runner.state_snapshot) ~(after:Runner.state_snapshot) step=
  previous:=Some(!current_origin,before,after,step);
  List.iter(fun(_,_,_,_,_,_,writes,latest)->
   List.iter(function I8080.Step.Write q->
    Hashtbl.replace latest q.address(I8080.Step.pc_before step,q.value);
    (match I8080.Step.control_flow step with I8080.Step.Call _->()|_->writes:=(q.address,q.value)::!writes)
    |_->())(I8080.Step.memory_accesses step))!active in
 let on_before_instruction ~origin ~step_index boundary=
  current_origin:=origin;let state=boundary.Runner.state in
  (match !active with
  |(entry_step,parent_entry_step,(input:Runner.state_snapshot),entry_memory,call,(p:B.prepared),writes,latest)::rest when state.pc=call.B.resume->
    let ret_pc=match call.operation with B.Publish->0x9cef|B.Recycle->0x9dbe in
    (match !previous with Some(_,before,after,step)->
     require(I8080.Step.pc_before step=ret_pc && I8080.Step.control_flow step=I8080.Step.Return{target=Some call.resume;taken=true}
      &&before.sp=input.sp&&after=state)"terminal RET ancestry";
     let reads=List.filter_map(function I8080.Step.Read q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses step)in
     require(reads=[input.sp,call.resume land 255;Pli80_host.U16.wrap(input.sp+1),call.resume lsr 8])"RET consumes original CALL slot";
     require(not(Hashtbl.mem latest input.sp)&&not(Hashtbl.mem latest(Pli80_host.U16.wrap(input.sp+1))))"continuation overwritten"
     |_->assert false);
    let logical=List.map(fun(w:Pli80_host.Mapped_lookup.write)->w.address,w.value)p.writes in
    require(List.rev !writes=logical)"logical write chronology";
    require(state=p.state)"returned registers/flags";
    List.iter(fun(a,v)->require(Hashtbl.find_opt latest a=Some(0x9dae,v))"child CALL final writer")p.compatibility_writes;
    require(Hashtbl.length latest=List.length(List.sort_uniq compare(List.map fst(logical@p.compatibility_writes))))"unexplained write cell";
    let post=boundary.copy_memory()in require(post=p.memory)"full64KiB post-state";
    cases:={caller=call.coordinate;entry_step;return_step=step_index-1;parent_entry_step;input;output=state;result=p.result;writes=p.writes;entry_scratch=List.map(fun a->a,Char.code(Bytes.get entry_memory a))[0xae33;0xae34;0xae3c;0xae3d;0xae4a;0xae4b];
      entry_memory_sha256=Experiment.sha256_hex entry_memory;final_memory_sha256=Experiment.sha256_hex post;
      logical_writes_sha256=Native_dispatch.write_digest logical;compatibility_writes=p.compatibility_writes}::!cases;
    snapshots:=(entry_step,entry_memory,post)::!snapshots;active:=rest
  |_->());
  let selected_image=match origin with Analysis.Execution_map.Image_byte{image;_}->image.name="PLI1.OVL"|_->false in
  if selected_image&&(state.pc=0x9cd5||state.pc=0x9da2) then (
   let call=match !previous with Some(origin,before,after,step)->B.verify_call bridge ~origin ~before ~after step ~entry:state|_->failwith"Entry without actual CALL"in
   let parent=match !active with (s,_,_,_,_,_,_,_)::_->Some s|[]->None in
   require((call.runtime_site=0x9dae)=(parent<>None))"publication child ancestry";
   let memory=boundary.copy_memory()in let p=B.prepare bridge ~call ~origin ~state ~memory in
   active:=(step_index,parent,state,memory,call,p,ref[],Hashtbl.create 8)::!active)in
 match Experiment.run ~analysis:Experiment.Execution ~on_before_instruction ~on_guest_step ~on_bdos_record input with
 |Error _ as e->e|Ok result->require(!active=[])"missing return";
  Ok({cases=List.sort(fun a b->compare a.entry_step b.entry_step)!cases;snapshots= !snapshots;
    records=List.rev !records;input_digest=Experiment.sha256_hex(Marshal.to_bytes input[])},result)
let publications v=List.filter(fun c->match c.result with R.Publication _->true|_->false)v.cases
let recycles v=List.filter(fun c->match c.result with R.Recycle _->true|_->false)v.cases
let record_summaries v=List.map(fun(n,r,b)->n,r,Experiment.sha256_hex b)v.records
let controller ?(exclude_entry_steps=[]) operation v input =
 require(v.input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]))"source/input proof mismatch";
 let members=match operation with B.Publish->publications v|B.Recycle->recycles v in
 require(List.for_all(fun s->List.exists(fun c->c.entry_step=s)members)exclude_entry_steps
   &&List.length exclude_entry_steps=List.length(List.sort_uniq compare exclude_entry_steps))"invalid child exclusion";
 let selected=List.filter(fun c->not(List.mem c.entry_step exclude_entry_steps))members in
 let bridge=B.create ~pli1:input.Experiment.pli1_ovl in
 let oracles=List.map(fun c->let _,entry_memory,post_memory=List.find(fun(s,_,_)->s=c.entry_step)v.snapshots in
   {Native_dispatch.input=c.input;output=c.output;entry_memory;post_memory;logical_digest=c.logical_writes_sha256})selected in
 let prepare(previous:Native_dispatch.previous)origin boundary=
  let call=B.verify_call bridge ~origin:previous.origin ~before:previous.before ~after:previous.after previous.step ~entry:boundary.Runner.state in
  let p=B.prepare bridge ~call ~origin ~state:boundary.state ~memory:(boundary.copy_memory())in
  {Native_dispatch.state=p.state;memory=p.memory;logical_writes=List.map(fun(w:Pli80_host.Mapped_lookup.write)->w.address,w.value)p.writes;
   compatibility_writes=p.compatibility_writes}in
 let entry_pc,end_pc=match operation with B.Publish->0x9cd5,0x9cf0|B.Recycle->0x9da2,0x9dbf in
 Native_dispatch.create ~image:"PLI1.OVL" ~entry_pc ~end_pc ~oracles ~records:v.records ~prepare
let standalone v input=Native_dispatch.run input[controller B.Publish v input]
let inside windows step=List.exists(fun(a,b)->a<step&&step<b)windows
let children v=let windows=List.map(fun c->c.entry_step,c.return_step)(recycles v)in
 publications v|>List.filter(fun c->inside windows c.entry_step)|>List.map(fun c->c.entry_step)
let hierarchical v input=Native_dispatch.run input[controller B.Recycle v input;controller ~exclude_entry_steps:(children v) B.Publish v input]
let cumulative v recursive words balances input=
 let windows=List.map(fun(c:Native_7c1b.case)->c.entry_step,c.return_step)(Native_7c1b.roots recursive)in
 let word_steps=Native_7bbf.cases words|>List.filter(fun(c:Native_7bbf.case)->inside windows c.entry_step)|>List.map(fun(c:Native_7bbf.case)->c.entry_step)in
 let balance_steps=Native_7b7a.cases balances|>List.filter(fun(c:Native_7b7a.case)->inside windows c.entry_step)|>List.map(fun(c:Native_7b7a.case)->c.entry_step)in
 (* Cross-check these operations do not acquire a suppressed ancestor silently. *)
 require(not(List.exists(fun c->inside windows c.entry_step)(recycles v)))"recycle nested beneath recursive root";
 let publication_steps=List.sort_uniq compare(children v@(publications v|>List.filter(fun c->inside windows c.entry_step)|>List.map(fun c->c.entry_step)))in
 Native_dispatch.run input[Native_7c1b.controller recursive input;
  Native_7bbf.controller ~exclude_entry_steps:word_steps words input;
  Native_7b7a.controller ~exclude_entry_steps:balance_steps balances input;
  controller B.Recycle v input;controller ~exclude_entry_steps:publication_steps B.Publish v input]
