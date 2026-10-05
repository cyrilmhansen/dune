[@@@warning "-4-40-41-42"]
module B=Mapped_control_bridge
type case={caller:string;entry_step:int;return_step:int;parent_entry_step:int option;
  input:Runner.state_snapshot;output:Runner.state_snapshot;result:B.result;
  writes:Pli80_host.Mapped_lookup.write list;entry_scratch:(int*int)list;
  entry_memory_sha256:string;final_memory_sha256:string;logical_writes_sha256:string;
  compatibility_writes:(int*int)list}
type validated={cases:case list;snapshots:(int*bytes*bytes)list;records:(string*int*bytes)list;input_digest:string;historical:Experiment.result}
let cases v=v.cases
let require b message=if not b then failwith("Native mapped control: "^message)
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
    let ret_pc=match call.operation with B.Read->0x9ca8|B.Publish->0x9d2d in
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
    require(p.compatibility_writes=[])"leaf has unexpected stack residue";
    require(Hashtbl.length latest=List.length(List.sort_uniq compare(List.map fst(logical@p.compatibility_writes))))"unexplained write cell";
    let post=boundary.copy_memory()in require(post=p.memory)"full64KiB post-state";
    cases:={caller=call.coordinate;entry_step;return_step=step_index-1;parent_entry_step;input;output=state;result=p.result;writes=p.writes;entry_scratch=List.map(fun a->a,Char.code(Bytes.get entry_memory a))[0xae39;0xae3a;0xae41;0xae42];
      entry_memory_sha256=Experiment.sha256_hex entry_memory;final_memory_sha256=Experiment.sha256_hex post;
      logical_writes_sha256=Native_dispatch.write_digest logical;compatibility_writes=p.compatibility_writes}::!cases;
    snapshots:=(entry_step,entry_memory,post)::!snapshots;active:=rest
  |_->());
  let selected_image=match origin with Analysis.Execution_map.Image_byte{image;_}->image.name="PLI1.OVL"|_->false in
  if selected_image&&(state.pc=0x9c93||state.pc=0x9d13) then (
   let call=match !previous with Some(origin,before,after,step)->B.verify_call bridge ~origin ~before ~after step ~entry:state|_->failwith"Entry without actual CALL"in
   let parent=match !active with (s,_,_,_,_,_,_,_)::_->Some s|[]->None in
   require(parent=None)"leaf has nested/reentrant invocation";
   let memory=boundary.copy_memory()in let p=B.prepare bridge ~call ~origin ~state ~memory in
   active:=(step_index,parent,state,memory,call,p,ref[],Hashtbl.create 8)::!active)in
 match Experiment.run ~analysis:Experiment.Execution ~on_before_instruction ~on_guest_step ~on_bdos_record input with
 |Error _ as e->e|Ok result->require(!active=[])"missing return";
  Ok({cases=List.sort(fun a b->compare a.entry_step b.entry_step)!cases;snapshots= !snapshots;
    records=List.rev !records;input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]);historical=result},result)
let reads v=List.filter(fun c->match c.result with B.Read_result _->true|_->false)v.cases
let publications v=List.filter(fun c->match c.result with B.Publish_result _->true|_->false)v.cases
let record_summaries v=List.map(fun(n,r,b)->n,r,Experiment.sha256_hex b)v.records
let controller ?(exclude_entry_steps=[]) operation v input =
 require(v.input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]))"source/input proof mismatch";
 let members=match operation with B.Read->reads v|B.Publish->publications v in
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
 let entry_pc,end_pc=match operation with B.Read->0x9c93,0x9ca9|B.Publish->0x9d13,0x9d2e in
 Native_dispatch.create ~image:"PLI1.OVL" ~entry_pc ~end_pc ~oracles ~records:v.records ~prepare
let single operation v input=match Native_dispatch.run input[controller operation v input]with
 |Error _ as e->e|Ok(_,r)as q->
 require(Cpm.Filesystem.equal r.filesystem v.historical.filesystem)"final filesystem identity";
 let event(e:Experiment.file_event)=e.operation,e.file,e.succeeded,e.logical_record,e.byte_range in
 require(List.map event r.file_events=List.map event v.historical.file_events)"file event order";
 require(r.int_bytes=v.historical.int_bytes&&r.rel_bytes=v.historical.rel_bytes)"INT/REL identity";q
