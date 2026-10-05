[@@@warning "-4-40-41-42"]
module B=Range_publication_bridge
type case={caller:string;entry_step:int;return_step:int;parent_entry_step:int option;
  input:Runner.state_snapshot;output:Runner.state_snapshot;result:Pli80_host.Range_publication.result;journal:B.journal list;
  writes:Pli80_host.Mapped_lookup.write list;entry_scratch:(int*int)list;
  entry_memory_sha256:string;final_memory_sha256:string;logical_writes_sha256:string;
  compatibility_writes:(int*int)list}
type validated={cases:case list;snapshots:(int*bytes*bytes)list;records:(string*int*bytes)list;input_digest:string;historical:Experiment.result}
let cases v=v.cases
let require b message=if not b then failwith("Native range publication: "^message)
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
    writes:=(q.address,q.value,I8080.Step.pc_before step)::!writes
    |_->())(I8080.Step.memory_accesses step))!active in
 let on_before_instruction ~origin ~step_index boundary=
  current_origin:=origin;let state=boundary.Runner.state in
  (match !active with
  |(entry_step,parent_entry_step,(input:Runner.state_snapshot),entry_memory,call,(p:B.prepared),writes,latest)::rest when state.pc=call.B.resume->
    let ret_pc=0xa0bf in
    (match !previous with Some(_,before,after,step)->
     require(I8080.Step.pc_before step=ret_pc && I8080.Step.control_flow step=I8080.Step.Return{target=Some call.resume;taken=true}
      &&before.sp=input.sp&&after=state)"terminal RET ancestry";
     let reads=List.filter_map(function I8080.Step.Read q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses step)in
     require(reads=[input.sp,call.resume land 255;Pli80_host.U16.wrap(input.sp+1),call.resume lsr 8])"RET consumes original CALL slot";
     require(not(Hashtbl.mem latest input.sp)&&not(Hashtbl.mem latest(Pli80_host.U16.wrap(input.sp+1))))"continuation overwritten"
     |_->assert false);
    let logical=List.map(fun(w:Pli80_host.Mapped_lookup.write)->w.address,w.value)p.writes in
    require(List.rev !writes=List.map(fun(w:B.journal)->w.address,w.value,w.writer)p.journal)"full ordered logical/ABI writer chronology";
    require(state=p.state)"returned registers/flags";
    List.iter(fun(a,v)->let expected=List.find(fun(w:B.journal)->w.address=a)(List.rev p.journal)in
     require(Hashtbl.find_opt latest a=Some(expected.writer,v))"derived final stack writer")p.compatibility_writes;
    require(Hashtbl.length latest=List.length(List.sort_uniq compare(List.map fst(logical@p.compatibility_writes))))"unexplained write cell";
    let post=boundary.copy_memory()in require(post=p.memory)"full64KiB post-state";
    cases:={caller=call.coordinate;entry_step;return_step=step_index-1;parent_entry_step;input;output=state;result=p.result;journal=p.journal;writes=p.writes;entry_scratch=List.map(fun a->a,Char.code(Bytes.get entry_memory a))[0xae32;0xae33;0xae34;0xae35;0xae36;0xae54;0xae55;0xae56];
      entry_memory_sha256=Experiment.sha256_hex entry_memory;final_memory_sha256=Experiment.sha256_hex post;
      logical_writes_sha256=Native_dispatch.write_digest logical;compatibility_writes=p.compatibility_writes}::!cases;
    snapshots:=(entry_step,entry_memory,post)::!snapshots;active:=rest
  |_->());
  let selected_image=match origin with Analysis.Execution_map.Image_byte{image;_}->image.name="PLI1.OVL"|_->false in
  if selected_image&&state.pc=0xa05f then (
   let call=match !previous with Some(origin,before,after,step)->B.verify_call bridge ~origin ~before ~after step ~entry:state|_->failwith"Entry without actual CALL"in
   let parent=match !active with (s,_,_,_,_,_,_,_)::_->Some s|[]->None in
   require(parent=None)"leaf has nested/reentrant invocation";
   let memory=boundary.copy_memory()in let p=B.prepare bridge ~call ~origin ~state ~memory in
   active:=(step_index,parent,state,memory,call,p,ref[],Hashtbl.create 8)::!active)in
 match Experiment.run ~analysis:Experiment.Execution ~on_before_instruction ~on_guest_step ~on_bdos_record input with
 |Error _ as e->e|Ok result->require(!active=[])"missing return";
  Ok({cases=List.sort(fun a b->compare a.entry_step b.entry_step)!cases;snapshots= !snapshots;
    records=List.rev !records;input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]);historical=result},result)
let record_summaries v=List.map(fun(n,r,b)->n,r,Experiment.sha256_hex b)v.records
let controller v input =
 require(v.input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]))"source/input proof mismatch";
 let selected=v.cases in
 let bridge=B.create ~pli1:input.Experiment.pli1_ovl in
 let oracles=List.map(fun c->let _,entry_memory,post_memory=List.find(fun(s,_,_)->s=c.entry_step)v.snapshots in
   {Native_dispatch.input=c.input;output=c.output;entry_memory;post_memory;logical_digest=c.logical_writes_sha256})selected in
 let prepare(previous:Native_dispatch.previous)origin boundary=
  let call=B.verify_call bridge ~origin:previous.origin ~before:previous.before ~after:previous.after previous.step ~entry:boundary.Runner.state in
  let p=B.prepare bridge ~call ~origin ~state:boundary.state ~memory:(boundary.copy_memory())in
  {Native_dispatch.state=p.state;memory=p.memory;logical_writes=List.map(fun(w:Pli80_host.Mapped_lookup.write)->w.address,w.value)p.writes;
   compatibility_writes=p.compatibility_writes}in
 Native_dispatch.create ~image:"PLI1.OVL" ~entry_pc:0xa05f ~end_pc:0xa0c0 ~oracles ~records:v.records ~prepare
let compare_external v (r:Experiment.result)=
 require(Cpm.Filesystem.equal r.filesystem v.historical.filesystem)"final filesystem identity";
 let event(e:Experiment.file_event)=e.operation,e.file,e.succeeded,e.logical_record,e.byte_range in
 require(List.map event r.file_events=List.map event v.historical.file_events)"file event sequence";
 require(r.int_bytes=v.historical.int_bytes&&r.rel_bytes=v.historical.rel_bytes)"INT/REL identity"
let single v input=match Native_dispatch.run input[controller v input]with Error _ as e->e|Ok(_,r)as q->compare_external v r;q
let cumulative v new_publications range words emitter attributes publications recursive packed balances input =
 let windows=List.map(fun c->c.entry_step,c.return_step)v.cases in
 let excludes cases=List.filter_map(fun(c:Native_publication_primitives.case)->if List.exists(fun(a,b)->a<c.entry_step&&c.entry_step<b)windows then Some c.entry_step else None)cases in
 let old=Native_range_processing.controllers ~exclude_windows:windows range words emitter attributes publications recursive packed balances input in
 let extra=[Native_publication_primitives.controller ~exclude_entry_steps:(excludes(Native_publication_primitives.mapped_words new_publications)) Publication_primitives_bridge.Mapped_word new_publications input;
 Native_publication_primitives.controller ~exclude_entry_steps:(excludes(Native_publication_primitives.secondary_bytes new_publications)) Publication_primitives_bridge.Secondary new_publications input]in
 match Native_dispatch.run input(controller v input::old@extra)with
 |Error _ as e->e|Ok(_,r)as q->compare_external v r;Native_int_emitter.compare_external emitter r;q
