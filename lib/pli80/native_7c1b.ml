[@@@warning "-4-40-41-42"]
module R=Pli80_host.Recursive_mapped
module B=Recursive_mapped_bridge
type case={caller:string;entry_step:int;return_step:int;parent_entry_step:int option;
  input:Runner.state_snapshot;output:Runner.state_snapshot;result:R.result;
  entry_memory_sha256:string;final_memory_sha256:string;logical_writes_sha256:string;
  compatibility_writes:(int*int)list;final_writers:B.residue list}
type validated={cases:case list; snapshots:(int*bytes*bytes)list;records:(string*int*bytes)list;input_digest:string}
let cases v=v.cases
let require yes message=if not yes then failwith("Native7C1B: "^message)
let logical_write step before address =
  let site=I8080.Step.pc_before step in
  match I8080.Step.control_flow step with I8080.Step.Call _->false|_->
  if List.mem site[0x9e48;0x9ddf;0x9de3]then false
  else if site=0x9e1e then address=Pli80_host.U16.wrap(before.Runner.sp-1)
  else true
let shadow input =
  let bridge=B.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
  let active=ref[]and previous=ref None and current_origin=ref Analysis.Execution_map.Unknown in
  let cases=ref[]and snapshots=ref[]and records=ref[]in
  let on_bdos_record ~step_index:_=function Cpm.Bdos.Write_record{file;logical_record;data;_}->records:=(file.name,logical_record,Bytes.copy data)::!records|_->()in
  let on_guest_step ~step_index:_ ~before ~after step=
    previous:=Some(!current_origin,before,after,step);
    List.iter(fun(_,_,_,_,_,_,writes,latest)->
      List.iter(function I8080.Step.Write q->
        let site=I8080.Step.pc_before step-0x2200 in
        Hashtbl.replace latest q.address(site,q.value);
        if logical_write step before q.address then writes:=(q.address,q.value,site)::!writes
        |_->())(I8080.Step.memory_accesses step))!active in
  let on_before_instruction ~origin ~step_index boundary=
    current_origin:=origin;let state=boundary.Runner.state in
    (match !active with
    |(entry_step,parent_entry_step,(input:Runner.state_snapshot),entry_memory,call,(p:B.prepared),writes,latest)::rest when state.pc=call.B.resume->
      (match !previous with Some(_,before,after,step)->
        require(I8080.Step.pc_before step=p.result.tree.return_site+0x2200
          &&I8080.Step.control_flow step=I8080.Step.Return{target=Some call.resume;taken=true}
          &&before.sp=input.sp&&after=state)"actual terminal RET ancestry";
        let reads=List.filter_map(function I8080.Step.Read q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses step)in
        require(reads=[input.sp,call.resume land 255;Pli80_host.U16.wrap(input.sp+1),call.resume lsr 8])"RET consumes original CALL slot";
        require(not(Hashtbl.mem latest input.sp)&&not(Hashtbl.mem latest(Pli80_host.U16.wrap(input.sp+1))))"original continuation rewritten"
        |_->assert false);
      let logical=List.map(fun(w:R.write)->w.address,w.value,w.writer)p.result.writes in
      require(List.rev !writes=logical)(Printf.sprintf"logical chronology at entry%d path%s"entry_step p.result.tree.path);
      require(state=p.state)(Printf.sprintf"returned state at entry%d path%s"entry_step p.result.tree.path);
      List.iter(fun(q:B.residue)->require(Hashtbl.find_opt latest q.address=Some(q.writer,q.value))
        (Printf.sprintf"last writer %04X at entry%d"q.address entry_step))p.final_writers;
      require(Hashtbl.length latest=List.length p.final_writers)"omitted final write dependency";
      let post=boundary.copy_memory()in
      if post<>p.memory then (
        let differences=List.init 65536 Fun.id|>List.filter(fun a->Bytes.get post a<>Bytes.get p.memory a)in
        failwith(Printf.sprintf"7C1B full memory at entry%d path%s differs:%s"entry_step p.result.tree.path
          (String.concat","(List.map(fun a->Printf.sprintf"%04X expected%02X got%02X"a(Char.code(Bytes.get post a))(Char.code(Bytes.get p.memory a)))differences))));
      let digest=Native_dispatch.write_digest(List.map(fun(a,v,_)->a,v)logical)in
      cases:={caller=call.coordinate;entry_step;return_step=step_index-1;parent_entry_step;input;output=state;result=p.result;
        entry_memory_sha256=Experiment.sha256_hex entry_memory;final_memory_sha256=Experiment.sha256_hex post;
        logical_writes_sha256=digest;compatibility_writes=p.compatibility_writes;final_writers=p.final_writers}::!cases;
      snapshots:=(entry_step,entry_memory,post)::!snapshots;active:=rest
    |_->());
    if state.pc=0x9e1b then (
      let call=match !previous with Some(origin,before,after,step)->B.verify_call bridge ~origin ~before ~after step ~entry:state|_->failwith"Entry without actual CALL"in
      let parent=match !active with (s,_,_,_,_,_,_,_)::_->Some s|[]->None in
      require((call.runtime_site>=0x9e1b&&call.runtime_site<0x9f53)=(parent<>None))"recursive CALL forest ancestry";
      let memory=boundary.copy_memory()in
      let p=B.prepare bridge ~call ~origin ~state ~memory in
      active:=(step_index,parent,state,memory,call,p,ref[],Hashtbl.create 64)::!active)in
  match Experiment.run ~analysis:Experiment.Execution ~on_before_instruction ~on_guest_step ~on_bdos_record input with
  |Error _ as e->e|Ok result->require(!active=[])"missing nested return";
    Ok({cases=List.sort(fun a b->compare a.entry_step b.entry_step)!cases;snapshots= !snapshots;
      records=List.rev !records;input_digest=Experiment.sha256_hex(Marshal.to_bytes input[])},result)
let roots v=List.filter(fun c->c.parent_entry_step=None)v.cases
let inside_steps v entries=List.filter(fun(step,_)->List.exists(fun c->c.entry_step<step&&step<c.return_step)(roots v))entries|>List.map fst
let record_summaries v=List.map(fun(n,r,b)->n,r,Experiment.sha256_hex b)v.records
let controller ?(exclude_entry_steps=[]) validated input =
  let members=roots validated in
  require(List.for_all(fun step->List.exists(fun c->c.entry_step=step)members)exclude_entry_steps
    &&List.length exclude_entry_steps=List.length(List.sort_uniq compare exclude_entry_steps))"invalid root exclusion";
  let members=List.filter(fun c->not(List.mem c.entry_step exclude_entry_steps))members in
  require(validated.input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]))"source/input proof mismatch";
  let bridge=B.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
  let oracles=List.map(fun c->let _,entry_memory,post_memory=List.find(fun(s,_,_)->s=c.entry_step)validated.snapshots in
    {Native_dispatch.input=c.input;output=c.output;entry_memory;post_memory;logical_digest=c.logical_writes_sha256})members in
  let prepare(previous:Native_dispatch.previous)origin boundary=
    let call=B.verify_call bridge ~origin:previous.origin ~before:previous.before ~after:previous.after previous.step ~entry:boundary.Runner.state in
    let p=B.prepare bridge ~call ~origin ~state:boundary.state ~memory:(boundary.copy_memory())in
    {Native_dispatch.state=p.state;memory=p.memory;logical_writes=List.map(fun(w:R.write)->w.address,w.value)p.result.writes;
     compatibility_writes=p.compatibility_writes}in
  Native_dispatch.create ~image:"PLI1.OVL" ~entry_pc:0x9e1b ~end_pc:0x9f53 ~oracles ~records:validated.records ~prepare
let hybrid v input=Native_dispatch.run input [controller v input]
let cumulative v words balances input=
  let word_steps=inside_steps v(List.map(fun(c:Native_7bbf.case)->c.entry_step,())(Native_7bbf.cases words))in
  let balance_steps=inside_steps v(List.map(fun(c:Native_7b7a.case)->c.entry_step,())(Native_7b7a.cases balances))in
  Native_dispatch.run input[controller v input;Native_7bbf.controller ~exclude_entry_steps:word_steps words input;
    Native_7b7a.controller ~exclude_entry_steps:balance_steps balances input]
