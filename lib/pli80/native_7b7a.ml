[@@@warning "-4-40-41-42"]
type case = {
  caller : string; entry_step : int; return_step : int;
  input : Runner.state_snapshot; output : Runner.state_snapshot;
  result : Pli80_host.Balance_scan.result;
  entry_memory_sha256 : string; final_memory_sha256 : string;
  logical_writes_sha256 : string; compatibility_writes : (int * int) list;
}
type validated = { cases : case list; input_digest : string;
  records : (string * int * bytes) list; snapshots : (bytes * bytes) list }
let cases v=v.cases
let require b message=if not b then failwith("Native7B7A: "^message)
let digest writes=Experiment.sha256_hex(Bytes.of_string(String.concat";"(List.map(fun(a,v)->Printf.sprintf"%04X:%02X"a v)writes)))
let shadow input =
  let bridge=Balance_scan_bridge.create ~pli1:input.Experiment.pli1_ovl in
  let cases=ref[]and snapshots=ref[]and records=ref[]and active=ref None and previous=ref None and current_origin=ref Analysis.Execution_map.Unknown in
  let on_bdos_record ~step_index:_ = function Cpm.Bdos.Write_record{file;logical_record;data;_}->records:=(file.name,logical_record,Bytes.copy data)::!records|_->()in
  let on_guest_step ~step_index:_ ~before ~after step=
    previous:=Some(!current_origin,before,after,step);
    match !active with None->()|Some(_,_,_,_,(prepared:Balance_scan_bridge.prepared),writes,latest)->
    List.iter(function I8080.Step.Write q->
      if List.mem_assoc q.address prepared.compatibility_writes then Hashtbl.replace latest q.address(I8080.Step.pc_before step,q.value)
      else writes:=(q.address,q.value)::!writes|_->())(I8080.Step.memory_accesses step)in
  let on_before_instruction ~origin ~step_index boundary=
    current_origin:=origin;
    let state=boundary.Runner.state in
    if state.pc=0x9d7a then (
      require(!active=None)"scan reentry";
      let call=match !previous with Some(origin,before,after,step)->Balance_scan_bridge.verify_call bridge ~origin ~before ~after step ~entry:state|None->failwith"Missing caller"in
      let memory=boundary.copy_memory()in
      let prepared=Balance_scan_bridge.prepare bridge ~call ~origin ~state ~memory in
      active:=Some(step_index,state,memory,call,prepared,ref[],Hashtbl.create 4))
    else match !active with
    |Some(entry_step,input,entry_memory,call,prepared,writes,latest)when state.pc=call.resume->
      (match !previous with Some(_,_,_,step)->require(I8080.Step.pc_before step=0x9da1 && I8080.Step.control_flow step=I8080.Step.Return{target=Some call.resume;taken=true})"actual RET"|_->assert false);
      let logical=List.map(fun(w:Pli80_host.Mapped_lookup.write)->w.address,w.value)prepared.result.writes in
      require(List.rev !writes=logical)"logical write chronology";
      require(state=prepared.state)"returned registers/flags";
      List.iter(fun(a,v)->let site=if a=Pli80_host.U16.wrap(input.sp-4)||a=Pli80_host.U16.wrap(input.sp-3)then 0x9c6b else 0x9d87 in
        require(Hashtbl.find_opt latest a=Some(site,v))"final residue writer")prepared.compatibility_writes;
      let post=boundary.copy_memory()in require(post=prepared.memory)"full64KiB post-state";
      snapshots:=(entry_memory,post)::!snapshots;
      cases:={caller=call.coordinate;entry_step;return_step=step_index-1;input;output=state;result=prepared.result;
        entry_memory_sha256=Experiment.sha256_hex entry_memory;final_memory_sha256=Experiment.sha256_hex post;
        logical_writes_sha256=digest logical;compatibility_writes=prepared.compatibility_writes}::!cases;active:=None
    |_->()in
  match Experiment.run ~analysis:Experiment.Execution ~on_before_instruction ~on_guest_step ~on_bdos_record input with
  |Error _ as e->e|Ok result->require(!active=None)"missing return";
    Ok({cases=List.rev !cases;snapshots=List.rev !snapshots;records=List.rev !records;input_digest=Experiment.sha256_hex(Marshal.to_bytes input [])},result)

let record_summaries v=List.map(fun(n,r,b)->n,r,Experiment.sha256_hex b)v.records
let controller ?(exclude_entry_steps=[]) validated input =
  require(validated.input_digest=Experiment.sha256_hex(Marshal.to_bytes input []))"source/input proof mismatch";
  require(List.for_all(fun s->List.exists(fun c->c.entry_step=s)validated.cases)exclude_entry_steps
    &&List.length exclude_entry_steps=List.length(List.sort_uniq compare exclude_entry_steps))"invalid nested invocation exclusion";
  let bridge=Balance_scan_bridge.create ~pli1:input.Experiment.pli1_ovl in
  let selected=List.combine validated.cases validated.snapshots|>List.filter(fun(c,_)->not(List.mem c.entry_step exclude_entry_steps))in
  let oracles=List.map(fun(c,(entry_memory,post_memory))->
    {Native_dispatch.input=c.input;output=c.output;entry_memory;post_memory;logical_digest=c.logical_writes_sha256})selected in
  let prepare(previous:Native_dispatch.previous)origin boundary=
    let call=Balance_scan_bridge.verify_call bridge ~origin:previous.origin ~before:previous.before ~after:previous.after previous.step ~entry:boundary.Runner.state in
    let p=Balance_scan_bridge.prepare bridge ~call ~origin ~state:boundary.state ~memory:(boundary.copy_memory())in
    {Native_dispatch.state=p.state;memory=p.memory;
     logical_writes=List.map(fun(w:Pli80_host.Mapped_lookup.write)->w.address,w.value)p.result.writes;
     compatibility_writes=p.compatibility_writes}in
  Native_dispatch.create ~image:"PLI1.OVL" ~entry_pc:0x9d7a ~end_pc:0x9da2 ~oracles ~records:validated.records ~prepare
let hybrid validated input=
  match Native_dispatch.run input [controller validated input]with
  |Error _ as e->e|Ok([count],result)->Ok(count,result)|_->assert false
let cumulative validated word_validated input=
  match Native_dispatch.run input [Native_7bbf.controller word_validated input;controller validated input]with
  |Error _ as e->e|Ok([words;balances],result)->Ok((words,balances),result)|_->assert false
