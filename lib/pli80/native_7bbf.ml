[@@@warning "-4-40-41-42"]
type case = {
  entry_step : int; return_step : int; input : Runner.state_snapshot;
  output : Runner.state_snapshot; result : Pli80_host.Packed_scan.result;
  entry_memory_sha256 : string; final_memory_sha256 : string;
  logical_writes_sha256 : string; compatibility_writes : (int * int) list;
}
type validated = { cases : case list; input_digest : string; records : (string * int * bytes) list; snapshots : (bytes * bytes) list }
let cases v = v.cases
let record_summaries v = List.map(fun(n,r,b)->n,r,Experiment.sha256_hex b)v.records
(* Same-process value binding only, not a persistent snapshot/IR format. *)
let input_digest input = Experiment.sha256_hex (Marshal.to_bytes input [])
let require yes message = if not yes then failwith("Native7BBF: "^message)
let write_digest writes =
  Experiment.sha256_hex(Bytes.of_string(String.concat ";" (List.map(fun(a,v)->Printf.sprintf"%04X:%02X"a v)writes)))
let shadow input =
  let bridge=Packed_scan_bridge.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
  let records=ref [] and snapshots=ref [] in
  let on_bdos_record ~step_index:_ = function
    |Cpm.Bdos.Write_record{file;logical_record;data;_}->records:=(file.name,logical_record,Bytes.copy data)::!records
    |_->() in
  let active=ref None and previous=ref None and cases=ref [] in
  let on_guest_step ~step_index:_ ~before ~after step =
    previous:=Some(before,after,step);
    match !active with
    |None->()
    |Some(_,entry,_,(prepared:Packed_scan_bridge.prepared),writes,latest)->
      List.iter(function
        |I8080.Step.Write q->
          let frame=entry.Runner.sp in
          if List.exists(fun(a,_)->a=q.address)prepared.compatibility_writes then
            Hashtbl.replace latest q.address (I8080.Step.pc_before step,q.value)
          else (
            require (q.address<>frame && q.address<>Pli80_host.U16.wrap(frame+1)) "operation rewrote original CALL slot";
            writes:=(q.address,q.value)::!writes)
        |_->())(I8080.Step.memory_accesses step) in
  let on_before_instruction ~origin ~step_index boundary =
    let state=boundary.Runner.state in
    if state.pc=0x9dbf then (
      require (!active=None) "unexpected recursive/reentered scan";
      (match !previous with Some(before,after,step)->Packed_scan_bridge.verify_call ~before ~after step ~entry:state|None->failwith"Missing CALL writer");
      let memory=boundary.copy_memory() in
      let prepared=Packed_scan_bridge.prepare bridge ~origin ~state ~memory in
      active:=Some(step_index,state,memory,prepared,ref [],Hashtbl.create 6))
    else if state.pc=0x9e3a then (match !active with
      |None->()
      |Some(entry_step,input,entry_memory,prepared,writes,latest)->
        (match !previous with Some(_,_,step)->require(I8080.Step.pc_before step=0x9e1a && I8080.Step.control_flow step=I8080.Step.Return{target=Some 0x9e3a;taken=true})"historical RET identity"|None->assert false);
        let logical=List.map(fun(w:Pli80_host.Packed_scan.write)->w.address,w.value)prepared.result.writes in
        require (List.rev !writes=logical) "logical write chronology differs";
        require (state=prepared.state) "returned register/flag state differs";
        List.iter(fun(a,v)->
          let site=if a=Pli80_host.U16.wrap(input.sp-6) || a=Pli80_host.U16.wrap(input.sp-5) then 0x9df3 else if a=Pli80_host.U16.wrap(input.sp-4) || a=Pli80_host.U16.wrap(input.sp-3) then 0x9df7 else 0x9e14 in
          require (Hashtbl.find_opt latest a=Some(site,v)) "stack residue latest writer differs")prepared.compatibility_writes;
        let historical=boundary.copy_memory() in
        require (historical=prepared.memory) "final full64KiB memory differs";
        snapshots:=(entry_memory,historical)::!snapshots;
        let entry_memory_sha256=Experiment.sha256_hex entry_memory in
        cases:={entry_step;return_step=step_index-1;input;output=state;result=prepared.result;entry_memory_sha256;
          final_memory_sha256=Experiment.sha256_hex historical;logical_writes_sha256=write_digest logical;
          compatibility_writes=prepared.compatibility_writes}::!cases;
        active:=None) in
  match Experiment.run ~analysis:Experiment.Execution ~on_bdos_record ~on_guest_step ~on_before_instruction input with
  |Error _ as e->e
  |Ok result->require(!active=None)"scan never resumed";Ok({cases=List.rev !cases;input_digest=input_digest input;records=List.rev !records;snapshots=List.rev !snapshots},result)

let controller validated input =
  require (validated.input_digest=input_digest input) "shadow proof belongs to another input";
  let bridge=Packed_scan_bridge.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
  let oracles=List.map2(fun c (entry_memory,post_memory)->
    {Native_dispatch.input=c.input;output=c.output;entry_memory;post_memory;logical_digest=c.logical_writes_sha256})validated.cases validated.snapshots in
  let prepare (previous:Native_dispatch.previous) origin boundary=
    Packed_scan_bridge.verify_call ~before:previous.before ~after:previous.after previous.step ~entry:boundary.Runner.state;
    let p=Packed_scan_bridge.prepare bridge ~origin ~state:boundary.state ~memory:(boundary.copy_memory())in
    {Native_dispatch.state=p.state;memory=p.memory;
     logical_writes=List.map(fun(w:Pli80_host.Packed_scan.write)->w.address,w.value)p.result.writes;
     compatibility_writes=p.compatibility_writes}in
  Native_dispatch.create ~image:"PLI1.OVL" ~entry_pc:0x9dbf ~end_pc:0x9e1b ~oracles ~records:validated.records ~prepare

let hybrid validated input =
  match Native_dispatch.run input [controller validated input]with
  |Error _ as e->e|Ok([count],result)->Ok(count,result)|_->assert false
