[@@@warning "-4-40-41-42"]
module B=Acquisition_family_bridge
module Q=Native_recursive_parent
open Q
type case=Q.case
type result=Q.result
let cases v=v.Q.cases
let record_summaries=Q.record_summaries
let filesystem_hash=Q.filesystem_hash
let require b m=if not b then failwith("resident output proof: "^m)
let compatibility_writes=Q.compatibility_writes
let prepare bridge offset ~call ~origin boundary=B.prepare bridge (B.Output offset) ~call ~origin boundary
let shadow ?(offset=0x1272) ?(within=[]) ?(run_negatives=true) input=
 let bridge=B.create_with_images ~pli_com:input.Experiment.pli_com ~pli0:input.pli0_ovl ~pli1:input.pli1_ovl ~pli2:input.pli2_ovl in
 let previous=ref None and origin=ref Analysis.Execution_map.Unknown and active=ref None in
 let cases=ref[]and snapshots=ref[]and records=ref[]and root_records=ref[]and service_index=ref 0 in
 let on_bdos_record ~step_index:_=function Cpm.Bdos.Write_record q->records:=(q.file.name,q.logical_record,Bytes.copy q.data)::!records;(if !active<>None then root_records:=(q.file.name,q.logical_record,Bytes.copy q.data)::!root_records)|_->()in
 let on_guest_step ~step_index:_ ~before ~after step=
  previous:=Some{Native_dispatch.origin= !origin;before;after;step};
  match !active with None->()|Some(_,_,_,_,_,_,_,_,writes,latest,calls)->
   (match I8080.Step.control_flow step with I8080.Step.Call{taken=true;_}->calls:=before.Runner.pc::!calls|_->());
   List.iter(function I8080.Step.Write w->Hashtbl.replace latest w.address(before.pc,w.value);
    if before.pc<>0x1abb&&before.pc<>0x1abc&&before.pc<>0x1ac3&&
     not(List.mem(Char.code(Bytes.get(I8080.Step.fetched_bytes step)0))[0xcd;0xc5;0xd5;0xe5;0xf5])then writes:=(w.address,w.value)::!writes|_->())(I8080.Step.memory_accesses step)in
 let on_before_instruction ~origin:o ~step_index (boundary:Runner.instruction_boundary)=
  origin:=o;let state=boundary.state in
  (match !active with
   |Some(entry_step,call,(entry:Runner.state_snapshot),ram,files,dma,(p:B.prepared),(preview:Runner.host_program_result),writes,latest,calls)when state.pc=call.B.resume&&state.sp=entry.sp+2->
    let prev=Option.get !previous in
    require(I8080.Step.control_flow prev.step=I8080.Step.Return{target=Some call.resume;taken=true}&&prev.before.sp=entry.sp)"RET consumer";
    require(state=p.state)"returned state";
    require(boundary.copy_memory()=preview.memory)"full64KiB RAM";
    require(boundary.dma=preview.dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())preview.filesystem)"DMA/filesystem";
    require(!service_index=List.length preview.services)"service count/order";
    let planned_records=List.concat_map(fun(s:Runner.host_service)->List.filter_map(function Cpm.Bdos.Write_record q->Some(q.file.name,q.logical_record,q.data)|_->None)s.events)preview.services in
    require(planned_records=List.rev !root_records)"record chronology and bytes";
    require(List.rev !writes=p.logical_writes)"ordered logical writes";
    let final=Hashtbl.create 128 in List.iter(fun(w:B.write)->Hashtbl.replace final w.address(w.writer,w.value))p.journal;
    Hashtbl.iter(fun address value->require(Hashtbl.find_opt latest address=Some value)(Printf.sprintf"last writer %04X"address))final;
    require(Hashtbl.length final=Hashtbl.length latest)"omitted writer";
    let planned_calls=List.filter_map(fun(w:B.write)->if w.kind="compatibility"&&w.address mod 2=entry.sp mod 2&&Char.code(Bytes.get input.pli_com(w.writer-0x100))=0xcd then Some w.writer else None)p.journal in
    require(List.rev !calls=planned_calls)"child CALL chronology";
    require(not(Hashtbl.mem latest entry.sp)&&not(Hashtbl.mem latest(entry.sp+1)))"original continuation lifetime";
    cases:={Q.caller=call.coordinate;entry_step;return_step=step_index-1;input=entry;output=state;route=(if offset=0x1272 then"pending_REL_padding_and_close"else if offset=0x119e then"counted_bits"else if offset=0x1140 then"append_bit"else"tagged_cached_word");entry_memory_sha256=Experiment.sha256_hex ram;post_memory_sha256=Experiment.sha256_hex preview.memory;stack_cells=List.length(compatibility_writes p);logical_writes=List.length p.logical_writes;prepared=p;services=preview.services;entry_dma=dma;post_dma=preview.dma}::!cases;
    snapshots:=(entry_step,{Q.entry_memory=ram;post_memory=preview.memory;entry_files=files;post_files=boundary.copy_filesystem()})::!snapshots;active:=None
   |_->());
  (match !active with Some(_,_,_,_,_,_,_,(preview:Runner.host_program_result),_,_,_)when state.pc=5->
   let service=List.nth preview.services !service_index in incr service_index;
   require(state=service.resume_state&&boundary.copy_memory()=service.memory_after&&boundary.dma=service.dma_after)"historical ordered service resume boundary"|_->());
  if o=B.origin"PLI.COM"offset&&
   (if within<>[]then List.exists(fun(a,b)->a<step_index&&step_index<b)within
    else offset<>0x1140||(Option.get !previous).before.pc=0x13a1) then(
   require(!active=None)"nested output root";
   let call=B.verify_call bridge (B.Output offset)(Option.get !previous)~entry:state in
   let ram=boundary.copy_memory()and files=boundary.copy_filesystem()and dma=boundary.dma in
   let negative=ref 0 in
   let rejects fn=incr negative;match fn()with exception Invalid_argument _->()|_->failwith(Printf.sprintf"unsupported output accepted offset=%04X negative=%d"offset !negative)in
   let altered edits={boundary with copy_memory=(fun()->let b=Bytes.copy ram in List.iter(fun(a,v)->Bytes.set b a(Char.chr v))edits;b);preview_host_program=(fun p->boundary.preview_host_program{p with effects=List.map(fun(a,v)->Runner.Memory_write(a,v))edits@p.effects})}in
   if run_negatives then(
   rejects(fun()->B.verify_call bridge (B.Output offset){(Option.get !previous)with origin=B.origin"PLI1.OVL"0x02e3}~entry:state);
   rejects(fun()->prepare bridge offset ~call ~origin:o(altered[call.site,0]));
   rejects(fun()->prepare bridge offset ~call ~origin:(B.origin"PLI1.OVL"offset)boundary);
   rejects(fun()->prepare bridge offset ~call ~origin:o{boundary with state={state with sp=0x20b6}});
   rejects(fun()->prepare bridge offset ~call ~origin:o(altered[state.pc,0]));
   rejects(fun()->prepare bridge offset ~call ~origin:o(altered[state.sp,(Char.code(Bytes.get ram state.sp) lxor 1)]));
   List.iter(fun edits->rejects(fun()->prepare bridge offset ~call ~origin:o(altered edits)))[[0x2029,1];[0x1d8a,128];[0x1d8b,8];[0x2155,0x0a;0x2156,0x1d]];
   if offset=0x1272 then(
    rejects(fun()->prepare bridge offset ~call ~origin:o(altered[0x1d05,0]));
    (* Synthetic current indices drive padding; no oracle or live mutation. *)
    List.iter(fun(index,bits)->let p=prepare bridge offset ~call ~origin:o(altered[0x1d8a,index;0x1d8b,bits])in
     let n=List.length(List.filter(fun(w:B.write)->w.writer=0x1269)p.journal)in
     require(n=(if index=0&&bits=0 then 0 else(128-index)*8-bits))"state-driven padding termination") [0,0;127,7;127,1;1,0]);
   );
   if run_negatives && List.mem offset[0x11c3;0x11e5;0x1207]then(
    let cache,prefix=List.assoc offset[0x11c3,(0x20b9,0);0x11e5,(0x20bb,0x40);0x1207,(0x20bd,0x80)]in
    rejects(fun()->prepare bridge offset ~call ~origin:o(altered[0x2155,cache land 255;0x2156,cache lsr 8]));
    rejects(fun()->prepare bridge offset ~call ~origin:o(altered[state.pc+9,prefix lxor 0x40]));
    rejects(fun()->prepare bridge offset ~call ~origin:o(altered[state.pc+1,0xb6]));
    List.iter(fun(index,bits,value)->
     let staged=altered[0x1d8a,index;0x1d8b,bits;cache,0xfe;cache+1,0xfd]in
     let staged={staged with state={state with b=value lsr 8;c=value land 255}}in
     let plan=prepare bridge offset ~call ~origin:o staged in
     let result=match staged.preview_host_program plan.program with Ok r->r|Error e->failwith e in
     let buffer=Bytes.sub ram 0x1d0a 128 and cursor=ref index and bit=ref bits and records=ref[]in
     for n=0 to 17 do
      let incoming=if n<2 then(prefix lsr(7-n))land 1 else if n<10 then(value lsr(9-n))land 1 else(value lsr(25-n))land 1 in
      let old=Char.code(Bytes.get buffer !cursor)in Bytes.set buffer !cursor(Char.chr(((old lsl 1)lor incoming)land 255));
      incr bit;if !bit=8 then(bit:=0;incr cursor;if !cursor=128 then(records:=Bytes.copy buffer::!records;cursor:=0))
     done;
     require(Bytes.sub result.memory 0x1d0a 128=buffer)"independent tagged bit stream";
     require(Char.code(Bytes.get result.memory 0x1d8a)= !cursor&&Char.code(Bytes.get result.memory 0x1d8b)= !bit)"wrapping cursor";
     require(Char.code(Bytes.get result.memory cache)=value land 255&&Char.code(Bytes.get result.memory(cache+1))=value lsr 8)"word cache provenance";
     let actual=List.concat_map(fun(s:Runner.host_service)->List.filter_map(function Cpm.Bdos.Write_record r->Some r.data|_->None)s.events)result.services in
     require(actual=List.rev !records)"synthetic boundary record bytes";
     require(List.map(fun(s:Runner.host_service)->s.call_state.c)result.services=(if !records=[]then[]else[26;21]))"synthetic flush service chronology"
    )[1,0,0x0001;1,0,0x0100;127,7,0xa55a]);
   require(boundary.copy_memory()=ram&&boundary.dma=dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())files)"rejection leaked live state";
   let p=prepare bridge offset ~call ~origin:o boundary in
   let preview=match boundary.preview_host_program p.program with Ok r->r|Error e->failwith e in
   root_records:=[];service_index:=0;active:=Some(step_index,call,state,ram,files,dma,p,preview,ref[],Hashtbl.create 128,ref[]))in
 match Experiment.run ~analysis:Experiment.Execution ~on_guest_step ~on_before_instruction ~on_bdos_record input with
 |Error _->failwith"historical output experiment"|Ok historical->require(!active=None)"missing output return";Ok{Q.cases=List.rev !cases;pending=[];historical;snapshots= !snapshots;records=List.rev !records;input_digest=Experiment.sha256_hex(Marshal.to_bytes input[])}

let controller ?(offset=0x1272) ?(exclude_entry_steps=[]) v input=
 require(v.pending=[])"cannot enable an unfinished logical proof";
 let first,last=B.bounds(B.Output offset) in
 require(v.input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]))"source/input proof mismatch";
 let exclusions=List.sort_uniq compare exclude_entry_steps in
 require(List.length exclusions=List.length exclude_entry_steps&&List.for_all(fun n->List.exists(fun c->c.entry_step=n)(cases v))exclusions)"invalid exclusions";
 let selected=List.filter(fun c->not(List.mem c.entry_step exclusions))(cases v) in
 let bridge=B.create_with_images ~pli_com:input.Experiment.pli_com ~pli0:input.pli0_ovl ~pli1:input.pli1_ovl ~pli2:input.pli2_ovl in
 let remaining=ref selected and pending=ref None in
 let prepare previous origin (boundary:Runner.instruction_boundary)=
  let c=match !remaining with q::_->q|[]->failwith"Additional acquisition parent root"in
  let s=List.assoc c.entry_step v.snapshots in
  require(boundary.dma=c.entry_dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())s.entry_files)"entry service_result state proof";
  let call=B.verify_call bridge (B.Output offset) previous ~entry:boundary.state in
  let p=prepare bridge offset ~call ~origin boundary in
  require(p.journal=c.prepared.journal)"ordered compatibility/last-writer proof mismatch";
  let validate(r:Runner.host_program_result)=
   match p.program.validate r with Error _ as e->e|Ok()->
   if r.memory<>s.post_memory||r.dma<>c.post_dma||r.services<>c.services
    ||not(Cpm.Filesystem.equal r.filesystem s.post_files)then Error"root service_result/post-state proof mismatch"else Ok()in
  let program={p.program with validate}in
  let preview=match boundary.preview_host_program program with Ok q->q|Error e->failwith e in
  pending:=Some program;remaining:=List.tl !remaining;
  {Native_dispatch.state=p.state;memory=preview.memory;logical_writes=p.logical_writes;compatibility_writes=compatibility_writes p}in
 let oracles=List.map(fun c->let s=List.assoc c.entry_step v.snapshots in
  {Native_dispatch.input=c.input;output=c.output;entry_memory=s.entry_memory;post_memory=s.post_memory;
   logical_digest=Native_dispatch.write_digest c.prepared.logical_writes})selected in
 let t=Native_dispatch.create ~image:"PLI.COM" ~entry_pc:(first+0x100) ~end_pc:(last+0x100) ~oracles ~records:v.records ~prepare in
 Native_dispatch.with_host_program t(fun _ _->let p=Option.get !pending in pending:=None;p)
let compare_external v (r:Experiment.result)=
 require(Cpm.Filesystem.equal r.filesystem v.historical.filesystem)"final filesystem";
 let event(e:Experiment.file_event)=e.operation,e.file,e.succeeded,e.logical_record,e.byte_range in
 require(List.map event r.file_events=List.map event v.historical.file_events)"file event order";
 require(r.console=v.historical.console)"complete console chronology";
 require(r.int_bytes=v.historical.int_bytes&&r.rel_bytes=v.historical.rel_bytes)"INT/REL identity"
let run v input controllers=match Native_dispatch.run input controllers with Error _ as e->e|Ok(_,r)as q->compare_external v r;q
let single ?(offset=0x1272) v input=run v input[controller ~offset v input]
