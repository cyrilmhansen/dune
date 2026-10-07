[@@@warning "-4-40-41-42"]
(* Independent logical/outer proofs and bounded native root controller. *)
module B=Reentrant_acquisition_bridge
module H=Pli80_host.Reentrant_acquisition
type case={caller:string;entry_step:int;return_step:int;input:Runner.state_snapshot;output:Runner.state_snapshot;
 route:H.route;entry_memory_sha256:string;post_memory_sha256:string;stack_cells:int;logical_writes:int;prepared:B.prepared;services:Runner.host_service list;entry_dma:int;post_dma:int}
type pending={pending_caller:string;pending_entry_step:int;entry_sp:int;reason:string}
type snapshot={entry_memory:bytes;post_memory:bytes;entry_files:Cpm.Filesystem.t;post_files:Cpm.Filesystem.t}
type result={cases:case list;pending:pending list;historical:Experiment.result;snapshots:(int*snapshot)list;records:(string*int*bytes)list;input_digest:string}
let cases v=List.filter(fun(c:case)->not(List.exists(fun(p:case)->p.entry_step<c.entry_step&&c.return_step<p.return_step)v.cases))v.cases
let filesystem_hash=Native_acquisition_parent.filesystem_hash
let record_summaries v=List.map(fun(n,r,b)->n,r,Experiment.sha256_hex b)v.records
let require b m=if not b then failwith("reentrant acquisition proof: "^m)
let shadow input=
 let bridge=B.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
 let previous=ref None and current_origin=ref Analysis.Execution_map.Unknown and active=ref [] in
 let cases=ref[]and pending=ref[]and snapshots=ref[]and all_records=ref[]and composed=ref[]and logical_trees=ref[]in
 let on_bdos_record ~step_index:_=function Cpm.Bdos.Write_record q->
  all_records:=(q.file.name,q.logical_record,Bytes.copy q.data)::!all_records;List.iter(fun(_,_,_,_,_,_,_,_,_,_,records)->records:=(q.file.name,q.logical_record,Bytes.copy q.data)::!records)!active|_->()in
 let on_guest_step ~step_index:_ ~before ~after step=
  previous:=Some{Native_dispatch.origin= !current_origin;before;after;step};
  List.iter(fun(_,_,_,_,_,_,_,_,writes,latest,_)->
   List.iter(function I8080.Step.Write q->
    Hashtbl.replace latest q.address(I8080.Step.pc_before step,q.value);
    if ((I8080.Step.pc_before step=0x4712&&q.address=before.sp-1)||
      (Native_7c1b.logical_write step before q.address&&
       (match I8080.Step.control_flow step with I8080.Step.Call _->false|_->true)&&
       not(List.mem(Char.code(Bytes.get(I8080.Step.fetched_bytes step)0))[0xc5;0xd5;0xe5;0xf5])))
      &&not(List.mem(I8080.Step.pc_before step)[0x9f82;0x1abb;0x1abc;0x9d09])
    then writes:=(q.address,q.value)::!writes|_->())(I8080.Step.memory_accesses step))!active in
 let on_before_instruction ~origin:o ~step_index (boundary:Runner.instruction_boundary)=
  current_origin:=o;let state=boundary.state in
  (match !active with
  |(entry_step,call,(entry:Runner.state_snapshot),ram,(_files:Cpm.Filesystem.t),_dma,(p:B.prepared),(preview:Runner.host_program_result),writes,latest,records)::rest
    when state.pc=call.B.resume&&state.sp=entry.sp+2->
   let prev=Option.get !previous in
   require(I8080.Step.pc_before prev.step=0x844c&&prev.before.sp=entry.sp&&prev.after=state
    &&I8080.Step.control_flow prev.step=I8080.Step.Return{target=Some call.resume;taken=true})"outer RET ancestry";
   require(state=p.state)"return registers/flags/SP/PC";
   let actual=boundary.copy_memory()in
   if actual<>preview.memory then(
    let differences=List.init 65536 Fun.id|>List.filter(fun a->Bytes.get actual a<>Bytes.get preview.memory a)in
    failwith("root memory differences "^String.concat","(List.map(fun a->Printf.sprintf"%04X:%02X/%02X"a(Char.code(Bytes.get actual a))(Char.code(Bytes.get preview.memory a)))differences)));
   require(Cpm.Filesystem.equal(boundary.copy_filesystem())preview.filesystem&&boundary.dma=preview.dma)"DMA/filesystem";
   require(List.rev !writes=p.logical_writes)"ordered logical writes";
   let final=Hashtbl.create 64 in List.iter(fun(w:B.write)->Hashtbl.replace final w.address(w.writer,w.value))p.journal;
   Hashtbl.iter(fun address value->require(Hashtbl.find_opt latest address=Some value)(Printf.sprintf"final writer %04X"address))final;
   require(Hashtbl.length final=Hashtbl.length latest)"missing observed publication";
   let planned=List.concat_map(fun(s:Runner.host_service)->List.filter_map(function
    Cpm.Bdos.Write_record q->Some(q.file.name,q.logical_record,q.data)|_->None)s.events)preview.services in
   require(planned=List.rev !records)"record chronology/data";
   cases:={caller=call.coordinate;entry_step;return_step=step_index-1;input=entry;output=state;route=p.result.route;
    entry_memory_sha256=Experiment.sha256_hex ram;post_memory_sha256=Experiment.sha256_hex actual;
    prepared=p;services=preview.services;entry_dma=_dma;post_dma=preview.dma;stack_cells=List.length(List.sort_uniq compare(List.map fst p.compatibility_writes));logical_writes=List.length p.logical_writes}::!cases;
   snapshots:=(entry_step,{entry_memory=ram;post_memory=actual;entry_files=_files;post_files=boundary.copy_filesystem()})::!snapshots;
   active:=rest
  |_->());
  if o=B.origin"PLI1.OVL"0x6223 then(
   let call=B.verify_call bridge(Option.get !previous)~entry:state in
   let ram=boundary.copy_memory()and files=boundary.copy_filesystem()and dma=boundary.dma in
   let rejects fn=match fn()with exception Invalid_argument _->()|_->failwith"malformed root accepted"in
   rejects(fun()->B.verify_call bridge {(Option.get !previous)with origin=B.origin"PLI2.OVL"0x6273}~entry:state);
   rejects(fun()->B.prepare bridge ~call ~origin:(B.origin"PLI2.OVL"0x6223)boundary);
   rejects(fun()->B.prepare bridge ~call ~origin:o {boundary with state={state with pc=state.pc+1}});
   rejects(fun()->B.prepare bridge ~call ~origin:o {boundary with state={state with c=256}});
   rejects(fun()->B.prepare bridge ~call ~origin:o {boundary with state={state with sp=0xa945}});
   let changed address=let value=(Char.code(Bytes.get ram address)+1)land 255 in {boundary with copy_memory=(fun()->let b=Bytes.copy ram in Bytes.set b address(Char.chr value);b);preview_host_program=(fun p->boundary.preview_host_program{p with effects=Runner.Memory_write(address,value)::p.effects})}in
   List.iter(fun address->rejects(fun()->B.prepare bridge ~call ~origin:o(changed address)))[0x8423;0x2416;0x459c;state.sp];
   require(boundary.copy_memory()=ram&&boundary.dma=dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())files)"negative preparation leaked live state";
   let logical=ref[]in
   match B.prepare ~observe:(fun call entry memory p service_result->logical:=(call,entry,Bytes.copy memory,p,service_result)::!logical)bridge ~call ~origin:o boundary with
   |exception Invalid_argument m when m="reentrant acquisition bridge: required acquisition-family implementation is unfinished"->
    require(boundary.copy_memory()=ram&&boundary.dma=dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())files)"rejected preparation leaked live state";
    pending:={pending_caller=call.coordinate;pending_entry_step=step_index;entry_sp=state.sp;reason=m}::!pending
   |exception Acquisition_family_bridge.Unfinished(_,_,_,_)->
    require(boundary.copy_memory()=ram&&boundary.dma=dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())files)"unfinished field80 leaked live state";
    pending:={pending_caller=call.coordinate;pending_entry_step=step_index;entry_sp=state.sp;reason="field80 recursive family preparation unfinished"}::!pending
   |p->
    if !active=[]then(composed:= !logical@ !composed;logical_trees:=(step_index,List.rev !logical)::!logical_trees);
    if p.result.route<>H.Route_b then List.iter(fun off->rejects(fun()->B.prepare bridge ~call ~origin:o(changed(off+0x2200))))[0x6108;0x5edc;0x6273;0x671f;0x3304;0x5031];
    let preview=match boundary.preview_host_program p.program with Ok q->q|Error e->failwith e in
    active:=(step_index,call,state,ram,files,dma,p,preview,ref[],Hashtbl.create 64,ref[])::!active)in
 match Experiment.run ~analysis:Experiment.Execution ~on_guest_step ~on_before_instruction ~on_bdos_record input with
 |Error _ as e->e|Ok historical->require(!active=[])"omitted return";
  List.iter(fun(c:case)->
   let actual=List.filter(fun(e:Experiment.file_event)->c.entry_step<=e.step_index&&e.step_index<=c.return_step)historical.file_events in
   let planned=List.concat_map(fun(s:Runner.host_service)->s.file_events)c.services in
   let operation=function Experiment.Open->Cpm.Bdos.Open|Close->Close|Make->Make|Delete->Delete|Sequential_read->Sequential_read|Sequential_write->Sequential_write in
   require(List.map(fun(e:Experiment.file_event)->operation e.operation,e.file,e.succeeded,e.logical_record)actual=
    List.map(fun(e:Cpm.Bdos.file_event)->e.operation,e.file,e.succeeded,e.logical_record)planned)"logical/root file-event chronology")!cases;
  List.iter(fun(step,children)->
   let outer=List.find(fun(c:case)->c.entry_step=step)!cases in
   let expected=List.filter(fun(c:case)->outer.entry_step<=c.entry_step&&c.return_step<=outer.return_step)!cases|>List.sort(fun(x:case)(y:case)->compare x.return_step y.return_step)in
   require(List.map(fun(call,entry,_,(p:B.prepared),_)->call.B.coordinate,entry,p.state,p.result.route)children=
    List.map(fun(c:case)->c.caller,c.input,c.output,c.route)expected)"first/second recursive invocation chronology")!logical_trees;
  require(List.length !composed=List.length !cases)"composed logical invocation count";
  List.iter(fun(call,entry,memory,(p:B.prepared),(service_result:Runner.host_program_result))->
   let c=List.find(fun(c:case)->c.input=entry&&c.caller=call.B.coordinate)!cases in
   let snap=List.assoc c.entry_step !snapshots in
   require(memory=snap.entry_memory&&service_result.memory=snap.post_memory&&p.state=c.output&&p.result.route=c.route)"recursive logical checkpoint state/RAM";
   require(p.journal=c.prepared.journal&&p.logical_writes=c.prepared.logical_writes)"recursive logical checkpoint writers/depth/chronology";
   require(service_result.dma=c.post_dma&&service_result.services=c.services&&Cpm.Filesystem.equal service_result.filesystem snap.post_files)"recursive logical checkpoint service_result effects")!composed;
  Ok{cases=List.sort(fun(x:case)(y:case)->compare x.entry_step y.entry_step)!cases;pending=List.rev !pending;historical;snapshots= !snapshots;records=List.rev !all_records;input_digest=Experiment.sha256_hex(Marshal.to_bytes input[])}

let controller ?(exclude_entry_steps=[]) v input=
 require(v.pending=[])"cannot enable an unfinished logical proof";
 let first,last=0x6223,0x624d in
 require(v.input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]))"source/input proof mismatch";
 let exclusions=List.sort_uniq compare exclude_entry_steps in
 require(List.length exclusions=List.length exclude_entry_steps&&List.for_all(fun n->List.exists(fun c->c.entry_step=n)(cases v))exclusions)"invalid exclusions";
 let selected=List.filter(fun c->not(List.mem c.entry_step exclusions))(cases v) in
 let bridge=B.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
 let remaining=ref selected and pending=ref None in
 let prepare previous origin (boundary:Runner.instruction_boundary)=
  let c=match !remaining with q::_->q|[]->failwith"Additional acquisition parent root"in
  let s=List.assoc c.entry_step v.snapshots in
  require(boundary.dma=c.entry_dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())s.entry_files)"entry service_result state proof";
  let call=B.verify_call bridge previous ~entry:boundary.state in
  let p=B.prepare bridge ~call ~origin boundary in
  let validate(r:Runner.host_program_result)=
   match p.program.validate r with Error _ as e->e|Ok()->
   if r.memory<>s.post_memory||r.dma<>c.post_dma||r.services<>c.services
    ||not(Cpm.Filesystem.equal r.filesystem s.post_files)then Error"root service_result/post-state proof mismatch"else Ok()in
  let program={p.program with validate}in
  let preview=match boundary.preview_host_program program with Ok q->q|Error e->failwith e in
  pending:=Some program;remaining:=List.tl !remaining;
  {Native_dispatch.state=p.state;memory=preview.memory;logical_writes=p.logical_writes;compatibility_writes=p.compatibility_writes}in
 let oracles=List.map(fun c->let s=List.assoc c.entry_step v.snapshots in
  {Native_dispatch.input=c.input;output=c.output;entry_memory=s.entry_memory;post_memory=s.post_memory;
   logical_digest=Native_dispatch.write_digest c.prepared.logical_writes})selected in
 let t=Native_dispatch.create ~image:"PLI1.OVL" ~entry_pc:(first+0x2200) ~end_pc:(last+0x2200) ~oracles ~records:v.records ~prepare in
 Native_dispatch.with_host_program t(fun _ _->let p=Option.get !pending in pending:=None;p)
let compare_external v (r:Experiment.result)=
 require(Cpm.Filesystem.equal r.filesystem v.historical.filesystem)"final filesystem";
 let event(e:Experiment.file_event)=e.operation,e.file,e.succeeded,e.logical_record,e.byte_range in
 require(List.map event r.file_events=List.map event v.historical.file_events)"file event order";
 require(r.int_bytes=v.historical.int_bytes&&r.rel_bytes=v.historical.rel_bytes)"INT/REL identity"
let run v input controllers=match Native_dispatch.run input controllers with Error _ as e->e|Ok(_,r)as q->compare_external v r;q
let single v input=run v input[controller v input]
