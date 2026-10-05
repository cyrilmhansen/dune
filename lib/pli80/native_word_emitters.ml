[@@@warning "-4-40-41-42"]
module B=Word_emitter_bridge
type case={caller:string;entry_step:int;return_step:int;parent_entry_step:int option;
 input:Runner.state_snapshot;output:Runner.state_snapshot;result:B.result;
 logical_writes:(int*int)list;compatibility_writes:(int*int)list;
 residue_writers:(int*int*int)list;services:Runner.host_service list;
 entry_cells:(int*int)list;entry_memory_sha256:string;post_memory_sha256:string;entry_dma:int;post_dma:int}
type snapshot={entry_memory:bytes;post_memory:bytes;entry_files:Cpm.Filesystem.t;post_files:Cpm.Filesystem.t}
type validated={cases:case list;snapshots:(int*snapshot)list;records:(string*int*bytes)list;
 input_digest:string;historical:Experiment.result}
let cases v=v.cases
let record_summaries v=List.map(fun(n,r,b)->n,r,Experiment.sha256_hex b)v.records
let operation c=match c.result with B.Word _->B.Mapped_word|B.Emission(s,_)->if s.low_wrapper then B.Low else B.High
let selected op v=List.filter(fun c->operation c=op)v.cases
let require b msg=if not b then failwith("Native word emitters: "^msg)
let shadow input =
 let bridge=B.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
 let previous=ref None and origin=ref Analysis.Execution_map.Unknown and active=ref[]in
 let cases=ref[]and snapshots=ref[]and records=ref[]in
 let on_bdos_record ~step_index:_=function Cpm.Bdos.Write_record{file;logical_record;data;_}->records:=(file.name,logical_record,Bytes.copy data)::!records|_->()in
 let on_guest_step ~step_index:_ ~before ~after step=
  previous:=Some{Native_dispatch.origin= !origin;before;after;step};
  List.iter(fun(_,_,_,(entry:Runner.state_snapshot),_,_,_,_,_,writes,latest)->
   List.iter(function I8080.Step.Write q->
    Hashtbl.replace latest q.address(I8080.Step.pc_before step,q.value);
    let depth=if entry.pc=0x9c79 then 0 else 12 in
    let stack=List.init(depth+2)(fun i->Pli80_host.U16.wrap(entry.sp-depth+i))in
    if not(List.mem q.address stack)then writes:=(q.address,q.value)::!writes|_->())
    (I8080.Step.memory_accesses step))!active in
 let on_before_instruction ~origin:o ~step_index (boundary:Runner.instruction_boundary)=
  origin:=o;let state=boundary.state in
  (match !active with
   |(entry_step,parent,call,(entry:Runner.state_snapshot),ram,files,dma,(p:B.prepared),(preview:Runner.host_program_result),writes,latest)::rest when state.pc=call.B.resume->
    let prev=Option.get !previous in
    let _,end_offset=B.extent call.operation in
    require(I8080.Step.pc_before prev.step=end_offset+0x2200-1 &&prev.before.sp=entry.sp&&prev.after=state
     &&I8080.Step.control_flow prev.step=I8080.Step.Return{target=Some call.resume;taken=true})"outer original hardware RET ancestry";
    let reads=List.filter_map(function I8080.Step.Read q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses prev.step)in
    require(reads=[entry.sp,call.resume land 255;Pli80_host.U16.wrap(entry.sp+1),call.resume lsr 8])"original slot RET consumer";
    require(not(Hashtbl.mem latest entry.sp)&&not(Hashtbl.mem latest(Pli80_host.U16.wrap(entry.sp+1))))"original continuation changed";
    require(List.rev !writes=p.logical_writes)"logical write chronology";
    require(state=p.state)"all returned registers/flags";
    require(boundary.copy_memory()=preview.memory)"full64KiB memory identity";
    require(Cpm.Filesystem.equal(boundary.copy_filesystem())preview.filesystem&&boundary.dma=preview.dma)"complete external state";
    let final=Hashtbl.create 20 in
    List.iter(fun(a,v,writer)->Hashtbl.replace final a(writer,v))p.residue_writers;
    Hashtbl.iter(fun a q->require(Hashtbl.find_opt latest a=Some q)"derived exact last stack writer")final;
    cases:={caller=call.coordinate;entry_step;return_step=step_index-1;parent_entry_step=parent;input=entry;output=state;result=p.result;
     logical_writes=p.logical_writes;compatibility_writes=p.compatibility_writes;residue_writers=p.residue_writers;services=preview.services;
     entry_cells=List.map(fun a->a,Char.code(Bytes.get ram a))[0xae38;0xae39;0xae4f;0xae50;0xae52;0xae53];
     entry_memory_sha256=Experiment.sha256_hex ram;post_memory_sha256=Experiment.sha256_hex preview.memory;
     entry_dma=dma;post_dma=preview.dma}::!cases;
    snapshots:=(entry_step,{entry_memory=ram;post_memory=preview.memory;entry_files=files;post_files=preview.filesystem})::!snapshots;
    active:=rest
   |_->());
  let canonical=match o with Analysis.Execution_map.Image_byte{image;_}->image.name="PLI1.OVL"|_->false in
  if canonical&&List.mem state.pc[0x9c79;0xa046;0xa056]then(
   let call=B.verify_call bridge(Option.get !previous)~entry:state in
   let parent=match !active with (s,_,_,_,_,_,_,_,_,_,_)::_->Some s|[]->None in
   require(parent=None||call.operation=B.Mapped_word)"unexpected nested wrapper";
   let ram=boundary.copy_memory()and files=boundary.copy_filesystem()in
   let p=B.prepare bridge ~call ~origin:o ~state ~memory:ram in
   let preview=match boundary.preview_host_program p.program with Ok r->r|Error e->failwith e in
   active:=(step_index,parent,call,state,ram,files,boundary.dma,p,preview,ref[],Hashtbl.create 20)::!active)in
 match Experiment.run ~analysis:Experiment.Execution ~on_guest_step ~on_before_instruction ~on_bdos_record input with
 |Error _ as e->e|Ok historical->require(!active=[])"omitted hardware return";
  Ok({cases=List.sort(fun a b->compare a.entry_step b.entry_step)!cases;snapshots= !snapshots;
   records=List.rev !records;input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]);historical},historical)
let controller ?(exclude_entry_steps=[]) op v input =
 require(v.input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]))"source/input proof mismatch";
 let members=selected op v in
 require(List.for_all(fun s->List.exists(fun c->c.entry_step=s)members)exclude_entry_steps
  &&List.length exclude_entry_steps=List.length(List.sort_uniq compare exclude_entry_steps))"invalid child exclusion";
 let members=List.filter(fun c->not(List.mem c.entry_step exclude_entry_steps))members in
 let bridge=B.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
 let remaining=ref members and pending=ref None in
 let prepare previous origin (boundary:Runner.instruction_boundary)=
  let c=match !remaining with q::_->q|[]->failwith"Additional word invocation"in
  let s=List.assoc c.entry_step v.snapshots in
  require(boundary.dma=c.entry_dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())s.entry_files)"entry external state proof";
  let call=B.verify_call bridge previous ~entry:boundary.state in
  let p=B.prepare bridge ~call ~origin ~state:boundary.state ~memory:(boundary.copy_memory())in
  let base=p.program.validate in
  let validate r=match base r with Error _ as e->e|Ok()->
   if r.Runner.memory<>s.post_memory||r.dma<>c.post_dma||r.services<>c.services
     ||not(Cpm.Filesystem.equal r.filesystem s.post_files)then Error"word/external/service post-state oracle mismatch"else Ok()in
  let program={p.program with validate}in
  let preview=match boundary.preview_host_program program with Ok r->r|Error e->failwith e in
  pending:=Some program;remaining:=List.tl !remaining;
  {Native_dispatch.state=p.state;memory=preview.memory;logical_writes=p.logical_writes;compatibility_writes=p.compatibility_writes}in
 let oracles=List.map(fun c->let s=List.assoc c.entry_step v.snapshots in
  {Native_dispatch.input=c.input;output=c.output;entry_memory=s.entry_memory;post_memory=s.post_memory;
   logical_digest=Native_dispatch.write_digest c.logical_writes})members in
 let a,b=B.extent op in
 let t=Native_dispatch.create ~image:"PLI1.OVL" ~entry_pc:(a+0x2200) ~end_pc:(b+0x2200) ~oracles ~records:v.records ~prepare in
 Native_dispatch.with_host_program t(fun _ _->let p=Option.get !pending in pending:=None;p)
let compare_external v result =
 require(Cpm.Filesystem.equal result.Experiment.filesystem v.historical.filesystem)"final full filesystem identity";
 let event(e:Experiment.file_event)=e.operation,e.file,e.succeeded,e.logical_record,e.byte_range in
 require(List.map event result.file_events=List.map event v.historical.file_events)"complete file-event sequence";
 require(result.int_bytes=v.historical.int_bytes&&result.rel_bytes=v.historical.rel_bytes)"complete INT/REL identity"
let run v input controllers=match Native_dispatch.run input controllers with
 |Error _ as e->e|Ok(_,r)as q->compare_external v r;q
let single op v input=run v input[controller op v input]
let hierarchical v input=run v input[controller B.Low v input;controller B.High v input]
let cumulative v emitter attributes publications recursive packed balances input =
 let parents=List.map(fun(c:Native_7c1b.case)->c.entry_step,c.return_step)(Native_7c1b.roots recursive)
  @List.map(fun(c:Native_7bbf.case)->c.entry_step,c.return_step)(Native_7bbf.cases packed)
  @List.map(fun c->c.entry_step,c.return_step)(selected B.Low v@selected B.High v)in
 let excluded=List.filter_map(fun c->if List.exists(fun(a,b)->a<c.entry_step&&c.entry_step<b)parents then Some c.entry_step else None)(selected B.Mapped_word v)in
 let emitter_excluded=List.filter_map(fun(c:Native_int_emitter.case)->
  if List.exists(fun w->w.entry_step<c.entry_step&&c.entry_step<w.return_step)(selected B.Low v@selected B.High v)
  then Some c.entry_step else None)(Native_int_emitter.cases emitter)in
 let controllers=Native_mapped_publication.controllers publications recursive packed balances input
  @[Native_attribute_auxiliary.controller Attribute_auxiliary_bridge.High_attribute attributes input;
    Native_attribute_auxiliary.controller Attribute_auxiliary_bridge.Second_auxiliary attributes input;
    Native_int_emitter.controller ~exclude_entry_steps:emitter_excluded emitter input;
    controller ~exclude_entry_steps:excluded B.Mapped_word v input;controller B.Low v input;controller B.High v input]in
 let q=run v input controllers in
 (match q with Ok(_,r)->Native_int_emitter.compare_external emitter r|_->());q
