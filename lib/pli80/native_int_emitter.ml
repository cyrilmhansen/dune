[@@@warning "-4-40-41-42"]
module B=Int_emitter_bridge
type case={caller:string;entry_step:int;return_step:int;input:Runner.state_snapshot;output:Runner.state_snapshot;
 plan:Pli80_host.Int_emitter.plan;logical_writes:(int*int)list;compatibility_writes:(int*int)list;
 services:Runner.host_service list;entry_memory_sha256:string;post_memory_sha256:string;entry_dma:int;post_dma:int}
type snapshot={entry_memory:bytes;post_memory:bytes;entry_files:Cpm.Filesystem.t;post_files:Cpm.Filesystem.t}
type validated={cases:case list;snapshots:snapshot list;records:(string*int*bytes)list;input_digest:string;historical:Experiment.result}
let cases v=v.cases
let require b msg=if not b then failwith("Native INT emitter: "^msg)
let shadow input =
 let bridge=B.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
 let previous=ref None and origin=ref Analysis.Execution_map.Unknown and active=ref None in
 let cases=ref[]and snapshots=ref[]and records=ref[]in
 let on_bdos_record ~step_index:_=function Cpm.Bdos.Write_record{file;logical_record;data;_}->records:=(file.name,logical_record,Bytes.copy data)::!records|_->()in
 let on_guest_step ~step_index:_ ~before ~after step=
  previous:=Some{Native_dispatch.origin= !origin;before;after;step};
  match !active with
   |None->()
   |Some(_,_,(entry:Runner.state_snapshot),_,_,_,_,_,writes,latest)->
     List.iter(function I8080.Step.Write q->
       Hashtbl.replace latest q.address(I8080.Step.pc_before step,q.value);
       let stack=List.init 12(fun i->Pli80_host.U16.wrap(entry.sp-10+i))in
       if not(List.mem q.address stack)then writes:=(q.address,q.value)::!writes
       |_->())(I8080.Step.memory_accesses step)in
 let on_before_instruction ~origin:o ~step_index (boundary:Runner.instruction_boundary)=
  origin:=o;let state=boundary.state in
  (match !active with
   |Some(entry_step,call,(entry:Runner.state_snapshot),ram,files,dma,(p:B.prepared),(preview:Runner.host_program_result),writes,latest)when state.pc=call.B.resume->
     let previous=Option.get !previous in
     require(I8080.Step.pc_before previous.step=0x102c && previous.before.sp=entry.sp &&previous.after=state
       &&I8080.Step.control_flow previous.step=I8080.Step.Return{target=Some call.resume;taken=true})"outer RET ancestry";
     let reads=List.filter_map(function I8080.Step.Read q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses previous.step)in
     require(reads=[entry.sp,call.resume land 255;Pli80_host.U16.wrap(entry.sp+1),call.resume lsr 8])"actual original RET slot consumer";
     require(not(Hashtbl.mem latest entry.sp)&&not(Hashtbl.mem latest(Pli80_host.U16.wrap(entry.sp+1))))"outer continuation overwritten";
     require(List.rev !writes=p.logical_writes)"compiler logical write chronology";
     require(state=p.state)"all returned registers/flags";
     require(boundary.copy_memory()=preview.memory)"full64KiB post-memory";
     require(Cpm.Filesystem.equal(boundary.copy_filesystem())preview.filesystem)"full post-filesystem";
     require(boundary.dma=preview.dma)"post DMA";
     let final_abi=Hashtbl.create 10 in
     List.iter(fun(a,v)->Hashtbl.replace final_abi a v)p.compatibility_writes;
     let writers=[2,0x1021;4,0x434;6,0x1abb;8,0x1abc;10,0x1ac3]in
     Hashtbl.iter(fun a v->
       let depth=List.find(fun(d,_)->a=Pli80_host.U16.wrap(entry.sp-d)||a=Pli80_host.U16.wrap(entry.sp-d+1))writers in
       require(Hashtbl.find_opt latest a=Some(snd depth,v))"ABI exact final writer coordinate")final_abi;
     cases:={caller=call.coordinate;entry_step;return_step=step_index-1;input=entry;output=state;plan=p.plan;
       logical_writes=p.logical_writes;compatibility_writes=p.compatibility_writes;services=preview.services;
       entry_memory_sha256=Experiment.sha256_hex ram;post_memory_sha256=Experiment.sha256_hex preview.memory;
       entry_dma=dma;post_dma=preview.dma}::!cases;
     snapshots:={entry_memory=ram;post_memory=preview.memory;entry_files=files;post_files=preview.filesystem}::!snapshots;
     active:=None
   |_->());
  (match !active with
   |Some(_,_,_,_,_,_,_,(preview:Runner.host_program_result),_,_) when state.pc=5->
    let service=List.find(fun(s:Runner.host_service)->s.resume_state.c=state.c)preview.services in
    require(state=service.resume_state && boundary.copy_memory()=service.memory_after
      &&boundary.dma=service.dma_after)"actual historical post-BDOS boundary";
   |_->());
  if state.pc=0xff6 then (
    require(!active=None)"unexpected reentrant emitter";
    let call=B.verify_call bridge(Option.get !previous)~entry:state in
    let ram=boundary.copy_memory()and files=boundary.copy_filesystem()in
    let p=B.prepare bridge ~call ~origin:o ~state ~memory:ram in
    let preview=match boundary.preview_host_program p.program with Ok r->r|Error e->failwith("Emitter preview: "^e)in
    active:=Some(step_index,call,state,ram,files,boundary.dma,p,preview,ref[],Hashtbl.create 20))in
 match Experiment.run ~analysis:Experiment.Execution ~on_guest_step ~on_before_instruction ~on_bdos_record input with
 |Error _ as e->e|Ok historical->require(!active=None)"missing emitter return";
  Ok({cases=List.rev !cases;snapshots=List.rev !snapshots;records=List.rev !records;
    input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]);historical},historical)
let controller ?(exclude_entry_steps=[]) v input =
 require(v.input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]))"source/input proof mismatch";
 let bridge=B.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
 require(List.for_all(fun step->List.exists(fun c->c.entry_step=step)v.cases)exclude_entry_steps
  &&List.length exclude_entry_steps=List.length(List.sort_uniq compare exclude_entry_steps))"invalid emitter child exclusion";
 let members=List.filter(fun(c,_)->not(List.mem c.entry_step exclude_entry_steps))(List.combine v.cases v.snapshots)in
 let remaining=ref members and pending_program=ref None in
 let prepare previous origin (boundary:Runner.instruction_boundary)=
  let c,s=match !remaining with q::_->q|[]->failwith"Additional emitter invocation"in
  require(Cpm.Filesystem.equal(boundary.copy_filesystem())s.entry_files && boundary.dma=c.entry_dma)"entry external-state proof";
  let call=B.verify_call bridge previous ~entry:boundary.state in
  let p=B.prepare bridge ~call ~origin ~state:boundary.state ~memory:(boundary.copy_memory())in
  let base_validate=p.program.validate in
  let validate r=match base_validate r with
   |Error e->Error e|Ok()->
    if r.Runner.memory<>s.post_memory || not(Cpm.Filesystem.equal r.filesystem s.post_files)
      ||r.dma<>c.post_dma ||r.services<>c.services then Error"external/memory/service oracle mismatch"else Ok()in
  let program={p.program with validate}in
  let preview=match boundary.preview_host_program program with Ok r->r|Error e->failwith e in
  pending_program:=Some program;remaining:=List.tl !remaining;
  {Native_dispatch.state=p.state;memory=preview.memory;logical_writes=p.logical_writes;compatibility_writes=p.compatibility_writes}in
 let oracles=List.map(fun(c,s)->{Native_dispatch.input=c.input;output=c.output;entry_memory=s.entry_memory;post_memory=s.post_memory;logical_digest=Native_dispatch.write_digest c.logical_writes})members in
 let t=Native_dispatch.create ~image:"PLI.COM" ~entry_pc:0xff6 ~end_pc:0x102d ~oracles ~records:v.records ~prepare in
 Native_dispatch.with_host_program t(fun _ _->let p=Option.get !pending_program in pending_program:=None;p)
let compare_external v result =
 require(Cpm.Filesystem.equal result.Experiment.filesystem v.historical.filesystem)"final full filesystem";
 let without_step(e:Experiment.file_event)=e.operation,e.file,e.succeeded,e.logical_record,e.byte_range in
 require(List.map without_step result.file_events=List.map without_step v.historical.file_events)"complete file-event sequence";
 require(result.int_bytes=v.historical.int_bytes && result.rel_bytes=v.historical.rel_bytes)"complete INT/REL bytes";
 let flushes=List.length(List.filter(fun c->c.plan.flush)v.cases)in
 require(result.run.host_bdos_services=2*flushes)"native BDOS accounting"
let run v input controllers =match Native_dispatch.run input(controllers@[controller v input])with
 |Error _ as e->e|Ok(counts,result)->compare_external v result;Ok(counts,result)
let single v input=run v input[]
let cumulative v attributes publications recursive words balances input =
 run v input(Native_mapped_publication.controllers publications recursive words balances input
  @[Native_attribute_auxiliary.controller Attribute_auxiliary_bridge.High_attribute attributes input;
    Native_attribute_auxiliary.controller Attribute_auxiliary_bridge.Second_auxiliary attributes input])
