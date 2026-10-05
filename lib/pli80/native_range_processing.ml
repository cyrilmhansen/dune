[@@@warning "-4-40-41-42"]
module B=Range_processing_bridge
module H=Pli80_host.Range_processing
type case={caller:string;entry_step:int;return_step:int;input:Runner.state_snapshot;output:Runner.state_snapshot;
 prepared:B.prepared;services:Runner.host_service list;entry_cells:(int*int)list;
 entry_memory_sha256:string;post_memory_sha256:string;entry_dma:int;post_dma:int}
type snapshot={entry_memory:bytes;post_memory:bytes;entry_files:Cpm.Filesystem.t;post_files:Cpm.Filesystem.t}
type validated={cases:case list;snapshots:(int*snapshot)list;records:(string*int*bytes)list;
 input_digest:string;historical:Experiment.result}
let cases v=v.cases
let record_summaries v=List.map(fun(n,r,b)->n,r,Experiment.sha256_hex b)v.records
let require b m=if not b then failwith("Native7D53: "^m)
let shadow input=
 let bridge=B.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
 let previous=ref None and current_origin=ref Analysis.Execution_map.Unknown and active=ref None in
 let cases=ref[]and snapshots=ref[]and records=ref[]and psws=ref[]and direct=ref 0 in
 let on_bdos_record ~step_index:_=function Cpm.Bdos.Write_record q->records:=(q.file.name,q.logical_record,Bytes.copy q.data)::!records|_->()in
 let on_guest_step ~step_index:_ ~before ~after step=
  previous:=Some{Native_dispatch.origin= !current_origin;before;after;step};
  match !active with None->()|Some(_,_,(entry:Runner.state_snapshot),_,_,_,(p:B.prepared),_,writes,latest,calls)->
   (match I8080.Step.control_flow step with
    |I8080.Step.Call{taken=true;_} when before.sp=entry.sp->
      let child=List.nth p.children !direct in
      require(after=child.input&&I8080.Step.pc_before step=child.site+0x2200)"exact ordinal direct child entry state";
      incr direct
    |I8080.Step.Return{taken=true;_} when after.sp=entry.sp->
      let child=List.nth p.children(!direct-1)in
      require(after=child.output)"exact direct child returned state"
    |_->());
   (match I8080.Step.control_flow step with I8080.Step.Call{taken=true;_}->calls:=I8080.Step.pc_before step::!calls|_->());
   List.iter(function I8080.Step.Write q->
    Hashtbl.replace latest q.address(I8080.Step.pc_before step,q.value);
    if I8080.Step.pc_before step=0x9f82 then psws:=(q.address,q.value)::!psws;
    if Native_7c1b.logical_write step before q.address
      &&not(List.mem(I8080.Step.pc_before step)[0x9f82;0x1abb;0x1abc])
    then writes:=(q.address,q.value)::!writes|_->())(I8080.Step.memory_accesses step)in
 let on_before_instruction ~origin:o ~step_index (boundary:Runner.instruction_boundary)=
  current_origin:=o;let state=boundary.state in
  (match !active with
  |Some(entry_step,call,(entry:Runner.state_snapshot),ram,files,dma,(p:B.prepared),(preview:Runner.host_program_result),writes,latest,calls)
    when state.pc=call.B.resume->
   let prev=Option.get !previous in
   require(List.mem(I8080.Step.pc_before prev.step)[0x9f5d;0x9f65;0xa045]
    &&prev.before.sp=entry.sp&&prev.after=state
    &&I8080.Step.control_flow prev.step=I8080.Step.Return{target=Some call.resume;taken=true})"original hardware RET ancestry";
   let reads=List.filter_map(function I8080.Step.Read q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses prev.step)in
   require(reads=[entry.sp,call.resume land 255;entry.sp+1,call.resume lsr 8])"original CALL slot consumed";
   let label=Printf.sprintf"entry%d path%s"entry_step p.result.path in
   if state<>p.state then failwith(label^" return ABI: "^Marshal.to_string(state,p.state)[]);
   if boundary.copy_memory()<>preview.memory then(
    let actual=boundary.copy_memory()in
    let differences=List.init 65536 Fun.id|>List.filter(fun a->Bytes.get actual a<>Bytes.get preview.memory a)in
    failwith(label^" memory differences "^String.concat","(List.map(fun a->Printf.sprintf"%04X:%02X/%02X"a(Char.code(Bytes.get actual a))(Char.code(Bytes.get preview.memory a)))differences)));
   require(Cpm.Filesystem.equal(boundary.copy_filesystem())preview.filesystem&&boundary.dma=preview.dma)(label^" external state");
   if List.rev !writes<>p.logical_writes then(
    let rec diff i a b=match a,b with x::xs,y::ys when x=y->diff(i+1)xs ys|_->
     let show xs=String.concat","(List.map(fun(a,v)->Printf.sprintf"%04X=%02X"a v)(List.filteri(fun j _->j<10)xs))in
     failwith(Printf.sprintf"%s logical chronology %d historical[%s] native[%s]"label i(show a)(show b))in
    diff 0(List.rev !writes)p.logical_writes);
   let final=Hashtbl.create 64 in List.iter(fun(w:B.write)->Hashtbl.replace final w.address(w.writer,w.value))p.journal;
   Hashtbl.iter(fun a q->require(Hashtbl.find_opt latest a=Some q)(Printf.sprintf"%s last writer %04X expected %04X"label a(fst q)^ (match Hashtbl.find_opt latest a with None->" absent"|Some(w,v)->Printf.sprintf" actual %04X=%02X"w v)))final;
   require(Hashtbl.length final=Hashtbl.length latest)"omitted observed write dependency";
   let rec planned_calls=function
    |(x:B.write)::y::rest when x.kind="compatibility"&&y.kind="compatibility"&&x.writer=y.writer
       &&x.address=Pli80_host.U16.wrap(y.address+1)&&Char.code(Bytes.get ram x.writer)=0xcd->x.writer::planned_calls rest
    |_::rest->planned_calls rest|[]->[]in
   let packed_mechanics=[0x9dcc;0x9de0;0x9de8;0x9df3;0x9df7;0x9d87;0x9c6b]in
   let keep s=not(List.mem s packed_mechanics)in
   let expected=List.filter keep(planned_calls p.journal)and actual=List.filter keep(List.rev !calls)in
   let planned_psw=List.filter_map(fun(w:B.write)->if w.writer=0x9f82 then Some(w.address,w.value)else None)p.journal in
   require(planned_psw=List.rev !psws)(label^" every PUSH PSW byte/write order");
   if expected<>actual then (
    let show xs=String.concat","(List.map(Printf.sprintf"%04X")xs)in
    failwith(label^" CALL chronology actual="^show actual^" planned="^show expected));
   cases:={caller=call.coordinate;entry_step;return_step=step_index-1;input=entry;output=state;prepared=p;services=preview.services;
    entry_cells=List.map(fun a->a,Char.code(Bytes.get ram a))[0xae34;0xae35;0xaa1a;0x202b;0x2011;0x1e0c];
    entry_memory_sha256=Experiment.sha256_hex ram;post_memory_sha256=Experiment.sha256_hex preview.memory;entry_dma=dma;post_dma=preview.dma}::!cases;
   snapshots:=(entry_step,{entry_memory=ram;post_memory=preview.memory;entry_files=files;post_files=preview.filesystem})::!snapshots;active:=None
  |_->());
  if o=B.origin "PLI1.OVL" 0x7d53 then(
   require(!active=None)"unexpected recursive 7D53 root";psws:=[];direct:=0;
   let call=B.verify_call bridge(Option.get !previous)~entry:state in
   let ram=boundary.copy_memory()and files=boundary.copy_filesystem()in
   let p=B.prepare bridge ~call ~origin:o boundary in
   let preview=match boundary.preview_host_program p.program with Ok q->q|Error e->failwith e in
   active:=Some(step_index,call,state,ram,files,boundary.dma,p,preview,ref[],Hashtbl.create 64,ref[]))in
 match Experiment.run ~analysis:Experiment.Execution ~on_guest_step ~on_before_instruction ~on_bdos_record input with
 |Error _ as e->e|Ok historical->require(!active=None)"missing root return";
  Ok({cases=List.sort(fun a b->compare a.entry_step b.entry_step)!cases;snapshots= !snapshots;records=List.rev !records;
   input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]);historical},historical)
let controller v input=
 require(v.input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]))"source/input proof mismatch";
 let bridge=B.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
 let remaining=ref v.cases and pending=ref None in
 let prepare previous origin (boundary:Runner.instruction_boundary)=
  let c=match !remaining with q::_->q|[]->failwith"Additional7D53 root"in
  let s=List.assoc c.entry_step v.snapshots in
  require(boundary.dma=c.entry_dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())s.entry_files)"entry external state proof";
  let call=B.verify_call bridge previous ~entry:boundary.state in
  let p=B.prepare bridge ~call ~origin boundary in
  let validate(r:Runner.host_program_result)=
   match p.program.validate r with Error _ as e->e|Ok()->
   if r.memory<>s.post_memory||r.dma<>c.post_dma||r.services<>c.services
    ||not(Cpm.Filesystem.equal r.filesystem s.post_files)then Error"root external/post-state proof mismatch"else Ok()in
  let program={p.program with validate}in
  let preview=match boundary.preview_host_program program with Ok q->q|Error e->failwith e in
  pending:=Some program;remaining:=List.tl !remaining;
  {Native_dispatch.state=p.state;memory=preview.memory;logical_writes=p.logical_writes;compatibility_writes=p.compatibility_writes}in
 let oracles=List.map(fun c->let s=List.assoc c.entry_step v.snapshots in
  {Native_dispatch.input=c.input;output=c.output;entry_memory=s.entry_memory;post_memory=s.post_memory;
   logical_digest=Native_dispatch.write_digest c.prepared.logical_writes})v.cases in
 let t=Native_dispatch.create ~image:"PLI1.OVL" ~entry_pc:0x9f53 ~end_pc:0xa046 ~oracles ~records:v.records ~prepare in
 Native_dispatch.with_host_program t(fun _ _->let p=Option.get !pending in pending:=None;p)
let compare_external v (r:Experiment.result)=
 require(Cpm.Filesystem.equal r.filesystem v.historical.filesystem)"final filesystem";
 let event(e:Experiment.file_event)=e.operation,e.file,e.succeeded,e.logical_record,e.byte_range in
 require(List.map event r.file_events=List.map event v.historical.file_events)"file event order";
 require(r.int_bytes=v.historical.int_bytes&&r.rel_bytes=v.historical.rel_bytes)"INT/REL identity"
let run v input controllers=match Native_dispatch.run input controllers with Error _ as e->e|Ok(_,r)as q->compare_external v r;q
let single v input=run v input[controller v input]

let cumulative v words emitter attributes publications recursive packed balances input=
 let windows=List.map(fun c->c.entry_step,c.return_step)v.cases in
 let inside step windows=List.exists(fun(a,b)->a<step&&step<b)windows in
 let excluded get cases windows=List.filter_map(fun c->let s=get c in if inside s windows then Some s else None)cases in
 let recursive_windows=List.map(fun(c:Native_7c1b.case)->c.entry_step,c.return_step)(Native_7c1b.roots recursive)in
 let recycle_windows=List.map(fun(c:Native_mapped_publication.case)->c.entry_step,c.return_step)(Native_mapped_publication.recycles publications)in
 let wrapper_windows=List.map(fun(c:Native_word_emitters.case)->c.entry_step,c.return_step)
  (Native_word_emitters.selected Word_emitter_bridge.Low words@Native_word_emitters.selected High words)in
 let packed_windows=List.map(fun(c:Native_7bbf.case)->c.entry_step,c.return_step)(Native_7bbf.cases packed)in
 let controllers=[controller v input;
  Native_7c1b.controller ~exclude_entry_steps:(excluded(fun(c:Native_7c1b.case)->c.entry_step)(Native_7c1b.roots recursive)windows)recursive input;
  Native_7bbf.controller ~exclude_entry_steps:(excluded(fun(c:Native_7bbf.case)->c.entry_step)(Native_7bbf.cases packed)(windows@recursive_windows))packed input;
  Native_7b7a.controller ~exclude_entry_steps:(excluded(fun(c:Native_7b7a.case)->c.entry_step)(Native_7b7a.cases balances)(windows@recursive_windows))balances input;
  Native_mapped_publication.controller ~exclude_entry_steps:(excluded(fun(c:Native_mapped_publication.case)->c.entry_step)(Native_mapped_publication.recycles publications)windows)Mapped_publication_bridge.Recycle publications input;
  Native_mapped_publication.controller ~exclude_entry_steps:(excluded(fun(c:Native_mapped_publication.case)->c.entry_step)(Native_mapped_publication.publications publications)(windows@recycle_windows))Publish publications input;
  Native_attribute_auxiliary.controller ~exclude_entry_steps:(excluded(fun(c:Native_attribute_auxiliary.case)->c.entry_step)(Native_attribute_auxiliary.high_attributes attributes)windows)High_attribute attributes input;
  Native_attribute_auxiliary.controller ~exclude_entry_steps:(excluded(fun(c:Native_attribute_auxiliary.case)->c.entry_step)(Native_attribute_auxiliary.second_auxiliaries attributes)windows)Second_auxiliary attributes input;
  Native_int_emitter.controller ~exclude_entry_steps:(excluded(fun(c:Native_int_emitter.case)->c.entry_step)(Native_int_emitter.cases emitter)(windows@wrapper_windows))emitter input;
  Native_word_emitters.controller ~exclude_entry_steps:(excluded(fun(c:Native_word_emitters.case)->c.entry_step)(Native_word_emitters.selected Word_emitter_bridge.Mapped_word words)(windows@wrapper_windows@recursive_windows@packed_windows))Mapped_word words input;
  Native_word_emitters.controller ~exclude_entry_steps:(excluded(fun(c:Native_word_emitters.case)->c.entry_step)(Native_word_emitters.selected Word_emitter_bridge.Low words)windows)Low words input;
  Native_word_emitters.controller ~exclude_entry_steps:(excluded(fun(c:Native_word_emitters.case)->c.entry_step)(Native_word_emitters.selected Word_emitter_bridge.High words)windows)High words input]in
 match run v input controllers with Error _ as e->e|Ok(_,r)as q->Native_int_emitter.compare_external emitter r;q
