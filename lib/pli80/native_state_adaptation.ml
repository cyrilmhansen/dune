[@@@warning "-4-40-41-42"]
module B=State_adaptation_bridge
module H=Pli80_host.State_adaptation
type case={caller:string;entry_step:int;return_step:int;input:Runner.state_snapshot;output:Runner.state_snapshot;
 prepared:B.prepared;services:Runner.host_service list;entry_cells:(int*int)list;
 entry_memory_sha256:string;post_memory_sha256:string;entry_dma:int;post_dma:int;entry_filesystem_sha256:string;post_filesystem_sha256:string}
type snapshot={entry_memory:bytes;post_memory:bytes;entry_files:Cpm.Filesystem.t;post_files:Cpm.Filesystem.t}
type validated={operation:B.operation;cases:case list;snapshots:(int*snapshot)list;records:(string*int*bytes)list;
 input_digest:string;historical:Experiment.result}
let cases v=v.cases
let record_summaries v=List.map(fun(n,r,b)->n,r,Experiment.sha256_hex b)v.records
let require b m=if not b then failwith("Native attribute gate: "^m)
let filesystem_hash files=
 let inventory=ref[]in
 for drive=0 to 15 do for user=0 to 31 do
  List.iter(fun name->
   let key:Cpm.Filesystem.key={drive;user;name}in
   let logical=match Cpm.Filesystem.get_file files ~drive ~user ~name()with Ok(Some b)->b|_->assert false in
   let count=Option.get(Cpm.Filesystem.record_count files key)in
   let records=List.init count(fun record->match Cpm.Filesystem.read_record files key ~record with Ok(Some b)->b|_->assert false)in
   inventory:=(drive,user,name,logical,records)::!inventory)(Cpm.Filesystem.list_files files ~drive ~user())
 done done;
 Experiment.sha256_hex(Marshal.to_bytes(List.rev !inventory)[])
let shadow operation input=
 let first,last=B.bounds operation in
 let bridge=B.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
 let previous=ref None and current_origin=ref Analysis.Execution_map.Unknown and active=ref None in
 let cases=ref[]and snapshots=ref[]and records=ref[]and psws=ref[]and direct=ref 0 in
 let root_records=ref[]in
 let on_bdos_record ~step_index:_=function Cpm.Bdos.Write_record q->
  let r=q.file.name,q.logical_record,Bytes.copy q.data in
  records:=r::!records;if !active<>None then root_records:=r::!root_records
  |_->()in
 let on_guest_step ~step_index:_ ~before ~after step=
  previous:=Some{Native_dispatch.origin= !current_origin;before;after;step};
  match !active with None->()|Some(_,_,(entry:Runner.state_snapshot),_,_,_,(p:B.prepared),_,writes,latest,calls)->
   (match I8080.Step.control_flow step with
    |I8080.Step.Call{taken=true;_} when before.sp=entry.sp-(if operation=B.Saved then 1 else 0)->
      let child=List.nth p.children !direct in
      require(after=child.input&&I8080.Step.pc_before step=child.site+0x2200)"exact ordinal direct child entry state";
      incr direct
    |I8080.Step.Return{taken=true;_} when after.sp=entry.sp-(if operation=B.Saved then 1 else 0)->
      let child=List.nth p.children(!direct-1)in
      require(after=child.output)"exact direct child returned state"
    |_->());
   (match I8080.Step.control_flow step with I8080.Step.Call{taken=true;_}->calls:=I8080.Step.pc_before step::!calls|_->());
   List.iter(function I8080.Step.Write q->
    Hashtbl.replace latest q.address(I8080.Step.pc_before step,q.value);
    if I8080.Step.pc_before step=0x9f82 then psws:=(q.address,q.value)::!psws;
    if (I8080.Step.pc_before step<>0x4712||q.address=entry.sp-1) && Native_7c1b.logical_write step before q.address
      &&not(List.mem(I8080.Step.pc_before step)[0x9f82;0x1abb;0x1abc;0x9d09])
    then writes:=(q.address,q.value)::!writes|_->())(I8080.Step.memory_accesses step)in
 let on_before_instruction ~origin:o ~step_index (boundary:Runner.instruction_boundary)=
  current_origin:=o;let state=boundary.state in
  (match !active with
  |Some(entry_step,call,(entry:Runner.state_snapshot),ram,files,dma,(p:B.prepared),(preview:Runner.host_program_result),writes,latest,calls)
    when state.pc=call.B.resume->
   let prev=Option.get !previous in
   require(List.mem(I8080.Step.pc_before prev.step)(if operation=B.Minimum then[0x45b3;0x45b7]else[last+0x2200-1])
    &&prev.before.sp=entry.sp&&prev.after=state
    &&I8080.Step.control_flow prev.step=I8080.Step.Return{target=Some call.resume;taken=true})"original hardware RET ancestry";
   let reads=List.filter_map(function I8080.Step.Read q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses prev.step)in
   require(reads=[entry.sp,call.resume land 255;entry.sp+1,call.resume lsr 8])"original CALL slot consumed";
   require(!direct=List.length p.children)"omitted direct child";
   let label=Printf.sprintf"entry%d path%s"entry_step p.result.route in
   if state<>p.state then failwith(label^" return ABI: "^Marshal.to_string(state,p.state)[]);
   if boundary.copy_memory()<>preview.memory then(
    let actual=boundary.copy_memory()in
    let differences=List.init 65536 Fun.id|>List.filter(fun a->Bytes.get actual a<>Bytes.get preview.memory a)in
    failwith(label^" memory differences "^String.concat","(List.map(fun a->Printf.sprintf"%04X:%02X/%02X"a(Char.code(Bytes.get actual a))(Char.code(Bytes.get preview.memory a)))differences)));
   require(Cpm.Filesystem.equal(boundary.copy_filesystem())preview.filesystem&&boundary.dma=preview.dma)(label^" external state");
   let planned_records=List.concat_map(fun(s:Runner.host_service)->List.filter_map(function
    Cpm.Bdos.Write_record q->Some(q.file.name,q.logical_record,q.data)|_->None)s.events)preview.services in
   require(planned_records=List.rev !root_records)(label^" exact ordered root record events/data");
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
    entry_cells=List.map(fun a->a,Char.code(Bytes.get ram a))[0xae32;0xae33;0xa628+entry.c;0xa62b+entry.c;0xa62e+entry.c;0xa642;0xa652;0xa653;0x1e0c];
    entry_memory_sha256=Experiment.sha256_hex ram;post_memory_sha256=Experiment.sha256_hex preview.memory;entry_dma=dma;post_dma=preview.dma;entry_filesystem_sha256=filesystem_hash files;post_filesystem_sha256=filesystem_hash preview.filesystem}::!cases;
   snapshots:=(entry_step,{entry_memory=ram;post_memory=preview.memory;entry_files=files;post_files=preview.filesystem})::!snapshots;active:=None
  |_->());
  if o=B.origin "PLI1.OVL" first then(
   require(!active=None)"unexpected recursive state adaptation root";psws:=[];root_records:=[];direct:=0;
   let call=B.verify_call bridge operation(Option.get !previous)~entry:state in
   let ram=boundary.copy_memory()and files=boundary.copy_filesystem()in
   let p=B.prepare bridge operation ~call ~origin:o boundary in
   let preview=match boundary.preview_host_program p.program with Ok q->q|Error e->failwith e in
   active:=Some(step_index,call,state,ram,files,boundary.dma,p,preview,ref[],Hashtbl.create 64,ref[]))in
 match Experiment.run ~analysis:Experiment.Execution ~on_guest_step ~on_before_instruction ~on_bdos_record input with
 |Error _ as e->e|Ok historical->require(!active=None)"missing root return";
  List.iter(fun c->
   let actual=List.filter(fun(e:Experiment.file_event)->c.entry_step<=e.step_index&&e.step_index<=c.return_step)historical.file_events in
   let planned=List.concat_map(fun(s:Runner.host_service)->s.file_events)c.services in
   let operation=function Experiment.Open->Cpm.Bdos.Open|Close->Close|Make->Make|Delete->Delete|Sequential_read->Sequential_read|Sequential_write->Sequential_write in
   require(List.map(fun(e:Experiment.file_event)->operation e.operation,e.file,e.succeeded,e.logical_record)actual
    =List.map(fun(e:Cpm.Bdos.file_event)->e.operation,e.file,e.succeeded,e.logical_record)planned)"root factual file-event sequence")!cases;
  Ok({operation;cases=List.sort(fun a b->compare a.entry_step b.entry_step)!cases;snapshots= !snapshots;records=List.rev !records;
   input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]);historical},historical)
let controller ?(exclude_entry_steps=[]) v input=
 let operation=v.operation in let first,last=B.bounds operation in
 require(v.input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]))"source/input proof mismatch";
 let exclusions=List.sort_uniq compare exclude_entry_steps in
 require(List.length exclusions=List.length exclude_entry_steps&&List.for_all(fun n->List.exists(fun c->c.entry_step=n)v.cases)exclusions)"invalid exclusions";
 let selected=List.filter(fun c->not(List.mem c.entry_step exclusions))v.cases in
 let bridge=B.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
 let remaining=ref selected and pending=ref None in
 let prepare previous origin (boundary:Runner.instruction_boundary)=
  let c=match !remaining with q::_->q|[]->failwith"Additional state adaptation root"in
  let s=List.assoc c.entry_step v.snapshots in
  require(boundary.dma=c.entry_dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())s.entry_files)"entry external state proof";
  let call=B.verify_call bridge operation previous ~entry:boundary.state in
  let p=B.prepare bridge operation ~call ~origin boundary in
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
