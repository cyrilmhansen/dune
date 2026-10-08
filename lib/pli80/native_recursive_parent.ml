[@@@warning "-4-40-41-42"]
(* Independent logical/outer proofs and bounded native root controller. *)
module P=Native_selection_parent
module B=Acquisition_family_bridge
module N=Native_reentrant_acquisition
module RB=Reentrant_acquisition_bridge
type case={caller:string;entry_step:int;return_step:int;input:Runner.state_snapshot;output:Runner.state_snapshot;
 route:string;entry_memory_sha256:string;post_memory_sha256:string;stack_cells:int;logical_writes:int;prepared:B.prepared;services:Runner.host_service list;entry_dma:int;post_dma:int}
type pending={pending_caller:string;pending_entry_step:int;entry_sp:int;reason:string}
type snapshot={entry_memory:bytes;post_memory:bytes;entry_files:Cpm.Filesystem.t;post_files:Cpm.Filesystem.t}
type result={cases:case list;pending:pending list;historical:Experiment.result;snapshots:(int*snapshot)list;records:(string*int*bytes)list;input_digest:string}
let cases v=List.filter(fun(c:case)->not(List.exists(fun(p:case)->p.entry_step<c.entry_step&&c.return_step<p.return_step)v.cases))v.cases
let filesystem_hash=Native_acquisition_parent.filesystem_hash
let record_summaries v=List.map(fun(n,r,b)->n,r,Experiment.sha256_hex b)v.records
let require b m=if not b then failwith("wrapper acquisition proof: "^m)
let compatibility_writes (p:B.prepared)=List.filter_map(fun(w:B.write)->if w.kind="logical"then None else Some(w.address,w.value))p.journal
let route (p:B.prepared)=if List.exists(fun(w:B.write)->w.depth=0&&w.writer=0x25cd)p.journal then "R2_direct_recursion"else if List.exists(fun(w:B.write)->w.depth=0&&w.writer=0x265e)p.journal then "R1_mediated_recursion"else if List.exists(fun(w:B.write)->w.depth=0&&w.writer=0x2503)p.journal then "R3_cached_probe"else "R0_reader_tail"
let prepare_root ?(observe=(fun _ _ _ _ _->())) bridge input ~call ~origin boundary=
 let child=RB.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
 B.prepare ~follow_spine:true ~recursive:(fun site boundary->
  let p=RB.prepare ~observe child ~call:(RB.internal_call child site)~origin:(B.origin"PLI1.OVL"0x6223)boundary in
  p.program,p.state,p.journal)bridge (B.Recursive Pli80_host.Recursive_parent.Parent) ~call ~origin boundary
let shadow input=
 let bridge=B.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
 let previous=ref None and current_origin=ref Analysis.Execution_map.Unknown and active=ref [] in
 let parent_children=match P.shadow input with Ok v->v|_->failwith"19F0 child proof"in
 let wrapper_children=match Native_wrapper_acquisition.shadow input with Ok v->v|_->failwith"6619 child proof"in
 let native_children=match N.shadow input with Ok v->v|_->failwith"6223 child proof"in
 let cases=ref[]and pending=ref[]and snapshots=ref[]and all_records=ref[]and composed=ref[]and logical_trees=ref[]in
 let on_bdos_record ~step_index:_=function Cpm.Bdos.Write_record q->
  all_records:=(q.file.name,q.logical_record,Bytes.copy q.data)::!all_records;List.iter(fun(_,_,_,_,_,_,_,_,_,_,records)->records:=(q.file.name,q.logical_record,Bytes.copy q.data)::!records)!active|_->()in
 let call_sequences=Hashtbl.create 20 in
 let wrapper_sites=[0x3fa;0x424;0x6b2;0x820;0x830;0x83f;0x84f;0x855;0xad3;0xbda;0xbfd;0xe45;0xe55;0xe6a;0xe94;0xeef;0xef2;0xf04;0x13b8;0x14c5;0x14ce;0x14dd;0x1511;0x151a;0x152c;0x1543;0x155a;0x1578;0x1634;0x1643;0x166d;0x17c4;0x17c7;0x17ec;0x17ef;0x182f;0x1839;0x1847;0x18f5;0x18ff;0x1905;0x193c;0x1973;0x19f3;0x2346;0x234b;0x247d;0x2498;0x24a1;0x24a8;0x24b9;0x24c0;0x24ca;0x24cd;0x24d0;0x24d6;0x24db;0x24e5;0x24f1;0x24f4;0x24fc;0x2503;0x250b;0x2594;0x25af;0x25b6;0x25b9;0x25be;0x25c3;0x25cd;0x25d0;0x25d9;0x25e2;0x25e8;0x25f3;0x25fb;0x2602;0x2607;0x2629;0x264e;0x265e;0x266f;0x26f6;0x273b;0x2758;0x2813;0x2874;0x2877;0x2a6e;0x2a77;0x2ab0;0x2ab9;0x2ac6;0x2acb;0x2b0f;0x2b2d;0x2b3e;0x2b71;0x2b89;0x2b98;0x2bc1;0x2bcf;0x2bdf;0x2be2;0x2beb;0x2bf0;0x2bfa;0x2c13;0x2c1e;0x2c43;0x2c46;0x2c4d;0x2cad;0x2cbb;0x2cc3;0x2cd2;0x2ce5;0x2cf2;0x2cf5;0x2cfc;0x2d06;0x2d13;0x2d21;0x2d2e;0x2d37;0x2d3c;0x2d79;0x2f7b;0x2f90;0x2f99;0x300c;0x3024;0x3043;0x3048;0x304f;0x3054;0x3090;0x30b6;0x30be;0x30cc;0x30e7;0x30ed;0x3168;0x316b;0x3172;0x31b7;0x31c0;0x31c5;0x31ce;0x3219;0x323d;0x3278;0x3282;0x3291;0x3294;0x329a;0x32a3;0x32a9;0x32b0;0x32b9;0x32e4;0x3351;0x3361;0x3378;0x3387;0x33ea;0x33f6;0x3405;0x3468;0x347c;0x3486;0x3493;0x34b0;0x34bf;0x34c5;0x34c8;0x34cb;0x34d1;0x34fe;0x3518;0x35af;0x3613;0x361a;0x361d;0x363e;0x369c;0x36b4;0x36cd;0x36df;0x36ec;0x3701;0x3707;0x376f;0x3ca2;0x3cac;0x3cba;0x3cd6;0x3cdd;0x3cf6;0x3d0b;0x3d10;0x3d7b;0x3d7f;0x3d84;0x3d97;0x3dab;0x3db6;0x3dbb;0x3dce;0x3dd1;0x3ddc;0x3ddf;0x3de4;0x3dea;0x3e13;0x3e34;0x3e3b;0x3e40;0x3e44;0x3e49;0x3e4f;0x3e56;0x3e59;0x3e5c;0x3e69;0x3e80;0x3e8b;0x3e90;0x3e95;0x3e99;0x3e9e;0x3ea9;0x3eb0;0x3ebc;0x3ee2;0x3eeb;0x3efc;0x3f01;0x3f06;0x3f2b;0x3f30;0x3f33;0x421f;0x4232;0x4243;0x424c;0x42a2;0x46f9;0x4700;0x49e6;0x4a00;0x4b85;0x4c55;0x4cb4;0x4d26;0x4d3f;0x4d7b;0x4e55;0x4fc3;0x4fc6;0x4fef;0x5022;0x51b8;0x5405;0x540f;0x5419;0x5423;0x542d;0x5438;0x5442;0x544c;0x5456;0x5475;0x547f;0x5489;0x5493;0x5583;0x558a;0x5591;0x55b1;0x55c6;0x55d2;0x55d8;0x562f;0x563c;0x5733;0x5736;0x5743;0x6b54;0x6b8b;0x6ba2;0x6c39;0x6c3c;0x6c44;0x6c4c;0x6c53;0x7aca;0x7ae4;0x7ae9;0x7af2;0x7b00;0x7b19;0x7b1c;0x7b1f;0x7b25;0x83b6;0x8466;0x8473;0x847d;0x8525;0x85c9;0x860e;0x8614;0x8678;0x867e;0x86f2;0x86f7;0x8750;0x8756;0x8765;0x8778;0x87a7;0x87ce;0x87f0;0x87f9;0x87fe;0x8819;0x881e;0x883e;0x8845;0xa2b3;0xa2d8;0xa2e8;0xa2eb;0xa2f7;0xa2ff;0xa307;0xa31b;0xa360;0xa36b;0xa409]in
 let on_guest_step ~step_index:_ ~before ~after step=
  previous:=Some{Native_dispatch.origin= !current_origin;before;after;step};
  List.iter(fun(entry_step,_,_,_,_,_,_,_,writes,latest,_)->
   if List.mem before.Runner.pc wrapper_sites &&(match I8080.Step.control_flow step with I8080.Step.Call{taken=true;_}->true|_->false)then
    Hashtbl.replace call_sequences entry_step (before.pc::(Option.value ~default:[](Hashtbl.find_opt call_sequences entry_step)));
   List.iter(function I8080.Step.Write q->
    Hashtbl.replace latest q.address(I8080.Step.pc_before step,q.value);
    if ((I8080.Step.pc_before step=0x4712&&q.address=before.sp-1)||
      (Native_7c1b.logical_write step before q.address&&
       (match I8080.Step.control_flow step with I8080.Step.Call _->false|_->true)&&
       (not(List.mem(Char.code(Bytes.get(I8080.Step.fetched_bytes step)0))[0xc5;0xd5;0xe5;0xf5])||List.mem(I8080.Step.pc_before step)[0x9e1b;0x9e1c;0x9e1e])))
      &&not(List.mem(I8080.Step.pc_before step)[0x9f82;0x1abb;0x1abc;0x9d09])
    then writes:=(q.address,q.value)::!writes|_->())(I8080.Step.memory_accesses step))!active in
 let on_before_instruction ~origin:o ~step_index (boundary:Runner.instruction_boundary)=
  current_origin:=o;let state=boundary.state in
  (match !active with
  |(entry_step,call,(entry:Runner.state_snapshot),ram,(_files:Cpm.Filesystem.t),_dma,(p:B.prepared),(preview:Runner.host_program_result),writes,latest,records)::rest
    when state.pc=call.B.resume&&state.sp=entry.sp+2->
   let prev=Option.get !previous in
   require(I8080.Step.pc_before prev.step=0x287b&&prev.before.sp=entry.sp&&prev.after=state
    &&I8080.Step.control_flow prev.step=I8080.Step.Return{target=Some call.resume;taken=true})(Printf.sprintf"outer RET ancestry PC=%04X SP=%04X expectedSP=%04X"(I8080.Step.pc_before prev.step)prev.before.sp entry.sp);
   require(state=p.state)"return registers/flags/SP/PC";
   let actual=boundary.copy_memory()in
   if actual<>preview.memory then(
    let differences=List.init 65536 Fun.id|>List.filter(fun a->Bytes.get actual a<>Bytes.get preview.memory a)in
    failwith("root memory differences "^String.concat","(List.map(fun a->Printf.sprintf"%04X:%02X/%02X"a(Char.code(Bytes.get actual a))(Char.code(Bytes.get preview.memory a)))differences)));
   require(Cpm.Filesystem.equal(boundary.copy_filesystem())preview.filesystem&&boundary.dma=preview.dma)"DMA/filesystem";
   require(List.rev !writes=p.logical_writes)"ordered logical writes";
   let rec calls=function
    (a:B.write)::(b:B.write)::rest when a.kind="compatibility"&&b.kind="compatibility"&&a.writer=b.writer&&List.mem a.writer wrapper_sites->a.writer::calls rest
    |_::rest->calls rest|[]->[]in
   let actual_calls=List.rev(Option.value ~default:[](Hashtbl.find_opt call_sequences entry_step))and planned_calls=calls p.journal in
   if actual_calls<>planned_calls then(let rec mismatch i a b=match a,b with x::xs,y::ys when x=y->mismatch(i+1)xs ys|x::_,y::_->Printf.sprintf"index%d actual%04X native%04X"i x y|_->"length"in failwith("recursive child CALL chronology "^mismatch 0 actual_calls planned_calls^Printf.sprintf" counts%d/%d"(List.length actual_calls)(List.length planned_calls)));
   let final=Hashtbl.create 64 in List.iter(fun(w:B.write)->Hashtbl.replace final w.address(w.writer,w.value))p.journal;
   Hashtbl.iter(fun address value->require(Hashtbl.find_opt latest address=Some value)(Printf.sprintf"final writer %04X"address))final;
   require(Hashtbl.length final=Hashtbl.length latest)"missing observed publication";
   let planned=List.concat_map(fun(s:Runner.host_service)->List.filter_map(function
    Cpm.Bdos.Write_record q->Some(q.file.name,q.logical_record,q.data)|_->None)s.events)preview.services in
   require(planned=List.rev !records)"record chronology/data";
   cases:={caller=call.coordinate;entry_step;return_step=step_index-1;input=entry;output=state;route=(route p);
    entry_memory_sha256=Experiment.sha256_hex ram;post_memory_sha256=Experiment.sha256_hex actual;
    prepared=p;services=preview.services;entry_dma=_dma;post_dma=preview.dma;stack_cells=List.length(List.sort_uniq compare(List.map fst(compatibility_writes p)));logical_writes=List.length p.logical_writes}::!cases;
   snapshots:=(entry_step,{entry_memory=ram;post_memory=actual;entry_files=_files;post_files=boundary.copy_filesystem()})::!snapshots;
   active:=rest
  |_->());
  if o=B.origin"PLI1.OVL"0x02f0 then(
   let call=B.verify_call bridge (B.Recursive Pli80_host.Recursive_parent.Parent)(Option.get !previous)~entry:state in
   let ram=boundary.copy_memory()and files=boundary.copy_filesystem()and dma=boundary.dma in
   let negative=ref 0 in let rejects fn=incr negative;match fn()with exception Invalid_argument _->()|_->failwith(Printf.sprintf"malformed root accepted negative %d at %d" !negative step_index)in
   rejects(fun()->B.verify_call bridge (B.Recursive Pli80_host.Recursive_parent.Parent) {(Option.get !previous)with origin=B.origin"PLI2.OVL"0x6273}~entry:state);
   rejects(fun()->prepare_root bridge input ~call ~origin:(B.origin"PLI2.OVL"0x02f0)boundary);
   rejects(fun()->prepare_root bridge input ~call ~origin:o {boundary with state={state with pc=state.pc+1}});
   rejects(fun()->prepare_root bridge input ~call ~origin:o {boundary with state={state with c=256}});
   rejects(fun()->prepare_root bridge input ~call ~origin:o {boundary with state={state with sp=0xa945}});
   let changed address=let value=(Char.code(Bytes.get ram address)+1)land 255 in {boundary with copy_memory=(fun()->let b=Bytes.copy ram in Bytes.set b address(Char.chr value);b);preview_host_program=(fun p->boundary.preview_host_program{p with effects=Runner.Memory_write(address,value)::p.effects})}in
   List.iter(fun address->rejects(fun()->prepare_root bridge input ~call ~origin:o(changed address)))[0x24f0;0x25cd;0x25e8;0x265e;0x33e2;0x2d79;0x883e;0x891f;state.sp];
   let altered address value={boundary with copy_memory=(fun()->let b=Bytes.copy ram in Bytes.set b address(Char.chr value);b);preview_host_program=(fun p->boundary.preview_host_program{p with effects=Runner.Memory_write(address,value)::p.effects})}in
   rejects(fun()->prepare_root bridge input ~call ~origin:o(altered 0x20c3 0x28));
   rejects(fun()->prepare_root bridge input ~call ~origin:o(altered 0xaa1a 1));
   require(boundary.copy_memory()=ram&&boundary.dma=dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())files)"negative preparation leaked live state";
   let logical=ref[]in
   match prepare_root ~observe:(fun call entry memory p service_result->logical:=(call,entry,Bytes.copy memory,p,service_result)::!logical)bridge input ~call ~origin:o boundary with
   |exception Invalid_argument m when m="reentrant acquisition bridge: required acquisition-family implementation is unfinished"->
    require(boundary.copy_memory()=ram&&boundary.dma=dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())files)"rejected preparation leaked live state";
    pending:={pending_caller=call.coordinate;pending_entry_step=step_index;entry_sp=state.sp;reason=m}::!pending
   |exception Acquisition_family_bridge.Unfinished(_,_,_,_)->
    require(boundary.copy_memory()=ram&&boundary.dma=dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())files)"unfinished field80 leaked live state";
    pending:={pending_caller=call.coordinate;pending_entry_step=step_index;entry_sp=state.sp;reason="field80 recursive family preparation unfinished"}::!pending
   |p->
    if !active=[]then(composed:= !logical@ !composed;logical_trees:=(step_index,List.rev !logical)::!logical_trees);
    if route p="repeat" then List.iter(fun off->rejects(fun()->prepare_root bridge input ~call ~origin:o(changed(off+0x2200))))[0x6556;0x6564;0x65f0;0x6273;0x671f];
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
   let expected=List.filter(fun(c:N.case)->outer.entry_step<c.entry_step&&c.return_step<outer.return_step)native_children.cases|>List.sort(fun(x:N.case)(y:N.case)->compare x.return_step y.return_step)in
   require(List.map(fun(call,entry,_,(p:RB.prepared),_)->call.RB.coordinate,entry,p.state,p.result.route)children=
    List.map(fun(c:N.case)->c.caller,c.input,c.output,c.route)expected)"internal6223 chronology";
   List.iter(fun(call,entry,memory,(p:RB.prepared),(service_result:Runner.host_program_result))->
    let c=List.find(fun(c:N.case)->c.input=entry&&c.caller=call.RB.coordinate)expected in
    let snap=List.assoc c.entry_step native_children.snapshots in
    require(memory=snap.entry_memory&&service_result.memory=snap.post_memory&&p.state=c.output)"internal6223 fullRAM checkpoint";
    require(p.journal=c.prepared.journal&&p.logical_writes=c.prepared.logical_writes)"internal6223 writer chronology";
    let own_services=List.fold_left(fun n->function Runner.Dispatch_bdos _->n+1|_->n)0 p.program.effects in
    let services=List.filteri(fun i _->i>=List.length service_result.services-own_services)service_result.services in
    require(service_result.dma=c.post_dma&&services=c.services&&Cpm.Filesystem.equal service_result.filesystem snap.post_files)"internal6223 external checkpoint")children)!logical_trees;
  List.iter(fun(c:case)->
   let children=List.filter(fun(w:Native_wrapper_acquisition.case)->c.entry_step<w.entry_step&&w.return_step<c.return_step)(Native_wrapper_acquisition.cases wrapper_children)in
   List.iter(fun(w:Native_wrapper_acquisition.case)->
    let wanted=w.prepared.journal in
    let normalize xs=match xs with []->[]|first::_->List.map(fun(v:B.write)->v.address,v.value,v.writer,v.depth-first.B.depth,v.kind)xs in
    let rec scan xs=match xs with
    |[]->failwith"missing internal6619 journal"
    |first::rest->if first.B.address=(List.hd wanted).address&&first.writer=(List.hd wanted).writer then(
      let rec take n ys=if n=0 then[]else match ys with []->[]|v::vs->v::take(n-1)vs in
      let actual=take(List.length wanted)xs in
      if normalize actual<>normalize wanted then scan rest)
      else scan rest in
    scan c.prepared.journal;
    let calls=List.filter(fun(v:B.write)->v.writer=0x883e&&v.kind="compatibility")c.prepared.journal in
    require(List.exists(fun(v:B.write)->v.address=w.input.sp&&v.value=0x41)calls&&List.exists(fun(v:B.write)->v.address=w.input.sp+1&&v.value=0x88)calls)"internal6619 CALL/SP/continuation correlation")children)!cases;
  List.iter(fun(c:case)->List.iter(fun(w:P.case)->
   let wanted=w.prepared.journal in
   let normalize xs=match xs with []->[]|first::_->List.map(fun(v:B.write)->v.address,v.value,v.writer,v.depth-first.B.depth,v.kind)xs in
   let rec take n xs=if n=0 then[]else match xs with[]->[]|v::vs->v::take(n-1)vs in
   let rec find xs=match xs with []->failwith"missing canonical19F0 journal"|_::rest->if normalize(take(List.length wanted)xs)<>normalize wanted then find rest in
   find c.prepared.journal)(List.filter(fun(w:P.case)->c.entry_step<w.entry_step&&w.return_step<c.return_step)parent_children.cases))!cases;
  Ok{cases=List.sort(fun(x:case)(y:case)->compare x.entry_step y.entry_step)!cases;pending=List.rev !pending;historical;snapshots= !snapshots;records=List.rev !all_records;input_digest=Experiment.sha256_hex(Marshal.to_bytes input[])}

let controller ?(exclude_entry_steps=[]) v input=
 require(v.pending=[])"cannot enable an unfinished logical proof";
 let first,last=0x02f0,0x067c in
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
  let call=B.verify_call bridge (B.Recursive Pli80_host.Recursive_parent.Parent) previous ~entry:boundary.state in
  let p=prepare_root bridge input ~call ~origin boundary in
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
 let t=Native_dispatch.create ~image:"PLI1.OVL" ~entry_pc:(first+0x2200) ~end_pc:(last+0x2200) ~oracles ~records:v.records ~prepare in
 Native_dispatch.with_host_program t(fun _ _->let p=Option.get !pending in pending:=None;p)
let compare_external v (r:Experiment.result)=
 require(Cpm.Filesystem.equal r.filesystem v.historical.filesystem)"final filesystem";
 let event(e:Experiment.file_event)=e.operation,e.file,e.succeeded,e.logical_record,e.byte_range in
 require(List.map event r.file_events=List.map event v.historical.file_events)"file event order";
 require(r.int_bytes=v.historical.int_bytes&&r.rel_bytes=v.historical.rel_bytes)"INT/REL identity"
let run v input controllers=match Native_dispatch.run input controllers with Error _ as e->e|Ok(_,r)as q->compare_external v r;q
let single v input=run v input[controller v input]
