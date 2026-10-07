[@@@warning "-4-40-41-42"]
module B=Acquisition_family_bridge
let require b m=if not b then failwith("family shadow: "^m)
let shadow ?(spine=false) ?(entry_steps=[]) operation input=
 let bridge=B.create ~pli_com:input.Experiment.pli_com ~pli1:input.pli1_ovl in
 let previous=ref None and current_origin=ref Analysis.Execution_map.Unknown and active=ref [] in
 let count=ref 0 and pending=ref 0 and partial=ref None and proofs=ref[]in
 let on_guest_step ~step_index:_ ~before ~after step=
  previous:=Some{Native_dispatch.origin= !current_origin;before;after;step};
  let targets=List.map(fun(_,_,_,_,w,l)->w,l)!active@(match !partial with None->[]|Some(_,_,_,_,w,l)->[w,l])in
  List.iter(fun(writes,latest)->
  List.iter(function I8080.Step.Write w->
   Hashtbl.replace latest w.address(I8080.Step.pc_before step,w.value);
   let opcode=Char.code(Bytes.get(I8080.Step.fetched_bytes step)0)in
   if ((I8080.Step.pc_before step=0x4712&&w.address=before.sp-1)||(match I8080.Step.control_flow step with I8080.Step.Call _->false|_->true)
    &&not(List.mem opcode[0xc5;0xd5;0xe5;0xf5]))then writes:=(w.address,w.value)::!writes|_->())(I8080.Step.memory_accesses step))targets in
 let on_before_instruction ~origin:o ~step_index (boundary:Runner.instruction_boundary)=
  current_origin:=o;let state=boundary.state in
  (match !partial with Some(expected,memory,journal,(external_state:Runner.host_program_result),writes,latest)when state.pc=expected.Runner.pc&&state.sp=expected.Runner.sp&&(not spine||boundary.read_memory(state.sp+2)=Char.code(Bytes.get memory(state.sp+2))&&boundary.read_memory(state.sp+3)=Char.code(Bytes.get memory(state.sp+3)))->
   if state<>expected then failwith(Printf.sprintf"partial entry step %d historical A=%02X BC=%02X%02X DE=%02X%02X HL=%02X%02X flags=%b%b%b%b%b SP=%04X; native A=%02X BC=%02X%02X DE=%02X%02X HL=%02X%02X flags=%b%b%b%b%b SP=%04X"step_index state.a state.b state.c state.d state.e state.h state.l state.sign state.zero state.auxiliary_carry state.parity state.carry state.sp expected.a expected.b expected.c expected.d expected.e expected.h expected.l expected.sign expected.zero expected.auxiliary_carry expected.parity expected.carry expected.sp);
   let actual=boundary.copy_memory()in
   if actual<>memory then(
    let ds=List.init 65536 Fun.id|>List.filter(fun a->Bytes.get actual a<>Bytes.get memory a)in
    failwith("4F54 entry RAM differences "^String.concat","(List.map(fun a->Printf.sprintf"%04X:%02X/%02X"a(Char.code(Bytes.get actual a))(Char.code(Bytes.get memory a)))ds)));
   require(boundary.dma=external_state.Runner.dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())external_state.filesystem)"partial external state";
   require(external_state.services=[])"unexpected service in the proven acquisition prefix";
   let logical=List.rev !writes and planned=List.filter_map(fun(w:B.write)->if w.kind="logical"then Some(w.address,w.value)else None)journal in
   if logical<>planned then(
    let out=open_out "_build/host-compiler-pass-44/stage1/partial-chronology.tsv"in
    List.iteri(fun i(a,v)->Printf.fprintf out "H %d %04X %02X\n"i a v)logical;
    List.iteri(fun i(w:B.write)->if w.kind="logical"then Printf.fprintf out "N %d %04X %02X %04X\n"i w.address w.value w.writer)journal;close_out out;
    let rec first i x y=match x,y with a::xs,b::ys when a=b->first(i+1)xs ys|a::_,b::_->Printf.sprintf"at %d %04X:%02X/%04X:%02X"i(fst a)(snd a)(fst b)(snd b)|_->"length"in failwith("partial chronology "^first 0 logical planned));
   let final=Hashtbl.create 128 in List.iter(fun(w:B.write)->Hashtbl.replace final w.address(w.writer,w.value))journal;
   Hashtbl.iter(fun address value->require(Hashtbl.find_opt latest address=Some value)(Printf.sprintf"checkpoint preceding writer %04X expected %04X:%02X observed %s"address(fst value)(snd value)(match Hashtbl.find_opt latest address with None->"absent"|Some(w,v)->Printf.sprintf"%04X:%02X"w v)))final;
   proofs:=Printf.sprintf"{\"kind\":%S,\"step\":%d,\"pc\":%d,\"sp\":%d,\"context\":%d,\"selector\":%d,\"reader_index\":%d,\"reader_count\":%d,\"memory_sha256\":%S,\"ordered_writes\":%d,\"final_writer_cells\":%d}"(if expected.pc=0x5504 then"3304_entry"else if expected.pc=0x1476 then"resident_numeric_entry"else"4F54_entry")step_index state.pc state.sp (Char.code(Bytes.get actual 0x20c1))(Char.code(Bytes.get actual 0x20c3))(Char.code(Bytes.get actual 0x1f06))(Char.code(Bytes.get actual 0x1f08))(Experiment.sha256_hex actual)(List.length planned)(Hashtbl.length final)::!proofs;
   incr pending;partial:=None
  |_->());
  (match !active with
  |(call,entry,(p:B.prepared),(preview:Runner.host_program_result),writes,latest)::rest when state.pc=call.B.resume&&state.sp=entry.Runner.sp+2->
   if state<>p.state then failwith(Printf.sprintf"family return step %d historical A=%02X BC=%02X%02X DE=%02X%02X HL=%02X%02X flags=%b%b%b%b%b; native A=%02X BC=%02X%02X DE=%02X%02X HL=%02X%02X flags=%b%b%b%b%b"step_index state.a state.b state.c state.d state.e state.h state.l state.sign state.zero state.auxiliary_carry state.parity state.carry p.state.a p.state.b p.state.c p.state.d p.state.e p.state.h p.state.l p.state.sign p.state.zero p.state.auxiliary_carry p.state.parity p.state.carry);
   let actual=boundary.copy_memory()in
   if actual<>preview.memory then(
    let ds=List.init 65536 Fun.id|>List.filter(fun a->Bytes.get actual a<>Bytes.get preview.memory a)in
    failwith("family memory differences "^String.concat","(List.map(fun a->Printf.sprintf"%04X:%02X/%02X"a(Char.code(Bytes.get actual a))(Char.code(Bytes.get preview.memory a)))ds)));
   require(Cpm.Filesystem.equal(boundary.copy_filesystem())preview.filesystem&&boundary.dma=preview.dma)"external state";
   let logical=List.rev !writes in
   if logical<>p.logical_writes then(
    let rec first i a b=match a,b with x::xs,y::ys when x=y->first(i+1)xs ys|x::_,y::_->Printf.sprintf"at %d actual=%04X:%02X native=%04X:%02X"i(fst x)(snd x)(fst y)(snd y)|_->Printf.sprintf"length %d/%d"(List.length logical)(List.length p.logical_writes)in let out=open_out "_build/host-compiler-pass-44/stage1/writes.tsv"in List.iteri(fun i (a,v)->Printf.fprintf out "H %d %04X %02X\n"i a v)logical;List.iteri(fun i(w:B.write)->if w.kind="logical"then Printf.fprintf out "N %d %04X %02X %04X\n"i w.address w.value w.writer)p.journal;close_out out;failwith("family write chronology "^first 0 logical p.logical_writes));
   let final=Hashtbl.create 128 in List.iter(fun(w:B.write)->Hashtbl.replace final w.address(w.writer,w.value))p.journal;
   Hashtbl.iter(fun address value->require(Hashtbl.find_opt latest address=Some value)(Printf.sprintf"final writer %04X"address))final;
   require(Hashtbl.length final=Hashtbl.length latest)"missing observed writer";
   require(state.sp=entry.Runner.sp+2)"return SP";
   proofs:=Printf.sprintf"{\"kind\":\"field15_complete\",\"return_step\":%d,\"memory_sha256\":%S,\"ordered_writes\":%d,\"final_writer_cells\":%d}"step_index(Experiment.sha256_hex actual)(List.length logical)(Hashtbl.length final)::!proofs;
   incr count;active:=rest
  |_->());
  let offset=match operation with B.Context->0x60e5|B.Field->0x5e98|Attribute->0x256c|Spine->0x4f54|Resident->0x1376 in
  if o=B.origin(if operation=B.Resident then"PLI.COM"else"PLI1.OVL")offset&&(entry_steps=[]||List.mem step_index entry_steps)then(
   let call=B.verify_call bridge operation(Option.get !previous)~entry:state in
   let ram=boundary.copy_memory()and dma=boundary.dma and files=boundary.copy_filesystem()in
   let rejects f=match f()with exception Invalid_argument _->()|_->failwith"family malformed entry accepted"in
   rejects(fun()->B.prepare bridge operation ~call ~origin:(B.origin"PLI2.OVL"offset)boundary);
   rejects(fun()->B.prepare bridge operation ~call ~origin:o{boundary with state={state with pc=state.pc+1}});
   rejects(fun()->B.prepare bridge operation ~call ~origin:o{boundary with state={state with sp=0xa6ca}});
   rejects(fun()->B.prepare bridge operation ~call ~origin:o{boundary with copy_memory=(fun()->let b=Bytes.copy ram in Bytes.set b state.pc(Char.chr((Char.code(Bytes.get b state.pc)+1)land 255));b)});
   if operation=B.Resident then(
    let altered edits={boundary with copy_memory=(fun()->let b=Bytes.copy ram in List.iter(fun(a,v)->Bytes.set b a(Char.chr v))edits;b)}in
    List.iter(fun edits->rejects(fun()->B.prepare bridge operation ~call ~origin:o(altered edits)))
     [[0x2012,1];[0x20c4,1];[0x1f06,Char.code(Bytes.get ram 0x1f08)];
      [0x1e8e+Char.code(Bytes.get ram 0x1f06),0x2e];[0x1e8e+Char.code(Bytes.get ram 0x1f06),0x45];[0x20c1,0x27]];
    rejects(fun()->B.prepare bridge operation ~call ~origin:o(altered([0x20c1,0x31;0x1f06,0;0x1f08,200]@List.init 130(fun i->0x1e8e+i,0x31)))));
   require(boundary.copy_memory()=ram&&boundary.dma=dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())files)"family rejected preparation leaked live state";
   match B.prepare ~follow_spine:spine ~recursive:(fun site boundary->
    let t=Reentrant_acquisition_bridge.create ~pli_com:input.pli_com ~pli1:input.pli1_ovl in
    let p=Reentrant_acquisition_bridge.prepare t ~call:(Reentrant_acquisition_bridge.internal_call t site)
     ~origin:(B.origin"PLI1.OVL"0x6223)boundary in p.program,p.state,p.journal)
    bridge operation ~call ~origin:o boundary with
   |exception B.Unfinished(state,ram,journal,external_state)->partial:=Some(state,ram,journal,external_state,ref[],Hashtbl.create 128)
   |exception Invalid_argument m->failwith(Printf.sprintf"prepare step %d: %s"step_index m)
   |p->let preview=match boundary.preview_host_program p.program with Ok r->r|Error e->failwith e in
    active:=(call,state,p,preview,ref[],Hashtbl.create 128)::!active)in
 match Experiment.run ~analysis:Experiment.Execution ~on_guest_step ~on_before_instruction input with
 |Error _->failwith"historical experiment"|Ok _->require(!active=[]&& !partial=None)"missing return/checkpoint"; !count,!pending,List.rev !proofs
