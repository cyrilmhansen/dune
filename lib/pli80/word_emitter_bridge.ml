[@@@warning "-4-40-41-42"]
module S=Pli80_host.State
module W=Pli80_host.Mapped_word
module E=Pli80_host.Word_emitter
type operation=Mapped_word|Low|High
type t={image:bytes;code:(int*bytes)list;resident_code:int list;emitter:Int_emitter_bridge.t}
type call={coordinate:string;site:int;resume:int;operation:operation}
type result=Word of W.result|Emission of E.selection * Pli80_host.Int_emitter.plan
type prepared={result:result;program:Runner.host_program;state:Runner.state_snapshot;
 logical_writes:(int*int)list;compatibility_writes:(int*int)list;
 residue_writers:(int*int*int)list}
let require b msg=if not b then invalid_arg("Word emitter bridge: "^msg)
let word b a=Char.code(Bytes.get b a)lor(Char.code(Bytes.get b(a+1))lsl 8)
let extent=function Mapped_word->0x7a79,0x7a93|Low->0x7e46,0x7e56|High->0x7e56,0x7e5f
let operation=function 0x9c79->Mapped_word|0xa046->Low|0xa056->High|_->invalid_arg"Unsupported word operation entry"
let create ~pli_com ~pli1 =
 let emitter=Int_emitter_bridge.create ~pli_com ~pli1 in
 let code=List.map(fun(a,b)->a+0x2200,Bytes.sub pli1 a(b-a))[extent Mapped_word;extent Low;extent High]in
 let resident_code=List.concat_map(fun(a,b)->List.init(b-a)(fun i->a+0x100+i))
  [0xef6,0xf2d;0x2ee,0x2fe;0x328,0x338;0x19bb,0x19d7;0x1a0f,0x1a1c]in
 {image=Bytes.copy pli1;code;resident_code;emitter}
let verify_call t (p:Native_dispatch.previous) ~(entry:Runner.state_snapshot)=
 let operation=operation entry.pc in
 let site=I8080.Step.pc_before p.step and offset=p.before.pc-0x2200 in
 require(match p.origin with Analysis.Execution_map.Image_byte{image;offset=o}->image.name="PLI1.OVL"&&image.drive=0&&image.user=0&&o=offset|_->false)"canonical CALL ancestry";
 require(offset>=0&&offset+3<=Bytes.length t.image&&Char.code(Bytes.get t.image offset)=0xcd&&word t.image(offset+1)=entry.pc)"immutable CALL identity";
 require(p.before.pc=site&&p.after=entry&&I8080.Step.pc_after p.step=entry.pc
  &&I8080.Step.fetched_bytes p.step=Bytes.sub t.image offset 3
  &&I8080.Step.control_flow p.step=I8080.Step.Call{target=entry.pc;taken=true}
  &&p.before.sp=Pli80_host.U16.wrap(entry.sp+2))"actual CALL/state/SP relation";
 let resume=Pli80_host.U16.wrap(site+3)in
 let writes=List.filter_map(function I8080.Step.Write q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses p.step)in
 require(List.sort compare writes=List.sort compare[entry.sp,resume land 255;Pli80_host.U16.wrap(entry.sp+1),resume lsr 8])"actual CALL continuation writer";
 {coordinate=Printf.sprintf"PLI1.OVL+%04X"offset;site;resume;operation}
let prepare t ~call ~origin ~(state:Runner.state_snapshot) ~memory =
 let first,_=extent call.operation in
 require(state.pc=first+0x2200)"wrong entry PC";
 require(match origin with Analysis.Execution_map.Image_byte{image;offset}->image.name="PLI1.OVL"&&image.drive=0&&image.user=0&&offset=first|_->false)"wrong canonical entry";
 List.iter Pli80_host.U8.check[state.a;state.b;state.c;state.d;state.e;state.h;state.l];Pli80_host.U16.check state.sp;
 let m=S.of_bytes memory in
 List.iter(fun(a,b)->require(Bytes.sub memory a(Bytes.length b)=b)"changed historical mapped-word/wrapper code")t.code;
 require(call.site>=0x2200&&call.site+3<=0x2200+Bytes.length t.image
  &&Bytes.sub memory call.site 3=Bytes.sub t.image(call.site-0x2200)3)"changed outer CALL";
 require(call.resume=Pli80_host.U16.wrap(call.site+3)
  &&Char.code(Bytes.get t.image(call.site-0x2200))=0xcd
  &&word t.image(call.site-0x2200+1)=state.pc)"outer CALL target/continuation identity";
 require(S.word m state.sp=call.resume)"malformed outer continuation";
 let flush=call.operation<>Mapped_word&&S.read m 0x1e0c=127 in
 let depth=if call.operation=Mapped_word then 0 else if flush then 12 else 2 in
 let stack=List.init(depth+2)(fun i->Pli80_host.U16.wrap(state.sp-depth+i))in
 let code=List.concat_map(fun(a,b)->List.init(Bytes.length b)(fun i->a+i))t.code@List.init 3(fun i->call.site+i)in
 require(not(List.exists(fun a->List.mem a code)stack))"stack/code alias";
 if call.operation<>Mapped_word then (
  let emitter_state=[0x20b0;0x1e0c;0x1e0d;0x205f;0x2060;0x2065;0x2066]
   @List.init 128(fun i->0x1d8c+i)@List.init 36(fun i->0x1ca2+i)in
  let guard=if flush then [5;6;7;0x2155;0x2156;0x215c;0x215d;0x215e;S.word m 0x2155]else[]in
  require(not(List.exists(fun a->List.mem a(emitter_state@guard@t.resident_code))stack))"outer stack aliases emitter/service state");
 let protected=stack@code in
 let abi=ref[]and writers=ref[]in
 let internal_call site target =
  let off=site-0x2200 in
  require(Char.code(Bytes.get t.image off)=0xcd&&word t.image(off+1)=target)"internal static CALL identity";
  let resume=site+3 and slot=Pli80_host.U16.wrap(state.sp-2)in
  let writes=[Pli80_host.U16.wrap(slot+1),resume lsr 8;slot,resume land 255]in
  List.iter(fun(a,v)->S.write m a v;writers:= !writers@[a,v,site])writes;
  abi:= !abi@writes;writes,resume in
 match call.operation with
 |Mapped_word->
  let writes=ref[]in
  let q=W.lookup m ~position:state.c ~protected ~write:(fun w->writes:= !writes@[w.W.address,w.value])in
  let next={state with b=0;c=q.index;d=q.high_address lsr 8;e=q.high_address land 255;
   h=q.high;l=q.low;carry=false;sp=Pli80_host.U16.wrap(state.sp+2);pc=call.resume}in
  {result=Word q;state=next;logical_writes= !writes;compatibility_writes=[];residue_writers=[];
   program={Runner.effects=List.map(fun(a,v)->Runner.Memory_write(a,v))!writes;next_state=next;validate=(fun _->Ok());on_commit=ignore}}
 |Low|High->
  let first_call=if call.operation=Low then fst(internal_call 0xa04a 0x9c79)else[]in
  let emit m (selection:E.selection)=
   let emitter_site=if selection.low_wrapper then 0xa052 else 0xa05b in
   let emitter_call,resume=internal_call emitter_site 0xff6 in
   let child={state with a=selection.emitted_byte;c=selection.emitted_byte;
    h=selection.selected_word lsr 8;l=selection.selected_word land 255;
    sp=Pli80_host.U16.wrap(state.sp-2);pc=0xff6}in
   let child=match selection.lookup with None->child|Some q->{child with b=0;d=q.high_address lsr 8;e=q.high_address land 255;carry=false}in
   let image:Cpm.Filesystem.key={drive=0;user=0;name="PLI.COM"}in
   let child_origin=Analysis.Execution_map.Image_byte{image;offset=0xef6}in
   let child_call:Int_emitter_bridge.call={coordinate=Printf.sprintf"PLI1.OVL+%04X"(emitter_site-0x2200);
    site=emitter_site;resume;image="PLI1.OVL";offset=emitter_site-0x2200}in
   let p=Int_emitter_bridge.prepare t.emitter ~call:child_call ~origin:child_origin ~state:child ~memory:(S.copy m)in
   emitter_call,p in
  let selection,(last_call,p)=
   (if call.operation=Low then E.low else E.high)m ~protected ~emit in
  let wrapper_writes=List.map(fun(w:W.write)->w.address,w.value)selection.writes in
  let next={p.state with sp=Pli80_host.U16.wrap(state.sp+2);pc=call.resume}in
  let effects=List.map(fun(a,v)->Runner.Memory_write(a,v))(first_call@wrapper_writes@last_call)@p.program.effects in
  (* Concrete child entry is S-2. Its verified service CALL/PUSH planner supplies
     deeper writers; the last wrapper emitter CALL overwrites the lookup CALL. *)
  let child_sp=Pli80_host.U16.wrap(state.sp-2)in
  List.iteri(fun i (a,v)->
   let depth=(child_sp-a)land 65535 in
   let base=if depth mod 2=0 then depth else depth+1 in
   let site=match base with 2->if i<10 then 0x1016 else 0x1021|4->if i<10 then 0x3fa else 0x434|6->0x1abb|8->0x1abc|10->0x1ac3|_->invalid_arg"Unknown emitter ABI writer"in
   writers:= !writers@[a,v,site])p.compatibility_writes;
  {result=Emission(selection,p.plan);state=next;logical_writes=wrapper_writes@p.logical_writes;
   compatibility_writes= !abi@p.compatibility_writes;residue_writers= !writers;
   program={p.program with effects;next_state=next}}
