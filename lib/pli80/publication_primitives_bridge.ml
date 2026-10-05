[@@@warning "-4-40-41-42"]
type t = { image : bytes; code : (int * bytes) list }
type operation = Mapped_word | Secondary
type call = { coordinate : string; runtime_site : int; resume : int; operation : operation }
type result = Word of Pli80_host.Mapped_word.publication | Byte of Pli80_host.Auxiliary.access
type prepared = {
  result : result; writes : Pli80_host.Mapped_lookup.write list; memory : bytes;
  state : Runner.state_snapshot; compatibility_writes : (int * int) list; residue_writer:int option;
}
let require b message=if not b then invalid_arg("Publication primitives bridge: "^message)
let word bytes a=Char.code(Bytes.get bytes a)lor(Char.code(Bytes.get bytes(a+1))lsl 8)
let create ~pli1 =
  require(Experiment.sha256_hex pli1="1ed6d00f423ffb55ab4ea9a49c33a72617b7ccc5ead5ecdcb5bbf1733214e564")"wrong historical image identity";
  let image=Bytes.copy pli1 in
  let code=List.map(fun(a,b)->0x2200+a,Bytes.sub image a(b-a))[0x7af0,0x7b13;0x7b49,0x7b64]in
  {image;code}
let verify_call t ~origin ~(before:Runner.state_snapshot) ~(after:Runner.state_snapshot) step ~(entry:Runner.state_snapshot) =
  let operation,target=match entry.Runner.pc with 0x9cf0->Mapped_word,0x9cf0|0x9d49->Secondary,0x9d49|_->invalid_arg "Unsupported publication entry" in
  let site=I8080.Step.pc_before step in
  let offset=site-0x2200 in
  require(match origin with Analysis.Execution_map.Image_byte{image;offset=o}->image.name="PLI1.OVL" && image.drive=0 && image.user=0 && o=offset|_->false)(Printf.sprintf"unvalidated canonical CALL site runtime%04X entry%04X"site entry.pc);
  require(offset>=0 && offset+3<=Bytes.length t.image && Char.code(Bytes.get t.image offset)=0xcd && word t.image(offset+1)=target)"not a historical selected CALL site";
  require(I8080.Step.fetched_bytes step=Bytes.sub t.image offset 3
    && I8080.Step.control_flow step=I8080.Step.Call{target;taken=true}
    && before.pc=site && entry.pc=target
    && I8080.Step.pc_after step=target && after=entry
    && before.sp=(entry.sp+2)land 65535)"actual CALL/state/SP ancestry";
  let resume=(site+3)land 65535 in
  let writes=List.filter_map(function I8080.Step.Write q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses step)in
  require(List.sort compare writes=List.sort compare[entry.sp,resume land 255;(entry.sp+1)land 65535,resume lsr 8])"original return-slot writer";
  {coordinate=Printf.sprintf"PLI1.OVL+%04X"offset;runtime_site=site;resume;operation}
let extent=function Mapped_word->0x7af0,0x7b13|Secondary->0x7b49,0x7b64
let prepare t ~call ~origin ~(state:Runner.state_snapshot) ~memory =
 let offset,_=extent call.operation in
 require(state.pc=offset+0x2200)"wrong entry PC";
 require(match origin with Analysis.Execution_map.Image_byte{image;offset=o}->image.name="PLI1.OVL"&&image.drive=0&&image.user=0&&o=offset|_->false)"wrong canonical entry";
 List.iter Pli80_host.U8.check[state.a;state.b;state.c;state.d;state.e;state.h;state.l];Pli80_host.U16.check state.sp;
 let m=Pli80_host.State.of_bytes memory in
 List.iter(fun(a,b)->require(Bytes.sub memory a(Bytes.length b)=b)"changed historical code")t.code;
 require(call.runtime_site>=0x2200&&call.runtime_site+3<=Bytes.length t.image+0x2200
  &&Bytes.sub memory call.runtime_site 3=Bytes.sub t.image(call.runtime_site-0x2200)3
  &&Char.code(Bytes.get t.image(call.runtime_site-0x2200))=0xcd
  &&word t.image(call.runtime_site-0x2200+1)=state.pc
  &&call.resume=Pli80_host.U16.wrap(call.runtime_site+3))"changed CALL/continuation identity";
 require(Pli80_host.State.word m state.sp=call.resume)"malformed continuation";
 let depth=if call.operation=Mapped_word then 2 else 0 in
 let stack=List.init(depth+2)(fun i->Pli80_host.U16.wrap(state.sp-depth+i))in
 let code=List.concat_map(fun(a,b)->List.init(Bytes.length b)(fun i->a+i))t.code@List.init 3(fun i->call.runtime_site+i)in
 require(not(List.exists(fun a->List.mem a code)stack))"stack/code alias";
 let protected=stack@code in
 let writes=ref[]and compatibility_writes=ref[]in
 let write w=writes:=w::!writes in
 let save_destination value=
  require(Char.code(Bytes.get t.image 0x7b09)=0xe5&&Char.code(Bytes.get t.image 0x7b0e)=0xe1)"destination PUSH/POP identity";
  let high=Pli80_host.U16.wrap(state.sp-1)and low=Pli80_host.U16.wrap(state.sp-2)in
  List.iter(fun(a,v)->Pli80_host.State.write m a v)[high,value lsr 8;low,value land 255];
  compatibility_writes:=[high,value lsr 8;low,value land 255]in
 let result=match call.operation with
 |Mapped_word->Word(Pli80_host.Mapped_word.publish m ~position:state.c ~value:(state.d lsl 8 lor state.e)~protected
   ~write:(fun(w:Pli80_host.Mapped_word.write)->write{Pli80_host.Mapped_lookup.address=w.address;value=w.value;phase=w.phase})~save_destination)
 |Secondary->Byte(Pli80_host.Auxiliary.publish_secondary m ~position:state.c ~value:state.e ~protected ~write)in
 let next=match result with
 |Word q->{state with b=0;c=q.index;d=q.high;e=q.low;h=q.high_address lsr 8;l=q.high_address land 255;carry=false}
 |Byte q->{state with a=q.value;b=0;c=q.index;h=q.address lsr 8;l=q.address land 255;carry=false}in
 let state={next with sp=Pli80_host.U16.wrap(state.sp+2);pc=call.resume}in
 {result;writes=List.rev !writes;memory=Pli80_host.State.copy m;state;compatibility_writes= !compatibility_writes;
  residue_writer=(if call.operation=Mapped_word then Some 0x9d09 else None)}
