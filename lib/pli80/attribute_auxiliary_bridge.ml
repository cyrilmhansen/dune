[@@@warning "-4-40-41-42"]
type t = { image : bytes; code : (int * bytes) list }
type operation = High_attribute | Second_auxiliary
type call = { coordinate : string; runtime_site : int; resume : int; operation : operation }
type result = High of Pli80_host.Mapped_lookup.high_attribute | Secondary of Pli80_host.Auxiliary.access
type prepared = {
  result : result; writes : Pli80_host.Mapped_lookup.write list; memory : bytes;
  state : Runner.state_snapshot; compatibility_writes : (int * int) list;
}
let require b message=if not b then invalid_arg("Attribute auxiliary bridge: "^message)
let word bytes a=Char.code(Bytes.get bytes a)lor(Char.code(Bytes.get bytes(a+1))lsl 8)
let create ~pli1 =
  require(Experiment.sha256_hex pli1="1ed6d00f423ffb55ab4ea9a49c33a72617b7ccc5ead5ecdcb5bbf1733214e564")"wrong historical image identity";
  let image=Bytes.copy pli1 in
  let code=List.map(fun(a,b)->0x2200+a,Bytes.sub image a(b-a))[0x7b64,0x7b7a;0x7abf,0x7ad5]in
  {image;code}
let verify_call t ~origin ~(before:Runner.state_snapshot) ~(after:Runner.state_snapshot) step ~(entry:Runner.state_snapshot) =
  let operation,target=match entry.Runner.pc with 0x9d64->High_attribute,0x9d64|0x9cbf->Second_auxiliary,0x9cbf|_->invalid_arg "Unsupported attribute/auxiliary entry" in
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
let parity value =
  let rec bits n count=if n=0 then count else bits(n lsr 1)(count+(n land 1))in bits value 0 mod 2=0
let prepare t ~call ~origin ~(state:Runner.state_snapshot) ~memory =
  let offset=match call.operation with High_attribute->0x7b64|Second_auxiliary->0x7abf in
  require(state.pc=offset+0x2200)"wrong entry PC";
  require(match origin with Analysis.Execution_map.Image_byte{image;offset=o}->image.name="PLI1.OVL" && image.drive=0 && image.user=0 && o=offset|_->false)"wrong entry identity";
  List.iter Pli80_host.U8.check[state.a;state.b;state.c;state.d;state.e;state.h;state.l];Pli80_host.U16.check state.sp;
  let m=Pli80_host.State.of_bytes memory in
  List.iter(fun(a,b)->require(Bytes.sub memory a(Bytes.length b)=b)"changed historical leaf code")t.code;
  require(Bytes.sub memory call.runtime_site 3=Bytes.sub t.image(call.runtime_site-0x2200)3)"changed caller code";
  require(Pli80_host.State.word m state.sp=call.resume)"malformed continuation";
  let stack=[state.sp;Pli80_host.U16.wrap(state.sp+1)]in
  let code=List.concat_map(fun(a,b)->List.init(Bytes.length b)(fun i->a+i))t.code
    @List.init 3(fun i->call.runtime_site+i)in
  require(not(List.exists(fun a->List.mem a code)stack))"stack/code alias";
  let protected=stack@code in let writes=ref[]in let write w=writes:=w::!writes in
  let result=match call.operation with
   |High_attribute->High(Pli80_host.Mapped_lookup.high_attribute m ~byte_index:state.c ~protected ~write)
   |Second_auxiliary->Secondary(Pli80_host.Auxiliary.read_secondary m ~position:state.c ~protected ~write)in
  let state=match result with
   |High q->let third=List.nth q.shifts 2 in
     {state with a=q.high3;b=0x1b;c=0x4b;h=q.address lsr 8;l=q.address land 255;
       sign=q.high3 land 128<>0;zero=q.high3=0;parity=parity q.high3;
       auxiliary_carry=(third lor 7)land 8<>0;carry=false}
   |Secondary q->{state with a=q.value;b=0;c=q.index;h=q.address lsr 8;l=q.address land 255;carry=false}in
  let state={state with sp=Pli80_host.U16.wrap(state.sp+2);pc=call.resume}in
  {result;writes=List.rev !writes;memory=Pli80_host.State.copy m;state;compatibility_writes=[]}
