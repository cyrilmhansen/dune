[@@@warning "-4-40-41-42"]
module E=Pli80_host.Int_emitter
module S=Pli80_host.State
type t={resident:bytes;overlay:bytes;code:(int*bytes)list}
type call={coordinate:string;site:int;resume:int;image:string;offset:int}
type prepared={plan:E.plan;program:Runner.host_program;state:Runner.state_snapshot;
  logical_writes:(int*int)list;compatibility_writes:(int*int)list}
let require b message=if not b then invalid_arg("INT emitter bridge: "^message)
let word b a=Char.code(Bytes.get b a)lor(Char.code(Bytes.get b(a+1))lsl 8)
let create ~pli_com ~pli1 =
 require(Experiment.sha256_hex pli_com="c6d9c7b697b8909e7ff7326f25bf870d0e9f52b6444fe517c2484742a23bcd80")"wrong resident image";
 require(Experiment.sha256_hex pli1="1ed6d00f423ffb55ab4ea9a49c33a72617b7ccc5ead5ecdcb5bbf1733214e564")"wrong overlay image";
 let code=List.map(fun(a,b)->a+0x100,Bytes.sub pli_com a(b-a))
   [0xef6,0xf2d;0x2ee,0x2fe;0x328,0x338;0x19bb,0x19d7;0x1a0f,0x1a1c] in
 {resident=Bytes.copy pli_com;overlay=Bytes.copy pli1;code}
let verify_call t (p:Native_dispatch.previous) ~(entry:Runner.state_snapshot) =
 let site=I8080.Step.pc_before p.step in
 let image,offset,bytes=match p.origin with
  |Analysis.Execution_map.Image_byte{image;offset} when image.drive=0 && image.user=0->
    let bytes,base=match image.name with "PLI.COM"->t.resident,0x100|"PLI1.OVL"->t.overlay,0x2200|_->invalid_arg "Unsupported emitter caller image"in
    require(site=base+offset)"caller runtime/canonical mismatch";image.name,offset,bytes
  |_->invalid_arg "Emitter lacks canonical CALL ancestry"in
 require(offset>=0 && offset+3<=Bytes.length bytes && Char.code(Bytes.get bytes offset)=0xcd && word bytes(offset+1)=0xff6)"not immutable emitter CALL";
 require(p.before.pc=site && p.after=entry && entry.pc=0xff6 && p.before.sp=Pli80_host.U16.wrap(entry.sp+2)
  && I8080.Step.fetched_bytes p.step=Bytes.sub bytes offset 3
  && I8080.Step.pc_after p.step=0xff6
  && I8080.Step.control_flow p.step=I8080.Step.Call{target=0xff6;taken=true})"actual CALL/SP/register ancestry";
 let resume=Pli80_host.U16.wrap(site+3) in
 let writes=List.filter_map(function I8080.Step.Write q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses p.step)in
 require(List.sort compare writes=List.sort compare[entry.sp,resume land 255;Pli80_host.U16.wrap(entry.sp+1),resume lsr 8])"CALL continuation writer";
 {coordinate=Printf.sprintf"%s+%04X"image offset;site;resume;image;offset}
let parity v=let n=ref v and count=ref 0 in while !n<>0 do count:= !count+(!n land 1);n:= !n lsr 1 done;!count mod 2=0
let cmp (s:Runner.state_snapshot) a b =let q=(a-b)land 255 in
 {s with sign=q land 128<>0;zero=q=0;auxiliary_carry=(a land 15)>=(b land 15);parity=parity q;carry=a<b}
let prepare t ~call ~origin ~(state:Runner.state_snapshot) ~memory =
 require(state.pc=0xff6)"wrong entry PC";
 require(match origin with Analysis.Execution_map.Image_byte{image;offset}->image.name="PLI.COM"&&image.drive=0&&image.user=0&&offset=0xef6|_->false)"wrong canonical emitter entry";
 List.iter Pli80_host.U8.check[state.a;state.b;state.c;state.d;state.e;state.h;state.l];Pli80_host.U16.check state.sp;
 let m=S.of_bytes memory in
 List.iter(fun(a,b)->require(Bytes.sub memory a(Bytes.length b)=b)"altered emitter/wrapper/bridge code")t.code;
 let caller=if call.image="PLI.COM"then t.resident else t.overlay in
 require(Bytes.sub memory call.site 3=Bytes.sub caller call.offset 3)"altered caller code";
 require(S.word m state.sp=call.resume)"malformed outer continuation";
 let flush=S.read m 0x1e0c=127 in
 let stack=List.init(if flush then 12 else 2)(fun i->Pli80_host.U16.wrap(state.sp-(if flush then 10 else 0)+i))in
 let code=List.concat_map(fun(a,b)->List.init(Bytes.length b)(fun i->a+i))t.code@List.init 3(fun i->call.site+i)in
 let wrapper=[0x205f;0x2060;0x2065;0x2066] in
 let fcb=List.init 36(fun i->0x1ca2+i)in
 let guard=if flush then List.init 3(fun i->5+i)@List.init 3(fun i->0x215c+i)@[0x2155;0x2156;S.word m 0x2155]else []in
 let logical=0x20b0::0x1e0c::0x1e0d::List.init 128(fun i->0x1d8c+i)@wrapper@fcb@guard in
 require(not(List.exists(fun a->List.mem a(code@logical))stack))"stack aliases compiler/service state";
 require(not(List.exists(fun a->List.mem a code)logical))"logical state aliases historical code";
 if flush then (
  require(List.for_all(fun i->S.read m(5+i)=S.read m(0x215c+i))[0;1;2])"BDOS entry guard failure";
  require(S.read m(S.word m 0x2155)=0xaa)"BDOS sentinel guard failure";
  require(not(List.mem(S.word m 0x2155)(wrapper@fcb@List.init 128(fun i->0x1d8c+i)@[0x20b0;0x1e0c;0x1e0d])))"guard/input alias");
 let plan=E.plan m ~input_byte:state.c ~protected:(stack@code@fcb@wrapper@guard) in
 let next=if not plan.flush then cmp {state with a=plan.incremented_index;b=0x1d;c=0x8c;h=plan.destination lsr 8;l=plan.destination land 255}plan.incremented_index 0x80
  else cmp {state with a=0;b=0;c=21;d=0x1c;e=0xa2;h=0;l=0}0 0 in
 let next={next with sp=Pli80_host.U16.wrap(state.sp+2);pc=call.resume}in
 let compatibility=ref []and logical_writes=ref []in
 let write a v=Runner.Memory_write(a,v)in
 let push depth value=
  let a=Pli80_host.U16.wrap(state.sp-depth)in
  let pairs=[Pli80_host.U16.wrap(a+1),value lsr 8;a,value land 255]in
  compatibility:= !compatibility@pairs;List.map(fun(a,v)->write a v)pairs in
 let continuation offset target=
  require(Char.code(Bytes.get t.resident offset)=0xcd && word t.resident(offset+1)=target)"static residue CALL identity";
  offset+0x100+3 in
 require(Char.code(Bytes.get t.resident 0x19bb)=0xc5 && Char.code(Bytes.get t.resident 0x19bc)=0xd5)"guard bridge PUSH identity";
 let service function_number argument callsite wrapper_call scratch =
  let bc=(argument land 0xff00)lor function_number in
  let guard_state=cmp {state with a=0xaa;b=bc lsr 8;c=bc land 255;d=argument lsr 8;e=argument land 255;
    h=S.word m 0x2155 lsr 8;l=S.word m 0x2155 land 255;sp=Pli80_host.U16.wrap(state.sp-4);pc=5}0xaa 0xaa in
  let resume={guard_state with a=0;b=0;h=0;l=0}in
  let scratch_writes=[scratch+1,argument lsr 8;scratch,argument land 255]in
  logical_writes:= !logical_writes@scratch_writes;
  push 2(continuation callsite wrapper_call)@List.map(fun(a,v)->write a v)scratch_writes
  @push 4(continuation(if function_number=26 then 0x2fa else 0x334)0x1abb)
  @push 6 bc@push 8 argument@push 10(continuation 0x19c3 0x1b0f)
  @[Runner.Dispatch_bdos{call_state=guard_state;expected_resume=resume}]in
 let effects=List.concat_map(function
  |E.Write w->logical_writes:= !logical_writes@[w.address,w.value];[write w.address w.value]
  |E.Set_dma address->service 26 address 0xf16 0x3ee 0x205f
  |E.Sequential_write fcb->service 21 fcb 0xf21 0x428 0x2065)plan.effects in
 let validate (r:Runner.host_program_result)=
  let functions=List.map(fun(s:Runner.host_service)->s.call_state.c)r.services in
  if functions<>(if flush then[26;21]else[])then Error"emitter host-service order"
  else if flush && (List.exists(fun(s:Runner.host_service)->
    Char.code(Bytes.get s.memory_before 0x1e0c)<>(if s.call_state.c=26 then 128 else 0)
    ||(s.call_state.c=21 && s.dma_before<>0x1d8c))r.services)
  then Error"emitter DMA-before-reset / reset-before-write chronology"
  else if flush && (r.dma<>0x1d8c || Char.code(Bytes.get r.memory 0x1e0c)<>0)then Error"emitter DMA/reset chronology"
  else Ok()in
 {plan;program={Runner.effects;next_state=next;validate;on_commit=ignore};state=next;logical_writes= !logical_writes;compatibility_writes= !compatibility}
