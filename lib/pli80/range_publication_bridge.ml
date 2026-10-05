[@@@warning "-4-40-41-42"]
type t={image:bytes;code:(int*bytes)list}
type call={coordinate:string;runtime_site:int;resume:int}
type journal={address:int;value:int;writer:int;depth:int;kind:string}
type prepared={result:Pli80_host.Range_publication.result;writes:Pli80_host.Mapped_lookup.write list;
 journal:journal list;compatibility_writes:(int*int)list;memory:bytes;state:Runner.state_snapshot}
let require b m=if not b then invalid_arg("Range publication bridge: "^m)
let word b a=Char.code(Bytes.get b a)lor(Char.code(Bytes.get b(a+1))lsl 8)
let create ~pli1=
 require(Experiment.sha256_hex pli1="1ed6d00f423ffb55ab4ea9a49c33a72617b7ccc5ead5ecdcb5bbf1733214e564")"wrong image";
 let image=Bytes.copy pli1 in
 {image;code=List.map(fun(a,b)->a+0x2200,Bytes.sub image a(b-a))[0x7e5f,0x7ec0;0x7ad5,0x7b13;0x7b2e,0x7b64]}
let verify_call t ~origin ~(before:Runner.state_snapshot) ~(after:Runner.state_snapshot) step ~(entry:Runner.state_snapshot) =
  require(entry.pc=0xa05f)"wrong root entry";let target=0xa05f in
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
  {coordinate=Printf.sprintf"PLI1.OVL+%04X"offset;runtime_site=site;resume}
let prepare t ~call ~origin ~(state:Runner.state_snapshot) ~memory =
 require(state.pc=0xa05f)"wrong entry";
 require(match origin with Analysis.Execution_map.Image_byte{image;offset}->image.name="PLI1.OVL"&&image.drive=0&&image.user=0&&offset=0x7e5f|_->false)"wrong canonical entry";
 List.iter Pli80_host.U8.check[state.a;state.b;state.c;state.d;state.e;state.h;state.l];Pli80_host.U16.check state.sp;
 let m=Pli80_host.State.of_bytes memory in
 List.iter(fun(a,b)->require(Bytes.sub memory a(Bytes.length b)=b)"changed historical code")t.code;
 require(Bytes.sub memory call.runtime_site 3=Bytes.sub t.image(call.runtime_site-0x2200)3&&word memory state.sp=call.resume)"CALL/continuation mismatch";
 let stack=List.init 6(fun i->Pli80_host.U16.wrap(state.sp-4+i))in
 let code=List.concat_map(fun(a,b)->List.init(Bytes.length b)(fun i->a+i))t.code@List.init 3(fun i->call.runtime_site+i)in
 require(not(List.exists(fun a->List.mem a code)stack))"stack/code alias";
 let writes=ref[]and journal=ref[]in
 let record writer depth kind address value=journal:={address;value;writer;depth;kind}::!journal in
 let write ~site ~address ~value=
  writes:={Pli80_host.Mapped_lookup.address;value;phase=Printf.sprintf"PLI1+%04X"site}::!writes;
  record(site+0x2200)(if site>=0x7e5f then 0 else 1)"logical" address value in
 let compatibility writer depth slot value=
  List.iter(fun(a,v)->Pli80_host.State.write m a v;record writer depth "ABI" a v)
   [Pli80_host.U16.wrap(slot+1),value lsr 8;slot,value land 255]in
 let call_child site=
  let target=List.assoc site[0x7e95,0x9cd5;0x7ea0,0x9cf0;0x7ea9,0x9d2e;0x7eb2,0x9d49]in
  require(Char.code(Bytes.get t.image site)=0xcd&&word t.image(site+1)=target)"child CALL identity";
  compatibility(site+0x2200)0(Pli80_host.U16.wrap(state.sp-2))(site+0x2203)in
 let save_destination address=
  require(Char.code(Bytes.get t.image 0x7b09)=0xe5&&Char.code(Bytes.get t.image 0x7b0e)=0xe1)"PUSH/POP identity";
  compatibility 0x9d09 1(Pli80_host.U16.wrap(state.sp-4))address in
 let result=Pli80_host.Range_publication.run m ~input_c:state.c ~input_de:(state.d*256+state.e)~protected:(stack@code)~write ~call:call_child ~save_destination in
 let _,flags=Pli80_host.Range_processing.unary
  {Pli80_host.Recursive_mapped.sign=state.sign;zero=state.zero;auxiliary_carry=state.auxiliary_carry;parity=state.parity;carry=false}result.increment_before true in
 let final={state with a=result.returned_a;b=0;c=result.secondary.index;d=result.word.high;e=0;h=0xae;l=0x35;
  sign=flags.sign;zero=flags.zero;auxiliary_carry=flags.auxiliary_carry;parity=flags.parity;carry=flags.carry;
  sp=Pli80_host.U16.wrap(state.sp+2);pc=call.resume}in
 let latest=Hashtbl.create 4 in
 List.iter(fun w->if w.kind="ABI" then Hashtbl.replace latest w.address w.value)(List.rev !journal);
 let compatibility_writes=Hashtbl.to_seq latest|>List.of_seq|>List.sort compare in
 {result;writes=List.rev !writes;journal=List.rev !journal;compatibility_writes;memory=Pli80_host.State.copy m;state=final}
