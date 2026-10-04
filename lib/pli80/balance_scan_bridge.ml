[@@@warning "-4-40-41-42"]
type t = { image : bytes; code : (int * bytes) list; residues : (int * int) list }
type call = { coordinate : string; runtime_site : int; resume : int }
type prepared = {
  result : Pli80_host.Balance_scan.result; memory : bytes;
  state : Runner.state_snapshot; compatibility_writes : (int * int) list;
}
let require b message=if not b then invalid_arg("7B7A bridge: "^message)
let word bytes a=Char.code(Bytes.get bytes a)lor(Char.code(Bytes.get bytes(a+1))lsl 8)
let create ~pli1 =
  require(Experiment.sha256_hex pli1="1ed6d00f423ffb55ab4ea9a49c33a72617b7ccc5ead5ecdcb5bbf1733214e564")"wrong historical image identity";
  let image=Bytes.copy pli1 in
  let residues=List.map(fun(depth,site,target)->
    require(Char.code(Bytes.get image site)=0xcd && word image(site+1)=target)"residue CALL encoding";
    depth,0x2200+site+3)[2,0x7b87,0x9c63;4,0x7a6b,0x9c4d] in
  let code=List.map(fun(a,b)->0x2200+a,Bytes.sub image a(b-a))[0x7b7a,0x7ba2;0x7a4d,0x7a79]in
  {image;code;residues}
let verify_call t ~origin ~(before:Runner.state_snapshot) ~(after:Runner.state_snapshot) step ~(entry:Runner.state_snapshot) =
  let site=I8080.Step.pc_before step in
  let offset=site-0x2200 in
  require(match origin with Analysis.Execution_map.Image_byte{image;offset=o}->image.name="PLI1.OVL" && image.drive=0 && image.user=0 && o=offset|_->false)"unvalidated canonical CALL site";
  require(offset>=0 && offset+3<=Bytes.length t.image && Char.code(Bytes.get t.image offset)=0xcd && word t.image(offset+1)=0x9d7a)"not a historical CALL7B7A site";
  require(I8080.Step.fetched_bytes step=Bytes.sub t.image offset 3
    && I8080.Step.control_flow step=I8080.Step.Call{target=0x9d7a;taken=true}
    && before.pc=site && entry.pc=0x9d7a
    && I8080.Step.pc_after step=0x9d7a && after=entry
    && before.sp=(entry.sp+2)land 65535)"actual CALL/state/SP ancestry";
  let resume=(site+3)land 65535 in
  let writes=List.filter_map(function I8080.Step.Write q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses step)in
  require(List.sort compare writes=List.sort compare[entry.sp,resume land 255;(entry.sp+1)land 65535,resume lsr 8])"original return-slot writer";
  {coordinate=Printf.sprintf"PLI1.OVL+%04X"offset;runtime_site=site;resume}
let prepare t ~call ~origin ~(state:Runner.state_snapshot) ~memory =
  require(state.pc=0x9d7a)"wrong entry PC";
  require(match origin with Analysis.Execution_map.Image_byte{image;offset}->image.name="PLI1.OVL" && image.drive=0 && image.user=0 && offset=0x7b7a|_->false)"wrong entry identity";
  List.iter Pli80_host.U8.check[state.a;state.b;state.c;state.d;state.e;state.h;state.l];Pli80_host.U16.check state.sp;
  let m=Pli80_host.State.of_bytes memory in
  List.iter(fun(a,b)->require(Bytes.sub memory a(Bytes.length b)=b)"changed helper/scan code")t.code;
  require(Bytes.sub memory call.runtime_site 3=Bytes.sub t.image(call.runtime_site-0x2200)3)"changed caller code";
  require(Pli80_host.State.word m state.sp=call.resume)"malformed continuation";
  let protected=List.init 6(fun i->Pli80_host.U16.wrap(state.sp-4+i))in
  require(not(List.exists(fun a->List.exists(fun(b,c)->a>=b && a<b+Bytes.length c)t.code || (a>=call.runtime_site && a<call.runtime_site+3))protected))"stack/code alias";
  let result=Pli80_host.Balance_scan.run m ~cursor:state.c ~protected in
  let compatibility_writes=List.concat_map(fun(depth,value)->
    let a=Pli80_host.U16.wrap(state.sp-depth)in[a,value land 255;Pli80_host.U16.wrap(a+1),value lsr 8])t.residues in
  List.iter(fun(a,v)->Pli80_host.State.write m a v)compatibility_writes;
  let state={state with a=result.stop_cursor;b=0;c=0;h=0xae;l=0x49;
    sp=Pli80_host.U16.wrap(state.sp+2);pc=call.resume;
    sign=false;zero=true;auxiliary_carry=true;parity=true;carry=false}in
  {result;memory=Pli80_host.State.copy m;state;compatibility_writes}
