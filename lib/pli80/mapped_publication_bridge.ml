[@@@warning "-4-40-41-42"]
type t = { image : bytes; code : (int * bytes) list; residue : int }
type operation = Publish | Recycle
type call = { coordinate : string; runtime_site : int; resume : int; operation : operation }
type prepared = {
  result : Pli80_host.Mapped_publication.result; writes : Pli80_host.Mapped_lookup.write list; memory : bytes;
  state : Runner.state_snapshot; compatibility_writes : (int * int) list;
}
let require b message=if not b then invalid_arg("Mapped publication bridge: "^message)
let word bytes a=Char.code(Bytes.get bytes a)lor(Char.code(Bytes.get bytes(a+1))lsl 8)
let create ~pli1 =
  require(Experiment.sha256_hex pli1="1ed6d00f423ffb55ab4ea9a49c33a72617b7ccc5ead5ecdcb5bbf1733214e564")"wrong historical image identity";
  let image=Bytes.copy pli1 in
  require(Char.code(Bytes.get image 0x7bae)=0xcd && word image 0x7baf=0x9cd5)"child CALL encoding";
  let residue=0x2200+0x7bae+3 in
  let code=List.map(fun(a,b)->0x2200+a,Bytes.sub image a(b-a))[0x7ad5,0x7af0;0x7ba2,0x7bbf]in
  {image;code;residue}
let verify_call t ~origin ~(before:Runner.state_snapshot) ~(after:Runner.state_snapshot) step ~(entry:Runner.state_snapshot) =
  let operation,target=match entry.Runner.pc with 0x9cd5->Publish,0x9cd5|0x9da2->Recycle,0x9da2|_->invalid_arg "Unsupported mapped publication entry" in
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
let prepare t ~call ~origin ~(state:Runner.state_snapshot) ~memory =
  let offset=match call.operation with Publish->0x7ad5|Recycle->0x7ba2 in
  require(state.pc=offset+0x2200)"wrong entry PC";
  require(match origin with Analysis.Execution_map.Image_byte{image;offset=o}->image.name="PLI1.OVL" && image.drive=0 && image.user=0 && o=offset|_->false)"wrong entry identity";
  List.iter Pli80_host.U8.check[state.a;state.b;state.c;state.d;state.e;state.h;state.l];Pli80_host.U16.check state.sp;
  let m=Pli80_host.State.of_bytes memory in
  List.iter(fun(a,b)->require(Bytes.sub memory a(Bytes.length b)=b)"changed publication/helper code")t.code;
  require(Bytes.sub memory call.runtime_site 3=Bytes.sub t.image(call.runtime_site-0x2200)3)"changed caller code";
  require(Pli80_host.State.word m state.sp=call.resume)"malformed continuation";
  let depth=match call.operation with Publish->0|Recycle->2 in
  let stack=List.init(depth+2)(fun i->Pli80_host.U16.wrap(state.sp-depth+i))in
  let code=List.concat_map(fun(a,b)->List.init(Bytes.length b)(fun i->a+i))t.code
    @List.init 3(fun i->call.runtime_site+i)in
  require(not(List.exists(fun a->List.mem a code)stack))"stack/code alias";
  let protected=stack@code in
  let writes=ref[]in let write w=writes:=w::!writes in
  let result=match call.operation with
    |Publish->Pli80_host.Mapped_publication.Publication(Pli80_host.Mapped_publication.publish m ~position:state.c ~value:state.e ~protected ~write)
    |Recycle->Pli80_host.Mapped_publication.Recycle(Pli80_host.Mapped_publication.recycle m ~position:state.c ~protected ~write)in
  let compatibility_writes=match call.operation with
    |Publish->[]
    |Recycle->let a=Pli80_host.U16.wrap(state.sp-2)in[a,t.residue land 255;Pli80_host.U16.wrap(a+1),t.residue lsr 8]in
  List.iter(fun(a,v)->Pli80_host.State.write m a v)compatibility_writes;
  let a,bc,de,hl=match result with
    |Pli80_host.Mapped_publication.Publication q->q.value,q.index,state.d*256+state.e,q.address
    |Pli80_host.Mapped_publication.Recycle q->q.fresh_index,0xaa1f,q.old_word,0xaa1f+(q.fresh_carrier land 255)in
  let state={state with a;b=bc lsr 8;c=bc land 255;d=de lsr 8;e=de land 255;h=hl lsr 8;l=hl land 255;
    sp=Pli80_host.U16.wrap(state.sp+2);pc=call.resume;carry=false}in
  {result;writes=List.rev !writes;memory=Pli80_host.State.copy m;state;compatibility_writes}

let internal_call t site =
  let offset=site-0x2200 in
  require(offset>=0 && offset+3<=Bytes.length t.image && Char.code(Bytes.get t.image offset)=0xcd) "unproven internal CALL";
  let operation=match word t.image(offset+1) with 0x9cd5->Publish|0x9da2->Recycle|_->invalid_arg "Not a mapped publication CALL" in
  {coordinate=Printf.sprintf "PLI1.OVL+%04X" offset;runtime_site=site;resume=site+3;operation}
