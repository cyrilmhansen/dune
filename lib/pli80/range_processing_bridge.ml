[@@@warning "-4-40-41-42"]
module H=Pli80_host.Range_processing
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
module U=Pli80_host.U16
type t={image:bytes;recursive:Recursive_mapped_bridge.t;balance:Balance_scan_bridge.t;
 publication:Mapped_publication_bridge.t;attribute:Attribute_auxiliary_bridge.t;
 word:Word_emitter_bridge.t;emitter:Int_emitter_bridge.t}
type call={coordinate:string;site:int;resume:int}
type write={address:int;value:int;writer:int;depth:int;kind:string}
type child={site:int;operation:H.operation;input:Runner.state_snapshot;output:Runner.state_snapshot;
 recursive:R.result option;balance:Pli80_host.Balance_scan.result option}
type prepared={result:H.result;program:Runner.host_program;state:Runner.state_snapshot;
 journal:write list;children:child list;logical_writes:(int*int)list;compatibility_writes:(int*int)list}
let require b m=if not b then invalid_arg("7D53 bridge: "^m)
let word b a=Char.code(Bytes.get b a)lor(Char.code(Bytes.get b(a+1))lsl 8)
let create ~pli_com ~pli1={image=Bytes.copy pli1;
 recursive=Recursive_mapped_bridge.create ~pli_com ~pli1;balance=Balance_scan_bridge.create ~pli1;
 publication=Mapped_publication_bridge.create ~pli1;attribute=Attribute_auxiliary_bridge.create ~pli1;
 word=Word_emitter_bridge.create ~pli_com ~pli1;emitter=Int_emitter_bridge.create ~pli_com ~pli1}
let origin image offset=Analysis.Execution_map.Image_byte{image={Cpm.Filesystem.drive=0;user=0;name=image};offset}
let verify_call t (p:Native_dispatch.previous) ~(entry:Runner.state_snapshot)=
 let site=p.before.pc and off=p.before.pc-0x2200 in
 require(p.origin=origin "PLI1.OVL" off &&off>=0&&off+3<=Bytes.length t.image
  &&Char.code(Bytes.get t.image off)=0xcd&&word t.image(off+1)=0x9f53)"canonical CALL ancestry";
 require(p.after=entry&&entry.pc=0x9f53&&I8080.Step.pc_before p.step=site
  &&I8080.Step.pc_after p.step=entry.pc&&I8080.Step.fetched_bytes p.step=Bytes.sub t.image off 3
  &&I8080.Step.control_flow p.step=I8080.Step.Call{target=entry.pc;taken=true}
  &&p.before.sp=U.wrap(entry.sp+2))"CALL/SP ancestry";
 let resume=U.wrap(site+3)in
 let writes=List.filter_map(function I8080.Step.Write q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses p.step)in
 require(List.sort compare writes=List.sort compare[entry.sp,resume land 255;U.wrap(entry.sp+1),resume lsr 8])"original CALL word";
 {coordinate=Printf.sprintf"PLI1.OVL+%04X"off;site;resume}
let logical (s:Runner.state_snapshot)={R.a=s.a;bc=s.b lsl 8 lor s.c;de=s.d lsl 8 lor s.e;hl=s.h lsl 8 lor s.l;
 flags={sign=s.sign;zero=s.zero;auxiliary_carry=s.auxiliary_carry;parity=s.parity;carry=s.carry}}
let machine template (q:R.returned) sp pc={template with Runner.a=q.a;b=q.bc lsr 8;c=q.bc land 255;
 d=q.de lsr 8;e=q.de land 255;h=q.hl lsr 8;l=q.hl land 255;sp;pc;
 sign=q.flags.sign;zero=q.flags.zero;auxiliary_carry=q.flags.auxiliary_carry;parity=q.flags.parity;carry=q.flags.carry}
let prepare t ~call:(call:call) ~origin:o (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 require(o=origin "PLI1.OVL" 0x7d53&&entry.pc=0x9f53)"wrong canonical entry";
 let memory=boundary.copy_memory()in let m=S.of_bytes memory in
 List.iter Pli80_host.U8.check[entry.a;entry.b;entry.c;entry.d;entry.e;entry.h;entry.l];U.check entry.sp;
 List.iter(fun(a,b)->require(Bytes.sub memory(a+0x2200)(b-a)=Bytes.sub t.image a(b-a))"changed historical root/helper code")
  [0x7d53,0x7e46;0x7a4d,0x7a79;0x7aa9,0x7ad5;0x7ad5,0x7af0;0x7b64,0x7bbf;0x7e46,0x7e5f];
 require(call.site>=0x2200&&call.site+3<=Bytes.length t.image+0x2200
  &&Bytes.sub memory call.site 3=Bytes.sub t.image(call.site-0x2200)3
  &&Char.code(Bytes.get t.image(call.site-0x2200))=0xcd
  &&word t.image(call.site-0x2200+1)=0x9f53&&call.resume=U.wrap(call.site+3)
  &&S.word m entry.sp=call.resume)"malformed continuation/caller identity";
 (* Full historical stack is above the compiler tables. Selected child contracts
    check the deeper recursive frame/scratch/table boundaries independently. *)
 require(entry.sp>=0xae60&&entry.sp<=0xfffc)"root stack/table/scratch alias";
 let effects=ref[]and journal=ref[]and children=ref[]in
 let append item=effects:=item::!effects in
 let put kind depth writer address value=
  S.write m address value;append(Runner.Memory_write(address,value));
  journal:={address;value;writer;depth;kind}::!journal in
 let compat writer depth sp value=
  put "compatibility" depth writer(U.wrap(sp-1))(value lsr 8);
  put "compatibility" depth writer(U.wrap(sp-2))(value land 255)in
 let static_call site target sp depth=
  require(Char.code(Bytes.get t.image site)=0xcd&&word t.image(site+1)=target)"unproven internal CALL";
  compat(site+0x2200)depth sp(site+0x2203)in
 let sync bytes=for a=0 to 65535 do let v=Char.code(Bytes.get bytes a)in if S.read m a<>v then S.write m a v done in
 let staged next={Runner.effects=List.rev !effects;next_state=next;validate=(fun _->Ok());on_commit=ignore}in
 let preview next=match boundary.preview_host_program(staged next)with Ok r->sync r.memory;r|Error e->invalid_arg e in
 let apply_program ~sp (p:Runner.host_program)=
  let reset=ref false in
  List.iter(function
   |Runner.Dispatch_bdos _ as e->append e
   |Runner.Memory_write(a,v)->
    let offset=(sp-a)land 65535 in
    let stack=offset>=1&&offset<=10 in
    let writer=if stack then (match (offset+1)/2 with
     |1->if !reset then 0x1021 else 0x1016
     |2->if !reset then 0x434 else 0x3fa
     |3->0x1abb|4->0x1abc|5->0x1ac3|_->assert false)
     else if a=0x20b0 then 0xff9 else if a=0x1e0c then (if v=0 then 0x101c else 0x100b)
     else if a>=0x1d8c&&a<0x1e8c then 0x1006
     else match a with 0x2060->0x3f1|0x205f->0x3f3|0x2066->0x42b|0x2065->0x42d|_->0 in
    if a=0x1e0c&&v=0 then reset:=true;
    put(if stack then "compatibility"else "logical")1 writer a v)p.effects;
  if List.exists(function Runner.Dispatch_bdos _->true|_->false)p.effects then ignore(preview p.next_state)in
 let child ~site ~operation q=
  let target=match operation with H.Mapping->0x9c4d|Recursive->0x9e1b|Balance->0x9d7a|Emit->0xff6
   |High_attribute->0x9d64|Primary->0x9ca9|Secondary->0x9cbf|Low_word->0xa046|High_word->0xa056|Recycle->0x9da2 in
  static_call site target entry.sp 0;
  let sp=U.wrap(entry.sp-2)in let input=machine entry q sp target in
  let observe writer(w:Pli80_host.Mapped_lookup.write)=put "logical" 1 writer w.address w.value in
  let protected=[sp;U.wrap(sp+1);entry.sp;entry.sp+1]in
  let recursive=ref None and balance=ref None in
  let output=match operation with
  |H.Mapping->let r=Pli80_host.Mapped_lookup.mapped_byte m ~position:input.c ~protected ~write:(observe 0x9c50)in
   {input with a=r.byte;b=0;c=r.index;h=(0xaab4+r.index)lsr 8;l=(0xaab4+r.index)land 255;carry=false}
  |Primary|Secondary->let r=(if operation=Primary then Pli80_host.Auxiliary.read else Pli80_host.Auxiliary.read_secondary)
    m ~position:input.c ~protected ~write:(observe(if operation=Primary then 0x9cac else 0x9cc2))in
   {input with a=r.value;b=0;c=r.index;h=r.address lsr 8;l=r.address land 255;carry=false}
  |High_attribute->let p=Attribute_auxiliary_bridge.prepare t.attribute
    ~call:(Attribute_auxiliary_bridge.internal_call t.attribute(site+0x2200))
    ~origin:(origin "PLI1.OVL" 0x7b64) ~state:input ~memory:(S.copy m)in
   List.iter(observe 0x9d67)p.writes;p.state
  |Recursive->let p=Recursive_mapped_bridge.prepare t.recursive
    ~call:(Recursive_mapped_bridge.internal_call t.recursive(site+0x2200))
    ~origin:(origin "PLI1.OVL" 0x7c1b) ~state:input ~memory:(S.copy m)in
   recursive:=Some p.result;
   List.iter(fun(w:Recursive_mapped_bridge.residue)->put w.kind(w.depth+1)(w.writer+0x2200)w.address w.value)p.journal;
   require(S.copy m=p.memory)"recursive journal completeness";p.state
  |Balance->let p=Balance_scan_bridge.prepare t.balance
    ~call:(Balance_scan_bridge.internal_call t.balance(site+0x2200))
    ~origin:(origin "PLI1.OVL" 0x7b7a) ~state:input ~memory:(S.copy m)in
   balance:=Some p.result;
   List.iter(fun(w:Pli80_host.Mapped_lookup.write)->
    let writer=match w.phase with
     |"cursor_initialization"->0x9d7d|"balance_initialization"->0x9d81
     |"attribute_position"->static_call 0x7b87 0x9c63 sp 1;0x9c66
     |"mapped_position"->static_call 0x7a6b 0x9c4d(U.wrap(sp-2))2;0x9c50
     |"balance_publication"->0x9d8f|"cursor_decrement"->0x9d9a|_->invalid_arg"unproved balance phase"in
    observe writer w)p.result.writes;
   require(S.copy m=p.memory)"balance journal completeness";p.state
  |Recycle->let p=Mapped_publication_bridge.prepare t.publication
    ~call:(Mapped_publication_bridge.internal_call t.publication(site+0x2200))
    ~origin:(origin "PLI1.OVL" 0x7ba2) ~state:input ~memory:(S.copy m)in
   List.iter(fun(w:Pli80_host.Mapped_lookup.write)->
    let writer=match w.phase with
     |"recycle_position"->0x9da5
     |"mapped_write_value"->static_call 0x7bae 0x9cd5 sp 1;0x9cd8
     |"mapped_write_position"->0x9cda|"mapped_publication"->0x9cee|"recycle_cached_index"->0x9dbb
     |_->invalid_arg"unproved recycle phase"in observe writer w)p.writes;
   require(S.copy m=p.memory)"recycle journal completeness";p.state
  |Emit->let c:Int_emitter_bridge.call={coordinate=Printf.sprintf"PLI1.OVL+%04X"site;
    site=site+0x2200;resume=site+0x2203;image="PLI1.OVL";offset=site}in
   let p=Int_emitter_bridge.prepare t.emitter ~call:c ~origin:(origin "PLI.COM" 0xef6) ~state:input ~memory:(S.copy m)in
   apply_program ~sp p.program;p.state
  |Low_word|High_word->let op=if operation=Low_word then Word_emitter_bridge.Low else High in
   let c:Word_emitter_bridge.call={coordinate=Printf.sprintf"PLI1.OVL+%04X"site;site=site+0x2200;resume=site+0x2203;operation=op}in
   let p=Word_emitter_bridge.prepare t.word ~call:c ~origin:(origin "PLI1.OVL"(if op=Low then 0x7e46 else 0x7e56)) ~state:input ~memory:(S.copy m)in
   (* Wrapper prefix and nested emitter suffix have separate proven writers. *)
   let prefix=if op=Low then 5 else 2 in
   List.iteri(fun i e->if i<prefix then match e with
    |Runner.Memory_write(a,v)->let writer=if i<2 then (if op=Low then 0xa04a else 0xa05b)
      else if a=0xae38 then 0x9c7c else 0xa04d in
     put(if i<2 then "compatibility"else "logical")1 writer a v
    |_->invalid_arg"wrapper prefix service"else())p.program.effects;
   let rest=List.filteri(fun i _->i>=prefix)p.program.effects in
   (* Low prefix also leaves a second emitter CALL at S-2. *)
   let rest=if op=Low then (
    let first=List.filteri(fun i _->i<2)rest in
    List.iter(function Runner.Memory_write(a,v)->put "compatibility"1 0xa052 a v|_->assert false)first;
    List.filteri(fun i _->i>=2)rest)else rest in
   apply_program ~sp:(U.wrap(sp-2)){p.program with effects=rest};p.state in
  let output=if List.mem operation[H.Mapping;Primary;Secondary]then {output with sp=entry.sp;pc=site+0x2203}else output in
  require(output.sp=entry.sp&&output.pc=site+0x2203)"internal child return/SP";
  children:={site;operation;input;output;recursive= !recursive;balance= !balance}::!children;
  logical output in
 let result=H.run m ~entry:(logical entry)
  ~write:(fun ~site ~address ~value->put "logical"0(site+0x2200)address value)
  ~push_psw:(fun ~a ~flags->require(Char.code(Bytes.get t.image 0x7d82)=0xf5)"PUSH PSW identity";
    compat 0x9f82 0 entry.sp(a lsl 8 lor flags)) ~call:child in
 let state=machine entry result.returned(U.wrap(entry.sp+2))call.resume in
 let journal=List.rev !journal in
 let logical_writes=List.filter_map(fun w->if w.kind="logical"then Some(w.address,w.value)else None)journal in
 let compatibility_writes=List.filter_map(fun w->if w.kind="compatibility"then Some(w.address,w.value)else None)journal in
 let expected=preview state in
 let validate(r:Runner.host_program_result)=
  if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services
    ||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)
  then Error "root ordered-program/service result mismatch"else Ok()in
 let program={(staged state)with validate}in
 {result;program;state;journal;children=List.rev !children;logical_writes;compatibility_writes}

let internal_call t site =
 let offset=site-0x2200 in
 require(offset>=0&&offset+3<=Bytes.length t.image&&Char.code(Bytes.get t.image offset)=0xcd&&word t.image(offset+1)=0x9f53)"unproven internal CALL";
 {coordinate=Printf.sprintf"PLI1.OVL+%04X"offset;site=site;resume=site+3}
