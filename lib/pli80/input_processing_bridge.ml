[@@@warning "-4-40-41-42"]
module H=Pli80_host.Input_processing
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
module U=Pli80_host.U16
type t={image:bytes;range:Range_processing_bridge.t;publication:Range_publication_bridge.t;control:Mapped_control_bridge.t;emitter:Int_emitter_bridge.t}
type call={coordinate:string;site:int;resume:int}
type write=Range_processing_bridge.write={address:int;value:int;writer:int;depth:int;kind:string}
type child={site:int;operation:H.operation;input:Runner.state_snapshot;output:Runner.state_snapshot}
type prepared={result:H.result;program:Runner.host_program;state:Runner.state_snapshot;journal:write list;children:child list;
 range:Range_processing_bridge.prepared option;publication:Range_publication_bridge.prepared option;
 logical_writes:(int*int)list;compatibility_writes:(int*int)list}
let require b m=if not b then invalid_arg("8048 bridge: "^m)
let word b a=Char.code(Bytes.get b a)lor(Char.code(Bytes.get b(a+1))lsl 8)
let create ~pli_com ~pli1={image=Bytes.copy pli1;range=Range_processing_bridge.create ~pli_com ~pli1;
 publication=Range_publication_bridge.create ~pli1;control=Mapped_control_bridge.create ~pli1;emitter=Int_emitter_bridge.create ~pli_com ~pli1}
let origin=Range_processing_bridge.origin
let verify_call t (p:Native_dispatch.previous) ~(entry:Runner.state_snapshot)=
 let site=p.before.pc and off=p.before.pc-0x2200 in
 require(p.origin=origin "PLI1.OVL" off&&off>=0&&off+3<=Bytes.length t.image
  &&Char.code(Bytes.get t.image off)=0xcd&&word t.image(off+1)=0xa248)"canonical CALL ancestry";
 require(p.after=entry&&entry.pc=0xa248&&I8080.Step.pc_before p.step=site
  &&I8080.Step.pc_after p.step=entry.pc&&I8080.Step.fetched_bytes p.step=Bytes.sub t.image off 3
  &&I8080.Step.control_flow p.step=I8080.Step.Call{target=entry.pc;taken=true}
  &&p.before.sp=U.wrap(entry.sp+2))"CALL/SP ancestry";
 let resume=U.wrap(site+3)in
 let writes=List.filter_map(function I8080.Step.Write q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses p.step)in
 require(List.sort compare writes=List.sort compare[entry.sp,resume land 255;U.wrap(entry.sp+1),resume lsr 8])"original CALL word";
 {coordinate=Printf.sprintf"PLI1.OVL+%04X"off;site;resume}
let internal_call t site=
 let off=site-0x2200 in
 require(off>=0&&off+3<=Bytes.length t.image&&Char.code(Bytes.get t.image off)=0xcd&&word t.image(off+1)=0xa248)"internal CALL identity";
 {coordinate=Printf.sprintf"PLI1.OVL+%04X"off;site;resume=site+3}
let logical (s:Runner.state_snapshot)={R.a=s.a;bc=s.b lsl 8 lor s.c;de=s.d lsl 8 lor s.e;hl=s.h lsl 8 lor s.l;
 flags={sign=s.sign;zero=s.zero;auxiliary_carry=s.auxiliary_carry;parity=s.parity;carry=s.carry}}
let machine template (q:R.returned) sp pc={template with Runner.a=q.a;b=q.bc lsr 8;c=q.bc land 255;
 d=q.de lsr 8;e=q.de land 255;h=q.hl lsr 8;l=q.hl land 255;sp;pc;
 sign=q.flags.sign;zero=q.flags.zero;auxiliary_carry=q.flags.auxiliary_carry;parity=q.flags.parity;carry=q.flags.carry}
let prepare t ~call:(call:call) ~origin:o (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in require(o=origin "PLI1.OVL" 0x8048&&entry.pc=0xa248)"wrong canonical entry";
 let memory=boundary.copy_memory()in let m=S.of_bytes memory in
 List.iter Pli80_host.U8.check[entry.a;entry.b;entry.c;entry.d;entry.e;entry.h;entry.l];U.check entry.sp;
 List.iter(fun(a,b)->require(Bytes.sub memory(a+0x2200)(b-a)=Bytes.sub t.image a(b-a))"changed historical code")
  [0x8048,0x80b1;0x7a93,0x7ad5;0x7b13,0x7b64];
 require(call.site>=0x2200&&call.site+3<=Bytes.length t.image+0x2200
  &&Bytes.sub memory call.site 3=Bytes.sub t.image(call.site-0x2200)3
  &&Char.code(Bytes.get t.image(call.site-0x2200))=0xcd&&word t.image(call.site-0x2200+1)=0xa248
  &&call.resume=U.wrap(call.site+3)&&S.word m entry.sp=call.resume)"caller/continuation mismatch";
 require(entry.sp>=0xae70&&entry.sp<=0xfffc)"stack/table/scratch alias";
 let effects=ref[]and journal=ref[]and children=ref[]and range=ref None and publication=ref None in
 let append e=effects:=e::!effects in
 let put kind depth writer address value=S.write m address value;append(Runner.Memory_write(address,value));journal:={address;value;writer;depth;kind}::!journal in
 let staged state={Runner.effects=List.rev !effects;next_state=state;validate=(fun _->Ok());on_commit=ignore}in
 let sync bytes=for a=0 to 65535 do let v=Char.code(Bytes.get bytes a)in if S.read m a<>v then S.write m a v done in
 let preview next=match boundary.preview_host_program(staged next)with Ok r->sync r.memory;r|Error e->invalid_arg e in
 let static_call site target=
  require(Char.code(Bytes.get t.image site)=0xcd&&word t.image(site+1)=target)"unproven internal CALL";
  put "compatibility"0(site+0x2200)(entry.sp-1)((site+0x2203)lsr 8);
  put "compatibility"0(site+0x2200)(entry.sp-2)((site+0x2203)land 255)in
 let apply_journal depth ws=List.iter(fun(w:write)->put w.kind(w.depth+depth)w.writer w.address w.value)ws in
 let child ~site ~operation q=
  let target=match operation with H.Range_publish->0xa05f|Range_process->0x9f53|Emit->0xff6
   |Control_read->0x9c93|Control_publish->0x9d13|Primary_read->0x9ca9|Primary_publish->0x9d2e
   |Secondary_read->0x9cbf|Secondary_publish->0x9d49 in
  static_call site target;let sp=entry.sp-2 in let input=machine entry q sp target in
  let protected=[entry.sp;entry.sp+1;sp;sp+1;0xae32;0xae33;0xae34;0xae35;0xae36;0xae6a;0xae6b]in
  let observe writer(w:Pli80_host.Mapped_lookup.write)=put "logical"1 writer w.address w.value in
  let output=match operation with
  |Range_publish->let p=Range_publication_bridge.prepare t.publication
    ~call:(Range_publication_bridge.internal_call t.publication(site+0x2200))
    ~origin:(origin "PLI1.OVL" 0x7e5f)~state:input ~memory:(S.copy m)in
   publication:=Some p;
   apply_journal 1(List.map(fun(w:Range_publication_bridge.journal)->{address=w.address;value=w.value;writer=w.writer;depth=w.depth;kind=if w.kind="ABI"then"compatibility"else w.kind})p.journal);
   require(S.copy m=p.memory)"publication journal completeness";p.state
  |Range_process->
   (* Prefix previews replay against the original private transaction. No live
      RAM/services/callbacks are exposed by a nested preview. *)
   let prefix=List.rev !effects in
   let b={boundary with Runner.state=input;read_memory=S.read m;copy_memory=(fun()->S.copy m);
    preview_host_program=(fun p->boundary.preview_host_program{p with effects=prefix@p.effects})}in
   let p=Range_processing_bridge.prepare t.range
    ~call:(Range_processing_bridge.internal_call t.range(site+0x2200))~origin:(origin "PLI1.OVL" 0x7d53)b in
   require(not(List.exists(fun(c:Range_processing_bridge.child)->
    List.mem c.operation[Pli80_host.Range_processing.Primary;Secondary]
    &&List.mem(c.output.h lsl 8 lor c.output.l)[0xae6a;0xae6b])p.children))"child table/saved-input read alias";
   range:=Some p;
   (* The child's journal omits real BDOS host writes. Preserve its original
      ordered program and attach the proven machine writers separately. *)
   List.iter append p.program.effects;
   journal:=List.rev_append(List.map(fun(w:write)->{w with depth=w.depth+1})p.journal)!journal;
   ignore(preview p.state);p.state
  |Control_read|Control_publish->let p=Mapped_control_bridge.prepare t.control
    ~call:(Mapped_control_bridge.internal_call t.control(site+0x2200))
    ~origin:(origin "PLI1.OVL"(if operation=Control_read then 0x7a93 else 0x7b13))~state:input ~memory:(S.copy m)in
   List.iter(fun(w:Pli80_host.Mapped_lookup.write)->observe
     (match w.phase with "control_read_position"->0x9c96|"control_value"->0x9d16|"control_write_position"->0x9d18|"control_publication"->0x9d2c|_->assert false)w)p.writes;
   require(S.copy m=p.memory)"control journal completeness";p.state
  |Primary_read|Secondary_read->let r=(if operation=Primary_read then Pli80_host.Auxiliary.read else Pli80_host.Auxiliary.read_secondary)
    m ~position:input.c ~protected ~write:(observe(if operation=Primary_read then 0x9cac else 0x9cc2))in
   {input with a=r.value;b=0;c=r.index;h=r.address lsr 8;l=r.address land 255;carry=false;sp=entry.sp;pc=site+0x2203}
  |Primary_publish|Secondary_publish->let r=(if operation=Primary_publish then Pli80_host.Auxiliary.publish else Pli80_host.Auxiliary.publish_secondary)
    m ~position:input.c ~value:input.e ~protected ~write:(fun w->observe
     (match w.Pli80_host.Mapped_lookup.phase with "auxiliary_value"->0x9d31|"auxiliary_position"->0x9d33|"auxiliary_publication"->0x9d47
      |"secondary_auxiliary_value"->0x9d4c|"secondary_auxiliary_write_position"->0x9d4e|"secondary_auxiliary_publication"->0x9d62|_->assert false)w)in
   {input with a=r.value;b=0;c=r.index;h=r.address lsr 8;l=r.address land 255;carry=false;sp=entry.sp;pc=site+0x2203}
  |Emit->let c:Int_emitter_bridge.call={coordinate=Printf.sprintf"PLI1.OVL+%04X"site;site=site+0x2200;resume=site+0x2203;image="PLI1.OVL";offset=site}in
   let p=Int_emitter_bridge.prepare t.emitter ~call:c ~origin:(origin "PLI.COM" 0xef6)~state:input ~memory:(S.copy m)in
   let reset=ref false in
   List.iter(function Runner.Dispatch_bdos _ as e->append e|Runner.Memory_write(a,v)->
    let offset=sp-a in let stack=offset>=1&&offset<=10 in
    let writer=if stack then(match(offset+1)/2 with 1->if !reset then 0x1021 else 0x1016|2->if !reset then 0x434 else 0x3fa|3->0x1abb|4->0x1abc|5->0x1ac3|_->assert false)
     else if a=0x20b0 then 0xff9 else if a=0x1e0c then(if v=0 then 0x101c else 0x100b)
     else if a>=0x1d8c&&a<0x1e8c then 0x1006 else match a with 0x2060->0x3f1|0x205f->0x3f3|0x2066->0x42b|0x2065->0x42d|_->invalid_arg"unproved emitter writer"in
    if a=0x1e0c&&v=0 then reset:=true;
    put(if stack then "compatibility"else "logical")1 writer a v)p.program.effects;
   ignore(preview p.state);p.state in
  require(output.sp=entry.sp&&output.pc=site+0x2203)"child return/SP";
  children:={site;operation;input;output}::!children;logical output in
 let result=H.run m ~entry:(logical entry)~write:(fun ~site ~address ~value->put "logical"0(site+0x2200)address value)~call:child in
 let state=machine entry result.returned(entry.sp+2)call.resume in
 let expected=preview state in
 let validate(r:Runner.host_program_result)=if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)
  then Error"8048 ordered program mismatch"else Ok()in
 let journal=List.rev !journal in
 require(not(List.exists(fun w->(w.address=0xae6a&&w.writer<>0xa24b)||w.address=0xae6b)journal))"child table/saved-input alias";
 let logical_writes=List.filter_map(fun w->if w.kind="logical"then Some(w.address,w.value)else None)journal in
 let compatibility_writes=List.filter_map(fun w->if w.kind="compatibility"then Some(w.address,w.value)else None)journal in
 {result;program={(staged state)with validate};state;journal;children=List.rev !children;range= !range;publication= !publication;logical_writes;compatibility_writes}
