[@@@warning "-4-40-41-42"]
module H=Pli80_host.State_adaptation
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
module U=Pli80_host.U16
type operation=Minimum|Publish|Adapt|Saved
type t={image:bytes;gate:Attribute_gate_bridge.t;input:Input_processing_bridge.t;word:Publication_primitives_bridge.t;control:Mapped_control_bridge.t}
type call={coordinate:string;site:int;resume:int}
type write=Range_processing_bridge.write={address:int;value:int;writer:int;depth:int;kind:string}
type child={site:int;operation:H.operation;input:Runner.state_snapshot;output:Runner.state_snapshot}
type prepared={result:H.result;program:Runner.host_program;state:Runner.state_snapshot;journal:write list;children:child list;
 input:Input_processing_bridge.prepared option;gate:Attribute_gate_bridge.prepared option;nested:prepared list;
 logical_writes:(int*int)list;compatibility_writes:(int*int)list}
let require b m=if not b then invalid_arg("state adaptation bridge: "^m)
let word b a=Char.code(Bytes.get b a)lor(Char.code(Bytes.get b(a+1))lsl 8)
let bounds=function Minimum->0x23a0,0x23b8|Publish->0x23d2,0x240a|Adapt->0x240a,0x24f1|Saved->0x2511,0x252b
let create ~pli_com ~pli1=
 require(Experiment.sha256_hex pli1="1ed6d00f423ffb55ab4ea9a49c33a72617b7ccc5ead5ecdcb5bbf1733214e564")"historical image identity";
 {image=Bytes.copy pli1;gate=Attribute_gate_bridge.create ~pli_com ~pli1;input=Input_processing_bridge.create ~pli_com ~pli1;
 word=Publication_primitives_bridge.create ~pli1;control=Mapped_control_bridge.create ~pli1}
let origin=Range_processing_bridge.origin
let internal_call t op site=
 let off=site-0x2200 and first,_=bounds op in
 require(off>=0&&off+3<=Bytes.length t.image&&Char.code(Bytes.get t.image off)=0xcd&&word t.image(off+1)=first+0x2200)"internal CALL identity";
 {coordinate=Printf.sprintf"PLI1.OVL+%04X"off;site;resume=site+3}
let verify_call t op (p:Native_dispatch.previous) ~(entry:Runner.state_snapshot)=
 let call=internal_call t op p.before.pc in
 require(p.origin=origin "PLI1.OVL"(call.site-0x2200)&&p.after=entry
  &&entry.pc=fst(bounds op)+0x2200&&I8080.Step.pc_before p.step=call.site
  &&I8080.Step.pc_after p.step=entry.pc&&I8080.Step.fetched_bytes p.step=Bytes.sub t.image(call.site-0x2200)3
  &&I8080.Step.control_flow p.step=I8080.Step.Call{target=entry.pc;taken=true}
  &&p.before.sp=U.wrap(entry.sp+2))"canonical CALL/SP ancestry";
 let writes=List.filter_map(function I8080.Step.Write q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses p.step)in
 require(List.sort compare writes=List.sort compare[entry.sp,call.resume land 255;U.wrap(entry.sp+1),call.resume lsr 8])"original CALL word";call
let logical (s:Runner.state_snapshot)={R.a=s.a;bc=s.b lsl 8 lor s.c;de=s.d lsl 8 lor s.e;hl=s.h lsl 8 lor s.l;
 flags={sign=s.sign;zero=s.zero;auxiliary_carry=s.auxiliary_carry;parity=s.parity;carry=s.carry}}
let machine template (q:R.returned) sp pc={template with Runner.a=q.a;b=q.bc lsr 8;c=q.bc land 255;d=q.de lsr 8;e=q.de land 255;h=q.hl lsr 8;l=q.hl land 255;sp;pc;
 sign=q.flags.sign;zero=q.flags.zero;auxiliary_carry=q.flags.auxiliary_carry;parity=q.flags.parity;carry=q.flags.carry}
let rec prepare t op ~call:(call:call) ~origin:o (boundary:Runner.instruction_boundary)=
 let entry=boundary.state and first,last=bounds op in
 require(o=origin"PLI1.OVL"first&&entry.pc=first+0x2200)"wrong canonical entry";
 let memory=boundary.copy_memory()in let m=S.of_bytes memory in
 List.iter Pli80_host.U8.check[entry.a;entry.b;entry.c;entry.d;entry.e;entry.h;entry.l];U.check entry.sp;
 require(entry.sp>=0xaec0&&entry.sp<=0xfffc)"stack/table/scratch alias";
 let code=[first,last;0x23a0,0x23b8;0x23d2,0x240a;0x7af0,0x7b13;0x7b13,0x7b64]in
 List.iter(fun(a,b)->require(Bytes.sub memory(a+0x2200)(b-a)=Bytes.sub t.image a(b-a))"changed historical code")code;
 require(call=internal_call t op call.site&&Bytes.sub memory call.site 3=Bytes.sub t.image(call.site-0x2200)3&&S.word m entry.sp=call.resume)"caller/continuation mismatch";
 let effects=ref[]and journal=ref[]and children=ref[]and input=ref None and gate=ref None and nested=ref[]in
 let append e=effects:=e::!effects in
 let put kind depth writer address value=S.write m address value;append(Runner.Memory_write(address,value));journal:={address;value;writer;depth;kind}::!journal in
 let staged state={Runner.effects=List.rev !effects;next_state=state;validate=(fun _->Ok());on_commit=ignore}in
 let sync bytes=for a=0 to 65535 do let v=Char.code(Bytes.get bytes a)in if S.read m a<>v then S.write m a v done in
 let preview next=match boundary.preview_host_program(staged next)with Ok r->sync r.memory;r|Error e->invalid_arg e in
 let root_sp=entry.sp-(if op=Saved then 1 else 0)in
 let stack=List.init(entry.sp-root_sp+8)(fun i->root_sp-6+i)in
 let own_cells=match op with Minimum->[0xa64e;0xa64f]|Publish->[0xa652;0xa653]|Adapt->[0xa653;0xa654;0xa652;0xa64e;0xa64f]|Saved->[root_sp]in
 let index=entry.c in
 let sources=if op=Publish||op=Adapt then [0xa628+index;0xa62b+index;0xa62e+index;0xae32;0xae33]@(if op=Adapt then[0xa63b+2*index;0xa63c+2*index;0xa642;0xa643]else[])else[]in
 require(not(List.exists(fun a->List.mem a own_cells)sources))"source/cache alias";
 let protected=stack@own_cells@sources@List.concat_map(fun(a,b)->List.init(b-a)(fun n->a+0x2200+n))code in
 let child ~site ~operation q=
  let target=match operation with H.Minimum->0x45a0|Publish->0x45d2|Adapt->0x460a|Input_process->0xa248|Gate->0xa0c0
   |Word_publish->0x9cf0|Control_publish->0x9d13|Primary_publish->0x9d2e|Secondary_publish->0x9d49|Saved->assert false in
  require(Char.code(Bytes.get t.image site)=0xcd&&word t.image(site+1)=target)"internal CALL identity";
  put"compatibility"0(site+0x2200)(root_sp-1)((site+0x2203)lsr 8);
  put"compatibility"0(site+0x2200)(root_sp-2)((site+0x2203)land 255);
  let child_input=machine entry q(root_sp-2)target in
  let prefix=List.rev !effects in let before=preview child_input in
  let b={Runner.state=child_input;read_memory=S.read m;copy_memory=(fun()->S.copy m);
   dma=before.dma;copy_filesystem=(fun()->Cpm.Filesystem.copy before.filesystem);
   preview_host_program=(fun p->boundary.preview_host_program{p with effects=prefix@p.effects})}in
  let import program ws state=
   List.iter append program.Runner.effects;
   journal:=List.rev_append(List.map(fun(w:write)->{w with depth=w.depth+1})ws)!journal;
   ignore(preview state);state in
  let output=match operation with
  |H.Minimum|Publish|Adapt->
   let op=match operation with H.Minimum->Minimum|Publish->Publish|_->Adapt in
   let p=prepare t op ~call:(internal_call t op(site+0x2200))~origin:(origin"PLI1.OVL"(fst(bounds op)))b in
   nested:=p::!nested;import p.program p.journal p.state
  |Input_process->let p=Input_processing_bridge.prepare t.input
    ~call:(Input_processing_bridge.internal_call t.input(site+0x2200))~origin:(origin"PLI1.OVL"0x8048)b in
   input:=Some p;import p.program p.journal p.state
  |Gate->let p=Attribute_gate_bridge.prepare t.gate Attribute_gate_bridge.Gate
    ~call:(Attribute_gate_bridge.internal_call t.gate Attribute_gate_bridge.Gate(site+0x2200))~origin:(origin"PLI1.OVL"0x7ec0)b in
   gate:=Some p;import p.program p.journal p.state
  |Word_publish->
   let call=Publication_primitives_bridge.internal_call t.word(site+0x2200)in
   let p=Publication_primitives_bridge.prepare t.word ~call ~origin:(origin"PLI1.OVL"0x7af0)~state:child_input ~memory:(S.copy m)in
   let r=match p.result with Publication_primitives_bridge.Word r->r|_->assert false in
   require(not(List.exists(fun a->List.mem a protected)[r.low_address;r.high_address;0xaa1f+r.position]))"word/source alias";
   (* The destination PUSH occurs between scratch and low/high publication. *)
   List.iter(fun(w:Pli80_host.Mapped_lookup.write)->
    if w.phase="mapped_word_publication_low"then List.iter(fun(a,v)->put"compatibility"1 0x9d09 a v)p.compatibility_writes;
    let writer=List.assoc w.phase["mapped_word_value_high",0x9cf3;"mapped_word_value_low",0x9cf5;"mapped_word_write_position",0x9cf7;"mapped_word_publication_low",0x9d0f;"mapped_word_publication_high",0x9d11]in
    put"logical"1 writer w.address w.value)p.writes;
   require(S.copy m=p.memory)"word journal completeness";p.state
  |Control_publish->
   let p=Mapped_control_bridge.prepare t.control ~call:(Mapped_control_bridge.internal_call t.control(site+0x2200))
    ~origin:(origin"PLI1.OVL"0x7b13)~state:child_input ~memory:(S.copy m)in
   require(not(List.mem(p.state.h lsl 8 lor p.state.l)protected))"control/source alias";
   List.iter(fun(w:Pli80_host.Mapped_lookup.write)->put"logical"1
    (List.assoc w.phase["control_value",0x9d16;"control_write_position",0x9d18;"control_publication",0x9d2c])w.address w.value)p.writes;
   require(S.copy m=p.memory)"control journal completeness";p.state
  |Primary_publish|Secondary_publish->
   let r=(if operation=Primary_publish then Pli80_host.Auxiliary.publish else Pli80_host.Auxiliary.publish_secondary)m
    ~position:child_input.c ~value:child_input.e ~protected ~write:(fun w->put"logical"1
     (List.assoc w.Pli80_host.Mapped_lookup.phase["auxiliary_value",0x9d31;"auxiliary_position",0x9d33;"auxiliary_publication",0x9d47;"secondary_auxiliary_value",0x9d4c;"secondary_auxiliary_write_position",0x9d4e;"secondary_auxiliary_publication",0x9d62])w.address w.value)in
   {child_input with a=r.value;b=0;c=r.index;h=r.address lsr 8;l=r.address land 255;carry=false;sp=root_sp;pc=site+0x2203}
  |Saved->assert false in
  require(output.sp=root_sp&&output.pc=site+0x2203)"child resume ancestry";
  children:={site;operation;input=child_input;output}::!children;logical output in
 let frame ~address ~value=
  require(Char.code(Bytes.get t.image 0x2512)=0xc5&&Char.code(Bytes.get t.image 0x2513)=0x33)"PUSH B/INX SP proof";
  put"logical"0 0x4712 address value;put"compatibility"0 0x4712(address-1)value in
 let result=H.run (match op with Minimum->H.Minimum|Publish->H.Publish|Adapt->H.Adapt|Saved->H.Saved)m
  ~entry:(logical entry)~sp:entry.sp ~protected:stack
  ~write:(fun ~site ~address ~value->put"logical"0(site+0x2200)address value)~frame ~call:child in
 let state=machine entry result.returned(entry.sp+2)call.resume in
 let journal=List.rev !journal in
 require(not(List.exists(fun w->w.address=entry.sp||w.address=entry.sp+1)journal))"outer return alias";
 if op=Saved then require(not(List.exists(fun w->w.address=root_sp&&w.writer<>0x4712)journal))"private frame overwritten";
 let expected=preview state in
 let validate(r:Runner.host_program_result)=if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)
  then Error"state adaptation ordered program mismatch"else Ok()in
 let select kind=List.filter_map(fun w->if w.kind=kind then Some(w.address,w.value)else None)journal in
 {result;program={(staged state)with validate};state;journal;children=List.rev !children;input= !input;gate= !gate;nested=List.rev !nested;
 logical_writes=select"logical";compatibility_writes=select"compatibility"}
