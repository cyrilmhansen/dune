[@@@warning "-4-40-41-42"]
module F=Pli80_host.Acquisition_family
module C=Pli80_host.Acquisition_parent
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
module U=Pli80_host.U16
module A=Acquisition_parent_bridge
module B=State_adaptation_bridge
type operation=Context|Field|Attribute|Spine|Resident|Pair_gate|Selected_transform|Table_adapter|Wrapper|Repeat
type call={coordinate:string;site:int;resume:int;operation:operation}
type write=Range_processing_bridge.write={address:int;value:int;writer:int;depth:int;kind:string}
type t={com:bytes;image:bytes;adapt:B.t;publication:Range_publication_bridge.t;
 balance:Balance_scan_bridge.t;word:Publication_primitives_bridge.t;mapped:Mapped_publication_bridge.t;control:Mapped_control_bridge.t}
type prepared={result:F.result;program:Runner.host_program;state:Runner.state_snapshot;journal:write list;logical_writes:(int*int)list}
let origin=A.origin
let require b m=if not b then invalid_arg("acquisition family bridge: "^m)
let word b a=Char.code(Bytes.get b a)lor(Char.code(Bytes.get b(a+1))lsl 8)
let bounds=function Context->0x60e5,0x61a4|Field->0x5e98,0x60e5|Attribute->0x256c,0x25a9|Spine->0x4f54,0x4f6e|Resident->0x1376,0x15da|Pair_gate->0x2259,0x22c0|Selected_transform->0x345e,0x34ac|Table_adapter->0x25a9,0x25c0|Wrapper->0x6619,0x6639|Repeat->0x654e,0x65f9
let create ~pli_com ~pli1={com=Bytes.copy pli_com;image=Bytes.copy pli1;adapt=B.create ~pli_com ~pli1;
 publication=Range_publication_bridge.create ~pli1;balance=Balance_scan_bridge.create ~pli1;
 word=Publication_primitives_bridge.create ~pli1;mapped=Mapped_publication_bridge.create ~pli1;control=Mapped_control_bridge.create ~pli1}
let internal_call t operation site=
 let off=site-0x2200 in let target=fst(bounds operation)+(if operation=Resident then 0x100 else 0x2200) in
 require(off>=0&&off+3<=Bytes.length t.image&&Char.code(Bytes.get t.image off)=0xcd&&word t.image(off+1)=target)"CALL identity";
 {coordinate=Printf.sprintf"PLI1.OVL+%04X"off;site;resume=site+3;operation}
let verify_call t operation (p:Native_dispatch.previous) ~(entry:Runner.state_snapshot)=
 let c=internal_call t operation p.before.pc in
 require(p.origin=origin"PLI1.OVL"(c.site-0x2200)&&p.after=entry&&entry.pc=fst(bounds operation)+(if operation=Resident then 0x100 else 0x2200)
  &&I8080.Step.pc_before p.step=c.site&&I8080.Step.pc_after p.step=entry.pc
  &&I8080.Step.fetched_bytes p.step=Bytes.sub t.image(c.site-0x2200)3
  &&I8080.Step.control_flow p.step=I8080.Step.Call{target=entry.pc;taken=true}
  &&p.before.sp=U.wrap(entry.sp+2))"canonical CALL/SP ancestry";
 let ws=List.filter_map(function I8080.Step.Write w->Some(w.address,w.value)|_->None)(I8080.Step.memory_accesses p.step)in
 require(ws=[entry.sp+1,c.resume lsr 8;entry.sp,c.resume land 255])"CALL word";c
exception Unfinished of Runner.state_snapshot * bytes * write list * Runner.host_program_result
let prepare ?(follow_spine=false) ?(recursive=(fun _ _->invalid_arg"unfinished recursive 6223 callback")) t operation ~call ~origin:o (boundary:Runner.instruction_boundary)=
 let entry=boundary.state and first,_=bounds operation in
 require(o=origin(if operation=Resident then"PLI.COM"else"PLI1.OVL")first&&entry.pc=first+(if operation=Resident then 0x100 else 0x2200))"wrong entry/image";
 List.iter Pli80_host.U8.check[entry.a;entry.b;entry.c;entry.d;entry.e;entry.h;entry.l];U.check entry.sp;
 require(entry.sp>=0xb000&&entry.sp<=0xfffc)"stack alias/bounds";
 let memory=boundary.copy_memory()in let m=S.of_bytes memory in
 let resident_code=[0x0817,0x082e;0x12ae,0x12e1;0x1376,0x166e;0x1a1c,0x1a4b]in
 let overlay_code=[0x4cc2,0x4ce9;0x4f54,0x4f6e;0x61a4,0x6223;0x625d,0x6288;0x6314,0x63cf;0x640d,0x6477;0x6477,0x64f2;0x64f2,0x6508;0x654e,0x65f9;0x65f9,0x6619;0x6619,0x6639;0x2308,0x230e;0x4c4c,0x4c52;0x4cd4,0x4ce1;0x4f2a,0x4f54;0x56e1,0x570e;0x2185,0x21ad;0x28aa,0x2dc3;0x6708,0x6ca1;0x8309,0x8314;0x834f,0x8357;0x8380,0x8386;0x8396,0x83ac;0x21d4,0x21e9;0x2221,0x22c0;0x345e,0x34ac;0x25a9,0x25c0;0x23a0,0x23d2;0x25d6,0x25ec;0x2c53,0x2c59;0x2fc2,0x31a8;0x31fb,0x3262;0x329f,0x32b3;0x3304,0x3333;0x01af,0x01c6;0x020e,0x0222;0x213c,0x2185;0x21ad,0x21d4;0x22cb,0x234e;0x2355,0x23a0;0x3558,0x3563;0x387f,0x38a9;0x3963,0x3987;0x3a76,0x3c16;0x3c8a,0x415e;0x415e,0x41ba;0x421f,0x43ac;0x452b,0x45f0;0x500f,0x5035;0x506e,0x50b4;0x53bb,0x53c6;0x81f1,0x8214;0x45f0,0x462d;0x5a46,0x5ab2;0x5e48,0x61a4;0x784e,0x7a15;0x7ff3,0x8003;0x83a0,0x83ac]in
 List.iter(fun(a,b)->require(Bytes.sub memory(a+0x100)(b-a)=Bytes.sub t.com a(b-a))(Printf.sprintf"resident code changed %04X"a))resident_code;
 List.iter(fun(a,b)->require(Bytes.sub memory(a+0x2200)(b-a)=Bytes.sub t.image a(b-a))(Printf.sprintf"overlay code changed %04X"a))overlay_code;
 require(call=internal_call t operation call.site&&S.word m entry.sp=call.resume)"continuation mismatch";
 let effects=ref[]and journal=ref[]and sp=ref entry.sp and depth=ref 0 and frames=ref[]in
 let append item=effects:=item::!effects in
 let frame_sites=[0x6564;0x6570;0x6572;0x6577;0x65d8;0x60f0;0x60f2;0x6108;0x610d;0x6116;0x5ea7;0x5eaa;0x5ebc;0x5ed2;0x5ed4;0x5edc;0x6072;0x5f16;0x507f;0x5081;0x3ca9;0x3caf;0x3cb1]in
 let put kind writer address value=
  U.check address;Pli80_host.U8.check value;
  if kind="logical"&&address>=entry.sp-512&&address<=entry.sp+1 then(
   require(List.mem(writer-0x2200)frame_sites&&address>= !sp&&address<entry.sp)"frame/stack alias");
  S.write m address value;append(Runner.Memory_write(address,value));journal:={address;value;writer;depth= !depth;kind}::!journal in
 let push site value=put"compatibility"site(!sp-1)(value lsr 8);put"compatibility"site(!sp-2)(value land 255);sp:= !sp-2 in
 let code site size=
  if site>=0x2200&&site-0x2200+size<=Bytes.length t.image then Bytes.sub t.image(site-0x2200)size
  else if site>=0x100&&site-0x100+size<=Bytes.length t.com then Bytes.sub t.com(site-0x100)size else invalid_arg"compatibility coordinate"in
 let compatibility=function
 |C.Enter(site,target)->let b=code site 3 in require(Char.code(Bytes.get b 0)=0xcd&&word b 1=target)"child CALL bytes";
   frames:=(!sp,target,site+3)::!frames;push site(site+3);incr depth
 |Leave->let before,_,_=List.hd !frames in require(!sp+2=before)"child stack result";sp:= !sp+2;decr depth;frames:=List.tl !frames
 |Push(site,v)->require(List.mem(Char.code(Bytes.get(code site 1)0))[0xc5;0xd5;0xe5;0xf5])"PUSH identity";push site v
 |Pop->sp:= !sp+2
 |Constructor_arguments _->invalid_arg"acquisition family: unexpected constructor"in
 let software ~site ~consumed=
  require(site=0x891f&&consumed=8&&Char.code(Bytes.get(code site 1)0)=0xd5)"software continuation writer";
  match !frames with
  |(before,target,resume)::rest->require(target=0x8908&& !sp=before+6&&S.word m !sp=resume)"N8 copied continuation/SP";frames:=(before+consumed,target,resume)::rest
  |[]->invalid_arg"missing software frame"in
 let adjust ~site ~delta=require(Char.code(Bytes.get(code site 1)0)=(if delta=1 then 0x33 else 0x3b)&&List.mem delta[1;-1])"private SP instruction";sp:= !sp+delta in
 let staged state={Runner.effects=List.rev !effects;next_state=state;validate=(fun _->Ok());on_commit=ignore}in
 let sync b=for a=0 to 65535 do S.write m a(Char.code(Bytes.get b a))done in
 let preview state=match boundary.preview_host_program(staged state)with Ok result->sync result.memory;result|Error e->invalid_arg e in
 let guard_field base width=
  U.check base;require(width>=0&&base+width<=65536)"pointer bounds";
  let protected=[entry.sp-512,entry.sp+2;0xa628,0xa65b;0xa6ca,0xa861;0xa863,0xa865;0xa8ab,0xa93a;0xa947,0xa9e5;0xaa16,0xaa1a;0xae32,0xae6d;0x1c36,0x1c5b;0x1f06,0x1f09;0x20c1,0x214a]
   @List.map(fun(a,b)->a+0x100,b+0x100)resident_code@List.map(fun(a,b)->a+0x2200,b+0x2200)overlay_code in
  require(not(List.exists(fun(a,b)->base<b&&base+width>a)protected))"pointer/scratch/code/stack alias"in
 let native ~site ~target (q:R.returned)=
  let state=A.machine entry q !sp target in
  let prior=List.rev !effects in let before=preview state in
  let boundary={Runner.state;read_memory=S.read m;copy_memory=(fun()->S.copy m);dma=before.dma;
   copy_filesystem=(fun()->Cpm.Filesystem.copy before.filesystem);
   preview_host_program=(fun p->boundary.preview_host_program{p with effects=prior@p.effects})}in
  let import program ws result=
   List.iter append program.Runner.effects;
   journal:=List.rev_append(List.map(fun(w:write)->{w with depth=w.depth+ !depth})ws)!journal;
   ignore(preview result);require(result.sp= !sp+2&&result.pc=site+3)"native child continuation";A.logical result in
  let put_writes writes writer=List.iter(fun(w:Pli80_host.Mapped_lookup.write)->put"logical"(writer w.phase)w.address w.value)writes in
  match target with
  |0x8423->let program,child_state,child_journal=recursive site boundary in import program child_journal child_state
  |0x4711->let p=B.prepare t.adapt B.Saved ~call:(B.internal_call t.adapt B.Saved site)~origin:(origin"PLI1.OVL"0x2511)boundary in import p.program p.journal p.state
  |0x9d64->let r=Pli80_host.Mapped_lookup.high_attribute m ~byte_index:state.c ~protected:(List.init 2(fun i-> !sp+i))
    ~write:(fun w->put"logical"0x9d67 w.Pli80_host.Mapped_lookup.address w.value)in
   let a=r.high3 in let f=R.comparison a 0 in
   {q with R.a=a;bc=0x1b4b;hl=r.address;flags={f with R.auxiliary_carry=(List.hd(List.rev r.shifts))land 8<>0;carry=false}}
  |0x460a->let p=B.prepare t.adapt B.Adapt ~call:(B.internal_call t.adapt B.Adapt site)~origin:(origin"PLI1.OVL"0x240a)boundary in import p.program p.journal p.state
  |0xa05f->let p=Range_publication_bridge.prepare t.publication ~call:(Range_publication_bridge.internal_call t.publication site)~origin:(origin"PLI1.OVL"0x7e5f)~state ~memory:(S.copy m)in
   List.iter(fun(w:Range_publication_bridge.journal)->put(if w.kind="ABI"then"compatibility"else"logical")w.writer w.address w.value)p.journal;
   require(S.copy m=p.memory)"publication journal";A.logical p.state
  |0x9d7a->let p=Balance_scan_bridge.prepare t.balance ~call:(Balance_scan_bridge.internal_call t.balance site)~origin:(origin"PLI1.OVL"0x7b7a)~state ~memory:(S.copy m)in
   List.iter(fun(w:Pli80_host.Mapped_lookup.write)->
    (match w.phase with
    |"attribute_position"->compatibility(C.Enter(0x9d87,0x9c63))
    |"mapped_position"->compatibility(C.Enter(0x9c6b,0x9c4d))
    |"balance_publication"->compatibility C.Leave;compatibility C.Leave|_->());
    put"logical"(List.assoc w.phase["cursor_initialization",0x9d7d;"balance_initialization",0x9d82;"attribute_position",0x9c66;"mapped_position",0x9c50;"balance_publication",0x9d8f;"cursor_decrement",0x9d9a])w.address w.value)p.result.writes;
   require(S.copy m=p.memory)"balance chronology";A.logical p.state
  |0x9c93|0x9ca9|0x9cbf->
   let protected=List.init 2(fun i-> !sp+i)in
   let write phase writer (w:Pli80_host.Mapped_lookup.write)=require(w.phase=phase)"read phase";put"logical"writer w.address w.value in
   let value,index,address=if target=0x9c93 then(
    let r=Pli80_host.Mapped_control.read m ~position:state.c ~protected ~write:(write"control_read_position"0x9c96)in r.value,r.index,r.address)
   else if target=0x9ca9 then(
    let r=Pli80_host.Auxiliary.read m ~position:state.c ~protected ~write:(write"auxiliary_read_position"0x9cac)in r.value,r.index,r.address)
   else(let r=Pli80_host.Auxiliary.read_secondary m ~position:state.c ~protected ~write:(write"secondary_auxiliary_position"0x9cc2)in r.value,r.index,r.address)in
   {q with R.a=value;bc=index;hl=address;flags={q.flags with carry=false}}
  |0x9c79->let r=Pli80_host.Mapped_word.lookup m ~position:state.c ~protected:(List.init 2(fun i-> !sp+i))
    ~write:(fun w->put"logical"0x9c7c w.Pli80_host.Mapped_word.address w.value)in
   {q with R.bc=r.index;de=r.high_address;hl=r.word;flags={q.flags with carry=false}}
  |0x9a4e|0x7154|0x5504|0x4aaa|0x4508->raise(Unfinished(state,S.copy m,List.rev !journal,before))
  |0x9da2->let p=Mapped_publication_bridge.prepare t.mapped ~call:(Mapped_publication_bridge.internal_call t.mapped site)~origin:(origin"PLI1.OVL"0x7ba2)~state ~memory:(S.copy m)in
   List.iter(fun(w:Pli80_host.Mapped_lookup.write)->
    if w.phase="mapped_write_value"then compatibility(C.Enter(0x9dae,0x9cd5));
    if w.phase="recycle_cached_index"then compatibility C.Leave;
    put"logical"(List.assoc w.phase["recycle_position",0x9da5;"mapped_write_value",0x9cd8;"mapped_write_position",0x9cda;"mapped_publication",0x9cee;"recycle_cached_index",0x9dbb])w.address w.value)p.writes;
   require(S.copy m=p.memory)"recycle chronology";A.logical p.state
  |0x9cd5->let p=Mapped_publication_bridge.prepare t.mapped ~call:(Mapped_publication_bridge.internal_call t.mapped site)~origin:(origin"PLI1.OVL"0x7ad5)~state ~memory:(S.copy m)in
   put_writes p.writes(fun phase->List.assoc phase["mapped_write_value",0x9cd8;"mapped_write_position",0x9cda;"mapped_publication",0x9cee]);require(S.copy m=p.memory)"mapped publication chronology";A.logical p.state
  |0x9cf0|0x9d49->let off=target-0x2200 in let p=Publication_primitives_bridge.prepare t.word ~call:(Publication_primitives_bridge.internal_call t.word site)~origin:(origin"PLI1.OVL"off)~state ~memory:(S.copy m)in
   List.iter(fun(w:Pli80_host.Mapped_lookup.write)->
    if w.phase="mapped_word_publication_low"then(
     let low_address=match p.result with Publication_primitives_bridge.Word r->r.low_address|_->assert false in
     compatibility(C.Push(0x9d09,low_address));compatibility C.Pop);
    put"logical"(List.assoc w.phase["mapped_word_value_high",0x9cf3;"mapped_word_value_low",0x9cf5;"mapped_word_write_position",0x9cf7;"mapped_word_publication_low",0x9d0f;"mapped_word_publication_high",0x9d11;"secondary_auxiliary_value",0x9d4c;"secondary_auxiliary_write_position",0x9d4e;"secondary_auxiliary_publication",0x9d62])w.address w.value)p.writes;
   require(S.copy m=p.memory)"word/secondary publication chronology";A.logical p.state
  |0x9d13->let p=Mapped_control_bridge.prepare t.control ~call:(Mapped_control_bridge.internal_call t.control site)~origin:(origin"PLI1.OVL"0x7b13)~state ~memory:(S.copy m)in
   put_writes p.writes(fun phase->List.assoc phase["control_value",0x9d16;"control_write_position",0x9d18;"control_publication",0x9d2c]);require(S.copy m=p.memory)"control publication chronology";A.logical p.state
  |0x9d2e->let r=Pli80_host.Auxiliary.publish m ~position:state.c ~value:state.e ~protected:(List.init 8(fun i-> !sp-6+i))
    ~write:(fun w->put"logical"(List.assoc w.Pli80_host.Mapped_lookup.phase["auxiliary_value",0x9d31;"auxiliary_position",0x9d33;"auxiliary_publication",0x9d47])w.address w.value)in
   {q with R.a=r.value;bc=r.index;hl=r.address;flags={q.flags with carry=false}}
  |_->invalid_arg(Printf.sprintf"acquisition family: unfinished native child %04X"target)in
 let result=F.run(match operation with Context->F.Context|Field->F.Field|Attribute->F.Attribute|Spine->F.Spine|Resident->F.Resident|Pair_gate->F.Pair_gate|Selected_transform->F.Selected_transform|Table_adapter->F.Table_adapter|Wrapper->F.Wrapper|Repeat->F.Repeat)m ~entry:(A.logical entry)
  ~write:(fun ~site ~address ~value->put"logical"site address value)~compatibility ~adjust ~sp:(fun()-> !sp)~guard_field ~native ~follow_spine ~software in
 require(!sp=entry.sp&& !frames=[])"root/private frame balance";
 let state=A.machine entry result.returned(entry.sp+2)call.resume in
 let expected=preview state in let validate(r:Runner.host_program_result)=
  if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)
  then Error"family ordered program mismatch"else Ok()in
 let journal=List.rev !journal in
 {result;program={effects=List.rev !effects;next_state=state;validate;on_commit=ignore};state;journal;
 logical_writes=List.filter_map(fun w->if w.kind="logical"then Some(w.address,w.value)else None)journal}
