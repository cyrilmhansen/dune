[@@@warning "-4-40-41-42"]
module H=Pli80_host.Acquisition_parent
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
module U=Pli80_host.U16
module B=State_adaptation_bridge
type t={com:bytes;image:bytes;saved:B.t}
type call={coordinate:string;site:int;resume:int}
type write=Range_processing_bridge.write={address:int;value:int;writer:int;depth:int;kind:string}
type prepared={result:H.result;program:Runner.host_program;state:Runner.state_snapshot;journal:write list;
 saved:B.prepared;logical_writes:(int*int)list;compatibility_writes:(int*int)list}
let origin=B.origin
let require b m=if not b then invalid_arg("acquisition parent bridge: "^m)
let word b a=Char.code(Bytes.get b a)lor(Char.code(Bytes.get b(a+1))lsl 8)
let create ~pli_com ~pli1={com=Bytes.copy pli_com;image=Bytes.copy pli1;saved=B.create ~pli_com ~pli1}
let internal_call t site=
 let off=site-0x2200 in require(off>=0&&off+3<=Bytes.length t.image&&Char.code(Bytes.get t.image off)=0xcd&&word t.image(off+1)=0x7b29)"CALL identity";
 {coordinate=Printf.sprintf"PLI1.OVL+%04X"off;site;resume=site+3}
let verify_call t (p:Native_dispatch.previous) ~(entry:Runner.state_snapshot)=
 let c=internal_call t p.before.pc in
 require(p.origin=origin"PLI1.OVL"(c.site-0x2200)&&p.after=entry&&entry.pc=0x7b29
  &&I8080.Step.pc_before p.step=c.site&&I8080.Step.pc_after p.step=entry.pc
  &&I8080.Step.fetched_bytes p.step=Bytes.sub t.image(c.site-0x2200)3
  &&I8080.Step.control_flow p.step=I8080.Step.Call{target=entry.pc;taken=true}
  &&p.before.sp=U.wrap(entry.sp+2))"canonical CALL/SP ancestry";
 let ws=List.filter_map(function I8080.Step.Write w->Some(w.address,w.value)|_->None)(I8080.Step.memory_accesses p.step)in
 require(List.sort compare ws=List.sort compare[entry.sp,c.resume land 255;entry.sp+1,c.resume lsr 8])"CALL word";c
let logical (s:Runner.state_snapshot)={R.a=s.a;bc=s.b lsl 8 lor s.c;de=s.d lsl 8 lor s.e;hl=s.h lsl 8 lor s.l;
 flags={sign=s.sign;zero=s.zero;auxiliary_carry=s.auxiliary_carry;parity=s.parity;carry=s.carry}}
let machine template (q:R.returned) sp pc={template with Runner.a=q.a;b=q.bc lsr 8;c=q.bc land 255;d=q.de lsr 8;e=q.de land 255;h=q.hl lsr 8;l=q.hl land 255;sp;pc;
 sign=q.flags.sign;zero=q.flags.zero;auxiliary_carry=q.flags.auxiliary_carry;parity=q.flags.parity;carry=q.flags.carry}
let prepare t ~call ~origin:o (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in require(o=origin"PLI1.OVL"0x5929&&entry.pc=0x7b29)"wrong entry/image";
 List.iter Pli80_host.U8.check[entry.a;entry.b;entry.c;entry.d;entry.e;entry.h;entry.l];U.check entry.sp;
 require(entry.sp>=0xaec0&&entry.sp<=0xfffc)"stack alias/bounds";
 let memory=boundary.copy_memory()in let m=S.of_bytes memory in
 (* Both complete historical images are immutable input identities. Data beyond
    the resident/overlay image is shared state, never an oracle. *)
 let resident_code=[0xef6,0xf2d;0x2ee,0x2fe;0x328,0x338;0x19bb,0x19d7;0x1a0f,0x1a1c;0x0817,0x082e;0x12ae,0x12e1;0x1376,0x166e;0x1a1c,0x1a4b]in
 let overlay_code=[0x213c,0x2185;0x21ad,0x21d4;0x22cb,0x234e;0x2355,0x23a0;0x419f,0x41a6;0x422f,0x4241;0x4275,0x429d;0x4394,0x43d5;0x4468,0x456d;0x4584,0x45f0;0x4651,0x46c1;0x57b7,0x57ec;0x5929,0x5a46;0x784e,0x7a15;0x8396,0x83ac]in
 List.iter(fun(a,b)->require(Bytes.sub memory(a+0x100)(b-a)=Bytes.sub t.com a(b-a))(Printf.sprintf"resident code changed %04X"a))resident_code;
 List.iter(fun(a,b)->require(Bytes.sub memory(a+0x2200)(b-a)=Bytes.sub t.image a(b-a))(Printf.sprintf"overlay code changed %04X"a))overlay_code;
 require(call=internal_call t call.site&&S.word m entry.sp=call.resume)"continuation mismatch";
 let effects=ref[]and journal=ref[]and sp=ref entry.sp and depth=ref 0 and frames=ref[]and saved=ref None in
 let append x=effects:=x::!effects in
 let put kind writer address value=
  U.check address;Pli80_host.U8.check value;
  if kind="logical"then require(address<entry.sp-128||address>entry.sp+1)"logical/stack alias";
  S.write m address value;append(Runner.Memory_write(address,value));
  journal:={address;value;writer;depth= !depth;kind}::!journal in
 let push site value=put"compatibility"site(!sp-1)(value lsr 8);put"compatibility"site(!sp-2)(value land 255);sp:= !sp-2 in
 let code site size=
  if site>=0x2200&&site<0xaa00 then Bytes.sub t.image(site-0x2200)size
  else if site>=0x100&&site<0x2080 then Bytes.sub t.com(site-0x100)size else invalid_arg"compatibility site"in
 let compatibility=function
 |H.Enter(site,target)->let b=code site 3 in require(Char.code(Bytes.get b 0)=0xcd&&word b 1=target)"child CALL bytes";
   frames:=(!sp,target,site+3)::!frames;push site(site+3);incr depth
 |Leave->let before,target,_=List.hd !frames in
   let expected=if target=0x6668 then before+2 else before in
   require(!sp+2=expected)"child stack result";sp:= !sp+2;decr depth;frames:=List.tl !frames
 |Push(site,v)->let op=Char.code(Bytes.get(code site 1)0)in require(List.mem op[0xc5;0xd5;0xe5;0xf5])"PUSH identity";push site v
 |Pop->sp:= !sp+2
 |Constructor_arguments site->
   require(Char.code(Bytes.get(code site 1)0)=0xd5)"copied continuation PUSH";
   let continuation=S.word m !sp and source=S.word m(!sp+2)in
   let _,target,resume=List.hd !frames in
   require(target=0x6668&&source=0x20c6&&continuation=resume)"constructor argument ancestry";
   sp:= !sp+4;push site continuation in
 let staged state={Runner.effects=List.rev !effects;next_state=state;validate=(fun _->Ok());on_commit=ignore}in
 let sync b=for i=0 to 65535 do S.write m i(Char.code(Bytes.get b i))done in
 let preview state=match boundary.preview_host_program(staged state)with Ok r->sync r.memory;r|Error e->invalid_arg e in
 let child (q:R.returned)=
  let state=machine entry q !sp 0x4711 in
  let prior=List.rev !effects in let service_state=preview state in
  let b={Runner.state;read_memory=S.read m;copy_memory=(fun()->S.copy m);dma=service_state.dma;
   copy_filesystem=(fun()->Cpm.Filesystem.copy service_state.filesystem);
   preview_host_program=(fun p->boundary.preview_host_program{p with effects=prior@p.effects})}in
  let p=B.prepare t.saved B.Saved ~call:(B.internal_call t.saved B.Saved 0x7c39)~origin:(origin"PLI1.OVL"0x2511)b in
  saved:=Some p;List.iter append p.program.effects;
  journal:=List.rev_append(List.map(fun(w:write)->{w with depth=w.depth+ !depth})p.journal)!journal;
  ignore(preview p.state);require(p.state.sp= !sp+2&&p.state.pc=0x7c3c)"saved child resume";
  logical p.state in
 let guard_field base width=
  U.check base;require(width>=0&&base+width<=65536)"pointer field bounds";
  let scratch=[0xa628,0xa655;0xa760,0xa865;0xa8ab,0xa93a;0xaa16,0xaa1a;0xae32,0xae6d;0x1c36,0x1c5b;0x1f06,0x1f09;0x20c1,0x214a]in
  let protected=scratch@List.map(fun(a,b)->a+0x100,b+0x100)resident_code@List.map(fun(a,b)->a+0x2200,b+0x2200)overlay_code@[entry.sp-128,entry.sp+2]in
  require(not(List.exists(fun(a,b)->base<b&&base+width>a)protected))"pointer/scratch/code/stack alias"in
 let result=H.run m ~entry:(logical entry)~write:(fun ~site ~address ~value->put"logical"site address value)~compatibility ~guard_field ~saved:child in
 require(!sp=entry.sp&& !frames=[])"root stack balance";
 let state=machine entry result.returned(entry.sp+2)call.resume in
 let expected=preview state in
 let validate(r:Runner.host_program_result)=
  if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)
  then Error"acquisition parent ordered transition mismatch"else Ok()in
 let journal=List.rev !journal in let select kind=List.filter_map(fun w->if w.kind=kind then Some(w.address,w.value)else None)journal in
 {result;program={(staged state)with validate};state;journal;saved=Option.get !saved;logical_writes=select"logical";compatibility_writes=select"compatibility"}
