[@@@warning "-4-40-41-42"]
module H=Pli80_host.Reentrant_acquisition
module A=Acquisition_parent_bridge
module B=State_adaptation_bridge
module C=Pli80_host.Acquisition_parent
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
module U=Pli80_host.U16
type t={com:bytes;image:bytes;parent:A.t;saved:B.t;family:Acquisition_family_bridge.t}
type call={coordinate:string;site:int;resume:int}
type write=Range_processing_bridge.write={address:int;value:int;writer:int;depth:int;kind:string}
type prepared={result:H.result;program:Runner.host_program;state:Runner.state_snapshot;journal:write list;logical_writes:(int*int)list;compatibility_writes:(int*int)list}
let origin=A.origin
let require b m=if not b then invalid_arg("reentrant acquisition bridge: "^m)
let word b a=Char.code(Bytes.get b a)lor(Char.code(Bytes.get b(a+1))lsl 8)
let create ~pli_com ~pli1={com=Bytes.copy pli_com;image=Bytes.copy pli1;parent=A.create ~pli_com ~pli1;saved=B.create ~pli_com ~pli1;family=Acquisition_family_bridge.create ~pli_com ~pli1}
let internal_call t site=
 let off=site-0x2200 in require(off>=0&&off+3<=Bytes.length t.image&&Char.code(Bytes.get t.image off)=0xcd&&word t.image(off+1)=0x8423)"CALL identity";
 {coordinate=Printf.sprintf"PLI1.OVL+%04X"off;site;resume=site+3}
let verify_call t (p:Native_dispatch.previous) ~(entry:Runner.state_snapshot)=
 let c=internal_call t p.before.pc in
 require(p.origin=origin"PLI1.OVL"(c.site-0x2200)&&p.after=entry&&entry.pc=0x8423
  &&I8080.Step.pc_before p.step=c.site&&I8080.Step.pc_after p.step=entry.pc
  &&I8080.Step.fetched_bytes p.step=Bytes.sub t.image(c.site-0x2200)3
  &&I8080.Step.control_flow p.step=I8080.Step.Call{target=entry.pc;taken=true}
  &&p.before.sp=U.wrap(entry.sp+2))"canonical CALL/SP ancestry";
 let ws=List.filter_map(function I8080.Step.Write w->Some(w.address,w.value)|_->None)(I8080.Step.memory_accesses p.step)in
 require(List.sort compare ws=List.sort compare[entry.sp,c.resume land 255;entry.sp+1,c.resume lsr 8])"CALL word";c
let rec prepare ?(observe=(fun _ _ _ _ _->())) t ~call ~origin:o (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in require(o=origin"PLI1.OVL"0x6223&&entry.pc=0x8423)"wrong entry/image";
 List.iter Pli80_host.U8.check[entry.a;entry.b;entry.c;entry.d;entry.e;entry.h;entry.l];U.check entry.sp;
 require(entry.sp>=0xaf00&&entry.sp<=0xfffc)"stack alias/bounds";
 let memory=boundary.copy_memory()in let m=S.of_bytes memory in
 List.iter(fun(a,b)->require(Bytes.sub memory(a+0x2200)(b-a)=Bytes.sub t.image a(b-a))(Printf.sprintf"overlay code changed %04X"a))
  [0x01e8,0x01f7;0x020e,0x0222;0x213c,0x2185;0x21ad,0x21d4;0x22cb,0x234e;0x2355,0x23a0;0x620c,0x624d];
 require(call=internal_call t call.site&&S.word m entry.sp=call.resume)"continuation mismatch";
 let effects=ref[]and journal=ref[]and sp=ref entry.sp and depth=ref 0 and frames=ref[]in
 let append x=effects:=x::!effects in
 let put kind writer address value=
  U.check address;Pli80_host.U8.check value;
  if kind="logical"then require(address<entry.sp-256||address>entry.sp+1)"logical/stack alias";
  S.write m address value;append(Runner.Memory_write(address,value));
  journal:={address;value;writer;depth= !depth;kind}::!journal in
 let push site value=put"compatibility"site(!sp-1)(value lsr 8);put"compatibility"site(!sp-2)(value land 255);sp:= !sp-2 in
 let code site size=require(site>=0x2200&&site-0x2200+size<=Bytes.length t.image)"compatibility site";Bytes.sub t.image(site-0x2200)size in
 let compatibility=function
 |C.Enter(site,target)->let b=code site 3 in require(Char.code(Bytes.get b 0)=0xcd&&word b 1=target)"child CALL bytes";
   frames:=(!sp,target,site+3)::!frames;push site(site+3);incr depth
 |Leave->let before,_,_=List.hd !frames in require(!sp+2=before)"child stack result";sp:= !sp+2;decr depth;frames:=List.tl !frames
 |Push(site,v)->require(List.mem(Char.code(Bytes.get(code site 1)0))[0xc5;0xd5;0xe5;0xf5])"PUSH identity";push site v
 |Pop->sp:= !sp+2
 |Exchange _->invalid_arg"exchange belongs to initialization planner"
 |Constructor_arguments _->invalid_arg"reentrant acquisition bridge: constructor protocol belongs to child planner"in
 let staged state={Runner.effects=List.rev !effects;next_state=state;validate=(fun _->Ok());on_commit=ignore}in
 let sync b=for i=0 to 65535 do S.write m i(Char.code(Bytes.get b i))done in
 let preview state=match boundary.preview_host_program(staged state)with Ok r->sync r.memory;r|Error e->invalid_arg e in
 let child ~site ~operation (q:R.returned)=
  let target=match operation with H.Acquisition_parent->0x7b29|Saved_input->0x4711|Acquisition_frame->0x82e5|Attribute_dispatch->0x476c in
  let state=A.machine entry q !sp target in
  let prior=List.rev !effects in let service_state=preview state in
  let b={Runner.state;read_memory=S.read m;copy_memory=(fun()->S.copy m);dma=service_state.dma;
   copy_filesystem=(fun()->Cpm.Filesystem.copy service_state.filesystem);
   preview_host_program=(fun p->boundary.preview_host_program{p with effects=prior@p.effects})}in
  let program,child_state,child_journal=match operation with
  |H.Acquisition_parent->let p=A.prepare t.parent ~call:(A.internal_call t.parent site)~origin:(origin"PLI1.OVL"0x5929)b in p.program,p.state,p.journal
  |Saved_input->let p=B.prepare t.saved B.Saved ~call:(B.internal_call t.saved B.Saved site)~origin:(origin"PLI1.OVL"0x2511)b in p.program,p.state,p.journal
  |Acquisition_frame|Attribute_dispatch->
   let operation,offset=if operation=H.Acquisition_frame then Acquisition_family_bridge.Context,0x60e5 else Acquisition_family_bridge.Attribute,0x256c in
   let p=Acquisition_family_bridge.prepare ~follow_spine:true ~recursive:(fun site boundary->
    let p=prepare ~observe t ~call:(internal_call t site)~origin:(origin"PLI1.OVL"0x6223)boundary in p.program,p.state,p.journal)
    t.family operation ~call:(Acquisition_family_bridge.internal_call t.family operation site)~origin:(origin"PLI1.OVL"offset)b in
   p.program,p.state,p.journal in
  List.iter append program.effects;
  journal:=List.rev_append(List.map(fun(w:write)->{w with depth=w.depth+ !depth})child_journal)!journal;
  ignore(preview child_state);require(child_state.sp= !sp+2&&child_state.pc=site+3)"child resume";
  A.logical child_state in
 let result=H.run m ~entry:(A.logical entry)~write:(fun ~site ~address ~value->put"logical"site address value)~compatibility ~child in
 require(!sp=entry.sp&& !frames=[])"root stack balance";
 let state=A.machine entry result.returned(entry.sp+2)call.resume in
 let expected=preview state in
 let validate(r:Runner.host_program_result)=
  if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)
  then Error"reentrant acquisition ordered transition mismatch"else Ok()in
 let journal=List.rev !journal in let select kind=List.filter_map(fun w->if w.kind=kind then Some(w.address,w.value)else None)journal in
 let p={result;program={effects=List.rev !effects;next_state=state;validate;on_commit=ignore};state;journal;logical_writes=select"logical";compatibility_writes=select"compatibility"}in
 observe call entry memory p expected;p
