[@@@warning "-4-40-41-42"]
module F=Pli80_host.Acquisition_family
module C=Pli80_host.Acquisition_parent
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
module U=Pli80_host.U16
module A=Acquisition_parent_bridge
module B=State_adaptation_bridge
type operation=Pli2_output of int|Output of int|Adapter of int|Resident_reader of Pli80_host.Resident_reader.operation|Context|Field|Attribute|Spine|Resident|Pair_gate|Selected_transform|Table_adapter|Wrapper|Repeat|Copy05|Traversal|Construction|Record_output|Index_one|Parent|Reader of Pli80_host.Reader_construction.operation|Recursive of Pli80_host.Recursive_parent.operation
type call={coordinate:string;site:int;resume:int;operation:operation}
type write=Range_processing_bridge.write={address:int;value:int;writer:int;depth:int;kind:string}
type t={emitter:Int_emitter_bridge.t;pli0:bytes;pli2:bytes;range:Range_processing_bridge.t;gate:Attribute_gate_bridge.t;com:bytes;image:bytes;adapt:B.t;input:Input_processing_bridge.t;publication:Range_publication_bridge.t;
 balance:Balance_scan_bridge.t;word:Publication_primitives_bridge.t;mapped:Mapped_publication_bridge.t;control:Mapped_control_bridge.t}
type prepared={result:F.result;program:Runner.host_program;state:Runner.state_snapshot;journal:write list;logical_writes:(int*int)list}
let origin=A.origin
let require b m=if not b then invalid_arg("acquisition family bridge: "^m)
let word b a=Char.code(Bytes.get b a)lor(Char.code(Bytes.get b(a+1))lsl 8)
let bounds=function Pli2_output offset->offset,List.assoc offset[0x7b1b,0x7b79;0x7314,0x7338;0x7365,0x7397;0x793c,0x79a2;0x7b99,0x7bb2;0x7397,0x73a7;0x73a7,0x73c4;0x7903,0x793c;0x79b6,0x79be;0x7ac4,0x7ad4;0x7ad4,0x7ae4;0x7ae4,0x7b02;0x79e2,0x7a17;0x7a17,0x7a4e;0x73d0,0x73fe;0x8225,0x8248;0x8248,0x8258;0x7701,0x77bf;0x746f,0x74c7;0x74c7,0x7510;0x7510,0x7529;0x7557,0x756d;0x756d,0x75a7;0x75a7,0x75ce;0x75ce,0x75f1;0x75f1,0x7619;0x7619,0x7630;0x7434,0x744d;0x7630,0x7647;0x765e,0x7675;0x753c,0x7550;0x7550,0x7557]| Output offset->offset,(List.assoc offset[0x1272,0x12ae;0x1140,0x119e;0x119e,0x11c3;0x11c3,0x11e5;0x11e5,0x1207;0x1207,0x1229;0x1a29,0x1a33])| Adapter offset->offset,(List.assoc offset [0x33d6,0x33dc;0x33ad,0x33d6;0x335b,0x33ad;0x2dca,0x2e26;0x2dc3,0x2dca;0x13ad,0x13ba;0x0187,0x01af;0x61b6,0x61c5])| Recursive op->Pli80_host.Recursive_parent.bounds op| Resident_reader op->Pli80_host.Resident_reader.bounds op| Context->0x60e5,0x61a4|Field->0x5e98,0x60e5|Attribute->0x256c,0x25a9|Spine->0x4f54,0x4f6e|Resident->0x1376,0x15da|Pair_gate->0x2259,0x22c0|Selected_transform->0x345e,0x34ac|Table_adapter->0x25a9,0x25c0|Wrapper->0x6619,0x6639|Repeat->0x654e,0x65f9|Copy05->0x6708,0x67bb|Traversal->0x46ed,0x4738|Construction->0x4738,0x478d|Record_output->0x666e,0x6708|Index_one->0x28aa,0x2c53|Parent->0x19f0,0x1afd|Reader op->Pli80_host.Reader_construction.bounds op
let resident_operation=function Output _|Resident|Resident_reader _->true|_->false
let create ~pli_com ~pli1={emitter=Int_emitter_bridge.create ~pli_com ~pli1;pli0=Bytes.empty;pli2=Bytes.empty;range=Range_processing_bridge.create ~pli_com ~pli1;gate=Attribute_gate_bridge.create ~pli_com ~pli1;com=Bytes.copy pli_com;image=Bytes.copy pli1;adapt=B.create ~pli_com ~pli1;input=Input_processing_bridge.create ~pli_com ~pli1;
 publication=Range_publication_bridge.create ~pli1;balance=Balance_scan_bridge.create ~pli1;
 word=Publication_primitives_bridge.create ~pli1;mapped=Mapped_publication_bridge.create ~pli1;control=Mapped_control_bridge.create ~pli1}
let create_with_pli0 ~pli_com ~pli0 ~pli1={ (create ~pli_com ~pli1) with pli0=Bytes.copy pli0 }
let create_with_images ~pli_com ~pli0 ~pli1 ~pli2={ (create_with_pli0 ~pli_com ~pli0 ~pli1) with pli2=Bytes.copy pli2 }
let internal_call t operation site=
 let base=if site<0x2200 then 0x100 else 0x2200 in let off=site-base in let target=fst(bounds operation)+(if resident_operation operation then 0x100 else 0x2200) in
 let fits image=off>=0&&off+3<=Bytes.length image&&Char.code(Bytes.get image off)=0xcd&&word image(off+1)=target in
 let image=if (match operation with Pli2_output _->true|_->false)&&fits t.pli2 then"PLI2.OVL"else if base=0x100&&fits t.com then"PLI.COM"else if base=0x2200&&fits t.image then"PLI1.OVL"else if resident_operation operation&&fits t.pli0 then"PLI0.OVL"else if (resident_operation operation||(match operation with Pli2_output _->true|_->false))&&fits t.pli2 then"PLI2.OVL"else invalid_arg"acquisition family bridge: CALL identity"in
 {coordinate=Printf.sprintf"%s+%04X"image off;site;resume=site+3;operation}
let verify_call t operation (p:Native_dispatch.previous) ~(entry:Runner.state_snapshot)=
 let c=internal_call t operation p.before.pc in
 let caller_image=String.sub c.coordinate 0(String.index c.coordinate '+') in
 let caller_bytes=if caller_image="PLI.COM"then t.com else if caller_image="PLI0.OVL"then t.pli0 else if caller_image="PLI2.OVL"then t.pli2 else t.image in
 let caller_base=if caller_image="PLI.COM"then 0x100 else 0x2200 in
 require(p.origin=origin caller_image(c.site-caller_base)&&p.after=entry&&entry.pc=fst(bounds operation)+(if resident_operation operation then 0x100 else 0x2200)
  &&I8080.Step.pc_before p.step=c.site&&I8080.Step.pc_after p.step=entry.pc
  &&I8080.Step.fetched_bytes p.step=Bytes.sub caller_bytes(c.site-caller_base)3
  &&I8080.Step.control_flow p.step=I8080.Step.Call{target=entry.pc;taken=true}
  &&p.before.sp=U.wrap(entry.sp+2))"canonical CALL/SP ancestry";
 let ws=List.filter_map(function I8080.Step.Write w->Some(w.address,w.value)|_->None)(I8080.Step.memory_accesses p.step)in
 require(ws=[entry.sp+1,c.resume lsr 8;entry.sp,c.resume land 255])"CALL word";c
exception Unfinished of Runner.state_snapshot * bytes * write list * Runner.host_program_result
let prepare ?(follow_spine=false) ?(recursive=(fun _ _->invalid_arg"unfinished recursive 6223 callback")) t operation ~call ~origin:o (boundary:Runner.instruction_boundary)=
 let entry=boundary.state and first,_=bounds operation in
 require(o=origin(if resident_operation operation then"PLI.COM"else(match operation with Pli2_output _->"PLI2.OVL"|_->"PLI1.OVL"))first&&entry.pc=first+(if resident_operation operation then 0x100 else 0x2200))"wrong entry/image";
 List.iter Pli80_host.U8.check[entry.a;entry.b;entry.c;entry.d;entry.e;entry.h;entry.l];U.check entry.sp;
 require(entry.sp>=0xb000&&entry.sp<=0xfffc)"stack alias/bounds";
 let memory=boundary.copy_memory()in let m=S.of_bytes memory in
 let resident_code=[0x1272,0x12ae;0x064c,0x0670;0x0328,0x0338;0x1688,0x18fa;0x02ee,0x034a;0x05b2,0x05f8;0x070c,0x0788;0x19bb,0x19d5;0x1a0f,0x1a1c;0x09cb,0x0e47;0x1140,0x1229;0x0817,0x082e;0x12ae,0x12e1;0x1376,0x166e;0x1a1c,0x1a4b]in
 let overlay_code=[0x0c75,0x0d1c;0x01c6,0x01d8;0x013d,0x0146;0x0b84,0x0c75;0x47e2,0x4929;0x3563,0x3585;0x256c,0x25a9;0x0187,0x01af;0x2dc3,0x2fc2;0x4929,0x49d7;0x0146,0x014f;0x086e,0x0a0b;0x80ef,0x810b;0x8273,0x82ac;0x0a0b,0x0ba8;0x11e2,0x1328;0x0e00,0x1187;0x1187,0x11e2;0x342f,0x345e;0x335b,0x33dc;0x810b,0x8167;0x0277,0x02e9;0x0fc9,0x1014;0x01d8,0x01e8;0x0261,0x026b;0x026b,0x0277;0x02e9,0x02f0;0x02f0,0x067c;0x80ca,0x80ef;0x2006,0x20a6;0x13ad,0x13ba;0x4a26,0x4a72;0x58bb,0x590e;0x0d6e,0x0d9d;0x140d,0x1510;0x1afd,0x1d37;0x8167,0x8179;0x8380,0x8396;0x13e3,0x1510;0x156d,0x157a;0x1be8,0x1c07;0x7ed7,0x7f4f;0x8268,0x8273;0x19f0,0x1afd;0x21e9,0x2221;0x24f1,0x2511;0x25c0,0x25d6;0x27d1,0x2804;0x2f1c,0x2fc2;0x31a8,0x31fb;0x3262,0x329f;0x3533,0x3547;0x6639,0x6649;0x80b1,0x80b7;0x8179,0x8187;0x666e,0x6708;0x82bb,0x82cd;0x4394,0x452b;0x46ed,0x478d;0x4cc2,0x4ce9;0x4f54,0x4f6e;0x61a4,0x6223;0x625d,0x6288;0x6314,0x63cf;0x640d,0x6477;0x6477,0x64f2;0x64f2,0x6508;0x654e,0x65f9;0x65f9,0x6619;0x6619,0x6639;0x2308,0x230e;0x4c4c,0x4c52;0x4cd4,0x4ce1;0x4f2a,0x4f54;0x56e1,0x570e;0x2185,0x21ad;0x28aa,0x2dc3;0x6708,0x6ca1;0x8309,0x8314;0x834f,0x8357;0x8380,0x8386;0x8396,0x83ac;0x21d4,0x21e9;0x2221,0x22c0;0x345e,0x34ac;0x25a9,0x25c0;0x23a0,0x23d2;0x25d6,0x25ec;0x2c53,0x2c59;0x2fc2,0x31a8;0x31fb,0x3262;0x329f,0x32b3;0x3304,0x3333;0x01af,0x01c6;0x020e,0x0222;0x213c,0x2185;0x21ad,0x21d4;0x22cb,0x234e;0x2355,0x23a0;0x3558,0x3563;0x387f,0x38a9;0x3963,0x3987;0x3a76,0x3c16;0x3c8a,0x415e;0x415e,0x41ba;0x421f,0x43ac;0x452b,0x45f0;0x500f,0x5035;0x506e,0x50b4;0x53bb,0x53c6;0x81f1,0x8214;0x45f0,0x462d;0x5a46,0x5ab2;0x5e48,0x61a4;0x784e,0x7a15;0x7ff3,0x8003;0x83a0,0x83ac]in
 List.iter(fun(a,b)->require(Bytes.sub memory(a+0x100)(b-a)=Bytes.sub t.com a(b-a))(Printf.sprintf"resident code changed %04X"a))resident_code;
 if not(resident_operation operation||(match operation with Pli2_output _->true|_->false)) then List.iter(fun(a,b)->require(Bytes.sub memory(a+0x2200)(b-a)=Bytes.sub t.image a(b-a))(Printf.sprintf"overlay code changed %04X"a))overlay_code;
 (match operation with Pli2_output _->
  List.iter(fun(a,b)->require(Bytes.sub memory(a+0x2200)(b-a)=Bytes.sub t.pli2 a(b-a))"PLI2 emission code changed")[0x7b1b,0x7b79;0x7314,0x7338;0x7365,0x7397;0x793c,0x79a2;0x7b99,0x7bb2;0x7397,0x73a7;0x73a7,0x73c4;0x7903,0x793c;0x79b6,0x79be;0x7ac4,0x7ad4;0x7ad4,0x7ae4;0x7ae4,0x7b02;0x79e2,0x7a17;0x7a17,0x7a4e;0x73d0,0x73fe;0x8225,0x8248;0x8248,0x8258;0x7701,0x77bf;0x7434,0x744d;0x746f,0x7529;0x753c,0x7630;0x7630,0x7647;0x765e,0x7675];
  require(Bytes.sub memory call.site 3=Bytes.sub t.pli2(call.site-0x2200)3)"PLI2 caller changed";
  (match operation with Pli2_output (0x7701|0x8225|0x8248 as offset)->
   let pointer=if offset=0x8225 then(entry.d lsl 8)lor entry.e else(entry.b lsl 8)lor entry.c in
   require(pointer<=0xfffa)"7701 nonwrapping field scope";
   let intersects(a,b)=pointer<b&&pointer+5>a in
   require(not(List.exists intersects [0xadd3,0xadd5;0xadd8,0xadda;0xadea,0xadef;0xae61,0xae66;0xadab,0xadb3;0xadc4,0xadc6;0xadcc,0xadcd;0x1c2c,0x1c2e;0x1ce4,0x1d8c;0x205f,0x20c1;entry.sp-32,entry.sp+2]))"7701 pointer/scratch/buffer/stack alias"
  |_->());
  let sentinel=S.word m 0x2155 in
  (match operation with Pli2_output(0x793c|0x7b99)->require(not(sentinel>=0xadab&&sentinel<0xadc6))"indexed carrier/sentinel alias"|_->());
  (match operation with Pli2_output(0x7b1b|0x7314|0x7365)->require(not(sentinel>=0xadaa&&sentinel<0xadc6))"carrier-clear/sentinel alias"|_->());
  require(not(sentinel>=0xadc6&&sentinel<0xae66))"PLI2 cache/sentinel alias";
  require(not(sentinel>=entry.sp-32&&sentinel<entry.sp+2)&&not(sentinel>=0x1ce4&&sentinel<0x1d8c)&&not(sentinel>=0x205f&&sentinel<0x20c1)&&not(sentinel>=0x1c2c&&sentinel<0x1c2e))"PLI2 output scratch/stack alias";
  require(not(List.exists(fun(a,b)->sentinel>=a+0x100&&sentinel<b+0x100)resident_code)&&not(List.exists(fun(a,b)->sentinel>=a+0x2200&&sentinel<b+0x2200)[0x7b1b,0x7b79;0x7314,0x7338;0x7365,0x7397;0x793c,0x79a2;0x7b99,0x7bb2;0x7397,0x73a7;0x73a7,0x73c4;0x7903,0x793c;0x79b6,0x79be;0x7ac4,0x7ad4;0x7ad4,0x7ae4;0x7ae4,0x7b02;0x79e2,0x7a17;0x7a17,0x7a4e;0x73d0,0x73fe;0x8225,0x8248;0x8248,0x8258;0x7701,0x77bf;0x7434,0x744d;0x746f,0x7529;0x753c,0x7630;0x7630,0x7647;0x765e,0x7675]))"PLI2 output code/sentinel alias"
 |Output _->
  let caller,base=if call.site<0x2200 then t.com,0x100 else if String.starts_with ~prefix:"PLI0.OVL+"call.coordinate then t.pli0,0x2200 else if String.starts_with ~prefix:"PLI2.OVL+"call.coordinate then t.pli2,0x2200 else t.image,0x2200 in
  require(Bytes.sub memory call.site 3=Bytes.sub caller(call.site-base)3)"output caller code changed";
  let sentinel=S.word m 0x2155 in
  require(not(sentinel>=entry.sp-32&&sentinel<entry.sp+2)&&
   not(sentinel>=0x1ce4&&sentinel<0x1d8c)&&not(sentinel>=0x205f&&sentinel<0x20c1)&&
   not(List.exists(fun(a,b)->sentinel>=a+0x100&&sentinel<b+0x100)resident_code))(Printf.sprintf"output sentinel/code/scratch/stack alias %04X"sentinel)
 |_->());
 require(call=internal_call t operation call.site&&S.word m entry.sp=call.resume)"continuation mismatch";
 let effects=ref[]and journal=ref[]and sp=ref entry.sp and depth=ref 0 and frames=ref(if operation=Copy05 then[entry.sp+2,0x8908,call.resume]else[])in
 let append item=effects:=item::!effects in
 let frame_sites=[0x0c25;0x0c27;0x08e6;0x08e8;0x08f8;0x0a3f;0x0a41;0x1219;0x1222;0x1224;0x122c;0x1235;0x1237;0x123f;0x1244;0x19fb;0x6564;0x6570;0x6572;0x6577;0x65d8;0x60f0;0x60f2;0x6108;0x610d;0x6116;0x5ea7;0x5eaa;0x5ebc;0x5ed2;0x5ed4;0x5edc;0x6072;0x5f16;0x507f;0x5081;0x3ca9;0x3caf;0x3cb1]in
 let put kind writer address value=
  U.check address;Pli80_host.U8.check value;
  if kind="logical"&&address>=entry.sp-512&&address<=entry.sp+1 then(
   require(List.mem(writer-0x2200)frame_sites&&address>= !sp&&address<entry.sp)"frame/stack alias");
  S.write m address value;append(Runner.Memory_write(address,value));journal:={address;value;writer;depth= !depth;kind}::!journal in
 let push site value=put"compatibility"site(!sp-1)(value lsr 8);put"compatibility"site(!sp-2)(value land 255);sp:= !sp-2 in
 let code site size=
  if site>=0x2200&&site-0x2200+size<=Bytes.length t.image then Bytes.sub (match operation with Pli2_output _->t.pli2|_->t.image)(site-0x2200)size
  else if site>=0x100&&site-0x100+size<=Bytes.length t.com then Bytes.sub t.com(site-0x100)size else invalid_arg"compatibility coordinate"in
 let compatibility=function
 |C.Enter(site,target)->let b=code site 3 in require(Char.code(Bytes.get b 0)=0xcd&&word b 1=target)"child CALL bytes";
   frames:=(!sp,target,site+3)::!frames;push site(site+3);incr depth
 |Leave->let before,_,_=List.hd !frames in require(!sp+2=before)"child stack result";sp:= !sp+2;decr depth;frames:=List.tl !frames
 |Push(site,v)->require(List.mem(Char.code(Bytes.get(code site 1)0))[0xc5;0xd5;0xe5;0xf5])"PUSH identity";push site v
 |Exchange(site,v)->require(Char.code(Bytes.get(code site 1)0)=0xe3)"XTHL identity";put"compatibility"site !sp(v land 255);put"compatibility"site(!sp+1)(v lsr 8)
 |Pop->sp:= !sp+2
 |Constructor_arguments site->
   require(site=0x6674&&Char.code(Bytes.get(code site 1)0)=0xd5)"N2 PUSH D identity";
   (match !frames with
   |(before,target,resume)::rest->require(target=0x6668&& !sp=before-2&&S.word m !sp=resume)"N2 original continuation";
     sp:= !sp+4;push site resume;frames:=(before+2,target,resume)::rest
   |[]->invalid_arg"missing constructor frame")in
 let software ~site ~consumed=
  require(site=0x891f&&consumed=8&&Char.code(Bytes.get(code site 1)0)=0xd5)"software continuation writer";
  match !frames with
  |(before,target,resume)::rest->require(target=0x8908&& !sp=before+6&&S.word m !sp=resume)"N8 copied continuation/SP";frames:=(before+consumed,target,resume)::rest
  |[]->invalid_arg"missing software frame"in
 let adjust ~site ~delta=if site=0x3526 then(require(delta=11&&Char.code(Bytes.get(code site 1)0)=0xf9)"11E2 SPHL";sp:= !sp+delta)else(require(Char.code(Bytes.get(code site 1)0)=(if delta=1 then 0x33 else 0x3b)&&List.mem delta[1;-1])"private SP instruction";sp:= !sp+delta)in
 let staged state={Runner.effects=List.rev !effects;next_state=state;validate=(fun _->Ok());on_commit=ignore}in
 let sync b=for a=0 to 65535 do S.write m a(Char.code(Bytes.get b a))done in
 let preview state=match boundary.preview_host_program(staged state)with Ok result->sync result.memory;result|Error e->invalid_arg e in
 let guard_field base width=
  U.check base;require(width>=0&&base+width<=65536)"pointer bounds";
  let protected=[entry.sp-512,entry.sp+2;0xa628,0xa65b;0xa6ca,0xa861;0xa863,0xa865;0xa8ab,0xa93a;0xa947,0xa9e5;0xaa16,0xaa1a;0xae32,0xae6d;0x1c36,0x1c5b;0x1f06,0x1f09;0x20c1,0x214a]
   @List.map(fun(a,b)->a+0x100,b+0x100)resident_code@List.map(fun(a,b)->a+0x2200,b+0x2200)overlay_code in
  require(not(List.exists(fun(a,b)->base<b&&base+width>a)protected))"pointer/scratch/code/stack alias"in
 let rec native ~site ~target (q:R.returned)=
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
  |target when List.mem_assoc target [0x074c,Pli80_host.Resident_reader.Close;0x0428,Write_record;0x03fe,Default_dma;0x1b35,Pointer_tail;0x1b40,Memory_zero;0x1b33,Pointer_difference;0x1788,Lookahead;0x19db,Peek_cached;0x1943,Read_ahead;0x19a2,Boundary_probe;0x19bc,Boundary_clear;0x19c5,Letter_probe;0x080c,Read_buffer;0x06b2,Poll;0x0441,Poll_console;0x03ee,Set_dma;0x0418,Read_record;0x1abb,Service_gate;0x1b2c,Difference;0x1b38,Memory_difference;0x0e40,Refill;0x0dd9,Reset;0x0c86,Format_counter;0x0bf5,Source;0x0acb,Filter;0x0ba9,Fetch_masked;0x0f1f,Store]->
   (if target=0x080c then guard_field(S.word m 0x1d06)1);
   Pli80_host.Resident_reader.run(List.assoc target [0x074c,Pli80_host.Resident_reader.Close;0x0428,Write_record;0x03fe,Default_dma;0x1b35,Pointer_tail;0x1b40,Memory_zero;0x1b33,Pointer_difference;0x1788,Lookahead;0x19db,Peek_cached;0x1943,Read_ahead;0x19a2,Boundary_probe;0x19bc,Boundary_clear;0x19c5,Letter_probe;0x080c,Read_buffer;0x06b2,Poll;0x0441,Poll_console;0x03ee,Set_dma;0x0418,Read_record;0x1abb,Service_gate;0x1b2c,Difference;0x1b38,Memory_difference;0x0e40,Refill;0x0dd9,Reset;0x0c86,Format_counter;0x0bf5,Source;0x0acb,Filter;0x0ba9,Fetch_masked;0x0f1f,Store])m ~entry:q ~write:(fun ~site ~address ~value->put"logical"site address value)~compatibility ~sp:(fun()-> !sp)~invoke:native
  |0x0917->(Pli80_host.Acquisition_parent.run ~operation:Pli80_host.Acquisition_parent.Context_mask m ~entry:q ~write:(fun ~site ~address ~value->put"logical"site address value)~compatibility ~guard_field ~saved:(fun _->invalid_arg"context saved child")).returned
  |0x13ae->(Pli80_host.Acquisition_parent.run ~operation:Pli80_host.Acquisition_parent.Counted_read ~reader_refill:(fun q->native ~site:0x13b8 ~target:0x0e40 q)m ~entry:q ~write:(fun ~site ~address ~value->put"logical"site address value)~compatibility ~guard_field ~saved:(fun _->invalid_arg"reader saved child")).returned
  |0xff6->
   let offset=site-0x2200 in let call:Int_emitter_bridge.call={coordinate=Printf.sprintf"PLI1.OVL+%04X"offset;site;resume=site+3;image="PLI1.OVL";offset}in
   let p=Int_emitter_bridge.prepare t.emitter ~call ~origin:(origin"PLI.COM"0xef6)~state ~memory:(S.copy m)in
   let reset=ref false in
   List.iter(function Runner.Dispatch_bdos _ as e->append e|Runner.Memory_write(address,value)->
    let distance= !sp-address in let stack=distance>=1&&distance<=10 in
    let writer=if stack then(match(distance+1)/2 with 1->if !reset then 0x1021 else 0x1016|2->if !reset then 0x434 else 0x3fa|3->0x1abb|4->0x1abc|5->0x1ac3|_->assert false)
     else if address=0x20b0 then 0xff9 else if address=0x1e0c then(if value=0 then 0x101c else 0x100b)
     else if address>=0x1d8c&&address<0x1e8c then 0x1006 else match address with 0x2060->0x3f1|0x205f->0x3f3|0x2066->0x42b|0x2065->0x42d|_->invalid_arg"unproved emitter writer"in
    if address=0x1e0c&&value=0 then reset:=true;put(if stack then"compatibility"else"logical")writer address value)p.program.effects;
   ignore(preview p.state);require(p.state.sp= !sp+2&&p.state.pc=site+3)"emitter continuation";A.logical p.state
  |5->
   let fn=q.bc land 255 in require(List.mem fn[11;16;20;21;26])"reader BDOS function";
   let status=if fn<>20 then 0 else(
    let ram=I8080.Memory.create()in I8080.Memory.load ram ~address:0(S.copy m);
    let key=match Cpm.Filesystem.key_of_fcb ~memory:ram ~fcb_address:q.de ~current_drive:0 ~current_user:0 with Ok k->k|Error _->invalid_arg"reader FCB"in
    let fcb=Cpm.Fcb.at ram ~address:q.de in let record=Cpm.Fcb.extent fcb*128+Cpm.Fcb.current_record fcb in
    match Cpm.Filesystem.record_count before.filesystem key with Some n when Cpm.Fcb.current_record fcb<=128&&record<n->0|_->1)in
   let call_state=A.machine entry q !sp 5 in
   let expected_resume={call_state with Runner.a=status;b=0;h=0;l=status;sp= !sp;pc=5}in
   append(Runner.Dispatch_bdos{call_state;expected_resume});ignore(preview expected_resume);A.logical expected_resume
  |0x45d2->let p=B.prepare t.adapt B.Publish ~call:(B.internal_call t.adapt B.Publish site)~origin:(origin"PLI1.OVL"0x23d2)boundary in import p.program p.journal p.state
  |0xa0c0->let p=Attribute_gate_bridge.prepare t.gate Attribute_gate_bridge.Gate ~call:(Attribute_gate_bridge.internal_call t.gate Attribute_gate_bridge.Gate site)~origin:(origin"PLI1.OVL"0x7ec0)boundary in import p.program p.journal p.state
  |0x9f53->let call=Range_processing_bridge.internal_call t.range site in let p=Range_processing_bridge.prepare t.range ~call ~origin:(origin"PLI1.OVL"0x7d53)boundary in import p.program p.journal p.state
  |0xa2b7->let p=Attribute_gate_bridge.prepare t.gate Attribute_gate_bridge.Saved ~call:(Attribute_gate_bridge.internal_call t.gate Attribute_gate_bridge.Saved site) ~origin:(origin"PLI1.OVL"0x80b7)boundary in import p.program p.journal p.state
  |0x8423->let program,child_state,child_journal=recursive site boundary in import program child_journal child_state
  |0xa248->let p=Input_processing_bridge.prepare t.input ~call:(Input_processing_bridge.internal_call t.input site)~origin:(origin"PLI1.OVL"0x8048)boundary in import p.program p.journal p.state
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
 let result=match operation with Resident_reader op->{F.returned=Pli80_host.Resident_reader.run op m ~entry:(A.logical entry)~write:(fun ~site ~address ~value->put"logical"site address value)~compatibility ~sp:(fun()-> !sp)~invoke:native;field=None}|_->F.run(match operation with Pli2_output offset->F.Pli2_output offset|Output offset->F.Output offset| Adapter offset->F.Adapter offset|Resident_reader _->assert false| Context->F.Context|Field->F.Field|Attribute->F.Attribute|Spine->F.Spine|Resident->F.Resident|Pair_gate->F.Pair_gate|Selected_transform->F.Selected_transform|Table_adapter->F.Table_adapter|Wrapper->F.Wrapper|Repeat->F.Repeat|Copy05->F.Copy05|Traversal->F.Traversal|Construction->F.Construction|Record_output->F.Record_output|Index_one->F.Index_one|Parent->F.Parent|Reader op->F.Reader op|Recursive op->F.Recursive op)m ~entry:(A.logical entry)
  ~write:(fun ~site ~address ~value->put"logical"site address value)~compatibility ~adjust ~sp:(fun()-> !sp)~guard_field ~native ~follow_spine ~software in
 let consumed=if operation=Copy05 then 8 else 0 in
 if operation=Copy05 then(require(!frames=[entry.sp+10,0x8908,call.resume])"root copied continuation frame";frames:=[]);
 require(!sp=entry.sp+consumed&& !frames=[])"root/private frame balance";
 let state=A.machine entry result.returned(entry.sp+2+consumed)call.resume in
 let expected=preview state in let validate(r:Runner.host_program_result)=
  if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)
  then Error"family ordered program mismatch"else Ok()in
 let journal=List.rev !journal in
 {result;program={effects=List.rev !effects;next_state=state;validate;on_commit=ignore};state;journal;
 logical_writes=List.filter_map(fun w->if w.kind="logical"then Some(w.address,w.value)else None)journal}
