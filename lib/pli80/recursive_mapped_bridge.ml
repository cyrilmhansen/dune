[@@@warning "-4-40-41-42"]
module R = Pli80_host.Recursive_mapped
type t = { image:bytes; code:(int*bytes)list }
type call = { coordinate:string; runtime_site:int; resume:int }
type residue = { address:int; value:int; writer:int; depth:int; kind:string }
type prepared = { result:R.result; memory:bytes; state:Runner.state_snapshot;
                  compatibility_writes:(int*int)list; final_writers:residue list; journal:residue list }
let require b message=if not b then invalid_arg("7C1B bridge: "^message)
let word b a=Char.code(Bytes.get b a)lor(Char.code(Bytes.get b(a+1))lsl 8)
let create ~pli_com ~pli1 =
  ignore(Packed_scan_bridge.create ~pli_com ~pli1);
  let image=Bytes.copy pli1 in
  let code=(0x1b2c,Bytes.sub pli_com 0x1a2c 7)::List.map(fun(a,b)->a+0x2200,Bytes.sub pli1 a(b-a))
    [0x7c1b,0x7d53;0x7a4d,0x7a93;0x7aa9,0x7abf;0x7b2e,0x7b49;
     0x7b7a,0x7ba2;0x7bbf,0x7c1b;0x82bb,0x82c6;0x82c9,0x82d0;0x82e1,0x82ea]in
  {image;code}
let verify_call t ~origin ~(before:Runner.state_snapshot) ~(after:Runner.state_snapshot) step ~(entry:Runner.state_snapshot) =
  let site=I8080.Step.pc_before step and offset=I8080.Step.pc_before step-0x2200 in
  require(match origin with Analysis.Execution_map.Image_byte{image;offset=o}->image.name="PLI1.OVL"&&image.drive=0&&image.user=0&&o=offset|_->false)"noncanonical/non-CALL entry";
  require(offset>=0&&offset+3<=Bytes.length t.image&&Char.code(Bytes.get t.image offset)=0xcd&&word t.image(offset+1)=0x9e1b)"not a historical CALL7C1B";
  require(before.pc=site&&entry.pc=0x9e1b&&I8080.Step.pc_after step=0x9e1b&&after=entry
    &&I8080.Step.fetched_bytes step=Bytes.sub t.image offset 3
    &&I8080.Step.control_flow step=I8080.Step.Call{target=0x9e1b;taken=true}
    &&before.sp=Pli80_host.U16.wrap(entry.sp+2))"CALL/state/SP ancestry";
  let resume=Pli80_host.U16.wrap(site+3)in
  let writes=List.filter_map(function I8080.Step.Write q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses step)in
  require(List.sort compare writes=List.sort compare[entry.sp,resume land 255;Pli80_host.U16.wrap(entry.sp+1),resume lsr 8])"original continuation writer";
  {coordinate=Printf.sprintf"PLI1.OVL+%04X"offset;runtime_site=site;resume}
let targets=[0x7c25,0x9c4d;0x7c37,0x9dbf;0x7c5d,0x9e1b;0x7c6c,0x9d7a;0x7c71,0x9e1b;
  0x7cab,0x9d2e;0x7cc8,0x9c4d;0x7cd5,0x9ca9;0x7ce3,0x9e1b;0x7cf5,0x9d2e;
  0x7d06,0x9ca9;0x7d13,0x9c63;0x7d2d,0x9e1b;0x7d3a,0x9d7a;0x7a6b,0x9c4d;
  0x7b87,0x9c63;0x7bf3,0xa4c9;0x7bf7,0x1b2c;0x7c14,0x9d2e]
let prepare t ~call ~origin ~(state:Runner.state_snapshot) ~memory =
  require(state.pc=0x9e1b)"wrong entry PC";
  require(match origin with Analysis.Execution_map.Image_byte{image;offset}->image.name="PLI1.OVL"&&image.drive=0&&image.user=0&&offset=0x7c1b|_->false)"wrong entry coordinate";
  List.iter Pli80_host.U8.check[state.a;state.b;state.c;state.d;state.e;state.h;state.l];
  Pli80_host.U16.check state.sp;
  let m=Pli80_host.State.of_bytes memory in
  List.iter(fun(a,b)->require(Bytes.sub memory a(Bytes.length b)=b)"changed historical code/helper identity")t.code;
  require(Bytes.sub memory call.runtime_site 3=Bytes.sub t.image(call.runtime_site-0x2200)3)"changed root caller";
  require(Pli80_host.State.word m state.sp=call.resume)"malformed continuation";
  let latest=Hashtbl.create 64 and journal=ref[] in
  let remember address value writer depth kind=
    let item={address;value;writer;depth;kind}in
    journal:=item::!journal;Hashtbl.replace latest address item in
  let put site depth address value=
    Pli80_host.State.write m address value;
    remember address value site depth "compatibility"in
  let save site depth sp value=
    require(Char.code(Bytes.get t.image site)=(if site=0x7c1e then 0xc5 else 0xf5))"save opcode identity";
    (* Retained F0 already belongs to the logical frame; only the discarded
       low byte of PUSH B belongs to compatibility. PSW saves use both bytes. *)
    if site<>0x7c1e then put site depth(Pli80_host.U16.wrap(sp-1))(value lsr 8);
    put site depth(Pli80_host.U16.wrap(sp-2))(value land 255)in
  let compatibility_event=function
    |R.Position_carrier{sp;position;depth}->save 0x7c1e depth sp (position lor(position lsl 8))
    |R.Dispatch_carrier{sp;mapped;depth}->
      (* SUI1 / SBB A produces FF with S1/Z0/AC0/P1/CY1 on equality,
         otherwise 00 with S0/Z1/AC1/P1/CY0. Bit1 is the fixed PSW bit. *)
      save 0x7c48 depth sp (if mapped=0x1e then 0xff87 else 0x0056)
    |R.Call{site;sp;depth}->
      require(List.mem_assoc site targets&&Char.code(Bytes.get t.image site)=0xcd
        &&word t.image(site+1)=List.assoc site targets)"unproven compatibility CALL";
      let value=0x2200+site+3 in
      put site depth(Pli80_host.U16.wrap(sp-1))(value lsr 8);
      put site depth(Pli80_host.U16.wrap(sp-2))(value land 255)in
  let result=R.run m ~entry:{R.position=state.c;hl=state.h lsl 8 lor state.l;de=state.d lsl 8 lor state.e;sp=state.sp}
    ~compatibility:compatibility_event ~observe:(fun w->remember w.R.address w.value w.writer w.depth "logical")in
  let q=result.tree.returned in
  let state={Runner.a=q.a;b=q.bc lsr 8;c=q.bc land 255;d=q.de lsr 8;e=q.de land 255;
    h=q.hl lsr 8;l=q.hl land 255;sp=Pli80_host.U16.wrap(state.sp+2);pc=call.resume;
    sign=q.flags.sign;zero=q.flags.zero;auxiliary_carry=q.flags.auxiliary_carry;parity=q.flags.parity;carry=q.flags.carry}in
  let final_writers=Hashtbl.fold(fun _ v acc->v::acc)latest[]|>List.sort(fun a b->compare a.address b.address)in
  (* Replay logical writes, then compatibility alone, can overwrite frame cells
     that later acquired logical owners. Supply only final compatibility cells
     to the unchanged generic Runner transition API. *)
  let compatibility_writes=List.filter_map(fun q->if q.kind="compatibility"then Some(q.address,q.value)else None)final_writers in
  {result;memory=Pli80_host.State.copy m;state;compatibility_writes;final_writers;journal=List.rev !journal}

let internal_call t site =
  let offset=site-0x2200 in
  require(offset>=0 && offset+3<=Bytes.length t.image && Char.code(Bytes.get t.image offset)=0xcd && word t.image(offset+1)=0x9e1b) "unproven internal CALL";
  {coordinate=Printf.sprintf "PLI1.OVL+%04X" offset;runtime_site=site;resume=site+3}
