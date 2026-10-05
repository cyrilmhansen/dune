[@@@warning "-4-40-41-42"]
module H=Pli80_host
let rejects f=match f()with exception Invalid_argument _->()|_->failwith"Unsupported state accepted"
let flags s (q:I8080.Alu.result8)=
 assert(s.Runner.sign=q.status.szp.sign && s.zero=q.status.szp.zero && s.parity=q.status.szp.parity
  &&s.auxiliary_carry=q.status.auxiliary_carry &&s.carry=q.carry)
let primitives ()=
 for i=0 to 127 do for byte=0 to 255 do
  let state=H.State.of_bytes(Bytes.make 65536 '\000')in
  H.State.write state 0x1e0c i;H.State.write state 0x1e0d 0x73;
  let p=H.Int_emitter.plan state ~input_byte:byte ~protected:[]in
  assert(p.index=i &&p.discarded_neighbor=0x73 &&p.destination=0x1d8c+i &&p.fresh_scratch=byte &&p.reloaded_index=i
    &&p.incremented_index=i+1&&p.flush=(i=127));
  assert(H.State.read state 0x20b0=byte&&H.State.read state(0x1d8c+i)=byte&&H.State.read state 0x1e0c=i+1);
  let writes=List.filter_map(function H.Int_emitter.Write w->Some(w.address,w.value)|_->None)p.effects in
  assert(writes=[0x20b0,byte;0x1d8c+i,byte;0x1e0c,i+1]@(if i=127 then[0x1e0c,0]else []));
  if i=127 then assert(match p.effects with [_;_;_;H.Int_emitter.Set_dma 0x1d8c;H.Int_emitter.Write w;H.Int_emitter.Sequential_write 0x1ca2]->w.address=0x1e0c &&w.value=0|_->false)
 done done;
 let m=H.State.of_bytes(Bytes.make 65536 '\000')in
 List.iter(fun i->H.State.write m 0x1e0c i;rejects(fun()->H.Int_emitter.plan m ~input_byte:0 ~protected:[]))[128;129;255];
 H.State.write m 0x1e0c 0;
 List.iter(fun a->rejects(fun()->H.Int_emitter.plan m ~input_byte:0 ~protected:[a]))[0x20b0;0x1e0c;0x1e0d;0x1d8c;0x1e0b;65536];
 rejects(fun()->H.Int_emitter.plan m ~input_byte:256 ~protected:[]);
 rejects(fun()->H.State.of_bytes Bytes.empty)
let origins ()=
 let map=Analysis.Execution_map.create()in
 let image:Cpm.Filesystem.key={drive=0;user=0;name="UNIT.COM"}in
 assert(Analysis.Execution_map.seed_image map ~image ~runtime_base:0x100(Bytes.of_string "AB")=Ok());
 assert(Analysis.Execution_map.origin_at map 0x100<>Analysis.Execution_map.Unknown);
 Analysis.Execution_map.invalidate_host_writes map[0x100,Char.code 'A'];
 assert(Analysis.Execution_map.origin_at map 0x100=Analysis.Execution_map.Unknown);
 assert(Analysis.Execution_map.origin_at map 0x101<>Analysis.Execution_map.Unknown);
 rejects(fun()->Analysis.Execution_map.invalidate_host_writes map[0x101,0;65536,0]);
 assert(Analysis.Execution_map.origin_at map 0x101<>Analysis.Execution_map.Unknown)
let transaction ()=
 let make_program boundary ~missing ~reverse ~invalid ~reject_final ~early_reset =
  let s=boundary.Runner.state in
  let call function_number address={s with a=0xaa;b=address lsr 8;c=function_number;d=address lsr 8;e=address land 255;h=0x12;l=0x34;pc=5}in
  let service c=Runner.Dispatch_bdos{call_state=c;expected_resume={c with a=0;b=0;h=0;l=0}}in
  let dma=service(call 26 0x3000)and record=service(call 21 0x2000)in
  let name=if missing then "MISSING INT"else "UNIT    INT"in
  let writes=List.init 36(fun i->Runner.Memory_write(0x2000+i,if i>0&&i<12 then Char.code name.[i-1]else 0))
    @List.init 128(fun i->Runner.Memory_write(0x3000+i,i))@[Runner.Memory_write(0x4000,128)]in
  {Runner.effects=writes@(if reverse then[record;Runner.Memory_write(0x4000,0);dma]
    else if early_reset then[Runner.Memory_write(0x4000,0);dma;record]
    else[dma;Runner.Memory_write(0x4000,0);record])@(if invalid then[Runner.Memory_write(65536,0)]else[]);
   next_state={s with pc=0};validate=(fun r->
    if reject_final then Error"explicit unsupported final scope"
    else if List.map(fun(s:Runner.host_service)->s.call_state.c)r.services<>[26;21]then Error"wrong service order"
    else if List.exists(fun(s:Runner.host_service)->Char.code(Bytes.get s.memory_before 0x4000)<>(if s.call_state.c=26 then 128 else 0))r.services then Error"reset order"
    else Ok());on_commit=ignore}in
 List.iter(fun(missing,reverse,invalid,reject_final,early_reset)->
  let filesystem=Cpm.Filesystem.create()in
  assert(Cpm.Filesystem.add_file filesystem ~name:"UNIT.INT" Bytes.empty=Ok());
  let before_fs=Cpm.Filesystem.copy filesystem and leaked=ref 0 and retained=ref None and guest_steps=ref 0 and guest_bdos=ref 0 in
  let intercept ~step_index:_ (b:Runner.instruction_boundary)=
   retained:=Some b;
   let before=b.copy_memory()in
   let program=make_program b ~missing ~reverse ~invalid ~reject_final ~early_reset in
   let preview=b.preview_host_program program in
   let success=not(missing||reverse||invalid||reject_final||early_reset)in
   assert((match preview with Ok _->true|Error _->false)=success);
   assert(b.copy_memory()=before &&Cpm.Filesystem.equal filesystem before_fs);
   let probe={Runner.effects=[];next_state=b.state;validate=(fun _->Ok());on_commit=ignore}in
   assert(match b.preview_host_program probe with Ok r->r.dma=0x80 &&r.memory=before&&Cpm.Filesystem.equal r.filesystem before_fs|_->false);
   Runner.Apply_host_program program in
  let result=Runner.run_bytes ~filesystem ~intercept ~output:ignore
    ~on_event:(function Runner.Step _->incr guest_steps|Runner.Bdos_call _->incr guest_bdos|_->()) ~on_bdos_event:(fun ~step_index:_ _->incr leaked)(Bytes.of_string"\x00")in
  if missing||reverse||invalid||reject_final||early_reset then(
   assert(match result with Error(Runner.Invalid_host_transition _)->true|_->false);
   assert(!leaked=0&&Cpm.Filesystem.equal filesystem before_fs);
   let b=Option.get !retained in assert(b.read_memory 0x4000=0 &&b.read_memory 0x2001=0);
   let probe={Runner.effects=[];next_state=b.state;validate=(fun _->Ok());on_commit=ignore}in
   assert(match b.preview_host_program probe with Ok r->r.dma=0x80&&Cpm.Filesystem.equal r.filesystem before_fs|_->false))
  else(
   assert(match result with Ok r->r.steps=0&&r.t_states=0&&r.host_transitions=1&&r.host_bdos_services=2&&r.termination=Runner.Warm_boot|_->false);
   assert(!leaked=1 && !guest_steps=0 && !guest_bdos=0);
   assert(match Cpm.Filesystem.get_file filesystem ~name:"UNIT.INT"()with Ok(Some b)->b=Bytes.init 128 Char.chr|_->false))
 )[false,false,false,false,false;true,false,false,false,false;false,true,false,false,false;false,false,true,false,false;false,false,false,true,false;false,false,false,false,true]
let bridge ()=match Sys.getenv_opt "RUNES_HOST_IMAGES"with None->()|Some dir->
 let read name=let c=open_in_bin(Filename.concat dir name)in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)in
 let com=read "PLI.COM"and pli1=read "PLI1.OVL"in
 let module B=Pli80.Int_emitter_bridge in let t=B.create ~pli_com:com ~pli1 in
 rejects(fun()->B.create ~pli_com:Bytes.empty ~pli1);
 let bad=Bytes.copy com in Bytes.set bad 0xef6 '\000';rejects(fun()->B.create ~pli_com:bad ~pli1);
 let memory=Bytes.make 65536 '\000'in Bytes.blit com 0 memory 0x100(Bytes.length com);Bytes.blit pli1 0 memory 0x2200(Bytes.length pli1);
 let image:Cpm.Filesystem.key={drive=0;user=0;name="PLI.COM"}in
 let origin offset=Analysis.Execution_map.Image_byte{image;offset}in
 let state:Runner.state_snapshot={a=0;b=0;c=0x5a;d=0x67;e=0x89;h=0x10;l=0x11;pc=0xff6;sp=0xf000;sign=false;zero=false;auxiliary_carry=false;parity=false;carry=false}in
 let callsite=0x10af in let resume=callsite+0x103 in
 Bytes.set memory 0xf000(Char.chr(resume land 255));Bytes.set memory 0xf001(Char.chr(resume lsr 8));
 let fetched=Bytes.sub com callsite 3 in let decoded=match I8080.Decode.decode fetched ~offset:0 with Ok d->d|_->assert false in
 let before={state with pc=callsite+0x100;sp=0xf002}in
 let step=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:before.pc ~pc_after:state.pc ~decoded ~fetched_bytes:fetched
  ~memory_accesses:[I8080.Step.Write{address=state.sp;value=resume land 255};I8080.Step.Write{address=state.sp+1;value=resume lsr 8}]~control_flow:(I8080.Step.Call{target=state.pc;taken=true})in
 let previous:Pli80.Native_dispatch.previous={origin=origin callsite;before;after=state;step}in
 let call=B.verify_call t previous ~entry:state in
 let noncall=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:before.pc ~pc_after:state.pc ~decoded ~fetched_bytes:fetched ~memory_accesses:[] ~control_flow:I8080.Step.Sequential in
 rejects(fun()->B.verify_call t {previous with step=noncall}~entry:state);
 rejects(fun()->B.verify_call t previous ~entry:{state with pc=0});
 rejects(fun()->B.verify_call t {previous with origin=Analysis.Execution_map.Unknown}~entry:state);
 rejects(fun()->B.verify_call t {previous with before={before with sp=0}}~entry:state);
 rejects(fun()->B.verify_call t {previous with origin=Analysis.Execution_map.Image_byte{image={image with name="PLI2.OVL"};offset=callsite}}~entry:state);
 for i=0 to 126 do for mask=0 to 31 do
  Bytes.set memory 0x1e0c(Char.chr i);Bytes.set memory 0x1e0d '\x73';
  let s={state with sign=mask land 16<>0;zero=mask land 8<>0;auxiliary_carry=mask land 4<>0;parity=mask land 2<>0;carry=mask land 1<>0}in
  let p=B.prepare t ~call ~origin:(origin 0xef6)~state:s ~memory in
  flags p.state(I8080.Alu.subtract ~borrow:false (i+1)0x80);
  assert(p.state.a=i+1&&p.state.b=0x1d&&p.state.c=0x8c&&p.state.d=0x67&&p.state.e=0x89&&p.state.sp=0xf002&&p.state.pc=resume);
  assert(p.compatibility_writes=[]&&p.logical_writes=[0x20b0,0x5a;0x1d8c+i,0x5a;0x1e0c,i+1])
 done done;
 Bytes.set memory 0x1e0c '\000';
 rejects(fun()->B.prepare t ~call ~origin:(origin 0)~state ~memory);
 rejects(fun()->B.prepare t ~call ~origin:(origin 0xef6)~state:{state with pc=0}~memory);
 rejects(fun()->B.prepare t ~call ~origin:(origin 0xef6)~state:{state with c=256}~memory);
 rejects(fun()->B.prepare t ~call ~origin:(origin 0xef6)~state ~memory:Bytes.empty);
 List.iter(fun address->let bad=Bytes.copy memory in Bytes.set bad address '\xff';rejects(fun()->B.prepare t ~call ~origin:(origin 0xef6)~state ~memory:bad))[0xf000;0xff6;0x3ee;0x428;0x1abb];
 let alias=Bytes.copy memory in Bytes.set alias 0x1d8c(Char.chr(resume land 255));Bytes.set alias 0x1d8d(Char.chr(resume lsr 8));
 rejects(fun()->B.prepare t ~call ~origin:(origin 0xef6)~state:{state with sp=0x1d8c}~memory:alias);
 Bytes.set memory 0x1e0c '\x7f';
 rejects(fun()->B.prepare t ~call ~origin:(origin 0xef6)~state ~memory);
 let guard=Bytes.copy memory in
 Bytes.set guard 0x2155 '\xfe';Bytes.set guard 0x2156 '\xfd';Bytes.set guard 0xfdfe '\xaa';
 Bytes.blit guard 5 guard 0x215c 3;
 let p=B.prepare t ~call ~origin:(origin 0xef6)~state ~memory:guard in
 assert(p.logical_writes=[0x20b0,0x5a;0x1e0b,0x5a;0x1e0c,128;0x2060,0x1d;0x205f,0x8c;0x1e0c,0;0x2066,0x1c;0x2065,0xa2]);
 let bad=Bytes.copy guard in Bytes.set bad 0xfdfe '\xab';rejects(fun()->B.prepare t ~call ~origin:(origin 0xef6)~state ~memory:bad)

let invocation_accounting ()=
 let state:Runner.state_snapshot={a=0;b=0;c=0;d=0;e=0;h=0;l=0;sp=65534;pc=0xff6;sign=false;zero=false;auxiliary_carry=false;parity=false;carry=false}in
 let input bytes:Pli80.Experiment.input={pli_com=bytes;pli0_ovl=Bytes.empty;pli1_ovl=Bytes.empty;pli2_ovl=Bytes.empty;source_name="UNIT.PLI";source_bytes=Bytes.empty;module_name="UNIT";command_tail=Bytes.empty;max_steps=10}in
 let controller oracles=Pli80.Native_dispatch.create ~image:"PLI.COM" ~entry_pc:0xff6 ~end_pc:0x102d ~oracles ~records:[] ~prepare:(fun _ _ _->failwith"Must reject count before preparation")in
 let fails f=match f()with exception Failure _->()|_->failwith"Failed-open expected invocation accounting"in
 fails(fun()->Pli80.Native_dispatch.run(input(Bytes.of_string"\xc3\xf6\x0f"))[controller[]]);
 let oracle:Pli80.Native_dispatch.oracle={input=state;output=state;entry_memory=Bytes.empty;post_memory=Bytes.empty;logical_digest=""}in
 fails(fun()->Pli80.Native_dispatch.run(input(Bytes.of_string"\xc3\x00\x00"))[controller[oracle]])
let ()=primitives();origins();transaction();bridge();invocation_accounting();print_endline "32768 emitter plans,4064 CPI flag cases,real BDOS atomicity/service-order and boundary negatives passed"
