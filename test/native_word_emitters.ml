[@@@warning "-4-40-41-42"]
module H=Pli80_host
module B=Pli80.Word_emitter_bridge
let rejects f=match f()with exception Invalid_argument _->()|_->failwith"Unsupported state accepted"
let fails f=match f()with exception Failure _->()|_->failwith"Failed-open proof"
let primitives ()=
 let m=H.State.of_bytes(Bytes.make 65536 '\000')in let put=H.State.write m in
 for position=0 to 255 do for index=0 to 255 do
  put(0xaa1f+position)index;put 0xae39 0x63;
  let address=0xab49+2*index in put address position;put(address+1)index;
  let writes=ref[]in let q=H.Mapped_word.lookup m ~position ~protected:[] ~write:(fun w->writes:=w::!writes)in
  assert(q.position=position&&q.index=index&&q.offset=index*2&&q.low_address=address&&q.high_address=address+1
   &&q.word=position+256*index&&q.discarded_ae39=0x63);
  assert(List.map(fun(w:H.Mapped_word.write)->w.address,w.value)!writes=[0xae38,position])
 done done;
 put 0xaa1f 0;
 for word=0 to 65535 do
  put 0xab49(word land 255);put 0xab4a(word lsr 8);
  assert((H.Mapped_word.lookup m ~position:0 ~protected:[] ~write:ignore).word=word)
 done;
 put 0xae4f 0;put 0xae50 0x76;put 0xae39 0x54;put 0xab49 0x12;put 0xab4a 0x34;
 let emit m (s:H.Word_emitter.selection)=H.Int_emitter.plan m ~input_byte:s.emitted_byte ~protected:[]in
 let s,p=H.Word_emitter.low m ~protected:[] ~emit in
 assert(s.paired_word=0x7600&&s.neighbor=0x76&&p.input_byte=0x12);
 assert(List.map(fun(w:H.Mapped_word.write)->w.address,w.value)s.writes=[0xae38,0;0xae52,0x12;0xae53,0x34]);
 put 0xae52 0x99;put 0xae53 0x5a;
 let s,p=H.Word_emitter.high m ~protected:[] ~emit in
 assert(s.selected_word=0x5a99&&s.neighbor=0x99&&s.emitted_byte=0x5a&&p.input_byte=0x5a);
 assert(H.State.read m 0x1d8d=0x5a);
 put 0xab49 0xe1;put 0xab4a 0xa2;
 assert((H.Mapped_word.lookup m ~position:0 ~protected:[] ~write:ignore).word=0xa2e1);
 List.iter(fun a->rejects(fun()->H.Mapped_word.lookup m ~position:0 ~protected:[a]~write:ignore))[0xae38;0xae39;0xaa1f;0xab49;0xab4a;65536];
 rejects(fun()->H.Mapped_word.lookup m ~position:256 ~protected:[]~write:ignore);
 rejects(fun()->H.State.of_bytes Bytes.empty);
 List.iter(fun a->rejects(fun()->H.Word_emitter.low m ~protected:[a] ~emit))[0xae4f;0xae50;0xae52;0xae53];
 List.iter(fun a->rejects(fun()->H.Word_emitter.high m ~protected:[a] ~emit))[0xae52;0xae53];
 put 0x1e0c 128;rejects(fun()->H.Word_emitter.high m ~protected:[] ~emit)
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let origin offset=let image:Cpm.Filesystem.key={drive=0;user=0;name="PLI1.OVL"}in Analysis.Execution_map.Image_byte{image;offset}
let state pc:Runner.state_snapshot={a=0x83;b=0x91;c=3;d=0x62;e=0x47;h=0x71;l=0x5a;sp=0xf000;pc;
 sign=true;zero=false;auxiliary_carry=true;parity=false;carry=true}
let bridge com pli1=
 let t=B.create ~pli_com:com ~pli1 in
 rejects(fun()->B.create ~pli_com:Bytes.empty ~pli1);
 let changed=Bytes.copy pli1 in Bytes.set changed 0x7a79 '\000';rejects(fun()->B.create ~pli_com:com ~pli1:changed);
 List.iter(fun(op,site)->
  let a,_=B.extent op in let entry=state(a+0x2200)in
  let ram=Bytes.make 65536 '\000'in Bytes.blit com 0 ram 0x100(Bytes.length com);Bytes.blit pli1 0 ram 0x2200(Bytes.length pli1);
  let resume=site+0x2203 in Bytes.set ram entry.sp(Char.chr(resume land 255));Bytes.set ram(entry.sp+1)(Char.chr(resume lsr 8));
  let fetched=Bytes.sub pli1 site 3 in let decoded=match I8080.Decode.decode fetched ~offset:0 with Ok d->d|_->assert false in
  let before={entry with pc=site+0x2200;sp=entry.sp+2}in
  let step=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:before.pc ~pc_after:entry.pc ~decoded ~fetched_bytes:fetched
   ~memory_accesses:[I8080.Step.Write{address=entry.sp;value=resume land 255};I8080.Step.Write{address=entry.sp+1;value=resume lsr 8}]
   ~control_flow:(I8080.Step.Call{target=entry.pc;taken=true})in
  let previous:Pli80.Native_dispatch.previous={origin=origin site;before;after=entry;step}in
  let call=B.verify_call t previous ~entry in
  rejects(fun()->B.verify_call t {previous with origin=origin(site+1)}~entry);
  rejects(fun()->B.verify_call t {previous with origin=Analysis.Execution_map.Unknown}~entry);
  rejects(fun()->B.verify_call t {previous with origin=(let image:Cpm.Filesystem.key={drive=0;user=0;name="PLI2.OVL"}in Analysis.Execution_map.Image_byte{image;offset=site})}~entry);
  let noncall=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:before.pc ~pc_after:entry.pc ~decoded ~fetched_bytes:fetched ~memory_accesses:[]~control_flow:I8080.Step.Sequential in
  rejects(fun()->B.verify_call t {previous with step=noncall}~entry);
  rejects(fun()->B.prepare t ~call ~origin:(origin a)~state:{entry with pc=0}~memory:ram);
  rejects(fun()->B.prepare t ~call ~origin:(origin(a+1))~state:entry ~memory:ram);
  rejects(fun()->B.prepare t ~call:{call with resume=0}~origin:(origin a)~state:entry ~memory:ram);
  rejects(fun()->B.prepare t ~call ~origin:(origin a)~state:{entry with c=256}~memory:ram);
  rejects(fun()->B.prepare t ~call ~origin:(origin a)~state:entry ~memory:Bytes.empty);
  List.iter(fun address->let bad=Bytes.copy ram in Bytes.set bad address '\xff';rejects(fun()->B.prepare t ~call ~origin:(origin a)~state:entry ~memory:bad))[0xf000;0x9c79;0xa046;0xa056];
  let overlaps=if op=B.Mapped_word then [0xae38;0xab49]else[0xae52;0x1d8c]in
  List.iter(fun sp->let bad=Bytes.copy ram in Bytes.set bad sp(Char.chr(resume land 255));Bytes.set bad(sp+1)(Char.chr(resume lsr 8));
   rejects(fun()->B.prepare t ~call ~origin:(origin a)~state:{entry with sp}~memory:bad))overlaps;
  if op=B.Mapped_word then for j=0 to 255 do for mask=0 to 31 do
   Bytes.set ram(0xaa1f+entry.c)(Char.chr j);Bytes.set ram(0xab49+2*j)'\x53';Bytes.set ram(0xab4a+2*j)'\x8a';
   let s={entry with sign=mask land 16<>0;zero=mask land 8<>0;auxiliary_carry=mask land 4<>0;parity=mask land 2<>0;carry=mask land 1<>0}in
   let p=B.prepare t ~call ~origin:(origin a)~state:s ~memory:ram in
   assert(p.state={s with b=0;c=j;d=(0xab4a+2*j)lsr 8;e=(0xab4a+2*j)land 255;h=0x8a;l=0x53;carry=false;sp=0xf002;pc=resume});
   assert(p.compatibility_writes=[])
  done done else(
   Bytes.set ram 0x1e0c '\x80';rejects(fun()->B.prepare t ~call ~origin:(origin a)~state:entry ~memory:ram);
   Bytes.set ram 0x1e0c '\000';let bad=Bytes.copy ram in Bytes.set bad 0xff6 '\000';
   rejects(fun()->B.prepare t ~call ~origin:(origin a)~state:entry ~memory:bad);
   List.iter(fun address->let bad=Bytes.copy ram in Bytes.set bad address '\xff';
    rejects(fun()->B.prepare t ~call ~origin:(origin a)~state:entry ~memory:bad))[0x3ee;0x428;0x1abb])
 )[B.Mapped_word,0x3293;B.Low,0x7de6;B.High,0x7df1]
(* Synthetic successful/error flushes use real historical bytes, CPU CALL/RET and
   live CP/M services. They establish compatibility/transaction behavior only. *)
let wrapper_flush com pli1 op ~native ~missing ~reorder ~duplicate =
 let t=B.create ~pli_com:com ~pli1 in
 let filesystem=Cpm.Filesystem.create()in
 if not missing then assert(Cpm.Filesystem.add_file filesystem ~name:"UNIT.INT" Bytes.empty=Ok());
 let retained=ref None and before=ref None and oracle=ref None and records=ref[]and callbacks=ref 0 and previous=ref None and initialized=ref false in
 let a,_=B.extent op and site=if op=B.Low then 0x7de6 else 0x7df1 in
 let resume=site+0x2203 in
 let on_step_state_pair ~step_index:_ ~before ~after step=
  previous:=Some{Pli80.Native_dispatch.origin=origin site;before;after;step}in
 let intercept ~step_index:_ (b:Runner.instruction_boundary)=
  if not !initialized then(
   initialized:=true;
   let ram=b.copy_memory()in Bytes.blit com 0 ram 0x100(Bytes.length com);Bytes.blit pli1 0 ram 0x2200(Bytes.length pli1);
   let put a v=Bytes.set ram a(Char.chr v)in
   put 0xae4f 3;put 0xae50 0x76;put(0xaa1f+3)4;put 0xab51 0x5c;put 0xab52 0x9d;
   put 0xae52 0x5c;put 0xae53 0x9d;put 0xae39 0x37;put 0x1e0c 127;put 0x1e0d 0x63;
   for i=0 to 127 do put(0x1d8c+i)i done;
   for i=0 to 35 do put(0x1ca2+i)(if i>0&&i<12 then Char.code "UNIT    INT".[i-1]else 0)done;
   put 0x2155 0xfe;put 0x2156 0xfd;put 0xfdfe 0xaa;Bytes.blit ram 5 ram 0x215c 3;
   Runner.Apply_host_transition{memory_writes=List.init 65536(fun i->i,Char.code(Bytes.get ram i));next_state={(state(site+0x2200))with sp=0xf002}})
  else if b.state.pc=a+0x2200 then(
   retained:=Some b;before:=Some(b.copy_memory(),b.copy_filesystem(),b.dma);
   let call=B.verify_call t(Option.get !previous)~entry:b.state in
   let p=B.prepare t ~call ~origin:(origin a)~state:b.state ~memory:(b.copy_memory())in
   let effects=if reorder then
    (* Fail validation after a wrong chronology even if services themselves succeed. *)
    List.rev p.program.effects
    else if duplicate then p.program.effects@List.filter(function Runner.Dispatch_bdos _->true|_->false)p.program.effects
    else p.program.effects in
   let program={p.program with effects}in
   let preview=b.preview_host_program program in
   if missing||reorder||duplicate then assert(match preview with Error _->true|_->false)
   else oracle:=Some(match preview with Ok r->r,p.state|Error e->failwith e);
   if native then Runner.Apply_host_program program else Runner.Continue_guest_execution)
  else if b.state.pc=resume then(
   let r,s=Option.get !oracle in assert(b.state=s&&b.copy_memory()=r.memory&&b.dma=r.dma&&Cpm.Filesystem.equal(b.copy_filesystem())r.filesystem);
   let writes=List.filter_map(function Cpm.Bdos.Write_record q->Some(q.dma,q.logical_record,q.data)|_->None)!records in
   assert(List.length writes=1);let dma,n,data=List.hd writes in
   assert(dma=0x1d8c&&n=0&&Bytes.get data 127=Char.chr(if op=B.Low then 0x5c else 0x9d));
   assert(b.read_memory 0x1e0c=0&&b.read_memory 0x1d8c=0&&b.read_memory 0x1e0b=(if op=B.Low then 0x5c else 0x9d));
   Runner.Apply_host_transition{memory_writes=[];next_state={b.state with pc=0}})
  else Runner.Continue_guest_execution in
 let result=Runner.run_bytes ~filesystem ~intercept ~on_step_state_pair ~output:ignore
  ~on_bdos_event:(fun ~step_index:_ e->incr callbacks;records:=e::!records)(Bytes.of_string"\x00")in
 if missing||reorder||duplicate then(
  assert(native);assert(match result with Error(Runner.Invalid_host_transition _)->true|_->false);
  let b=Option.get !retained and ram,files,dma=Option.get !before in
  assert(b.copy_memory()=ram&&b.dma=dma&&Cpm.Filesystem.equal filesystem files&& !callbacks=0))
 else assert(match result with Ok r->r.termination=Runner.Warm_boot&&r.host_bdos_services=(if native then 2 else 0)|_->false)
let dispatch_failures ()=
 let state:Runner.state_snapshot={a=0;b=0;c=0;d=0;e=0;h=0;l=0;sp=65534;pc=0x100;sign=false;zero=false;auxiliary_carry=false;parity=false;carry=false}in
 let input:Pli80.Experiment.input={pli_com=Bytes.of_string"\xc3\x00\x00";pli0_ovl=Bytes.empty;pli1_ovl=Bytes.empty;pli2_ovl=Bytes.empty;source_name="UNIT.PLI";source_bytes=Bytes.empty;module_name="UNIT";command_tail=Bytes.empty;max_steps=10}in
 let make pc oracles=Pli80.Native_dispatch.create ~image:"PLI.COM" ~entry_pc:pc ~end_pc:(pc+1)~oracles ~records:[] ~prepare:(fun _ _ _->failwith"Should not prepare")in
 fails(fun()->Pli80.Native_dispatch.run input[make 0x100 []]);
 let oracle:Pli80.Native_dispatch.oracle={input=state;output=state;entry_memory=Bytes.empty;post_memory=Bytes.empty;logical_digest=""}in
 fails(fun()->Pli80.Native_dispatch.run input[make 0x200 [oracle]]);
 (* A different image at the same runtime PC remains real guest execution. *)
 let collision=Pli80.Native_dispatch.create ~image:"PLI1.OVL" ~entry_pc:0x100 ~end_pc:0x101 ~oracles:[] ~records:[] ~prepare:(fun _ _ _->failwith"Wrong-image interception")in
 match Pli80.Native_dispatch.run input[collision]with
 |Ok([0],r)->assert(r.run.host_transitions=0 && r.run.steps>0)
 |_->failwith"Canonical image collision was not isolated"
let ()=primitives();dispatch_failures();
 (match Sys.getenv_opt"RUNES_HOST_IMAGES"with None->()|Some dir->
  let com=read(Filename.concat dir"PLI.COM")and pli1=read(Filename.concat dir"PLI1.OVL")in
  bridge com pli1;
  List.iter(fun op->List.iter(fun native->wrapper_flush com pli1 op ~native ~missing:false ~reorder:false ~duplicate:false)[false;true];
   wrapper_flush com pli1 op ~native:true ~missing:true ~reorder:false ~duplicate:false;
   wrapper_flush com pli1 op ~native:true ~missing:false ~reorder:true ~duplicate:false;
   wrapper_flush com pli1 op ~native:true ~missing:false ~reorder:false ~duplicate:true)[B.Low;B.High]);
 print_endline"65536 position/index lookups,65536 word values,8192 ABI flag cases,fresh cache dependencies and actual CPU/native flush/atomicity cases passed"
