[@@@warning "-4-40-41-42"]
module H=Pli80_host
module M=H.Mapped_publication
let rejects f=match f()with exception Invalid_argument _->()|_->failwith"Unsupported state accepted"
let fails f=match f()with exception Failure _->()|_->failwith"Failed-open proof"
let primitives ()=
 let memory=H.State.of_bytes(Bytes.make 65536 '\000')in let put=H.State.write memory in
 for index=0 to 255 do for value=0 to 255 do
  put 0xaa1f index;put(0xaab4+index)(255-value);
  let writes=ref[]in
  let q=M.publish memory ~position:0 ~value ~protected:[] ~write:(fun w->writes:=w::!writes)in
  assert(q.index=index&&q.value=value&&q.old_value=255-value&&q.discarded_high=value);
  assert(List.rev_map(fun(w:H.Mapped_lookup.write)->w.address,w.value)!writes=[0xae3d,value;0xae3c,0;0xaab4+index,value]);
  let r=H.Mapped_lookup.mapped_byte memory ~position:0 ~protected:[] ~write:ignore in
  assert(r.index=index&&r.byte=value)
 done done;
 for position=0 to 255 do
  let j=if position=149 then 1 else 0 in
  put(0xaa1f+position)j;put 0xae33 0x53;put 0xae34 0x71;put 0xae4b 0xa6;
  let writes=ref[]in
  let r=M.recycle memory ~position ~protected:[] ~write:(fun w->writes:=w::!writes)in
  assert(r.old_word=0x7153&&r.initial_carrier=0xa600+position&&r.fresh_carrier=r.initial_carrier&&r.fresh_index=j);
  assert(List.rev_map(fun(w:H.Mapped_lookup.write)->w.address,w.value)!writes=[0xae4a,position;0xae3d,0x53;0xae3c,position;0xaab4+j,0x53;0xae33,j]);
  let q=H.Mapped_lookup.mapped_byte memory ~position ~protected:[] ~write:ignore in assert(q.byte=0x53)
 done;
 (* Chronological read probe: observer explicitly changes the distinct map cell
    after child publication. Not a naturally differing static compiler state. *)
 put 0xaa1f 2;put 0xae33 0x42;
 let r=M.recycle memory ~position:0 ~protected:[] ~write:(fun(w:H.Mapped_lookup.write)->
   if w.phase="mapped_publication"then put 0xaa1f 3)in
 assert(r.child.index=2&&r.child.address=0xaab6&&r.fresh_index=3&&H.State.read memory 0xae33=3);
 put 0xaa1f 2;put 0xaa20 4;
 let r=M.recycle memory ~position:0 ~protected:[] ~write:(fun(w:H.Mapped_lookup.write)->
   if w.phase="mapped_publication"then put 0xae4a 1)in
 assert(r.child.position=0&&r.fresh_carrier land 255=1&&r.fresh_index=4);
 (* A static way to change the second read would alias the accessed map byte;
    that lies outside the declared contract and must reject. *)
 put 0xaab4 0;
 rejects(fun()->M.publish memory ~position:149 ~value:1 ~protected:[] ~write:ignore);
 rejects(fun()->M.recycle memory ~position:149 ~protected:[] ~write:ignore);
 rejects(fun()->H.State.of_bytes Bytes.empty);
 rejects(fun()->M.publish memory ~position:256 ~value:0 ~protected:[] ~write:ignore);
 rejects(fun()->M.publish memory ~position:0 ~value:(-1) ~protected:[] ~write:ignore);
 rejects(fun()->M.publish memory ~position:0 ~value:0 ~protected:[0xae3d] ~write:ignore);
 rejects(fun()->M.recycle memory ~position:0 ~protected:[0xae34] ~write:ignore);
 rejects(fun()->M.recycle memory ~position:0 ~protected:[0xae4a] ~write:ignore);
 put 0xaa1f 0;
 rejects(fun()->M.publish memory ~position:0 ~value:0 ~protected:[0xaab4] ~write:ignore);
 rejects(fun()->M.publish memory ~position:0 ~value:0 ~protected:[0xaa1f] ~write:ignore);
 rejects(fun()->M.recycle memory ~position:0 ~protected:[65536] ~write:ignore);
 rejects(fun()->H.State.read memory 65536);
 rejects(fun()->H.State.write memory (-1) 0)
let bridge ()=match Sys.getenv_opt"RUNES_HOST_IMAGES"with None->()|Some dir->
 let channel=open_in_bin(Filename.concat dir "PLI1.OVL")in
 let raw=Fun.protect ~finally:(fun()->close_in channel)(fun()->let b=Bytes.create(in_channel_length channel)in really_input channel b 0(Bytes.length b);b)in
 let module B=Pli80.Mapped_publication_bridge in let t=B.create ~pli1:raw in
 let bad=Bytes.copy raw in Bytes.set bad 0x7ad5 '\x00';rejects(fun()->B.create ~pli1:bad);
 rejects(fun()->B.create ~pli1:Bytes.empty);
 let image:Cpm.Filesystem.key={drive=0;user=0;name="PLI1.OVL"}in
 let origin offset=Analysis.Execution_map.Image_byte{image;offset}in
 List.iter(fun(entry_offset,site)->
  let memory=Bytes.make 65536 '\000'in Bytes.blit raw 0 memory 0x2200(Bytes.length raw);
  let resume=site+0x2203 and pc=entry_offset+0x2200 in
  Bytes.set memory 0xf000(Char.chr(resume land 255));Bytes.set memory 0xf001(Char.chr(resume lsr 8));
  let fetched=Bytes.sub raw site 3 in let decoded=match I8080.Decode.decode fetched ~offset:0 with Ok d->d|_->assert false in
  let entry:Runner.state_snapshot={a=0x41;b=0x32;c=0;d=0x12;e=0x34;h=0x87;l=0x65;sp=0xf000;pc;
    sign=false;zero=false;auxiliary_carry=false;parity=false;carry=false}in
  let before={entry with pc=site+0x2200;sp=0xf002}in
  let step=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:before.pc ~pc_after:pc ~decoded ~fetched_bytes:fetched
    ~memory_accesses:[I8080.Step.Write{address=0xf000;value=resume land 255};I8080.Step.Write{address=0xf001;value=resume lsr 8}]
    ~control_flow:(I8080.Step.Call{target=pc;taken=true})in
  let noncall=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:before.pc ~pc_after:pc ~decoded ~fetched_bytes:fetched ~memory_accesses:[] ~control_flow:I8080.Step.Sequential in
  rejects(fun()->B.verify_call t ~origin:(origin site)~before ~after:entry noncall ~entry);
  rejects(fun()->B.verify_call t ~origin:Analysis.Execution_map.Unknown ~before ~after:entry step ~entry);
  let other=Analysis.Execution_map.Image_byte{image={image with name="PLI2.OVL"};offset=site}in
  rejects(fun()->B.verify_call t ~origin:other ~before ~after:entry step ~entry);
  rejects(fun()->B.verify_call t ~origin:(origin(site+1))~before ~after:entry step ~entry);
  let call=B.verify_call t ~origin:(origin site)~before ~after:entry step ~entry in
  for flags=0 to 31 do
   let state={entry with sign=flags land 16<>0;zero=flags land 8<>0;auxiliary_carry=flags land 4<>0;parity=flags land 2<>0;carry=flags land 1<>0}in
   let p=B.prepare t ~call ~origin:(origin entry_offset)~state ~memory in
   assert(p.state.sign=state.sign&&p.state.zero=state.zero&&p.state.auxiliary_carry=state.auxiliary_carry&&p.state.parity=state.parity&&not p.state.carry);
   assert(p.state.sp=0xf002&&p.state.pc=resume);
   if entry_offset=0x7ad5 then assert(p.compatibility_writes=[]&&p.state.a=0x34&&p.state.d=0x12&&p.state.e=0x34)
   else assert(p.compatibility_writes=[0xeffe,0xb1;0xefff,0x9d]&&p.state.b=0xaa&&p.state.c=0x1f)
  done;
  rejects(fun()->B.prepare t ~call ~origin:(origin(entry_offset+1))~state:entry ~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with pc=0}~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with c=256}~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:entry ~memory:Bytes.empty);
  List.iter(fun address->let bad=Bytes.copy memory in Bytes.set bad address '\xff';
    rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:entry ~memory:bad))[0xf000;0x9cd5;0x9dae];
  let bad=Bytes.copy memory in Bytes.set bad 0xae3c(Char.chr(resume land 255));Bytes.set bad 0xae3d(Char.chr(resume lsr 8));
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with sp=0xae3c}~memory:bad)
 ) [0x7ad5,0x7bae;0x7ba2,0x7e35]
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
let ()=primitives();bridge();dispatch_failures();print_endline"65536 mapped publications,256 shared-memory recycle cases,independent-read probe and fail-closed ABI/alias/count proofs passed"
