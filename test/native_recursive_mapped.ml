[@@@warning "-4-40-41-42"]
module H=Pli80_host
module R=H.Recursive_mapped
let rejects f=match f()with exception Invalid_argument _->()|_->failwith"Unsupported state accepted"
let fails f=match f()with exception Failure _->()|_->failwith"Proof failed open"
let memory ()=H.State.of_bytes(Bytes.make 65536 '\000')
let entry:R.inherited={position=3;hl=0x1234;de=0x5678;sp=0xf000}
let run m e=R.run m ~entry:e ~compatibility:ignore ~observe:ignore
let map m p j byte=H.State.write m(0xaa1f+p)j;H.State.write m(0xaab4+j)byte
let auxiliary ()=
 let m=memory()in
 for p=0 to 255 do
  H.State.write m(0xaa1f+p)0;H.State.write m 0xad08 93;H.State.write m 0xae3b 71;
  let writes=ref[]in
  let q=H.Auxiliary.read m ~position:p ~protected:[] ~write:(fun w->writes:=w::!writes)in
  assert(q.position=p&&q.index=0&&q.address=0xad08&&q.value=93&&q.discarded_high=71);
  assert(List.map(fun(w:H.Mapped_lookup.write)->w.address,w.value)!writes=[0xae3a,p])
 done;
 for j=0 to 255 do for v=0 to 255 do
  H.State.write m 0xaa1f j;
  let writes=ref[]in
  let q=H.Auxiliary.publish m ~position:0 ~value:v ~protected:[] ~write:(fun w->writes:=w::!writes)in
  assert(q.index=j&&q.address=0xad08+j&&q.value=v&&q.discarded_high=v);
  assert(List.rev_map(fun(w:H.Mapped_lookup.write)->w.address,w.value)!writes=[0xae44,v;0xae43,0;0xad08+j,v])
 done done;
 rejects(fun()->H.Auxiliary.read m ~position:256 ~protected:[] ~write:ignore);
 rejects(fun()->H.Auxiliary.publish m ~position:0 ~value:256 ~protected:[] ~write:ignore);
 rejects(fun()->H.Auxiliary.read m ~position:0 ~protected:[0xae3a] ~write:ignore);
 rejects(fun()->H.Auxiliary.publish m ~position:0 ~value:1 ~protected:[0xad08+H.State.read m 0xaa1f] ~write:ignore)
let operation ()=
 let m=memory()in map m 3 3 5;H.State.write m 0xad0b 77;
 let q=run m entry in
 assert(q.tree.initial_frame=[3;0x34;0x12;0x34;0x12]);
 assert(q.tree.final_frame=[3;0;0x12;5;77]);
 assert(q.tree.returned.a=77&&q.tree.returned.bc=5&&q.tree.returned.de=0x5678&&q.tree.returned.hl=0x4d05);
 assert(q.tree.returned.flags.zero&&q.tree.returned.flags.auxiliary_carry);
 (* Fallback is independently defined by exact !=0A dispatch and complete
    getter. No value-specific snapshot list determines this behavior. *)
 for predecessor=0 to 255 do if predecessor<>10 then (
  let m=memory()in map m 3 3 23;map m 2 2 predecessor;H.State.write m 0xad0b 91;
  let q=run m entry in
  assert(q.tree.path="mapped17_fallback"&&q.tree.children=[]&&q.tree.returned.a=91);
  assert(q.tree.final_frame=[3;0x34;0x12;23;0x12]);
  assert(q.tree.returned.de=0x5678&&q.tree.returned.hl=0x1217);
  assert(not(List.exists(function R.Auxiliary_write _->true|_->false)q.tree.helpers)))done;
 let special first second=
  let m=memory()in map m 3 3 30;map m 2 2 5;map m 1 1 5;
  H.State.write m 0xad0a first;H.State.write m 0xad09 second;m in
 let q=run(special 1 15)entry in
 assert(List.map(fun(n:R.node)->n.entry.position)q.tree.children=[2;1]);
 assert(List.map(fun(n:R.node)->n.returned.a)q.tree.children=[1;15]);
 assert(q.tree.returned.a=15&&List.nth q.tree.final_frame 2=15);
 let updates=List.filter(fun(w:R.write)->w.address=q.tree.frame+2)q.writes in
 assert(List.map(fun(w:R.write)->w.value)updates=[0x12;1;15;16;15]);
 rejects(fun()->run(special 15 1)entry);
 rejects(fun()->run(special 1 2)entry);
 rejects(fun()->run(special 1 255)entry); (* wraps to00 before <=0F guard *)
 let m=memory()in map m 3 3 33;rejects(fun()->run m entry);
 (* Unexpected recursive mapped21 rejects inside private state. *)
 let m=memory()in map m 3 3 5;map m 2 2 33;H.State.write m 0x1b50 1;
 rejects(fun()->run m entry);
 rejects(fun()->run(memory()){entry with position=256});
 rejects(fun()->run(memory()){entry with sp=0xae40});
 rejects(fun()->H.State.of_bytes Bytes.empty)
let flags ()=
 for a=0 to 255 do for b=0 to 255 do
  let q=R.comparison a b in
  let historical=I8080.Alu.subtract ~borrow:false a b in
  assert(q.sign=historical.status.szp.sign&&q.zero=historical.status.szp.zero&&q.parity=historical.status.szp.parity
    &&q.auxiliary_carry=historical.status.auxiliary_carry&&q.carry=historical.carry)
 done done
let bridge ()=match Sys.getenv_opt"RUNES_HOST_IMAGES"with None->()|Some dir->
 let read name=let c=open_in_bin(Filename.concat dir name)in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)in
 let resident=read"PLI.COM"and raw=read"PLI1.OVL"in
 let module B=Pli80.Recursive_mapped_bridge in
 let t=B.create ~pli_com:resident ~pli1:raw in
 rejects(fun()->B.create ~pli_com:resident ~pli1:Bytes.empty);
 let memory=Bytes.make 65536 '\000'in Bytes.blit resident 0 memory 0x100(Bytes.length resident);Bytes.blit raw 0 memory 0x2200(Bytes.length raw);
 let put a v=Bytes.set memory a(Char.chr v)in put 0xaa22 3;put 0xaab7 5;put 0x1b50 0;put 0xad0b 77;
 let image:Cpm.Filesystem.key={drive=0;user=0;name="PLI1.OVL"}in
 let origin offset=Analysis.Execution_map.Image_byte{image;offset}in
 let state:Runner.state_snapshot={a=0;b=0;c=3;d=0x56;e=0x78;h=0x12;l=0x34;sp=0xf000;pc=0x9e1b;
  sign=false;zero=false;auxiliary_carry=false;parity=false;carry=false}in
 let before={state with pc=0x9f9d;sp=0xf002}in put 0xf000 0xa0;put 0xf001 0x9f;
 let fetched=Bytes.sub raw 0x7d9d 3 in
 let decoded=match I8080.Decode.decode fetched ~offset:0 with Ok d->d|_->assert false in
 let step control writes=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:before.pc ~pc_after:state.pc ~decoded ~fetched_bytes:fetched ~memory_accesses:writes ~control_flow:control in
 let actual=step(I8080.Step.Call{target=state.pc;taken=true})[I8080.Step.Write{address=state.sp;value=0xa0};I8080.Step.Write{address=state.sp+1;value=0x9f}]in
 rejects(fun()->B.verify_call t ~origin:(origin 0x7d9d) ~before ~after:state(step I8080.Step.Sequential[]) ~entry:state);
 rejects(fun()->B.verify_call t ~origin:Analysis.Execution_map.Unknown ~before ~after:state actual ~entry:state);
 rejects(fun()->B.verify_call t ~origin:(origin 0x7d9d) ~before:{before with sp=0xf003} ~after:state actual ~entry:state);
 rejects(fun()->B.verify_call t ~origin:(origin 0x7d9d) ~before ~after:state(step(I8080.Step.Call{target=state.pc;taken=true})[]) ~entry:state);
 let call=B.verify_call t ~origin:(origin 0x7d9d) ~before ~after:state actual ~entry:state in
 let p=B.prepare t ~call ~origin:(origin 0x7c1b) ~state ~memory in
 assert(p.state.pc=0x9fa0&&p.state.sp=0xf002&&p.state.a=77&&p.state.h=77&&p.state.l=5);
 assert(Char.code(Bytes.get memory 0xae36)<>3); (* private cloned state *)
 rejects(fun()->B.prepare t ~call ~origin:(origin 0x7c1c) ~state ~memory);
 rejects(fun()->B.prepare t ~call ~origin:(origin 0x7c1b) ~state:{state with pc=0} ~memory);
 rejects(fun()->B.prepare t ~call ~origin:(origin 0x7c1b) ~state ~memory:Bytes.empty);
 rejects(fun()->B.prepare t ~call ~origin:(origin 0x7c1b) ~state:{state with sp=65536} ~memory);
 let bad=Bytes.copy memory in Bytes.set bad 0xae43 '\xa0';Bytes.set bad 0xae44 '\x9f';
 rejects(fun()->B.prepare t ~call ~origin:(origin 0x7c1b) ~state:{state with sp=0xae43} ~memory:bad);
 let bad=Bytes.copy memory in Bytes.set bad 0xf000 '\000';rejects(fun()->B.prepare t ~call ~origin:(origin 0x7c1b) ~state ~memory:bad);
 let bad=Bytes.copy memory in Bytes.set bad 0x9c4d '\000';rejects(fun()->B.prepare t ~call ~origin:(origin 0x7c1b) ~state ~memory:bad);
 let bad=Bytes.copy memory in Bytes.set bad 0xaab7 '\x21';rejects(fun()->B.prepare t ~call ~origin:(origin 0x7c1b) ~state ~memory:bad)
let dispatcher_failures ()=
 let input:Pli80.Experiment.input={pli_com=Bytes.of_string"\xc3\x00\x00";pli0_ovl=Bytes.empty;pli1_ovl=Bytes.empty;pli2_ovl=Bytes.empty;source_name="UNIT.PLI";source_bytes=Bytes.empty;module_name="UNIT";command_tail=Bytes.empty;max_steps=10}in
 let state:Runner.state_snapshot={a=0;b=0;c=0;d=0;e=0;h=0;l=0;sp=65534;pc=0x100;sign=false;zero=false;auxiliary_carry=false;parity=false;carry=false}in
 let make pc oracles=Pli80.Native_dispatch.create ~image:"PLI.COM" ~entry_pc:pc ~end_pc:(pc+1) ~oracles ~records:[] ~prepare:(fun _ _ _->failwith"Should not prepare")in
 fails(fun()->Pli80.Native_dispatch.run input[make 0x100 []]);
 let oracle:Pli80.Native_dispatch.oracle={input=state;output=state;entry_memory=Bytes.empty;post_memory=Bytes.empty;logical_digest=""}in
 fails(fun()->Pli80.Native_dispatch.run input[make 0x200 [oracle]])
let ()=auxiliary();operation();flags();bridge();dispatcher_failures();print_endline"Native auxiliary, inherited recursive frames, supported special, 65536 comparisons and fail-closed tests passed"
