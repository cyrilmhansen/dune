[@@@warning "-4-40-41-42"]
module H=Pli80_host
module R=H.Recursive_mapped
module P=H.Input_processing
module B=Pli80.Input_processing_bridge
let rejects f=match f()with exception Invalid_argument _->()|_->failwith"unsupported state accepted"
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let primitives()=
 let m=H.State.of_bytes(Bytes.make 65536 '\000')in
 let put=H.State.write m in
 let ws=ref[]in let write w=ws:=w::!ws in
 for pos=0 to 255 do for value=0 to 255 do
  put(0xaa1f+pos)0x11;put 0xae3a 0x83;
  let q=H.Mapped_control.publish m ~position:pos ~value ~protected:[]~write in
  assert(q.index=0x11&&q.address=0xac84&&q.value=value&&q.discarded_high=value);
  assert(List.map(fun(w:H.Mapped_lookup.write)->w.address,w.value)(List.rev !ws)=[0xae42,value;0xae41,pos;0xac84,value]);ws:=[];
  let q=H.Mapped_control.read m ~position:pos ~protected:[]~write in
  assert(q.value=value&&q.discarded_high=0x83);ws:=[]
 done done;
 put 0xaa20 2;put 0xac75 0x55;
 assert((H.Mapped_control.read m ~position:1 ~protected:[]~write).value=0x55);
 put 0xac75 0x66;assert((H.Mapped_control.read m ~position:1 ~protected:[]~write).value=0x66);
 put 0xaa20 3;put 0xac76 0x77;assert((H.Mapped_control.read m ~position:1 ~protected:[]~write).value=0x77);
 List.iter(fun p->rejects(fun()->H.Mapped_control.read m ~position:p ~protected:[]~write))[-1;256];
 List.iter(fun a->rejects(fun()->H.Mapped_control.publish m ~position:1 ~value:0 ~protected:[a]~write))[0xae41;0xae42;0xaa20;0xac76];
 rejects(fun()->H.Mapped_control.read m ~position:1 ~protected:[0xae3a]~write);
 let entry:R.returned={a=0;bc=1;de=0x1234;hl=0;flags=R.comparison 0 0}in
 (* Mutation doubles below prove fresh dependencies; they are not new compiler-semantic evidence. *)
 let calls=ref[]in
 let child ~site ~operation (q:R.returned)=calls:=site::!calls;
  match operation with
  |P.Range_publish->put 0xae32 10;q
  |Control_read->assert(q.bc land 255=9);{q with a=11}
  |Control_publish->assert(q.bc land 255=10&&q.de land 255=11);put 0xae32 20;q
  |Primary_read->assert(q.bc land 255=19);{q with a=22}
  |Primary_publish->assert(q.bc land 255=20&&q.de land 255=22);put 0xae32 30;q
  |Secondary_read->assert(q.bc land 255=29);{q with a=33}
  |Secondary_publish->assert(q.bc land 255=30&&q.de land 255=33);q
  |_->failwith"wrong route child"in
 let result=P.run m ~entry ~write:(fun ~site:_ ~address:_ ~value:_->())~call:child in
 assert(result.route="low"&&List.map(fun(c:P.channel)->c.predecessor,c.position,c.value)result.channels=[9,10,11;19,20,22;29,30,33]);
 assert(List.rev !calls=[0x807d;0x8085;0x808d;0x8095;0x809d;0x80a5;0x80ad]);
 put 0xaa1a 0x80;
 let high_child ~site:_ ~operation (q:R.returned)=match operation with
  |P.Range_process->assert(q.a=0xc0&&not q.flags.carry);put 0xae6a 0xef;{q with a=0x12}
  |Emit->assert(q.bc land 255=0xef&&q.a=0x12);q|_->failwith"wrong high child"in
 let p=P.run m ~entry:{entry with bc=0xfe}~write:(fun ~site:_ ~address:_ ~value:_->())~call:high_child in
 assert(p.emitted=Some 0xef&&p.returned.a=0x12);
 put 0xaa1a 1;
 rejects(fun()->P.run m ~entry:{entry with bc=0xfe}~write:(fun ~site:_ ~address:_ ~value:_->())~call:(fun ~site:_ ~operation:_ _->failwith"gate was not rejected"))
let state pc c:Runner.state_snapshot={a=0x12;b=0x34;c;d=0x56;e=0x78;h=0x9a;l=0xbc;sp=0xf002;pc;sign=false;zero=false;auxiliary_carry=false;parity=false;carry=true}
let experiment com pli1 mode=
 Printf.printf"root test %s\n%!"mode;
 let t=B.create ~pli_com:com ~pli1 in let fs=Cpm.Filesystem.create()in
 if mode<>"missing"then assert(Cpm.Filesystem.add_file fs ~name:"UNIT.INT" Bytes.empty=Ok());
 let initialized=ref false and previous=ref None and retained=ref None and pre=ref None and callbacks=ref 0 and complete=ref false in
 let site=0x80bf and resume=0xa2c2 in
 let on_step_state_pair ~step_index:_ ~before ~after step=previous:=Some{Pli80.Native_dispatch.origin=B.origin "PLI1.OVL" site;before;after;step}in
 let intercept ~step_index:_ (b:Runner.instruction_boundary)=
  if not !initialized then(
   initialized:=true;let ram=b.copy_memory()in
   Bytes.blit com 0 ram 0x100(Bytes.length com);Bytes.blit pli1 0 ram 0x2200(Bytes.length pli1);
   let put a v=Bytes.set ram a(Char.chr v)in
   put 0xae34 0;put 0xae35 0;put 0xae33 0;put 0xaa1a 0;put 0x202b 0;put 0x2011 0;
   put 0xaa1f 0;put 0xaab4 0x0a;put(0x1b4b+10)0x10;put 0xab49 0;put 0xab4a 0;put 0x1e0c 127;
   for i=0 to 35 do put(0x1ca2+i)(if i>0&&i<12 then Char.code "UNIT    INT".[i-1]else 0)done;
   put 0x2155 0xfe;put 0x2156 0xfd;put 0xfdfe 0xaa;Bytes.blit ram 5 ram 0x215c 3;
   (match mode with
    |"gate"->put 0xaa1a 1|"end"->put 0xae35 149|"alias"->put 0xae33 0xcd
    |"source_alias"->put(0xaa1f+255)150
    |"high_alias"->put 0xae35 1;put 0xaa1f 205;put(0xaab4+205)10;
     put(0xab49+410)0;put(0xab49+411)0;put(0x1b4b+10)24
    |"shortcut"->put 0xae35 1;put 0x202b 1
    |"work"->put 0xae35 1
    |"attr5"->put 0xae35 1;put(0x1b4b+10)40
    |"index"->put 0x1e0c 128|"guard"->put 0xfdfe 0
    |"code"->put 0xa248 0|"helper"->put 0x9c93 0|_->());
   let c=if List.mem mode["low";"end";"alias";"source_alias"]then 1 else 0xfe in
   Runner.Apply_host_transition{memory_writes=List.init 65536(fun a->a,Char.code(Bytes.get ram a));next_state=state(site+0x2200)c})
  else if b.state.pc=0xa248 then(
   retained:=Some b;pre:=Some(b.copy_memory(),b.copy_filesystem(),b.dma,b.state);
   let p=Option.get !previous in let call=B.verify_call t p ~entry:b.state in
   rejects(fun()->B.verify_call t {p with origin=B.origin "PLI2.OVL" site}~entry:b.state);
   rejects(fun()->B.verify_call t {p with origin=Analysis.Execution_map.Unknown}~entry:b.state);
   rejects(fun()->B.verify_call t {p with before={p.before with sp=0}}~entry:b.state);
   let noncall=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:p.before.pc ~pc_after:p.after.pc
    ~decoded:(I8080.Step.decoded p.step)~fetched_bytes:(I8080.Step.fetched_bytes p.step)
    ~memory_accesses:(I8080.Step.memory_accesses p.step)~control_flow:I8080.Step.Sequential in
   rejects(fun()->B.verify_call t {p with step=noncall}~entry:b.state);
   rejects(fun()->B.prepare t ~call ~origin:(B.origin "PLI1.OVL" 0x8048){b with state={b.state with pc=0}});
   rejects(fun()->B.prepare t ~call ~origin:(B.origin "PLI1.OVL" 0x8048){b with state={b.state with sp=0xae6a}});
   rejects(fun()->B.prepare t ~call ~origin:(B.origin "PLI1.OVL" 0x8048){b with state={b.state with c=256}});
   rejects(fun()->B.prepare t ~call ~origin:(B.origin "PLI1.OVL" 0x8048){b with copy_memory=(fun()->let m=b.copy_memory()in Bytes.set m b.state.sp '\000';m)});
   let p=B.prepare t ~call ~origin:(B.origin "PLI1.OVL" 0x8048)b in
   let program=if mode="duplicate"then {p.program with effects=p.program.effects@List.filter(function Runner.Dispatch_bdos _->true|_->false)p.program.effects}
    else if mode="reorder"then{p.program with effects=List.rev p.program.effects}else p.program in
   Runner.Apply_host_program program)
  else if b.state.pc=resume then(complete:=true;Runner.Apply_host_transition{memory_writes=[];next_state={b.state with pc=0}})
  else Runner.Continue_guest_execution in
 let result=try Some(Runner.run_bytes ~filesystem:fs ~intercept ~on_step_state_pair
   ~on_bdos_event:(fun ~step_index:_ _->incr callbacks)~output:ignore ~max_steps:20(Bytes.of_string"\xc3\x00\x00"))with Invalid_argument e->Printf.printf"rejected %s: %s\n%!"mode e;None in
 Printf.printf"completed %b callbacks %d\n%!" !complete !callbacks;
 if List.mem mode["low";"high";"work"]then assert(!complete&& !callbacks=(if mode<>"low"then 1 else 0)&&match result with Some(Ok r)->r.termination=Runner.Warm_boot&&r.host_bdos_services=(if mode<>"low"then 2 else 0)|_->false)
 else(
  assert(not !complete);let ram,files,dma,s=Option.get !pre and b=Option.get !retained in
  assert(b.copy_memory()=ram&&Cpm.Filesystem.equal(b.copy_filesystem())files&&b.dma=dma&&b.state=s&& !callbacks=0))
let ()=primitives();
 (match Sys.getenv_opt"RUNES_HOST_IMAGES"with None->()|Some dir->
  let com=read(Filename.concat dir"PLI.COM")and pli1=read(Filename.concat dir"PLI1.OVL")in
  let bad=Bytes.copy pli1 in Bytes.set bad 0x8048 '\000';rejects(fun()->B.create ~pli_com:com ~pli1:bad);
  List.iter(experiment com pli1)["low";"high";"work";"attr5";"gate";"end";"alias";"source_alias";"high_alias";"shortcut";"index";"guard";"missing";"code";"helper";"duplicate";"reorder"]);
 print_endline"AC73 shared-memory/order, independent channels, saved high byte, actual CALL and transactional negatives passed"
