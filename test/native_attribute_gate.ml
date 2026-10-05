[@@@warning "-4-40-41-42"]
module H=Pli80_host
module R=H.Recursive_mapped
module P=H.Attribute_gate
module B=Pli80.Attribute_gate_bridge
let rejects f=match f()with exception Invalid_argument _->()|_->failwith"unsupported state accepted"
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let primitives()=
 let memory=H.State.of_bytes(Bytes.make 65536 '\000')in
 let put=H.State.write memory and write ~site:_ ~address:_ ~value:_=()in
 (* Enumerate every packed byte, position, and incoming NZPAC combination.
    Flags are independently expected unchanged except for original bit7. *)
 for position=0 to 255 do for packed=0 to 255 do for bits=0 to 31 do
  let flags:R.flags={sign=bits land 1<>0;zero=bits land 2<>0;auxiliary_carry=bits land 4<>0;parity=bits land 8<>0;carry=bits land 16<>0}in
  let entry:R.returned={a=0x91;bc=0x1200 lor position;de=0x3456;hl=0x789a;flags}in
  put(0x1b4b+position)packed;put 0xae58 0xab;
  let calls=ref 0 in
  let call ~site ~operation (q:R.returned)=
   assert(site=0x7ed3&&operation=P.Range_process&&q.a=packed&&q.bc=0x1b4b&&q.hl=0x1b4b+position);
   incr calls;q in
  let r=P.gate memory ~entry ~write ~call in
  assert(r.discarded_high=0xab&&r.packed=Some packed&&r.returned.a=packed);
  assert(r.returned.flags={flags with carry=packed>=128});
  assert(!calls=(if packed>=128 then 1 else 0));
  assert(r.rotated=Some(((packed*2)land 255)lor(packed lsr 7)))
 done done done;
 let entry:R.returned={a=0;bc=1;de=0x1234;hl=0;flags=R.comparison 0 0}in
 put 0xae6c 0x92;
 let calls=ref[]in
 let call ~site ~operation (q:R.returned)=calls:=site::!calls;match operation with
 |P.Input_process->assert(q.bc land 255=1&&q.hl=0x9201);put 0xae6b 7;put 0xae6c 0x83;{q with a=0x41;bc=0x1242}
 |P.Gate->assert(q.bc=0x1207&&q.hl=0x8307&&q.a=0x41);q
 |_->assert false in
 let r=P.saved memory ~entry ~write ~call in
 assert(r.fresh_input=Some 7&&List.rev !calls=[0x80bf;0x80c6]);
 rejects(fun()->H.State.of_bytes(Bytes.empty));
 List.iter(fun v->rejects(fun()->H.State.write memory 0xae57 v))[-1;256];
 List.iter(fun a->rejects(fun()->H.State.read memory a))[-1;65536]
let state pc c:Runner.state_snapshot={a=0x12;b=0x34;c;d=0x56;e=0x78;h=0x9a;l=0xbc;sp=0xf002;pc;sign=false;zero=false;auxiliary_carry=false;parity=false;carry=true}
let experiment com pli1 mode=
 let op=if String.starts_with ~prefix:"gate_"mode then B.Gate else B.Saved in
 let first,_=B.bounds op in
 Printf.printf"root test %s\n%!"mode;
 let t=B.create ~pli_com:com ~pli1 in let fs=Cpm.Filesystem.create()in
 if mode<>"missing"then assert(Cpm.Filesystem.add_file fs ~name:"UNIT.INT" Bytes.empty=Ok());
 let initialized=ref false and previous=ref None and retained=ref None and pre=ref None and callbacks=ref 0 and complete=ref false in
 let site,resume=if op=B.Gate then 0x80c6,0xa2c9 else 0x80f7,0xa2fa in
 let on_step_state_pair ~step_index:_ ~before ~after step=previous:=Some{Pli80.Native_dispatch.origin=B.origin "PLI1.OVL" site;before;after;step}in
 let intercept ~step_index:_ (b:Runner.instruction_boundary)=
  if not !initialized then(
   initialized:=true;let ram=b.copy_memory()in
   Bytes.blit com 0 ram 0x100(Bytes.length com);Bytes.blit pli1 0 ram 0x2200(Bytes.length pli1);
   let put a v=Bytes.set ram a(Char.chr v)in
   put 0xae34 0;put 0xae35 0;put 0xae33 0;put 0xaa1a 0;put 0x202b 0;put 0x2011 0;
   put 0xaa1f 0;put 0xaab4 0x0a;put(0x1b4b+0x10)0x80;put(0x1b4b+10)0x10;put 0xab49 0;put 0xab4a 0;put 0x1e0c 127;
   for i=0 to 35 do put(0x1ca2+i)(if i>0&&i<12 then Char.code "UNIT    INT".[i-1]else 0)done;
   put 0x2155 0xfe;put 0x2156 0xfd;put 0xfdfe 0xaa;Bytes.blit ram 5 ram 0x215c 3;
   (match mode with
    |"gate"->put 0xaa1a 1
    |"gate_work"->put 0xae35 1
    |"gate_shortcut"->put 0xae35 1;put 0x202b 1
    |"gate_code"->put 0xa0c0 0
    |"gate_helper"->put 0x9f53 0
    |"saved_alias"->put 0xae33 0xcf
    |"root_stack_alias"->put 0xae33 0xf3|"end"->put 0xae35 149|"alias"->put 0xae33 0xcd
    |"source_alias"->put(0xaa1f+255)150
    |"high_alias"->put 0xae35 1;put 0xaa1f 205;put(0xaab4+205)10;
     put(0xab49+410)0;put(0xab49+411)0;put(0x1b4b+10)24
    |"shortcut"->put 0xae35 1;put 0x202b 1
    |"work"->put 0xae35 1
    |"attr5"->put 0xae35 1;put(0x1b4b+10)40
    |"index"->put 0x1e0c 128|"guard"->put 0xfdfe 0
    |"code"->put 0xa2b7 0|"helper"->put 0x9c93 0|_->());
   let c=if op=B.Gate then (if mode="gate_skip"then 1 else 0x10)else if List.mem mode["low";"end";"alias";"source_alias";"saved_alias";"root_stack_alias"]then 1 else 0xfe in
   Runner.Apply_host_transition{memory_writes=List.init 65536(fun a->a,Char.code(Bytes.get ram a));next_state=(let q=state(site+0x2200)c in if mode="root_stack_alias"then {q with sp=0xae92}else q)})
  else if b.state.pc=first+0x2200 then(
   retained:=Some b;pre:=Some(b.copy_memory(),b.copy_filesystem(),b.dma,b.state);
   let p=Option.get !previous in let call=B.verify_call t op p ~entry:b.state in
   rejects(fun()->B.verify_call t op {p with origin=B.origin "PLI2.OVL" site}~entry:b.state);
   rejects(fun()->B.verify_call t op {p with origin=Analysis.Execution_map.Unknown}~entry:b.state);
   rejects(fun()->B.verify_call t op {p with before={p.before with sp=0}}~entry:b.state);
   let noncall=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:p.before.pc ~pc_after:p.after.pc
    ~decoded:(I8080.Step.decoded p.step)~fetched_bytes:(I8080.Step.fetched_bytes p.step)
    ~memory_accesses:(I8080.Step.memory_accesses p.step)~control_flow:I8080.Step.Sequential in
   rejects(fun()->B.verify_call t op {p with step=noncall}~entry:b.state);
   rejects(fun()->B.prepare t op ~call ~origin:(B.origin "PLI1.OVL" first){b with state={b.state with pc=0}});
   rejects(fun()->B.prepare t op ~call ~origin:(B.origin "PLI1.OVL" first){b with state={b.state with sp=0xae6a}});
   rejects(fun()->B.prepare t op ~call ~origin:(B.origin "PLI1.OVL" first){b with state={b.state with c=256}});
   rejects(fun()->B.prepare t op ~call ~origin:(B.origin "PLI1.OVL" first){b with copy_memory=(fun()->let m=b.copy_memory()in Bytes.set m b.state.sp '\000';m)});
   rejects(fun()->B.prepare t op ~call ~origin:(B.origin "PLI2.OVL" first)b);
   let p=B.prepare t op ~call ~origin:(B.origin "PLI1.OVL" first)b in
   let program=if mode="duplicate"then {p.program with effects=p.program.effects@List.filter(function Runner.Dispatch_bdos _->true|_->false)p.program.effects}
    else if mode="reorder"then{p.program with effects=List.rev p.program.effects}else p.program in
   Runner.Apply_host_program program)
  else if b.state.pc=resume then(complete:=true;Runner.Apply_host_transition{memory_writes=[];next_state={b.state with pc=0}})
  else Runner.Continue_guest_execution in
 let result=try Some(Runner.run_bytes ~filesystem:fs ~intercept ~on_step_state_pair
   ~on_bdos_event:(fun ~step_index:_ _->incr callbacks)~output:ignore ~max_steps:20(Bytes.of_string"\xc3\x00\x00"))with Invalid_argument e->Printf.printf"rejected %s: %s\n%!"mode e;None in
 Printf.printf"completed %b callbacks %d\n%!" !complete !callbacks;
 if List.mem mode["low";"high";"work";"gate_work";"gate_skip"]then (
  let flush=not(List.mem mode["low";"gate_skip"])in
  assert(!complete&& !callbacks=(if flush then 1 else 0)&&match result with Some(Ok r)->r.termination=Runner.Warm_boot&&r.host_bdos_services=(if flush then 2 else 0)|_->false))
 else(
  assert(not !complete);let ram,files,dma,s=Option.get !pre and b=Option.get !retained in
  assert(b.copy_memory()=ram&&Cpm.Filesystem.equal(b.copy_filesystem())files&&b.dma=dma&&b.state=s&& !callbacks=0))
let ()=primitives();
 (match Sys.getenv_opt"RUNES_HOST_IMAGES"with None->()|Some dir->
  let com=read(Filename.concat dir"PLI.COM")and pli1=read(Filename.concat dir"PLI1.OVL")in
  let bad=Bytes.copy pli1 in Bytes.set bad 0x80b7 '\000';rejects(fun()->B.create ~pli_com:com ~pli1:bad);
  List.iter(experiment com pli1)["gate_skip";"gate_work";"gate_shortcut";"gate_code";"gate_helper";"saved_alias";"root_stack_alias";"low";"high";"work";"attr5";"gate";"end";"alias";"source_alias";"high_alias";"shortcut";"index";"guard";"missing";"code";"helper";"duplicate";"reorder"]);
 print_endline"Exhaustive rotate/flag fidelity, fresh saved-byte dependency, actual CALL and transactional negatives passed"
