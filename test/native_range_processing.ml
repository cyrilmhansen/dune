[@@@warning "-4-40-41-42"]
module H=Pli80_host
module R=H.Recursive_mapped
module P=H.Range_processing
module B=Pli80.Range_processing_bridge
let rejects f=match f()with exception Invalid_argument _->()|_->failwith"unsupported root accepted"
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let primitives()=
 let m=H.State.of_bytes(Bytes.make 65536 '\000')in
 let nochild ~site:_ ~operation:_ _=failwith"early return invoked child"in
 let no_write ~site:_ ~address:_ ~value:_=failwith"early return wrote RAM"in
 let no_push ~a:_ ~flags:_=failwith"early return PUSH"in
 let q:R.returned={a=17;bc=0x3456;de=0x789a;hl=0xbcde;flags=R.comparison 17 0}in
 for begin_=0 to 255 do for end_=0 to 255 do
  H.State.write m 0xae34 begin_;H.State.write m 0xae35 end_;
  (* Gate set, so every nonempty range terminates without touching a table. *)
  H.State.write m 0xaa1a 0x83;
  let p=P.run m ~entry:q ~write:no_write ~push_psw:no_push ~call:nochild in
  let cmp=I8080.Alu.subtract ~borrow:false end_ begin_ in
  assert(p.returned.bc=q.bc&&p.returned.de=q.de&&p.returned.hl=0xae34);
  assert(p.returned.flags.sign=cmp.status.szp.sign&&p.returned.flags.zero=cmp.status.szp.zero
   &&p.returned.flags.auxiliary_carry=cmp.status.auxiliary_carry&&p.returned.flags.parity=cmp.status.szp.parity);
  if begin_=end_ then assert(p.path="equal"&&p.returned.a=end_&&not p.returned.flags.carry)
  else assert(p.path="gate"&&p.returned.a=(0x41 lor(if end_<begin_ then 128 else 0))&&p.returned.flags.carry)
 done done;
 for mask=0 to 31 do
  let flags:R.flags={sign=mask land 16<>0;zero=mask land 8<>0;auxiliary_carry=mask land 4<>0;parity=mask land 2<>0;carry=mask land 1<>0}in
  let expected=(if flags.sign then 128 else 0)lor(if flags.zero then 64 else 0)lor(if flags.auxiliary_carry then 16 else 0)lor(if flags.parity then 4 else 0)lor 2 lor(if flags.carry then 1 else 0)in
  assert(P.psw flags=expected);
  for n=0 to 255 do List.iter(fun increment->
   let value,f=P.unary flags n increment in
   let v,s=(if increment then I8080.Alu.increment else I8080.Alu.decrement)n in
   assert(value=v&&f.carry=flags.carry&&f.sign=s.szp.sign&&f.zero=s.szp.zero&&f.parity=s.szp.parity&&f.auxiliary_carry=s.auxiliary_carry))[false;true]done
 done;
 List.iter(fun a->rejects(fun()->P.supported_attribute a))[0;1;5;7];
 List.iter P.supported_attribute[2;3;4;6];rejects(fun()->P.supported_forward_cursor 0);
 for n=1 to 255 do P.supported_forward_cursor n done;
 rejects(fun()->H.State.of_bytes Bytes.empty);
 rejects(fun()->R.supported_special ~first:15 ~second:1);
 rejects(fun()->R.supported_special ~first:1 ~second:2);
 rejects(fun()->H.Balance_scan.run m ~cursor:0 ~protected:[0xae49]);
 (* A child test double changes the subsequent forward mapping. This is an
    ordering/dependency test, not a historical claim about Balance_scan effects. *)
 H.State.write m 0xae34 0;H.State.write m 0xae35 1;H.State.write m 0xaa1a 0;
 H.State.write m 0x202b 0;H.State.write m 0x2011 0;
 let emitted=ref[] and forward_mapping=ref false in
 let child ~site:_ ~operation (q:R.returned)=match operation with
  |P.Mapping->{q with a=(if !forward_mapping then 0xf7 else 0x0a)}
  |Recursive->{q with a=0}
  |Balance->forward_mapping:=true;{q with a=0;flags=R.comparison 0 0}
  |Emit->emitted:=q.bc land 255::!emitted;q
  |_->failwith"F7 guard was reached too late"in
 rejects(fun()->P.run m ~entry:q ~write:(fun ~site:_ ~address:_ ~value:_->())~push_psw:(fun ~a:_ ~flags:_->())~call:child);
 assert(!emitted=[0xf7])
let state pc:Runner.state_snapshot={a=0;b=0;c=0;d=0x42;e=0x63;h=0x56;l=0x78;sp=0xf002;pc;
 sign=false;zero=false;auxiliary_carry=false;parity=false;carry=false}
(* Each synthetic root enters through an ACTUALLY executed historical CALL.
   No cyclic table is constructed: mapped0A and low3=0 terminate both children. *)
let experiment com pli1 mode=
 Printf.printf "root test %s\n%!"mode;
 let t=B.create ~pli_com:com ~pli1 in
 let fs=Cpm.Filesystem.create()in
 if mode<>"missing"then assert(Cpm.Filesystem.add_file fs ~name:"UNIT.INT" Bytes.empty=Ok());
 let initialized=ref false and previous=ref None and retained=ref None and pre=ref None and callbacks=ref 0 and oracle=ref None in
 let site=0x7ed3 and resume=0xa0d6 in
 let on_step_state_pair ~step_index:_ ~before ~after step=previous:=Some{Pli80.Native_dispatch.origin=B.origin "PLI1.OVL" site;before;after;step}in
 let intercept ~step_index:_ (b:Runner.instruction_boundary)=
  if not !initialized then(
   initialized:=true;let ram=b.copy_memory()in
   Bytes.blit com 0 ram 0x100(Bytes.length com);Bytes.blit pli1 0 ram 0x2200(Bytes.length pli1);
   let put a v=Bytes.set ram a(Char.chr v)in
   put 0xae34 0;put 0xae35 1;put 0xaa1a 0;put 0x202b 0;put 0x2011 0;
   put 0xaa1f 0;put 0xaab4 0x0a;put 0xab49 0;put 0xab4a 0;put 0xae33 0;
   put(0x1b4b+0x0a)0x10;put 0x1e0c 127;
   for i=0 to 35 do put(0x1ca2+i)(if i>0&&i<12 then Char.code "UNIT    INT".[i-1]else 0)done;
   put 0x2155 0xfe;put 0x2156 0xfd;put 0xfdfe 0xaa;Bytes.blit ram 5 ram 0x215c 3;
   (match mode with
    |"202B"->put 0x202b 1|"2011"->put 0x2011 1
    |"reverse_F7"->put 0xaab4 0xf7
    |"mapped21"->put 0xaab4 0x21
    |"forward_wrap"->put 0xae34 255;put 0xae35 0;put(0xaa1f+255)0
    |"special_ge"|"special_small"->
      put 0xaab4 0x1e;put(0xaa1f+255)1;put(0xaa1f+254)2;put 0xaab5 0x0a;put 0xaab6 0x0a;
      put 0xab4b 0;put 0xab4c 0;put 0xab4d(if mode="special_small"then 1 else 0);put 0xab4e 0
    |"attr0"->put(0x1b4b+10)0|"attr1"->put(0x1b4b+10)8
    |"attr5"->put(0x1b4b+10)40|"attr7"->put(0x1b4b+10)56
    |"index"->put 0x1e0c 128|"guard"->put 0xfdfe 0
    |"code"->put 0x9f53 0|"helper"->put 0x9c4d 0|_->());
   Runner.Apply_host_transition{memory_writes=List.init 65536(fun a->a,Char.code(Bytes.get ram a));next_state=state(site+0x2200)})
  else if b.state.pc=0x9f53 then(
   retained:=Some b;pre:=Some(b.copy_memory(),b.copy_filesystem(),b.dma,b.state);
   let p=Option.get !previous in
   let call=B.verify_call t p ~entry:b.state in
   rejects(fun()->B.verify_call t {p with origin=B.origin "PLI2.OVL" site}~entry:b.state);
   rejects(fun()->B.verify_call t {p with origin=Analysis.Execution_map.Unknown}~entry:b.state);
   let wrong={b with state={b.state with pc=0}}in
   rejects(fun()->B.prepare t ~call ~origin:(B.origin "PLI1.OVL" 0x7d53)wrong);
   let alias={b with state={b.state with sp=0xae4f}}in
   rejects(fun()->B.prepare t ~call ~origin:(B.origin "PLI1.OVL" 0x7d53)alias);
   let malformed={b with copy_memory=(fun()->let ram=b.copy_memory()in Bytes.set ram b.state.sp '\000';ram)}in
   rejects(fun()->B.prepare t ~call ~origin:(B.origin "PLI1.OVL" 0x7d53)malformed);
   let prepared=B.prepare t ~call ~origin:(B.origin "PLI1.OVL" 0x7d53)b in
   let effects=if mode="duplicate"then prepared.program.effects@List.filter(function Runner.Dispatch_bdos _->true|_->false)prepared.program.effects
    else if mode="reorder"then List.rev prepared.program.effects else prepared.program.effects in
   let program={prepared.program with effects;validate=(fun r->
    match prepared.program.validate r with Error _ as e->e|Ok()->
     if List.length r.services<>2 then Error"unexpected service cardinality"else Ok())}in
   oracle:=Some(match b.preview_host_program program with Ok r->r,prepared.state|Error e->invalid_arg e);
   Runner.Apply_host_program program)
  else if b.state.pc=resume then(
   let r,s=Option.get !oracle in assert(b.state=s&&b.copy_memory()=r.memory&&b.dma=r.dma&&Cpm.Filesystem.equal fs r.filesystem);
   Runner.Apply_host_transition{memory_writes=[];next_state={b.state with pc=0}})
  else Runner.Continue_guest_execution in
 let result=try Some(Runner.run_bytes ~filesystem:fs ~intercept ~on_step_state_pair ~on_bdos_event:(fun ~step_index:_ _->incr callbacks)~output:ignore(Bytes.of_string"\000"))with Invalid_argument _->None in
 if mode="success"then assert(match result with Some(Ok r)->r.termination=Runner.Warm_boot&&r.host_bdos_services=2|_->false)
 else(
  assert(result=None||match result with Some(Error(Runner.Invalid_host_transition _))->true|_->false);
  let b=Option.get !retained and ram,files,dma,s=Option.get !pre in
  assert(b.copy_memory()=ram&&b.state=s&&b.dma=dma&&Cpm.Filesystem.equal fs files&& !callbacks=0))
let ()=primitives();
 (match Sys.getenv_opt"RUNES_HOST_IMAGES"with None->()|Some dir->
  let com=read(Filename.concat dir"PLI.COM")and pli1=read(Filename.concat dir"PLI1.OVL")in
  List.iter(experiment com pli1)["success";"forward_wrap";"special_ge";"special_small";"202B";"2011";"reverse_F7";"mapped21";"attr0";"attr1";"attr5";"attr7";"index";"guard";"code";"helper";"missing";"duplicate";"reorder"]);
 print_endline"65536 early ABIs,16384 unary cases,32 PSWs,private late rejection and real CP/M root transaction tests passed"
