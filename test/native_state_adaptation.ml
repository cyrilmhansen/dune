[@@@warning "-4-40-41-42"]
module H=Pli80_host
module P=H.State_adaptation
module R=H.Recursive_mapped
module B=Pli80.State_adaptation_bridge
let rejects f=match f()with exception Invalid_argument _->()|_->failwith"unsupported state accepted"
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let memory=H.State.of_bytes(Bytes.make 65536 '\000')
let entry:R.returned={a=0x91;bc=0;de=0x1234;hl=0x5678;flags=R.comparison 1 2}
let run ?(protected=[]) ?(call=(fun ~site:_ ~operation:_ _->assert false)) op q=
 let writes=ref[]in
 let r=P.run op memory ~entry:q ~sp:0xf000 ~protected
  ~write:(fun ~site ~address ~value->writes:=(site,address,value)::!writes)
  ~frame:(fun ~address ~value->H.State.write memory address value)~call in r,List.rev !writes
let primitives()=
 for c=0 to 255 do for e=0 to 255 do
  let q={entry with bc=0xab00 lor c;de=0xcd00 lor e}in
  let r,ws=run P.Minimum q and difference=(c-e)land 255 in
  let parity=ref 0 in for bit=0 to 7 do parity:= !parity+((difference lsr bit)land 1)done;
  assert(r.returned.a=min c e&&r.returned.bc=q.bc&&r.returned.de=q.de&&r.returned.hl=0xa64f);
  assert(r.returned.flags={R.sign=difference>=128;zero=c=e;auxiliary_carry=(c land 15)>=(e land 15);parity= !parity mod 2=0;carry=c<e});
  assert(ws=[0x23a3,0xa64f,e;0x23a5,0xa64e,c])
 done done;
 let put=H.State.write memory in
 put 0xa628 11;put 0xa62b 22;put 0xa62e 33;put 0xae32 4;
 let calls=ref[]in
 let call ~site ~operation (q:R.returned)=
  calls:=(site,operation,q.bc land 255,q.de land 255)::!calls;
  put 0xae32((q.bc+1)land 255);{q with a=0;bc=0x1234;de=q.de}in
 ignore(run ~call P.Publish entry);
 assert(List.rev !calls=[0x23e4,P.Control_publish,4,11;0x23f5,P.Primary_publish,5,22;0x2406,P.Secondary_publish,6,33]);
 List.iter(fun selector->put 0xa628 selector;rejects(fun()->run P.Adapt entry))[0x16;0x19];
 put 0xa628 0x15;put 0xa62e 1;
 rejects(fun()->run ~call:(fun ~site:_ ~operation:_ q->q)P.Adapt entry);
 put (0xa628+7)5;put (0xa63b+14)0x34;put (0xa63c+14)0x12;put 0xae32 6;
 let observed=ref[]in
 let call ~site ~operation (q:R.returned)=observed:=(site,operation,q.bc land 255,q.de)::!observed;q in
 ignore(run ~call P.Adapt{entry with bc=7});
 assert(List.rev !observed=[0x24e6,P.Word_publish,6,0x1234;0x24ed,P.Publish,7,0x1234]);
 let sites=ref[]in
 let call ~site ~operation (q:R.returned)=sites:=site::!sites;match operation with
 |P.Input_process->assert(q.bc land 255=entry.bc land 255);{q with bc=0xabfe}
 |P.Adapt->assert(q.bc=0xab00);{q with bc=0xcdef}
 |P.Gate->assert(q.bc=0xcd00);q|_->assert false in
 ignore(run ~call P.Saved entry);assert(List.rev !sites=[0x2519;0x251e;0x2526]);
 rejects(fun()->run ~protected:[0xa64e]P.Minimum entry);
 rejects(fun()->run P.Minimum{entry with a=256});
 rejects(fun()->H.State.of_bytes Bytes.empty)
let machine pc:Runner.state_snapshot={a=1;b=2;c=0;d=3;e=4;h=5;l=6;sp=0xf002;pc;sign=false;zero=false;auxiliary_carry=false;parity=false;carry=true}
let bridge com pli1=
 let t=B.create ~pli_com:com ~pli1 and fs=Cpm.Filesystem.create()in
 List.iter(fun(op,site)->
 let first,_=B.bounds op in
 let initial=ref false and previous=ref None and complete=ref false in
 let on_step_state_pair ~step_index:_ ~before ~after step=previous:=Some{Pli80.Native_dispatch.origin=B.origin"PLI1.OVL"site;before;after;step}in
 let intercept ~step_index:_ (b:Runner.instruction_boundary)=
  if not !initial then(
   initial:=true;let ram=b.copy_memory()in
   Bytes.blit com 0 ram 0x100(Bytes.length com);Bytes.blit pli1 0 ram 0x2200(Bytes.length pli1);
   List.iter(fun a->Bytes.set ram a '\000')[0xa628;0xa62b;0xa62e;0xa642;0xa643;0xa63b;0xa63c;0xae32;0xae33;0xae34;0xae35;0xaa1f;0xaab4;0x1b4b;0x1e0c];
   Runner.Apply_host_transition{memory_writes=List.init 65536(fun a->a,Char.code(Bytes.get ram a));next_state=machine(site+0x2200)})
  else if b.state.pc=first+0x2200 then(
   let previous=Option.get !previous in let call=B.verify_call t op previous ~entry:b.state in
   let origin=B.origin"PLI1.OVL"first in
   rejects(fun()->B.verify_call t op {previous with origin=B.origin"PLI2.OVL"site}~entry:b.state);
   rejects(fun()->B.verify_call t op {previous with before={previous.before with sp=0}}~entry:b.state);
   rejects(fun()->B.prepare t op ~call ~origin:(B.origin"PLI2.OVL"first) b);
   let changed address value={b with copy_memory=(fun()->let ram=b.copy_memory()in Bytes.set ram address(Char.chr value);ram)}in
   rejects(fun()->B.prepare t op ~call ~origin(changed b.state.sp 0));
   rejects(fun()->B.prepare t op ~call ~origin(changed b.state.pc 0));
   rejects(fun()->B.prepare t op ~call ~origin{b with state={b.state with sp=0xa650}});
   rejects(fun()->B.prepare t op ~call ~origin{b with state={b.state with c=256}});
   if op=B.Adapt then(
    List.iter(fun selector->rejects(fun()->B.prepare t op ~call ~origin(changed 0xa628 selector)))[0x16;0x19];
    rejects(fun()->B.prepare t op ~call ~origin{b with copy_memory=(fun()->let ram=b.copy_memory()in Bytes.set ram 0xa628 '\021';Bytes.set ram 0xa62e '\001';ram);preview_host_program=(fun p->b.preview_host_program{p with effects=Runner.Memory_write(0xa628,0x15)::Runner.Memory_write(0xa62e,1)::p.effects})}));
   let ram=b.copy_memory()and files=b.copy_filesystem()in
   let p=B.prepare t op ~call ~origin b in
   assert(b.copy_memory()=ram&&Cpm.Filesystem.equal(b.copy_filesystem())files);
   Runner.Apply_host_program p.program)
  else if b.state.pc=site+0x2203 then(complete:=true;Runner.Apply_host_transition{memory_writes=[];next_state={b.state with pc=0}})
  else Runner.Continue_guest_execution in
 ignore(Runner.run_bytes ~filesystem:fs ~intercept ~on_step_state_pair ~output:ignore ~max_steps:2000(Bytes.of_string"\xc3\x00\x00"));assert(!complete)
 )[B.Minimum,0x242b;B.Publish,0x24ed;B.Adapt,0x251e;B.Saved,0x0c47]
let ()=primitives();(match Sys.getenv_opt"RUNES_HOST_IMAGES"with None->()|Some dir->bridge(read(Filename.concat dir"PLI.COM"))(read(Filename.concat dir"PLI1.OVL")));print_endline"Exhaustive cached minimum and independent fresh channel/frame inputs passed"
