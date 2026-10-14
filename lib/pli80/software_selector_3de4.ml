[@@@warning "-4-40-41-42"]
(* Scoped software selector dispatcher. No live interception or invented CALL. *)
module B=Acquisition_family_bridge
module A=Acquisition_parent_bridge
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
exception Outside_scope of string
let rotate (q:R.returned)=
 let v=q.a in {q with R.a=(v lsr 1)lor(if q.flags.carry then 128 else 0);flags={q.flags with carry=v land 1<>0}}
let prepare ?k33_gateway ?(observe_read=(fun _ _ _->())) bridge (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 let need c s=if not c then invalid_arg("3DE4: "^s)in
 need(entry.pc=0x5fe4&&entry.sp>=0xb220&&entry.sp<=0xfffa)"entry/frame";
 let memory=S.of_bytes(boundary.copy_memory())in
 let code a b=for o=a to b-1 do need(S.read memory(o+0x2200)=Char.code(Bytes.get bridge.B.pli2 o))"code"done in
 let ranges=[0x3de4,0x3e36;0x3b7a,0x3bfb;0x3c27,0x3d10;0x3747,0x3752;0x3726,0x3731;0x368a,0x369f]in
 List.iter(fun(a,b)->code a b)ranges;
 need(Bytes.sub bridge.B.pli2 0x20ac 8=Bytes.sub(boundary.copy_memory())0x42ac 8)"gateway PUSH/PCHL code";
 need(S.word memory entry.sp=0x42b4&&S.word memory 0xad1f=0x5fe4)"software continuation/handler pointer";
 let sentinel=S.word memory 0x2155 in
 need(not(List.exists(fun(a,b)->sentinel>=a+0x2200&&sentinel<b+0x2200)ranges))"own code/sentinel alias";
 need(not(sentinel>=entry.sp-8&&sentinel<entry.sp+2))"software stack/sentinel alias";
 let q=ref(A.logical entry) and sp=ref entry.sp and effects=ref[]and journal=ref[]in
 let put kind writer address value=
  S.write memory address value;effects:=Runner.Memory_write(address,value)::!effects;
  journal:={B.address;value;writer;depth=0;kind}::!journal in
 let read=S.read memory and word=S.word memory in
 let a v=q:={!q with R.a=v}and hl v=q:={!q with R.hl=v}and de v=q:={!q with R.de=v}in
 let c v=q:={!q with R.bc=(!q.bc land 0xff00)lor v}in

 let push site v=put"compatibility"site(!sp-1)(v lsr 8);put"compatibility"site(!sp-2)(v land 255);sp:= !sp-2 in
 let read_at site address=let v=read address in observe_read site address v;v in
 let word_at site address=let lo=read_at site address in let hi=read_at site(address+1)in lo lor(hi lsl 8)in
 let pop site=let v=word_at site !sp in sp:= !sp+2;v in
 let rar()=q:=rotate !q in
 let call site ret fn=push site(site+3);fn();need(pop ret=site+3)"child continuation"in
 let preview state=match boundary.preview_host_program{Runner.effects=List.rev !effects;next_state=state;validate=(fun _->Ok());on_commit=ignore}with
  |Error e->invalid_arg e|Ok p->for i=0 to 65535 do S.write memory i(Char.code(Bytes.get p.memory i))done;p in
 let staged site target prepare=
  push site(site+3);
  let state=A.machine entry !q !sp target in
  let prior=List.rev !effects in
  let before=preview state in
  let view:Runner.instruction_boundary={state;read_memory=read;copy_memory=(fun()->Bytes.init 65536(fun i->Char.chr(read i)));dma=before.dma;
   copy_filesystem=(fun()->Cpm.Filesystem.copy before.filesystem);
   preview_host_program=(fun p->boundary.preview_host_program{p with effects=prior@p.effects})}in
  let p:B.prepared=prepare view in
  effects:=List.rev_append p.program.effects !effects;
  journal:=List.rev_append(List.map(fun(w:B.write)->{w with depth=w.depth+1})p.journal)!journal;
  sp:=p.state.sp;q:=A.logical p.state;ignore(preview p.state)in
 let canonical site operation=
  let target=fst(B.bounds operation)+(if B.resident_operation operation then 0x100 else 0x2200)in
  staged site target (B.prepare bridge operation ~call:(B.internal_call bridge operation site)
   ~origin:(B.origin(if B.resident_operation operation then "PLI.COM"else"PLI2.OVL")(fst(B.bounds operation))))in
 let dad value=let sum= !q.hl+value in q:={!q with R.hl=sum land 65535;flags={!q.flags with carry=sum>65535}}in
 let gateway site=
  staged site 0x41b5(fun view->
   let ram=view.Runner.copy_memory()in
   need(Bytes.sub ram 0x267d 22=Bytes.sub bridge.pli2 0x047d 22)"canonical lookup code";
   let memory=S.of_bytes ram in
   let impossible _=invalid_arg "3DE4 lookup unexpectedly needs effects"in
   let mapped=Pli80_host.Acquisition_family.run(Pli80_host.Acquisition_family.Pli2_output 0x047d)memory
    ~entry:(A.logical view.state)~write:(fun ~site:_ ~address:_ ~value:_->())
    ~compatibility:impossible ~adjust:(fun ~site:_ ~delta:_->impossible())~sp:(fun()->view.state.sp)
    ~guard_field:(fun _ _->impossible())~native:(fun ~site:_ ~target:_ _->impossible())~follow_spine:false
    ~software:(fun ~site:_ ~consumed:_->impossible())in
   let index=mapped.returned.a in
   let call=B.internal_call bridge(B.Pli2_output 0x1fb5)site in
   if index=23 then B.prepare bridge(B.Pli2_output 0x1fb5)~call ~origin:(B.origin "PLI2.OVL"0x1fb5)view
   else if index=33&&Option.is_some k33_gateway then (Option.get k33_gateway)~call_site:site view
   else(
    let r=A.logical view.state in
    let entry:Pli80_host.K123_child_7d05_front.state={pc=view.state.pc;sp=view.state.sp;a=r.a;bc=r.bc;de=r.de;hl=r.hl;flags=r.flags}in
    if Pli80_host.K123_gateway_transaction.eligible(S.of_bytes(view.copy_memory())) ~pli2:bridge.pli2 ~pli_com:bridge.com ~call_site:site ~entry
    then B.prepare_k123 bridge ~call ~origin:(B.origin "PLI2.OVL"0x1fb5)view
    else raise(Outside_scope(Printf.sprintf "nested gateway canonical index %d outside installed domain"index))))in
 canonical 0x5fe4(B.Pli2_output 0x3660);rar();
 if !q.flags.carry then raise(Outside_scope "unobserved optional37CB route");
 hl(word_at 0x5ff5 0xad0a);c(!q.hl land 255);q:={!q with R.bc= !q.bc land 255};
 let selector= !q.bc in
 if not(List.mem selector[1;2;4])then raise(Outside_scope "unsupported selector0/3");
 hl 0x602b;dad !q.bc;dad !q.bc;de(read_at 0x6000 !q.hl);hl(!q.hl+1);de((read_at 0x6002 !q.hl)lsl 8 lor !q.de);
 let old= !q.hl in hl !q.de;de old;
 need(!q.hl=List.assoc selector[1,0x600d;2,0x6013;4,0x6023])"fresh jump-table destination";
 if selector=1 then canonical 0x600d(B.Pli2_output 0x3d10)
 else if selector=4 then(
  c 1;call 0x6025 0x5dfa(fun()->
   q:={!q with R.bc=(!q.bc land 255)*257};push 0x5d7b !q.bc;sp:= !sp+1;
   canonical 0x5d7d(B.Pli2_output 0x3660);rar();
   if !q.flags.carry then raise(Outside_scope "unproved3B7A high predicate arm");
   call 0x5dc3 0x5951(fun()->
    hl(word_at 0x5947 0xad0d);c(!q.hl land 255);gateway 0x594b;
    call 0x594e 0x5930(fun()->
     call 0x5926 0x589e(fun()->
      a(read_at 0x588a 0xad08);rar();
      if !q.flags.carry then a 1 else(
       hl(word_at 0x5894 0xad0d);c(!q.hl land 255);canonical 0x5898(B.Pli2_output 0x059e);
       q:=Indexed_parent_397f.less_eight !q));
     rar();if !q.flags.carry then raise(Outside_scope "unproved3726/36E0 route")));
   hl 0;dad !sp;a(read_at 0x5dca !q.hl);rar();
   if not !q.flags.carry then raise(Outside_scope "unproved3B7A low frame0 arm");
   hl(word_at 0x5dcf 0xad0c);c(!q.hl land 255);canonical 0x5dd3(B.Pli2_output 0x7c22);
   sp:= !sp+1))
 else(
  c 1;call 0x6015 0x5f0f(fun()->
   sp:= !sp-1;q:={!q with R.bc=(!q.bc land 255)*257};push 0x5e29 !q.bc;sp:= !sp+1;
   canonical 0x5e2b(B.Pli2_output 0x3660);rar();
   if !q.flags.carry then raise(Outside_scope "unproved3C27 high predicate arm");
   hl(word_at 0x5eaa 0xad10);c(!q.hl land 255);gateway 0x5eae;
   hl 0;dad !sp;c(read_at 0x5eb5 !q.hl);push 0x5eb6 !q.bc;
   hl(word_at 0x5eb7 0xad0e);c(!q.hl land 255);canonical 0x5ebb(B.Pli2_output 0x3790);
   q:={!q with R.bc= !q.hl};de((!q.de land 0xff00)lor 4);
   staged 0x5ec2 0x5a2e(Stack_argument_382e.prepare ~allow_single_forward:true ~observe_read bridge ~call_site:0x5ec2);
   canonical 0x5ec5(B.Pli2_output 0x3bfb);rar();
   if not !q.flags.carry then raise(Outside_scope "unproved3C27 second predicate arm");
   hl(word_at 0x5ecc 0xad0c);c(!q.hl land 255);canonical 0x5ed0(B.Pli2_output 0x7c22);
   hl(pop 0x5f0e)));
 let pc=pop 0x6035 in need(pc=0x42b4&& !sp=entry.sp+2)"software RET consumer";
 let state=A.machine entry !q !sp pc in
 let expected=preview state in
 let validate(r:Runner.host_program_result)=if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)then Error"3DE4 ordered composition"else Ok()in
 {B.result={Pli80_host.Acquisition_family.returned= !q;field=None};program={effects=List.rev !effects;next_state=state;validate;on_commit=ignore};state;journal=List.rev !journal;
  logical_writes=List.filter_map(fun(w:B.write)->if w.kind="logical"then Some(w.address,w.value)else None)(List.rev !journal)}
