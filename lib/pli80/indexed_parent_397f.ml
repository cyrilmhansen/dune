[@@@warning "-4-40-41-42"]
(* Selector15 parent only: scoped canonical composition, no interception. *)
module B=Acquisition_family_bridge
module A=Acquisition_parent_bridge
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
let less_eight (q:R.returned)=
 let borrowed=q.a<8 in
 let v=if borrowed then 255 else 0 in
 let f=R.comparison v 0 in
 {q with R.a=v;flags={f with carry=borrowed;auxiliary_carry=not borrowed}}
let prepare ?(observe_read=(fun _ _ _->())) bridge ~call_site (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 let need c s=if not c then invalid_arg("397F: "^s)in
 need(entry.pc=0x5b7f&&entry.sp>=0xb220&&entry.sp<=0xfffa)"entry/frame";
 let memory=S.of_bytes(boundary.copy_memory())in
 let code a b=for o=a to b-1 do need(S.read memory(o+0x2200)=Char.code(Bytes.get bridge.B.pli2 o))"code"done in
 List.iter(fun(a,b)->code a b)[0x397f,0x398f;0x3acc,0x3aee;0x3b62,0x3b70;0x373c,0x3747;0x371b,0x3726;0x3675,0x368a;0x8386,0x838e;0x3b3c,0x3b62];
 need(S.read memory call_site=0xcd&&S.word memory(call_site+1)=0x5b7f&&S.word memory entry.sp=call_site+3)"CALL continuation";
 let sentinel=S.word memory 0x2155 in
 need(not(sentinel>=0xad50&&sentinel<0xad55)&&not(sentinel>=0xae47&&sentinel<0xae49))"scratch/sentinel alias";
 need(not(List.exists(fun(a,b)->sentinel>=a+0x2200&&sentinel<b+0x2200)[0x397f,0x398f;0x3acc,0x3aee;0x3b62,0x3b70;0x373c,0x3747;0x371b,0x3726;0x3675,0x368a;0x8386,0x838e;0x3b3c,0x3b62]))"own code/sentinel alias";
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
 let rar()=let v= !q.a in q:={!q with R.a=(v lsr 1)lor(if !q.flags.carry then 128 else 0);flags={!q.flags with carry=v land 1<>0}}in
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
 (* Publication-epoch selector15 arm only; the actual table must still select it. *)
 hl(word_at 0x5b7f 0xad0a);c(!q.hl land 255);q:={!q with R.bc= !q.bc land 255};
 need(!q.bc=15)"unsupported selector";hl 0x5d3c;dad !q.bc;dad !q.bc;
 de(read_at 0x5b8a !q.hl);hl(!q.hl+1);de((read_at 0x5b8c !q.hl)lsl 8 lor !q.de);
 let old= !q.hl in hl !q.de;de old;need(!q.hl=0x5ccc)"selector15 table";
 call 0x5ccc 0x5946(fun()->
  hl(word_at 0x593c 0xad0c);c(!q.hl land 255);
  (* This complete canonical gateway preparation validates the original k23
     state domain. It never invokes a live interceptor. *)
  canonical 0x5940(B.Pli2_output 0x1fb5);
  call 0x5943 0x5925(fun()->
   call 0x591b 0x5889(fun()->
    a(read_at 0x5875 0xad08);rar();
    if !q.flags.carry then a 1 else(
     hl(word_at 0x587f 0xad0c);c(!q.hl land 255);
     canonical 0x5883(B.Pli2_output 0x059e);
     q:=less_eight !q));
   rar();need(not !q.flags.carry)"unproved 36E0 emission route"));
 c 1;push 0x5cd1 !q.bc;
 hl(word_at 0x5cd2 0xad0d);c(!q.hl land 255);canonical 0x5cd6(B.Pli2_output 0x3790);
 hl((!q.hl+1)land 65535);call 0x5cda 0xa58d(fun()->q:=Stack_argument_382e.negation !q);
 q:={!q with R.bc= !q.hl};de((!q.de land 0xff00)lor 4);
 staged 0x5ce1 0x5a2e(Stack_argument_382e.prepare bridge ~call_site:0x5ce1);
 de((!q.de land 0xff00)lor 4);c 7;canonical 0x5ce8(B.Pli2_output 0x7b99);
 hl(word_at 0x5d62 0xad0a);hl(!q.hl land 255);q:={!q with R.bc=0x579b};dad !q.bc;
 a(read_at 0x5d6b !q.hl);put"logical"0x5d6c 0xad06 !q.a;
 let pc=pop 0x5d6f in need(pc=call_site+3&& !sp=entry.sp+2)"original RET";
 let state=A.machine entry !q !sp pc in
 let expected=preview state in
 let validate(r:Runner.host_program_result)=if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)then Error"397F ordered composition"else Ok()in
 {B.result={Pli80_host.Acquisition_family.returned= !q;field=None};program={effects=List.rev !effects;next_state=state;validate;on_commit=ignore};state;journal=List.rev !journal;
  logical_writes=List.filter_map(fun(w:B.write)->if w.kind="logical"then Some(w.address,w.value)else None)(List.rev !journal)}
