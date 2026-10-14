[@@@warning "-4-40-41-42"]
(* Scoped +382E composition. No live interception; canonical children keep
   their own unchanged guards and staged service implementation. *)
module B=Acquisition_family_bridge
module A=Acquisition_parent_bridge
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
let negation (q:R.returned)=
 let low=q.hl land 255 and high=q.hl lsr 8 in
 let borrow=if low=0 then 0 else 1 in
 let lo=(-low)land 255 and hi=(-high-borrow)land 255 in
 let f=R.comparison hi 0 in
 {q with R.a=hi;hl=hi lsl 8 lor lo;
  flags={f with auxiliary_carry=0>=(high land 15)+borrow;carry=0<high+borrow}}
let prepare ?(allow_single_forward=false) ?(observe_read=(fun _ _ _->())) bridge ~call_site (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 let need c s=if not c then invalid_arg("382E: "^s)in
 need(entry.pc=0x5a2e&&entry.sp>=0xb220&&entry.sp<=0xfffa)"entry/frame";
 let memory=S.of_bytes(boundary.copy_memory())in
 let code a b=for o=a to b-1 do need(S.read memory(o+0x2200)=Char.code(Bytes.get bridge.B.pli2 o))"code"done in
 List.iter(fun(a,b)->code a b)[0x382e,0x38b1;0x8386,0x838e;0x83a3,0x83a9;0x80b2,0x80d0];
 need(S.read memory call_site=0xcd&&S.word memory(call_site+1)=0x5a2e&&S.word memory entry.sp=call_site+3)"CALL continuation";
 let sentinel=S.word memory 0x2155 in
 need(not(sentinel>=0xad50&&sentinel<0xad55)&&not(sentinel>=0xae47&&sentinel<0xae49))"scratch/sentinel alias";
 need(not(List.exists(fun(a,b)->sentinel>=a+0x2200&&sentinel<b+0x2200)[0x382e,0x38b1;0x8386,0x838e;0x83a3,0x83a9;0x80b2,0x80d0]))"own code/sentinel alias";
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
 let canonical site operation=
  let target=fst(B.bounds operation)+(if B.resident_operation operation then 0x100 else 0x2200)in
  push site(site+3);
  let state=A.machine entry !q !sp target in
  let prior=List.rev !effects in
  let before=preview state in
  let view:Runner.instruction_boundary={state;read_memory=read;copy_memory=(fun()->Bytes.init 65536(fun i->Char.chr(read i)));dma=before.dma;
   copy_filesystem=(fun()->Cpm.Filesystem.copy before.filesystem);
   preview_host_program=(fun p->boundary.preview_host_program{p with effects=prior@p.effects})}in
  let p=B.prepare bridge operation ~call:(B.internal_call bridge operation site)
   ~origin:(B.origin(if B.resident_operation operation then "PLI.COM"else"PLI2.OVL")(fst(B.bounds operation)))view in
  effects:=List.rev_append p.program.effects !effects;
  journal:=List.rev_append(List.map(fun(w:B.write)->{w with depth=w.depth+1})p.journal)!journal;
  sp:=p.state.sp;q:=A.logical p.state;ignore(preview p.state)in
 (* Entry's separate caller word is consumed before any child. *)
 hl 0xad53;put"logical"0x5a31 !q.hl(!q.de land 255);hl(!q.hl-1);
 put"logical"0x5a33 !q.hl(!q.bc lsr 8);hl(!q.hl-1);put"logical"0x5a35 !q.hl(!q.bc land 255);hl(!q.hl-1);
 de(pop 0x5a37);q:={!q with R.bc=pop 0x5a38};put"logical"0x5a39 !q.hl(!q.bc land 255);push 0x5a3a !q.de;
 c 1;a(read_at 0x5a3d 0xad51);
 call 0x5a40 0xa5a8(fun()->let v= !q.a in a((v lsl 1 land 255)lor(v lsr 7));
  let f=R.comparison 0 0 in q:={!q with R.bc= !q.bc land 0xff00;flags={f with carry=v land 128<>0}});
 rar();
 if !q.flags.carry then(hl(word_at 0x5a47 0xad51);call 0x5a4a 0xa58d(fun()->q:=negation !q);
  put"logical"0x5a4d 0xad51(!q.hl land 255);put"logical"0x5a4d 0xad52(!q.hl lsr 8);
  a(read_at 0x5a50 0xad50);a(!q.a lxor 255);put"logical"0x5a54 0xad50 !q.a);
 a(read_at 0x5a57 0xad53);de 0xad51;canonical 0x5a5d(B.Resident_reader Pli80_host.Resident_reader.Memory_zero);
 if !q.flags.carry then(
  need allow_single_forward "unobserved bounded-loop arm";
  hl(word_at 0x5a63 0xad51);let old= !q.hl in hl !q.de;de old;hl 0xad54;
  put"logical"0x5a6a !q.hl(!q.de land 255);
  a 0;hl 0xad54;let counter=read_at 0x5a70 !q.hl in q:={!q with R.flags=R.comparison !q.a counter};
  need(counter=1)"single forward counter domain";
  hl 0xad54;let old=read_at 0x5a77 !q.hl in let value=(old-1)land 255 in
  let f=R.comparison value 0 in q:={!q with R.flags={f with carry= !q.flags.carry;auxiliary_carry=old land 15<>0}};
  put"logical"0x5a77 !q.hl value;
  a(read_at 0x5a78 0xad50);rar();need !q.flags.carry "unobserved backward7D85 route";
  c 4;canonical 0x5a81(B.Pli2_output 0x7d47);
  a 0;hl 0xad54;let remaining=read_at 0x5a70 !q.hl in q:={!q with R.flags=R.comparison !q.a remaining};
  need(remaining=0)"forward child counter alias")else(
 a(read_at 0x5a92 0xad50);rar();
 if not !q.flags.carry then(hl(word_at 0x5a99 0xad51);call 0x5a9c 0xa58d(fun()->q:=negation !q);
  put"logical"0x5a9f 0xad51(!q.hl land 255);put"logical"0x5a9f 0xad52(!q.hl lsr 8));
 hl(word_at 0x5aa2 0xad51);let old= !q.hl in hl !q.de;de old;c 0;
 canonical 0x5aa8(B.Pli2_output 0x8072);
 c 0;call 0x5aad 0xa2cf(fun()->
  hl 0xae47;put"logical"0xa2b5 !q.hl(!q.bc land 255);
  canonical 0xa2b6(B.Pli2_output 0x73ca);
  a(read_at 0xa2b9 0xae47);q:={!q with R.flags=R.comparison !q.a 6};need(not !q.flags.zero)"unobserved index6 publication";
  hl(word_at 0xa2c6 0xae47);let old= !q.hl in hl !q.de;de old;c 9;
  canonical 0xa2cc(B.Pli2_output 0x75ce)));
 let pc=pop 0x5ab0 in need(pc=call_site+3&& !sp=entry.sp+4)"relocated RET/argument consumption";
 let state=A.machine entry !q !sp pc in
 let expected=preview state in
 let validate(r:Runner.host_program_result)=if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)then Error"382E ordered composition"else Ok()in
 {B.result={Pli80_host.Acquisition_family.returned= !q;field=None};program={effects=List.rev !effects;next_state=state;validate;on_commit=ignore};state;journal=List.rev !journal;
  logical_writes=List.filter_map(fun(w:B.write)->if w.kind="logical"then Some(w.address,w.value)else None)(List.rev !journal)}
