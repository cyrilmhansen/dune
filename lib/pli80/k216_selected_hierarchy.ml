[@@@warning "-4-40-41-42"]
module B=Acquisition_family_bridge
module A=Acquisition_parent_bridge
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
module Q=Pli80_host.K123_child_7d05_front
let prepare ?(child=false) ?(observe_read=(fun _ _ _->())) bridge (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 let need c s=if not c then invalid_arg("selected k216 hierarchy: "^s)in
 let first=K216_nested_front.prepare ~at_667a:child ~observe_read bridge boundary in
 let preview_first=match boundary.preview_host_program first.program with Ok p->p|Error e->invalid_arg e in
 let memory=S.of_bytes preview_first.memory in
 for off=0x6694 to 0x669f do need(S.read memory(off+0x2200)=Char.code(Bytes.get bridge.B.pli2 off))"child return code"done;
 let q=ref(A.logical first.state) and sp=ref first.state.sp and effects=ref(List.rev first.program.effects)and journal=ref(List.rev first.journal)in
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
 let rar()=q:=Software_selector_3de4.rotate !q in
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
 let prior=List.rev !effects in
 let view:Runner.instruction_boundary={state=first.state;read_memory=read;copy_memory=(fun()->S.copy memory);dma=preview_first.dma;copy_filesystem=(fun()->Cpm.Filesystem.copy preview_first.filesystem);preview_host_program=(fun p->boundary.preview_host_program{p with effects=prior@p.effects})}in
 let p=K27_gateway_transaction.prepare ~observe_read bridge ~call_site:0x8891 view in
 effects:=List.rev_append p.program.effects !effects;journal:=List.rev_append p.journal !journal;
 q:=A.logical p.state;sp:=p.state.sp;ignore(preview p.state);need(p.state.pc=0x8894)"k27 hardware return";
 hl 0;dad !sp;de((!q.de land 0xff00)lor read_at 0x8898 !q.hl);c 2;
 push 0x889b 0x889e;
 let r=Pli80_host.K123_parent_7d31.run memory ~pli2:bridge.B.pli2
  ~entry:{Q.pc=0x9f31;sp= !sp;a= !q.a;bc= !q.bc;de= !q.de;hl= !q.hl;flags= !q.flags}
  ~observe:(function Q.Read _->()|Q.Write(addr,value)->put "inherited" (-1) addr value)in
 need(r.pc=0x889e&&r.sp= !sp+2)"7D31 hardware return";
 q:={R.a=r.a;bc=r.bc;de=r.de;hl=r.hl;flags=r.flags};sp:=r.sp;
 hl(pop 0x889e);let pc=pop 0x889f in need(pc=0x8931)"667A hardware RET";
 let pc=if child then pc else pop 0x8931 in
 need(pc=(if child then 0x8931 else 0x89e1)&& !sp=entry.sp+2)"parent continuation ownership";
 let state=A.machine entry !q !sp pc in let expected=preview state in
 let validate(r:Runner.host_program_result)=if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)then Error"selected hierarchy complete composition"else Ok()in
 {B.result={Pli80_host.Acquisition_family.returned= !q;field=None};program={effects=List.rev !effects;next_state=state;validate;on_commit=ignore};state;journal=List.rev !journal;
  logical_writes=List.filter_map(fun(w:B.write)->if w.kind="logical"then Some(w.address,w.value)else None)(List.rev !journal)}
let selected ?(observe_read=(fun _ _ _->())) bridge (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 let first=K216_handler_return.front ~observe_read bridge boundary in
 let before=match boundary.preview_host_program first.program with Ok p->p|Error e->invalid_arg e in
 let view:Runner.instruction_boundary={state=first.state;read_memory=(fun a->Char.code(Bytes.get before.memory a));copy_memory=(fun()->Bytes.copy before.memory);dma=before.dma;copy_filesystem=(fun()->Cpm.Filesystem.copy before.filesystem);preview_host_program=(fun p->boundary.preview_host_program{p with effects=first.program.effects@p.effects})}in
 let middle=prepare ~observe_read bridge view in
 let result=match view.preview_host_program middle.program with Ok p->p|Error e->invalid_arg e in
 let need c s=if not c then invalid_arg("selected6792: "^s)in
 List.iter(fun(a,b)->for off=a to b-1 do need(Char.code(Bytes.get result.memory(off+0x2200))=Char.code(Bytes.get bridge.B.pli2 off))"return code"done)[0x67e1,0x67e4;0x6820,0x6821];
 need(middle.state.pc=0x89e1&&middle.state.sp=entry.sp)"6726 hardware return";
 let lo=Char.code(Bytes.get result.memory entry.sp)and hi=Char.code(Bytes.get result.memory(entry.sp+1))in
 observe_read 0x8a20 entry.sp lo;observe_read 0x8a20(entry.sp+1)hi;
 let pc=lo lor(hi lsl 8)in need(pc=0x8f4a)"original6792 hardware word";
 let state={middle.state with Runner.pc;sp=entry.sp+2}in
 {middle with state;program={middle.program with effects=first.program.effects@middle.program.effects;next_state=state};journal=first.journal@middle.journal;logical_writes=first.logical_writes@middle.logical_writes}
