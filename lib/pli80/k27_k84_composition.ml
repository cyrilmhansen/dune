[@@@warning "-4-40-41-42"]
(* Selected k84 software handler; k27 extension composes existing staged operations. *)
module B=Acquisition_family_bridge
module A=Acquisition_parent_bridge
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
let counter memory ~(entry:R.returned) ~observe_read ~write =
 let old=S.read memory 0xae06 in observe_read 0x9bd7 0xae06 old;
 let value=(old+1)land 255 in let flags={(R.comparison value 0)with carry=entry.flags.carry;auxiliary_carry=old land 15=15}in
 write 0x9bdb 0xae06 value;write 0x9bde 0xae04 value;{entry with R.a=value;flags}
let prefix ?(complete=false) ?(observe_read=(fun _ _ _->())) bridge (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 let need c s=if not c then invalid_arg("k27 extended prefix: "^s)in
 let first=K27_handler_segments.prepare ~observe_read bridge boundary in
 let preview_first=match boundary.preview_host_program first.program with Ok p->p|Error e->invalid_arg e in
 let memory=S.of_bytes preview_first.memory in
 List.iter(fun(a,b)->for off=a to b-1 do need(S.read memory(off+0x2200)=Char.code(Bytes.get bridge.B.pli2 off))"code"done)[0x232c,0x2336;0x79d7,0x79e2];
 if complete then List.iter(fun(a,b)->for off=a to b-1 do need(S.read memory(off+0x2200)=Char.code(Bytes.get bridge.B.pli2 off))"complete segment code"done)
  [0x2336,0x2348;0x3675,0x368a;0x7aa3,0x7ac4;0x79be,0x79cc;0x80b2,0x80d0];
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
 let view:Runner.instruction_boundary={state=first.state;read_memory=read;copy_memory=(fun()->S.copy memory);dma=preview_first.dma;
  copy_filesystem=(fun()->Cpm.Filesystem.copy preview_first.filesystem);
  preview_host_program=(fun p->boundary.preview_host_program{p with effects=prior@p.effects})}in
 let transaction=Scanned_gateway_dependencies.gateway105 ~observe_read bridge ~call_site:0x4529 view in
 effects:=List.rev_append transaction.program.effects !effects;journal:=List.rev_append transaction.journal !journal;
 q:=A.logical transaction.state;sp:=transaction.state.sp;ignore(preview transaction.state);
 need(!sp=entry.sp-1&&transaction.state.pc=0x452c)"k105 return ownership";
 call 0x452c 0x9be1(fun()->q:=counter memory ~entry:!q ~observe_read ~write:(fun site addr value->put "logical" site addr value));
 hl(word_at 0x452f 0xad0c);c(!q.hl land 255);push 0x4533 0x4536;
 let pc=if not complete then 0x41b5 else(
  let invoke_existing target prepare=
   let state=A.machine entry !q !sp target in let prior=List.rev !effects in let before=preview state in
   let view:Runner.instruction_boundary={state;read_memory=read;copy_memory=(fun()->S.copy memory);dma=before.dma;
    copy_filesystem=(fun()->Cpm.Filesystem.copy before.filesystem);preview_host_program=(fun p->boundary.preview_host_program{p with effects=prior@p.effects})}in
   let p:B.prepared=prepare view in effects:=List.rev_append p.program.effects !effects;journal:=List.rev_append p.journal !journal;
   q:=A.logical p.state;sp:=p.state.sp;ignore(preview p.state);p.state.pc in
  need(invoke_existing 0x41b5(Scanned_gateway_dependencies.gateway84 ~observe_read bridge ~call_site:0x4533)=0x4536)"k84 hardware continuation";
  call 0x4536 0x5889(fun()->
   a(read_at 0x5875 0xad08);rar();if !q.flags.carry then a 1 else(
    hl(word_at 0x587f 0xad0c);c(!q.hl land 255);canonical 0x5883(B.Pli2_output 0x059e);q:=Indexed_parent_397f.less_eight !q));
  rar();need(not !q.flags.carry)"unproved k27 +36E0 error branch";
  call 0x4540 0x9cc3(fun()->
   a(read_at 0x9ca3 0xae04);q:={!q with R.flags=R.comparison !q.a 0};need !q.flags.zero "unproved k27 nonzero AE04";
   if !q.flags.zero then(c 2;call 0x9cad 0x9bcb(fun()->
    hl 0xae07;put "logical" 0x9bc1 !q.hl(!q.bc land 255);hl(word_at 0x9bc2 0xae07);
    let old= !q.hl in hl !q.de;de old;c 0xc1;canonical 0x9bc8(B.Pli2_output 0x7903)));
   a(read_at 0x9cb8 0xae05);put "logical" 0x9cbb 0xae06 !q.a;hl 0xae04;put "logical" 0x9cc1 !q.hl 0);
  c 2;call 0x4545 0xa2cf(fun()->
   hl 0xae47;put "logical" 0xa2b5 !q.hl(!q.bc land 255);canonical 0xa2b6(B.Pli2_output 0x73ca);
   a(read_at 0xa2b9 0xae47);q:={!q with R.flags=R.comparison !q.a 6};need(not !q.flags.zero)"unproved k27 index6 publication";
   hl(word_at 0xa2c6 0xae47);let old= !q.hl in hl !q.de;de old;c 9;canonical 0xa2cc(B.Pli2_output 0x75ce));
  let pc=invoke_existing 0x4548(K27_handler_segments.prepare ~tail:true ~observe_read bridge)in
  need(pc=0x42b4&& !sp=entry.sp+2)"k27 software continuation";pc)in
 let state=A.machine entry !q !sp pc in let expected=preview state in
 let validate(r:Runner.host_program_result)=if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)then Error"k27 composed prefix"else Ok()in
 {B.result={Pli80_host.Acquisition_family.returned= !q;field=None};program={effects=List.rev !effects;next_state=state;validate;on_commit=ignore};state;journal=List.rev !journal;
  logical_writes=List.filter_map(fun(w:B.write)->if w.kind="logical"then Some(w.address,w.value)else None)(List.rev !journal)}
