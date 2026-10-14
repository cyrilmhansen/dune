[@@@warning "-4-40-41-42"]
(* Selected k84 software handler; k27 extension composes existing staged operations. *)
module B=Acquisition_family_bridge
module A=Acquisition_parent_bridge
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
let prepare ?(observe_read=(fun _ _ _->())) bridge (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 let need c s=if not c then invalid_arg("selected k84: "^s)in
 need(entry.pc=0x6516&&entry.sp>=0xb240&&entry.sp<=0xfff0)"entry/frame";
 let memory=S.of_bytes(boundary.copy_memory())in
 let ranges=[0x4316,0x433a;0x4287,0x4316;0x3752,0x376c;0x3731,0x373c;0x369f,0x36b4;0x360b,0x3613]in
 List.iter(fun(a,b)->for off=a to b-1 do need(S.read memory(off+0x2200)=Char.code(Bytes.get bridge.B.pli2 off))"code/table"done)ranges;
 need(S.word memory entry.sp=0x42b4)"software continuation";
 let sentinel=S.word memory 0x2155 in
 need(not(sentinel>=entry.sp-64&&sentinel<entry.sp+2)&&not(List.exists(fun(a,b)->sentinel>=a+0x2200&&sentinel<b+0x2200)ranges))"own frame/code/table alias";
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
 a(read_at 0x6516 0xad0a);q:={!q with R.flags=R.comparison !q.a 1};need !q.flags.zero "unsupported non1 software selector";
 call 0x651e 0x6515(fun()->
  sp:= !sp-1;push 0x6488 !q.hl;
  hl(word_at 0x6489 0xad0c);c(!q.hl land 255);canonical 0x648d(B.Pli2_output 0x3790);
  let old= !q.hl in hl !q.de;de old;hl 1;dad !sp;
  put "logical" 0x6495 !q.hl(!q.de land 255);hl(!q.hl+1);put "logical" 0x6497 !q.hl(!q.de lsr 8);
  a(!q.de lsr 8);q:={!q with R.flags=R.comparison !q.a 0};need !q.flags.zero "unproved nonzero mapped high byte";
  if !q.flags.zero then(
   hl 0;dad !sp;put "logical" 0x64a2 !q.hl 0;
   let rec scan budget=
    need(budget>0)"scan termination";
    a 7;hl 0;dad !sp;q:={!q with R.flags=R.comparison !q.a(read_at 0x64aa !q.hl)};
    if not !q.flags.carry then(
     hl 0;dad !sp;c(read_at 0x64b2 !q.hl);q:={!q with R.bc= !q.bc land 255};hl 0x580b;dad !q.bc;
     push 0x64b9 !q.hl;hl 3;dad !sp;hl((!q.hl land 0xff00)lor read_at 0x64be !q.hl);
     q:={!q with R.bc=pop 0x64bf};a(read_at 0x64c0 !q.bc);q:={!q with R.flags=R.comparison !q.a(!q.hl land 255)};
     need(not !q.flags.zero)"unproved matched table arm";
     hl 0;dad !sp;let old=read_at 0x64fa !q.hl in let value=(old+1)land 255 in
     q:={!q with R.flags={(R.comparison value 0)with carry= !q.flags.carry;auxiliary_carry=old land 15=15}};
     put "logical" 0x64fa !q.hl value;need(not !q.flags.zero)"unproved wrapped scan";scan(budget-1))in scan 9);
  call 0x64fe 0x595c(fun()->
   hl(word_at 0x5952 0xad0e);c(!q.hl land 255);canonical 0x5956(B.Pli2_output 0x1fb5);
   call 0x5959 0x593b(fun()->
    call 0x5931 0x58b3(fun()->
     a(read_at 0x589f 0xad08);rar();if !q.flags.carry then a 1 else(
      hl(word_at 0x58a9 0xad0e);c(!q.hl land 255);canonical 0x58ad(B.Pli2_output 0x059e);q:=Indexed_parent_397f.less_eight !q));
    rar();need(not !q.flags.carry)"unproved +3731 error branch"));
  hl 1;dad !sp;de((!q.de land 0xff00)lor read_at 0x6505 !q.hl);hl(!q.hl+1);de(read_at 0x6507 !q.hl lsl 8 lor(!q.de land 255));
  c 2;canonical 0x650a(B.Pli2_output 0x8072);
  q:={!q with R.bc=0x5824};canonical 0x6510(B.Pli2_output 0x8248);
  sp:= !sp+1;hl(pop 0x6514));
 call 0x6536 0x596b(fun()->canonical 0x595d(B.Pli2_output 0x3660);rar();need(not !q.flags.carry)"unproved +375D diagnostic branch");
 let pc=pop 0x6539 in need(pc=0x42b4&& !sp=entry.sp+2)"software RET consumer";
 let state=A.machine entry !q !sp pc in let expected=preview state in
 let validate(r:Runner.host_program_result)=if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)then Error"selected k84 ordered composition"else Ok()in
 {B.result={Pli80_host.Acquisition_family.returned= !q;field=None};program={effects=List.rev !effects;next_state=state;validate;on_commit=ignore};state;journal=List.rev !journal;
  logical_writes=List.filter_map(fun(w:B.write)->if w.kind="logical"then Some(w.address,w.value)else None)(List.rev !journal)}
