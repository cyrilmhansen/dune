[@@@warning "-4-40-41-42"]
(* k27 private-byte prefix and return-side segment; middle remains guest. *)
module B=Acquisition_family_bridge
module A=Acquisition_parent_bridge
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
let prepare ?(tail=false) ?(observe_read=(fun _ _ _->())) bridge (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 let need c s=if not c then invalid_arg("k27 segments: "^s)in
 need(entry.pc=(if tail then 0x4548 else 0x44ea)&&entry.sp>=0xb240&&entry.sp<=0xfff0)"entry/frame";
 let memory=S.of_bytes(boundary.copy_memory())in
 List.iter(fun(a,b)->for off=a to b-1 do need(S.read memory(off+0x2200)=Char.code(Bytes.get bridge.B.pli2 off))"code"done)
  (if tail then[0x2348,0x2352]else[0x22ea,0x2303;0x2325,0x232c]);
 need(S.word memory(entry.sp+(if tail then 1 else 0))=0x42b4)"software continuation";
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
 let pc=if tail then(
  hl 0;dad !sp;a(read_at 0x454c !q.hl);put "logical" 0x454d 0xad08 !q.a;
  sp:= !sp+1;let pc=pop 0x4551 in need(pc=0x42b4)"software RET consumer";pc
 )else(
  sp:= !sp-1;a(read_at 0x44eb 0xad08);hl 0;dad !sp;put "logical" 0x44f2 !q.hl !q.a;
  hl 0xad08;put "logical" 0x44f6 !q.hl 0;
  hl(word_at 0x44f8 0xad0d);c(!q.hl land 255);
  staged 0x44fc 0x43ae(K216_nested_front.prepare ~predicate:true ~observe_read bridge);
  rar();need(not !q.flags.carry)"unproved +2303 carry-set route";
  hl(word_at 0x4525 0xad0d);c(!q.hl land 255);push 0x4529 0x452c;0x41b5)in
 let state=A.machine entry !q !sp pc in let expected=preview state in
 let validate(r:Runner.host_program_result)=if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)then Error"k27 ordered segments"else Ok()in
 {B.result={Pli80_host.Acquisition_family.returned= !q;field=None};program={effects=List.rev !effects;next_state=state;validate;on_commit=ignore};state;journal=List.rev !journal;
  logical_writes=List.filter_map(fun(w:B.write)->if w.kind="logical"then Some(w.address,w.value)else None)(List.rev !journal)}
