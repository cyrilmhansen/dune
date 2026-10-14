[@@@warning "-4-40-41-42"]
(* Selected +6726/+667A front and its complete +21AE predicate.
   Neither operation executes an unsupported gateway. *)
module B=Acquisition_family_bridge
module A=Acquisition_parent_bridge
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
let prepare ?(predicate=false) ?(observe_read=(fun _ _ _->())) bridge (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 let need c s=if not c then invalid_arg("k216 nested front: "^s)in
 need(entry.pc=(if predicate then 0x43ae else 0x8926)&&entry.sp>=0xb240&&entry.sp<=0xfff0)"entry/frame";
 let memory=S.of_bytes(boundary.copy_memory())in
 List.iter(fun(a,b)->for off=a to b-1 do need(S.read memory(off+0x2200)=Char.code(Bytes.get bridge.B.pli2 off))"code"done)
  (if predicate then [0x21ae,0x21cd]else[0x6726,0x6732;0x667a,0x6694;0x21ae,0x21cd]);
 if not predicate then need(S.word memory entry.sp=0x89e1&&S.word memory(entry.sp+2)=0x8f4a&&S.word memory(entry.sp+4)=0x42b4)"hardware/software ancestry";
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
 let sub value=let flags=R.comparison !q.a value in q:={!q with R.a=(!q.a-value)land 255;flags}in
 let sbb_self()=let cy= !q.flags.carry in let value=if cy then 255 else 0 in
  q:={!q with R.a=value;flags={R.sign=cy;zero=not cy;parity=true;auxiliary_carry=not cy;carry=cy}}in
 let psw f=2 lor(if f.R.sign then 128 else 0)lor(if f.zero then 64 else 0)lor(if f.auxiliary_carry then 16 else 0)lor(if f.parity then 4 else 0)lor(if f.carry then 1 else 0)in
 let predicate_body()=
  hl 0xad2a;put "logical" 0x43b1 !q.hl(!q.bc land 255);
  hl(word_at 0x43b2 0xad2a);c(!q.hl land 255);canonical 0x43b6(B.Pli2_output 0x047d);
  put "logical" 0x43b9 0xad2a !q.a;
  sub 1;sbb_self();a(!q.a lxor 255);push 0x43c0(!q.a lsl 8 lor psw !q.flags);
  a 8;hl 0xad2a;sub(read_at 0x43c6 !q.hl);sbb_self();a(!q.a lxor 255);
  q:={!q with R.bc=pop 0x43c9};c(!q.bc lsr 8);
  let old= !q.a and v= !q.bc land 255 in let value=old land v in
  q:={!q with R.a=value;flags={(R.comparison value 0)with carry=false;auxiliary_carry=(old lor v)land 8<>0}}
 in
 let pc=if predicate then(predicate_body();pop 0x43cc)else(
  hl(word_at 0x8926 0xad0f);c(!q.hl land 255);hl(word_at 0x892a 0xad0d);
  let old= !q.hl in hl !q.de;de old;
  push 0x892e 0x8931;
  de((!q.de land 255)*257);push 0x887b !q.de;sp:= !sp+1;
  q:={!q with R.bc=(!q.bc land 255)*257};push 0x887e !q.bc;sp:= !sp+1;
  hl 0;dad !sp;c(read_at 0x8884 !q.hl);
  call 0x8885 0x43cc predicate_body;
  rar();need !q.flags.carry "unproved carry-clear +66A0 route";
  hl 1;dad !sp;c(read_at 0x8890 !q.hl);push 0x8891 0x8894;0x41b5)in
 let state=A.machine entry !q !sp pc in let expected=preview state in
 let validate(r:Runner.host_program_result)=if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)then Error"nested front ordered composition"else Ok()in
 {B.result={Pli80_host.Acquisition_family.returned= !q;field=None};program={effects=List.rev !effects;next_state=state;validate;on_commit=ignore};state;journal=List.rev !journal;
  logical_writes=List.filter_map(fun(w:B.write)->if w.kind="logical"then Some(w.address,w.value)else None)(List.rev !journal)}
