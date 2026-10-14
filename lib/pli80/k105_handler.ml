[@@@warning "-4-40-41-42"]
(* k105 software handler, with a scoped real +2269 operation. *)
module B=Acquisition_family_bridge
module A=Acquisition_parent_bridge
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
(* +77BF carrier publication; flags/registers other than HL are inherited. *)
let carrier memory ~(entry:R.returned) ~observe_read ~write =
 write 0x99c2 0xadf2(entry.bc lsr 8);write 0x99c4 0xadf1(entry.bc land 255);
 let lo=S.read memory 0xadf1 in observe_read 0x99c5 0xadf1 lo;
 let hi=S.read memory 0xadf2 in observe_read 0x99c5 0xadf2 hi;
 let hl=lo lor(hi lsl 8)in write 0x99c8 0xadef lo;write 0x99c8 0xadf0 hi;
 {entry with R.hl}
let prepare ?(observe_read=(fun _ _ _->())) bridge (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 let need c s=if not c then invalid_arg("k105 handler: "^s)in
 need(entry.pc=0x4552&&entry.sp>=0xb240&&entry.sp<=0xfff0)"entry/frame";
 let memory=S.of_bytes(boundary.copy_memory())in
 List.iter(fun(a,b)->for off=a to b-1 do need(S.read memory(off+0x2200)=Char.code(Bytes.get bridge.B.pli2 off))"code"done)
  [0x2352,0x2362;0x2269,0x22a2;0x21cd,0x21ed;0x16f8,0x16fb;0x77bf,0x77cc;0x7d05,0x7d47];
 need(S.word memory entry.sp=0x42b4)"software continuation";
 let sentinel=S.word memory 0x2155 in
 need(not(List.exists(fun(a,b)->sentinel>=a&&sentinel<b)
  [0xac9f,0xaca1;0xad2a,0xad2d;0xadef,0xadf3;0xae2d,0xae33;entry.sp-64,entry.sp+2;
   0x4552,0x4562;0x4469,0x44a2;0x43ae,0x43ed;0x38f8,0x38fb;0x99bf,0x99cc;0x9f05,0x9f47]))"own scratch/code/frame sentinel alias";

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
 hl(word_at 0x4552 0xad0c);c(!q.hl land 255);canonical 0x4556(B.Pli2_output 0x052c);
 let old= !q.hl in hl !q.de;de old;
 hl(word_at 0x455a 0xad0d);c(!q.hl land 255);
 call 0x455e 0x44a1(fun()->
  push 0x4469 !q.de;q:={!q with R.bc=(!q.bc land 255)*257};push 0x446b !q.bc;sp:= !sp+1;
  hl 0;dad !sp;c(read_at 0x4471 !q.hl);
  call 0x4472 0x43ec(fun()->
   hl 0xad2b;put "logical" 0x43d0 !q.hl(!q.bc land 255);
   hl(word_at 0x43d1 0xad2b);c(!q.hl land 255);
   staged 0x43d5 0x43ae(K216_nested_front.prepare ~predicate:true ~observe_read bridge);
   rar();need !q.flags.carry "unproved +21CD early-return route";
   hl(word_at 0x43df 0xad2b);c(!q.hl land 255);canonical 0x43e3(B.Pli2_output 0x052c);
   put "logical" 0x43e6 0xac9f(!q.hl land 255);put "logical" 0x43e6 0xaca0(!q.hl lsr 8);
   call 0x43e9 0x38fa(fun()->a 0));
  rar();need(not !q.flags.carry)"unproved +2269 +21ED branch";
  hl 1;dad !sp;c(read_at 0x448f !q.hl);hl((!q.hl+1)land 65535);
  q:={!q with R.bc=(read_at 0x4491 !q.hl lsl 8)lor(!q.bc land 255)};
  call 0x4492 0x99cb(fun()->q:=carrier memory ~entry:!q ~observe_read
   ~write:(fun site address value->put "logical" site address value));
  hl 0;dad !sp;de((!q.de land 0xff00)lor read_at 0x4499 !q.hl);c 4;
  call 0x449c 0x9f46(fun()->
   hl 0xae31;put "logical" 0x9f34 !q.hl(!q.de land 255);hl(!q.hl-1);put "logical" 0x9f36 !q.hl(!q.bc land 255);
   hl(word_at 0x9f37 0xae31);c(!q.hl land 255);canonical 0x9f3b(B.Pli2_output 0x052c);
   let old= !q.hl in hl !q.de;de old;hl(word_at 0x9f3f 0xae30);c(!q.hl land 255);
   call 0x9f43 0x9f30(fun()->
    hl 0xae2f;put "logical" 0x9f08 !q.hl(!q.de lsr 8);hl(!q.hl-1);put "logical" 0x9f0a !q.hl(!q.de land 255);
    hl(!q.hl-1);put "logical" 0x9f0c !q.hl(!q.bc land 255);
    a(read_at 0x9f0d 0xae2d);q:={!q with R.flags=R.comparison !q.a 4};need !q.flags.zero "unproved non4 generation selector";
    canonical 0x9f15(B.Pli2_output 0x7a17);
    hl(word_at 0x9f18 0xae2d);c(!q.hl land 255);canonical 0x9f1c(B.Pli2_output 0x73a7);
    hl(word_at 0x9f1f 0xae2d);let old= !q.hl in hl !q.de;de old;c 1;canonical 0x9f25(B.Pli2_output 0x75ce);
    hl(word_at 0x9f28 0xae2e);q:={!q with R.bc= !q.hl};canonical 0x9f2d(B.Pli2_output 0x785c)));
  sp:= !sp+1;hl(pop 0x44a0));
 let pc=pop 0x4561 in need(pc=0x42b4&& !sp=entry.sp+2)"software RET consumer";
 let state=A.machine entry !q !sp pc in let expected=preview state in
 let validate(r:Runner.host_program_result)=if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)then Error"k105 ordered composition"else Ok()in
 {B.result={Pli80_host.Acquisition_family.returned= !q;field=None};program={effects=List.rev !effects;next_state=state;validate;on_commit=ignore};state;journal=List.rev !journal;
  logical_writes=List.filter_map(fun(w:B.write)->if w.kind="logical"then Some(w.address,w.value)else None)(List.rev !journal)}
