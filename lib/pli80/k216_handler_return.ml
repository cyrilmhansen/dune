[@@@warning "-4-40-41-42"]
(* Complete return-side k216 segment. +6792 is deliberately outside this law. *)
module B=Acquisition_family_bridge
module A=Acquisition_parent_bridge
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
let scale memory ~(entry:R.returned) ~observe_read =
 let read site address=let value=S.read memory address in observe_read site address value;value in
 let add left right=
  let sum=left+right in let value=sum land 255 in let f=R.comparison value 0 in
  value,{f with R.carry=sum>255;auxiliary_carry=(left land 15)+(right land 15)>15}in
 let value=read 0x8a21 0xad0a in
 let value,_=add value value in let value,_=add value value in
 let value,flags=add value(read 0x8a29 0xad0a)in
 {entry with R.a=value;hl=0xad0a;flags}
let prepare ?(observe_read=(fun _ _ _->())) bridge (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 let need c s=if not c then invalid_arg("k216 return-side: "^s)in
 need(entry.pc=0x8f4a&&entry.sp>=0xb220&&entry.sp<=0xfffc)"entry/stack";
 let memory=S.of_bytes(boundary.copy_memory())in
 List.iter(fun(a,b)->for off=a to b-1 do need(S.read memory(off+0x2200)=Char.code(Bytes.get bridge.B.pli2 off))"code"done)[0x6d47,0x6d5a;0x6821,0x682b];
 need(S.word memory entry.sp=0x42b4)"software continuation";
 let sentinel=S.word memory 0x2155 in
 need(not(List.exists(fun(a,b)->sentinel>=a&&sentinel<b)[0x8f47,0x8f5a;0x8a21,0x8a2b;entry.sp-4,entry.sp+2]))"sentinel/code/frame alias";
 let q=ref(A.logical entry) and sp=ref entry.sp and effects=ref[]and journal=ref[]in
 let put kind writer address value=
  S.write memory address value;effects:=Runner.Memory_write(address,value)::!effects;
  journal:={B.address;value;writer;depth=0;kind}::!journal in
 let read=S.read memory in
 let hl v=q:={!q with R.hl=v}in
 let c v=q:={!q with R.bc=(!q.bc land 0xff00)lor v}in

 let push site v=put"compatibility"site(!sp-1)(v lsr 8);put"compatibility"site(!sp-2)(v land 255);sp:= !sp-2 in
 let read_at site address=let v=read address in observe_read site address v;v in
 let word_at site address=let lo=read_at site address in let hi=read_at site(address+1)in lo lor(hi lsl 8)in
 let pop site=let v=word_at site !sp in sp:= !sp+2;v in
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
 call 0x8f4a 0x8a2a(fun()->q:=scale memory ~entry:!q ~observe_read);
 c !q.a;q:={!q with R.bc= !q.bc land 255};hl 0x87c5;dad !q.bc;q:={!q with R.bc= !q.hl};
 canonical 0x8f56(B.Pli2_output 0x8248);
 let pc=pop 0x8f59 in need(pc=0x42b4&& !sp=entry.sp+2)"software RET";
 let state=A.machine entry !q !sp pc in
 let expected=preview state in
 let validate(r:Runner.host_program_result)=if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)then Error"k216 ordered return-side composition"else Ok()in
 {B.result={Pli80_host.Acquisition_family.returned= !q;field=None};program={effects=List.rev !effects;next_state=state;validate;on_commit=ignore};state;journal=List.rev !journal;
  logical_writes=List.filter_map(fun(w:B.write)->if w.kind="logical"then Some(w.address,w.value)else None)(List.rev !journal)}

(* The separately executable +6792 front stops at the actual +6726 entry.
   It does not execute or claim that unresolved child. *)
let front ?(observe_read=(fun _ _ _->())) bridge (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 let need c s=if not c then invalid_arg("k216 +6792 front: "^s)in
 need(entry.pc=0x8992&&entry.sp>=0xb220&&entry.sp<=0xfffa)"entry/stack";
 let m=S.of_bytes(boundary.copy_memory())in
 List.iter(fun(a,b)->for off=a to b-1 do need(S.read m(off+0x2200)=Char.code(Bytes.get bridge.B.pli2 off))"code/table"done)[0x6792,0x67a2;0x67de,0x67e4;0x680e,0x6821;0x6d47,0x6d4a];
 need(S.word m entry.sp=0x8f4a&&S.word m(entry.sp+2)=0x42b4)"hardware/software ownership";
 let read site addr=let v=S.read m addr in observe_read site addr v;v in
 let word site addr=let lo=read site addr in let hi=read site(addr+1)in lo lor(hi lsl 8)in
 let q=ref(A.logical entry)in
 q:={!q with R.hl=word 0x8992 0xad0a};q:={!q with R.bc= !q.hl land 255;hl=0x8a0e};
 need(!q.bc<9)"table index";
 let dad v=let sum= !q.hl+v in q:={!q with R.hl=sum land 65535;flags={!q.flags with carry=sum>65535}}in
 dad !q.bc;dad !q.bc;
 let low=read 0x899d !q.hl in q:={!q with R.hl=(!q.hl+1)land 65535};
 let target=low lor(read 0x899f !q.hl lsl 8)in let address= !q.hl in
 q:={!q with R.hl=target;de=address};need(target=0x89de)"unproved other selector arm";
 let journal=List.map(fun(address,value)->S.write m address value;
  {B.address;value;writer=0x89de;depth=0;kind="compatibility"})[entry.sp-1,0x89;entry.sp-2,0xe1]in
 let state=A.machine entry !q(entry.sp-2)0x8926 in
 let validate(r:Runner.host_program_result)=if r.memory=S.copy m&&r.services=[]&&r.dma=boundary.dma&&Cpm.Filesystem.equal r.filesystem(boundary.copy_filesystem())then Ok()else Error"k216 front boundary"in
 {B.result={Pli80_host.Acquisition_family.returned= !q;field=None};state;journal;logical_writes=[];
  program={effects=List.map(fun(w:B.write)->Runner.Memory_write(w.address,w.value))journal;next_state=state;validate;on_commit=ignore}}
