[@@@warning "-4-40-41-42"]
(* New descriptor domains on copied state. Installed gateway logic is untouched. *)
module B=Acquisition_family_bridge
module A=Acquisition_parent_bridge
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
exception Outside_scope of string
let scope c s=if not c then raise(Outside_scope s)
let predicate ?(k105_fallback=false) ?(observe_read=(fun _ _ _->())) bridge ~call_site (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 let need c s=if not c then invalid_arg("scanned predicate: "^s)in
 scope(entry.pc=0x3fff&&entry.sp>=0xb220&&entry.sp<=0xfffc)"predicate entry/frame";
 let memory=S.of_bytes(boundary.copy_memory())in
 let index=S.read memory 0xad1c and pointer=S.word memory 0xad1d in
 let records=if k105_fallback then(
  scope(index=105&&call_site=0x4285)"k105 fallback ownership";
  let table=0x1b4b+index in
  scope(S.read memory table=Char.code(Bytes.get bridge.B.com(table-0x100)))"k105 fallback index table";
  let j=S.read memory table land 7 in let slot=0x3c13+2*j in
  for address=slot to slot+1 do scope(S.read memory address=Char.code(Bytes.get bridge.B.pli2(address-0x2200)))"k105 fallback pointer table"done;
  let record=(S.word memory slot+1)land 65535 in
  scope(record=0x3bf6)"k105 fallback record domain";[record]
 )else match index with 33->[0x57d7]|216->[0x8719;0x871e;0x8723;0x8728]|_->raise(Outside_scope "predicate index")in
 scope(List.mem pointer records)"predicate record pointer";
 let count=S.read memory pointer in scope(count=(if k105_fallback then 2 else if index=33 then 3 else 4))"predicate record count";
 for i=0 to count do scope(S.read memory(pointer+i)=Char.code(Bytes.get bridge.B.pli2(pointer+i-0x2200)))"predicate immutable record"done;
 for o=0x1dff to 0x1fb4 do scope(S.read memory(o+0x2200)=Char.code(Bytes.get bridge.pli2 o))"predicate code"done;
 scope(S.read memory call_site=0xcd&&S.word memory(call_site+1)=0x3fff&&S.word memory entry.sp=call_site+3)"predicate CALL word";
 let sentinel=S.word memory 0x2155 in
 scope(not(sentinel>=0xad0b&&sentinel<0xad27)&&not(sentinel>=entry.sp-32&&sentinel<entry.sp+2)&&not(sentinel>=0x3fff&&sentinel<0x41b5)&&not(sentinel>=pointer&&sentinel<pointer+count+1))"predicate sentinel alias";
 let q=ref(A.logical entry) and sp=ref entry.sp and effects=ref[]and journal=ref[]in
 let put kind writer address value=
  S.write memory address value;effects:=Runner.Memory_write(address,value)::!effects;
  journal:={B.address;value;writer;depth=0;kind}::!journal in
 let read=S.read memory in
 let a v=q:={!q with R.a=v}and hl v=q:={!q with R.hl=v}and de v=q:={!q with R.de=v}in
 let c v=q:={!q with R.bc=(!q.bc land 0xff00)lor v}in

 let push site v=put"compatibility"site(!sp-1)(v lsr 8);put"compatibility"site(!sp-2)(v land 255);sp:= !sp-2 in
 let read_at site address=let v=read address in observe_read site address v;v in
 let word_at site address=let lo=read_at site address in let hi=read_at site(address+1)in lo lor(hi lsl 8)in
 let pop site=let v=word_at site !sp in sp:= !sp+2;v in
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
 let cmp v=q:={!q with R.flags=R.comparison !q.a v}in
 let dec value=let v=(value-1)land 255 in let f=R.comparison v 0 in q:={!q with R.flags={f with carry= !q.flags.carry;auxiliary_carry=value land 15<>0}};v in
 let inc value=let v=(value+1)land 255 in let f=R.comparison v 0 in q:={!q with R.flags={f with carry= !q.flags.carry;auxiliary_carry=value land 15=15}};v in
 let psw f=2 lor(if f.R.sign then 128 else 0)lor(if f.zero then 64 else 0)lor(if f.auxiliary_carry then 16 else 0)lor(if f.parity then 4 else 0)lor(if f.carry then 1 else 0)in
 hl 0xad21;put"logical"0x4002 !q.hl(!q.bc land 255);hl(word_at 0x4003 0xad1d);a(read_at 0x4006 !q.hl);put"logical"0x4007 0xad25 !q.a;
 hl 0xad15;List.iteri(fun i site->if i>0 then hl(!q.hl+1);put"logical"site !q.hl 255)[0x400d;0x4010;0x4013;0x4016;0x4019];
 hl 0xad22;put"logical"0x401e !q.hl 0;hl(!q.hl-1);a(read_at 0x4021 !q.hl);put"logical"0x4022 0xad0b !q.a;
 let ret=ref 0x41b4 in
 let rec scan budget=
  need(budget>0)"descriptor termination";
  a(read_at 0x4025 0xad25);cmp 0;
  if !q.flags.zero then a 1 else(
   hl 0xad25;let v=dec(read_at 0x4030 !q.hl)in put"logical"0x4030 !q.hl v;
   hl(word_at 0x4031 0xad22);hl(!q.hl land 255);q:={!q with R.bc=1};dad !q.bc;
   let old= !q.hl in hl !q.de;de old;hl(word_at 0x403b 0xad1d);dad !q.de;a(read_at 0x403f !q.hl);put"logical"0x4040 0xad26 !q.a;
   a(read_at 0x4043 0xad21);a(dec !q.a);put"logical"0x4047 0xad21 !q.a;push 0x404a(!q.a lsl 8 lor psw !q.flags);
   a(read_at 0x404b 0xad22);a(inc !q.a);put"logical"0x404f 0xad22 !q.a;c !q.a;q:={!q with R.bc= !q.bc land 255};hl 0xad0b;dad !q.bc;
   q:={!q with R.bc=pop 0x4059};c(!q.bc lsr 8);put"logical"0x405b !q.hl(!q.bc land 255);
   a(read_at 0x405c 0xad26);cmp 0xed;
   if !q.flags.carry then(
    hl(word_at 0x4064 0xad21);c(!q.hl land 255);canonical 0x4068(B.Pli2_output 0x047d);
    hl 0xad26;cmp(read_at 0x406e !q.hl);
    if !q.flags.zero then scan(budget-1)else(a 0;ret:=0x4074)
   )else(
    a(read_at 0x4078 0xad26);cmp 0xed;scope(not !q.flags.zero)"unsupported ED token";
    a(read_at 0x4091 0xad26);cmp 0xee;scope(not !q.flags.zero)"unsupported EE token";
    a(read_at 0x409c 0xad26);cmp 0xf6;scope(not !q.flags.carry)"unsupported F0..F5 token";
    a(read_at 0x40f4 0xad26);cmp 0xfb;scope(not !q.flags.carry)"unsupported F6..FA token";
    a(read_at 0x413b 0xad26);let old= !q.a in cmp 0xfb;a((old-0xfb)land 255);put"logical"0x4140 0xad26 !q.a;
    c !q.a;q:={!q with R.bc= !q.bc land 255};hl 0xad15;dad !q.bc;a(read_at 0x414a !q.hl);put"logical"0x414b 0xad23 !q.a;cmp 255;
    scope !q.flags.zero "unproved repeated-cache predicate";
    hl(word_at 0x4198 0xad26);hl(!q.hl land 255);q:={!q with R.bc=0xad15};dad !q.bc;
    a(read_at 0x41a1 0xad22);put"logical"0x41a4 !q.hl !q.a;
    hl(word_at 0x41a5 0xad21);c(!q.hl land 255);canonical 0x41a9(B.Pli2_output 0x0992);
    put"logical"0x41ac 0xad21 !q.a;scan(budget-1)))in scan 5;
 let pc=pop !ret in need(pc=call_site+3&& !sp=entry.sp+2)"predicate RET";
 let state=A.machine entry !q !sp pc in let expected=preview state in
 let validate(r:Runner.host_program_result)=if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)then Error"scanned ordered transaction"else Ok()in
 {B.result={Pli80_host.Acquisition_family.returned= !q;field=None};program={effects=List.rev !effects;next_state=state;validate;on_commit=ignore};state;journal=List.rev !journal;
  logical_writes=List.filter_map(fun(w:B.write)->if w.kind="logical"then Some(w.address,w.value)else None)(List.rev !journal)}

(* Copied k33 candidate-success and opt-in k105 zero-candidate transactions.
   Both reuse the established frame law; installed operations are untouched. *)
let gateway ?(k105_fallback=false) ?(observe_read=(fun _ _ _->())) bridge ~call_site (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 let need c s=if not c then invalid_arg((if k105_fallback then "k105 gateway: "else "k33 gateway: ")^s)in
 scope(entry.pc=0x41b5&&entry.sp>=0xb220&&entry.sp<=0xfffc)"gateway entry/frame";
 let memory=S.of_bytes(boundary.copy_memory())in
 for off=0x1fb5 to 0x20ea do scope(S.read memory(off+0x2200)=Char.code(Bytes.get bridge.B.pli2 off))"gateway code"done;
 scope(call_site>=0x2200&&call_site+3<0xaa00&&S.read memory call_site=0xcd&&S.word memory(call_site+1)=0x41b5&&S.word memory entry.sp=call_site+3)"gateway CALL ancestry";
 for i=0 to 2 do scope(S.read memory(call_site+i)=Char.code(Bytes.get bridge.pli2(call_site-0x2200+i)))"gateway caller image"done;
 scope(S.read memory 0x202e land 1=0)"gateway trace";
 if k105_fallback then scope(S.read memory 0x201d land 1=0&&S.read memory 0x2029 land 1=0&&S.read memory 0x1d8a<=120&&S.read memory 0x1d8b<8&&S.word memory 0x1c2c>0&&S.word memory 0x1c2c<0xfffe)"k105 bounded output";

 let sentinel=S.word memory 0x2155 in
 scope(not(sentinel>=entry.sp-32&&sentinel<entry.sp+2)&&not(sentinel>=0xad0a&&sentinel<0xad27)&&not(sentinel>=0x41b5&&sentinel<0x42eb)&&not(sentinel>=(if k105_fallback then 0x434f else 0x57d6)&&sentinel<(if k105_fallback then 0x4350 else 0x57db)))"gateway sentinel alias";
 let q=ref(A.logical entry) and sp=ref entry.sp and effects=ref[]and journal=ref[]in
 let put kind writer address value=
  S.write memory address value;effects:=Runner.Memory_write(address,value)::!effects;
  journal:={B.address;value;writer;depth=0;kind}::!journal in
 let read=S.read memory in
 let a v=q:={!q with R.a=v}and hl v=q:={!q with R.hl=v}and de v=q:={!q with R.de=v}in
 let c v=q:={!q with R.bc=(!q.bc land 0xff00)lor v}in

 let push site v=put"compatibility"site(!sp-1)(v lsr 8);put"compatibility"site(!sp-2)(v land 255);sp:= !sp-2 in
 let read_at site address=let v=read address in observe_read site address v;v in
 let word_at site address=let lo=read_at site address in let hi=read_at site(address+1)in lo lor(hi lsl 8)in
 let pop site=let v=word_at site !sp in sp:= !sp+2;v in
 let rar()=q:=Software_selector_3de4.rotate !q in
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
 let software target prepare=
  let state=A.machine entry !q !sp target in let prior=List.rev !effects in let before=preview state in
  let view:Runner.instruction_boundary={state;read_memory=read;copy_memory=(fun()->S.copy memory);dma=before.dma;copy_filesystem=(fun()->Cpm.Filesystem.copy before.filesystem);preview_host_program=(fun p->boundary.preview_host_program{p with effects=prior@p.effects})}in
  let p:B.prepared=prepare view in effects:=List.rev_append p.program.effects !effects;
  journal:=List.rev_append(List.map(fun(w:B.write)->{w with depth=w.depth+1})p.journal)!journal;
  sp:=p.state.sp;q:=A.logical p.state;ignore(preview p.state)in
 let dec value=let v=(value-1)land 255 in let f=R.comparison v 0 in q:={!q with R.flags={f with carry= !q.flags.carry;auxiliary_carry=value land 15<>0}};v in
 let inc value=let v=(value+1)land 255 in let f=R.comparison v 0 in q:={!q with R.flags={f with carry= !q.flags.carry;auxiliary_carry=value land 15=15}};v in
 let pair site addr=hl(word_at site addr)in
 let store site addr value=put"logical"site addr(value land 255);put"logical"site(addr+1)(value lsr 8)in
 hl 0xfff5;dad !sp;sp:= !q.hl;
 q:={!q with R.bc=(!q.bc land 255)*257};push 0x41bb !q.bc;sp:= !sp+1;
 hl((!q.hl land 0xff00)lor 10);push 0x41bf !q.hl;
 hl 3;dad !sp;let old= !q.hl in hl !q.de;de old;q:={!q with R.bc=0xad0b};hl(pop 0x41c8);
 let rec save()=a(read_at 0x41c9 !q.bc);put"logical"0x41ca !q.de !q.a;q:={!q with R.bc=(!q.bc+1)land 65535};de((!q.de+1)land 65535);
  let l=dec(!q.hl land 255)in hl((!q.hl land 0xff00)lor l);if not !q.flags.zero then save()in save();
 a(read_at 0x41d1 0xad0a);hl 11;dad !sp;put"logical"0x41d8 !q.hl !q.a;
 hl 0;dad !sp;c(read_at 0x41dd !q.hl);canonical 0x41de(B.Pli2_output 0x047d);put"logical"0x41e1 0xad1c !q.a;
 scope(!q.a=(if k105_fallback then 105 else 33))"gateway canonical index";
 c !q.a;q:={!q with R.bc= !q.bc land 255};hl 0x3c21;dad !q.bc;dad !q.bc;
 de((!q.de land 0xff00)lor read_at 0x41ec !q.hl);hl(!q.hl+1);de((read_at 0x41ee !q.hl)lsl 8 lor(!q.de land 255));
 let old= !q.hl in hl !q.de;de old;scope(!q.hl=(if k105_fallback then 0x434f else 0x57d6))"gateway descriptor";store 0x41f0 0xad1d !q.hl;
 hl 0xad0a;put"logical"0x41f6 !q.hl 0;pair 0x41f8 0xad1d;a(read_at 0x41fb !q.hl);put"logical"0x41fc 0xad1a !q.a;scope(!q.a=(if k105_fallback then 0 else 3))"gateway descriptor count";
 pair 0x41ff 0xad1c;hl(!q.hl land 255);q:={!q with R.bc=0x3ddd};dad !q.hl;dad !q.bc;
 de((!q.de land 0xff00)lor read_at 0x4209 !q.hl);hl(!q.hl+1);de((read_at 0x420b !q.hl)lsl 8 lor(!q.de land 255));
 let old= !q.hl in hl !q.de;de old;scope(!q.hl=(if k105_fallback then 0x4552 else 0x61fd))"gateway handler";store 0x420d 0xad1f !q.hl;hl 0xad1b;put"logical"0x4213 !q.hl 0;
 let rec scan budget=need(budget>0)"candidate termination";a(read_at 0x4215 0xad1a);q:={!q with R.flags=R.comparison !q.a 0};
  if not !q.flags.zero then(
   a(read_at 0x421d 0xad1a);a(dec !q.a);put"logical"0x4221 0xad1a !q.a;
   a(read_at 0x4224 0xad0a);a(inc !q.a);put"logical"0x4228 0xad0a !q.a;
   pair 0x422b 0xad1d;hl(!q.hl+1);store 0x422f 0xad1d !q.hl;
   hl 0;dad !sp;c(read_at 0x4236 !q.hl);
   staged 0x4237 0x3fff(predicate ~observe_read bridge ~call_site:0x4237);rar();
   if !q.flags.carry then(hl 0xad1a;put"logical"0x4241 !q.hl 0;hl(!q.hl+1);put"logical"0x4244 !q.hl 1);
   pair 0x4246 0xad1d;de((!q.de land 0xff00)lor read_at 0x4249 !q.hl);de(!q.de land 255);pair 0x424c 0xad1d;dad !q.de;store 0x4250 0xad1d !q.hl;scan(budget-1))in scan 4;
 a(read_at 0x4256 0xad1b);a(!q.a lxor 255);rar();
 if k105_fallback then(
  scope !q.flags.carry "k105 requires actual fallback";
  hl 0xad0a;put"logical"0x4261 !q.hl 0;pair 0x4263 0xad1c;hl(!q.hl land 255);q:={!q with R.bc=0x1b4b};dad !q.bc;
  a 7;let old= !q.a and v=read_at 0x426e !q.hl in let value=old land v in
  q:={!q with R.a=value;flags={(R.comparison value 0)with carry=false;auxiliary_carry=(old lor v)land 8<>0}};
  c !q.a;q:={!q with R.bc= !q.bc land 255};hl 0x3c13;dad !q.bc;dad !q.bc;
  c(read_at 0x4277 !q.hl);hl(!q.hl+1);q:={!q with R.bc=read_at 0x4279 !q.hl lsl 8 lor(!q.bc land 255)};
  q:={!q with R.bc=(!q.bc+1)land 65535};hl !q.bc;scope(!q.hl=0x3bf6)"k105 fallback record";store 0x427d 0xad1d !q.hl;
  hl 0;dad !sp;c(read_at 0x4284 !q.hl);
  staged 0x4285 0x3fff(predicate ~k105_fallback:true ~observe_read bridge ~call_site:0x4285);
  put"logical"0x4288 0xad1b !q.a
 )else scope(not !q.flags.carry) "unproved k33 fallback route";
 a(read_at 0x428b 0x202e);rar();scope(not !q.flags.carry)"gateway pre-handler trace";
 hl 0x42b4;push 0x42af !q.hl;pair 0x42b0 0xad1f;scope(!q.hl=(if k105_fallback then 0x4552 else 0x61fd))"fresh handler pointer";
 if k105_fallback then software 0x4552(K105_handler.prepare bridge)else software 0x61fd(K33_handler.prepare bridge);
 need(!sp=entry.sp-12)"handler software RET";
 a(read_at 0x42b4 0x202e);rar();scope(not !q.flags.carry)"gateway post-handler trace";
 hl((!q.hl land 0xff00)lor 10);push 0x42ca !q.hl;hl 3;dad !sp;q:={!q with R.bc= !q.hl};de 0xad0b;hl(pop 0x42d4);
 let rec restore()=a(read_at 0x42d5 !q.bc);put"logical"0x42d6 !q.de !q.a;q:={!q with R.bc=(!q.bc+1)land 65535};de((!q.de+1)land 65535);
  let l=dec(!q.hl land 255)in hl((!q.hl land 0xff00)lor l);if not !q.flags.zero then restore()in restore();
 hl 11;dad !sp;a(read_at 0x42e1 !q.hl);put"logical"0x42e2 0xad0a !q.a;hl 12;dad !sp;sp:= !q.hl;
 need(!sp=entry.sp)"gateway original frame";
 let pc=pop 0x42ea in need(pc=call_site+3)"gateway original RET";
 let state=A.machine entry !q !sp pc in let expected=preview state in
 let validate(r:Runner.host_program_result)=if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)then Error"k33 ordered handler composition"else Ok()in
 {B.result={Pli80_host.Acquisition_family.returned= !q;field=None};program={effects=List.rev !effects;next_state=state;validate;on_commit=ignore};state;journal=List.rev !journal;
  logical_writes=List.filter_map(fun(w:B.write)->if w.kind="logical"then Some(w.address,w.value)else None)(List.rev !journal)}

let gateway33 ?observe_read bridge ~call_site boundary=
 gateway ?observe_read bridge ~call_site boundary
let gateway105 ?observe_read bridge ~call_site boundary=
 gateway ~k105_fallback:true ?observe_read bridge ~call_site boundary

(* Only named scope restrictions decline; unexpected child/proof errors propagate. *)
let eligible33 bridge ~call_site boundary=
 match gateway33 bridge ~call_site boundary with
 |_->true
 |exception Outside_scope _->false
 |exception Invalid_argument text when List.mem text[
  "k33 handler: unsupported zero selector";"k33 handler: unsupported selector2/other";
  "k33 handler: unproved3EF6 high predicate/38B1";"k33 handler: unproved3731/36E0 route";
  "382E: single forward counter domain";"382E: unobserved forward7D47 route";
  "382E: unobserved backward7D85 route";"382E: unobserved index6 publication"]->false

(* New scope probe; unexpected canonical/code/continuation failures propagate. *)
let eligible105 bridge ~call_site boundary=
 match gateway105 bridge ~call_site boundary with
 |_->true
 |exception Outside_scope _->false
 |exception Invalid_argument text when List.mem text[
  "k105 handler: entry/frame";"k105 handler: own scratch/code/frame sentinel alias";
  "k105 handler: unproved +21CD early-return route";
  "k105 handler: unproved +2269 +21ED branch";
  "k105 handler: unproved non4 generation selector"]->false
