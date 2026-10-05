[@@@warning "-4-40-41-42"]
module H=Pli80_host.Attribute_gate
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
module U=Pli80_host.U16
type operation=Gate|Saved
type t={image:bytes;range:Range_processing_bridge.t;input:Input_processing_bridge.t}
type call={coordinate:string;site:int;resume:int}
type write=Range_processing_bridge.write={address:int;value:int;writer:int;depth:int;kind:string}
type child={site:int;operation:H.operation;input:Runner.state_snapshot;output:Runner.state_snapshot}
type prepared={result:H.result;program:Runner.host_program;state:Runner.state_snapshot;journal:write list;children:child list;
 range:Range_processing_bridge.prepared option;input:Input_processing_bridge.prepared option;gate:prepared option;
 logical_writes:(int*int)list;compatibility_writes:(int*int)list}
let require b m=if not b then invalid_arg("attribute gate bridge: "^m)
let word b a=Char.code(Bytes.get b a)lor(Char.code(Bytes.get b(a+1))lsl 8)
let bounds=function Gate->0x7ec0,0x7ed7|Saved->0x80b7,0x80ca
let create ~pli_com ~pli1={image=Bytes.copy pli1;range=Range_processing_bridge.create ~pli_com ~pli1;input=Input_processing_bridge.create ~pli_com ~pli1}
let origin=Range_processing_bridge.origin
let internal_call t op site=
 let off=site-0x2200 and first,_=bounds op in
 require(off>=0&&off+3<=Bytes.length t.image&&Char.code(Bytes.get t.image off)=0xcd&&word t.image(off+1)=first+0x2200)"internal CALL identity";
 {coordinate=Printf.sprintf"PLI1.OVL+%04X"off;site;resume=site+3}
let verify_call t op (p:Native_dispatch.previous) ~(entry:Runner.state_snapshot)=
 let call=internal_call t op p.before.pc in
 require(p.origin=origin "PLI1.OVL"(call.site-0x2200)&&p.after=entry
  &&entry.pc=fst(bounds op)+0x2200&&I8080.Step.pc_before p.step=call.site
  &&I8080.Step.pc_after p.step=entry.pc&&I8080.Step.fetched_bytes p.step=Bytes.sub t.image(call.site-0x2200)3
  &&I8080.Step.control_flow p.step=I8080.Step.Call{target=entry.pc;taken=true}
  &&p.before.sp=U.wrap(entry.sp+2))"canonical CALL/SP ancestry";
 let writes=List.filter_map(function I8080.Step.Write q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses p.step)in
 require(List.sort compare writes=List.sort compare[entry.sp,call.resume land 255;U.wrap(entry.sp+1),call.resume lsr 8])"original CALL word";call
let logical (s:Runner.state_snapshot)={R.a=s.a;bc=s.b lsl 8 lor s.c;de=s.d lsl 8 lor s.e;hl=s.h lsl 8 lor s.l;
 flags={sign=s.sign;zero=s.zero;auxiliary_carry=s.auxiliary_carry;parity=s.parity;carry=s.carry}}
let machine template (q:R.returned) sp pc={template with Runner.a=q.a;b=q.bc lsr 8;c=q.bc land 255;d=q.de lsr 8;e=q.de land 255;h=q.hl lsr 8;l=q.hl land 255;sp;pc;
 sign=q.flags.sign;zero=q.flags.zero;auxiliary_carry=q.flags.auxiliary_carry;parity=q.flags.parity;carry=q.flags.carry}
let rec prepare t op ~call:(call:call) ~origin:o (boundary:Runner.instruction_boundary)=
 let entry=boundary.state and first,last=bounds op in
 require(o=origin "PLI1.OVL" first&&entry.pc=first+0x2200)"wrong canonical entry";
 let memory=boundary.copy_memory()in let m=S.of_bytes memory in
 List.iter Pli80_host.U8.check[entry.a;entry.b;entry.c;entry.d;entry.e;entry.h;entry.l];U.check entry.sp;
 require(Bytes.sub memory(first+0x2200)(last-first)=Bytes.sub t.image first(last-first))"changed historical code";
 require(entry.sp>=0xae80&&entry.sp<=0xfffc)"stack/table/scratch alias";
 let verified=internal_call t op call.site in
 require(call=verified&&Bytes.sub memory call.site 3=Bytes.sub t.image(call.site-0x2200)3&&S.word m entry.sp=call.resume)"caller/continuation mismatch";
 let effects=ref[]and journal=ref[]and children=ref[]and range=ref None and input=ref None and gate=ref None in
 let append e=effects:=e::!effects in
 let put kind depth writer address value=S.write m address value;append(Runner.Memory_write(address,value));journal:={address;value;writer;depth;kind}::!journal in
 let staged state={Runner.effects=List.rev !effects;next_state=state;validate=(fun _->Ok());on_commit=ignore}in
 let sync bytes=for a=0 to 65535 do let v=Char.code(Bytes.get bytes a)in if S.read m a<>v then S.write m a v done in
 let preview next=match boundary.preview_host_program(staged next)with Ok r->sync r.memory;r|Error e->invalid_arg e in
 let child ~site ~operation q=
  let target=match operation with H.Input_process->0xa248|Range_process->0x9f53|Gate->0xa0c0 in
  require(Char.code(Bytes.get t.image site)=0xcd&&word t.image(site+1)=target)"unproven internal CALL";
  put "compatibility"0(site+0x2200)(entry.sp-1)((site+0x2203)lsr 8);
  put "compatibility"0(site+0x2200)(entry.sp-2)((site+0x2203)land 255);
  let child_input=machine entry q(entry.sp-2)target in
  let prefix=List.rev !effects in
  let before=preview child_input in
  let b={boundary with Runner.state=child_input;read_memory=S.read m;copy_memory=(fun()->S.copy m);
   dma=before.dma;copy_filesystem=(fun()->Cpm.Filesystem.copy before.filesystem);
   preview_host_program=(fun p->boundary.preview_host_program{p with effects=prefix@p.effects})}in
  let import program ws state=
   List.iter append program.Runner.effects;
   journal:=List.rev_append(List.map(fun(w:write)->{w with depth=w.depth+1})ws)!journal;
   ignore(preview state);state in
  let reject_source addresses ps=
   require(not(List.exists(fun(c:Range_processing_bridge.child)->
    List.mem c.operation[Pli80_host.Range_processing.Primary;Secondary]&&List.mem(c.output.h lsl 8 lor c.output.l)addresses)ps.Range_processing_bridge.children))"child table/saved-byte read alias";
   let rec node(n:R.node)=
    List.iter(function R.Auxiliary_read(_,a)->require(not(List.mem a.Pli80_host.Auxiliary.address addresses))"recursive table/saved-byte read alias"|_->())n.helpers;
    List.iter node n.children in
   List.iter(fun(c:Range_processing_bridge.child)->Option.iter(fun(r:R.result)->node r.tree)c.recursive)ps.children in
  let output=match operation with
  |H.Range_process->let p=Range_processing_bridge.prepare t.range
    ~call:(Range_processing_bridge.internal_call t.range(site+0x2200))~origin:(origin "PLI1.OVL" 0x7d53)b in
   reject_source [0xae57;0xae58;entry.sp;entry.sp+1] p;range:=Some p;import p.program p.journal p.state
  |H.Input_process->let p=Input_processing_bridge.prepare t.input
    ~call:(Input_processing_bridge.internal_call t.input(site+0x2200))~origin:(origin "PLI1.OVL" 0x8048)b in
   require(not(List.exists(fun(c:Input_processing_bridge.child)->List.mem c.operation[Pli80_host.Input_processing.Primary_read;Secondary_read]
    &&List.mem(c.output.h lsl 8 lor c.output.l)[0xae6b;0xae6c;entry.sp;entry.sp+1])p.children))"child table/saved-byte read alias";
   Option.iter(reject_source[0xae6b;0xae6c;entry.sp;entry.sp+1])p.range;
   input:=Some p;import p.program p.journal p.state
  |H.Gate->let p=prepare t Gate ~call:(internal_call t Gate(site+0x2200))~origin:(origin "PLI1.OVL" 0x7ec0)b in
   Option.iter(reject_source[0xae6b;0xae6c;entry.sp;entry.sp+1])p.range;
   gate:=Some p;import p.program p.journal p.state in
  require(output.sp=entry.sp&&output.pc=site+0x2203)"child return/SP";
  children:={site;operation;input=child_input;output}::!children;logical output in
 let result=(if op=Gate then H.gate else H.saved)m ~entry:(logical entry)
  ~write:(fun ~site ~address ~value->put "logical"0(site+0x2200)address value)~call:child in
 let state=machine entry result.returned(entry.sp+2)call.resume in
 let journal=List.rev !journal in
 let scratch,neighbor,writer=if op=Gate then 0xae57,0xae58,0xa0c3 else 0xae6b,0xae6c,0xa2ba in
 require(not(List.exists(fun w->(w.address=scratch&&w.writer<>writer)||w.address=neighbor||w.address=entry.sp||w.address=entry.sp+1)journal))"child table/saved-byte write alias";
 let expected=preview state in
 let validate(r:Runner.host_program_result)=if r.memory<>expected.memory||r.dma<>expected.dma||r.services<>expected.services||not(Cpm.Filesystem.equal r.filesystem expected.filesystem)
  then Error"attribute gate ordered program mismatch"else Ok()in
 let select kind=List.filter_map(fun w->if w.kind=kind then Some(w.address,w.value)else None)journal in
 {result;program={(staged state)with validate};state;journal;children=List.rev !children;range= !range;input= !input;gate= !gate;logical_writes=select"logical";compatibility_writes=select"compatibility"}
