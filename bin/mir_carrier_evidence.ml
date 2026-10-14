[@@@warning "-4-40-41-42"]
module E=Pli80.Experiment
module S=I8080.State
let need b s=if not b then failwith("Pass106: "^s)
let get=function Ok x->x|Error _->failwith"unexpected error"
let read p=let c=open_in_bin p in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let array f xs="["^String.concat","(List.map f xs)^"]"
let byte b a=Char.code(Bytes.get b a)
let words xs=array string_of_int xs
let check ram after source destination sp writes=
 need(source>=0&&source<8&&destination>=0&&destination<8)"scoped index";
 let logical=[0xadab+destination,(if source=6 then 0 else byte ram(0xadab+source));
              0xadb3+destination,byte ram(0xadb3+source)]in
 (* Independent projection; machine residue belongs only to this test adapter. *)
 let expected_writes=[0xae03,source;0xae02,destination] @
  (if source=6 then [List.hd logical] else
   [sp-1,0xad;sp-2,0xab+source;List.hd logical]) @
  [sp-1,0xad;sp-2,0xb3+source;List.nth logical 1]in
 need(writes=expected_writes)"complete prefix ordered writes, including residue";
 let expected=Bytes.copy ram in
 List.iter(fun(a,v)->Bytes.set expected a(Char.chr v))expected_writes;
 need(after=expected)"full RAM after explicit test-only machine accounting";
 logical
let json_case ram after source destination sp writes steps=
 let logical=check ram after source destination sp writes in
 Printf.sprintf"{\"source_slot\":%d,\"destination_slot\":%d,\"entry_A\":%s,\"entry_B\":%s,\"exit_A\":%s,\"exit_B\":%s,\"ordered_publications\":%s,\"CPU_writes\":%d,\"instructions\":%d,\"entry_SP\":%d,\"exit_SP\":%d,\"entry_RAM_sha256\":%S,\"post_RAM_sha256\":%S}"
 source destination(words(List.init 8(fun i->byte ram(0xadab+i))))(words(List.init 8(fun i->byte ram(0xadb3+i))))
 (words(List.init 8(fun i->byte after(0xadab+i))))(words(List.init 8(fun i->byte after(0xadb3+i))))
 (array(fun(a,v)->Printf.sprintf"[%d,%d]"a v)logical)(List.length writes)steps sp sp(E.sha256_hex ram)(E.sha256_hex after)
let synthetic pli2=
 let count=ref 0 and self=ref 0 and source6=ref [] in
 for destination=0 to 7 do for source=0 to 7 do
  let patterns=if source=6 then ["distinct";"same-valued";"zero"]else ["pass106"]in
  List.iter(fun pattern->
  let memory=I8080.Memory.create()in
  let ram=Bytes.init 65536(fun i->Char.chr((i*37+source*19+destination)land 255))in
  Bytes.blit pli2 0 ram 0x2200(Bytes.length pli2);
  for i=0 to 15 do
   let value=match pattern with
    | "distinct" -> (i*31+source*7)land 255
    | "same-valued" -> 255 | "zero" -> 0
    | _ -> if i<8 then (if i mod 2=0 then 0 else 255) else ((i-8)*31+source)land 255 in
   Bytes.set ram(0xadab+i)(Char.chr value)
  done;
  (* Explicit untouched continuation word, not an invented CALL into MIR. *)
  if source=6 then (Bytes.set ram 0xf000 '\052'; Bytes.set ram 0xf001 '\018');
  I8080.Memory.load memory ~address:0 ram;
  let state=S.create()in S.set_pc state 0x9b3c;S.set_sp state 0xf000;
  S.set_c state destination;S.set_e state source;S.set_b state 0x91;S.set_d state 0xe3;S.set_a state 0xff;
  let flags=S.flags state in I8080.Flags.set_carry flags true;I8080.Flags.set_auxiliary_carry flags true;
  let cpu=I8080.Cpu.create ~state ~bus:(I8080.Bus.create memory)in
  let writes=ref[]and steps=ref 0 and offsets=ref[]in
  while S.pc state<>0x9b7e do
   need(!steps<64)"synthetic prefix boundary";
   let step=get(I8080.Cpu.step cpu)in incr steps;
   offsets:=(I8080.Step.pc_before step-0x2200)::!offsets;
   if I8080.Step.pc_before step=0x9b47 then
    need(I8080.Step.control_flow step=I8080.Step.Jump{target=0x9b58;taken=source<>6})"fresh CPI6/JNZ decision";
   if I8080.Step.pc_before step=0x9b55 then
    need(source=6&&I8080.Step.control_flow step=I8080.Step.Jump{target=0x9b6b;taken=true})"source6 common-copy join";
   List.iter(function I8080.Step.Write w->writes:=(w.address,w.value)::!writes|_->())(I8080.Step.memory_accesses step)
  done;
  need(S.sp state=0xf000)"prefix PUSH/POP balance";
  let post=I8080.Memory.read_range memory ~address:0 ~length:65536 in
  ignore(check ram post source destination 0xf000(List.rev !writes));
  if source=6 then (
   let detail=json_case ram post source destination 0xf000(List.rev !writes) !steps in
   source6:=(String.sub detail 0(String.length detail-1)^Printf.sprintf
     ",\"classification\":\"DEDUCED / STATIC / UNOBSERVED\",\"pattern\":%S,\"endpoint\":%d,\"instruction_offsets\":%s,\"physical_writes\":%s}"
     pattern(S.pc state)(words(List.rev !offsets))
     (array(fun(a,v)->Printf.sprintf"[%d,%d]"a v)(List.rev !writes)))::!source6);
  if source=destination then incr self;incr count
 )patterns done done;
 !count,!self,List.rev !source6
let ()=
 let images=ref""and out=ref""in Arg.parse["--images",Arg.Set_string images,"historical images";"--output",Arg.Set_string out,"proof JSON"]ignore"Historical transfer projection evidence";
 let image n=read(Filename.concat !images n)in
 let pli2=image"PLI2.OVL"in
 let inp:E.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=pli2;
  source_name="FIZZBUZ.PLI";source_bytes=E.prepare_source ~normalize:true(read"examples/pli80/FIZZBUZ.PLI");module_name="FIZZBUZ";command_tail=Bytes.of_string" FIZZBUZ";max_steps=10_000_000}in
 let active=ref None and cases=ref[]and previous=ref None in
 let on_guest_step ~step_index:_ ~before ~after step=
  previous:=Some(before,after,step);
  match !active with None->()|Some(_,_,writes,steps)->incr steps;
   List.iter(function I8080.Step.Write w->writes:=(w.address,w.value)::!writes|_->())(I8080.Step.memory_accesses step)in
 let on_before_instruction ~origin ~step_index:_ (b:Runner.instruction_boundary)=
  (match !active with Some(entry,ram,writes,steps)when b.state.pc=0x9b7e->
   need(b.state.sp=entry.Runner.sp)"natural prefix balanced stack";
   cases:=json_case ram(b.copy_memory())entry.e entry.c entry.sp(List.rev !writes) !steps::!cases;active:=None|_->());
  if origin=Pli80.Acquisition_parent_bridge.origin"PLI2.OVL"0x793c then(
   need(!active=None)"unexpected overlapping window";
   let before,after,step=Option.get !previous in
   need(after=b.state&&before.Runner.sp=b.state.sp+2&&I8080.Step.control_flow step=I8080.Step.Call{target=0x9b3c;taken=true})(Printf.sprintf "original hardware child ancestry at %04x SP %04x/%04x target %04x" before.Runner.pc before.sp b.state.sp (I8080.Step.pc_after step));
   let ram=b.copy_memory()in
   need(byte ram b.state.sp lor(byte ram(b.state.sp+1)lsl 8)=(before.pc+3)land 65535)"original CALL continuation";
   need(Bytes.sub ram 0x9b3c(0x797e-0x793c)=Bytes.sub pli2 0x793c(0x797e-0x793c))"historical prefix bytes";
   need(b.state.e<>6)"unobserved special source";
   active:=Some(b.state,ram,ref[],ref 0))in
 let historical=get(E.run ~analysis:Execution ~on_guest_step ~on_before_instruction inp)in
 need(!active=None)"unfinished natural window";
 let cases=List.rev !cases in
 let synthetic,self,source6=synthetic pli2 in
 let rel=E.sha256_hex(Option.get historical.rel_bytes)in
 need(rel="68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203")"FIZZBUZ golden";
 let f=open_out !out in Fun.protect ~finally:(fun()->close_out f)(fun()->Printf.fprintf f
 "{\"all_passed\":true,\"prefix\":[31036,31102],\"natural_cases\":%s,\"synthetic_cases\":%d,\"synthetic_self_copies\":%d,\"source6_synthetic_cases\":%s,\"REL_sha256\":%S,\"PLI2_sha256\":%S,\"prefix_emits_file_or_console_bytes\":false,\"new_native_roots\":0,\"knowledge_promotions\":0}\n"
 (array Fun.id cases)synthetic self(array Fun.id source6) rel(E.sha256_hex pli2))
