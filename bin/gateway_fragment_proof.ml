[@@@warning "-4-40-41-42"]
module M=I8080.Memory
module S=I8080.State
let read p=let c=open_in_bin p in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let ()=
 let seed=ref""and output=ref""in Arg.parse["--seed",Arg.Set_string seed,"entry RAM";"--output",Arg.Set_string output,"JSON"]ignore"own gateway fragments; never substitutes a handler";
 let ram=read !seed and saves=ref 0 and successes=ref 0 in
 List.iter(fun sp->List.iter(fun c->List.iter(fun salt->
 let mem=M.create()in M.load mem ~address:0 ram;M.write16 mem sp 0x1234;
 let values=List.init 11(fun i->(salt+37*i)land 255)in List.iteri(fun i v->M.write mem(0xad0a+i)v)values;
 let s=S.create()in S.set_pc s 0x41b5;S.set_sp s sp;S.set_bc s(0x9900+c);S.set_de s 0xabcd;I8080.Flags.restore_from_psw_byte(S.flags s)0xd7;
 let cpu=I8080.Cpu.create ~state:s ~bus:(I8080.Bus.create mem)in
 let run_until pc=let n=ref 0 in while S.pc s<>pc do incr n;if !n>200 then failwith"fragment termination";match I8080.Cpu.step cpu with Error _->failwith"CPU"|Ok _->()done in
 run_until 0x41de;
 if S.sp s<>sp-12||M.read mem(sp-12)<>c||M.read16 mem sp<>0x1234 then failwith"save geometry";
 List.iteri(fun i v->let a=if i=0 then sp-1 else sp-12+i in if M.read mem a<>v then failwith"save byte provenance")values;
 (*Explicit fragment boundary: arbitrary overwritten shared state tests restoration,
   not a fabricated handler result or complete native transaction.*)
 List.iteri(fun i _->M.write mem(0xad0a+i)(255-i))values;S.set_pc s 0x42c8;S.set_hl s 0xbeef;
 run_until 0x42ea;
 if S.sp s<>sp||S.hl s<>sp||S.bc s<>sp-1||S.de s<>0xad15||S.a s<>List.hd values||M.read16 mem sp<>0x1234 then failwith"restore state";
 List.iteri(fun i v->if M.read mem(0xad0a+i)<>v then failwith"restore bytes")values;
 (match I8080.Cpu.step cpu with Ok _->()|Error _->failwith"RET");if S.pc s<>0x1234||S.sp s<>sp+2 then failwith"hardware continuation";incr saves
 )[0;113;255])[0;13;93;162;255])[0xf800;0xff00];
 for psw=0 to 255 do List.iter(fun old->
 let mem=M.create()in M.load mem ~address:0 ram;M.write mem 0xad1a old;M.write mem 0xad1b(255-old);let before=M.read_range mem ~address:0 ~length:65536 in
 let s=S.create()in S.set_pc s 0x423e;S.set_sp s 0xf800;S.set_bc s 0xaabb;S.set_de s 0xccdd;S.set_a s 0x81;I8080.Flags.restore_from_psw_byte(S.flags s)psw;let flags=I8080.Flags.to_psw_byte(S.flags s)in
 let cpu=I8080.Cpu.create ~state:s ~bus:(I8080.Bus.create mem)in let writes=ref []in
 for _i=0 to 3 do match I8080.Cpu.step cpu with Error _->failwith"success CPU"|Ok w->List.iter(function I8080.Step.Write{address;value}->writes:= !writes@[address,value]|_->())(I8080.Step.memory_accesses w)done;
 if !writes<>[0xad1a,0;0xad1b,1]||S.hl s<>0xad1b||S.pc s<>0x4246||S.sp s<>0xf800||S.bc s<>0xaabb||S.de s<>0xccdd||S.a s<>0x81||I8080.Flags.to_psw_byte(S.flags s)<>flags then failwith"success law";
 Bytes.set before 0xad1a(Char.chr 0);Bytes.set before 0xad1b(Char.chr 1);if M.read_range mem ~address:0 ~length:65536<>before then failwith"unrelated success writes";incr successes
 )[0;1;255]done;
 let c=open_out !output in Fun.protect ~finally:(fun()->close_out c)(fun()->Printf.fprintf c"{\"scope\":\"gateway-own save/restore fragments and success arm only; no opaque child/handler patched or executed\",\"save_restore_cases\":%d,\"success_cases\":%d,\"all_passed\":true}"!saves!successes)
