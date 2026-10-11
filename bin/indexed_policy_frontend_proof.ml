[@@@warning "-4-40-41-42"]
module M=I8080.Memory
module S=I8080.State
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let hex b=String.concat""(List.init(Bytes.length b)(fun i->Printf.sprintf"%02X"(Char.code(Bytes.get b i))))
let ()=
 let images=ref""and output=ref""and seed=ref""in
 Arg.parse["--images",Arg.Set_string images,"historical images";"--output",Arg.Set_string output,"JSON";"--seed",Arg.Set_string seed,"concrete RAM"]ignore"local CPU dispatcher arithmetic, no child emulation";
 let ram=read !seed in let image=read(Filename.concat !images"PLI2.OVL")in
 if Bytes.sub ram 0x5b7f 0x10<>Bytes.sub image 0x397f 0x10 then failwith"PLI2 seed code";
 let cases=ref []in
 List.iter(fun selector->List.iter(fun carry->List.iter(fun adjacent->List.iter(fun mutation->
 let m=M.create()in M.load m ~address:0 ram;M.write m 0xad0a selector;M.write m 0xad0b adjacent;
 if mutation<>0 then M.write16 m(0x5d3c+2*selector)(M.read16 m(0x5d3c+2*selector) lxor mutation);
 let before=M.read_range m ~address:0 ~length:65536 in
 let s=S.create()in S.set_pc s 0x5b7f;S.set_sp s 0xf800;S.set_bc s 0xabab;S.set_de s 0xcdcd;S.set_a s 0x96;
 I8080.Flags.restore_from_psw_byte(S.flags s)0xd6;I8080.Flags.set_carry(S.flags s)carry;
 let cpu=I8080.Cpu.create ~state:s ~bus:(I8080.Bus.create m)in
 let reads=ref []and steps=ref []in
 for _i=0 to 10 do match I8080.Cpu.step cpu with Error _->failwith"CPU frontend"|Ok w->
 List.iter(function I8080.Step.Write _->failwith"unexpected frontend write"|I8080.Step.Read{address;value}->reads:=(address,value)::!reads)(I8080.Step.memory_accesses w);
 steps:=Printf.sprintf"{\"pc\":%d,\"bytes\":%S,\"A\":%d,\"BC\":%d,\"DE\":%d,\"HL\":%d,\"CY\":%b}"(I8080.Step.pc_before w)(hex(I8080.Step.fetched_bytes w))(S.a s)(S.bc s)(S.de s)(S.hl s)(I8080.Flags.carry(S.flags s))::!steps done;
 let targets=Array.init 19(fun i->Char.code(Bytes.get image(0x3b3c+2*i)) lor(Char.code(Bytes.get image(0x3b3d+2*i)) lsl 8))in
 let expected=M.read16 m(0x5d3c+2*selector)in
 if I8080.Flags.to_psw_byte(S.flags s)<>0xd6 then failwith"frontend flags";
 if S.pc s<>expected||S.bc s<>selector||S.de s<>0x5d3d+2*selector||S.sp s<>0xf800||S.a s<>0x96||M.read_range m ~address:0 ~length:65536<>before then failwith"frontend state law";
 if selector<19 && mutation=0 && expected<>targets.(selector)then failwith"table law";
 if List.rev !reads<>[0xad0a,selector;0xad0b,adjacent;0x5d3c+2*selector,expected land 255;0x5d3d+2*selector,expected lsr 8]then failwith"fresh read order";
 cases:=Printf.sprintf"{\"selector\":%d,\"table_xor\":%d,\"adjacent\":%d,\"carry_in\":%b,\"target\":%d,\"supported_table_domain\":%b,\"steps\":[%s],\"RAM_unchanged\":true}"selector mutation adjacent carry expected(selector<19)(String.concat","(List.rev !steps))::!cases
 )[0;1;256])[0;255])[false;true])(List.init 20 Fun.id);
 let tails=ref 0 in
 List.iter(fun selector->List.iter(fun value->List.iter(fun psw->
 let m=M.create()in M.load m ~address:0 ram;M.write m 0xad0a selector;M.write m 0xad0b 239;M.write m(0x579b+selector)value;M.write16 m 0xf800 0x1234;
 let state=S.create()in S.set_pc state 0x5d62;S.set_sp state 0xf800;S.set_de state 0xabcd;I8080.Flags.restore_from_psw_byte(S.flags state)psw;
 let cpu=I8080.Cpu.create ~state:state ~bus:(I8080.Bus.create m)in let accesses=ref []in
 for _i=0 to 6 do match I8080.Cpu.step cpu with Error _->failwith"tail CPU"|Ok w->accesses:= !accesses @ I8080.Step.memory_accesses w done;
 if S.pc state<>0x1234 || S.sp state<>0xf802 || S.hl state<>0x579b+selector || S.bc state<>0x579b || S.de state<>0xabcd || S.a state<>value || M.read m 0xad06<>value || (I8080.Flags.to_psw_byte(S.flags state) land 0xfe)<>(psw land 0xd4 lor 2) || I8080.Flags.carry(S.flags state)then failwith"tail law";
 let expected=[I8080.Step.Read{address=0xad0a;value=selector};I8080.Step.Read{address=0xad0b;value=239};I8080.Step.Read{address=0x579b+selector;value};I8080.Step.Write{address=0xad06;value};I8080.Step.Read{address=0xf800;value=0x34};I8080.Step.Read{address=0xf801;value=0x12}]in
 if !accesses<>expected then failwith"tail access order";incr tails
 )[2;0xd7])[0;173;255])[0;15;18];
 let c=open_out !output in Fun.protect ~finally:(fun()->close_out c)(fun()->Printf.fprintf c"{\"scope\":\"instruction-only frontend and tail; no arm contract, corruption follows concrete bytes rather than a native acceptance claim\",\"cases\":[%s],\"tail_cases\":%d,\"all_passed\":true}"(String.concat","(List.rev !cases))!tails)
