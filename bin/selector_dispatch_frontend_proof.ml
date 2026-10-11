[@@@warning "-4-40-41-42"]
module M=I8080.Memory
module S=I8080.State
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let hex b=String.concat""(List.init(Bytes.length b)(fun i->Printf.sprintf"%02X"(Char.code(Bytes.get b i))))
let ()=
 let images=ref""and output=ref""and seed=ref""in
 Arg.parse["--images",Arg.Set_string images,"historical images";"--output",Arg.Set_string output,"JSON";"--seed",Arg.Set_string seed,"concrete RAM"]ignore"local CPU dispatcher arithmetic, no child emulation";
 let ram=read !seed in let image=read(Filename.concat !images"PLI2.OVL")in
 if Bytes.sub ram 0x5ff5 0x40<>Bytes.sub image 0x3df5 0x40 then failwith"PLI2 seed code";
 let cases=ref []in
 List.iter(fun selector->List.iter(fun carry->List.iter(fun adjacent->List.iter(fun mutation->
 let m=M.create()in M.load m ~address:0 ram;M.write m 0xad0a selector;M.write m 0xad0b adjacent;
 if mutation<>0 then M.write16 m(0x602b+2*selector)(M.read16 m(0x602b+2*selector) lxor mutation);
 let before=M.read_range m ~address:0 ~length:65536 in
 let s=S.create()in S.set_pc s 0x5ff5;S.set_sp s 0xf800;S.set_bc s 0xabab;S.set_de s 0xcdcd;S.set_a s 0x96;
 I8080.Flags.set_carry(S.flags s)carry;
 let cpu=I8080.Cpu.create ~state:s ~bus:(I8080.Bus.create m)in
 let reads=ref []and steps=ref []in
 for _i=0 to 10 do match I8080.Cpu.step cpu with Error _->failwith"CPU frontend"|Ok w->
 List.iter(function I8080.Step.Write _->failwith"unexpected frontend write"|I8080.Step.Read{address;value}->reads:=(address,value)::!reads)(I8080.Step.memory_accesses w);
 steps:=Printf.sprintf"{\"pc\":%d,\"bytes\":%S,\"A\":%d,\"BC\":%d,\"DE\":%d,\"HL\":%d,\"CY\":%b}"(I8080.Step.pc_before w)(hex(I8080.Step.fetched_bytes w))(S.a s)(S.bc s)(S.de s)(S.hl s)(I8080.Flags.carry(S.flags s))::!steps done;
 let targets=[|0x6005;0x600d;0x6013;0x601b;0x6023|]in
 let expected=M.read16 m(0x602b+2*selector)in
 if S.pc s<>expected||S.bc s<>selector||S.de s<>0x602c+2*selector||S.sp s<>0xf800||S.a s<>0x96||M.read_range m ~address:0 ~length:65536<>before then failwith"frontend state law";
 if selector<5 && mutation=0 && expected<>targets.(selector)then failwith"table law";
 if List.rev !reads<>[0xad0a,selector;0xad0b,adjacent;0x602b+2*selector,expected land 255;0x602c+2*selector,expected lsr 8]then failwith"fresh read order";
 cases:=Printf.sprintf"{\"selector\":%d,\"table_xor\":%d,\"adjacent\":%d,\"carry_in\":%b,\"target\":%d,\"supported_table_domain\":%b,\"steps\":[%s],\"RAM_unchanged\":true}"selector mutation adjacent carry expected(selector<5)(String.concat","(List.rev !steps))::!cases
 )[0;1;256])[0;255])[false;true])[0;1;2;3;4;5];
 let rotates=ref 0 in
 for a=0 to 255 do List.iter(fun cy->let m=M.create()in M.write m 0x5fe7(Char.code(Bytes.get image 0x3de7));let s=S.create()in S.set_pc s 0x5fe7;S.set_a s a;I8080.Flags.restore_from_psw_byte(S.flags s)(a lor 2);I8080.Flags.set_carry(S.flags s)cy;let old=I8080.Flags.to_psw_byte(S.flags s)in
 let cpu=I8080.Cpu.create ~state:s ~bus:(I8080.Bus.create m)in(match I8080.Cpu.step cpu with Ok _->()|Error _->failwith"RAR CPU");
 if S.a s<>(a lsr 1 lor(if cy then 128 else 0))||I8080.Flags.carry(S.flags s)<>(a land 1=1)||(I8080.Flags.to_psw_byte(S.flags s)land 0xfe)<>(old land 0xfe)then failwith"RAR law";incr rotates)[false;true]done;
 let c=open_out !output in Fun.protect ~finally:(fun()->close_out c)(fun()->Printf.fprintf c"{\"scope\":\"instruction-only frontend; stops before arm children; no native contract\",\"cases\":[%s],\"RAR_cases\":%d,\"all_passed\":true}"(String.concat","(List.rev !cases))!rotates)
