[@@@warning "-4-40-41-42"]
module H=Pli80_host.K123_handler_tail
module M=I8080.Memory
module S=I8080.State
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let flags s:Pli80_host.Recursive_mapped.flags={sign=I8080.Flags.sign(S.flags s);zero=I8080.Flags.zero(S.flags s);auxiliary_carry=I8080.Flags.auxiliary_carry(S.flags s);parity=I8080.Flags.parity(S.flags s);carry=I8080.Flags.carry(S.flags s)}
let psw f=(if f.Pli80_host.Recursive_mapped.sign then 128 else 0)lor(if f.zero then 64 else 0)lor(if f.auxiliary_carry then 16 else 0)lor(if f.parity then 4 else 0)lor 2 lor(if f.carry then 1 else 0)
let ()=
 let ram=ref""and expected_ram=ref""and output=ref""and pc=ref 0 and sp=ref 0 and a=ref 0 and bc=ref 0 and de=ref 0 and hl=ref 0 and psw_in=ref 0 and expected=Array.make 7 0 in
 let arg n r= n,Arg.Set_int r,"captured state"in
 Arg.parse(["--ram",Arg.Set_string ram,"captured tail RAM";"--expected-ram",Arg.Set_string expected_ram,"captured exit RAM";"--output",Arg.Set_string output,"proof summary";
  arg "--pc" pc;arg "--sp" sp;arg "--a" a;arg "--bc" bc;arg "--de" de;arg "--hl" hl;arg "--psw" psw_in;
  "--expected-pc",Arg.Int(fun v->expected.(0)<-v),"captured exit";"--expected-sp",Arg.Int(fun v->expected.(1)<-v),"captured exit";"--expected-a",Arg.Int(fun v->expected.(2)<-v),"captured exit";"--expected-bc",Arg.Int(fun v->expected.(3)<-v),"captured exit";"--expected-de",Arg.Int(fun v->expected.(4)<-v),"captured exit";"--expected-hl",Arg.Int(fun v->expected.(5)<-v),"captured exit";"--expected-psw",Arg.Int(fun v->expected.(6)<-v),"captured exit"])
  ignore"Independent CPU and faithful host tail comparison";
 let seed=read !ram and captured_exit=read !expected_ram in
 if Bytes.length seed<>65536||Bytes.length captured_exit<>65536 then failwith"RAM size";
 let cases=ref 0 and natural=ref false in
 let check value psw_value stack is_natural=
  let memory=M.create()in M.load memory ~address:0 seed;
  let cpu_state=S.create()in S.set_pc cpu_state !pc;S.set_sp cpu_state stack;S.set_a cpu_state value;S.set_bc cpu_state !bc;S.set_de cpu_state !de;S.set_hl cpu_state !hl;I8080.Flags.restore_from_psw_byte(S.flags cpu_state)psw_value;
  let host_memory=Pli80_host.State.of_bytes seed in
  let entry:H.state={pc= !pc;sp=stack;a=value;bc= !bc;de= !de;hl= !hl;flags=flags cpu_state}in
  let accesses=ref []in
  let host=H.run host_memory ~entry ~observe:(fun x->accesses:=x::!accesses)in
  let cpu=I8080.Cpu.create ~state:cpu_state ~bus:(I8080.Bus.create memory)in
  let actual=ref []and steps=ref 0 and done_=ref false in
  while not !done_ do
   incr steps;if !steps>16 then failwith"tail did not terminate";
   match I8080.Cpu.step cpu with Error _->failwith"tail CPU"|Ok w->
    List.iter(function I8080.Step.Read{address;value}->actual:=H.Read(address,value)::!actual|Write{address;value}->actual:=H.Write(address,value)::!actual)(I8080.Step.memory_accesses w);
    if I8080.Step.pc_before w=0x479a then done_:=true
  done;
  let actual_state:H.state={pc=S.pc cpu_state;sp=S.sp cpu_state;a=S.a cpu_state;bc=S.bc cpu_state;de=S.de cpu_state;hl=S.hl cpu_state;flags=flags cpu_state}in
  if host<>actual_state then failwith"tail registers, flags, PC or SP";
  if List.rev !accesses<>List.rev !actual then failwith"tail ordered memory accesses";
  let actual_ram=M.read_range memory ~address:0 ~length:65536 in
  if Pli80_host.State.copy host_memory<>actual_ram then failwith"tail full RAM";
  if is_natural then(
   if actual_ram<>captured_exit then failwith"natural exit RAM";
   if [|host.pc;host.sp;host.a;host.bc;host.de;host.hl;psw host.flags|]<>expected then failwith"natural exit state";
   natural:=true);
  incr cases in
 check !a !psw_in !sp true;
 List.iter(fun v->List.iter(fun psw_value->List.iter(fun stack->check v psw_value stack false)[!sp;0xad06;0xad07])[0x02;0xd7])[0;1;15;255];
 let c=open_out !output in Fun.protect ~finally:(fun()->close_out c)(fun()->Printf.fprintf c"{\"natural_passed\":%b,\"synthetic_cases\":%d,\"all_passed\":true,\"scope\":\"tail +2578..+259A only; no child or gateway replacement\"}\n" !natural(!cases-1))
