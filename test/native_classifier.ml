[@@@warning "-4-40-41-42"]
module H=Pli80_host.Classifier
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
open I8080
let image()=match Sys.getenv_opt"RUNES_HOST_IMAGES"with None->None|Some dir->
 let ch=open_in_bin(Filename.concat dir"PLI1.OVL")in
 Some(Fun.protect ~finally:(fun()->close_in ch)(fun()->let b=Bytes.create(in_channel_length ch)in really_input ch b 0(Bytes.length b);b))
let q_of s:R.returned={a=State.a s;bc=State.bc s;de=State.de s;hl=State.hl s;
 flags={sign=Flags.sign(State.flags s);zero=Flags.zero(State.flags s);auxiliary_carry=Flags.auxiliary_carry(State.flags s);parity=Flags.parity(State.flags s);carry=Flags.carry(State.flags s)}}
let ()=match image()with None->print_endline"classifier historical checks skipped (RUNES_HOST_IMAGES unset)"|Some image->
 let cases=ref 0 in
 List.iter(fun selector->for psw_bits=0 to 31 do
  let ram=Bytes.make 65536 '\000'in Bytes.blit image 0 ram 0x2200(Bytes.length image);
  let put a v=Bytes.set ram a(Char.chr v)in
  put 0xa628 selector;put 0xa64e 0x97;put 0xa648 0x86;put 0xa646 0x75;
  put 0xf000 0;put 0xf001 1;
  let memory=Memory.create()in Memory.load memory ~address:0 ram;
  let state=State.create()in State.set_pc state 0x459a;State.set_sp state 0xf000;
  State.set_a state 0x93;State.set_bc state 0x1729;State.set_de state 0x3456;State.set_hl state 0x8765;
  let psw=(if psw_bits land 16<>0 then 128 else 0)lor(if psw_bits land 8<>0 then 64 else 0)lor(if psw_bits land 4<>0 then 16 else 0)lor(if psw_bits land 2<>0 then 4 else 0)lor(psw_bits land 1)in
  Flags.restore_from_psw_byte(State.flags state)psw;
  let initial=q_of state in let cpu=Cpu.create ~state ~bus:(Bus.create memory)in
  let n=ref 0 in while State.pc state<>0x100 do incr n;assert(!n<500);match Cpu.step cpu with Ok _->()|Error _->failwith"classifier oracle"done;
  let native=S.of_bytes ram and sp=ref 0xf000 in
  let push _ value=S.write native(!sp-1)(value lsr 8);S.write native(!sp-2)(value land 255);sp:= !sp-2 in
  let pop()=sp:= !sp+2 in
  let call site _ fn=push site(site+3);fn();pop()in
  let actual=H.run native ~entry:initial ~write:(fun ~site:_ ~address:_ ~value:_->())~call ~push ~pop in
  assert(actual=q_of state);assert(!sp=0xf000&&State.sp state=0xf002);
  for a=0 to 65535 do assert(S.read native a=Memory.read memory a)done;
  incr cases
 done)[2;5;0x15;0x31;0x40;0x80];
 Printf.printf"Classifier: %d complete register/flag/RAM historical cases\n"!cases
