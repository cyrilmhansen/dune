(* Historical-binary queries, not a native compiler implementation. *)
[@@@warning "-4-40-41-42"]
open I8080
let raw () = match Sys.getenv_opt "RUNES_HOST_IMAGES" with
 | None -> None
 | Some dir -> let ch=open_in_bin(Filename.concat dir "PLI1.OVL")in
   Some(Fun.protect ~finally:(fun()->close_in ch)(fun()->let b=Bytes.create(in_channel_length ch)in really_input ch b 0(Bytes.length b);b))
let query image off c a psw pointer selected =
 let m=Memory.create()in Memory.load m ~address:0x2200 image;
 Memory.write16 m 0xf000 0x100;Memory.write16 m 0xa6cb pointer;
 Memory.write m 0xa943 (255-c);Memory.write16 m ((pointer+2*c)land 65535) selected;
 Memory.write16 m 0xa863 pointer;
 let s=State.create()in State.set_pc s(off+0x2200);State.set_sp s 0xf000;
 State.set_b s ((c+93)land 255);State.set_c s c;State.set_a s a;State.set_de s 0x1937;Flags.restore_from_psw_byte(State.flags s)psw;
 let cpu=Cpu.create ~state:s ~bus:(Bus.create m)in let writes=ref[]and reads=ref[]in
 (* Finite reviewed local graphs; this assertion is an oracle-harness failure,
    never a substitute termination condition for a compiler operation. *)
 let n=ref 0 in while State.pc s<>0x100 do
  incr n;assert(!n<=30);
  let step=match Cpu.step cpu with Ok q->q|Error _->failwith"historical query failed"in
  List.iter(function Step.Read{address;value}->reads:=(address,value)::!reads|Step.Write{address;value}->writes:=(address,value)::!writes)(Step.memory_accesses step)
 done;s,m,List.rev !writes,List.rev !reads
let ()=match raw()with None->print_endline"historical leaf queries skipped (RUNES_HOST_IMAGES unset)"|Some image->
 assert(Bytes.sub_string image 0x5e65 23=Bytes.to_string(Bytes.of_string"\x21\x42\xa9\x71\x2a\x42\xa9\x26\x00\x29\xeb\x2a\xcb\xa6\x19\x5e\x23\x56\xeb\x22\x63\xa8\xc9"));
 let cases=ref 0 in
 for c=0 to 255 do for flags=0 to 31 do
  let psw=(if flags land 16<>0 then 0x80 else 0)lor(if flags land 8<>0 then 0x40 else 0)lor(if flags land 4<>0 then 0x10 else 0)lor(if flags land 2<>0 then 4 else 0)lor(flags land 1)in
  List.iter(fun pointer->
   let selected=(0x3517+257*c)land 65535 and a=(c+19)land 255 in
   let s,m,w,r=query image 0x5e65 c a psw pointer selected in incr cases;
   let address=(pointer+2*c)land 65535 in
   assert(State.a s=a&&State.bc s=(((c+93)land 255)lsl 8 lor c)&&State.hl s=selected&&State.de s=((address+1)land 65535));
   assert(State.sp s=0xf002&&State.pc s=0x100&&Memory.read16 m 0xa863=selected);
   assert(Flags.to_psw_byte(State.flags s)=(psw land 0xd4 lor 2 lor(if pointer+2*c>65535 then 1 else 0)));
   assert(w=[0xa942,c;0xa863,selected land 255;0xa864,selected lsr 8]);
   assert(List.mem(0xa943,255-c)r);
  )[0xc000;0xff00]
 done done;
 (* +5E48 exact field-bit mask, both outcomes and all incoming flags. *)
 for field=0 to 255 do for flags=0 to 31 do
  let psw=(flags land 1)lor(if flags land 16<>0 then 0x80 else 0)lor(if flags land 8<>0 then 0x40 else 0)lor(if flags land 4<>0 then 0x10 else 0)lor(if flags land 2<>0 then 4 else 0)in
  let pointer=0xc000 in
  let m=Memory.create()in Memory.load m ~address:0x2200 image;Memory.write16 m 0xf000 0x100;Memory.write16 m 0xa863 pointer;Memory.write m (pointer+3)field;
  let s=State.create()in State.set_pc s 0x8048;State.set_sp s 0xf000;State.set_de s 0x1937;Flags.restore_from_psw_byte(State.flags s)psw;
  let cpu=Cpu.create ~state:s ~bus:(Bus.create m)in let n=ref 0 in
  while State.pc s<>0x100 do incr n;assert(!n<=30);match Cpu.step cpu with Ok _->()|Error _->assert false done;
  let set=field land 0x40<>0 in
  assert(State.a s=(if set then 255 else 0));assert(State.bc s=3&&State.hl s=pointer+3&&State.de s=0x1937);
  assert(Flags.to_psw_byte(State.flags s)=(if set then 0x87 else 0x56));
  assert(Memory.read16 m 0xeffe=0x804b);incr cases
 done done;
 (* +81F1: exhaustive byte counter / incoming flags, legal shared-table state.
    Selected mapped destination AB7C is disjoint from all position-map reads. *)
 for count=0 to 255 do for flags=0 to 31 do
  let m=Memory.create()in Memory.load m ~address:0x2200 image;Memory.write16 m 0xf000 0x100;
  for p=0 to 255 do Memory.write m (0xaa1f+p) 200 done;
  Memory.write m 0xae32 37;Memory.write m 0xae33 200;Memory.write m 0xae34 0x89;
  let s=State.create()in State.set_pc s 0xa3f1;State.set_sp s 0xf000;State.set_c s count;State.set_b s 0x31;State.set_de s 0x1937;
  let psw=(flags land 1)lor(if flags land 16<>0 then 0x80 else 0)lor(if flags land 8<>0 then 0x40 else 0)lor(if flags land 4<>0 then 0x10 else 0)lor(if flags land 2<>0 then 4 else 0)in
  Flags.restore_from_psw_byte(State.flags s)psw;
  let cpu=Cpu.create ~state:s ~bus:(Bus.create m)in let steps=ref 0 and writes=ref 0 in
  while State.pc s<>0x100 do
   incr steps;assert(!steps<20000);
   let q=match Cpu.step cpu with Ok q->q|Error _->assert false in
   List.iter(function Step.Write{address;_}when address<0xeffc->incr writes|_->())(Step.memory_accesses q)
  done;
  assert(State.a s=0&&State.hl s=0xae77&&State.sp s=0xf002&&Flags.to_psw_byte(State.flags s)=0x56);
  assert(Memory.read m 0xae77=0&&Memory.read m 0xae32=((37-count)land 255));
  assert(!writes=1+8*count);
  if count=0 then assert(State.bc s=0x3100&&State.de s=0x1937)
  else(assert(State.bc s=0xaa1f&&State.de s=0x89c8);assert(Memory.read m 0xae35=((38-count)land 255));
   assert(Memory.read m 0xab7c=200&&Memory.read16 m 0xeffe=0xa40c&&Memory.read16 m 0xeffc=0x9db1));
  incr cases
 done done;
 Printf.printf"historical leaf queries: %d exact byte/flag/address cases passed\n"!cases
