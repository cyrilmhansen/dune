type state = {
  pc : int; sp : int; a : int; bc : int; de : int; hl : int;
  flags : Recursive_mapped.flags;
}
type access = Read of int * int | Write of int * int

let code = [
  0x32;0x07;0xad;0xfe;0x00;0xc2;0x85;0x47;0x21;0x07;0xad;
  0x36;0x10;0x3a;0x07;0xad;0xfe;0x01;0xc2;0x95;0x47;
  0x21;0x06;0xad;0x36;0x01;0xc3;0x9a;0x47;
  0x21;0x06;0xad;0x36;0x0f;0xc9;
]

let run memory ~entry ~observe =
  if entry.pc <> 0x4778 then invalid_arg "K123 tail: wrong entry";
  if List.exists(fun(a,b)->State.read memory (0x4778+a)<>b)(List.mapi(fun i v->i,v)code)
  then invalid_arg "K123 tail: historical code changed";
  let read address = let value=State.read memory address in observe(Read(address,value));value in
  let write address value = State.write memory address value;observe(Write(address,value)) in
  let a=ref entry.a and flags=ref entry.flags in
  (* STA AD07; CPI 0; JNZ 4785. The zero arm writes AD07 before LDA. *)
  write 0xad07 !a;
  flags:=Recursive_mapped.comparison !a 0;
  if !flags.zero then write 0xad07 0x10;
  (* LDA AD07; CPI 1; JNZ 4795. Both arms publish through HL=AD06. *)
  a:=read 0xad07;
  flags:=Recursive_mapped.comparison !a 1;
  write 0xad06 (if !flags.zero then 1 else 0x0f);
  (* RET consumes the actual mutable software word, including any alias. *)
  let low=read entry.sp in
  let high=read(U16.wrap(entry.sp+1))in
  {entry with pc=low lor(high lsl 8);sp=U16.wrap(entry.sp+2);
              a= !a;hl=0xad06;flags= !flags}
