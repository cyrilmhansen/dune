type state = {
  pc : int; sp : int; a : int; bc : int; de : int; hl : int;
  flags : Recursive_mapped.flags;
}
type access = Read of int * int | Write of int * int

let code = [
  0x22;0x9f;0xac;0x01;0x03;0x00;0x2a;0x9f;0xac;
  0x09;0x3e;0x80;0xa6;0xd6;0x80;0xd6;0x01;0x9f;0xc9;
]

let parity byte =
  let folded = byte lxor (byte lsr 4) in
  let folded = folded lxor (folded lsr 2) in
  (folded lxor (folded lsr 1)) land 1 = 0

let run memory ~entry ~observe =
  if entry.pc <> 0x4668 then invalid_arg "k123 +245D tail: wrong entry";
  List.iteri (fun i byte ->
    if State.read memory (0x4668+i) <> byte then
      invalid_arg "k123 +245D tail: historical code changed") code;
  let read address =
    let value = State.read memory address in
    observe (Read (address,value)); value in
  let write address value =
    State.write memory address value;
    observe (Write (address,value)) in
  (* SHLD AC9F uses actual HL, then LHLD rereads its mutable bytes. *)
  write 0xac9f (entry.hl land 255);
  write 0xaca0 (entry.hl lsr 8);
  let low = read 0xac9f in
  let high = read 0xaca0 in
  let sum = (low lor (high lsl 8)) + 3 in
  let hl = U16.wrap sum in
  let _dad_carry = sum > 0xffff in
  (* MVI A,80; ANA M; SUI 80; SUI 1; SBB A. *)
  let operand = read hl in
  let masked = 0x80 land operand in
  let _ana_flags : Recursive_mapped.flags = {
    sign = masked land 128 <> 0; zero = masked = 0;
    parity = parity masked; auxiliary_carry = (0x80 lor operand) land 8 <> 0;
    carry = false;
  } in
  let after_80 = U8.wrap (masked-0x80) in
  let after_one = U8.wrap (after_80-1) in
  let borrow = (Recursive_mapped.comparison after_80 1).carry in
  let a = U8.wrap (after_one-after_one-(if borrow then 1 else 0)) in
  let flags : Recursive_mapped.flags = {
    sign = a land 128 <> 0; zero = a = 0; parity = parity a;
    auxiliary_carry = not borrow; carry = borrow;
  } in
  let return_low = read entry.sp in
  let return_high = read (U16.wrap (entry.sp+1)) in
  { entry with pc = return_low lor (return_high lsl 8);
               sp = U16.wrap (entry.sp+2); a; bc = 3; hl; flags }

let through_branch memory ~entry ~observe =
  let after_tail = run memory ~entry ~observe in
  if after_tail.pc <> 0x46bc then
    invalid_arg "k123 +245D tail: nonstandard child continuation";
  let branch_entry : K123_child_branch.state = {
    pc = after_tail.pc; sp = after_tail.sp; a = after_tail.a;
    bc = after_tail.bc; de = after_tail.de; hl = after_tail.hl;
    flags = after_tail.flags;
  } in
  K123_child_branch.run memory ~entry:branch_entry
    ~observe:(function
      | K123_child_branch.Read (address,value) -> observe (Read (address,value))
      | Write (address,value) -> observe (Write (address,value)))
