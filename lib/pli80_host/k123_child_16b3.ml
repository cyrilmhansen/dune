type state = {
  pc : int; sp : int; a : int; bc : int; de : int; hl : int;
  flags : Recursive_mapped.flags;
}
type access = Read of int * int | Write of int * int

let code = [
  0x21;0xef;0xac;0x70;0x2b;0x71;0x2a;0xee;0xac;
  0x22;0x9f;0xac;0x01;0x03;0x00;0x09;0x3e;0x07;
  0xa6;0xd6;0x00;0xd6;0x01;0x9f;0xc9;
]

let parity byte =
  let folded = byte lxor (byte lsr 4) in
  let folded = folded lxor (folded lsr 2) in
  (folded lxor (folded lsr 1)) land 1 = 0

let run memory ~entry ~observe =
  if entry.pc <> 0x38b3 then invalid_arg "k123 +16B3: wrong entry";
  List.iteri (fun i byte ->
    if State.read memory (0x38b3+i) <> byte then
      invalid_arg "k123 +16B3: historical code changed") code;
  let read address =
    let value = State.read memory address in
    observe (Read (address,value)); value in
  let write address value =
    State.write memory address value;
    observe (Write (address,value)) in
  let b = entry.bc lsr 8 and c = entry.bc land 255 in
  (* ACEE/ACEF are a live carrier. LHLD rereads them after the writes. *)
  write 0xacef b;
  write 0xacee c;
  let low = read 0xacee in
  let high = read 0xacef in
  let carrier = low lor (high lsl 8) in
  write 0xac9f low;
  write 0xaca0 high;
  let sum = carrier + 3 in
  let hl = U16.wrap sum in
  let _dad_carry = sum > 0xffff in
  (* MVI A,07; ANA M. ANA sets AC from bit3 and clears CY. *)
  let operand = read hl in
  let masked = 7 land operand in
  let _ana_flags : Recursive_mapped.flags = {
    sign = masked land 128 <> 0; zero = masked = 0;
    parity = parity masked; auxiliary_carry = (7 lor operand) land 8 <> 0;
    carry = false;
  } in
  (* SUI 0; SUI 1; SBB A. The last borrow controls the FF/00 mask. *)
  let after_zero = masked in
  let after_one = U8.wrap (after_zero-1) in
  let borrow = (Recursive_mapped.comparison after_zero 1).carry in
  let a = U8.wrap (after_one - after_one - (if borrow then 1 else 0)) in
  let flags : Recursive_mapped.flags = {
    sign = a land 128 <> 0; zero = a = 0; parity = parity a;
    auxiliary_carry = not borrow; carry = borrow;
  } in
  (* RET reads the current mutable stack word, including carrier aliases. *)
  let return_low = read entry.sp in
  let return_high = read (U16.wrap (entry.sp+1)) in
  { entry with pc = return_low lor (return_high lsl 8);
               sp = U16.wrap (entry.sp+2); a; bc = 3; hl; flags }
