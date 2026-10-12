type state = {
  pc : int; sp : int; a : int; bc : int; de : int; hl : int;
  flags : Recursive_mapped.flags;
}

type access = Read of int * int | Write of int * int

let bytes = [
  (0x46bc, [0x1f; 0xd2; 0xcc; 0x46]);
  (0x46c0, [0x2a; 0x0d; 0xad; 0xeb; 0x0e; 0x09; 0xcd; 0xaa; 0xa3]);
  (0x46cc, [0x01; 0x06; 0x00; 0x2a; 0x9f; 0xac; 0x09; 0x3e; 0x00; 0xcd; 0xdc; 0xa5]);
]

let run memory ~entry ~observe =
  if entry.pc <> 0x46bc then invalid_arg "k123 +247B branch: wrong entry";
  List.iter (fun (start, code) ->
    List.iteri (fun i byte ->
      if State.read memory (start + i) <> byte then
        invalid_arg "k123 +247B branch: historical code changed") code) bytes;
  let read address =
    let value = State.read memory address in
    observe (Read (address, value)); value in
  let write address value =
    State.write memory address value; observe (Write (address, value)) in
  (* RAR changes carry to old A.bit0; JNC tests that actual carry. *)
  let carry = entry.a land 1 <> 0 in
  let a = (entry.a lsr 1) lor (if entry.flags.carry then 0x80 else 0) in
  let flags = { entry.flags with carry } in
  let bc, de, hl, a, target, return, dad_carry =
    if carry then (
      (* LHLD AD0D; XCHG; MVI C,09; CALL A3AA. *)
      let low = read 0xad0d in
      let high = read 0xad0e in
      let word = low lor (high lsl 8) in
      ((entry.bc land 0xff00) lor 9, word, entry.de, a, 0xa3aa, 0x46c9, false)
    ) else (
      (* LXI B,0006; LHLD AC9F; DAD B; MVI A,00; CALL A5DC. *)
      let low = read 0xac9f in
      let high = read 0xaca0 in
      let sum = low lor (high lsl 8) in
      (6, entry.de, U16.wrap (sum + 6), 0, 0xa5dc, 0x46d8, sum + 6 > 0xffff)
    ) in
  let flags = if carry then flags else { flags with carry = dad_carry } in
  (* CALL writes high then low, in the CPU's actual order. *)
  let sp = U16.wrap (entry.sp - 2) in
  write (U16.wrap (entry.sp - 1)) (return lsr 8);
  write sp (return land 255);
  { pc = target; sp; a; bc; de; hl; flags }
