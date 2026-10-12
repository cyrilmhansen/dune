type state = {
  pc : int; sp : int; a : int; bc : int; de : int; hl : int;
  flags : Recursive_mapped.flags;
}
type access = Read of int * int | Write of int * int

let root_code = [
  0x21;0x2f;0xae;0x72;0x2b;0x73;0x2b;0x71;
  0x3a;0x2d;0xae;0xfe;0x04;0xc2;0x18;0x9f;
  0xcd;0x17;0x9c;0x2a;0x2d;0xae;0x4d;0xcd;0xa7;0x95;
]
let early_code = [0x3a;0x04;0xae;0xfe;0x00;0xc2;0x20;0x9c;0xc9]

let run memory ~entry ~observe =
  if entry.pc <> 0x9f05 then invalid_arg "k123 +7D05: wrong entry";
  List.iteri (fun i byte ->
    if State.read memory (0x9f05+i) <> byte then
      invalid_arg "k123 +7D05: historical root code changed") root_code;
  List.iteri (fun i byte ->
    if State.read memory (0x9c17+i) <> byte then
      invalid_arg "k123 +7D05: historical +7A17 code changed") early_code;
  let read address =
    let value = State.read memory address in
    observe (Read (address,value)); value in
  let write address value =
    State.write memory address value;
    observe (Write (address,value)) in
  let push sp continuation =
    let next_sp = U16.wrap (sp-2) in
    write (U16.wrap (sp-1)) (continuation lsr 8);
    write next_sp (continuation land 255);
    next_sp in
  let b = entry.bc lsr 8 and c = entry.bc land 255 in
  let d = entry.de lsr 8 and e = entry.de land 255 in
  (* LXI H,AE2F; MOV M,D; DCX H; MOV M,E; DCX H; MOV M,C. *)
  write 0xae2f d;
  write 0xae2e e;
  write 0xae2d c;
  let a = read 0xae2d in
  let flags = Recursive_mapped.comparison a 4 in
  let a, flags =
    if flags.zero then (
      (* CALL +7A17, whose observed early arm reads fresh AE04 and RETs. *)
      let child_sp = push entry.sp 0x9f18 in
      let child_a = read 0xae04 in
      let child_flags = Recursive_mapped.comparison child_a 0 in
      if not child_flags.zero then
        invalid_arg "k123 +7D05: unsupported +7A17 nonzero arm";
      let low = read child_sp in
      let high = read (U16.wrap (child_sp+1)) in
      if low lor (high lsl 8) <> 0x9f18 then
        invalid_arg "k123 +7D05: modified early continuation";
      child_a, child_flags
    ) else a, flags in
  (* The paired AE2D read is fresh after the optional child CALL. *)
  let low = read 0xae2d in
  let high = read 0xae2e in
  let hl = low lor (high lsl 8) in
  let bc = (b lsl 8) lor low in
  let sp = push entry.sp 0x9f1f in
  { entry with pc=0x95a7;sp;a;bc;hl;flags }
