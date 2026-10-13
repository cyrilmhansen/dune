(** Scoped +7D05 composition; retains the actual hardware continuation. *)
module Front = K123_child_7d05_front
module Emit = K123_child_7d05_emit
module Child = K123_child_785c

let run memory ~pli2 ~(entry:Front.state) ~observe =
  let q = Emit.run memory ~entry ~observe in
  if q.pc <> 0x9f28 then invalid_arg "k123 +7D05: wrong +785C adapter";
  let code = [0x2a;0x2e;0xae;0x44;0x4d;0xcd;0x5c;0x9a;0xc9] in
  List.iteri (fun i byte ->
    if State.read memory (0x9f28+i) <> byte then
      invalid_arg "k123 +7D05: adapter code changed") code;
  let read address =
    let value=State.read memory address in
    observe (Front.Read(address,value));value in
  let write address value =
    State.write memory address value;
    observe (Front.Write(address,value)) in
  (* LHLD AE2E, MOV B,H, MOV C,L, CALL +785C. *)
  let lo=read 0xae2e in
  let hi=read 0xae2f in
  let hl=lo lor (hi lsl 8) in
  let sp=U16.wrap(q.sp-2) in
  write (U16.wrap(q.sp-1)) 0x9f;
  write sp 0x30;
  let child_entry:Front.state={q with pc=0x9a5c;sp;bc=hl;hl} in
  let returned=Child.run memory ~pli2 ~entry:child_entry ~observe in
  if returned.pc<>0x9f30 || returned.sp<>q.sp then
    invalid_arg "k123 +7D05: child continuation";
  let low=read returned.sp in
  let high=read (U16.wrap(returned.sp+1)) in
  let continuation=low lor (high lsl 8) in
  if continuation<>0x9f46 then
    invalid_arg "k123 +7D05: original continuation changed";
  {returned with pc=continuation;sp=U16.wrap(returned.sp+2)}
