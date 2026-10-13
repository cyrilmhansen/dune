[@@@warning "-4-40-41-42"]
module Q=K123_child_7d05_front

let run memory ~pli2 ~(entry:Q.state) ~observe =
  if entry.pc<>0x9f31 || entry.sp<0xb204 || entry.sp>0xfffc then
    invalid_arg "k123 +7D31 entry/frame scope";
  for offset=0x7d31 to 0x7d46 do
    if State.read memory(offset+0x2200)<>Char.code(Bytes.get pli2 offset) then
      invalid_arg "k123 +7D31 immutable code"
  done;
  let read a=let v=State.read memory a in observe(Q.Read(a,v));v in
  let word a=let lo=read a in let hi=read(a+1) in lo lor(hi lsl 8) in
  let write a v=State.write memory a v;observe(Q.Write(a,v)) in
  let push sp v=write(sp-1)(v lsr 8);write(sp-2)(v land 255);sp-2 in
  (* LXI AE31; MOV M,E; DCX; MOV M,C; LHLD AE31; MOV C,L. *)
  write 0xae31(entry.de land 255);write 0xae30(entry.bc land 255);
  let hl=word 0xae31 in
  let q={entry with Q.pc=0x272c;sp=push entry.sp 0x9f3e;
    hl;bc=(entry.bc land 0xff00)lor(hl land 255)} in
  let q=K123_canonical_word.run memory ~pli2 ~entry:q ~observe in
  if q.pc<>0x9f3e || q.sp<>entry.sp then invalid_arg "k123 +7D31 lookup continuation";
  (* XCHG; independent LHLD AE30; MOV C,L; hardware CALL +7D05. *)
  let hl=word 0xae30 in
  let child={q with Q.pc=0x9f05;sp=push q.sp 0x9f46;
    de=q.hl;hl;bc=(q.bc land 0xff00)lor(hl land 255)} in
  let q=K123_child_7d05_complete.run memory ~pli2 ~entry:child ~observe in
  if q.pc<>0x9f46 || q.sp<>entry.sp then invalid_arg "k123 +7D31 generation continuation";
  let pc=word q.sp in
  {q with Q.pc;sp=q.sp+2}
