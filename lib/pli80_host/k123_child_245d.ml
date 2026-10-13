[@@@warning "-4-40-41-42"]
module Q=K123_child_7d05_front
module T=K123_child_245d_tail
let run memory ~pli2 ~(entry:Q.state) ~observe =
  if entry.pc<>0x465d || entry.sp<0xb202 then invalid_arg "k123 +245D entry/frame";
  for offset=0x245d to 0x247a do
    if State.read memory(offset+0x2200)<>Char.code(Bytes.get pli2 offset) then
      invalid_arg "k123 +245D immutable code"
  done;
  let read a=let v=State.read memory a in observe(Q.Read(a,v));v in
  let write a v=State.write memory a v;observe(Q.Write(a,v)) in
  write 0xad32(entry.bc land 255);
  let low=read 0xad32 in let high=read 0xad33 in
  write(entry.sp-1)0x46;write(entry.sp-2)0x68;
  let q={entry with Q.pc=0x272c;sp=entry.sp-2;
    hl=low lor(high lsl 8);bc=(entry.bc land 0xff00)lor low} in
  let q=K123_canonical_word.run memory ~pli2 ~entry:q ~observe in
  if q.pc<>0x4668 || q.sp<>entry.sp then invalid_arg "k123 +245D lookup continuation";
  let input:T.state={pc=q.pc;sp=q.sp;a=q.a;bc=q.bc;de=q.de;hl=q.hl;flags=q.flags} in
  let r=T.run memory ~entry:input ~observe:(function
    |T.Read(a,v)->observe(Q.Read(a,v))|T.Write(a,v)->observe(Q.Write(a,v))) in
  {Q.pc=r.pc;sp=r.sp;a=r.a;bc=r.bc;de=r.de;hl=r.hl;flags=r.flags}
