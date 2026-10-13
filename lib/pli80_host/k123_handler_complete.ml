[@@@warning "-4-40-41-42"]
module Q=K123_child_7d05_front
module R=Recursive_mapped
module T=K123_handler_tail
let run memory ~pli2 ~pli_com ~(entry:Q.state) ~observe =
  if entry.pc<>0x476e || entry.sp<0xb20a || entry.sp>0xfffc then
    invalid_arg "k123 software handler entry/frame";
  List.iter(fun(a,b)->for offset=a to b-1 do
    if State.read memory(offset+0x2200)<>Char.code(Bytes.get pli2 offset) then
      invalid_arg "k123 handler immutable code"
  done)[0x256e,0x259b;0x059e,0x05b4];
  let read a=let v=State.read memory a in observe(Q.Read(a,v));v in
  let word a=let lo=read a in let hi=read(a+1) in lo lor(hi lsl 8) in
  let write a v=State.write memory a v;observe(Q.Write(a,v)) in
  if State.word memory entry.sp<>0x42b4 then invalid_arg "k123 original software continuation";
  write(entry.sp-1)0x47;write(entry.sp-2)0x71;
  let q={entry with Q.pc=0x467b;sp=entry.sp-2} in
  let q=K123_parent_247b.run memory ~pli2 ~pli_com ~entry:q ~observe in
  let hl=word 0xad0b in
  let q={q with Q.pc=0x279e;sp=q.sp-2;hl;bc=(q.bc land 0xff00)lor(hl land 255)} in
  write(q.sp+1)0x47;write q.sp 0x78;
  let fail()=invalid_arg "k123 +059E unexpected descendant" in
  let input:R.returned={a=q.a;bc=q.bc;de=q.de;hl=q.hl;flags=q.flags} in
  let r=Acquisition_family.run(Acquisition_family.Pli2_output 0x059e)memory ~entry:input
    ~write:(fun ~site:_ ~address ~value->observe(Q.Write(address,value)))
    ~compatibility:(fun _->fail()) ~adjust:(fun ~site:_ ~delta:_->fail()) ~sp:(fun()->q.sp)
    ~guard_field:(fun _ _->fail()) ~native:(fun ~site:_ ~target:_ _->fail())
    ~follow_spine:false ~software:(fun ~site:_ ~consumed:_->fail()) in
  let pc=word q.sp in if pc<>0x4778 then invalid_arg "k123 mapped child continuation";
  let r=r.returned in
  let tail:T.state={pc;sp=q.sp+2;a=r.a;bc=r.bc;de=r.de;hl=r.hl;flags=r.flags} in
  let r=T.run memory ~entry:tail ~observe:(function T.Read(a,v)->observe(Q.Read(a,v))|Write(a,v)->observe(Q.Write(a,v))) in
  if r.pc<>0x42b4 || r.sp<>entry.sp+2 then invalid_arg "k123 software RET ownership";
  {Q.pc=r.pc;sp=r.sp;a=r.a;bc=r.bc;de=r.de;hl=r.hl;flags=r.flags}
