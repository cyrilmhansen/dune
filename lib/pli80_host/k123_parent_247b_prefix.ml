[@@@warning "-4-40-41-42"]
module Q=K123_child_7d05_front
module R=Recursive_mapped
module F=Acquisition_family
module Leaf=K123_child_16b3
module Branch=K123_child_branch

let run memory ~pli2 ~(entry:Q.state) ~observe =
  if entry.pc<>0x467b || entry.sp<0xb208 || entry.sp>0xfffc then
    invalid_arg "k123 +247B prefix entry/frame";
  List.iter(fun(a,b)->for offset=a to b-1 do
    if State.read memory(offset+0x2200)<>Char.code(Bytes.get pli2 offset) then
      invalid_arg "k123 +247B prefix immutable code"
  done)[0x247b,0x24bd;0x047d,0x0493];
  List.iteri(fun i byte->if State.read memory(0x1b29+i)<>byte then
    invalid_arg "k123 resident +1A29 immutable code")
    [0x5f;0x16;0;0x7b;0x95;0x6f;0x7a;0x9c;0x67;0xc9];
  let q=ref entry in
  let read a=let v=State.read memory a in observe(Q.Read(a,v));v in
  let word a=let lo=read a in let hi=read(a+1) in lo lor(hi lsl 8) in
  let write a v=State.write memory a v;observe(Q.Write(a,v)) in
  let push v=write(!q.sp-1)(v lsr 8);write(!q.sp-2)(v land 255);q:={!q with sp= !q.sp-2} in
  let pop()=let v=word !q.sp in q:={!q with sp= !q.sp+2};v in
  let psw f=(if f.R.sign then 128 else 0)lor(if f.zero then 64 else 0)lor
    (if f.auxiliary_carry then 16 else 0)lor(if f.parity then 4 else 0)lor 2 lor(if f.carry then 1 else 0) in
  let sub v=let f=R.comparison !q.a v in q:={!q with a=U8.wrap(!q.a-v);flags=f} in
  let mask()=let cy= !q.flags.carry in let a=if cy then 255 else 0 in
    q:={!q with a;flags={R.sign=a>=128;zero=a=0;parity=true;auxiliary_carry=not cy;carry=cy}} in
  let logical conjunction v=let old= !q.a in let a=if conjunction then old land v else old lor v in
    q:={!q with a;flags={R.sign=a>=128;zero=a=0;parity=(R.comparison a 0).parity;
      auxiliary_carry=conjunction && (old lor v)land 8<>0;carry=false}} in
  let c v=q:={!q with bc=(!q.bc land 0xff00)lor v} in
  let pair a=q:={!q with hl=word a} in
  let call site target fn=push(site+3);q:={!q with pc=target};q:=fn !q;
    if !q.pc<>site+3 then invalid_arg "k123 +247B child continuation" in
  let word_call site=call site 0x272c(fun entry->K123_canonical_word.run memory ~pli2 ~entry ~observe) in
  let raw_return r=let pc=pop() in q:={!q with pc;a=r.R.a;bc=r.bc;de=r.de;hl=r.hl;flags=r.flags};!q in
  let fail()=invalid_arg "k123 +247B unexpected canonical descendant" in
  let input(q:Q.state):R.returned={a=q.a;bc=q.bc;de=q.de;hl=q.hl;flags=q.flags} in
  push !q.hl;
  pair 0xad0d;c(!q.hl land 255);
  call 0x4680 0x267d(fun entry->
    let r=F.run(F.Pli2_output 0x047d)memory ~entry:(input entry)
      ~write:(fun ~site:_ ~address ~value->observe(Q.Write(address,value)))
      ~compatibility:(fun _->fail()) ~adjust:(fun ~site:_ ~delta:_->fail())
      ~sp:(fun()-> !q.sp) ~guard_field:(fun _ _->fail())
      ~native:(fun ~site:_ ~target:_ _->fail()) ~follow_spine:false
      ~software:(fun ~site:_ ~consumed:_->fail()) in raw_return r.returned);
  sub 6;sub 1;mask();push(!q.a lsl 8 lor psw !q.flags);
  pair 0xad0d;c(!q.hl land 255);word_call 0x468d;
  q:={!q with bc= !q.hl};
  call 0x4692 0x38b3(fun entry->
    let e:Leaf.state={pc=entry.pc;sp=entry.sp;a=entry.a;bc=entry.bc;de=entry.de;hl=entry.hl;flags=entry.flags} in
    let r=Leaf.run memory ~entry:e ~observe:(function Leaf.Read(a,v)->observe(Q.Read(a,v))|Write(a,v)->observe(Q.Write(a,v))) in
    {Q.pc=r.pc;sp=r.sp;a=r.a;bc=r.bc;de=r.de;hl=r.hl;flags=r.flags});
  let bc=pop() in q:={!q with bc};c(bc lsr 8);logical true(!q.bc land 255);
  let a= !q.a and cy= !q.flags.carry in
  q:={!q with a=(a lsr 1)lor(if cy then 128 else 0);flags={!q.flags with carry=a land 1<>0}};
  if not !q.flags.carry then invalid_arg "k123 +247B unsupported initial predicate route";
  pair 0xad0c;c(!q.hl land 255);word_call 0x46a0;
  q:={!q with a=0};
  call 0x46a5 0x1b29(fun entry->
    let r=Resident_reader.run Resident_reader.Byte_difference memory ~entry:(input entry)
      ~write:(fun ~site:_ ~address ~value->observe(Q.Write(address,value)))
      ~compatibility:(fun _->fail()) ~sp:(fun()-> !q.sp)
      ~invoke:(fun ~site:_ ~target:_ _->fail()) in raw_return r);
  logical false(!q.hl land 255);
  if !q.flags.zero then invalid_arg "k123 +247B unsupported zero difference route";
  pair 0xad0c;let de= !q.hl in q:={!q with hl= !q.de;de};c 4;
  call 0x46b2 0x9f31(fun entry->K123_parent_7d31.run memory ~pli2 ~entry ~observe);
  pair 0xad0d;c(!q.hl land 255);
  call 0x46b9 0x465d(fun entry->K123_child_245d.run memory ~pli2 ~entry ~observe);
  let e:Branch.state={pc= !q.pc;sp= !q.sp;a= !q.a;bc= !q.bc;de= !q.de;hl= !q.hl;flags= !q.flags} in
  let r=Branch.run memory ~entry:e ~observe:(function Branch.Read(a,v)->observe(Q.Read(a,v))|Write(a,v)->observe(Q.Write(a,v))) in
  {Q.pc=r.pc;sp=r.sp;a=r.a;bc=r.bc;de=r.de;hl=r.hl;flags=r.flags}
