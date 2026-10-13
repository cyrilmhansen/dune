[@@@warning "-4-40-41-42"]
(** Canonical +052C with its actual hardware stack, reused by k123 parents. *)
module Q=K123_child_7d05_front
module F=Acquisition_family
module H=Acquisition_parent
module R=Recursive_mapped

let run memory ~pli2 ~(entry:Q.state) ~observe =
  if entry.pc<>0x272c || entry.sp<0xb200 || entry.sp>0xfffc then
    invalid_arg "k123 +052C entry/frame scope";
  List.iter(fun(a,b)->for offset=a to b-1 do
    if State.read memory(offset+0x2200)<>Char.code(Bytes.get pli2 offset) then
      invalid_arg "k123 +052C immutable code"
  done)[0x04e9,0x0546;0x8398,0x83a2;0x83b4,0x83ba];
  let stack=ref entry.sp and frames=ref [] in
  let read a=let v=State.read memory a in observe(Q.Read(a,v));v in
  let write a v=State.write memory a v;observe(Q.Write(a,v)) in
  let push v=write(!stack-1)(v lsr 8);write(!stack-2)(v land 255);stack:= !stack-2 in
  let pop ()=let lo=read !stack in let hi=read(!stack+1) in
    stack:= !stack+2;lo lor(hi lsl 8) in
  let compatibility=function
    |H.Enter(site,target)->
      if State.read memory site<>0xcd || State.word memory(site+1)<>target then
        invalid_arg "k123 +052C child CALL identity";
      frames:=(site+3)::!frames;push(site+3)
    |H.Leave->(match !frames with
      |resume::rest->if pop()<>resume then invalid_arg "k123 +052C child continuation";frames:=rest
      |[]->invalid_arg "k123 +052C extra RET")
    |H.Push(_,v)->push v
    |H.Pop->ignore(pop())
    |_->invalid_arg "k123 +052C unsupported stack action" in
  let fail ()=invalid_arg "k123 +052C unexpected descendant" in
  let input:R.returned={a=entry.a;bc=entry.bc;de=entry.de;hl=entry.hl;flags=entry.flags} in
  let result=F.run(F.Pli2_output 0x052c)memory ~entry:input
    ~write:(fun ~site:_ ~address ~value->observe(Q.Write(address,value)))
    ~compatibility ~adjust:(fun ~site:_ ~delta:_->fail()) ~sp:(fun()-> !stack)
    ~guard_field:(fun _ _->fail()) ~native:(fun ~site:_ ~target:_ _->fail())
    ~follow_spine:false ~software:(fun ~site:_ ~consumed:_->fail()) in
  if !frames<>[] || !stack<>entry.sp then invalid_arg "k123 +052C frame imbalance";
  let pc=pop() in let r=result.returned in
  {Q.pc;sp= !stack;a=r.a;bc=r.bc;de=r.de;hl=r.hl;flags=r.flags}
