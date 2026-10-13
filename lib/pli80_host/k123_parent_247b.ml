[@@@warning "-4-40-41-42"]
module Q=K123_child_7d05_front
module R=Recursive_mapped
module F=Acquisition_family
module H=Acquisition_parent

let subtraction memory ~pli2 ~pli_com:_ ~(entry:Q.state) ~observe =
  if entry.pc<>0xa5dc then invalid_arg "k123 +83DC entry";
  for offset=0x83dc to 0x83e7 do
    if State.read memory(offset+0x2200)<>Char.code(Bytes.get pli2 offset) then
      invalid_arg "k123 +83DC code"
  done;
  let read a=let v=State.read memory a in observe(Q.Read(a,v));v in
  (* MOV E,A; MVI D,0; SUB M; INX H; SBB M; XCHG. *)
  let low_operand=read entry.hl in
  let low=U8.wrap(entry.a-low_operand) in
  let borrow=if entry.a<low_operand then 1 else 0 in
  let pointer=U16.wrap(entry.hl+1) in
  let high_operand=read pointer in
  let high=U8.wrap(-high_operand-borrow) in
  let flags:R.flags={sign=high>=128;zero=high=0;parity=(R.comparison high 0).parity;
    auxiliary_carry=0>=(high_operand land 15)+borrow;carry=0<high_operand+borrow} in
  let lo=read entry.sp in let hi=read(U16.wrap(entry.sp+1)) in
  {entry with Q.pc=lo lor(hi lsl 8);sp=U16.wrap(entry.sp+2);
    a=high;de=pointer;hl=low lor(high lsl 8);flags}

let generation memory ~pli2 ~pli_com ~(entry:Q.state) ~observe =
  if not(List.mem entry.pc[0xa3aa;0xa3c0;0xa387;0x962a]) ||
     entry.sp<0xb208 || entry.sp>0xfffc then invalid_arg "k123 generation entry/frame";
  List.iter(fun(a,b)->for offset=a to b-1 do
    if State.read memory(offset+0x2200)<>Char.code(Bytes.get pli2 offset) then
      invalid_arg "k123 generation immutable code"
  done)[0x8187,0x81e3;0x7397,0x744d;0x746f,0x7529;0x753c,0x7647;
        0x765e,0x7675;0x77cc,0x7897;0x79b6,0x7a4e;0x8342,0x834d];
  if State.read memory 0x201d land 1<>0 || State.read memory 0x2029 land 1<>0 ||
     State.read memory 0x1d8a>110 || State.read memory 0x1d8b>=8 then
    invalid_arg "k123 generation bounded successful output";
  List.iter(fun(a,b)->for offset=a to b-1 do
    if State.read memory(offset+0x100)<>Char.code(Bytes.get pli_com offset) then
      invalid_arg "k123 generation resident code"
  done)[0x1140,0x1229;0x1a29,0x1a33];
  let sentinel=State.word memory 0x2155 in
  if (sentinel>=0xadab && sentinel<0xae5f) ||
     (sentinel>=0x1c2c && sentinel<0x1d8c) ||
     (sentinel>=0x20b6 && sentinel<0x20c0) ||
     (sentinel>=entry.sp-64 && sentinel<entry.sp+2) then
    invalid_arg "k123 generation sentinel alias";
  let q=ref entry in
  let read a=let v=State.read memory a in observe(Q.Read(a,v));v in
  let word a=let lo=read a in let hi=read(a+1) in lo lor(hi lsl 8) in
  let write a v=State.write memory a v;observe(Q.Write(a,v)) in
  let push v=write(!q.sp-1)(v lsr 8);write(!q.sp-2)(v land 255);q:={!q with sp= !q.sp-2} in
  let pop()=let v=word !q.sp in q:={!q with sp= !q.sp+2};v in
  let c v=q:={!q with bc=(!q.bc land 0xff00)lor v} in
  let pair a=q:={!q with hl=word a} in
  let exchange()=let de= !q.hl in q:={!q with hl= !q.de;de} in
  let input():R.returned={a= !q.a;bc= !q.bc;de= !q.de;hl= !q.hl;flags= !q.flags} in
  let canonical offset=
    let original_sp= !q.sp and frames=ref [] in
    let compatibility=function
      |H.Enter(site,target)->
        if State.read memory site<>0xcd || State.word memory(site+1)<>target then
          invalid_arg "k123 generation child CALL";
        frames:=(site+3)::!frames;push(site+3)
      |H.Leave->(match !frames with
        |resume::rest->if pop()<>resume then invalid_arg "k123 generation child RET";frames:=rest
        |[]->invalid_arg "k123 generation extra RET")
      |H.Push(_,v)->push v |H.Pop->ignore(pop())
      |_->invalid_arg "k123 generation unsupported stack action" in
    let fail()=invalid_arg "k123 generation unresolved descendant/service" in
    let guard_field pointer width=
      if pointer<0xf000 || width<0 || pointer+width>original_sp-512 then
        invalid_arg "k123 generation pointer/stack alias" in
    let r=F.run(F.Pli2_output offset)memory ~entry:(input())
      ~write:(fun ~site:_ ~address ~value->observe(Q.Write(address,value)))
      ~compatibility ~adjust:(fun ~site:_ ~delta:_->fail()) ~sp:(fun()-> !q.sp)
      ~guard_field ~native:(fun ~site:_ ~target:_ _->fail())
      ~follow_spine:false ~software:(fun ~site:_ ~consumed:_->fail()) in
    if !frames<>[] || !q.sp<>original_sp then invalid_arg "k123 generation frame balance";
    let pc=pop() in let r=r.returned in
    q:={!q with pc;a=r.a;bc=r.bc;de=r.de;hl=r.hl;flags=r.flags} in
  let call site target fn=
    push(site+3);q:={!q with pc=target};fn();
    if !q.pc<>site+3 then invalid_arg "k123 generation continuation" in
  let child site offset=call (site+0x2200)(offset+0x2200)(fun()->canonical offset) in
  let adapter offset =
    (* These two historical adapters differ only in scratch and final child. *)
    let saved,final=if offset=0x8187 then 0xae57,0x785c else 0xae5c,0x7619 in
    write(saved+2)(!q.de lsr 8);write(saved+1)(!q.de land 255);write saved(!q.bc land 255);
    child(offset+8)0x79e2;child(offset+11)0x7a17;child(offset+14)0x73d0;
    pair saved;exchange();c 0xc4;child(offset+23)0x756d;
    pair(saved+1);q:={!q with bc= !q.hl};child(offset+31)final;
    let pc=pop() in q:={!q with pc}
  in
  (match entry.pc with
   |0xa3aa->
     write 0xae5b(!q.de land 255);write 0xae5a(!q.bc land 255);
     pair 0xae5b;c(!q.hl land 255);
     call 0xa3b4 0x272c(fun()->q:=K123_canonical_word.run memory ~pli2 ~entry:!q ~observe);
     exchange();pair 0xae5a;c(!q.hl land 255);
     call 0xa3bc 0xa387(fun()->adapter 0x8187);
     let pc=pop() in q:={!q with pc}
   |0xa387->adapter 0x8187
   |0xa3c0->adapter 0x81c0
   |0x962a->canonical 0x742a
   |_->assert false);
  !q

let run memory ~pli2 ~pli_com ~(entry:Q.state) ~observe =
  for offset=0x24bc to 0x256d do
    if State.read memory(offset+0x2200)<>Char.code(Bytes.get pli2 offset) then
      invalid_arg "k123 +247B immutable suffix"
  done;
  List.iter(fun(a,b)->for offset=a to b-1 do
    if State.read memory(offset+0x100)<>Char.code(Bytes.get pli_com offset) then
      invalid_arg "k123 +247B resident code"
  done)[0x1140,0x1229;0x1a29,0x1a33];
  let q=ref(K123_parent_247b_prefix.run memory ~pli2 ~entry ~observe) in
  let read a=let v=State.read memory a in observe(Q.Read(a,v));v in
  let word a=let lo=read a in let hi=read(a+1) in lo lor(hi lsl 8) in
  let write a v=State.write memory a v;observe(Q.Write(a,v)) in
  let push v=write(!q.sp-1)(v lsr 8);write(!q.sp-2)(v land 255);q:={!q with sp= !q.sp-2} in
  let pop()=let v=word !q.sp in q:={!q with sp= !q.sp+2};v in
  let call site target=
    push(site+3);q:={!q with pc=target};q:=generation memory ~pli2 ~pli_com ~entry:!q ~observe;
    if !q.pc<>site+3 then invalid_arg "k123 +247B suffix continuation" in
  if !q.pc=0xa5dc then (
    q:=subtraction memory ~pli2 ~pli_com ~entry:!q ~observe;
    let a= !q.a lor(!q.hl land 255) in
    q:={!q with a;flags={R.sign=a>=128;zero=a=0;parity=(R.comparison a 0).parity;
                        auxiliary_carry=false;carry=false}};
    if not !q.flags.zero then invalid_arg "k123 +247B nonzero +83DC route unsupported";
    q:={!q with de=0;bc=(!q.bc land 0xff00)lor 9};call 0x46e1 0xa3c0;
    call 0x46f0 0x962a;
    q:={!q with hl=U16.wrap(!q.hl-2);bc=6};push !q.hl;
    let pointer=word 0xac9f in
    let sum=pointer+6 in q:={!q with hl=U16.wrap sum;flags={!q.flags with carry=sum>65535}};
    let bc=pop() in q:={!q with bc};
    write !q.hl(!q.bc land 255);q:={!q with hl=U16.wrap(!q.hl+1)};
    write !q.hl(!q.bc lsr 8)
  ) else if !q.pc=0xa3aa then q:=generation memory ~pli2 ~pli_com ~entry:!q ~observe
  else invalid_arg "k123 +247B unexpected branch target";
  let hl=pop() in q:={!q with hl};
  let pc=pop() in
  if pc<>0x4771 || !q.sp<>entry.sp+2 then invalid_arg "k123 +247B original frame";
  {!q with Q.pc}
