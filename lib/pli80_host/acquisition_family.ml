[@@@warning "-4-40-41-42"]
(** Bounded nested-base acquisition family. Procedure calls are named historical
    algorithms; no instruction decoder, guest PC loop or oracle state. The
    separate compatibility planner supplies the actual CALL/private-frame stack. *)
module R=Recursive_mapped
module S=State
module U=U16
module B=U8
module H=Acquisition_parent
module K=Classifier
type operation=Context|Field|Attribute|Spine|Resident|Pair_gate|Selected_transform|Table_adapter|Wrapper|Repeat
type result={returned:R.returned;field:int option}
let run operation memory ~entry ~write ~compatibility ~adjust ~sp ~guard_field ~native ~follow_spine ~software =
 B.check entry.R.a;List.iter U.check[entry.bc;entry.de;entry.hl;sp()];
 let q=ref entry and acquired_field=ref None in
 let need condition text=if not condition then invalid_arg("Acquisition_family: "^text)in
 let read=S.read memory and word=S.word memory in
 let put site address value=S.write memory address value;write ~site:(site+0x2200) ~address ~value in
 let store site address value=put site address(value land 255);put site(U.wrap(address+1))(value lsr 8)in
 let a value=q:={!q with R.a=value}and bc value=q:={!q with R.bc=value}and de value=q:={!q with R.de=value}and hl value=q:={!q with R.hl=value}in
 let c value=q:={!q with R.bc=(!q.bc land 0xff00)lor value}and e value=q:={!q with R.de=(!q.de land 0xff00)lor value}in
 let pair address=hl(word address)in
 let parity n=let n=n lxor(n lsr 4)in let n=n lxor(n lsr 2)in(n lxor(n lsr 1))land 1=0 in
 let flags n ac cy={R.sign=n>=128;zero=n=0;parity=parity n;auxiliary_carry=ac;carry=cy}in
 let cmp v=q:={!q with R.flags=R.comparison !q.a v}in
 let sub v=let old= !q.a in cmp v;a(B.wrap(old-v))in
 let add v=let old= !q.a in let sum=old+v in let n=B.wrap sum in q:={!q with R.a=n;flags=flags n((old land 15)+(v land 15)>15)(sum>255)}in
 let mask()=let borrow= !q.flags.carry in let n=if borrow then 255 else 0 in q:={!q with R.a=n;flags=flags n(not borrow)borrow}in
 let logical conjunction v=let old= !q.a in let n=if conjunction then old land v else old lor v in q:={!q with R.a=n;flags=flags n(conjunction&&(old lor v)land 8<>0)false}in
 let ani v=logical true v in
 let rar()=let old= !q.a in q:={!q with R.a=(old lsr 1)lor(if !q.flags.carry then 128 else 0);flags={!q.flags with carry=old land 1<>0}}in
 let dad v=let sum= !q.hl+v in q:={!q with R.hl=U.wrap sum;flags={!q.flags with carry=sum>65535}}in
 let inc v=let n=B.wrap(v+1)in q:={!q with R.flags=flags n(v land 15=15)!q.flags.carry};n in
 let exchange()=let old= !q.hl in hl !q.de;de old in
 let psw()=let f= !q.flags in (if f.sign then 128 else 0)lor(if f.zero then 64 else 0)lor(if f.auxiliary_carry then 16 else 0)lor(if f.parity then 4 else 0)lor 2 lor(if f.carry then 1 else 0)in
 let push site value=compatibility(H.Push(site+0x2200,value))in
 let pop()=let value=word(sp())in compatibility H.Pop;value in
 let save site=push site(!q.a lsl 8 lor psw())in
 let restore()=let v=pop()in bc v;c(v lsr 8)in
 let frame offset=hl offset;dad(sp())in
 let call site target fn=compatibility(H.Enter(site+0x2200,target+0x2200));fn();compatibility H.Leave in
 let resident site target fn=compatibility(H.Enter(site+0x2200,target+0x100));fn();compatibility H.Leave in
 let child site target=call site target(fun()->q:=native ~site:(site+0x2200) ~target:(target+0x2200) !q)in
 let reuse op=q:=(H.run ~operation:op memory ~entry:!q ~write ~compatibility ~guard_field ~saved:(fun _->invalid_arg"Acquisition_family: unexpected saved child")).returned in
 let classifier op=q:=K.run ~operation:op memory ~entry:!q ~write
  ~call:(fun site target fn->compatibility(H.Enter(site,target));fn();compatibility H.Leave)
  ~push:(fun site value->compatibility(H.Push(site,value)))~pop:(fun()->compatibility H.Pop)in
 let difference left right=
  let low=(left land 255)-(right land 255)in let borrow=if low<0 then 1 else 0 in
  let l=left lsr 8 and r=right lsr 8 in let high=B.wrap(l-r-borrow)in
  q:={!q with R.a=high;hl=high lsl 8 lor B.wrap low;flags=flags high((l land 15)>=(r land 15)+borrow)(l<r+borrow)}in
 let pointer_words()=hl !q.bc;bc(word !q.hl);difference(word !q.de)!q.bc;de(U.wrap(!q.de+1))in
 let pointer_minus()=difference(word !q.de)!q.hl;de(U.wrap(!q.de+1))in
 let tag()=pair 0xa863;guard_field !q.hl 4;hl(U.wrap(!q.hl+2));a(read !q.hl)in
 let field_byte()=bc 3;pair 0xa863;guard_field !q.hl 4;dad !q.bc;a(read !q.hl)in
 let low_field()=bc 3;pair 0xa863;guard_field !q.hl 4;dad !q.bc;a 7;logical true(read !q.hl)in
 let high_field()=pair 0xa863;guard_field !q.hl 2;hl(U.wrap(!q.hl+1));a 0xe0;logical true(read !q.hl)in
 let count_field()=pair 0xa863;guard_field !q.hl 2;hl(U.wrap(!q.hl+1));a 0x1f;logical true(read !q.hl)in
 let bit7()=call 0x3558 0x41a6 field_byte;ani 128;sub 128;sub 1;mask()in
 let select_nested()=
  hl 0xa942;put 0x5e68 !q.hl(!q.bc land 255);pair 0xa942;hl(!q.hl land 255);dad !q.hl;exchange();pair 0xa6cb;dad !q.de;
  guard_field !q.hl 2;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();store 0x5e78 0xa863 !q.hl in
 let selector_match()=
  hl 0xa5af;put 0x01b2 !q.hl(!q.bc land 255);hl 0xa5af;a(read 0x20c3);cmp(read !q.hl);
  if !q.flags.zero then(call 0x01bd 0x784e(fun()->reuse H.Acquire_overlay);a 1)else a 0 in
 let cleanup()=
  hl 0xa90a;put 0x4604 !q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put 0x4606 !q.hl(!q.bc land 255);
  pair 0xa909;store 0x460a 0xa863 !q.hl;call 0x460d 0x4227 count_field;put 0x4610 0xa90b !q.a;
  bc 10;pair 0xa863;dad !q.bc;store 0x461a 0xa909 !q.hl;call 0x461d 0x428e(fun()->reuse H.Successor);
  pair 0xa909;bc !q.hl;pair 0xa90b;exchange();call 0x4629 0x4584(fun()->reuse H.Payload_match)in
 let classification()=
  call 0x429d 0x419f tag;put 0x42a0 0xa8f3 !q.a;
  call 0x42a3 0x41a6 field_byte;put 0x42a6 0xa8f4 !q.a;
  bc 4;pair 0xa863;dad !q.bc;a(read !q.hl);put 0x42b1 0xa8f5 !q.a;
  a(read 0xa8f3);cmp 0x15;
  if !q.flags.zero then(a(read 0xa8f5);ani 0xfc;rar();rar();rar();a(inc !q.a))else(
   List.iter(fun value->a(read 0xa8f3);cmp value;need(not !q.flags.zero)"429D selector16/19")[0x16;0x19];
   a(read 0xa8f3);ani 0x24;cmp 0x24;need(not !q.flags.zero)"429D mask24";
   a(read 0xa8f3);ani 0x28;cmp 0x28;need(not !q.flags.zero)"429D mask28";
   a(read 0xa8f3);cmp 0x30;if !q.flags.zero then a 2 else(
    a(read 0xa8f3);sub 0x40;sub 1;mask();save 0x4336;
    a(read 0xa8f3);sub 0x41;sub 1;mask();restore();logical false(!q.bc land 255);save 0x4342;
    a(read 0xa8f4);ani 0x40;sub 0x40;sub 1;mask();restore();logical true(!q.bc land 255);rar();need(not !q.flags.carry)"429D special mask";
    List.iter(fun value->a(read 0xa8f3);cmp value;need(not !q.flags.zero)"429D field44/42")[0x44;0x42];a 0))in
 let prepare_pointer()=
  List.iter(fun site->push site !q.hl)[0x3963;0x3964;0x3965;0x3966];
  push 0x3967 !q.bc;frame 0;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();store 0x3970 0xa863 !q.hl;
  call 0x3973 0x419f tag;cmp 0x70;need(not !q.flags.zero)"3963 field70";
  call 0x397b 0x429d classification;hl !q.a;
  for _=1 to 5 do de(pop())done in
 let bound_test()=
  hl 0xa6e0;put 0x3882 !q.hl(!q.de lsr 8);hl(U.wrap(!q.hl-1));put 0x3884 !q.hl(!q.de land 255);hl(U.wrap(!q.hl-1));put 0x3886 !q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put 0x3888 !q.hl(!q.bc land 255);
  de 0xa6df;bc 0xa6dd;resident 0x388f 0x1a33 pointer_words;need(not !q.flags.carry)"387F borrow alternative";
  pair 0xa6dd;store 0x389b 0xa863 !q.hl;call 0x389e 0x419f tag;cmp 0x70;need(not !q.flags.zero)"387F field70";a 0 in
 let advance()=pair 0xa863;guard_field !q.hl 1;e(read !q.hl);de(!q.de land 255);pair 0xa863;dad !q.de;store 0x424b 0xa863 !q.hl in
 let advance_matching()=
  hl 0xa8f2;put 0x4252 !q.hl(!q.bc land 255);
  let rec loop()=
   call 0x4253 0x4241 advance;exchange();hl 0xa861;
   call 0x425a 0x83a3(fun()->let address= !q.hl in difference !q.de(word address);de(U.wrap(address+1)));
   if not !q.flags.carry then(hl 0;store 0x4271 0xa863 !q.hl)
   else(call 0x4260 0x421f high_field;hl 0xa8f2;cmp(read !q.hl);if not !q.flags.zero then loop())in loop()in
 let pointer_walk()=
  hl 0xa744;put 0x3a79 !q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put 0x3a7b !q.hl(!q.bc land 255);pair 0xa743;store 0x3a7f 0xa745 !q.hl;store 0x3a82 0xa863 !q.hl;
  call 0x3a85 0x41af low_field;cmp 2;need(not !q.flags.zero)"3A76 initial low3=2";
  hl 0xa6e2;put 0x3a96 !q.hl 0;pair 0xa743;bc !q.hl;call 0x3a9d 0x3963 prepare_pointer;store 0x3aa0 0xa723 !q.hl;
  pair 0xa745;store 0x3aa6 0xa863 !q.hl;
  let rec loop()=
   call 0x3aa9 0x4275(fun()->reuse H.Pointer_compare);
   de 0xa743;bc 0xa863;save 0x3ab2;resident 0x3ab3 0x1a33 pointer_words;mask();a(!q.a lxor 255);restore();logical true(!q.bc land 255);rar();
   if !q.flags.carry then(
    bc 0xa743;de 0xa745;resident 0x3ac5 0x1a33 pointer_words;logical false(!q.hl land 255);sub 1;mask();save 0x3acc;
    pair 0xa745;bc !q.hl;pair 0xa743;exchange();call 0x3ad6 0x387f bound_test;restore();logical false(!q.bc land 255);rar();
    if !q.flags.carry then(pair 0xa745;store 0x3ae3 0xa863 !q.hl;call 0x3ae6 0x3558 bit7;rar();need(not !q.flags.carry)"3A76 bit7 acquisition alternative");
    pair 0xa745;store 0x3be7 0xa863 !q.hl;c 0;call 0x3bec 0x424f advance_matching;pair 0xa863;store 0x3bf2 0xa745 !q.hl;loop()
   )else(a(read 0xa6e2);cmp 0;need !q.flags.zero "3A76 nonzero tail")in loop()in
 let private_selection()=
  adjust ~site:0x5e8a ~delta:(-1);push 0x3c8b !q.hl;push 0x3c8c !q.hl;
  bc((!q.bc land 255)lsl 8 lor(!q.bc land 255));push 0x3c8e !q.bc;adjust ~site:0x5e8f ~delta:1;
  pair 0xa635;bc !q.hl;call 0x3c95 0x3a76 pointer_walk;
  hl 0xa628;put 0x3c9b !q.hl 0x15;hl 0xa62e;put 0x3ca0 !q.hl 0;
  a(read 0xae32);frame 1;put 0x3ca9 !q.hl !q.a;a 0;hl(U.wrap(!q.hl+3));put 0x3caf !q.hl !q.a;hl(U.wrap(!q.hl+1));put 0x3cb1 !q.hl 0;
  a 0;frame 0;cmp(read !q.hl);need(not !q.flags.carry)"3C8A positive-count body";
  frame 4;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();for _=1 to 3 do de(pop())done in
 let cached_selector()=call 0x415e 0x419f tag;put 0x4161 0xa75f !q.a;hl 0xa6e2;a(read 0xa754);cmp(read !q.hl);need !q.flags.zero "415E unequal saved count";a(read 0xa75f);put 0x4176 0xa628 !q.a in
 let common_gate()=
  need((!q.bc land 255)=0)"3DD9 bounded input C";
  hl 0xa755;put 0x3ddc !q.hl(!q.de land 255);hl(U.wrap(!q.hl-1));put 0x3dde !q.hl(!q.bc land 255);
  pair 0xa6cb;guard_field !q.hl 2;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();store 0x3de6 0xa863 !q.hl;
  pair 0xa6cb;guard_field !q.hl 2;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();store 0x3df0 0xa75a !q.hl;
  pair 0xa6ca;hl(!q.hl land 255);dad !q.hl;exchange();pair 0xa6cb;dad !q.de;guard_field !q.hl 2;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();store 0x3e02 0xa75c !q.hl;
  call 0x3e05 0x41af low_field;sub 2;sub 1;mask();save 0x3e0d;
  a(read 0xa6ca);sub 0;add 255;mask();restore();logical false(!q.bc land 255);rar();need(not !q.flags.carry)"3DD9 initial gate";
  a(read 0xa755);cmp 0;
  if not !q.flags.zero then(
   pair 0xa75c;store 0x3f4e 0xa635 !q.hl;pair 0xa754;c(!q.hl land 255);call 0x3f55 0x3c8a private_selection;store 0x3f58 0xa758 !q.hl;
   pair 0xa75a;store 0x3f5e 0xa863 !q.hl;pair 0xa6cb;push 0x3f64 !q.hl;pair 0xa863;exchange();hl(pop());put 0x3f6a !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x3f6c !q.hl(!q.de lsr 8);
   pair 0xae32;c(!q.hl land 255);child 0x3f71 0x7b7a;put 0x3f74 0xa75e !q.a;call 0x3f77 0x415e cached_selector;
   pair 0xa75e;c(!q.hl land 255);pair 0xa75f;exchange();child 0x3f82 0x7b13;
   bc 4;pair 0xa863;dad !q.bc;e(read !q.hl);pair 0xa75e;c(!q.hl land 255);child 0x3f91 0x7b2e;
   bc 5;pair 0xa863;dad !q.bc;e(read !q.hl);pair 0xa75e;c(!q.hl land 255);child 0x3fa0 0x7b49;
   bc 4;pair 0xa863;dad !q.bc;a(read !q.hl);put 0x3fab 0xa62b !q.a;
   pair 0xa863;bc(U.wrap(!q.bc+1));dad !q.bc;a(read !q.hl);put 0x3fb4 0xa62e !q.a;
   call 0x3fb7 0x239a(fun()->classifier K.Wrapper);a(inc !q.a);pair 0xa75e;e !q.a;c(!q.hl land 255);child 0x3fc0 0x7ad5;
   pair 0xa75e;c(!q.hl land 255);pair 0xa863;exchange();child 0x3fcb 0x7af0;
   pair 0xa75c;store 0x3fd1 0xa863 !q.hl;de 0xa75a;resident 0x3fd7 0x1a43 pointer_minus;logical false(!q.hl land 255);need !q.flags.zero "3DD9 unequal pointers";
   bc 0xa75a;de 0xa75c;resident 0x3ff6 0x1a33 pointer_words;logical false(!q.hl land 255);add 255;mask();save 0x3ffd;
   a 0;de 0xa758;resident 0x4003 0x1a40(fun()->hl !q.a;pointer_minus());logical false(!q.hl land 255);add 255;mask();restore();logical false(!q.bc land 255);rar();need(not !q.flags.carry)(Printf.sprintf"3DD9 publication alternatives first=%04X last=%04X saved=%04X maskA=%02X BC=%04X"(word 0xa75a)(word 0xa75c)(word 0xa758)!q.a !q.bc);
   pair 0xae32;c(!q.hl land 255);pair 0xa628;exchange();child 0x405c 0x7b13;
   pair 0xae32;c(!q.hl land 255);pair 0xa62b;exchange();child 0x4067 0x7b2e;
   pair 0xae32;c(!q.hl land 255);pair 0xa62e;exchange();child 0x4072 0x7b49);
  hl 0xa75e;put 0x4078 !q.hl 0;pair 0xa75a;store 0x407d 0xa758 !q.hl;
  let rec scan()=
   de 0xa75c;bc 0xa758;resident 0x4086 0x1a33 pointer_words;
   if not !q.flags.carry then(
    pair 0xa758;store 0x408f 0xa863 !q.hl;call 0x4092 0x421f high_field;cmp 0;need !q.flags.zero "3DD9 traversal high field";
    pair 0xa758;bc !q.hl;pair 0xa75c;exchange();call 0x40a3 0x387f bound_test;
    bc 0xa75c;de 0xa758;save 0x40ac;resident 0x40ad 0x1a33 pointer_words;logical false(!q.hl land 255);sub 1;mask();restore();logical false(!q.bc land 255);rar();need !q.flags.carry "3DD9 traversal bound";
    pair 0xa758;store 0x40be 0xa863 !q.hl;call 0x40c1 0x3558 bit7;rar();need(not !q.flags.carry)"3DD9 traversal bit7";
    pair 0xa863;guard_field !q.hl 1;e(read !q.hl);de(!q.de land 255);pair 0xa863;dad !q.de;store 0x40eb 0xa758 !q.hl;scan())in scan();
  a(read 0xa755);cmp 1;
  if !q.flags.zero then(
   call 0x40f9 0x421f high_field;cmp 0x40;need(not !q.flags.zero)"3DD9 E1 field40";
   hl 0xa75e;a(read 0xa754);cmp(read !q.hl);need !q.flags.zero "3DD9 E1 counter mismatch");
  hl 0xa754;a(read 0xa75e);sub(read !q.hl);put 0x4137 0xa631 !q.a;
  pair 0xa75a;store 0x413d 0xa863 !q.hl;call 0x4140 0x41af low_field;sub 6;sub 1;mask();save 0x4148;
  a(read 0xa631);sub 0;add 255;mask();restore();logical true(!q.bc land 255);rar();need(not !q.flags.carry)"3DD9 final diagnostic";a 1 in
 let pointer_acquire()=
  call 0x5a46 0x020e(fun()->q:=Input_gate.run memory ~entry:!q ~compatibility);rar();need !q.flags.carry "5A46 gate-clear alternative";
  call 0x5a4d 0x45f0(fun()->
   call 0x45f0 0x4562(fun()->reuse H.Hash_prefix);call 0x45f3 0x422f(fun()->reuse H.Select_pointer);
   pair 0x20c5;exchange();bc 0x20c6;call 0x45fd 0x4584(fun()->reuse H.Payload_match));
  call 0x5a50 0x4275(fun()->reuse H.Pointer_compare);rar();need !q.flags.carry "5A46 constructor fallback";
  hl 0xa6ca;let index=inc(read !q.hl)in put 0x5a7a !q.hl index;hl index;dad !q.hl;exchange();pair 0xa6cb;dad !q.de;de 0xa6a8;
  resident 0x5a87 0x1a2c(fun()->difference !q.de !q.hl);need(not !q.flags.carry)"5A46 nested-slot bound";
  pair 0xa6ca;hl(!q.hl land 255);dad !q.hl;exchange();pair 0xa6cb;dad !q.de;guard_field !q.hl 2;push 0x5a98 !q.hl;
  pair 0xa863;exchange();hl(pop());put 0x5a9e !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x5aa0 !q.hl(!q.de lsr 8)in
 let dec v=let n=B.wrap(v-1)in q:={!q with R.flags=flags n(v land 15<>0)!q.flags.carry};n in
 let recycle_count()=
  hl 0xae77;put 0x81f4 !q.hl(!q.bc land 255);
  let rec loop()=a 0;hl 0xae77;cmp(read !q.hl);
   if not !q.flags.carry then()else(
    hl 0xae77;let value=dec(read !q.hl)in put 0x8201 !q.hl value;
    a(read 0xae32);put 0x8205 0xae35 !q.a;c !q.a;child 0x8209 0x7ba2;
    hl 0xae32;let value=dec(read !q.hl)in put 0x820f !q.hl value;loop())in loop()in
 let attribute_dispatch()=
  bc((!q.bc land 255)lsl 8 lor(!q.bc land 255));push 0x256d !q.bc;adjust ~site:0x476e ~delta:1;
  frame 0;c(read !q.hl);child 0x2574 0x7b64;cmp 6;need(not !q.flags.zero)"256C unvalidated attribute6";
  need(!q.a=4)"256C unvalidated transformed attribute";
  frame 0;c(read !q.hl);child 0x25a4 0x2511;adjust ~site:0x47a7 ~delta:1 in
 (* Pass38/39 state transformation: fresh channels and PSW mask carriers. *)
 let maximum()=
  hl 0xa651;put 0x23bc !q.hl(!q.de land 255);hl(U.wrap(!q.hl-1));put 0x23be !q.hl(!q.bc land 255);
  a(read 0xa651);cmp(read !q.hl);if !q.flags.carry then a(read 0xa650)else a(read 0xa651)in
 let minimum()=
  hl 0xa64f;put 0x23a3 !q.hl(!q.de land 255);hl(U.wrap(!q.hl-1));put 0x23a5 !q.hl(!q.bc land 255);
  a(read 0xa64e);cmp(read 0xa64f);if !q.flags.carry then a(read 0xa64e)else a(read 0xa64f)in
 let convert_width()=
  hl 0xa65c;put 0x25d9 !q.hl(!q.bc land 255);pair 0xa65c;c(!q.hl land 255);e 0x10;call 0x25e0 0x23a0 minimum;
  c !q.a;bc(!q.bc land 255);hl 0x42dc;dad !q.bc;a(read !q.hl)in
 let special_index()=
  hl 0xa649;put 0x2224 !q.hl(!q.bc land 255);
  List.iter(fun k->pair 0xa649;hl(!q.hl land 255);bc 0xa628;dad !q.bc;a(read !q.hl);cmp k;need(not !q.flags.zero)"2221 unvalidated selector24/25")[0x24;0x25];
  pair 0xa649;hl(!q.hl land 255);bc 0xa628;dad !q.bc;a(read !q.hl);sub 6;sub 4;mask()in
 let equality address value=a(read address);sub value;sub 1;mask()in
 let combine saved_site restore_fn conjunction=
  save saved_site;restore_fn();restore();logical conjunction(!q.bc land 255)in
 let transformation_tail()=
  a(read 0xa62d);put 0x2fc5 0xa663 !q.a;a(read 0xa630);put 0x2fcb 0xa664 !q.a;
  a(read 0xa628);ani 0x11;sub 0x11;sub 1;mask();save 0x2fd8;
  equality 0xa62a 0x16;save 0x2fe1;pair 0xa62a;c(!q.hl land 255);call 0x2fe6 0x213c(fun()->classifier K.Predicate);
  restore();logical false(!q.bc land 255);restore();logical true(!q.bc land 255);rar();
  if !q.flags.carry then(
   pair 0xa663;c(!q.hl land 255);call 0x2ff7 0x25d6 convert_width;put 0x2ffa 0xa663 !q.a;
   a(read 0xa664);cmp 0;need !q.flags.zero "2FC2 second conversion");
  a(read 0xa628);ani 0x11;cmp 0x11;if !q.flags.zero then(hl 0xa62e;put 0x301c !q.hl 0);
  a(read 0xa628);cmp 0x19;need(not !q.flags.zero)"2FC2 selector19";
  hl 0xa62e;a(read 0xa62b);sub(read !q.hl);put 0x303e 0xa62b !q.a;
  hl 0xa664;a(read 0xa663);sub(read !q.hl);hl(U.wrap(!q.hl-1));put 0x3049 !q.hl !q.a;
  pair 0xa62e;c(!q.hl land 255);pair 0xa664;exchange();call 0x3052 0x23b9 maximum;put 0x3055 0xa62e !q.a;
  pair 0xa62b;c(!q.hl land 255);pair 0xa663;exchange();call 0x3060 0x23b9 maximum;
  hl 0xa62e;add(read !q.hl);put 0x3067 0xa62b !q.a;
  a(read 0xa628);cmp 0x15;need !q.flags.zero "2FC2 final selector15";
  pair 0xa62b;c(!q.hl land 255);pair 0xa642;exchange();call 0x307a 0x23a0 minimum;put 0x307d 0xa62b !q.a in
 let zero_pair()=equality 0xa632 0;combine 0x21dc(fun()->equality 0xa633 0)true in
 let pair_gate()=
  call 0x2259 0x21d4 zero_pair;put 0x225c 0xa64a !q.a;
  pair 0xa629;c(!q.hl land 255);call 0x2263 0x21ad(fun()->classifier K.Interval);rar();need !q.flags.carry "2259 first interval-clear arm";
  pair 0xa62a;c(!q.hl land 255);call 0x226e 0x21ad(fun()->classifier K.Interval);rar();need !q.flags.carry "2259 second interval-clear arm";
  a(read 0xa64a);rar();need !q.flags.carry "2259 cached mask-clear arm";a 0 in
 let interval_wrapper()=
   hl 0xa646;put 0x2188 !q.hl(!q.bc land 255);a(read 0xa646);ani 0xf0;cmp 0x10;
   if !q.flags.zero then a 1 else(
    pair 0xa646;c(!q.hl land 255);call 0x219a 0x213c(fun()->classifier K.Predicate);rar();
    if !q.flags.carry then a 1 else(equality 0xa646 0x31)) in
 let transform_first()=
  call 0x30c1 0x22c0(fun()->
   call 0x22c0 0x21d4 zero_pair;
   rar();need !q.flags.carry "22C0 clear gate");
  equality 0xa629 0x19;
  List.iter(fun(site,address,value)->combine site(fun()->equality address value)false)
   [0x30cc,0xa629,4;0x30d8,0xa629,0x0d;0x30e4,0xa62a,0x19;0x30f0,0xa62a,4;0x30fc,0xa62a,0x0d];
  rar();need(not !q.flags.carry)"30C1 selector19 publication";
  equality 0xa629 0x15;combine 0x311c(fun()->c 1;call 0x311f 0x2221 special_index)false;
  combine 0x3125(fun()->equality 0xa62a 0x15)false;
  combine 0x3131(fun()->c 2;call 0x3134 0x2221 special_index)false;
  rar();need !q.flags.carry "30C1 selector16 publication";hl 0xa628;put 0x3141 !q.hl 0x15;
  a(read 0xa62c);put 0x314e 0xa665 !q.a;a(read 0xa62f);put 0x3154 0xa666 !q.a;
  a(read 0xa628);ani 0x11;sub 0x11;sub 1;mask();save 0x3161;
  equality 0xa629 0x16;save 0x316a;pair 0xa629;c(!q.hl land 255);call 0x316f 0x213c(fun()->classifier K.Predicate);
  restore();logical false(!q.bc land 255);restore();logical true(!q.bc land 255);rar();need(not !q.flags.carry)"30C1 conversion alternative";
  a(read 0xa665);put 0x319b 0xa62b !q.a;a(read 0xa666);put 0x31a1 0xa62e !q.a;call 0x31a4 0x2fc2 transformation_tail in
 let acquire_two_groups()=
  a(read 0xae32);put 0x31fe 0xa667 !q.a;
  let channel site target destination=pair 0xa667;c(!q.hl land 255);child site target;put(site+3)destination !q.a in
  channel 0x3205 0x7a93 0xa62a;channel 0x320f 0x7aa9 0xa62d;channel 0x3219 0x7abf 0xa630;
  pair 0xa667;c(!q.hl land 255);child 0x3223 0x7a79;store 0x3226 0xa63f !q.hl;
  pair 0xa667;c(!q.hl land 255);child 0x322d 0x7b7a;a(dec !q.a);put 0x3231 0xa667 !q.a;
  channel 0x3238 0x7a93 0xa629;channel 0x3242 0x7aa9 0xa62c;channel 0x324c 0x7abf 0xa62f;
  pair 0xa667;c(!q.hl land 255);child 0x3256 0x7a79;store 0x3259 0xa63d !q.hl;
  hl 0xa634;put 0x325f !q.hl 1 in
 let indexed base=pair 0xa634;hl(!q.hl land 255);bc base;dad !q.bc in
 let argument_index base=pair 0xa9dd;hl(!q.hl land 255);bc base;dad !q.bc in
 let shift_word()=
  let rec loop()=dad !q.hl;let n=dec(!q.bc land 255)in c n;if n<>0 then loop()in loop()in
 let decimal_arguments()=
  hl 0xa9e1;put 0x670b !q.hl(!q.de land 255);hl(U.wrap(!q.hl-1));put 0x670d !q.hl(!q.bc land 255);hl(U.wrap(!q.hl-1));
  de(pop());bc(pop());put 0x6711 !q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put 0x6713 !q.hl(!q.bc land 255);hl(U.wrap(!q.hl-1));
  bc(pop());put 0x6716 !q.hl(!q.bc land 255);hl(U.wrap(!q.hl-1));
  bc(pop());put 0x6719 !q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put 0x671b !q.hl(!q.bc land 255);hl(U.wrap(!q.hl-1));
  bc(pop());put 0x671e !q.hl(!q.bc land 255);push 0x671f !q.de;software ~site:0x891f ~consumed:8;
  pair 0xa9db;store 0x6723 0xa863 !q.hl;
  argument_index 0xa628;a 0x28;logical true(read !q.hl);cmp 0x28;need(not !q.flags.zero)"6708 E05 path";
  argument_index 0xa628;a(read !q.hl);sub 0x24;sub 1;mask();save 0x67cd;
  a(read !q.hl);sub 0x25;sub 1;mask();restore();logical false(!q.bc land 255);rar();need(not !q.flags.carry)"6708 selector24/25";
  equality 0xa9e1 6;
  List.iter(fun(site,v)->combine site(fun()->equality 0xa9e1 v)false)[0x68f9,7;0x6905,8;0x6911,9];rar();need(not !q.flags.carry)"6708 E06..09";
  argument_index 0xa628;a(read !q.hl);cmp 0x19;need(not !q.flags.zero)"6708 selector19";
  a(read 0xa9e1);cmp 4;need(not !q.flags.zero)"6708 E04";
  argument_index 0xa628;a(read !q.hl);cmp 0x15;need !q.flags.zero "6708 required selector15";
  need(read 0xa9e1=2)"6708 bounded E02";need(List.mem(read 0xa9e0)[1;2])"6708 bounded source count1/2";
  hl 0;store 0x6ba3 0xa948 !q.hl;hl 0xa9e3;put 0x6ba9 !q.hl 1;hl(U.wrap(!q.hl-1));put 0x6bac !q.hl 0;
  let source()=pair 0xa9e2;hl(!q.hl land 255);exchange();pair 0xa9de;dad !q.de;guard_field !q.hl 1 in
  let rec loop()=
   a(read 0xa9e0);a(dec !q.a);hl 0xa9e2;cmp(read !q.hl);
   if not !q.flags.carry then(
    source();a(read !q.hl);sub 0x2e;sub 1;mask();hl 0xa9e3;logical true(read !q.hl);rar();need(not !q.flags.carry)"6708 decimal point";
    source();a(read !q.hl);sub 0x30;mask();save 0x6be7;a 0x39;sub(read !q.hl);mask();restore();logical false(!q.bc land 255);rar();need(not !q.flags.carry)"6708 nondigit";
    a(read 0xa9e3);rar();need !q.flags.carry "6708 disabled numeric state";
    de 0x0ccc;hl 0xa948;call 0x6c03 0x83a3(fun()->let address= !q.hl in difference !q.de(word address);de(U.wrap(address+1)));
    mask();bc 0x0ccc;de(U.wrap(!q.de-1));save 0x6c0b;
    resident 0x6c0c 0x1a38(fun()->difference(word !q.de)!q.bc;de(U.wrap(!q.de+1)));
    logical false(!q.hl land 255);sub 1;mask();source();save 0x6c1d;
    a 0x37;sub(read !q.hl);mask();restore();logical true(!q.bc land 255);restore();logical false(!q.bc land 255);rar();need(not !q.flags.carry)"6708 overflow";
    hl 0xa948;call 0x6c32 0x8309(fun()->e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();dad !q.hl;push 0x830e !q.hl;dad !q.hl;dad !q.hl;bc(pop());dad !q.bc);
    push 0x6c35 !q.hl;source();e(read !q.hl);de(!q.de land 255);hl(pop());dad !q.de;exchange();a 0x30;
    call 0x6c48 0x8396(fun()->bc !q.a;difference !q.de !q.bc);store 0x6c4b 0xa948 !q.hl;
    hl 0xa9e2;let n=inc(read !q.hl)in put 0x6c51 !q.hl n;need(n<>0)"6708 offset wrap";loop())in loop();
  argument_index 0xa62b;c(read !q.hl);hl 1;call 0x6c62 0x8380 shift_word;
  de 0xa948;resident 0x6c68 0x1a43 pointer_minus;need !q.flags.carry "6708 width overflow";
  a(read 0xa9da);cmp 0x2d;need(not !q.flags.zero)"6708 negation";
  argument_index 0xa62b;a 7;cmp(read !q.hl);need !q.flags.carry "6708 width<=7";
  hl 0xa947;put 0x6c9c !q.hl 2;a 1 in
 let acquire_selected02()=
  hl 0xa65f;put 0x28ad !q.hl(!q.bc land 255);
  List.iter(fun(value,site)->indexed 0xa628;a(read !q.hl);sub value;sub 1;mask();put site 0xa662 !q.a;rar();need(not !q.flags.carry)"28AA selector0B/0C/0D")[11,0x28bd;12,0x28e1;13,0x2905];
  indexed 0xa628;a 10;cmp(read !q.hl);need(not !q.flags.carry)"28AA guard-only exit";
  (* Historical DAD H precedes DAD B, not an index equation. *)
  pair 0xa634;hl(!q.hl land 255);bc 0xa63b;dad !q.hl;dad !q.bc;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();store 0x2938 0xa863 !q.hl;
  a(read 0xa662);rar();need(not !q.flags.carry)"28AA negative prefix";hl 0xa662;put 0x294d !q.hl 0x2b;
  pair 0xa628;c(!q.hl land 255);call 0x2953 0x2185 interval_wrapper;
  save 0x2956;pair 0xa662;push 0x295a !q.hl;
  pair 0xa634;hl(!q.hl land 255);bc 0xa63b;dad !q.hl;dad !q.bc;c(read !q.hl);hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor(!q.bc land 255));push 0x2968 !q.bc;c 0;push 0x296b !q.bc;
  bc 10;pair 0xa863;dad !q.bc;push 0x2973 !q.hl;
  pair 0xa863;guard_field !q.hl 1;a(read !q.hl);sub 10;indexed 0xa628;e(read !q.hl);c !q.a;
  call 0x2985 0x6708 decimal_arguments;
  restore();logical true(!q.bc land 255);rar();need !q.flags.carry "28AA acquisition false result";
  List.iter(fun(base,site)->indexed base;a(read !q.bc);put site !q.hl !q.a)[0xa628,0x2999;0xa62b,0x29a4;0xa62e,0x29af];
  indexed 0xa628;a(read !q.hl);sub 0x15;sub 1;mask();save 0x2ace;
  a(read !q.hl);sub 0x25;sub 1;mask();restore();logical false(!q.bc land 255);save 0x2ad8;
  a(read !q.hl);sub 0x24;sub 1;mask();restore();logical false(!q.bc land 255);hl 0xa65f;logical true(read !q.hl);rar();need !q.flags.carry "28AA construction arm";
  hl 0xa661;put 0x2aed !q.hl 10;pair 0xa948;hl(!q.hl land 255);store 0x2af4 0xa863 !q.hl;
  a(read 0xa947);cmp 2;need !q.flags.zero "28AA width1";
  pair 0xa949;hl(!q.hl land 255);c 8;call 0x2b06 0x8380 shift_word;
  de 0xa863;call 0x2b0c 0x834f(fun()->a(read !q.de);logical false(!q.hl land 255);hl((!q.hl land 0xff00)lor !q.a);de(U.wrap(!q.de+1));a(read !q.de);logical false(!q.hl lsr 8);hl(!q.a lsl 8 lor(!q.hl land 255)));
  exchange();hl(U.wrap(!q.hl-1));put 0x2b11 !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x2b13 !q.hl(!q.de lsr 8);
  pair 0xa634;hl(!q.hl land 255);bc 0xa63b;dad !q.hl;dad !q.bc;push 0x2b88 !q.hl;pair 0xa863;exchange();hl(pop());put 0x2b8e !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x2b90 !q.hl(!q.de lsr 8);
  pair 0xae32;c(!q.hl land 255);child 0x2b95 0x7b7a;put 0x2b98 0xa660 !q.a;
  a(read 0xa634);cmp 1;need(not !q.flags.zero)"28AA index1 arm";
  pair 0xa660;c(!q.hl land 255);pair 0xa863;exchange();child 0x2bb6 0x7af0;
  let publish base site=indexed base;e(read !q.hl);pair 0xa660;c(!q.hl land 255);child site (if base=0xa628 then 0x7b13 else if base=0xa62b then 0x7b2e else 0x7b49)in
  List.iter(fun(base,site)->publish base site)[0xa628,0x2bc7;0xa62b,0x2bd8;0xa62e,0x2be9];
  a(read 0xa661);cmp 0;need(not !q.flags.zero)"28AA literal-zero cached selector";
  pair 0xa660;c(!q.hl land 255);pair 0xa661;exchange();child 0x2c07 0x7ad5;
  hl 0xa660;let n=inc(read !q.hl)in put 0x2c0d !q.hl n;
  List.iter(fun(base,site)->publish base site)[0xa628,0x2c1c;0xa62b,0x2c2d;0xa62e,0x2c3e];
  pair 0xa634;c(!q.hl land 255);call 0x2c45 0x2355(fun()->classifier K.Indexed);add 0x13;
  pair 0xa660;e !q.a;c(!q.hl land 255);child 0x2c4f 0x7ad5 in
 let transform_second()=
  call 0x2c59 0x2c53(fun()->c 1;call 0x2c55 0x28aa acquire_selected02);
  indexed 0xa628;c(read !q.hl);call 0x2c66 0x21ad(fun()->classifier K.Interval);rar();need !q.flags.carry "2C59 clear classifier arm";
  indexed 0xa628;a(read !q.hl);cmp 0x2a;need(not !q.flags.zero)"2C59 selector2A";
  let indexed_mask selector base_value push_site=
   indexed 0xa628;a(read !q.hl);sub selector;sub 1;mask();save push_site;
   a(read !q.bc);sub base_value;sub 1;mask();restore();logical true(!q.bc land 255);rar();need(not !q.flags.carry)"2C59 indexed/base arm"in
  indexed_mask 0x16 0x19 0x2c8e;indexed_mask 0x28 0x19 0x2cae;
  equality 0xa628 0x16;indexed 0xa628;save 0x2cd3;a(read !q.hl);sub 0x19;sub 1;mask();restore();logical true(!q.bc land 255);rar();need(not !q.flags.carry)"2C59 base16/selected19";
  indexed 0xa628;a(read !q.hl);cmp 0x28;need(not !q.flags.zero)"2C59 selector28";
  indexed 0xa628;a(read !q.hl);sub 0x24;sub 1;mask();save 0x2d05;a(read !q.hl);sub 0x25;sub 1;mask();restore();logical false(!q.bc land 255);rar();need(not !q.flags.carry)"2C59 selector24/25";
  indexed 0xa628;a(read !q.hl);cmp 0x31;need(not !q.flags.zero)"2C59 selector31";
  List.iter(fun(base_bits,selected_bits,push_site)->
   a(read 0xa628);ani base_bits;sub base_bits;sub 1;mask();indexed 0xa628;save push_site;
   a selected_bits;logical true(read !q.hl);sub selected_bits;sub 1;mask();restore();logical true(!q.bc land 255);rar();need(not !q.flags.carry)"2C59 masked transformation")
   [0x11,0x12,0x2d3b;0x18,0x14,0x2d61];
  a(read 0xa628);ani 0x14;cmp 0x14;
  if !q.flags.zero then(
   indexed 0xa628;a(read !q.hl);cmp 0x19;need(not !q.flags.zero)"2C59 final selected19";
   a(read 0xa628);cmp 0x16;need(not !q.flags.zero)"2C59 final base16")in
 let transform_pair()=
  call 0x3304 0x31fb acquire_two_groups;call 0x3307 0x30c1 transform_first;
  hl 0xa628;a(read 0xa629);cmp(read !q.hl);need !q.flags.zero "3304 unequal first selectors";
  let gate()=a(read 0xa628);cmp 0x16;need(not !q.flags.zero)"2705 selector16"in
  call 0x3317 0x2705 gate;hl 0xa634;put 0x331d !q.hl 2;
  hl 0xa628;a(read 0xa62a);cmp(read !q.hl);
  if not !q.flags.zero then call 0x3329 0x2c59 transform_second;
  call 0x332c 0x2705 gate;
  call 0x332f 0x329f(fun()->pair 0xa62c;c(!q.hl land 255);pair 0xa62d;exchange();call 0x32a7 0x23b9 maximum;
   put 0x32aa 0xa62b !q.a;hl 0xa62e;put 0x32b0 !q.hl 0)in
 let selected_transform()=
  call 0x345e 0x31fb acquire_two_groups;call 0x3461 0x2259 pair_gate;rar();need(not !q.flags.carry)"345E initial set gate";
  pair 0xa629;c(!q.hl land 255);call 0x346f 0x2185 interval_wrapper;save 0x3472;
  pair 0xa62a;c(!q.hl land 255);call 0x3477 0x2185 interval_wrapper;restore();logical false(!q.bc land 255);rar();need !q.flags.carry "345E classifier-clear arm";
  call 0x3481 0x30c1 transform_first;hl 0xa628;a(read 0xa629);cmp(read !q.hl);need !q.flags.zero "345E unequal first selectors";
  let gate()=a(read 0xa628);cmp 0x16;need(not !q.flags.zero)"2705 selector16"in
  call 0x3491 0x2705 gate;hl 0xa634;put 0x3497 !q.hl 2;hl 0xa628;a(read 0xa62a);cmp(read !q.hl);
  if not !q.flags.zero then call 0x34a3 0x2c59 transform_second;
  call 0x34a6 0x2705 gate;a 0 in
 let table_adapter()=
  hl 0xa65a;put 0x25ac !q.hl(!q.de lsr 8);hl(U.wrap(!q.hl-1));put 0x25ae !q.hl(!q.de land 255);
  hl(U.wrap(!q.hl-1));put 0x25b0 !q.hl(!q.bc land 255);pair 0xa658;hl(!q.hl land 255);exchange();
  pair 0xa659;dad !q.de;guard_field !q.hl 1;c(read !q.hl);child 0x25bc 0x2511 in
 let reentry_leaf()=
  a(read 0xa934);rar();need(not !q.flags.carry)"625D initial gate-set";
  c 0x28;call 0x6266 0x01af selector_match;rar();need(not !q.flags.carry)"625D selector28 arm";
  child 0x6273 0x6223;
  hl 0xa934;put 0x6279 !q.hl 0;c 0xf9;call 0x627d 0x01af selector_match;rar();need(not !q.flags.carry)"625D selectorF9 arm"in
 let counted_spine ?(repeat_only=false) ()=
  let leaf()=
   adjust ~site:0x8514 ~delta:(-1);a(read 0xa934);rar();need(not !q.flags.carry)"6314 initial gate";
   bc 0x7950;call 0x6325 0x57b7(fun()->reuse H.Search);rar();need(not !q.flags.carry)"6314 search-found arm";
   call 0x63c9 0x625d reentry_leaf;adjust ~site:0x85cc ~delta:1 in
  let middle()=
   adjust ~site:0x860d ~delta:(-1);call 0x640e 0x6314 leaf;
   bc 0x7957;call 0x6414 0x57b7(fun()->reuse H.Search);rar();need(not !q.flags.carry)"640D search-found arm";
   adjust ~site:0x8675 ~delta:1 in
  let outer()=
   adjust ~site:0x8677 ~delta:(-1);call 0x6478 0x640d middle;
   bc 0x7960;call 0x647e 0x57b7(fun()->reuse H.Search);rar();need(not !q.flags.carry)"6477 search-found arm";
   adjust ~site:0x86f0 ~delta:1 in
  let wrapped()=
   call 0x64f2 0x6477 outer;c 0xf8;call 0x64f7 0x01af selector_match;rar();need(not !q.flags.carry)"64F2 selectorF8 arm"in
  let saved()=
   push 0x654e !q.hl;push 0x654f !q.hl;call 0x6550 0x64f2 wrapped;
   let rec search()=
    bc 0x7969;call 0x6556 0x57b7(fun()->reuse H.Search);rar();
    if !q.flags.carry then(
     a(read 0xa935);frame 0;put 0x6564 !q.hl !q.a;call 0x6565 0x784e(fun()->reuse H.Acquire_overlay);
     pair 0xa635;exchange();frame 1;put 0x6570 !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x6572 !q.hl(!q.de lsr 8);
     a(read 0xa631);hl(U.wrap(!q.hl+1));put 0x6577 !q.hl !q.a;call 0x6578 0x64f2 wrapped;
     frame 3;a(read !q.hl);put 0x6580 0xa632 !q.a;a(read 0xa631);put 0x6586 0xa633 !q.a;
     hl(U.wrap(!q.hl-2));e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();store 0x658f 0xa637 !q.hl;
     pair 0xa635;store 0x6595 0xa639 !q.hl;exchange();a 5;hl(U.wrap(!q.hl-2));cmp(read !q.hl);need(not !q.flags.carry)"654E offset above5 arm";
     call 0x65a7 0x345e selected_transform;rar();need(not !q.flags.carry)"654E transform set-result arm";
     frame 0;a(read !q.hl);add !q.a;add !q.a;add !q.a;save 0x65cd;call 0x65ce 0x239a(fun()->classifier K.Wrapper);restore();add(!q.bc land 255);
     frame 0;put 0x65d8 !q.hl !q.a;hl 0xa628;put 0x65dc !q.hl 0x24;hl 0xa62b;put 0x65e1 !q.hl 1;hl 0xa62e;put 0x65e6 !q.hl 0;
     frame 0;c(read !q.hl);de 0x7972;call 0x65f0 0x25a9 table_adapter;search())in
   search();hl(pop());hl(pop())in
  let gate()=
   call 0x65f9 0x654e saved;c 0x26;call 0x65fe 0x01af selector_match;rar();need(not !q.flags.carry)"65F9 selector26 arm"in
  if repeat_only then saved()else( call 0x6619 0x65f9 gate;c 0x5c;call 0x661e 0x01af selector_match;rar();need(not !q.flags.carry)"6619 selector5C arm")in
 let recursive_spine()=
  call 0x4f54 0x4cc2(fun()->c 0x28;call 0x4cc4 0x01af selector_match;rar();need !q.flags.carry "4CC2 selector mismatch";a 1);
  rar();need !q.flags.carry "4F54 literal-zero arm";call 0x4f5b 0x6619 counted_spine;
  call 0x4f5e 0x4ce1(fun()->c 0x2c;call 0x4ce3 0x01af selector_match;rar();need !q.flags.carry "4CE1 selector mismatch";a 1);
  rar();need !q.flags.carry "4F54 second gate";call 0x4f65 0x6619 counted_spine;
  call 0x4f68 0x3304 transform_pair;a 1 in
 let dispatch()=
  List.iter(fun site->push site !q.hl)[0x506e;0x506f;0x5070];
  de((!q.de land 255)lsl 8 lor(!q.de land 255));push 0x5072 !q.de;adjust ~site:0x7273 ~delta:1;
  bc((!q.bc land 255)lsl 8 lor(!q.bc land 255));push 0x5075 !q.bc;adjust ~site:0x7276 ~delta:1;
  pair 0xa635;exchange();frame 2;put 0x507f !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x5081 !q.hl(!q.de lsr 8);
  c 1;call 0x5084 0x81f1 recycle_count;
  a 0x32;frame 1;cmp(read !q.hl);need(not !q.flags.carry)"506E upper dispatch alternative";
  a 0x20;frame 1;cmp(read !q.hl);need(not !q.flags.carry)"506E lower dispatch alternative";
  frame 1;c(read !q.hl);bc(!q.bc land 255);hl 0x789f;dad !q.bc;dad !q.bc;
  e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();need(!q.hl=0x75bb)"506E unvalidated selected dispatch";
  c 0xcf;call 0x53bd 0x500f(fun()->
   bc((!q.bc land 255)lsl 8 lor(!q.bc land 255));push 0x5010 !q.bc;adjust ~site:0x7211 ~delta:1;
   call 0x5012 0x4f54(fun()->if follow_spine then recursive_spine()else q:=native ~site:0x7212 ~target:0x7154 !q);
   rar();need !q.flags.carry "500F clear result";a(read 0xa630);put 0x501c 0xa62e !q.a;
   call 0x501f 0x2308(fun()->c 0;call 0x230a 0x22cb(fun()->classifier K.Selected));
   frame 0;add(read !q.hl);c !q.a;child 0x5028 0x2511;
   call 0x502b 0x4cd4(fun()->c 0x29;call 0x4cd6 0x01af selector_match;rar();need !q.flags.carry "4CD4 mismatch arm");
   hl 0xa932;put 0x5031 !q.hl 1;adjust ~site:0x7233 ~delta:1);
  call 0x53c0 0x4f2a(fun()->
   a(read 0xa628);ani 0x14;cmp 0x14;need !q.flags.zero "4F2A mask mismatch";
   pair 0xa62f;c(!q.hl land 255);pair 0xa630;exchange();call 0x4f3c 0x23b9 maximum;put 0x4f3f 0xa62e !q.a;
   hl 0xa630;a(read 0xa62d);sub(read !q.hl);hl 0xa62e;add(read !q.hl);put 0x4f4d 0xa62b !q.a;
   call 0x4f50 0x4c4c(fun()->c 0;child 0x4c4e 0x240a));
  a 0x20;frame 1;cmp(read !q.hl);need(not !q.flags.carry)"506E restoration alternative";
  frame 2;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();store 0x5703 0xa635 !q.hl;
  a(read 0xa932);for _=1 to 4 do hl(pop())done in
 let field_acquisition()=
  List.iter(fun site->push site !q.hl)[0x5e98;0x5e99;0x5e9a];
  call 0x5e9b 0x5e7c(fun()->
   bc 0;call 0x5e7f 0x7ff3(fun()->
    hl 0xae66;put 0x7ff6 !q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put 0x7ff8 !q.hl(!q.bc land 255);pair 0xae65;exchange();c 0x0a;child 0x7fff 0x7e5f);
   hl 0xa628;put 0x5e85 !q.hl 0x15;a(read 0xa642);put 0x5e8a 0xa62b !q.a;hl 0xa62e;put 0x5e90 !q.hl 0;c 0;child 0x5e94 0x240a);
  hl 0xa6ca;put 0x5ea1 !q.hl 255;frame 1;put 0x5ea7 !q.hl 0;hl(U.wrap(!q.hl-1));put 0x5eaa !q.hl 1;
  let finished=ref false in
  let rec loop()=
   frame 0;a(read !q.hl);rar();
   if !q.flags.carry then(
    a(read 0x20c3);frame 3;put 0x5ebc !q.hl !q.a;call 0x5ebd 0x5a46 pointer_acquire;
    call 0x5ec0 0x784e(fun()->reuse H.Acquire_overlay);call 0x5ec3 0x4275(fun()->reuse H.Pointer_compare);rar();
    if !q.flags.carry then(
     pair 0xa863;exchange();frame 4;put 0x5ed2 !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x5ed4 !q.hl(!q.de lsr 8);
     call 0x5ed5 0x419f tag;acquired_field:=Some !q.a;frame 2;put 0x5edc !q.hl !q.a;
     sub 0x40;sub 1;mask();save 0x5ee2;a(read !q.hl);sub 0x41;sub 1;mask();restore();logical false(!q.bc land 255);save 0x5eec;
     a(read !q.hl);sub 0x80;sub 1;mask();restore();logical false(!q.bc land 255);rar();
     if !q.flags.carry then(
      frame 1;c(read !q.hl);e 0;call 0x5f01 0x3dd9 common_gate;rar();need !q.flags.carry "field80 first gate";
      pair 0xa6ca;c(!q.hl land 255);call 0x5f0c 0x5e65 select_nested;call 0x5f0f 0x419f tag;
      frame 2;put 0x5f16 !q.hl !q.a;cmp 0x80;need !q.flags.zero "field80 selected tag";
      frame 1;c(read !q.hl);e 1;call 0x5f23 0x3dd9 common_gate;rar();need !q.flags.carry "field80 second gate";
      bc 5;pair 0xa863;dad !q.bc;e(read !q.hl);frame 3;c(read !q.hl);call 0x5f3a 0x506e dispatch;
      for _=1 to 3 do hl(pop())done;finished:=true
     )else(
      need(!acquired_field=Some 0x15)"unvalidated field tag";
      frame 4;c(read !q.hl);hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor(!q.bc land 255));call 0x6051 0x4601 cleanup;
      call 0x5ec3 0x4275(fun()->reuse H.Pointer_compare);rar();need(not !q.flags.carry)"field15 cleanup loop alternative"));
    if not !finished then(
    c 0x28;call 0x6059 0x01af selector_match;rar();need(not !q.flags.carry)"field15 selector28";
    c 0x2e;call 0x606b 0x01af selector_match;frame 0;put 0x6072 !q.hl !q.a;loop()))in loop();
  if not !finished then(
  frame 1;c(read !q.hl);e 1;call 0x607d 0x3dd9 common_gate;rar();need !q.flags.carry "field15 gate rejected";
  c 0;call 0x6089 0x5e65 select_nested;call 0x608c 0x419f tag;cmp 0x42;need(not !q.flags.zero)"field15 selector42";
  c 0;call 0x60b9 0x5e65 select_nested;
  call 0x60bc 0x5e53(fun()->call 0x5e53 0x5e48(fun()->call 0x5e48 0x41a6 field_byte;ani 0x40;sub 0x40;sub 1;mask());rar();need !q.flags.carry "5E53 special path";a 0);
  rar();need(not !q.flags.carry)"field15 repeat";a 0;for _=1 to 3 do hl(pop())done)in
 let context()=
  adjust ~site:0x82e5 ~delta:(-1);push 0x60e6 !q.hl;push 0x60e7 !q.hl;
  pair 0xa6cb;exchange();frame 2;put 0x60f0 !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x60f2 !q.hl(!q.de lsr 8);
  pair 0xa6ca;hl(!q.hl land 255);bc 2;dad !q.hl;dad !q.bc;dad !q.de;store 0x60fe 0xa6cb !q.hl;
  a(read 0xa6ca);frame 4;put 0x6108 !q.hl !q.a;frame 0;put 0x610d !q.hl 0;
  call 0x610f 0x5e98 field_acquisition;frame 1;put 0x6116 !q.hl !q.a;
  c 0;call 0x6119 0x5e65 select_nested;call 0x611c 0x41af low_field;cmp 3;need(not !q.flags.zero)"60E5 field3";
  c 0;call 0x6129 0x5e65 select_nested;frame 0;a(read !q.hl);rar();need(not !q.flags.carry)"60E5 repeat-mask";
  call 0x6146 0x41af low_field;cmp 5;need(not !q.flags.zero)"60E5 field5";
  c 0xfc;call 0x6155 0x01af selector_match;rar();need(not !q.flags.carry)"60E5 special acquisition";
  frame 2;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();store 0x618d 0xa6cb !q.hl;
  de(U.wrap(!q.de+1));a(read !q.de);put 0x6192 0xa6ca !q.a;de(U.wrap(!q.de-3));a(read !q.de);
  adjust ~site:0x8399 ~delta:1;hl(pop());hl(pop())in
 (match operation with Context->context()|Field->field_acquisition()|Attribute->attribute_dispatch()|Spine->recursive_spine()|Resident->reuse H.Resident_acquisition|Pair_gate->pair_gate()|Selected_transform->selected_transform()|Table_adapter->table_adapter()|Wrapper->counted_spine()|Repeat->counted_spine ~repeat_only:true ());
 {returned= !q;field= !acquired_field}
