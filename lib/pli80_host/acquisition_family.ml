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
type operation=Pli2_output of int|Output of int|Adapter of int|Context|Field|Attribute|Spine|Resident|Pair_gate|Selected_transform|Table_adapter|Wrapper|Repeat|Copy05|Traversal|Construction|Record_output|Index_one|Parent|Reader of Reader_construction.operation|Recursive of Recursive_parent.operation
type result={returned:R.returned;field:int option}
let run operation memory ~entry ~write ~compatibility ~adjust ~sp ~guard_field ~native ~follow_spine ~software =
 B.check entry.R.a;List.iter U.check[entry.bc;entry.de;entry.hl;sp()];
 let q=ref entry and acquired_field=ref None in
 let console_entry_sp=sp()in
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
 let dec v=let n=B.wrap(v-1)in q:={!q with R.flags=flags n(v land 15<>0)!q.flags.carry};n in
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
 let reuse op=q:=(H.run ~reader_refill:(fun q->native ~site:0x13b8 ~target:0x0e40 q) ~operation:op memory ~entry:!q ~write ~compatibility ~guard_field ~saved:(fun _->invalid_arg"Acquisition_family: unexpected saved child")).returned in
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
  frame 0;c(read !q.hl);child 0x2574 0x7b64;cmp 6;
  if !q.flags.zero then(
   frame 0;c(read !q.hl);child 0x2581 0x8048;pair 0xae32;c(!q.hl land 255);pair 0xa5b0;exchange();child 0x258c 0x7af0;
   c 0;child 0x2591 0x23d2;frame 0;c(read !q.hl);child 0x2599 0x7ec0
  )else(need(!q.a=4)"256C unvalidated transformed attribute";frame 0;c(read !q.hl);child 0x25a4 0x2511);adjust ~site:0x47a7 ~delta:1 in
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
 let software_arguments()=
  hl 0xa9e1;put 0x670b !q.hl(!q.de land 255);hl(U.wrap(!q.hl-1));put 0x670d !q.hl(!q.bc land 255);hl(U.wrap(!q.hl-1));
  de(pop());bc(pop());put 0x6711 !q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put 0x6713 !q.hl(!q.bc land 255);hl(U.wrap(!q.hl-1));
  bc(pop());put 0x6716 !q.hl(!q.bc land 255);hl(U.wrap(!q.hl-1));
  bc(pop());put 0x6719 !q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put 0x671b !q.hl(!q.bc land 255);hl(U.wrap(!q.hl-1));
  bc(pop());put 0x671e !q.hl(!q.bc land 255);push 0x671f !q.de;software ~site:0x891f ~consumed:8;
  pair 0xa9db;store 0x6723 0xa863 !q.hl in
 let decimal_arguments()=
  software_arguments();
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
 (* E05 is the historical copy/padding route, independent of decimal E02.
    The output intentionally reaches A9DA..A9DD in the first acquisition.
    Those writes change the next fresh selector/limit read. *)
 let copy_arguments()=
  software_arguments();
  argument_index 0xa628;a 0x28;logical true(read !q.hl);cmp 0x28;need !q.flags.zero "6708 E05 mask28";
  a(read 0xa9e1);cmp 5;need !q.flags.zero "6708 copy E05";
  hl 0xa9e2;put 0x6745 !q.hl 0;hl(U.wrap(!q.hl+1));put 0x6748 !q.hl 0;
  argument_index 0xa628;a 0x22;logical true(read !q.hl);cmp 0x22;need(not !q.flags.zero)"6708 E05 mask22";
  let rec loop()=
   argument_index 0xa62b;a(read 0xa9e3);cmp(read !q.hl);
   if not !q.flags.carry then()else(
    hl 0xa9e0;a(read 0xa9e3);cmp(read !q.hl);
    if !q.flags.carry then(
     pair 0xa9e3;hl(!q.hl land 255);exchange();pair 0xa9de;dad !q.de;guard_field !q.hl 1;
     a(read !q.hl);put 0x678a 0xa9e4 !q.a
    )else(hl 0xa9e4;put 0x6793 !q.hl 0x20);
    pair 0xa9e2;hl(!q.hl land 255);bc 0xa948;dad !q.bc;
    need(!q.hl<0xa9de)"6708 output aliases active copy carriers";
    a(read 0xa9e4);put 0x67a1 !q.hl !q.a;
    hl 0xa9e2;let n=inc(read !q.hl)in put 0x67a5 !q.hl n;
    hl(U.wrap(!q.hl+1));let n=inc(read !q.hl)in put 0x67a7 !q.hl n;loop())in loop();
  a(read 0xa9e2);put 0x67ae 0xa947 !q.a;hl 0xa9e0;a(read 0xa9e3);sub(read !q.hl);mask();a(!q.a lxor 255)in
 let traversal()=
  hl 0xa915;put 0x46f0 !q.hl(!q.bc land 255);pair 0xa947;exchange();bc 0xa948;
  call 0x46f8 0x452b(fun()->reuse H.Prefix_sum);call 0x46fb 0x422f(fun()->reuse H.Select_pointer);
  let rec reference()=call 0x46fe 0x4275(fun()->reuse H.Pointer_compare);rar();
   if !q.flags.carry then(call 0x4705 0x428e(fun()->reuse H.Successor);reference())in reference();
  let rec matching()=
   call 0x470b 0x4281(fun()->reuse H.Null_mask);rar();
   if !q.flags.carry then(
    pair 0xa947;exchange();bc 0xa948;call 0x4719 0x4584(fun()->reuse H.Payload_match);
    call 0x471c 0x4281(fun()->reuse H.Null_mask);rar();need !q.flags.carry "46ED post-payload null alternative";
    pair 0xa863;guard_field !q.hl 3;hl(U.wrap(!q.hl+2));a(read 0xa915);cmp(read !q.hl);
    need(not !q.flags.zero)"46ED tag-equality early return";
    call 0x4731 0x428e(fun()->reuse H.Successor);matching())in matching()in
 let construction()=
  hl 0xa916;put 0x473b !q.hl(!q.bc land 255);pair 0xa916;c(!q.hl land 255);
  call 0x4740 0x46ed traversal;call 0x4743 0x4281(fun()->reuse H.Null_mask);rar();need(not !q.flags.carry)"4738 reuse alternative";
  bc 0xa948;push 0x474d !q.bc;pair 0xa947;c(!q.hl land 255);pair 0xa916;exchange();
  call 0x4756 0x4468(fun()->q:=(H.run ~operation:H.Constructor ~constructor_abi:(fun()->word(U.wrap(sp()+2)),word(sp())) memory ~entry:!q ~write ~compatibility ~guard_field ~saved:(fun _->invalid_arg"unexpected constructor saved child")).returned);
  pair 0xa8ab;store 0x475c 0xa863 !q.hl;guard_field !q.hl 4;hl(U.wrap(!q.hl+2));e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();store 0x4765 0xa917 !q.hl;
  pair 0xa863;hl(U.wrap(!q.hl+2));a(read 0xa947);
  resident 0x4770 0x1a1d(fun()->let address= !q.hl and addend= !q.a in let v=word address in let low=(v land 255)+addend in let carry=if low>255 then 1 else 0 in let high=(v lsr 8)+carry in let n=B.wrap high in q:={!q with R.a=n;hl=n lsl 8 lor B.wrap low;de=U.wrap(address+1);flags=flags n(((v lsr 8)land 15)+carry>15)(high>255)});
  exchange();hl(U.wrap(!q.hl-1));put 0x4775 !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x4777 !q.hl(!q.de lsr 8);
  pair 0x1c36;hl(U.wrap(!q.hl+1));store 0x477c 0xa863 !q.hl;bc 6;dad !q.bc;push 0x4783 !q.hl;
  pair 0xa917;exchange();hl(pop());put 0x4789 !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x478b !q.hl(!q.de lsr 8)in
 let resident_put site address value=put(site-0x2100)address value in
 let resident_call site target fn=compatibility(H.Enter(site+0x100,target+0x100));fn();compatibility H.Leave in
 let bit_write()=
  hl 0x20b6;resident_put 0x1143 !q.hl(!q.bc land 255);a(read 0x2029);rar();need(not !q.flags.carry)"1140 output gate-set";
  let address()=pair 0x1d8a;hl(!q.hl land 255);bc 0x1d0a;dad !q.bc;need(read 0x1d8a<128&&read 0x1d8b<8)"1140 cursor scope"in
  address();a(read !q.hl);add !q.a;compatibility(H.Push(0x1257,(!q.a lsl 8)lor psw()));
  a(read 0x20b6);ani 1;restore();logical false(!q.bc land 255);
  address();resident_put 0x1169 !q.hl !q.a;
  a(read 0x1d8b);a(inc !q.a);ani 7;resident_put 0x1170 0x1d8b !q.a;cmp 0;
  if !q.flags.zero then(a(read 0x1d8a);a(inc !q.a);resident_put 0x117c 0x1d8a !q.a;cmp 128;if !q.flags.zero then(
   need (match operation with Output _|Pli2_output _->true|_->false) "1140 refill/flush outside no-flush scope";
   bc 0x1d0a;resident_call 0x1187 0x02ee(fun()->q:=native ~site:0x1287 ~target:0x03ee !q);
   bc 0x1ce4;resident_call 0x118d 0x0328(fun()->q:=native ~site:0x128d ~target:0x0428 !q);
   cmp 0;need !q.flags.zero "1140 write error";hl 0x1d8a;resident_put 0x119b !q.hl 0))in
 let bits_write()=
  hl 0x20b8;resident_put 0x11a1 !q.hl(!q.de land 255);hl(U.wrap(!q.hl-1));resident_put 0x11a3 !q.hl(!q.bc land 255);
  let rec loop()=
   a 0;hl 0x20b8;cmp(read !q.hl);
   if !q.flags.carry then(
    a(read 0x20b7);let old= !q.a in q:={!q with R.a=B.wrap(old lsl 1)lor(old lsr 7);flags={!q.flags with carry=old land 128<>0}};
    resident_put 0x11b1 0x20b7 !q.a;c !q.a;resident_call 0x11b5 0x1140 bit_write;
    a(read 0x20b8);a(dec !q.a);resident_put 0x11bc 0x20b8 !q.a;loop())in loop()in
 let align_output()=
  a(read 0x2029);rar();if not !q.flags.carry then(
   a(read 0x1d05);rar();if !q.flags.carry then(
    let rec pad()=a(read 0x1d8b);cmp 0;if not !q.flags.zero then(c 0;resident_call 0x1264 0x1140 bit_write;pad())in pad();
    e 7;c 0x9e;resident_call 0x126e 0x119e bits_write))in
 let console offset=q:=Resident_console.run offset memory ~entry:!q ~write ~compatibility ~invoke:native
  ~guard_string:(fun pointer->
   let rec length i=need(i<256&&pointer+i<65536)"console bounded string";if read(pointer+i)=0x24 then i+1 else length(i+1)in
   let width=length 0 in
   need(not(List.exists(fun(a,b)->pointer<b&&pointer+width>a)[0x1ce4,0x1d8c;0x205f,0x20c1;0x2155,0x215d]))"console string/output/FCB/scratch alias";
   need(not(pointer+width>console_entry_sp-512))"console string/stack alias")in
 let word_bits ?(entry=0x1207) ()=
  let cache,prefix=List.assoc entry[0x11c3,(0x20b9,0);0x11e5,(0x20bb,0x40);0x1207,(0x20bd,0x80)]in
  hl(cache+1);resident_put(entry+3)!q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));resident_put(entry+5)!q.hl(!q.bc land 255);
  e 2;c prefix;resident_call(entry+10)0x119e bits_write;
  pair cache;a(!q.hl land 255);c !q.a;e 8;resident_call(entry+20)0x119e bits_write;
  pair cache;a(!q.hl lsr 8);c !q.a;e 8;resident_call(entry+30)0x119e bits_write in
 let position_step()=
  pair 0x1c2c;hl(U.wrap(!q.hl+1));store 0x7540 0x1c2c !q.hl;a 0;
  resident 0x7545 0x1a29(fun()->q:=Resident_reader.run Resident_reader.Byte_difference memory ~entry:!q ~write ~compatibility ~sp ~invoke:native);
  logical false(!q.hl land 255);need(not !q.flags.zero)"753C wrapped zero position/error alternative" in
 let position_pair()=call 0x7550 0x753c position_step;call 0x7553 0x753c position_step in
 let carrier offset cache word_input ()=
  hl(if word_input then cache+1 else cache);
  put(offset+3)!q.hl(if word_input then !q.bc lsr 8 else !q.bc land 255);
  if word_input then(hl( !q.hl-1);put(offset+5)!q.hl(!q.bc land 255));
  a(read 0x201d);rar();need(not !q.flags.carry)"compact field carrier gate/error alternative" in
 let byte_bits()=
  hl 0xadd2;put 0x755a !q.hl(!q.bc land 255);c 0;resident 0x755d 0x1140 bit_write;
  pair 0xadd2;c(!q.hl land 255);e 8;resident 0x7566 0x119e bits_write;call 0x7569 0x753c position_step in
 let word_bytes()=
  hl 0xadd9;put 0x75f4 !q.hl(!q.bc lsr 8);hl( !q.hl-1);put 0x75f6 !q.hl(!q.bc land 255);
  c 0;resident 0x75f9 0x1140 bit_write;pair 0xadd8;a(!q.hl land 255);c !q.a;e 8;resident 0x7603 0x119e bits_write;
  c 0;resident 0x7608 0x1140 bit_write;pair 0xadd8;a(!q.hl lsr 8);c !q.a;e 8;resident 0x7612 0x119e bits_write;
  call 0x7615 0x7550 position_pair in
 let pointer_generation()=
  hl 0xadeb;put 0x7704 !q.hl(!q.bc lsr 8);hl( !q.hl-1);put 0x7706 !q.hl(!q.bc land 255);
  bc 0;call 0x770a 0x75f1 word_bytes;e 7;c 0x8c;resident 0x7711 0x119e bits_write;
  pair 0x1c2c;hl(U.wrap(!q.hl-1));hl(U.wrap(!q.hl-1));bc !q.hl;resident 0x771b 0x11e5(fun()->word_bits ~entry:0x11e5());
  hl 0xadee;put 0x7721 !q.hl 4;
  let rec trim()=
   pair 0xadee;hl( !q.hl land 255);exchange();pair 0xadea;dad !q.de;a(read !q.hl);sub 0x20;sub 1;mask();save 0x7733;
   a(read 0xadee);sub 0;add 255;mask();bc(pop());c(!q.bc lsr 8);logical true(!q.bc land 255);rar();
   if !q.flags.carry then(hl 0xadee;let value=dec(read !q.hl)in put 0x7746 !q.hl value;trim())in
  trim();hl 0xadee;let value=inc(read !q.hl)in put 0x774d !q.hl value;let value=inc(read !q.hl)in put 0x774e !q.hl value;
  a(read 0xadee);add !q.a;add !q.a;add !q.a;add !q.a;add !q.a;c !q.a;e 3;resident 0x775a 0x119e bits_write;
  a(read 0x201d);rar();need(not !q.flags.carry)"7701 201D mode alternative";
  a(read 0x201c);rar();need(not !q.flags.carry)"7701 201C mode alternative";
  e 8;c 0x3f;resident 0x777d 0x119e bits_write;hl 0xadec;put 0x7783 !q.hl 0;
  let rec emit()=
   a(read 0xadee);a(dec !q.a);a(dec !q.a);hl 0xadec;cmp(read !q.hl);
   if not !q.flags.carry then(
    pair 0xadec;hl(!q.hl land 255);exchange();pair 0xadea;dad !q.de;a(read !q.hl);put 0x779c 0xaded !q.a;
    c !q.a;e 8;resident 0x77a2 0x119e bits_write;
    a(read 0x201c);hl 0x201d;logical false(read !q.hl);rar();need(not !q.flags.carry)"7701 combined mode alternative";
    hl 0xadec;let value=inc(read !q.hl)in put 0x77ba !q.hl value;if not !q.flags.zero then emit())in emit()in
 let preparation79e2()=a(read 0xae05);cmp 0;need !q.flags.zero "79E2 nonzero preparation arm"in
 let reset73d0()=
  a(read 0xadaa);rar();if !q.flags.carry then(
   hl 0xadaa;put 0x73db !q.hl 0;hl 0xadc4;put 0x73e0 !q.hl 0;
   let rec clear()=a 7;hl 0xadc4;cmp(read !q.hl);if not !q.flags.carry then(
    pair 0xadc4;hl(!q.hl land 255);bc 0xadab;dad !q.bc;put 0x73f4 !q.hl 0;
    hl 0xadc4;let value=inc(read !q.hl)in put 0x73f9 !q.hl value;if not !q.flags.zero then clear())in clear())in
 let rec pli2_output offset=match offset with
 |0x79e2->preparation79e2()|0x73d0->reset73d0()
 |0x83b4->
  need(!q.bc land 255>0&& !q.bc land 255<=8)"83B4 shift count";
  let rec shift()=dad !q.hl;let old= !q.bc land 255 in let n=dec old in c n;if not !q.flags.zero then shift()in shift()
 |0x8398->e !q.a;de(!q.de land 255);a(!q.de land 255);logical false(!q.hl land 255);hl((!q.hl land 0xff00)lor !q.a);a(!q.de lsr 8);logical false(!q.hl lsr 8);hl(!q.a lsl 8 lor(!q.hl land 255))
 |0x83d2->c !q.a;bc(!q.bc land 255);a(!q.de land 255);sub(!q.bc land 255);hl((!q.hl land 0xff00)lor !q.a);
  let old= !q.de lsr 8 and borrow=if !q.flags.carry then 1 else 0 in let n=B.wrap(old-borrow)in q:={!q with R.a=n;hl=n lsl 8 lor(!q.hl land 255);flags=flags n((old land 15)>=borrow)(old<borrow)}
 |0x7d47|0x7d85->
  need(!q.bc land 255<8)"paired adjustment carrier";
  let forward=offset=0x7d47 in let cell,start,tag=if forward then 0xae32,0x7d47,3 else 0xae33,0x7d85,11 in
  hl cell;put(start+3)!q.hl(!q.bc land 255);a(read cell);cmp 6;
  if !q.flags.zero then(hl 0xadc9;put(start+15)!q.hl 1;e 6;c tag;call(start+21)0x75ce(fun()->pli2_output 0x75ce))
  else(pair cell;exchange();c tag;call(start+31)0x75ce(fun()->pli2_output 0x75ce);
   pair cell;hl(!q.hl land 255);bc 0xadb4;dad !q.bc;a(read !q.hl);a(if forward then inc !q.a else dec !q.a);put(start+45)!q.hl !q.a;cmp(if forward then 0 else 255);
   if !q.flags.zero then(pair cell;hl(!q.hl land 255);bc 0xadb3;dad !q.bc;let n=if forward then inc(read !q.hl)else dec(read !q.hl)in put(start+60)!q.hl n))
 |0x7ed6->
  hl 0xae3c;put 0x7ed9 !q.hl(!q.de lsr 8);hl(!q.hl-1);put 0x7edb !q.hl(!q.de land 255);hl(!q.hl-1);put 0x7edd !q.hl(!q.bc land 255);
  a(read 0x202b);rar();if !q.flags.carry then a 0 else(
   a(read 0xadaa);rar();if not !q.flags.carry then a 0 else(
    a(read 0xae3a);cmp 6;if !q.flags.zero then a 0 else(
     need(read 0xae3a<7)"7ED6 adjacent bounded carrier indices";
     pair 0xae3a;hl(!q.hl land 255);bc 0xadab;dad !q.bc;push 0x7f06 !q.hl;
     pair 0xae3a;hl(!q.hl land 255);bc(!q.bc+1);dad !q.bc;a(read !q.hl);hl(pop());logical true(read !q.hl);rar();
     let arithmetic_done=if not !q.flags.carry then false else(
      pair 0xae3a;hl(!q.hl land 255);bc 0xadb3;dad !q.bc;c(read !q.hl);bc(!q.bc land 255);hl !q.bc;c 8;call 0x7f25 0x83b4(fun()->pli2_output 0x83b4);push 0x7f28 !q.hl;
      pair 0xae3a;hl(!q.hl land 255);bc 0xadb4;dad !q.bc;a(read !q.hl);hl(pop());call 0x7f34 0x8398(fun()->pli2_output 0x8398);store 0x7f37 0xae3e !q.hl;
      de 0xae3b;resident 0x7f3d 0x1a43 pointer_minus;exchange();a 3;call 0x7f43 0x83d2(fun()->pli2_output 0x83d2);
      let rec adjust_word direction remaining=
       need(remaining>0)"7ED6 bounded adjacent-word adjustment";
       bc(if direction then 0xae3e else 0xae3b);de(if direction then 0xae3b else 0xae3e);
       resident (if direction then 0x7f4f else 0x7f87) 0x1a33 pointer_words;
       a 0;resident (if direction then 0x7f54 else 0x7f8c) 0x1a29(fun()->q:=Resident_reader.run Resident_reader.Byte_difference memory ~entry:!q ~write ~compatibility ~sp ~invoke:native);
       logical false(!q.hl land 255);
       if !q.flags.zero then a 1 else(
        pair 0xae3a;c(!q.hl land 255);call (if direction then 0x7f5f else 0x7f97)(if direction then 0x7d47 else 0x7d85)(fun()->pli2_output(if direction then 0x7d47 else 0x7d85));
        pair 0xae3e;hl(U.wrap(!q.hl+(if direction then 1 else -1)));store (if direction then 0x7f66 else 0x7f9e) 0xae3e !q.hl;adjust_word direction(remaining-1))in
      if !q.flags.carry then(adjust_word true 3;true)else(
       bc 0xae3b;de 0xae3e;resident 0x7f75 0x1a33 pointer_words;exchange();a 3;call 0x7f7b 0x83d2(fun()->pli2_output 0x83d2);
       if !q.flags.carry then(adjust_word false 3;true)else false))in
     if not arithmetic_done then(
     pair 0xae3b;a(!q.hl lsr 8);put 0x7fab 0xae40 !q.a;a(!q.hl land 255);put 0x7faf 0xae41 !q.a;
     pair 0xae3a;c(!q.hl land 255);pair 0xae40;exchange();call 0x7fba 0x7365(fun()->pli2_output 0x7365);rar();
     let matched_first= !q.flags.carry in
     if matched_first then(
      a(read 0xae3a);a(inc !q.a);pair 0xae41;exchange();c !q.a;call 0x7fca 0x7e05(fun()->pli2_output 0x7e05);a 1)
     else(
      a(read 0xae3a);a(inc !q.a);pair 0xae41;exchange();c !q.a;call 0x7fd9 0x7365(fun()->pli2_output 0x7365);rar();
      if !q.flags.carry then(pair 0xae3a;c(!q.hl land 255);pair 0xae40;exchange();call 0x7fe8 0x7e05(fun()->pli2_output 0x7e05);a 1)
      else(
       hl 0xae42;put 0x7ff1 !q.hl 255;hl(!q.hl+1);put 0x7ff4 !q.hl 255;hl 0xae3d;put 0x7ff9 !q.hl 0;
       let rec search remaining=
        need(remaining>0)"7ED6 bounded scan";a 7;hl 0xae3d;cmp(read !q.hl);
        if not !q.flags.carry then(
         a(read 0xae3d);cmp 6;
         let found=if !q.flags.zero then false else(
          pair 0xae3b;a(!q.hl lsr 8);pair 0xae3d;e !q.a;c(!q.hl land 255);call 0x8015 0x7365(fun()->pli2_output 0x7365);rar();
          if !q.flags.carry then(a(read 0xae3d);put 0x801f 0xae42 !q.a);
          pair 0xae3b;a(!q.hl land 255);pair 0xae3d;e !q.a;c(!q.hl land 255);call 0x802b 0x7365(fun()->pli2_output 0x7365);rar();
          if !q.flags.carry then(hl 0xae3a;a(read 0xae3d);cmp(read !q.hl);if not !q.flags.zero then(a(read 0xae3d);put 0x803f 0xae43 !q.a));
          a(read 0xae43);hl 0xae42;logical false(read !q.hl);let old= !q.a in q:={!q with R.a=B.wrap(old lsl 1)lor(old lsr 7);flags={!q.flags with carry=old land 128<>0}};rar();
          not !q.flags.carry)in
         if found then(
          pair 0xae3a;c(!q.hl land 255);pair 0xae42;exchange();call 0x8056 0x793c(fun()->pli2_output 0x793c);
          a(read 0xae3a);a(inc !q.a);pair 0xae43;exchange();c !q.a;call 0x8062 0x793c(fun()->pli2_output 0x793c);a 1)
         else(hl 0xae3d;let n=inc(read !q.hl)in put 0x806b !q.hl n;if not !q.flags.zero then search(remaining-1)else a 0))else a 0 in
       search 9))))))
 |0x82dd->
  e 7;c 0x9a;resident 0x82e1 0x119e bits_write;
  pair 0x1c2c;bc !q.hl;resident 0x82e9 0x11e5(fun()->word_bits ~entry:0x11e5());
  e 7;c 0x9c;resident 0x82f0 0x119e bits_write;
  a(read 0xae6a);rar();let tag,site=if !q.flags.carry then 0x11e5,0x82fd else 0x11c3,0x8306 in
  bc 0;resident site tag(fun()->word_bits ~entry:tag());resident 0x8309 0x124b align_output;
  bc 0x94eb;resident 0x830f 0x05ff(fun()->console 0x05ff);
  pair 0x1c2c;bc !q.hl;resident 0x8317 0x0466(fun()->console 0x0466);
  bc 0x94fa;resident 0x831d 0x05ff(fun()->console 0x05ff);
  pair 0xaca3;store 0x8323 0xac9f !q.hl;pair 0xac9f;
  hl(U.wrap(!q.hl+1));hl(U.wrap(!q.hl+1));c(read !q.hl);hl(U.wrap(!q.hl+1));bc((read !q.hl lsl 8)lor(!q.bc land 255));
  resident 0x832e 0x0466(fun()->console 0x0466);
  bc 0x9507;resident 0x8334 0x05ff(fun()->console 0x05ff);
  pair 0x1c2e;bc !q.hl;resident 0x833c 0x0466(fun()->console 0x0466)
 |0x829c->
  (* Source acquisition precedes the header; the payload pointer is freshly
     reread after the canonical serializer, not retained from entry. *)
  pair 0xaca3;store 0x829f 0xac9f !q.hl;
  e 7;c 0x94;resident 0x82a6 0x119e bits_write;
  pair 0xac9f;hl(U.wrap(!q.hl+1));hl(U.wrap(!q.hl+1));c(read !q.hl);
  hl(U.wrap(!q.hl+1));bc((read !q.hl lsl 8)lor(!q.bc land 255));
  resident 0x82b1 0x11c3(fun()->word_bits ~entry:0x11c3())
 |0x7338->
  need(!q.bc land 255<=6)"7338 both publication indices bounded or C6 early return";
  hl 0xadbf;put 0x733b !q.hl(!q.de lsr 8);hl(!q.hl-1);put 0x733d !q.hl(!q.de land 255);hl(!q.hl-1);put 0x733f !q.hl(!q.bc land 255);
  a(read 0xadbd);cmp 6;
  if not !q.flags.zero then(
   pair 0xadbe;a(!q.hl lsr 8);pair 0xadbd;e !q.a;c(!q.hl land 255);
   call 0x7352 0x7314(fun()->pli2_output 0x7314);
   a(read 0xadbd);a(inc !q.a);pair 0xadbe;save 0x735c;
   a(!q.hl land 255);e !q.a;bc(pop());c(!q.bc lsr 8);
   call 0x7361 0x7314(fun()->pli2_output 0x7314))
 |0x7423->hl 0xffff;store 0x7426 0xada6 !q.hl
 |0x79a2->hl 0xae04;put 0x79a5 !q.hl 0;hl(!q.hl+1);put 0x79a8 !q.hl 0;hl(!q.hl+1);put 0x79ab !q.hl 0
 |0x742a->call 0x742a 0x73d0(fun()->pli2_output 0x73d0);call 0x742d 0x7423(fun()->pli2_output 0x7423);pair 0x1c2c
 |0x8258->
  hl 0xae67;put 0x825b !q.hl(!q.bc lsr 8);hl(!q.hl-1);put 0x825d !q.hl(!q.bc land 255);
  call 0x825e 0x73d0(fun()->pli2_output 0x73d0);pair 0x1c2c;store 0x8264 0xae68 !q.hl;
  pair 0xae66;hl(U.wrap(!q.hl+1));bc !q.hl;call 0x826d 0x7434(fun()->pli2_output 0x7434);
  a(read 0x201d);rar();need(not !q.flags.carry)"8258 201D-set arm unobserved";
  pair 0xae68;bc !q.hl;call 0x828d 0x7630(fun()->pli2_output 0x7630);
  pair 0xae68;bc !q.hl;call 0x8295 0x7434(fun()->pli2_output 0x7434);call 0x8298 0x7423(fun()->pli2_output 0x7423)
 |0x82b5->
  hl 0xadaa;put 0x82b8 !q.hl 1;call 0x82ba 0x73d0(fun()->pli2_output 0x73d0);
  hl 0;store 0x82c0 0xada8 !q.hl;bc 0;call 0x82c6 0x7434(fun()->pli2_output 0x7434);
  call 0x82c9 0x7423(fun()->pli2_output 0x7423);hl 0xadc9;put 0x82cf !q.hl 0;hl(!q.hl+1);put 0x82d2 !q.hl 0;
  hl 0xae6a;put 0x82d7 !q.hl 0;call 0x82d9 0x79a2(fun()->pli2_output 0x79a2)

 |0x7397->need(!q.bc land 255<8)"7397 carrier index scope";hl 0xadc2;put 0x739a !q.hl(!q.bc land 255);pair 0xadc2;hl(!q.hl land 255);bc 0xadab;dad !q.bc;put 0x73a4 !q.hl 0
 |0x73a7->
  hl 0xadc3;put 0x73aa !q.hl(!q.bc land 255);a(read 0xadc3);cmp 6;
  need(not !q.flags.zero)"73A7 index6 early return unobserved";
  if not !q.flags.zero then(pair 0xadc3;c(!q.hl land 255);call 0x73b8 0x7397(fun()->pli2_output 0x7397);a(read 0xadc3);a(inc !q.a);c !q.a;call 0x73c0 0x7397(fun()->pli2_output 0x7397))
 |0x7dc3|0x7de4->
  need(!q.bc land 255<8)"carrier adjustment bounded index";
  let first,cell,tag,site,write=if offset=0x7dc3 then 0x7dc3,0xae34,4,0x7dcd,0x7de2 else 0x7de4,0xae35,5,0x7dee,0x7e03 in
  hl cell;put(first+3)!q.hl(!q.bc land 255);pair cell;exchange();c tag;call site 0x75ce(fun()->pli2_output 0x75ce);
  a(read cell);cmp 6;if not !q.flags.zero then(pair cell;hl(!q.hl land 255);bc 0xadb3;dad !q.bc;
   let value=(if offset=0x7dc3 then inc else dec)(read !q.hl)in put write !q.hl value)
 |0x7e05->
  need(!q.bc land 255<8)"7E05 bounded destination carrier";
  hl 0xae37;put 0x7e08 !q.hl(!q.de land 255);hl(!q.hl-1);put 0x7e0a !q.hl(!q.bc land 255);
  pair 0xae36;c(!q.hl land 255);call 0x7e0f 0x7ae4(fun()->pli2_output 0x7ae4);
  a(read 0xae36);sub 6;add 255;mask();hl 0xadaa;logical true(read !q.hl);save 0x7e1e;
  a(read 0x202b);a(!q.a lxor 255);bc(pop());c(!q.bc lsr 8);logical true(!q.bc land 255);rar();
  let final()=
   pair 0xae36;c(!q.hl land 255);pair 0xae37;exchange();call 0x7ec2 0x7314(fun()->pli2_output 0x7314);
   pair 0xae36;exchange();c 6;call 0x7ecb 0x75ce(fun()->pli2_output 0x75ce);
   pair 0xae37;c(!q.hl land 255);call 0x7ed2 0x75a7(fun()->pli2_output 0x75a7)in
  let search()=
   hl 0xae39;put 0x7e76 !q.hl 0;
   let rec scan()=
    a 7;hl 0xae39;cmp(read !q.hl);
    if !q.flags.carry then final()else(
     pair 0xae39;hl(!q.hl land 255);bc 0xadab;dad !q.bc;a(read !q.hl);rar();
     let match_carrier=if not !q.flags.carry then false else(
      a(read 0xae39);cmp 6;if !q.flags.zero then false else(
       pair 0xae39;hl(!q.hl land 255);bc 0xadb3;dad !q.bc;a(read 0xae37);cmp(read !q.hl);!q.flags.zero))in
     if match_carrier then(pair 0xae36;c(!q.hl land 255);pair 0xae39;exchange();call 0x7eaf 0x793c(fun()->pli2_output 0x793c))
     else(hl 0xae39;let value=inc(read !q.hl)in put 0x7eb6 !q.hl value;if not !q.flags.zero then scan()else final()))in scan()in
  if not !q.flags.carry then final()else(
   pair 0xae36;hl(!q.hl land 255);bc 0xadab;dad !q.bc;a(read !q.hl);rar();
   if not !q.flags.carry then search()else(
    pair 0xae36;hl(!q.hl land 255);bc 0xadb3;dad !q.bc;a(read !q.hl);put 0x7e42 0xae38 !q.a;
    hl 0xae37;cmp(read !q.hl);
    if not !q.flags.zero then(
     a(read 0xae38);a(inc !q.a);hl 0xae37;cmp(read !q.hl);
     if !q.flags.zero then(pair 0xae36;c(!q.hl land 255);call 0x7e5c 0x7dc3(fun()->pli2_output 0x7dc3))
     else(a(read 0xae38);a(dec !q.a);hl 0xae37;cmp(read !q.hl);
      if !q.flags.zero then(pair 0xae36;c(!q.hl land 255);call 0x7e6f 0x7de4(fun()->pli2_output 0x7de4))else search()))))
 |0x7314->
  need(!q.bc land 255<8)"7314 bounded carrier index";
  hl 0xadbc;put 0x7317 !q.hl(!q.de land 255);hl(!q.hl-1);put 0x7319 !q.hl(!q.bc land 255);
  hl 0xadaa;put 0x731d !q.hl 1;push 0x731f !q.hl;
  pair 0xadbb;hl(!q.hl land 255);bc(pop());bc(!q.bc+1);dad !q.bc;put 0x7328 !q.hl 1;
  pair 0xadbb;hl(!q.hl land 255);bc 0xadb3;dad !q.bc;a(read 0xadbc);put 0x7336 !q.hl !q.a
 |0x7365->
  need(!q.bc land 255<8)"7365 bounded carrier index";
  hl 0xadc1;put 0x7368 !q.hl(!q.de land 255);hl(!q.hl-1);put 0x736a !q.hl(!q.bc land 255);
  a(read 0x202b);rar();if !q.flags.carry then a 0
  else(pair 0xadc0;hl(!q.hl land 255);bc 0xadab;dad !q.bc;a(read !q.hl);rar();
   if not !q.flags.carry then a 0
   else(pair 0xadc0;hl(!q.hl land 255);bc 0xadb3;dad !q.bc;a(read 0xadc1);sub(read !q.hl);sub 1;mask()))
 |0x7b1b->
  hl 0xae0d;put 0x7b1e !q.hl(!q.de land 255);hl(!q.hl-1);put 0x7b20 !q.hl(!q.bc land 255);
  a(read 0xae0c);sub 0xa8;sub 1;mask();save 0x7b29;
  a(read 0xae0d);sub 7;sub 1;mask();bc(pop());c(!q.bc lsr 8);logical true(!q.bc land 255);rar();
  let special= !q.flags.carry in
  let early=if special then(
   call 0x7b39 0x79e2 preparation79e2;e 0;c 7;call 0x7b40 0x7365(fun()->pli2_output 0x7365);rar();
   if !q.flags.carry then true else(e 0;c 7;call 0x7b4c 0x7314(fun()->pli2_output 0x7314);false))else false in
  if not early then(
   if not special then(a(read 0xae0c);cmp 0xb8;if not !q.flags.zero then(c 7;call 0x7b5c 0x7397(fun()->pli2_output 0x7397)));
   pair 0xae0c;c(!q.hl land 255);call 0x7b63 0x746f(carrier 0x746f 0xadcc false);
   pair 0xae0d;c(!q.hl land 255);call 0x7b6a 0x74c7(carrier 0x74c7 0xadcf false);
   a(read 0xae0d);hl 0xae0c;logical false(read !q.hl);c !q.a;call 0x7b75 0x7557 byte_bits)
 |0x793c->
  need(!q.bc land 255<8&& !q.de land 255<8)"793C bounded byte indices";
  hl 0xae03;put 0x793f !q.hl(!q.de land 255);hl(!q.hl-1);put 0x7941 !q.hl(!q.bc land 255);
  a(read 0xae03);cmp 6;
  if !q.flags.zero then(pair 0xae02;hl(!q.hl land 255);bc 0xadab;dad !q.bc;put 0x7953 !q.hl 0)
  else(pair 0xae03;hl(!q.hl land 255);bc 0xadab;dad !q.bc;push 0x7961 !q.hl;
   pair 0xae02;hl(!q.hl land 255);dad !q.bc;de(pop());a(read !q.de);put 0x796a !q.hl !q.a);
  pair 0xae03;hl(!q.hl land 255);bc 0xadb3;dad !q.bc;push 0x7974 !q.hl;
  pair 0xae02;hl(!q.hl land 255);dad !q.bc;de(pop());a(read !q.de);put 0x797d !q.hl !q.a;
  c 0x40;call 0x7980 0x746f(carrier 0x746f 0xadcc false);
  pair 0xae02;c(!q.hl land 255);call 0x7987 0x74c7(carrier 0x74c7 0xadcf false);
  pair 0xae03;c(!q.hl land 255);call 0x798e 0x74c7(carrier 0x74c7 0xadcf false);
  a(read 0xae02);add !q.a;add !q.a;add !q.a;logical false 0x40;hl 0xae03;logical false(read !q.hl);c !q.a;call 0x799e 0x7557 byte_bits
 |0x7b99->
  hl 0xae11;put 0x7b9c !q.hl(!q.de land 255);hl(!q.hl-1);put 0x7b9e !q.hl(!q.bc land 255);
  pair 0xae10;c(!q.hl land 255);call 0x7ba3 0x7ae4(fun()->pli2_output 0x7ae4);
  pair 0xae10;c(!q.hl land 255);pair 0xae11;exchange();call 0x7bae 0x793c(fun()->pli2_output 0x793c)
 |0x7903->
  hl 0xae01;put 0x7906 !q.hl(!q.de land 255);hl(!q.hl-1);put 0x7908 !q.hl(!q.bc land 255);
  a(read 0xae01);sub 6;sub 1;mask();put 0x7911 0xadca !q.a;
  a(read 0xae00);cmp 0xc1;
  if !q.flags.zero then(a(read 0xadca);rar();need(not !q.flags.carry)"7903 C1/E6 alternative";pair 0xae01;c(!q.hl land 255);call 0x792d 0x73a7(fun()->pli2_output 0x73a7));
  pair 0xae00;c(!q.hl land 255);pair 0xae01;exchange();call 0x7938 0x75ce(fun()->pli2_output 0x75ce)
 |0x79b6->e 4;c 0xc5;call 0x79ba 0x7903(fun()->pli2_output 0x7903)
 |0x7a17->
  a(read 0xae04);cmp 0;
  if not !q.flags.zero then(
   a(read 0xae04);cmp 1;need !q.flags.zero "7A17 AE04 other nonzero arm";
   call 0x7a28 0x79b6(fun()->pli2_output 0x79b6);
   a(read 0xae05);cmp 2;need(not !q.flags.zero)"7A17 AE05=2 alternative";
   hl 0xae04;put 0x7a3b !q.hl 0;hl 0xae06;let v=dec(read !q.hl)in put 0x7a40 !q.hl v)
 |0x7ac4->
  hl 0xae08;put 0x7ac7 !q.hl(!q.bc land 255);a(read 0xae08);cmp 7;
  if !q.flags.zero then call 0x7ad0 0x79e2 preparation79e2
 |0x7ad4->
  hl 0xae09;put 0x7ad7 !q.hl(!q.bc land 255);a(read 0xae09);cmp 4;
  if !q.flags.zero then call 0x7ae0 0x7a17(fun()->pli2_output 0x7a17)
 |0x7ae4->
  hl 0xae0a;put 0x7ae7 !q.hl(!q.bc land 255);
  pair 0xae0a;c(!q.hl land 255);call 0x7aec 0x7ac4(fun()->pli2_output 0x7ac4);
  pair 0xae0a;c(!q.hl land 255);call 0x7af3 0x7ad4(fun()->pli2_output 0x7ad4);
  a(read 0xae0a);cmp 5;if !q.flags.zero then call 0x7afe 0x7a17(fun()->pli2_output 0x7a17)
 |0x8225->
  need(read 0xae04=0)"8225 inherited clear AE04 scope";
  hl 0xae63;put 0x8228 !q.hl(!q.de lsr 8);hl(!q.hl-1);put 0x822a !q.hl(!q.de land 255);hl(!q.hl-1);put 0x822c !q.hl(!q.bc land 255);
  call 0x822d 0x79e2 preparation79e2;call 0x8230 0x7a17(fun()->pli2_output 0x7a17);call 0x8233 0x73d0 reset73d0;
  pair 0xae61;c(!q.hl land 255);e 9;call 0x823c 0x756d(fun()->pli2_output 0x756d);
  pair 0xae62;bc !q.hl;call 0x8244 0x7701 pointer_generation
 |0x8248->
  hl 0xae65;put 0x824b !q.hl(!q.bc lsr 8);hl(!q.hl-1);put 0x824d !q.hl(!q.bc land 255);
  pair 0xae64;exchange();c 0xc4;call 0x8254 0x8225(fun()->pli2_output 0x8225)
 |0x7701->pointer_generation()
 |0x753c->position_step()|0x7550->position_pair()
 |0x746f->carrier 0x746f 0xadcc false ()
 |0x74c7->carrier 0x74c7 0xadcf false ()
 |0x7510->carrier 0x7510 0xadd0 true ()
 |0x7557->byte_bits()
 |0x756d->
  hl 0xadd4;put 0x7570 !q.hl(!q.de land 255);hl( !q.hl-1);put 0x7572 !q.hl(!q.bc land 255);
  a(read 0xadd3);sub 0xc2;sub 1;mask();push 0x757b((!q.a lsl 8)lor psw());
  a(read 0xadd4);sub 9;sub 1;mask();bc(pop());c(!q.bc lsr 8);logical true(!q.bc land 255);rar();
  if !q.flags.carry then(hl 0xadd4;put 0x758e !q.hl 1);
  a(read 0xadd4);hl 0xadd3;logical false(read !q.hl);c !q.a;call 0x7598 0x746f(carrier 0x746f 0xadcc false);
  a(read 0xadd4);hl 0xadd3;logical false(read !q.hl);c !q.a;call 0x75a3 0x7557 byte_bits
 |0x75a7->
  hl 0xadd5;put 0x75aa !q.hl(!q.bc land 255);a(read 0x201d);rar();need(not !q.flags.carry)"75A7 gate/error alternative";
  c 0;resident 0x75be 0x1140 bit_write;pair 0xadd5;c(!q.hl land 255);e 8;resident 0x75c7 0x119e bits_write;call 0x75ca 0x753c position_step
 |0x75ce->
  hl 0xadd7;put 0x75d1 !q.hl(!q.de land 255);hl( !q.hl-1);put 0x75d3 !q.hl(!q.bc land 255);
  pair 0xadd6;c(!q.hl land 255);call 0x75d8 0x746f(carrier 0x746f 0xadcc false);
  pair 0xadd7;c(!q.hl land 255);call 0x75df 0x74c7(carrier 0x74c7 0xadcf false);
  a(read 0xadd7);add !q.a;add !q.a;add !q.a;hl 0xadd6;logical false(read !q.hl);c !q.a;call 0x75ed 0x7557 byte_bits
 |0x75f1->word_bytes()
 |0x7619->
  hl 0xaddb;put 0x761c !q.hl(!q.bc lsr 8);hl( !q.hl-1);put 0x761e !q.hl(!q.bc land 255);
  pair 0xadda;bc !q.hl;call 0x7624 0x7510(carrier 0x7510 0xadd0 true);
  pair 0xadda;bc !q.hl;call 0x762c 0x75f1 word_bytes
 |0x7434->
  hl 0xadc7;put 0x7437 !q.hl(!q.bc lsr 8);hl( !q.hl-1);put 0x7439 !q.hl(!q.bc land 255);
  e 7;c 0x96;resident 0x743e 0x119e bits_write;
  pair 0xadc6;store 0x7444 0x1c2c !q.hl;bc !q.hl;resident 0x7449 0x11e5(fun()->word_bits ~entry:0x11e5())
 |0x7630|0x765e->
  let cache,member=if offset=0x7630 then 0xaddc,0x11e5 else 0xade0,0x1207 in
  hl(cache+1);put(offset+3)!q.hl(!q.bc lsr 8);hl( !q.hl-1);put(offset+5)!q.hl(!q.bc land 255);
  c 1;resident(offset+8)0x1140 bit_write;pair cache;bc !q.hl;
  resident(offset+16)member(fun()->word_bits ~entry:member());call(offset+19)0x7550 position_pair
 |_->invalid_arg"PLI2 output operation" in
 let payload_bits()=
  a(read 0xa947);cmp 0;
  if not !q.flags.zero then(
   hl 0xa9d9;put 0x66d1 !q.hl 0;
   let rec loop()=
    a(read 0xa947);a(dec !q.a);hl 0xa9d9;cmp(read !q.hl);
    if not !q.flags.carry then(
     c 0;resident 0x66e0 0x1140 bit_write;
     pair 0xa9d9;hl(!q.hl land 255);bc 0xa948;dad !q.bc;c(read !q.hl);e 8;resident 0x66ef 0x119e bits_write;
     hl 0xa9d9;let n=inc(read !q.hl)in put 0x66f5 !q.hl n;if not !q.flags.zero then loop())in loop())in
 let record_output()=
  hl 0xa9d7;put 0x6671 !q.hl(!q.de lsr 8);hl(U.wrap(!q.hl-1));put 0x6673 !q.hl(!q.de land 255);
  hl(U.wrap(!q.hl-1));put 0x6675 !q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put 0x6677 !q.hl(!q.bc land 255);
  pair 0xa9d4;store 0x667b 0xa863 !q.hl;call 0x667e 0x41a6 field_byte;ani 31;put 0x6683 0xa9d8 !q.a;
  a(read 0xa9d8);cmp 9;need !q.flags.zero "666E field3 alternatives";
  e 7;c 0x96;resident 0x6692 0x119e bits_write;
  call 0x6695 0x66fa(fun()->bc 6;pair 0xa863;guard_field !q.hl 8;dad !q.bc;de 0xa9d6;
   call 0x6704 0x82bb(fun()->c(read !q.hl);hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor(!q.bc land 255));
    a(read !q.de);add(!q.bc land 255);hl((!q.hl land 0xff00)lor !q.a);de(U.wrap(!q.de+1));
    let v=read !q.de and cy=if !q.flags.carry then 1 else 0 in let n=v+(!q.bc lsr 8)+cy in
    q:={!q with R.a=B.wrap n;hl=(B.wrap n lsl 8)lor(!q.hl land 255);flags=flags(B.wrap n)((v land 15)+(!q.bc lsr 8 land 15)+cy>15)(n>255)}));
  bc !q.hl;resident 0x669a 0x1207 word_bits;call 0x669d 0x66c6 payload_bits in
 let acquisition_publications()=
  pair 0xa634;hl(!q.hl land 255);bc 0xa63b;dad !q.hl;dad !q.bc;push 0x2b88 !q.hl;pair 0xa863;exchange();hl(pop());put 0x2b8e !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x2b90 !q.hl(!q.de lsr 8);
  pair 0xae32;c(!q.hl land 255);child 0x2b95 0x7b7a;put 0x2b98 0xa660 !q.a;
  a(read 0xa634);cmp 1;need(not !q.flags.zero)"28AA index1 arm";
  pair 0xa660;c(!q.hl land 255);pair 0xa863;exchange();child 0x2bb6 0x7af0;
  let publish base site=indexed base;e(read !q.hl);pair 0xa660;c(!q.hl land 255);child site (if base=0xa628 then 0x7b13 else if base=0xa62b then 0x7b2e else 0x7b49)in
  List.iter(fun(base,site)->publish base site)[0xa628,0x2bc7;0xa62b,0x2bd8;0xa62e,0x2be9];
  a(read 0xa661);cmp 0;if !q.flags.zero then(pair 0xa634;c(!q.hl land 255);call 0x2bf8 0x2355(fun()->classifier K.Indexed);a(inc !q.a);put 0x2bfc 0xa661 !q.a);
  pair 0xa660;c(!q.hl land 255);pair 0xa661;exchange();child 0x2c07 0x7ad5;
  hl 0xa660;let n=inc(read !q.hl)in put 0x2c0d !q.hl n;
  List.iter(fun(base,site)->publish base site)[0xa628,0x2c1c;0xa62b,0x2c2d;0xa62e,0x2c3e];
  pair 0xa634;c(!q.hl land 255);call 0x2c45 0x2355(fun()->classifier K.Indexed);add 0x13;
  pair 0xa660;e !q.a;c(!q.hl land 255);child 0x2c4f 0x7ad5 in
 let acquisition_prefix()=
  hl 0xa65f;put 0x28ad !q.hl(!q.bc land 255);
  List.iter(fun(value,site)->indexed 0xa628;a(read !q.hl);sub value;sub 1;mask();put site 0xa662 !q.a;rar();need(not !q.flags.carry)"28AA selector0B/0C/0D")[11,0x28bd;12,0x28e1;13,0x2905];
  indexed 0xa628;a 10;cmp(read !q.hl) in
 let acquisition_arguments acquisition=
  (* Historical DAD H precedes DAD B, not an index equation. *)
  pair 0xa634;hl(!q.hl land 255);bc 0xa63b;dad !q.hl;dad !q.bc;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();store 0x2938 0xa863 !q.hl;
  a(read 0xa662);rar();need(not !q.flags.carry)"28AA negative prefix";hl 0xa662;put 0x294d !q.hl 0x2b;
  pair 0xa628;c(!q.hl land 255);call 0x2953 0x2185 interval_wrapper;
  save 0x2956;pair 0xa662;push 0x295a !q.hl;
  pair 0xa634;hl(!q.hl land 255);bc 0xa63b;dad !q.hl;dad !q.bc;c(read !q.hl);hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor(!q.bc land 255));push 0x2968 !q.bc;c 0;push 0x296b !q.bc;
  bc 10;pair 0xa863;dad !q.bc;push 0x2973 !q.hl;
  pair 0xa863;guard_field !q.hl 1;a(read !q.hl);sub 10;indexed 0xa628;e(read !q.hl);c !q.a;
  call 0x2985 0x6708 acquisition in
 let acquire_selected02()=
  acquisition_prefix();if not !q.flags.carry then(acquisition_arguments decimal_arguments;
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
  acquisition_publications()) in
 let acquire_index_one()=
  acquisition_prefix();
  if not !q.flags.carry then(
   acquisition_arguments copy_arguments;
   restore();logical true(!q.bc land 255);rar();need(not !q.flags.carry)"28AA first copy conversion arm";
   indexed 0xa628;a(read !q.hl);put 0x29bd 0xa661 !q.a;
   pair 0xa634;hl(!q.hl land 255);dad !q.bc;a(read !q.hl);sub 2;sub 1;mask();save 0x29cc;
   a(read !q.hl);sub 3;sub 1;mask();restore();logical false(!q.bc land 255);rar();need(not !q.flags.carry)"28AA selector2/3";
   indexed 0xa628;a(read !q.hl);cmp 4;need(not !q.flags.zero)"28AA selector4";
   indexed 0xa628;a(read !q.hl);cmp 5;need !q.flags.zero "28AA bounded selector05";
   equality 0xa628 0x28;combine 0x2a3b(fun()->equality 0xa628 0x2a)false;rar();need !q.flags.carry "28AA base selector28/2A";
   indexed 0xa628;put 0x2a54 !q.hl 0x28;
   pair 0xa662;push 0x2a8e !q.hl;
   pair 0xa634;hl(!q.hl land 255);bc 0xa63b;dad !q.hl;dad !q.bc;c(read !q.hl);hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor(!q.bc land 255));push 0x2a9c !q.bc;
   pair 0xa634;push 0x2aa0 !q.hl;bc 10;pair 0xa863;dad !q.bc;push 0x2aa8 !q.hl;
   pair 0xa863;guard_field !q.hl 1;a(read !q.hl);sub 10;pair 0xa661;exchange();c !q.a;
   call 0x2ab4 0x6708 copy_arguments;rar();need !q.flags.carry "28AA second copy false result";
   indexed 0xa628;a(read !q.hl);sub 0x15;sub 1;mask();save 0x2ace;
   a(read !q.hl);sub 0x25;sub 1;mask();restore();logical false(!q.bc land 255);save 0x2ad8;
   a(read !q.hl);sub 0x24;sub 1;mask();restore();logical false(!q.bc land 255);hl 0xa65f;logical true(read !q.hl);rar();need(not !q.flags.carry)"28AA numeric construction arm";
   hl 0xa661;put 0x2b1a !q.hl 0;indexed 0xa628;c(read !q.hl);call 0x2b26 0x46ed traversal;
   a 0;de 0xa863;resident 0x2b2e 0x1a40(fun()->hl !q.a;pointer_minus());logical false(!q.hl land 255);
   need !q.flags.zero "28AA existing-pointer construction alternative";
   indexed 0xa628;c(read !q.hl);call 0x2b3f 0x4738 construction;
   bc 3;pair 0xa863;dad !q.bc;put 0x2b49 !q.hl 0x29;
   indexed 0xa62b;bc 4;push 0x2b57 !q.hl;pair 0xa863;dad !q.bc;de(pop());a(read !q.de);put 0x2b5e !q.hl !q.a;
   indexed 0xa62e;bc 5;push 0x2b6b !q.hl;pair 0xa863;dad !q.bc;de(pop());a(read !q.de);put 0x2b72 !q.hl !q.a;
   pair 0xa863;bc !q.hl;de 0;call 0x2b7b 0x666e record_output;acquisition_publications())in
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
 let initial_channels()=
    List.iter(fun(site,address)->hl address;put site address 0)[0x3265,0xa629;0x326a,0xa62c;0x326f,0xa62f];
    let channel site target destination=pair 0xae32;c(!q.hl land 255);child site target;put(site+3)destination !q.a in
    channel 0x3275 0x7a93 0xa62a;channel 0x327f 0x7aa9 0xa62d;channel 0x3289 0x7abf 0xa630;
    pair 0xae32;c(!q.hl land 255);child 0x3293 0x7a79;store 0x3296 0xa63f !q.hl;hl 0xa634;put 0x329c !q.hl 2 in
 let parent()=
  let selector_minimum()=
   hl 0xa65b;put 0x25c3 !q.hl(!q.bc land 255);pair 0xa65b;c(!q.hl land 255);e 0x36;
   call 0x25ca 0x23a0 minimum;c !q.a;bc(!q.bc land 255);hl 0x42a6;dad !q.bc;a(read !q.hl)in
  let literal_wrapper()=
   hl 0xa654;put 0x24f4 !q.hl(!q.bc land 255);pair 0xa654;c(!q.hl land 255);child 0x24f9 0x8048;
   pair 0xa634;c(!q.hl land 255);child 0x2500 0x240a;
   a(read 0xa634);cmp 1;need(not !q.flags.zero)"24F1 index-one continuation arm"in
  let adjust_selected()=
   indexed 0xa628;put 0x27da !q.hl 0x28;
   indexed 0xa62b;c(read !q.hl);call 0x27e6 0x25c0 selector_minimum;a(inc !q.a);pair 0xa641;e !q.a;c(!q.hl land 255);
   call 0x27ef 0x23a0 minimum;add 3;indexed 0xa62b;put 0x27fd !q.hl !q.a;
   c 0x63;call 0x2800 0x24f1 literal_wrapper in
  let transform()=
   call 0x2f1c 0x2c53(fun()->c 1;call 0x2c55 0x28aa acquire_index_one);
   indexed 0xa628;c(read !q.hl);call 0x2f29 0x21ad(fun()->classifier K.Interval);rar();need !q.flags.carry "2F1C classifier-clear alternatives";
   indexed 0xa628;a(read !q.bc);cmp(read !q.hl);
   if not !q.flags.zero then(
    indexed 0xa628;a(read !q.hl);sub 0x24;sub 1;mask();save 0x2f4e;
    a(read !q.hl);sub 0x25;sub 1;mask();restore();logical false(!q.bc land 255);rar();need(not !q.flags.carry)"2F1C selector24/25";
    indexed 0xa628;a(read !q.hl);cmp 0x16;need(not !q.flags.zero)"2F1C selector16";
    indexed 0xa628;a(read !q.hl);cmp 0x19;need(not !q.flags.zero)"2F1C selector19";
    indexed 0xa628;a(read !q.hl);cmp 0x15;
    if !q.flags.zero then call 0x2f92 0x27d1 adjust_selected;
    indexed 0xa628;a(read !q.hl);cmp 0x31;need(not !q.flags.zero)"2F1C selector31")in
  let initial_transform()=
   call 0x3533 0x3262 initial_channels;
   call 0x3536 0x31a8(fun()->c 1;call 0x31aa 0x2221 special_index;save 0x31ad;c 2;call 0x31b0 0x2221 special_index;restore();logical true(!q.bc land 255);rar();need(not !q.flags.carry)"31A8 both-special alternative";
    hl 0xa62a;a(read 0xa629);cmp(read !q.hl);need(not !q.flags.zero)"31A8 equal-selector arm";hl 0xa628;put 0x31f8 !q.hl 0x28);
   hl 0xa628;a(read 0xa62a);cmp(read !q.hl);
   if not !q.flags.zero then call 0x3543 0x2fae(fun()->a(read 0xa628);ani 0x28;cmp 0x28;need !q.flags.zero "2FAE non28 arm";call 0x2fb8 0x2f1c transform)in
  adjust ~site:0x3bf0 ~delta:(-1);bc((!q.bc land 255)lsl 8 lor(!q.bc land 255));push 0x19f2 !q.bc;adjust ~site:0x3bf3 ~delta:1;
  a(read 0xa619);frame 1;put 0x19fb !q.hl !q.a;hl 0xa619;put 0x19ff !q.hl 0;hl 0xa934;put 0x1a04 !q.hl 0;
  a(read 0x20c3);cmp 0x28;need(not !q.flags.zero)"19F0 context28 arm";
  a(read 0xa5f7);cmp 0;need(not !q.flags.zero)"19F0 zero mode arm";
  call 0x1aa2 0x6639(fun()->hl 0xa933;put 0x663c !q.hl 0;call 0x663e 0x6619 counted_spine;
   pair 0xa933;c(!q.hl land 255);call 0x6645 0x8179(fun()->hl 0xae71;put 0x817c !q.hl(!q.bc land 255);hl 0xae71;a(read 0xae34);sub(read !q.hl);put 0x8184 0xae34 !q.a));
  hl 0xa61d;put 0x1aa8 !q.hl 0xb2;c 0;
  call 0x1aac 0x21e9(fun()->hl 0xa648;put 0x21ec !q.hl(!q.bc land 255);
   let selected()=pair 0xa648;hl(!q.hl land 255);bc 0xa628;dad !q.bc;a(read !q.hl)in
   selected();cmp 0x28;need(not !q.flags.zero)"21E9 selector28 early arm";selected();cmp 0x2a;need(not !q.flags.zero)"21E9 selector2A early arm";
   selected();sub 5;sub 1;mask());
  rar();if !q.flags.carry then(hl 0xa61d;put 0x1ab6 !q.hl 0xac);
  c 0;call 0x1aba 0x2221 special_index;rar();need(not !q.flags.carry)"19F0 special indexed arm";
  hl 0xa628;put 0x1ac9 !q.hl 0x2a;hl 0xa62b;put 0x1ace !q.hl 0xfe;
  a(read 0xae32);put 0x1ad3 0xa61c !q.a;call 0x1ad6 0x3533 initial_transform;
  pair 0xa61d;c(!q.hl land 255);child 0x1add 0x2511;
  hl 0xa61c;a(read 0xae32);sub(read !q.hl);put 0x1ae7 !q.hl !q.a;
  frame 0;a(read !q.hl);rar();need(not !q.flags.carry)"19F0 private input set-bit arm";
  call 0x1af6 0x80b1(fun()->c 0xfe;child 0x80b3 0x8048);a 0;hl(pop())in
  let rec invoke ~site ~target entry=
   q:=entry;
   (match target with
   |0x23af->selector_match()
   |0x63af->low_field()
   |0x63a6->field_byte()
   |0x641f->high_field()
   |0x6427->count_field()
   |0xa5a3->let address= !q.hl in difference !q.de(word address);de(U.wrap(address+1))
   |0x672b->reuse H.Prefix_sum
   |target when List.mem_assoc target [0x2e75,Initialization_parent.Driver;0x2e1b,Initialization_parent.Parent;0x23c6,Terminator;0x2d84,Structure;0x233d,Wrapper;0x6a02,Cursor;0x6a90,Advance;0x69e2,Index;0x69f7,Bit40;0x5763,Mode_step]->
    (if target=0x6a90 then guard_field(word 0xa861)1 else if target=0x2d84 then guard_field(word 0xa863)6);
    q:=Initialization_parent.run(List.assoc target [0x2e75,Initialization_parent.Driver;0x2e1b,Initialization_parent.Parent;0x23c6,Terminator;0x2d84,Structure;0x233d,Wrapper;0x6a02,Cursor;0x6a90,Advance;0x69e2,Index;0x69f7,Bit40;0x5763,Mode_step])memory ~entry:!q ~write ~compatibility ~sp ~invoke
   |0x35ad->c 0x3b;call 0x13af 0x01af selector_match;rar();need !q.flags.carry "13AD unmatched semicolon"
   |0x2387->a(read 0x2010);rar();need(not !q.flags.carry)"0187 set mode"
   |0x35ad->c 0x3b;call 0x13af 0x01af selector_match;rar();need !q.flags.carry "13AD unmatched semicolon"
   |0x7c46->pointer_acquire()
   |0x5fd9->common_gate()
   |0xa5a0->de !q.a;let address= !q.hl in difference !q.de(word address);de(U.wrap(address+1))
   |target when List.mem_assoc target [0x2ad9,Recursive_parent.Acquire_item;0x2a6e,Advance_context;0x6b86,Cleanup_heads;0x6b29,Cleanup_tables;0x2346,Finish_reader;0xa2ef,Emit_position;0xa473,Reset_map]->
    q:=Recursive_parent.run(List.assoc target [0x2ad9,Recursive_parent.Acquire_item;0x2a6e,Advance_context;0x6b86,Cleanup_heads;0x6b29,Cleanup_tables;0x2346,Finish_reader;0xa2ef,Emit_position;0xa473,Reset_map])memory ~entry:!q ~write ~compatibility ~adjust ~sp ~invoke
   |0x4508->c 0;call 0x230a 0x22cb(fun()->classifier K.Selected)
   |0x784e->reuse H.Acquire_overlay
   |0x9a4e->reuse H.Acquire_overlay
   |0x67f0->call 0x45f0 0x4562(fun()->reuse H.Hash_prefix);call 0x45f3 0x422f(fun()->reuse H.Select_pointer);pair 0x20c5;exchange();bc 0x20c6;call 0x45fd 0x4584(fun()->reuse H.Payload_match)
   |target when List.mem_assoc target [0x33e2,Recursive_parent.Inherited_frame;0x2c32,Recursive_frame;0x2c0b,Item_wrapper]->
    q:=Recursive_parent.run(List.assoc target [0x33e2,Recursive_parent.Inherited_frame;0x2c32,Recursive_frame;0x2c0b,Item_wrapper])memory ~entry:!q ~write ~compatibility ~adjust ~sp ~invoke
   |0x5504->transform_pair()
   |0xa3f1->recycle_count()
   |0x4fc3->call 0x2dc3 0x2c59 transform_second;call 0x2dc6 0x2705(fun()->a(read 0xa628);cmp 0x16;need(not !q.flags.zero)"2705 selector16")
   |0x7b0e->hl 0xa93d;put 0x5911 !q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put 0x5913 !q.hl(!q.bc land 255);pair 0xa93c;bc !q.hl;call 0x5919 0x58bb(fun()->ignore(invoke ~site:0x7b19 ~target:0x7abb !q));
    call 0x591c 0x01e8(fun()->ignore(invoke ~site:0x7b1c ~target:0x23e8 !q));call 0x591f 0x239a(fun()->classifier K.Wrapper);add 0x13;c !q.a;call 0x5925 0x256c attribute_dispatch
   |0x4e53->c 1;call 0x2c55 0x28aa(fun()->if read(0xa628+read 0xa634)<=10&&read(0xa628+read 0xa634)<>5 then acquire_selected02()else acquire_index_one())
   |0xa30b->hl 0xae6d;put 0x810e !q.hl(!q.bc land 255);hl 0xae6d;a(read 0xae35);sub(read !q.hl);hl(U.wrap(!q.hl+1));put 0x8117 !q.hl !q.a;put 0x8118 0xae35 !q.a;child 0x811b 0x7d53;a 0;hl 0xae6d;cmp(read !q.hl);need(not !q.flags.carry)"810B positive count route";a(read 0xae34);put 0x814e 0xae35 !q.a
   |target when List.mem_assoc target [0x3000,Recursive_parent.Header;0x3214,Primary_fields;0x329e,Secondary_fields;0x3387,Secondary_wrapper;0x562f,Reduce_fields;0xa352,Shift_fields]->
    q:=Recursive_parent.run(List.assoc target [0x3000,Recursive_parent.Header;0x3214,Primary_fields;0x329e,Secondary_fields;0x3387,Secondary_wrapper;0x562f,Reduce_fields;0xa352,Shift_fields]) memory ~entry:!q ~write ~compatibility ~adjust ~sp ~invoke
   |0x240e->q:=Input_gate.run memory ~entry:!q ~compatibility
   |0x23e8->hl 2;store 0x01eb 0xa5b0 !q.hl;a(read 0xa628);cmp 0x70;need(not !q.flags.zero)"01E8 selector70"
   |0x476c->attribute_dispatch()
   |0x8839->hl 0xa933;put 0x663c !q.hl 0;call 0x663e 0x6619 counted_spine;pair 0xa933;c(!q.hl land 255);call 0x6645 0x8179(fun()->ignore(invoke ~site:0x8845 ~target:0xa379 !q))
   |0x459a->classifier K.Wrapper
   |0x55d6->c 1;call 0x33d8 0x33ad(fun()->ignore(invoke ~site:0x55d8 ~target:0x55ad !q))
   |0x55ad->hl 0xa669;put 0x33b0 !q.hl(!q.bc land 255);call 0x33b1 0x31fb acquire_two_groups;
    a(read 0xa629);put 0x33b7 0xa628 !q.a;a(read 0xa62c);put 0x33bd 0xa62b !q.a;a(read 0xa62f);put 0x33c3 0xa62e !q.a;
    call 0x33c6 0x2259 pair_gate;rar();need(not !q.flags.carry)"33AD set-result arm";
    pair 0xa669;c(!q.hl land 255);call 0x33d2 0x335b(fun()->ignore(invoke ~site:0x55d2 ~target:0x555b !q))
   |0x555b->hl 0xa668;put 0x335e !q.hl(!q.bc land 255);hl 0xa634;put 0x3362 !q.hl 2;a(read 0xa628);cmp 0x31;need(not !q.flags.zero)"335B selector31";
    pair 0xa668;c(!q.hl land 255);call 0x3383 0x28aa(fun()->if read(0xa628+read 0xa634)<=10&&read(0xa628+read 0xa634)<>5 then acquire_selected02()else acquire_index_one());pair 0xa628;c(!q.hl land 255);call 0x338a 0x2185 interval_wrapper;rar();need !q.flags.carry "335B clear classifier";
    call 0x3391 0x2dca(fun()->ignore(invoke ~site:0x5591 ~target:0x4fca !q))
   |0x4fca->a(read 0xa62a);cmp 0x2a;need(not !q.flags.zero)"2DCA selector2A";a(read 0xa62a);cmp 0x28;need(not !q.flags.zero)"2DCA selector28";hl 0xa634;put 0x2e20 !q.hl 2;call 0x2e22 0x2dc3(fun()->call 0x2dc3 0x2c59 transform_second;call 0x2dc6 0x2705(fun()->a(read 0xa628);cmp 0x16;need(not !q.flags.zero)"2705 selector16"))
   |0x5462->initial_channels()
   |0x83b6->call 0x61b6 0x61a4(fun()->hl 0xa941;put 0x61a7 !q.hl 0;call 0x61a9 0x60e5 context);cmp 0;need !q.flags.zero "61B6 nonzero acquisition"
   |target when List.mem_assoc target [0xa379,Recursive_parent.Restore_index;0x249c,Bracket_setup;0x2477,Publish_pair;0x24ca,Advance_record;0x2466,Line_decrement;0x31c9,Lookahead_finish]->
    q:=Recursive_parent.run(List.assoc target [0xa379,Recursive_parent.Restore_index;0x249c,Bracket_setup;0x2477,Publish_pair;0x24ca,Advance_record;0x2466,Line_decrement;0x31c9,Lookahead_finish]) memory ~entry:!q ~write ~compatibility ~adjust ~sp ~invoke
   |target when List.mem_assoc target [0x24f0,Recursive_parent.Parent;0xa2ca,Line_gate;0x24e9,Base;0x23d8,Clear_state;0x2461,Line_increment;0x246b,Clear_fields]->
    q:=Recursive_parent.run(List.assoc target [0x24f0,Recursive_parent.Parent;0xa2ca,Line_gate;0x24e9,Base;0x23d8,Clear_state;0x2461,Line_increment;0x246b,Clear_fields])memory ~entry:!q ~write ~compatibility ~adjust ~sp ~invoke
   |0x4206->
    hl 0xa61e;put 0x2009 !q.hl 0;hl 0xa606;put 0x200e !q.hl 0;hl 0xa5f9;put 0x2013 !q.hl 0;a 0;hl(U.wrap(!q.hl+1));put 0x2018 !q.hl !q.a;hl(U.wrap(!q.hl+1));put 0x201a !q.hl 0;
    bc 0x3594;call 0x201f 0x57b7(fun()->reuse H.Search);rar();need(not !q.flags.carry)"2006 found table route";
    c 0x8c;call 0x2032 0x01af selector_match;rar();need(not !q.flags.carry)"2006 8C route";
    c 0x90;call 0x2043 0x01af selector_match;rar();need !q.flags.carry "2006 unmatched90 route";
    c 1;call 0x204c 0x1c07(fun()->ignore(invoke ~site:0x424c ~target:0x3e07 !q));
    call 0x20a2 0x13ad(fun()->c 0x3b;call 0x13af 0x01af selector_match;rar();need !q.flags.carry "13AD unmatched semicolon")
   |0x6c26->
    pair 0xa8eb;hl(!q.hl land 255);bc 0xa86d;dad !q.hl;dad !q.bc;de(word !q.hl);hl(U.wrap(!q.hl+1));exchange();store 0x4a34 0xa863 !q.hl;
    let rec loop()=c 0;call 0x4a39 0x424f advance_matching;call 0x4a3c 0x4275(fun()->reuse H.Pointer_compare);rar();need !q.flags.carry "4A26 exhausted traversal";
     call 0x4a44 0x419f tag;cmp 0x43;
     if not !q.flags.zero then loop()else(
      call 0x4a4c 0x47f7(fun()->call 0x47f7 0x41a6 field_byte;ani 0x40;sub 0x40;add 0xff;mask());rar();
      if not !q.flags.carry then loop()else(call 0x4a53 0x4227 count_field;cmp 0;if not !q.flags.zero then loop()else(
       pair 0xa8eb;hl(!q.hl land 255);bc 0xa86d;dad !q.hl;dad !q.bc;push 0x4a65 !q.hl;pair 0xa863;exchange();hl(pop());put 0x4a6b !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x4a6d !q.hl(!q.de lsr 8))))in loop()
   |0x7abb->
    hl 0xa93b;put 0x58be !q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put 0x58c0 !q.hl(!q.bc land 255);pair 0xa93a;store 0x58c4 0xa863 !q.hl;store 0x58c7 0xa63b !q.hl;
    call 0x58ca 0x419f tag;put 0x58cd 0xa628 !q.a;bc 4;pair 0xa863;dad !q.bc;a(read !q.hl);put 0x58d8 0xa62b !q.a;
    pair 0xa863;bc(U.wrap(!q.bc+1));dad !q.bc;a(read !q.hl);put 0x58e1 0xa62e !q.a;call 0x58e4 0x239a(fun()->classifier K.Wrapper);a(inc !q.a);c !q.a;child 0x58e9 0x2511;
    pair 0xa93a;store 0x58ef 0xa863 !q.hl;call 0x58f2 0x41af low_field;cmp 3;need(not !q.flags.zero)"58BB low-field3";call 0x5900 0x41af low_field;cmp 5;need(not !q.flags.zero)"58BB low-field5"
   |0x3e07->
    hl 0xa621;put 0x1c0a !q.hl(!q.bc land 255);a(read 0xa621);put 0x1c0e 0xa5f7 !q.a;c 1;call 0x1c13 0x8268(fun()->ignore(invoke ~site:0x3e13 ~target:0xa468 !q));
    let delegated site target=call site target(fun()->ignore(invoke ~site:(site+0x2200)~target:(target+0x2200) !q))in
    let finish site= c 0;delegated site 0x1afd;c !q.a;delegated(site+4)0x140d;c 0xb7;child(site+9)0x80b7 in
    let rec loop()=
     a(read 0x20c3);cmp 0x3b;need(not !q.flags.zero)"1C07 leading semicolon";
     c 0xc6;call 0x1c34 0x01af selector_match;rar();if !q.flags.carry then(delegated 0x1c3b 0x1d13;finish 0x1c40)else(
      c 0xc7;call 0x1c4f 0x01af selector_match;rar();if !q.flags.carry then(
       delegated 0x1c56 0x1d13;delegated 0x1c59 0x4a26;call 0x1c5c 0x4275(fun()->reuse H.Pointer_compare);rar();need !q.flags.carry "1C07 null structure";
       call 0x1c69 0x41af low_field;cmp 5;need(not !q.flags.zero)"1C07 low-field5";pair 0xa863;bc !q.hl;delegated 0x1c80 0x58bb;
       hl 0;store 0x1c86 0xa5b0 !q.hl;c 0x18;call 0x1c8b 0x256c attribute_dispatch;c 0xb0;child 0x1c90 0x80b7;finish 0x1c95;
       let rec trailing()=a(read 0x20c3);cmp 0x3b;if not !q.flags.zero then(call 0x1ca9 0x784e(fun()->reuse H.Acquire_overlay);trailing())in trailing()
      )else(
       delegated 0x1cb0 0x1be8;rar();need(not !q.flags.carry)"1C07 matched95";
       c 0xc4;call 0x1cbc 0x01af selector_match;rar();need(not !q.flags.carry)"1C07 C4 route";
       c 0xc2;call 0x1ce2 0x01af selector_match;rar();need !q.flags.carry "1C07 unmatched C2";
       c 3;delegated 0x1ceb 0x14e4;a(read 0x20c3);cmp 0x28;need(not !q.flags.zero)"1C07 C2 parenthesis arm";
       delegated 0x1cfc 0x0d94;c 0xb5;child 0x1d01 0x2511;c 3;delegated 0x1d06 0x13e3;loop()))in loop()
   |0x3bf0->parent()
   |0x3cfd->
    adjust ~site:0x3cfd ~delta:(-1);bc((!q.bc land 255)lsl 8 lor(!q.bc land 255));push 0x1aff !q.bc;adjust ~site:0x3d00 ~delta:1;
    hl 0xa619;put 0x1b04 !q.hl 0;frame 0;c(read !q.hl);call 0x1b0b 0x8268(fun()->ignore(invoke ~site:0x3d0b ~target:0xa468 !q));
    c 0x28;call 0x1b10 0x01af selector_match;rar();need !q.flags.carry "1AFD context28 unmatched";
    frame 0;a(read !q.hl);rar();need(not !q.flags.carry)"1AFD private bit-set arm";
    c 0;call 0x1b7b 0x19f0 parent;c !q.a;call 0x1b7f 0x140d(fun()->ignore(invoke ~site:0x3d7f ~target:0x360d !q));
    c 0x2c;call 0x1b84 0x01af selector_match;rar();need(not !q.flags.carry)"1AFD comma-repeat arm";
    call 0x1b97 0x156d(fun()->ignore(invoke ~site:0x3d97 ~target:0x376d !q));a 0;hl(pop())
   |0xa2b1->c 0xfe;child 0x80b3 0x8048
   |0xa1f3->hl 0xae66;put 0x7ff6 !q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put 0x7ff8 !q.hl(!q.bc land 255);pair 0xae65;exchange();c 0x0a;child 0x7fff 0x7e5f
   |target when List.mem_assoc target [0x3de8,Reader_construction.False_probe;0x35e3,Descriptor_marker;0x2f6e,Field_setup;0x2f94,Field_literal;0x3da8,Construction_start;0x3dbf,Descriptor_build;0x3f13,Reader_prefix;0x3621,Descriptor_sort;0x360d,Mode_finish;0x376d,Require_close;0xa0d7,Reader_construction.Map_rotate;0x36d4,Descriptor_mask;0x36e4,Descriptor_add;0xa586,Shift_right;0xa54f,Bit_union;0xa580,Shift_left;0xa468,Mode;0xa367,Range_finish]->
    q:=Reader_construction.run(List.assoc target [0x3de8,Reader_construction.False_probe;0x35e3,Descriptor_marker;0x2f6e,Field_setup;0x2f94,Field_literal;0x3da8,Construction_start;0x3dbf,Descriptor_build;0x3f13,Reader_prefix;0x3621,Descriptor_sort;0x360d,Mode_finish;0x376d,Require_close;0xa0d7,Reader_construction.Map_rotate;0x36d4,Descriptor_mask;0x36e4,Descriptor_add;0xa586,Shift_right;0xa54f,Bit_union;0xa580,Shift_left;0xa468,Mode;0xa367,Range_finish]) memory ~entry:!q ~write ~compatibility ~sp ~invoke
   |_->q:=native ~site ~target !q);!q in
 let finalize_output()=
  a(read 0x1d05);rar();need !q.flags.carry "1272 unopened output";
  a(read 0x2029);rar();need(not !q.flags.carry) "1272 suppressed-output close-only route";
  let rec pad()=
   a(read 0x1d8a);sub 0;add 255;mask();compatibility(H.Push(0x138f,(!q.a lsl 8)lor psw()));
   a(read 0x1d8b);sub 0;add 255;mask();restore();logical false(!q.bc land 255);rar();
   if !q.flags.carry then(c 0;resident_call 0x12a1 0x1140 bit_write;pad())in pad();
  bc 0x1ce4;resident_call 0x12aa 0x064c(fun()->q:=native ~site:0x13aa ~target:0x074c !q)in
 (match operation with Pli2_output offset->pli2_output offset|Output offset->(match offset with 0x1272->finalize_output()|0x124b->align_output()|offset when List.mem_assoc offset Resident_console.bounds->console offset|0x1140->bit_write()|0x1a29->q:=Resident_reader.run Resident_reader.Byte_difference memory ~entry:!q ~write ~compatibility ~sp ~invoke:native|0x119e->bits_write()|0x11c3|0x11e5|0x1207->word_bits ~entry:offset ()|_->invalid_arg"output operation")| Adapter offset->ignore(invoke ~site:0 ~target:(offset+0x2200)!q)|Context->context()|Field->field_acquisition()|Attribute->attribute_dispatch()|Spine->recursive_spine()|Resident->reuse H.Resident_acquisition|Pair_gate->pair_gate()|Selected_transform->selected_transform()|Table_adapter->table_adapter()|Wrapper->counted_spine()|Repeat->counted_spine ~repeat_only:true ()|Copy05->copy_arguments()|Traversal->traversal()|Construction->construction()|Record_output->record_output()|Index_one->acquire_index_one()|Parent->parent()|Recursive op->(match op with Recursive_parent.Initialization Initialization_parent.Advance->guard_field(word 0xa861)1|Initialization Structure->guard_field(word 0xa863)6|_->());q:=Recursive_parent.run op memory ~entry:!q ~write ~compatibility ~adjust ~sp ~invoke|Reader op->
  if List.mem_assoc op [Reader_construction.Reader_setup,0x4206;Reader_parent,0x3cfd;Reader_entry,0x3e07;Select_structure,0x6c26;Publish_structure,0x7abb]then ignore(invoke ~site:0 ~target:(List.assoc op [Reader_construction.Reader_setup,0x4206;Reader_parent,0x3cfd;Reader_entry,0x3e07;Select_structure,0x6c26;Publish_structure,0x7abb])!q)else q:=Reader_construction.run op memory ~entry:!q ~write ~compatibility ~sp ~invoke);
 {returned= !q;field= !acquired_field}
