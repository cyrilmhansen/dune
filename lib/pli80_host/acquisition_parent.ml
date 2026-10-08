[@@@warning "-4-40-41-42"]
(** Bounded +5929 historical composition. Shared numeric memory; no decoder,
    CPU, filesystem, corpus identity or oracle state. CALL/save artifacts are
    reported to a separate compatibility planner. *)
module R=Recursive_mapped
module S=State
module U=U16
module B=U8
type event=Enter of int*int|Leave|Push of int*int|Pop|Constructor_arguments of int
type result={returned:R.returned;selection:string;acquisition:string}
type operation=Parent|Hash_prefix|Payload_match|Acquire_overlay|Select_pointer|Successor|Pointer_compare|Null_mask|Search|Resident_acquisition|Prefix_sum|Constructor
let run ?(operation=Parent) ?(constructor_abi=(fun()->0x20c6,0x68a6)) memory ~entry ~write ~compatibility ~guard_field ~saved =
 List.iter B.check [entry.R.a;entry.bc land 255;entry.de land 255];List.iter U.check [entry.bc;entry.de;entry.hl];
 let q=ref entry in
 let need b text=if not b then invalid_arg("Acquisition_parent: "^text)in
 let read=S.read memory and word=S.word memory in
 let put site address value=S.write memory address value;write ~site ~address ~value in
 let pair address=q:={!q with R.hl=word address}in
 let a n=q:={!q with R.a=n}and bc n=q:={!q with R.bc=n}and de n=q:={!q with R.de=n}and hl n=q:={!q with R.hl=n}in
 let c n=q:={!q with R.bc=(!q.bc land 0xff00)lor n}in
 let e n=q:={!q with R.de=(!q.de land 0xff00)lor n}in
 let store site address value=put site address(value land 255);put site(U.wrap(address+1))(value lsr 8)in
 let parity n=let n=n lxor(n lsr 4)in let n=n lxor(n lsr 2)in (n lxor(n lsr 1))land 1=0 in
 let flags n ac cy={R.sign=n>=128;zero=n=0;parity=parity n;auxiliary_carry=ac;carry=cy}in
 let cmp n=q:={!q with R.flags=R.comparison !q.a n}in
 let sub n=let old= !q.a in cmp n;a(B.wrap(old-n))in
 let add n=let old= !q.a in let sum=old+n in let v=B.wrap sum in q:={!q with R.a=v;flags=flags v((old land 15)+(n land 15)>15)(sum>255)}in
 let mask()=let cy= !q.flags.carry in let v=if cy then 255 else 0 in q:={!q with R.a=v;flags=flags v(not cy)cy}in
 let logical and_op n=let v=if and_op then !q.a land n else !q.a lor n in q:={!q with R.a=v;flags=flags v and_op false}in
 let ani n=logical true n in
 let rar()=let old= !q.a in q:={!q with R.a=(old lsr 1)lor(if !q.flags.carry then 128 else 0);flags={!q.flags with carry=old land 1<>0}}in
 let dad n=let sum= !q.hl+n in q:={!q with R.hl=U.wrap sum;flags={!q.flags with carry=sum>65535}}in
 let inc v=let n=B.wrap(v+1)in q:={!q with R.flags=flags n(v land 15=15)!q.flags.carry};n in
 let dec v=let n=B.wrap(v-1)in q:={!q with R.flags=flags n(v land 15<>0)!q.flags.carry};n in
 let exchange()=let old= !q.hl in hl !q.de;de old in
 let psw()=let f= !q.flags in (if f.sign then 128 else 0)lor(if f.zero then 64 else 0)lor(if f.auxiliary_carry then 16 else 0)lor(if f.parity then 4 else 0)lor 2 lor(if f.carry then 1 else 0)in
 let push site v=compatibility(Push(site,v))in
 let pop()=compatibility Pop in
 let save_mask site=let v= !q.a lsl 8 lor psw()in push site v;v in
 let restore_mask v=pop();bc v;c(v lsr 8)in
 let call site target f=compatibility(Enter(site,target));f();compatibility Leave in
 let resident site=site+0x100 and overlay site=site+0x2200 in
 let call1 site target f=call(overlay site)(overlay target)f in
 let call0 site target f=call(resident site)(resident target)f in
 (* Complete resident arithmetic channels; final flags are high-byte arithmetic. *)
 let word_difference left right=
  let lo=left land 255 and rlo=right land 255 in
  let low= B.wrap(lo-rlo)and borrow=if lo<rlo then 1 else 0 in
  let high=left lsr 8 and rh=right lsr 8 in
  let value=B.wrap(high-rh-borrow)in
  q:={!q with R.a=value;hl=value lsl 8 lor low;flags=flags value((high land 15)>=(rh land 15)+borrow)(high<rh+borrow)}in
 let resident_compare()=hl !q.bc;bc(word !q.hl);word_difference(word !q.de)!q.bc;de(U.wrap(!q.de+1))in
 let mask_pointer()=
  a 0;de 0xa863;
  call(overlay 0x4286)0x1b40(fun()->word_difference(word !q.de)0;de(U.wrap(!q.de+1)));
  logical false(!q.hl land 255);add 255;mask()in
 let select_pointer()=
  pair 0xa760;hl(!q.hl land 255);bc 0xa761;dad !q.hl;dad !q.bc;
  e(read !q.hl);hl(U.wrap(!q.hl+1));de((read !q.hl lsl 8)lor(!q.de land 255));exchange();if !q.hl<>0 then guard_field !q.hl 10;store(overlay 0x423d)0xa863 !q.hl in
 let successor()=bc 8;pair 0xa863;guard_field !q.hl 10;dad !q.bc;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();store(overlay 0x4299)0xa863 !q.hl in
 let pointer_compare()=bc 0xa8ab;de 0xa863;call(overlay 0x427b)0x1b33 resident_compare;mask();a(!q.a lxor 255)in
 let prefix_sum()=
  hl 0xa903;put(overlay 0x452e)!q.hl(!q.de land 255);hl 0xa902;put(overlay 0x4530)!q.hl(!q.bc lsr 8);hl 0xa901;put(overlay 0x4532)!q.hl(!q.bc land 255);
  hl 0xa760;put(overlay 0x4536)!q.hl 0;
  let rec loop()=a 0;hl 0xa903;cmp(read !q.hl);if !q.flags.carry then(
   a(read 0xa903);a(dec !q.a);put(overlay 0x4545)0xa903 !q.a;bc !q.a;
   pair 0xa901;dad !q.bc;a(read 0xa760);add(read !q.hl);put(overlay 0x4553)0xa760 !q.a;loop())in
  loop();a(read 0xa760);ani 127;put(overlay 0x455e)0xa760 !q.a in
 let hash_prefix()=pair 0x20c5;exchange();bc 0x20c6;call1 0x4569 0x452b prefix_sum in
 let payload_match()=
  hl 0xa907;put(overlay 0x4587)!q.hl(!q.de land 255);hl 0xa906;put(overlay 0x4589)!q.hl(!q.bc lsr 8);hl 0xa905;put(overlay 0x458b)!q.hl(!q.bc land 255);
  de 0x1c36;bc 0xa863;call(overlay 0x4592)0x1b33 resident_compare;
  if !q.flags.carry then(
  pair 0xa863;guard_field !q.hl(10+read 0xa907);a(read !q.hl);a(dec !q.a);a(dec !q.a);sub 8;hl 0xa907;cmp(read !q.hl);need !q.flags.zero "payload length mismatch";
  a(read 0xa907);put(overlay 0x45aa)0xa908 !q.a;
  let rec loop()=a(read 0xa908);cmp 0;need(not !q.flags.zero)"zero payload alternative";
   hl 0xa908;let n=dec(read !q.hl)in put(overlay 0x45b8)!q.hl n;bc(read !q.hl);
   pair 0xa905;dad !q.bc;let source= !q.hl in push(overlay 0x45c0)source;
   pair 0xa908;hl(!q.hl land 255);bc 10;dad !q.bc;exchange();pair 0xa863;dad !q.de;
   pop();de source;a(read !q.de);cmp(read !q.hl);need !q.flags.zero "payload mismatch retry";
   a(read 0xa908);cmp 0;if not !q.flags.zero then loop()in loop())in
 let selection=ref ""in
 let selection_operation()=
  hl 0xa90f;put(overlay 0x4654)!q.hl(!q.bc land 255);call1 0x4655 0x4562 hash_prefix;call1 0x4658 0x422f select_pointer;
  let rec loop()=call1 0x465b 0x4275 pointer_compare;rar();if !q.flags.carry then(call1 0x4662 0x428e successor;loop())in loop();
  call1 0x4668 0x4281 mask_pointer;rar();
  if not !q.flags.carry then selection:="null" else(
   pair 0x20c5;exchange();bc 0x20c6;call1 0x4676 0x4584 payload_match;
   call1 0x4679 0x4281 mask_pointer;rar();need !q.flags.carry "post-match null";
   call1 0x4681 0x419f(fun()->pair 0xa863;hl(U.wrap(!q.hl+2));a(read !q.hl));
   hl 0xa90f;cmp(read !q.hl);need !q.flags.zero "tag mismatch retry";selection:="reuse")in
 let allocate()=
  hl 0xa8f6;put(overlay 0x4397)!q.hl(!q.bc land 255);pair 0x1c36;hl(U.wrap(!q.hl-1));exchange();a 8;
  let subtract_byte()=let left= !q.de and amount= !q.a in bc amount;word_difference left amount in
  call1 0x43a1 0x8396 subtract_byte;exchange();a(read 0xa8f6);call1 0x43a8 0x8396 subtract_byte;
  guard_field !q.hl(10+read 0xa8f6);store(overlay 0x43ab)0xa863 !q.hl;exchange();hl 0xae7a;
  call(overlay 0x43b2)0x1b2c(fun()->word_difference !q.de !q.hl);
  need(not !q.flags.carry)"allocator guard/failure";pair 0xa863;hl(U.wrap(!q.hl-1));store(overlay 0x43c2)0x1c36 !q.hl;
  a(read 0xa8f6);add 10;pair 0xa863;put(overlay 0x43cd)!q.hl !q.a;pair 0xa863;hl(U.wrap(!q.hl+1));put(overlay 0x43d2)!q.hl 0 in
 let constructor()=
  hl 0xa900;put(overlay 0x446b)!q.hl(!q.de land 255);hl 0xa8ff;put(overlay 0x446d)!q.hl(!q.bc land 255);hl 0xa8fe;
  let source,resume=constructor_abi()in U.check source;U.check resume;
  bc source;de resume;put(overlay 0x4471)0xa8fe(!q.bc lsr 8);hl 0xa8fd;put(overlay 0x4473)!q.hl(!q.bc land 255);
  compatibility(Constructor_arguments(overlay 0x4474));
  pair 0xa8ff;c(!q.hl land 255);call1 0x4479 0x4394 allocate;
  pair 0xa863;hl(U.wrap(!q.hl+2));a(read 0xa900);put(overlay 0x4484)!q.hl !q.a;
  bc 3;pair 0xa863;dad !q.bc;put(overlay 0x448c)!q.hl 0;
  pair 0xa863;bc(!q.bc+1);dad !q.bc;put(overlay 0x4493)!q.hl 0;
  pair 0xa863;bc(!q.bc+1);dad !q.bc;put(overlay 0x449a)!q.hl 0;
  bc 8;pair 0xa863;dad !q.bc;a 0;put(overlay 0x44a5)!q.hl !q.a;hl(U.wrap(!q.hl+1));put(overlay 0x44a7)!q.hl 0;
  bc 6;pair 0xa863;dad !q.bc;put(overlay 0x44b0)!q.hl !q.a;hl(U.wrap(!q.hl+1));put(overlay 0x44b2)!q.hl 0;
  let rec copy()=a 0;hl 0xa8ff;cmp(read !q.hl);if !q.flags.carry then(
   hl 0xa8ff;let n=dec(read !q.hl)in put(overlay 0x44c0)!q.hl n;bc(read !q.hl);
   pair 0xa8fd;dad !q.bc;let source= !q.hl in push(overlay 0x44c8)source;
   pair 0xa8ff;hl(!q.hl land 255);bc 10;dad !q.bc;exchange();pair 0xa863;dad !q.de;pop();de source;
   a(read !q.de);put(overlay 0x44d9)!q.hl !q.a;copy())in copy();
  call1 0x44dd 0x422f select_pointer;call1 0x44e0 0x4281 mask_pointer;rar();
  if not !q.flags.carry then(
   pair 0x1c36;hl(U.wrap(!q.hl+1));let pointer= !q.hl in push(overlay 0x44eb)pointer;
   pair 0xa760;hl(!q.hl land 255);bc 0xa761;dad !q.hl;dad !q.bc;pop();bc pointer;
   put(overlay 0x44f7)!q.hl(!q.bc land 255);hl(U.wrap(!q.hl+1));put(overlay 0x44f9)!q.hl(!q.bc lsr 8)
  )else(
   let rec walk()=bc 8;pair 0xa863;dad !q.bc;a 0;
    call1 0x4506 0x83a0(fun()->let address= !q.hl in word_difference 0(word address);de(U.wrap(address+1)));
    logical false(!q.hl land 255);if not !q.flags.zero then(call1 0x450d 0x428e successor;walk())in walk();
   pair 0x1c36;hl(U.wrap(!q.hl+1));bc 8;let pointer= !q.hl in push(overlay 0x451a)pointer;
   pair 0xa863;dad !q.bc;pop();bc pointer;put(overlay 0x4520)!q.hl(!q.bc land 255);hl(U.wrap(!q.hl+1));put(overlay 0x4522)!q.hl(!q.bc lsr 8));
  pair 0x1c36;hl(U.wrap(!q.hl+1));store(overlay 0x4527)0xa863 !q.hl in
 let construct_wrapper()=
  hl 0xa910;put(overlay 0x4696)!q.hl(!q.bc land 255);bc 0x20c6;push(overlay 0x469a)!q.bc;
  pair 0x20c5;c(!q.hl land 255);pair 0xa910;exchange();call1 0x46a3 0x4468 constructor in
 let select_or_construct()=
  hl 0xa911;put(overlay 0x46aa)!q.hl(!q.bc land 255);pair 0xa911;c(!q.hl land 255);
  call1 0x46af 0x4651 selection_operation;call1 0x46b2 0x4281 mask_pointer;rar();
  if not !q.flags.carry then(pair 0xa911;c(!q.hl land 255);call1 0x46bd 0x4693 construct_wrapper)in
 (* One canonical implementation also serves the parent dispatcher. *)
 let classifier()=q:=Classifier.run memory ~entry:!q ~write ~call ~push ~pop in
 let mask_context()=
  hl 0x208f;put(resident 0x081a)!q.hl(!q.bc land 255);a 0x5f;hl 0x208f;cmp(read !q.hl);
  if !q.flags.carry then(a(read 0x208f);ani 0x5f)else a(read 0x208f)in
 let counted_read()=
  hl 0x1f08;a(read 0x1f06);cmp(read !q.hl);need !q.flags.carry "reader refill/EOF";
  a(read 0x1f06);a(inc !q.a);put(resident 0x12cc)0x1f06 !q.a;a(dec !q.a);bc !q.a;
  hl 0x1e8e;dad !q.bc;a(read !q.hl)in
 let adapted_read()=call0 0x12d9 0x12ae counted_read;c !q.a;call0 0x12dd 0x0817 mask_context in
 let letter()=a(read 0x20c1);sub 0x41;cmp 0x1a;if !q.flags.carry then a 1 else(a(read 0x20c1);sub 0x3f;sub 1;mask())in
 let digit()=a(read 0x20c1);sub 0x30;sub 10;mask()in
 let continuation()=
  call0 0x15f9 0x15e3 letter;rar();if !q.flags.carry then a 1 else(
   call0 0x1603 0x15da digit;rar();need(not !q.flags.carry)"numeric continuation alternative";
   a(read 0x20c1);sub 0x5f;sub 1;mask())in
 let append_prefix()=
  a 127;hl 0x20c5;cmp(read !q.hl);need(not !q.flags.carry)"prefix overflow";
  pair 0x20c5;hl(!q.hl land 255);bc 0x20c6;dad !q.bc;a(read 0x20c1);put(resident 0x163c)!q.hl !q.a;
  bc(U.wrap(!q.bc-1));a(read !q.bc);a(inc !q.a);hl !q.bc;put(resident 0x1642)!q.hl !q.a;
  a(read 0x20c1);hl 0x1c58;add(read !q.hl);ani 15;put(resident 0x164c)!q.hl !q.a in
 let acquire_resident()=
  hl 0x2088;put(resident 0x1379)!q.hl 0;hl 0x2087;put(resident 0x137c)!q.hl 0;
  a(read 0x2012);rar();need(not !q.flags.carry)"EOF guard";
  hl 0x1c58;put(resident 0x138b)!q.hl 0;hl 0x20c5;put(resident 0x1390)!q.hl 0;
  hl 0x20c4;a(read !q.hl);rar();need(not !q.flags.carry)"reuse guard";
  hl 0x20c3;put(resident 0x13a3)!q.hl 0;
  let rec initial()=
   a(read 0x20c3);cmp 0;need !q.flags.zero "initial selector";
   a(read 0x20c1);sub 0x20;sub 1;mask();let carrier=save_mask(resident 0x13b5)in
   a(read 0x20c1);sub 0;sub 1;mask();restore_mask carrier;logical false(!q.bc land 255);rar();
   if !q.flags.carry then(call0 0x13c5 0x12d9 adapted_read;put(resident 0x13c8)0x20c1 !q.a;initial())else(
    call0 0x13ce 0x15e3 letter;rar();if !q.flags.carry then(hl 0x20c3;put(resident 0x13d8)!q.hl 1)
    else(call0 0x13dd 0x15da digit;rar();
     if !q.flags.carry then(hl 0x20c3;put(resident 0x13e7)!q.hl 2)else(
      a(read 0x20c1);cmp 0x27;need(not !q.flags.zero)"quoted acquisition";hl 0x20c3;put(resident 0x1404)!q.hl 10)))in initial();
  let rec accumulate()=
   a(read 0x20c1);cmp 0;need(not !q.flags.zero)"zero context";
   call0 0x1411 0x1627 append_prefix;a(read 0x20c1);put(resident 0x1417)0x20c2 !q.a;
   call0 0x141a 0x12ae counted_read;put(resident 0x141d)0x20c1 !q.a;
   a(read 0x20c3);cmp 5;need(not !q.flags.zero)"quoted selector";
   pair 0x20c1;c(!q.hl land 255);call0 0x142c 0x0817 mask_context;put(resident 0x142f)0x20c1 !q.a;
   a(read 0x20c3);cmp 10;
   if !q.flags.zero then(
    a(read 0x20c2);sub 0x2e;sub 1;mask();let carrier=save_mask(resident 0x1442)in
    call0 0x1443 0x15da digit;restore_mask carrier;logical true(!q.bc land 255);rar();need(not !q.flags.carry)"dot/digit rewrite");
   a(read 0x20c3);cmp 1;
   if !q.flags.zero then(
    call0 0x145a 0x15f9 continuation;a(!q.a lxor 255);rar();
    if not !q.flags.carry then accumulate()else(
     pair 0x1c58;hl(!q.hl land 255);bc 0x1c38;dad !q.hl;dad !q.bc;
     e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();store(resident 0x1470)0x1c59 !q.hl;
     a 0;de 0x1c59;call0 0x1478 0x1a40(fun()->word_difference(word !q.de)0;de(U.wrap(!q.de+1)));
     logical false(!q.hl land 255);need !q.flags.zero "nonzero acquired word"))
   else(
    List.iter(fun k->a(read 0x20c3);cmp k;need(not !q.flags.zero)"unsupported resident selector")[4;3];
    a(read 0x20c3);cmp 2;
    if !q.flags.zero then(
     a(read 0x20c1);cmp 0x2e;need(not !q.flags.zero)"numeric decimal-point alternative";
     pair 0x20c1;c(!q.hl land 255);call0 0x1534 0x1616(fun()->
      hl 0x2149;put(resident 0x1619)!q.hl(!q.bc land 255);pair 0x2149;c(!q.hl land 255);
      call0 0x161e 0x0817 mask_context;sub 0x45;sub 1;mask());
     rar();need(not !q.flags.carry)"numeric exponent alternative";
     call0 0x1543 0x15da digit;a(!q.a lxor 255);rar();
     if not !q.flags.carry then accumulate())
    else(a(read 0x20c3);cmp 5;need(not !q.flags.zero)"unsupported resident selector"))in accumulate()in
 let acquisition=ref ""in
 let acquire_overlay()=
  call(overlay 0x784e)0x1476 acquire_resident;
  a(read 0x20c3);sub 10;sub 1;mask();let carrier=save_mask(overlay 0x7859)in
  a(read 0x20c6);sub 0x2f;sub 1;mask();restore_mask carrier;logical true(!q.bc land 255);let carrier=save_mask(overlay 0x7865)in
  a(read 0x20c1);sub 0x2a;sub 1;mask();restore_mask carrier;logical true(!q.bc land 255);rar();need(not !q.flags.carry)"triple rewrite";
  a(read 0x20c3);sub 10;add 255;mask();let carrier=save_mask(overlay 0x78ab)in
  a(read 0x20c3);sub 1;add 255;mask();restore_mask carrier;logical true(!q.bc land 255);rar();
  if !q.flags.carry then(need(read 0x20c3=2)"unsupported passthrough acquisition";acquisition:="numeric_selector02_passthrough")else(
  a(read 0x20c3);cmp 10;
  if !q.flags.zero then(
   a(read 0x20c6);put(overlay 0x78c7)0x20c3 !q.a;
   List.iter(fun k->a(read 0x20c3);cmp k;need(not !q.flags.zero)"literal rewrite")[0x21;0x5c;0x2a;0x2d;0x3c;0x3e;0x5e];acquisition:="literal_first_byte")
  else(
   a 13;hl 0x20c5;cmp(read !q.hl);need(not !q.flags.carry)"wide descriptor";
   pair 0x20c5;hl(!q.hl land 255);bc 0x9a32;dad !q.hl;dad !q.bc;
   e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));exchange();store(overlay 0x79a4)0xaa16 !q.hl;
   a(read !q.hl);put(overlay 0x79a8)0xaa18 !q.a;
   let rec traverse()=
    a 0;hl 0xaa18;cmp(read !q.hl);
    if not !q.flags.carry then(hl 0x20c3;put(overlay 0x7a12)!q.hl 1;acquisition:="descriptor_exhausted")
    else(
     hl 0xaa18;let n=dec(read !q.hl)in put(overlay 0x79b7)!q.hl n;
     a(read 0x20c5);hl(U.wrap(!q.hl+1));put(overlay 0x79bc)!q.hl !q.a;
     let rec compare_reverse()=
      a 0;hl 0xaa19;sub(read !q.hl);mask();let carrier=save_mask(overlay 0x79c4)in
      a(read !q.hl);a(dec !q.a);bc !q.a;hl 0x20c6;dad !q.bc;let source= !q.hl in push(overlay 0x79ce)source;
      pair 0xaa19;hl(!q.hl land 255);exchange();pair 0xaa16;dad !q.de;pop();bc source;
      a(read !q.bc);sub(read !q.hl);sub 1;mask();restore_mask carrier;logical true(!q.bc land 255);rar();
      if !q.flags.carry then(hl 0xaa19;let n=dec(read !q.hl)in put(overlay 0x79e9)!q.hl n;compare_reverse())in compare_reverse();
     a(read 0x20c5);a(inc !q.a);de 0xaa16;
     call(overlay 0x79f4)0x1b1c(fun()->
      let amount= !q.a in exchange();e amount;de(!q.de land 255);exchange();a(read !q.de);add(!q.hl land 255);
      let low= !q.a and carry=if !q.flags.carry then 1 else 0 in hl((!q.hl land 0xff00)lor low);de(U.wrap(!q.de+1));a(read !q.de);
      let old= !q.a and high= !q.hl lsr 8 in let sum=old+high+carry in
      let v=B.wrap sum in q:={!q with R.a=v;hl=v lsl 8 lor low;flags=flags v((old land 15)+(high land 15)+carry>15)(sum>255)});
     exchange();hl(U.wrap(!q.hl-1));put(overlay 0x79f9)!q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put(overlay 0x79fb)!q.hl(!q.de lsr 8);
     a(read 0xaa19);cmp 0;if !q.flags.zero then(pair 0xaa16;a(read !q.hl);put(overlay 0x7a08)0x20c3 !q.a;acquisition:="descriptor_match")else traverse())in traverse()))in
 (* Complete +57B7 byte list search, conditional termination as historically. *)
 let search_operation()=
  hl 0xa937;put(overlay 0x57ba)!q.hl(!q.bc lsr 8);hl 0xa936;put(overlay 0x57bc)!q.hl(!q.bc land 255);hl 0xa935;put(overlay 0x57c0)!q.hl 255;
  let rec search()=a(read 0xa935);a(inc !q.a);put(overlay 0x57c6)0xa935 !q.a;bc !q.a;pair 0xa936;dad !q.bc;a(read !q.hl);put(overlay 0x57d1)0xa938 !q.a;cmp 0;
   if !q.flags.zero then(need(operation=Search)"57B7 not found";a 0)else(hl 0xa938;a(read 0x20c3);cmp(read !q.hl);if !q.flags.zero then a 1 else search())in search() in
 let parent()=
 bc 0x7923;call1 0x592c 0x57b7 search_operation;
 rar();need !q.flags.carry "5929 not found";
 pair 0x20c3;c(!q.hl land 255);call1 0x5937 0x46a7 select_or_construct;
 pair 0xa863;store(overlay 0x593d)0xa63b !q.hl;store(overlay 0x5940)0xa635 !q.hl;
 hl 0xa631;put(overlay 0x5946)!q.hl 0;a(read 0x20c3);put(overlay 0x594b)0xa628 !q.a;
 a(read 0x20c5);put(overlay 0x5951)0xa62b !q.a;hl 0xa62e;put(overlay 0x5957)!q.hl 0;
 a(read 0x20c3);sub 3;sub 1;mask();let carrier=save_mask(overlay 0x5961)in
 a(read 0x20c3);sub 4;sub 1;mask();restore_mask carrier;logical false(!q.bc land 255);rar();need(not !q.flags.carry)"selector3/4";
 List.iter(fun k->a(read 0x20c3);cmp k;need(not !q.flags.zero)"selector7/8/9")[7;8;9];
 need(List.mem(read 0x20c3)[2;5])"unsupported selector";
 bc 4;pair 0xa863;dad !q.bc;a(read 0xa62b);put(overlay 0x5a2a)!q.hl !q.a;
 pair 0xa863;bc(U.wrap(!q.bc+1));dad !q.bc;a(read 0xa62e);put(overlay 0x5a33)!q.hl !q.a;
 call1 0x5a34 0x239a classifier;a(inc !q.a);c !q.a;
 call1 0x5a39 0x2511(fun()->q:=saved !q);
 call1 0x5a3c 0x784e acquire_overlay in
 (match operation with Parent->parent()|Hash_prefix->hash_prefix()|Payload_match->payload_match()
 |Acquire_overlay->acquire_overlay()|Select_pointer->select_pointer()|Successor->successor()
 |Pointer_compare->pointer_compare()|Null_mask->mask_pointer()|Search->search_operation()|Resident_acquisition->acquire_resident()|Prefix_sum->prefix_sum()|Constructor->constructor());
 {returned= !q;selection= !selection;acquisition= !acquisition}
