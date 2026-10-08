[@@@warning "-4-40-41-42"]
(** Bounded initialization laws on historical byte-addressed memory. CALL and
    XTHL residue are reported separately; no guest execution or oracle state. *)
module R=Recursive_mapped
module S=State
module H=Acquisition_parent
module U=U16
module B=U8
type operation=Driver|Parent|Terminator|Structure|Wrapper|Cursor|Advance|Index|Bit40|Mode_step
let bounds=function Driver->0x0c75,0x0d1c|Parent->0x0c1b,0x0c75|Terminator->0x01c6,0x01d8|Structure->0x0b84,0x0c1b|Wrapper->0x013d,0x0146|Cursor->0x4802,0x4890|Advance->0x4890,0x4929|Index->0x47e2,0x47f7|Bit40->0x47f7,0x4802|Mode_step->0x3563,0x3585
let run operation memory ~entry ~write ~compatibility ~sp ~invoke =
 let q=ref entry in
 let read=S.read memory and word=S.word memory in
 let need b text=if not b then invalid_arg("Initialization_parent: "^text)in
 let a v=q:={!q with R.a=v}and bc v=q:={!q with R.bc=v}and de v=q:={!q with R.de=v}and hl v=q:={!q with R.hl=v}in
 let c v=bc((!q.bc land 0xff00)lor v)and e v=de((!q.de land 0xff00)lor v)in
 let put site address value=S.write memory address value;write ~site:(site+0x2200)~address ~value in
 let pair address=hl(word address)in
 let dad v=let n= !q.hl+v in q:={!q with R.hl=U.wrap n;flags={!q.flags with carry=n>65535}}in
 let cmp v=q:={!q with R.flags=R.comparison !q.a v}in
 let sub v=let old= !q.a in cmp v;a(B.wrap(old-v))in
 let parity n=n land 255|>fun n->let n=n lxor(n lsr 4)in let n=n lxor(n lsr 2)in(n lxor(n lsr 1))land 1=0 in
 let flags n ac cy={R.sign=n>=128;zero=n=0;auxiliary_carry=ac;parity=parity n;carry=cy}in
 let inc v=let n=B.wrap(v+1)in q:={!q with R.flags=flags n(v land 15=15)!q.flags.carry};n in
 let dec v=let n=B.wrap(v-1)in q:={!q with R.flags=flags n(v land 15<>0)!q.flags.carry};n in
 let add v=let old= !q.a in let n=old+v in q:={!q with R.a=B.wrap n;flags=flags(B.wrap n)((old land 15)+(v land 15)>15)(n>255)}in
 let rar()=let old= !q.a in q:={!q with R.a=(old lsr 1)lor(if !q.flags.carry then 128 else 0);flags={!q.flags with carry=old land 1<>0}}in
 let push site value=compatibility(H.Push(site+0x2200,value))in
 let pop()=let value=word(sp())in compatibility H.Pop;value in
 let call site target=
  compatibility(H.Enter(site+0x2200,target+0x2200));q:=invoke ~site:(site+0x2200)~target:(target+0x2200) !q;compatibility H.Leave in
 let psw()=let f= !q.flags in (if f.sign then 128 else 0)lor(if f.zero then 64 else 0)lor(if f.auxiliary_carry then 16 else 0)lor(if f.parity then 4 else 0)lor 2 lor(if f.carry then 1 else 0)in
 let mask()=let cy= !q.flags.carry in let n=if cy then 255 else 0 in q:={!q with R.a=n;flags=flags n(not cy)cy}in
 let store site address value=put site address(value land 255);put site(U.wrap(address+1))(value lsr 8)in
 let save site=push site(!q.a lsl 8 lor psw())in
 let restore()=bc(pop());c(!q.bc lsr 8)in
 let conjunction v=let old= !q.a in let n=old land v in q:={!q with R.a=n;flags=flags n((old lor v)land 8<>0)false}in
 let frame n=hl n;dad(sp())in
 (match operation with
 |Terminator->a(read 0x20c3);cmp 0x3b;need !q.flags.zero "01C6 nonsemicolon arm";call 0x01d4 0x784e
 |Structure->bc 5;pair 0xa863;dad !q.bc;a(read !q.hl);put 0x0b8c 0xa5d6 !q.a;hl 0xa5d5;put 0x0b92 !q.hl 1;a(read 0xa5d6);hl 0xa5d5;cmp(read !q.hl);need !q.flags.carry "0B84 nonborrow initialization arm"
 |Wrapper->call 0x013d 0x4802;c 0xfb;call 0x0142 0x80ef
 |Index->a(read 0xa8eb);a(inc !q.a);put 0x47e6 0xa8eb !q.a;c !q.a;a 0x1e;cmp(!q.bc land 255);need(not !q.flags.carry)"47E2 overflow arm"
 |Bit40->call 0x47f7 0x41a6;conjunction 0x40;sub 0x40;add 255;mask()
 |Mode_step->call 0x3563 0x421f;cmp 0;need(not !q.flags.zero)"3563 zero-high alternative";a 0
 |Advance->need(read(word 0xa861)>0)"4890 zero-length cursor record";pair 0xa861;store 0x4893 0xa863 !q.hl;pair 0xa863;e(read !q.hl);de(!q.de land 255);pair 0xa861;dad !q.de;store 0x48a0 0xa861 !q.hl;
  a(read 0xa91f);cmp 0;if !q.flags.zero then(call 0x48ab 0x41af;cmp 3;if !q.flags.zero then(call 0x48b3 0x47f7;rar();if !q.flags.carry then(hl 0xa91f;put 0x48bd !q.hl 1)));
  a(read 0xa91f);cmp 0;if not !q.flags.zero then(call 0x48c7 0x3563;hl 0xa91f;add(read !q.hl);a(dec !q.a);put 0x48cf !q.hl !q.a)
  else(call 0x48d3 0x421f;sub 0;sub 1;mask();save 0x48db;call 0x48dc 0x4227;c !q.a;a 0;sub(!q.bc land 255);mask();restore();conjunction(!q.bc land 255);rar();
   if !q.flags.carry then(bc 10;pair 0xa863;dad !q.bc;push 0x48f2 !q.hl;call 0x48f3 0x4227;e !q.a;bc(pop());call 0x48f8 0x452b;
    pair 0xa760;hl(!q.hl land 255);bc 0xa761;dad !q.hl;dad !q.bc;bc 8;push 0x4908 !q.hl;pair 0xa863;dad !q.bc;
    let old=word(sp())in compatibility(H.Exchange(0x6b0d,!q.hl));hl old;
    c(read !q.hl);hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor(!q.bc land 255));hl(pop());put 0x4912 !q.hl(!q.bc land 255);hl(U.wrap(!q.hl+1));put 0x4914 !q.hl(!q.bc lsr 8);
    pair 0xa760;hl(!q.hl land 255);bc 0xa761;dad !q.hl;dad !q.bc;push 0x491f !q.hl;pair 0xa863;let old= !q.hl in hl !q.de;de old;hl(pop());put 0x4925 !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x4927 !q.hl(!q.de lsr 8)))
 |Cursor->hl 0xa91f;put 0x4805 !q.hl 0;bc 0x1c32;de 0xa861;call 0x480d(-0x6cd);need !q.flags.carry "4802 no cursor/floor borrow";pair 0xa861;store 0x4817 0xa8e9 !q.hl;call 0x481a 0x4890;
  bc 4;pair 0xa863;dad !q.bc;a 0;put 0x4826 !q.hl !q.a;hl(U.wrap(!q.hl+1));put 0x4828 !q.hl 0;
  let rec grow()=call 0x482a 0x4227;c !q.a;a(read 0xa8eb);cmp(!q.bc land 255);if !q.flags.carry then(call 0x4835 0x47e2;pair 0xa8eb;hl(!q.hl land 255);bc 0xa8ab;dad !q.hl;dad !q.bc;a 0;put 0x4844 !q.hl !q.a;hl(U.wrap(!q.hl+1));put 0x4846 !q.hl 0;grow())in grow();
  pair 0xa8eb;hl(!q.hl land 255);bc 0xa8ab;dad !q.hl;dad !q.bc;push 0x4855 !q.hl;pair 0xa8e9;let old= !q.hl in hl !q.de;de old;hl(pop());put 0x485b !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x485d !q.hl(!q.de lsr 8);
  pair 0xa8eb;hl(!q.hl land 255);bc 0xa86d;dad !q.hl;dad !q.bc;put 0x4868 !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x486a !q.hl(!q.de lsr 8);
  let rec loop()=pair 0xa861;store 0x486e 0xa863 !q.hl;let old= !q.hl in hl !q.de;de old;hl 0x1c32;call 0x4875 0x83a3;mask();save 0x4879;call 0x487a 0x421f;sub 0x20;add 255;mask();restore();conjunction(!q.bc land 255);rar();if !q.flags.carry then(call 0x4889 0x4890;loop())in loop()
 |Driver->hl 0xa5d9;put 0x0c78 !q.hl 1;
  let rec drive()=
   a(read 0xa5d9);rar();if !q.flags.carry then(
    call 0x0c81 0x020e;rar();need !q.flags.carry "0C75 clear input gate alternative";
    call 0x0c88 0x013d;call 0x0c8b 0x45f0;pair 0xa863;store 0x0c91 0xa5da !q.hl;
    call 0x0c94 0x784e;c 0x3a;call 0x0c99 0x01af;rar();need !q.flags.carry "0C75 unmatched3A delimiter";
    c 0x9b;call 0x0ca2 0x01af;rar();need !q.flags.carry "0C75 unmatched9B delimiter";
    call 0x0ca9 0x0261;c 0x28;call 0x0cae 0x01af;rar();need(not !q.flags.carry)"0C75 matched28 alternative";
    a(read 0x2015);rar();need !q.flags.carry "0C75 clear2015 entry policy";c 0x8d;call 0x0cc1 0x80b7;
    let rec delimiter()=a(read 0x20c3);cmp 0x3b;if not !q.flags.zero then(call 0x0ccc 0x784e;delimiter())in delimiter();
    pair 0xa5da;bc !q.hl;call 0x0cd7 0x0c1b;
    a(read 0x2015);rar();need !q.flags.carry "0C75 clear2015 exit policy";c 0x8e;call 0x0ce3 0x80b7;
    call 0x0cf2 0x0146;a(read 0x20c3);cmp 0x1a;need !q.flags.zero "0C75 nonEOF continuation arm";
    hl 0xa5d9;put 0x0d06 !q.hl 0;drive())in drive()
 |Parent->push 0x0c1b !q.hl;push 0x0c1c !q.bc;pair 0xa5b5;let old= !q.hl in hl !q.de;de old;frame 2;put 0x0c25 !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x0c27 !q.hl(!q.de lsr 8);
  hl(U.wrap(!q.hl-3));e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));let old= !q.hl in hl !q.de;de old;store 0x0c2f 0xa5b5 !q.hl;
  call 0x0c32 0x01c6;call 0x0c35 0x0261;call 0x0c38 0x013d;frame 0;c(read !q.hl);hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor(!q.bc land 255));call 0x0c42 0x58bb;c 0x7d;call 0x0c47 0x2511;
  frame 0;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));let old= !q.hl in hl !q.de;de old;store 0x0c52 0xa863 !q.hl;call 0x0c55 0x0b84;
  frame 0;c(read !q.hl);hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor(!q.bc land 255));e 2;call 0x0c61 0x0a32;call 0x0c64 0x784e;
  frame 2;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));let old= !q.hl in hl !q.de;de old;store 0x0c6f 0xa5b5 !q.hl;hl(pop());hl(pop()));
 !q
