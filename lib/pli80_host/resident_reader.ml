[@@@warning "-4-40-41-42"]
module R=Recursive_mapped
module S=State
module H=Acquisition_parent
module U=U16
module B=U8
type operation=Byte_difference|Write_record|Close|Default_dma|Pointer_tail|Memory_zero|Pointer_difference|Lookahead|Peek_cached|Read_ahead|Boundary_probe|Boundary_clear|Letter_probe|Poll|Poll_console|Set_dma|Read_record|Service_gate|Difference|Memory_difference|Read_buffer|Fetch_masked|Refill|Format_counter|Reset|Source|Filter|Store
let bounds=function Byte_difference->0x1a29,0x1a33| Write_record->0x0328,0x0338|Close->0x064c,0x0670|Default_dma->0x02fe,0x0305| Pointer_tail->0x1a35,0x1a40|Memory_zero->0x1a40,0x1a4b| Pointer_difference->0x1a33,0x1a40| Lookahead->0x1688,0x1843|Peek_cached->0x18db,0x18fa|Read_ahead->0x1843,0x18a2|Boundary_probe->0x18a2,0x18bc|Boundary_clear->0x18bc,0x18c5|Letter_probe->0x18c5,0x18db| Poll->0x05b2,0x05f8|Poll_console->0x0341,0x034a|Set_dma->0x02ee,0x02fe|Read_record->0x0318,0x0328|Service_gate->0x19bb,0x19d5|Difference->0x1a2c,0x1a33|Memory_difference->0x1a38,0x1a40| Read_buffer->0x070c,0x0788| Fetch_masked->0x0aa9,0x0ae9| Refill->0x0d40,0x0e1f|Format_counter->0x0b86,0x0be3|Reset->0x0cd9,0x0cff|Source->0x0af5,0x0b2a|Filter->0x09cb,0x0aa5|Store->0x0e1f,0x0e47
let run operation memory ~entry ~write ~compatibility ~sp ~invoke =
 let q=ref entry in
 let read=S.read memory and word=S.word memory in
 let need b text=if not b then invalid_arg("Reader_construction: "^text)in
 let a v=q:={!q with R.a=v}and bc v=q:={!q with R.bc=v}and de v=q:={!q with R.de=v}and hl v=q:={!q with R.hl=v}in
 let c v=bc((!q.bc land 0xff00)lor v)and e v=de((!q.de land 0xff00)lor v)in
 let put site address value=S.write memory address value;write ~site:(site+0x100)~address ~value in
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
 let push site value=compatibility(H.Push(site+0x100,value))in
 let pop()=let value=word(sp())in compatibility H.Pop;value in
 let call site target=
  compatibility(H.Enter(site+0x100,target+0x100));q:=invoke ~site:(site+0x100)~target:(target+0x100) !q;compatibility H.Leave in
 let logical conjunction v=let old= !q.a in let n=if conjunction then old land v else old lor v in q:={!q with R.a=n;flags=flags n(conjunction&&(old lor v)land 8<>0)false}in
 let mask()=let cy= !q.flags.carry in let n=if cy then 255 else 0 in q:={!q with R.a=n;flags=flags n(not cy)cy}in
 let psw()=let f= !q.flags in (if f.sign then 128 else 0)lor(if f.zero then 64 else 0)lor(if f.auxiliary_carry then 16 else 0)lor(if f.parity then 4 else 0)lor 2 lor(if f.carry then 1 else 0)in
 let save site=push site(!q.a lsl 8 lor psw())in
 let restore()=bc(pop());c(!q.bc lsr 8)in
 (match operation with
 |Pointer_difference|Pointer_tail->if operation=Pointer_difference then hl !q.bc;let low=read !q.hl in hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor low);a(read !q.de);sub(!q.bc land 255);hl((!q.hl land 0xff00)lor !q.a);de(U.wrap(!q.de+1));a(read !q.de);let carry=if !q.flags.carry then 1 else 0 in let v= !q.a and b= !q.bc lsr 8 in let n=B.wrap(v-b-carry)in q:={!q with R.a=n;hl=n lsl 8 lor(!q.hl land 255);flags=flags n((v land 15)>=(b land 15)+carry)(v<b+carry)}
 |Boundary_clear->hl 0x214c;put 0x18bf !q.hl 0;hl(U.wrap(!q.hl-1));put 0x18c2 !q.hl 0
 |Boundary_probe->a(read 0x214c);rar();if not !q.flags.carry then(a(read 0x214f);sub 0;sub 1;mask();hl 0x214b;logical true(read !q.hl);hl(U.wrap(!q.hl+1));put 0x18b7 !q.hl !q.a;hl(U.wrap(!q.hl-1));put 0x18b9 !q.hl 0)
 |Letter_probe->a(read 0x214a);sub 0x41;cmp 0x1a;if !q.flags.carry then a 1 else(a(read 0x214a);sub 0x3f;sub 1;mask())
 |Read_ahead->
  a(read 0x2008);cmp 0xfe;need(not !q.flags.zero)"1843 replay capacity";
  hl 0x1f08;a(read 0x1f07);cmp(read !q.hl);
  if !q.flags.carry then(a(read 0x1f07);a(inc !q.a);put 0x1861 0x1f07 !q.a;a(dec !q.a);bc !q.a;hl 0x1e8e;dad !q.bc;a(read !q.hl);put 0x186d 0x214a !q.a)
  else(call 0x1873 0x09cb;put 0x1876 0x214a !q.a;a(read 0x2008);a(inc !q.a);put 0x187d 0x2008 !q.a;a(dec !q.a);bc !q.a;hl 0x1f09;dad !q.bc;a(read 0x214a);put 0x188b !q.hl !q.a);
  a(read 0x214a);logical true 0x7f;put 0x1891 0x214a !q.a;a(read 0x214a);cmp 0x1a;need(not !q.flags.zero)"1843 EOF"
 |Peek_cached->a 0;hl 0x2008;sub(read !q.hl);mask();hl 0x2087;logical false(read !q.hl);rar();
  if !q.flags.carry then a(read 0x2089)else(hl 0x2087;put 0x18f1 !q.hl 1;call 0x18f3 0x1688;put 0x18f6 0x2089 !q.a)
 |Lookahead->
  hl 0x214f;put 0x168b !q.hl 0;hl 0x2008;put 0x1690 !q.hl 0;hl(U.wrap(!q.hl+1));put 0x1693 !q.hl 0;
  a(read 0x1f06);put 0x1698 0x1f07 !q.a;hl 0x214b;put 0x169e !q.hl 1;hl(U.wrap(!q.hl+1));put 0x16a1 !q.hl 0;hl(U.wrap(!q.hl+1));put 0x16a4 !q.hl 0;
  a(read 0x20c1);put 0x16a9 0x214a !q.a;
  let eq byte value=a(read byte);sub value;sub 1;mask()in
  let advance()=call 0x183c 0x1843 in
  let rec scan()=
   eq 0x214a 0x20;save 0x16b4;eq 0x214a 9;restore();logical false(!q.bc land 255);rar();
   if !q.flags.carry then(call 0x16c4 0x18a2;call 0x16c7 0x1843;scan())else(
    eq 0x214a 0x3d;save 0x16d5;a(read 0x214d);a(!q.a lxor 255);restore();logical true(!q.bc land 255);rar();
    if !q.flags.carry then(eq 0x214f 0;put 0x16e9 0x214d !q.a;call 0x16ec 0x18bc;call 0x16ef 0x1843;scan())else(
     eq 0x214a 0x3a;save 0x16fd;eq 0x214f 0;restore();logical true(!q.bc land 255);rar();need(not !q.flags.carry)"1688 colon route";
     a(read 0x214a);cmp 0x3b;if !q.flags.zero then a(read 0x214d)else(
      a(read 0x214a);cmp 0x1a;need(not !q.flags.zero)"1688 EOF";a(read 0x214a);cmp 0x28;
      if !q.flags.zero then(call 0x172f 0x1843;a(read 0x214f);a(inc !q.a);put 0x1736 0x214f !q.a;call 0x1739 0x18bc;scan())else(
       a(read 0x214a);cmp 0x29;if !q.flags.zero then(call 0x1747 0x1843;a(read 0x214f);a(dec !q.a);put 0x174e 0x214f !q.a;sub 0;sub 1;mask();put 0x1756 0x214b !q.a;scan())else(
        a(read 0x214a);cmp 0x27;need(not !q.flags.zero)"1688 quoted forward scan";a(read 0x214a);cmp 0x2f;need(not !q.flags.zero)"1688 slash scan";
        a(read 0x214a);cmp 0x20;if !q.flags.carry then(call 0x17f5 0x1843;scan())else(
         pair 0x214a;c(!q.hl land 255);call 0x17ff 0x0817;put 0x1802 0x214a !q.a;call 0x1805 0x18c5;rar();
         if !q.flags.carry then(a(read 0x214c);rar();if !q.flags.carry then a 0 else(hl 0x214b;put 0x1819 !q.hl 1;advance();scan()))else(
          hl 0x214c;put 0x1821 !q.hl 0;eq 0x214a 0x5f;save 0x182b;a(read 0x214a);sub 0x30;c !q.a;a 9;sub(!q.bc land 255);mask();a(!q.a lxor 255);restore();logical false(!q.bc land 255);hl(U.wrap(!q.hl-1));put 0x183b !q.hl !q.a;advance();scan())))))))in scan()
 |Memory_zero->hl !q.a;let left=word !q.de and right= !q.hl in let low=(left land 255)-(right land 255)in let borrow=if low<0 then 1 else 0 in let l=left lsr 8 and r=right lsr 8 in let high=B.wrap(l-r-borrow)in q:={!q with R.a=high;hl=high lsl 8 lor B.wrap low;de=U.wrap(!q.de+1);flags=flags high((l land 15)>=(r land 15)+borrow)(l<r+borrow)}
 |Byte_difference|Difference|Memory_difference->
  if operation=Byte_difference then de !q.a;
  let left,right=if operation<>Memory_difference then !q.de,!q.hl else word !q.de,!q.bc in
  let low=(left land 255)-(right land 255)in let borrow=if low<0 then 1 else 0 in let l=left lsr 8 and r=right lsr 8 in let high=B.wrap(l-r-borrow)in
  q:={!q with R.a=high;hl=high lsl 8 lor B.wrap low;flags=flags high((l land 15)>=(r land 15)+borrow)(l<r+borrow)};
  if operation=Memory_difference then de(U.wrap(!q.de+1))
 |Poll->call 0x05b2 0x0341;rar();need(not !q.flags.carry)"05B2 console key-present"
 |Poll_console->de 0;c 11;call 0x0346 0x19bb
 |Default_dma->bc 0x80;call 0x0301 0x02ee
 |Close->push 0x064c !q.bc;call 0x064d 0x02fe;hl 0;dad(sp());e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));c 16;call 0x0659 0x19bb;cmp 255;need(not !q.flags.zero)"064C close error";hl(pop())
 |Set_dma|Read_record|Write_record->
  let scratch,site,fn=if operation=Set_dma then 0x205f,0x02ee,26 else if operation=Read_record then 0x2063,0x0318,20 else 0x2065,0x0328,21 in
  hl(scratch+1);put(site+3)!q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put(site+5)!q.hl(!q.bc land 255);pair scratch;let old= !q.hl in hl !q.de;de old;c fn;call(site+12)0x19bb
 |Service_gate->
  push 0x19bb !q.bc;push 0x19bc !q.de;hl 0x215c;de 5;
  compatibility(H.Enter(0x1ac3,0x1b0f));
  for i=0 to 2 do a(read !q.de);cmp(read !q.hl);need !q.flags.zero "19BB BDOS signature";if i<2 then(de(U.wrap(!q.de+1));hl(U.wrap(!q.hl+1)))done;
  compatibility H.Leave;pair 0x2155;a 0xaa;cmp(read !q.hl);need !q.flags.zero "19BB guard pointer";de(pop());bc(pop());q:=invoke ~site:0x1ad4 ~target:5 !q
 |Read_buffer->
  a(read 0x2012);rar();if !q.flags.carry then a 0x1a else(
   pair 0x1d08;hl(U.wrap(!q.hl+1));put 0x071a 0x1d08(!q.hl land 255);put 0x071a 0x1d09(!q.hl lsr 8);de 0x1ff;call 0x0720 0x1a2c;
   if not !q.flags.carry then(pair 0x1d08;let old= !q.hl in hl !q.de;de old;pair 0x1d06;dad !q.de;a(read !q.hl))else(
    call 0x0730 0x05b2;hl 0;put 0x0736 0x1d08 0;put 0x0736 0x1d09 0;
    let rec records()=bc 0x200;de 0x1d08;call 0x073f 0x1a38;if !q.flags.carry then(
     pair 0x1d08;let old= !q.hl in hl !q.de;de old;pair 0x1d06;dad !q.de;bc !q.hl;call 0x074f 0x02ee;bc 0x5c;call 0x0755 0x0318;cmp 0;
     if not !q.flags.zero then(pair 0x1d08;let old= !q.hl in hl !q.de;de old;pair 0x1d06;dad !q.de;put 0x0765 !q.hl 0x1a;hl 0x200;put 0x076a 0x1d08 0;put 0x076a 0x1d09 2;records())else(
      de 0x80;pair 0x1d08;dad !q.de;put 0x0777 0x1d08(!q.hl land 255);put 0x0777 0x1d09(!q.hl lsr 8);records()))in records();
    hl 0;put 0x0780 0x1d08 0;put 0x0780 0x1d09 0;pair 0x1d06;a(read !q.hl)))
 |Fetch_masked->a(read 0x200c);rar();need(not !q.flags.carry)"0AA9 alternate source";call 0x0ada 0x070c;put 0x0add 0x2098 !q.a;a(read 0x2098);logical true 0x7f;put 0x0ae5 0x2099 !q.a
 |Reset->a(read 0x200f);cmp 0;if !q.flags.zero then(a(read 0x2028);rar();need(not !q.flags.carry)"0CD9 listing output")else(a(read 0x200f);cmp 2;if !q.flags.zero then(a(read 0x2026);rar();need(not !q.flags.carry)"0CD9 listing output"))
 |Format_counter->
  hl 0x209e;put 0x0b89 !q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put 0x0b8b !q.hl(!q.bc land 255);hl 0x209f;put 0x0b8f !q.hl 4;
  let rec loop()=a(read 0x209f);a(dec !q.a);put 0x0b95 0x209f !q.a;cmp 255;if not !q.flags.zero then(
   pair 0x209f;hl(!q.hl land 255);let old= !q.hl in hl !q.de;de old;pair 0x209d;dad !q.de;a(read !q.hl);put 0x0ba8 0x20a0 !q.a;cmp 0x20;
   if !q.flags.zero then(hl 0x20a0;put 0x0bb3 !q.hl 0x30);
   a(read 0x20a0);a(inc !q.a);pair 0x209f;hl(!q.hl land 255);let old= !q.hl in hl !q.de;de old;pair 0x209d;dad !q.de;put 0x0bc3 !q.hl !q.a;c !q.a;a 0x39;cmp(!q.bc land 255);
   if !q.flags.carry then(pair 0x209f;hl(!q.hl land 255);let old= !q.hl in hl !q.de;de old;pair 0x209d;dad !q.de;put 0x0bd5 !q.hl 0x30)else(hl 0x209f;put 0x0bdd !q.hl 0);loop())in loop()
 |Store->hl 0x20ab;put 0x0e22 !q.hl(!q.bc land 255);a(read 0x1f06);a(inc !q.a);cmp 0x78;need !q.flags.carry "0E1F full buffer";
  a(read 0x1f06);a(inc !q.a);put 0x0e30 0x1f06 !q.a;bc !q.a;hl 0x1e8e;dad !q.bc;a(read 0x20ab);put 0x0e3d !q.hl !q.a
 |Source->a(read 0x2008);cmp 0;if !q.flags.zero then(call 0x0afd 0x09cb;put 0x0b00 0x209a !q.a)else(
  pair 0x2009;hl(!q.hl land 255);bc 0x1f09;dad !q.bc;a(read !q.hl);put 0x0b10 0x209a !q.a;hl 0x2008;let n=dec(read !q.hl)in put 0x0b16 !q.hl n;hl(U.wrap(!q.hl+1));let n=inc(read !q.hl)in put 0x0b18 !q.hl n);
  a(read 0x209a);cmp 0x1a;if !q.flags.zero then(hl 0x2012;put 0x0b24 !q.hl 1);a(read 0x209a)
 |Filter->a(read 0x200e);cmp 0;need !q.flags.zero "09CB retained-byte branch";call 0x09d3 0x0aa9;
  a(read 0x200d);cmp 2;if !q.flags.zero then(a(read 0x2099);cmp 0x27;if !q.flags.zero then(hl 0x200d;put 0x09fc !q.hl 0);a(read 0x2098))else(
   a(read 0x200d);cmp 3;need(not !q.flags.zero)"09CB comment mode";a(read 0x2099);cmp 0x27;
   if !q.flags.zero then(hl 0x200d;put 0x0a37 !q.hl 2;a 0x27)else(
    a(read 0x2099);cmp 0x2f;need(not !q.flags.zero)"09CB slash lookahead";
    a(read 0x200c);rar();need(not !q.flags.carry)"09CB alternate byte source";
    a(read 0x2099);cmp 0x25;need(not !q.flags.zero)"09CB percent source";a(read 0x2098)))
 |Refill->
  hl 0x20aa;put 0x0d43 !q.hl 0;call 0x0d45 0x0cd9;hl 0x1f06;put 0x0d4b !q.hl 255;hl 0x1f08;put 0x0d50 !q.hl 0;hl(U.wrap(!q.hl-1));put 0x0d53 !q.hl 0;
  call 0x0d55 0x0af5;put 0x0d58 0x20a9 !q.a;cmp 0x1a;
  if not !q.flags.zero then(pair 0x2036;hl(U.wrap(!q.hl+1));put 0x0d64 0x2036(!q.hl land 255);put 0x0d64 0x2037(!q.hl lsr 8);bc 0x2038;call 0x0d6a 0x0b86;hl 0x203c;put 0x0d70 !q.hl 0x20;
   let rec loop()=a(read 0x20a9);sub 10;sub 1;mask();save 0x0d7a;a(read 0x20a9);sub 0x1a;sub 1;mask();restore();logical false(!q.bc land 255);rar();
    if not !q.flags.carry then(
     a(read 0x20a9);cmp 13;if !q.flags.zero then(c 0;call 0x0d94 0x0e1f)else(
      a(read 0x20a9);cmp 9;need(not !q.flags.zero)"0D40 tab expansion";a(read 0x20a9);let old= !q.a in a((old lsl 1 land 255)lor(old lsr 7));q:={!q with R.flags={!q.flags with carry=old land 128<>0}};rar();need(not !q.flags.carry)"0D40 high-bit transform");
     a(read 0x20a9);sub 0x20;mask();a(!q.a lxor 255);save 0x0ddb;a(read 0x20a9);sub 0x7f;add 255;mask();restore();logical true(!q.bc land 255);rar();
     if !q.flags.carry then(pair 0x20a9;c(!q.hl land 255);call 0x0def 0x0e1f);
     call 0x0df2 0x0af5;put 0x0df5 0x20a9 !q.a;loop())in loop();a(read 0x1f06);a(inc !q.a);put 0x0dff 0x1f08 !q.a;c 0;call 0x0e04 0x0e1f;hl 0x200a;put 0x0e0a !q.hl 1);
  a(read 0x20aa);rar();need(not !q.flags.carry)"0D40 reporting state";hl 0x1f06;put 0x0e1c !q.hl 0);
 !q
