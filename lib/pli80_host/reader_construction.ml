[@@@warning "-4-40-41-42"]
(** Historical reader/construction state operations. Child algorithms are supplied
    by the canonical composition; no instruction interpreter or captured states. *)
module R=Recursive_mapped
module S=State
module H=Acquisition_parent
module U=U16
module B=U8
type operation=Map_rotate|Mode|Descriptor_marker|Descriptor_copy|Descriptor_sort|Require_close|False_probe|Descriptor_mask|Descriptor_add|Shift_right|Bit_union|Shift_left|Field_setup|Mode_finish|Range_finish|Construction_start|Descriptor_build|Reader_prefix|Field_literal|Reader_parent|Reader_entry|Select_structure|Publish_structure|Reader_setup
let bounds=function Reader_setup->0x2006,0x20a6| Reader_entry->0x1c07,0x1d13|Select_structure->0x4a26,0x4a72|Publish_structure->0x58bb,0x590e| Construction_start->0x1ba8,0x1bbf|Descriptor_build->0x1bbf,0x1be8|Reader_prefix->0x1d13,0x1d37|Field_literal->0x0d94,0x0d9d|Reader_parent->0x1afd,0x1b9e| Descriptor_mask->0x14d4,0x14e4|Descriptor_add->0x14e4,0x1510|Shift_right->0x8386,0x8396|Bit_union->0x834f,0x8357|Shift_left->0x8380,0x8386|Field_setup->0x0d6e,0x0d94|Mode_finish->0x140d,0x1421|Range_finish->0x8167,0x8179| Map_rotate->0x7ed7,0x7f4f|Mode->0x8268,0x8273|Descriptor_marker->0x13e3,0x140d|Descriptor_copy->0x14c8,0x14d4|Descriptor_sort->0x1421,0x14c8|Require_close->0x156d,0x157a|False_probe->0x1be8,0x1c07
let run operation memory ~entry ~write ~compatibility ~sp ~invoke =
 let q=ref entry in
 let read=S.read memory and word=S.word memory in
 let need b text=if not b then invalid_arg("Reader_construction: "^text)in
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
 let table_index base=let address= !q.hl in need(address>=base&&address<0xa606)"descriptor/scratch alias"in
 let copy()=a(read 0xa610);a(dec !q.a);c !q.a;call 0x14cd 0x7b7a;put 0x14d0 0xa60f !q.a in
 let map_rotate()=
  hl 0xae59;put 0x7eda !q.hl(!q.de land 255);hl(U.wrap(!q.hl-1));put 0x7edc !q.hl(!q.bc land 255);
  hl 0xae58;a(read 0xae35);sub(read !q.hl);put 0x7ee4 0xae5c !q.a;
  hl 0xae5a;put 0x7eea !q.hl 1;
  let rec outer()=
   a(read 0xae59);hl 0xae5a;cmp(read !q.hl);
   if not !q.flags.carry then(
    a(read 0xae35);a(dec !q.a);bc !q.a;hl 0xaa1f;dad !q.bc;a(read !q.hl);put 0x7f02 0xae5f !q.a;
    hl 0xae5b;put 0x7f08 !q.hl 2;
    let rec inner()=
     a(read 0xae5c);hl 0xae5b;cmp(read !q.hl);
     if not !q.flags.carry then(
      hl 0xae5b;a(read 0xae35);sub(read !q.hl);put 0x7f1b 0xae5d !q.a;
      a(inc !q.a);put 0x7f1f 0xae5e !q.a;
      pair 0xae5d;hl(!q.hl land 255);bc 0xaa1f;dad !q.bc;push 0x7f2b !q.hl;
      hl !q.a;dad !q.bc;de(pop());a(read !q.de);put 0x7f32 !q.hl !q.a;
      hl 0xae5b;let n=inc(read !q.hl)in put 0x7f36 !q.hl n;if n<>0 then inner())in inner();
    pair 0xae58;hl(!q.hl land 255);bc 0xaa1f;dad !q.bc;a(read 0xae5f);put 0x7f46 !q.hl !q.a;
    hl 0xae5a;let n=inc(read !q.hl)in put 0x7f4a !q.hl n;if n<>0 then outer())in outer()in
 let sort()=
  a(read 0xae35);put 0x1424 0xa611 !q.a;hl 0xa609;put 0x142a !q.hl 1;
  let rec pass()=
   a(read 0xa609);rar();if !q.flags.carry then(
    hl 0xa609;put 0x1436 !q.hl 0;a(read 0xae35);put 0x143b 0xa610 !q.a;
    (* Each copy computes the boundary afresh through the canonical balance scan. *)
    compatibility(H.Enter(0x363e,0x36c8));copy();compatibility H.Leave;
    hl 0xa60c;put 0x1444 !q.hl 1;
    let rec adjacent()=
     a(read 0xa606);hl 0xa60c;cmp(read !q.hl);
     if not !q.flags.carry then(
      hl 0xa60c;a(read 0xa606);sub(read !q.hl);hl(U.wrap(!q.hl+1));put 0x1458 !q.hl !q.a;bc !q.a;
      hl 0xa5fe;dad !q.bc;table_index 0xa5fe;a(read !q.hl);put 0x1461 0xa60a !q.a;push 0x1464 !q.hl;
      hl 0xa5ff;dad !q.bc;table_index 0xa5fe;a(read !q.hl);put 0x146a 0xa60b !q.a;hl(pop());cmp(read !q.hl);
      if !q.flags.carry then(
       hl 0xa609;put 0x1475 !q.hl 1;pair 0xa60d;hl(!q.hl land 255);bc 0xa5fe;dad !q.bc;
       a(read 0xa60b);put 0x1483 !q.hl !q.a;pair 0xa60d;hl(!q.hl land 255);bc(U.wrap(!q.bc+1));dad !q.bc;
       a(read 0xa60a);put 0x148e !q.hl !q.a;hl 0xa610;a(read 0xae35);sub(read !q.hl);put 0x1496 0xa60e !q.a;
       hl(U.wrap(!q.hl-1));c(read !q.hl);e !q.a;call 0x149c 0x7ed7;
       a(read 0xa60e);hl 0xa60f;add(read !q.hl);hl(U.wrap(!q.hl+1));put 0x14a7 !q.hl !q.a);
      a(read 0xa610);put 0x14ab 0xae35 !q.a;a(read 0xa60f);put 0x14b1 0xa610 !q.a;
      compatibility(H.Enter(0x36b4,0x36c8));copy();compatibility H.Leave;
      hl 0xa60c;let n=inc(read !q.hl)in put 0x14ba !q.hl n;if n<>0 then adjacent())in adjacent();
    a(read 0xa611);put 0x14c1 0xae35 !q.a;pass())in pass()in
 (match operation with
 |Construction_start->bc 0;call 0x1bab 0x7ff3;a(read 0xae32);put 0x1bb1 0xa620 !q.a;c 0xa1;call 0x1bb6 0x80b7;c 1;call 0x1bbb 0x13e3
 |Field_literal->e 5;bc 1;call 0x0d99 0x0d6e
 |Descriptor_build->a(read 0xa61e);rar();need(not !q.flags.carry)"1BBF state-bit alternative";call 0x1bce 0x0d94;call 0x1bd1 0x1ba8;pair 0xa620;c(!q.hl land 255);pair 0xa5fa;let old= !q.hl in hl !q.de;de old;call 0x1bdc 0x7af0;call 0x1bdf 0x1421;c 0;call 0x1be4 0x140d
 |Reader_prefix->hl 0x210;put 0x1d16 0xa5fa(!q.hl land 255);put 0x1d16 0xa5fb(!q.hl lsr 8);a(read 0xa621);cmp 0;need(not !q.flags.zero)"1D13 zero mode";c 6;call 0x1d2b 0x14e4;c 1;call 0x1d30 0x14e4;call 0x1d33 0x1bbf
 |Reader_setup|Reader_entry|Select_structure|Publish_structure|Reader_parent->invalid_arg "Reader_construction: frame operation must use canonical family planner"
  |Shift_right->
  de(word !q.hl);hl(U.wrap(!q.hl+1));let pointer= !q.hl in hl !q.de;de pointer;
  let rec loop()=a(!q.hl lsr 8);q:={!q with R.flags=flags !q.a false false};rar();hl(!q.a lsl 8 lor(!q.hl land 255));
   a(!q.hl land 255);rar();hl((!q.hl land 0xff00)lor !q.a);let n=dec(!q.bc land 255)in c n;if n<>0 then loop()in loop()
 |Shift_left->let rec loop()=dad !q.hl;let n=dec(!q.bc land 255)in c n;if n<>0 then loop()in loop()
 |Bit_union->
  a(read !q.de);a(!q.a lor(!q.hl land 255));q:={!q with R.flags=flags !q.a false false};hl((!q.hl land 0xff00)lor !q.a);
  de(U.wrap(!q.de+1));a(read !q.de);a(!q.a lor(!q.hl lsr 8));q:={!q with R.flags=flags !q.a false false};hl(!q.a lsl 8 lor(!q.hl land 255))
 |Descriptor_mask->hl 0xa612;put 0x14d7 !q.hl(!q.bc land 255);pair 0xa612;c(!q.hl land 255);hl 0xa5fa;call 0x14df 0x8386;a(!q.hl land 255)
 |Descriptor_add->
  hl 0xa613;put 0x14e7 !q.hl(!q.bc land 255);pair 0xa613;c(!q.hl land 255);call 0x14ec 0x14d4;rar();need(not !q.flags.carry)"14E4 existing descriptor arm";
  hl 0xa5f9;let n=inc(read !q.hl)in put 0x14f9 !q.hl n;pair 0xa613;c(!q.hl land 255);hl 1;call 0x1501 0x8380;
  de 0xa5fa;call 0x1507 0x834f;let old= !q.hl in hl !q.de;de old;hl(U.wrap(!q.hl-1));put 0x150c !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x150e !q.hl(!q.de lsr 8)
 |Field_setup->
  hl 0xa5e0;put 0x0d71 !q.hl(!q.de land 255);hl(U.wrap(!q.hl-1));put 0x0d73 !q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put 0x0d75 !q.hl(!q.bc land 255);
  pair 0xa5de;bc !q.hl;call 0x0d7b 0x7ff3;hl 0xa628;put 0x0d81 !q.hl 0x15;a(read 0xa5e0);put 0x0d86 0xa62b !q.a;hl 0xa62e;put 0x0d8c !q.hl 0;c 0x17;call 0x0d90 0x2511
 |Mode_finish->hl 0xa608;put 0x1410 !q.hl(!q.bc land 255);c 0;call 0x1413 0x8268;pair 0xa608;c(!q.hl land 255);call 0x141a 0x8167;call 0x141d 0x80b1
 |Range_finish->hl 0xae70;put 0x816a !q.hl(!q.bc land 255);call 0x816b 0x7d53;hl 0xae70;a(read 0xae34);sub(read !q.hl);put 0x8175 0xae34 !q.a
 |Map_rotate->map_rotate()
 |Descriptor_sort->sort()
 |Descriptor_copy->copy()
 |Mode->hl 0xae79;put 0x826b !q.hl(!q.bc land 255);a(read 0xae79);put 0x826f 0xaa1a !q.a
 |Descriptor_marker->
  hl 0xa607;put 0x13e6 !q.hl(!q.bc land 255);pair 0xa606;hl(!q.hl land 255);bc 0xa5fe;dad !q.bc;
  table_index 0xa5fe;a(read 0xa607);put 0x13f3 !q.hl !q.a;a(read 0xa606);cmp 7;
  need !q.flags.carry "13E3 counter saturation arm";
  a(read 0xa606);a(inc !q.a);put 0x1400 0xa606 !q.a;bc !q.a;hl 0xa5fe;dad !q.bc;table_index 0xa5fe;put 0x140a !q.hl 255
 |Require_close->c 0x29;call 0x156f 0x01af;rar();need !q.flags.carry "156D unmatched delimiter"
 |False_probe->c 0x95;call 0x1bea 0x01af;rar();need(not !q.flags.carry)"1BE8 matched alternative";a 0);
 !q
