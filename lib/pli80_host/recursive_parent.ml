[@@@warning "-4-40-41-42"]
module R=Recursive_mapped
module S=State
module H=Acquisition_parent
module U=U16
module B=U8
type operation=Acquire_item|Advance_context|Cleanup_heads|Cleanup_tables|Finish_reader|Emit_position|Reset_map|Inherited_frame|Recursive_frame|Item_wrapper|Header|Primary_fields|Secondary_fields|Secondary_wrapper|Reduce_fields|Shift_fields|Restore_index|Bracket_setup|Lookahead_finish|Publish_pair|Advance_record|Line_decrement|Parent|Line_gate|Base|Clear_state|Line_increment|Clear_fields|Initialization of Initialization_parent.operation
let bounds=function Initialization op->Initialization_parent.bounds op|Acquire_item->0x08d9,0x0a0b|Advance_context->0x086e,0x08d9|Cleanup_heads->0x4986,0x49d7|Cleanup_tables->0x4929,0x4986|Finish_reader->0x0146,0x014f|Emit_position->0x80ef,0x810b|Reset_map->0x8273,0x82ac| Inherited_frame->0x11e2,0x1328|Recursive_frame->0x0a32,0x0ba8|Item_wrapper->0x0a0b,0x0a32| Header->0x0e00,0x0fc9|Primary_fields->0x1014,0x109e|Secondary_fields->0x109e,0x1187|Secondary_wrapper->0x1187,0x11e2|Reduce_fields->0x342f,0x345e|Shift_fields->0x8152,0x8167| Restore_index->0x8179,0x8187|Bracket_setup->0x029c,0x02ca|Lookahead_finish->0x0fc9,0x1014|Publish_pair->0x0277,0x029c|Advance_record->0x02ca,0x02e9|Line_decrement->0x0266,0x026b| Parent->0x02f0,0x067c|Line_gate->0x80ca,0x80ef|Base->0x02e9,0x02f0|Clear_state->0x01d8,0x01e8|Line_increment->0x0261,0x0266|Clear_fields->0x026b,0x0277
let run operation memory ~entry ~write ~compatibility ~adjust ~sp ~invoke =
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
 let psw()=let f= !q.flags in (if f.sign then 128 else 0)lor(if f.zero then 64 else 0)lor(if f.auxiliary_carry then 16 else 0)lor(if f.parity then 4 else 0)lor 2 lor(if f.carry then 1 else 0)in
 let mask()=let cy= !q.flags.carry in let n=if cy then 255 else 0 in q:={!q with R.a=n;flags=flags n(not cy)cy}in
 let logical v=let n= !q.a lor v in q:={!q with R.a=n;flags=flags n false false}in
 let probe site byte=c byte;call site 0x01af;rar();!q.flags.carry in
 let store site address value=put site address(value land 255);put site(U.wrap(address+1))(value lsr 8)in
 let save site=push site(!q.a lsl 8 lor psw())in
 let restore()=bc(pop());c(!q.bc lsr 8)in
 let conjunction v=let old= !q.a in let n=old land v in q:={!q with R.a=n;flags=flags n((old lor v)land 8<>0)false}in
 let equality address value=a(read address);sub value;sub 1;mask()in
 let combine site fn and_op=save site;fn();restore();if and_op then conjunction(!q.bc land 255)else logical(!q.bc land 255)in
 let frame n=hl n;dad(sp())in
 (match operation with
 |Initialization op->q:=Initialization_parent.run op memory ~entry:!q ~write ~compatibility ~sp ~invoke

 |Cleanup_tables->hl 0xa921;put 0x492c !q.hl(!q.bc lsr 8);hl(U.wrap(!q.hl-1));put 0x492e !q.hl(!q.bc land 255);hl 0xa922;put 0x4932 !q.hl 0;
  let rec slots()=a 0x7f;hl 0xa922;cmp(read !q.hl);if not !q.flags.carry then(
   pair 0xa922;hl(!q.hl land 255);bc 0xa761;dad !q.hl;dad !q.bc;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));let old= !q.hl in hl !q.de;de old;store 0x494b 0xa863 !q.hl;
   let rec chain()=bc 0xa920;de 0xa863;call 0x4954(-0x6cd);
    if not !q.flags.carry then(bc 8;pair 0xa863;dad !q.bc;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));let old= !q.hl in hl !q.de;de old;store 0x4965 0xa863 !q.hl;
     pair 0xa922;hl(!q.hl land 255);bc 0xa761;dad !q.hl;dad !q.bc;let old= !q.hl in hl !q.de;de old;hl(U.wrap(!q.hl-1));c(read !q.hl);hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor(!q.bc land 255));let old= !q.hl in hl !q.de;de old;put 0x4978 !q.hl(!q.bc land 255);hl(U.wrap(!q.hl+1));put 0x497a !q.hl(!q.bc lsr 8);chain())in chain();
   hl 0xa922;let n=inc(read !q.hl)in put 0x4981 !q.hl n;if not !q.flags.zero then slots())in slots()
 |Cleanup_heads->pair 0xa8e9;bc !q.hl;call 0x498b 0x4929;
  let rec discard()=a 0;hl 0xa8eb;sub(read !q.hl);mask();save 0x4995;a(read !q.hl);a(dec !q.a);bc !q.a;hl 0xa8ab;dad !q.bc;dad !q.bc;a 0;call 0x49a2 0x83a0;logical(!q.hl land 255);sub 1;mask();restore();conjunction(!q.bc land 255);rar();if !q.flags.carry then(hl 0xa8eb;let n=dec(read !q.hl)in put 0x49b3 !q.hl n;discard())in discard();
  a 0;hl 0xa8eb;cmp(read !q.hl);if !q.flags.carry then(a(read 0xa8eb);a(dec !q.a);put 0x49c4 0xa8eb !q.a;bc !q.a;hl 0xa8ab;dad !q.bc;dad !q.bc;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));let old= !q.hl in hl !q.de;de old;store 0x49d3 0xa8e9 !q.hl)
 |Finish_reader->call 0x0146 0x4986;c 0xfc;call 0x014b 0x80ef
 |Emit_position->hl 0xae6c;put 0x80f2 !q.hl(!q.bc land 255);pair 0xae6c;c(!q.hl land 255);call 0x80f7 0x80b7;pair 0x2036;a(!q.hl land 255);c !q.a;call 0x80ff(-0x120a);pair 0x2036;a(!q.hl lsr 8);c !q.a;call 0x8107(-0x120a)
 |Reset_map->hl 0xae33;put 0x8276 !q.hl 0;
  let rec loop()=a 0x94;hl 0xae33;cmp(read !q.hl);if not !q.flags.carry then(a(read 0xae33);a(inc !q.a);pair 0xae33;hl(!q.hl land 255);bc 0xaab4;dad !q.bc;put 0x828e !q.hl !q.a;hl 0xae33;let n=inc(read !q.hl)in put 0x8292 !q.hl n;if not !q.flags.zero then loop())in loop();
  hl 0xaa1a;put 0x8299 !q.hl 0;a 0;hl(U.wrap(!q.hl+1));put 0x829e !q.hl !q.a;hl(U.wrap(!q.hl+1));put 0x82a0 !q.hl 0;put 0x82a2 0xae35 !q.a;put 0x82a5 0xae34 !q.a;put 0x82a8 0xae33 !q.a
 |Advance_context->let rec loop()=call 0x086e 0x020e;rar();if !q.flags.carry then(need(not(probe 0x0877 0x98))"086E selector98";
  if probe 0x08b0 0x8e then need(probe 0x08b9 5)"086E selector5 absent"else call 0x08c6 0x784e;
  need(not(probe 0x08cb 0x28))"086E parenthesis arm";loop())in loop()
 |Acquire_item->adjust ~site:0x2ad9 ~delta:(-1);push 0x08da !q.hl;bc((!q.bc land 255)lsl 8 lor(!q.bc land 255));push 0x08dc !q.bc;adjust ~site:0x2add ~delta:1;
  pair 0xa5ba;let old= !q.hl in hl !q.de;de old;frame 2;put 0x08e6 !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x08e8 !q.hl(!q.de lsr 8);hl 0;store 0x08ed 0xa5ba !q.hl;frame 0;a(read !q.hl);frame 1;put 0x08f8 !q.hl !q.a;
  a(read 0x20c3);cmp 2;need(not !q.flags.zero)"08D9 selector2 arm";need(not(probe 0x090f 0x28))"08D9 parenthesis arm";
  call 0x092d 0x020e;rar();need !q.flags.carry "08D9 gate-clear arm";
  frame 1;a(read !q.hl);cmp 1;need !q.flags.zero "08D9 private input not1";call 0x093e 0x02e9;hl 0xa6ca;put 0x0944 !q.hl 255;
  call 0x0971 0x5a46;pair 0xa6ca;hl(!q.hl land 255);bc 0xa6aa;dad !q.bc;push 0x097d !q.hl;frame 3;a(read !q.hl);hl(pop());put 0x0984 !q.hl !q.a;e 2;c 0;call 0x0989 0x3dd9;rar();need !q.flags.carry "08D9 state gate-clear";
  a 0;de 0xa5ba;call 0x0998(-0x6c0);logical(!q.hl land 255);need !q.flags.zero "08D9 existing base";
  pair 0xa635;store 0x09a2 0xa5ba !q.hl;pair 0xa635;store 0x09a8 0xa5bc !q.hl;frame 1;a(read !q.hl);cmp 1;need !q.flags.zero "08D9 second input not1";pair 0xa635;store 0x09b8 0xa5b8 !q.hl;
  pair 0xa5b8;store 0x09be 0xa863 !q.hl;call 0x09c1 0x41af;cmp 1;need(not !q.flags.zero)"08D9 field1 arm";pair 0xa635;store 0x09cc 0xa863 !q.hl;call 0x09cf 0x41a6;conjunction 0x20;cmp 0x20;need(not !q.flags.zero)"08D9 field20 arm";
  call 0x09df 0x784e;call 0x09e2 0x8273;call 0x09eb 0x0187;need(not(probe 0x09f0 0x28))"08D9 trailing parenthesis";call 0x09fa 0x086e;
  frame 2;e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));let old= !q.hl in hl !q.de;de old;store 0x0a05 0xa5ba !q.hl;hl(pop());hl(pop())

 |Item_wrapper->bc((!q.bc land 255)lsl 8 lor(!q.bc land 255));push 0x0a0c !q.bc;adjust ~site:0x2c0d ~delta:1;frame 0;c(read !q.hl);call 0x0a13 0x08d9;pair 0xa5bc;store 0x0a19 0xa5ba !q.hl;need(not(probe 0x0a1e 0x2c))"0A0B comma-repeat";adjust ~site:0x2c30 ~delta:1
 |Recursive_frame->
  adjust ~site:0x2c32 ~delta:(-1);push 0x0a33 !q.hl;push 0x0a34 !q.hl;de((!q.de land 255)lsl 8 lor(!q.de land 255));push 0x0a36 !q.de;adjust ~site:0x2c37 ~delta:1;push 0x0a38 !q.bc;
  let rec loop()=
   a 0;frame 3;put 0x0a3f !q.hl !q.a;hl(U.wrap(!q.hl+1));put 0x0a41 !q.hl 0;
   call 0x0a43 0x02e9;call 0x0a46(-0x825);rar();
   call 0x0a4d 0x020e;save 0x0a50;equality 0x214a 0x3a;restore();conjunction(!q.bc land 255);rar();need(not !q.flags.carry)"0A32 colon arm";
   call 0x0aad(-0x825);rar();if !q.flags.carry then(frame 3;c(read !q.hl);hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor(!q.bc land 255));call 0x0abb 0x02f0;loop())else(
   need(not(probe 0x0ac3 0x25))"0A32 percent arm";
   if probe 0x0ad2 0x8a then(
    frame 2;a(read !q.hl);cmp 2;if !q.flags.zero then(c 0xf7;call 0x0ae5 0x80b7);
    frame 2;a(read !q.hl);cmp 0;if not !q.flags.zero then call 0x0af2 0x0146;
    call 0x0af5 0x020e;rar();if !q.flags.carry then(call 0x0afc 0x45f0;frame 0;de 0xa863;call 0x0b06(-0x6cb);logical(!q.hl land 255);need !q.flags.zero "0A32 changed source pointer";call 0x0b13 0x784e);
    a(read 0x20c3);cmp 0x3b;need !q.flags.zero "0A32 trailing nonsemicolon";call 0x0b21 0x0266;for _=1 to 4 do hl(pop())done
   )else if probe 0x0b2e 0x87 then(c 1;call 0x0b37 0x0a0b;need(probe 0x0b3c 0x3b)"0A32 item missing semicolon";loop())
   else(a(read 0x20c3);cmp 0xa7;need(not !q.flags.zero)"0A32 A7 arm";a(read 0x20c3);cmp 0x9b;need(not !q.flags.zero)"0A32 9B arm";frame 3;c(read !q.hl);hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor(!q.bc land 255));call 0x0b79 0x02f0;loop()))in loop()
 |Inherited_frame->
  push 0x11e2 !q.hl;push 0x11e3 !q.hl;push 0x11e4 !q.hl;push 0x11e5 !q.hl;de((!q.de land 255)lsl 8 lor(!q.de land 255));push 0x11e7 !q.de;adjust ~site:0x33e8 ~delta:1;push 0x11e9 !q.bc;
  call 0x11ea 0x020e;rar();need !q.flags.carry "11E2 gate-clear";frame 2;c(read !q.hl);call 0x11f6 0x0e00;
  frame 2;a(read !q.hl);cmp 3;need(not !q.flags.zero)"11E2 selector3";need(probe 0x1205 0x3b)"11E2 unmatched semicolon";
  a(read 0xa5e3);frame 3;put 0x1219 !q.hl !q.a;pair 0xa5ec;let old= !q.hl in hl !q.de;de old;frame 7;put 0x1222 !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x1224 !q.hl(!q.de lsr 8);
  a(read 0xa5e5);frame 4;put 0x122c !q.hl !q.a;pair 0xa5f0;let old= !q.hl in hl !q.de;de old;frame 9;put 0x1235 !q.hl(!q.de land 255);hl(U.wrap(!q.hl+1));put 0x1237 !q.hl(!q.de lsr 8);
  a(read 0xa5e2);frame 5;put 0x123f !q.hl !q.a;a(read 0xa5e6);hl(U.wrap(!q.hl+1));put 0x1244 !q.hl !q.a;frame 2;a(read !q.hl);cmp 3;need(not !q.flags.zero)"11E2 selector3 second";
  frame 0;c(read !q.hl);hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor(!q.bc land 255));frame 2;e(read !q.hl);call 0x1268 0x0a32;
  frame 4;a(read !q.hl);cmp 0;need(not !q.flags.zero)"11E2 zero-field route";
  frame 7;c(read !q.hl);hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor(!q.bc land 255));call 0x127c 0x58bb;frame 7;c(read !q.hl);hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor(!q.bc land 255));call 0x1286 0x590e;
  frame 4;a(read !q.hl);cmp 5;need !q.flags.zero "11E2 non5-field route";call 0x1293 0x0d94;frame 4;a(read !q.hl);cmp 4;need(not !q.flags.zero)"11E2 field4 route";
  call 0x12b0 0x3304;a(read 0xa62c);put 0x12b6 0xa62b !q.a;a(read 0xa62f);put 0x12bc 0xa62e !q.a;call 0x12bf 0x2308;add 0x1c;c !q.a;call 0x12c5 0x2511;call 0x12c8 0x33d6;call 0x12cb 0x239a;add 11;c !q.a;call 0x12d1 0x2511;c 0xfa;call 0x12fe 0x2511;
  frame 2;a(read !q.hl);cmp 3;need(not !q.flags.zero)"11E2 final selector3";need(probe 0x1318 0x3b)"11E2 final missing semicolon";frame 11;adjust ~site:0x3526 ~delta:11

 |Shift_fields->hl 0xae34;a(read 0xae35);sub(read !q.hl);put 0x8159 0xae6f !q.a;pair 0xae6f;c(!q.hl land 255);call 0x8160 0x810b;a(read 0xae6f)
 |Reduce_fields->call 0x342f 0x3262;hl 0xa628;put 0x3435 !q.hl 0x24;hl 0xa634;put 0x343a !q.hl 2;call 0x343c 0x2c53;
  a(read 0xa62a);sub 0x24;add 255;mask();save 0x3447;a(read 0xa62a);sub 0x25;add 255;mask();restore();conjunction(!q.bc land 255);rar();need(not !q.flags.carry)"342F unequal selector arm"
 |Primary_fields->hl 0xa5e3;put 0x1017 !q.hl 2;call 0x1019 0x61b6;a 0x31;hl 0xa628;sub(read !q.hl);mask();combine 0x1023(fun()->a(read 0xa631);sub 0;add 255;mask())false;rar();need(not !q.flags.carry)"1014 selector31 arm";
  pair 0xae32;c(!q.hl land 255);call 0x103d 0x7b7a;hl 0xae32;cmp(read !q.hl);if !q.flags.zero then(hl 0xa5e3;put 0x104a !q.hl 1);
  pair 0xa6cb;hl(U.wrap(!q.hl+2));e(read !q.hl);hl(U.wrap(!q.hl+1));de(read !q.hl lsl 8 lor(!q.de land 255));let old= !q.hl in hl !q.de;de old;store 0x1055 0xa5ec !q.hl;
  List.iter(fun(source,site,dest)->a(read source);put site dest !q.a)[0xa628,0x105b,0xa5e7;0xa62b,0x1061,0xa5e8;0xa62e,0x1067,0xa5e9];pair 0xa635;store 0x106d 0xa637 !q.hl;a(read 0xa631);put 0x1073 0xa632 !q.a;
  need(probe 0x1078 0x3d)"1014 missing equals";call 0x1082 0x6639;pair 0xa635;store 0x1088 0xa639 !q.hl;a(read 0xa631);put 0x108e 0xa633 !q.a;call 0x1091 0x33d6;call 0x1094 0x239a;add 11;c !q.a;call 0x109a 0x2511
 |Secondary_fields->hl 0xa5f5;put 0x10a1 !q.hl 2;call 0x10a3 0x8152;put 0x10a6 0xa5f6 !q.a;call 0x10a9 0x6639;pair 0xa5f6;c(!q.hl land 255);call 0x10b0 0x8179;pair 0xa63b;store 0x10b6 0xa5ea !q.hl;call 0x10b9 0x3262;
  equality 0xa62a 2;combine 0x10c4(fun()->equality 0xa62a 3)false;combine 0x10d0(fun()->equality 0xa62a 4)false;rar();need !q.flags.carry "109E selectors outside2..4";
  pair 0xae32;c(!q.hl land 255);call 0x10e4 0x7b7a;save 0x10e7;a(read 0xae32);a(dec !q.a);restore();cmp(!q.bc land 255);if !q.flags.zero then(hl 0xa5f5;put 0x10f5 !q.hl 3);
  hl 0xa634;put 0x1138 !q.hl 2;List.iter(fun(source,site,dest)->a(read source);put site dest !q.a)[0xa5e7,0x113d,0xa628;0xa5e8,0x1143,0xa62b;0xa5e9,0x1149,0xa62e];hl 0xa631;put 0x114f !q.hl 0;call 0x1151 0x2dc3;
  a(read 0xa5f5);sub 2;add 255;mask();save 0x115c;pair 0xae32;c(!q.hl land 255);call 0x1161 0x7b7a;save 0x1164;a(read 0xae32);a(dec !q.a);restore();sub(!q.bc land 255);sub 1;mask();restore();conjunction(!q.bc land 255);rar();need !q.flags.carry "109E second postcheck clear";c 2;call 0x1178 0x81f1;a(read 0xa5f5)
 |Secondary_wrapper->call 0x1187 0x109e;put 0x118a 0xa5e4 !q.a;pair 0xa5ea;store 0x1190 0xa5ee !q.hl;a(read 0xa5e4);cmp 2;need(not !q.flags.zero)"1187 selector2 arm"
 |Header->hl 0xa5f2;put 0x0e03 !q.hl(!q.bc land 255);a(read 0xa5f2);cmp 3;if not !q.flags.zero then call 0x0e0c 0x80b1;
  hl 0xa5e1;put 0x0e12 !q.hl 0;hl 0xa5e3;put 0x0e17 !q.hl 0;hl(U.wrap(!q.hl-1));put 0x0e1a !q.hl 0;hl 0xa5e4;put 0x0e1f !q.hl 0;hl(U.wrap(!q.hl+1));put 0x0e22 !q.hl 0;
  call 0x0e24(-0x825);save 0x0e27;a(read 0x20c3);sub 0xb7;add 255;mask();restore();logical(!q.bc land 255);combine 0x0e33(fun()->a(read 0x214a);sub 0x3b;add 255;mask())false;rar();
  if !q.flags.carry then(call 0x0e43 0x1014;need(probe 0x0e48 0xb5)"0E00 no B5";call 0x0e4f 0x1187;need(not(probe 0x0e54 0xb6))"0E00 B6 arm");
  call 0x0e90 0x8152;put 0x0e93 0xa5f3 !q.a;a(read 0xae35);put 0x0e99 0xa5f4 !q.a;a(read 0xa5e4);cmp 0;need(not !q.flags.zero)"0E00 zero field arm";
  a(read 0xa5e5);cmp 0;if !q.flags.zero then(hl 0xa5e5;put 0x0eaf !q.hl 5);
  pair 0xa5ec;bc !q.hl;call 0x0eb6 0x590e;pair 0xa5ee;bc !q.hl;call 0x0ebe 0x590e;a(read 0xa5e4);cmp 4;need(not !q.flags.zero)"0E00 field4 arm";
  call 0x0ecc 0x3304;equality 0xa5e5 3;combine 0x0ed7(fun()->equality 0xa5e5 5)false;rar();need !q.flags.carry "0E00 other field5";
  call 0x0ee7 0x239a;add 0x39;c !q.a;call 0x0eed 0x2511;
  hl 0xa628;put 0x0f5a !q.hl 0x24;hl 0xa62b;put 0x0f5f !q.hl 1;hl 0xa62e;put 0x0f64 !q.hl 0;c 0;call 0x0f68 0x240a;call 0x0f6b 0x0fc9;pair 0xa5f3;c(!q.hl land 255);call 0x0f72 0x8179;
  equality 0xa5e1 0;combine 0x0f7d(fun()->equality 0xa5e4 0)true;rar();need(not !q.flags.carry)"0E00 zero conjunction arm";
  a(read 0xa5e1);sub 0;add 255;mask();combine 0x0f9d(fun()->a(read 0xa5e4);sub 0;add 255;mask())true;rar();need(not !q.flags.carry)"0E00 nonzero conjunction arm";
  c 0xa8;call 0x0fb7 0x8048;pair 0xa5f4;c(!q.hl land 255);e 1;call 0x0fc0 0x7ed7;c 0x6a;call 0x0fc5 0x2511

 |Restore_index->hl 0xae71;put 0x817c !q.hl(!q.bc land 255);a(read 0xae34);hl 0xae71;sub(read !q.hl);put 0x8184 0xae34 !q.a
 |Line_decrement->hl 0x203d;let n=dec(read !q.hl)in put 0x0269 !q.hl n
 |Bracket_setup->hl 0xa933;put 0x029f !q.hl 0;call 0x02a1 0x61b6;pair 0xa933;c(!q.hl land 255);call 0x02a8 0x8179;pair 0xa635;store 0x02ae 0xa5b2 !q.hl;a(read 0xa631);put 0x02b4 0xa5b4 !q.a;need(probe 0x02b9 0x3d)"029C absent equals";call 0x02c0 0x0277
 |Publish_pair->hl 0;store 0x027a 0xa635 !q.hl;call 0x027d 0x6639;pair 0xa635;store 0x0283 0xa639 !q.hl;a(read 0xa631);put 0x0289 0xa633 !q.a;pair 0xa5b2;store 0x028f 0xa637 !q.hl;a(read 0xa5b4);put 0x0295 0xa632 !q.a;call 0x0298 0x33d6
 |Advance_record->call 0x02ca 0x029c;call 0x02cd 0x01e8;call 0x02d0 0x239a;add 0x0b;c !q.a;call 0x02d6 0x256c;need(probe 0x02db 0x3b)"02CA unmatched semicolon";call 0x02e5 0x026b
 |Lookahead_finish->hl 0xa5e1;put 0x0fcc !q.hl 0;call 0x0fce(-0x825);rar();need(not !q.flags.carry)"0FC9 cached-set branch";
  a(read 0x20c3);sub 0xb7;sub 1;mask();save 0x0fdd;a(read 0x214a);sub 0x3b;sub 1;mask();restore();conjunction(!q.bc land 255);rar();need(not !q.flags.carry)"0FC9 combined branch"

 |Base->hl 0xa66a;put 0x02ec 0xa6cb(!q.hl land 255);put 0x02ec 0xa6cc(!q.hl lsr 8)
 |Clear_state->a(read 0x2010);rar();need(not !q.flags.carry)"01D8 set-bit route";hl 0x2010;put 0x01e5 !q.hl 0
 |Line_increment->hl 0x203d;let n=inc(read !q.hl)in put 0x0264 !q.hl n
 |Clear_fields->hl 0xa631;put 0x026e !q.hl 0;hl(U.wrap(!q.hl+1));put 0x0271 !q.hl 0;hl(U.wrap(!q.hl+1));put 0x0274 !q.hl 0
 |Line_gate->a(read 0xaa1a);rar();need(not !q.flags.carry)"80CA mode-set";bc 0x2036;de 0xaa1b;call 0x80d8 (-0x6cd);a(!q.a lor(!q.hl land 255));q:={!q with R.flags=flags !q.a false false};
  if not !q.flags.zero then(pair 0x2036;put 0x80e2 0xaa1b(!q.hl land 255);put 0x80e2 0xaa1c(!q.hl lsr 8);let old= !q.hl in hl !q.de;de old;c 0;call 0x80e8 0x7e5f);
  call 0x80eb 0x7d53
 |Parent->
  push 0x02f0 !q.bc;call 0x02f1 0x80ca;call 0x02f4 0x02e9;hl 0xa6ca;put 0x02fa !q.hl 0;call 0x02fc (-0x825);rar();
  if !q.flags.carry then call 0x0303 0x02ca else(
   need(not(probe 0x030b 0x3b))"02F0 initial semicolon arm";
   a(read 0x20c3);sub 0x83;sub 1;mask();push 0x031d(!q.a lsl 8 lor psw());
   a(read 0x20c3);sub 0x97;sub 1;mask();bc(pop());c(!q.bc lsr 8);logical(!q.bc land 255);rar();need(not !q.flags.carry)"02F0 83/97 arm";
   need(not(probe 0x0394 0x93))"02F0 93 arm";
   if probe 0x03af 0x82 then(
    call 0x03b6 0x6639;call 0x03b9 0x342f;c 0x6c;call 0x03be 0x80b7;
    need(probe 0x03c3 0xb4)"02F0 missing B4";bc 0;call 0x03cd 0x02f0;call 0x03d0 (-0x825);rar();
    if not !q.flags.carry then(
     if probe 0x03d9 0xb3 then(c 0xf8;call 0x03e2 0x80b7;bc 0;call 0x03e8 0x02f0));
    c 0xf9;call 0x03f3 0x80b7
   )else if probe 0x03fb 0x81 then(
    call 0x0402 0x0261;need(not(probe 0x0407 0x3b))"02F0 81 semicolon arm";call 0x0429 (-0x825);rar();need(not !q.flags.carry)"02F0 81 cached-set";
    call 0x044e 0x020e;rar();need !q.flags.carry "02F0 81 gate-clear";
    hl 0;dad(sp());c(read !q.hl);hl(U.wrap(!q.hl+1));bc(read !q.hl lsl 8 lor(!q.bc land 255));e 0;call 0x045e 0x11e2
   )else(
    List.iter(fun(site,byte)->need(not(probe site byte))(Printf.sprintf"02F0 unsupported %02X"byte))[0x046f,0xa8;0x04f6,0x9f;0x053b,0x9d;0x0558,0xb0;0x0613,0x96];call 0x0674 0x2006));
  call 0x0677 0x01d8;hl(pop()));
 !q
