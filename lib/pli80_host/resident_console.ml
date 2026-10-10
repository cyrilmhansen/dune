[@@@warning "-4-40-41-42"]
(** Historical resident character/string/hexadecimal output. The accepted route
    excludes listing and redirected-file output; it retains every scratch read,
    write and CALL. BDOS and the signature gate are canonical callbacks. *)
module R=Recursive_mapped
module S=State
module H=Acquisition_parent
let bounds=[0x0380,0x0390;0x0390,0x03e9;0x03e9,0x03f4;0x03f4,0x0421;0x0421,0x044b;0x044b,0x0466;0x0466,0x047d;0x05f8,0x05ff;0x05ff,0x0611]
let run offset memory ~entry ~write ~compatibility ~invoke ~guard_string =
 let q=ref entry in
 let need b text=if not b then invalid_arg("resident console: "^text)in
 let read=S.read memory and word=S.word memory in
 let a v=q:={!q with R.a=v}and bc v=q:={!q with R.bc=v}and de v=q:={!q with R.de=v}and hl v=q:={!q with R.hl=v}in
 let c v=bc((!q.bc land 0xff00)lor v)in
 let pair addr=hl(word addr)in
 let put site address value=S.write memory address value;write ~site:(site+0x100) ~address ~value in
 let parity n=let n=n lxor(n lsr 4)in let n=n lxor(n lsr 2)in(n lxor(n lsr 1))land 1=0 in
 let flags n ac cy={R.sign=n>=128;zero=n=0;parity=parity n;auxiliary_carry=ac;carry=cy}in
 let cmp v=q:={!q with R.flags=R.comparison !q.a v}in
 let sub v=let old= !q.a in cmp v;a((old-v)land 255)in
 let add v=let old= !q.a in let n=old+v in q:={!q with R.a=n land 255;flags=flags(n land 255)((old land 15)+(v land 15)>15)(n>255)}in
 let ani v=let old= !q.a in let n=old land v in q:={!q with R.a=n;flags=flags n((old lor v)land 8<>0)false}in
 let rar()=let old= !q.a in q:={!q with R.a=(old lsr 1)lor(if !q.flags.carry then 128 else 0);flags={!q.flags with carry=old land 1<>0}}in
 let exchange()=let old= !q.hl in hl !q.de;de old in
 let external_call site target=compatibility(H.Enter(site+0x100,target+0x100));q:=invoke ~site:(site+0x100)~target:(target+0x100) !q;compatibility H.Leave in
 let rec call site target=compatibility(H.Enter(site+0x100,target+0x100));body target;compatibility H.Leave
 and body=function
 |0x0380->hl 0x206a;put 0x0383 !q.hl(!q.bc land 255);pair 0x206a;hl(!q.hl land 255);exchange();c 2;external_call 0x038c 0x19bb
 |0x0390->hl 0x206b;put 0x0393 !q.hl(!q.bc land 255);a(read 0x202a);rar();need(not !q.flags.carry)"listing arm unsupported";
  a(read 0x201e);rar();need(not !q.flags.carry)"redirected file arm unsupported";pair 0x206b;c(!q.hl land 255);call 0x03e5 0x0380
 |0x03e9->c 13;call 0x03eb 0x0390;c 10;call 0x03f0 0x0390
 |0x03f4->guard_string !q.bc;hl 0x206e;put 0x03f7 !q.hl(!q.bc lsr 8);hl(!q.hl-1);put 0x03f9 !q.hl(!q.bc land 255);hl 0x206c;put 0x03fd !q.hl 0;
  let rec loop remaining=
   need(remaining>0)"string terminator/index scope";
   pair 0x206c;hl(!q.hl land 255);exchange();pair 0x206d;
   let sum= !q.hl+ !q.de in q:={!q with R.hl=sum land 65535;flags={!q.flags with carry=sum>65535}};
   a(read !q.hl);put 0x040a 0x206f !q.a;cmp 0x24;
   if not !q.flags.zero then(pair 0x206f;c(!q.hl land 255);call 0x0416 0x0390;
    hl 0x206c;let old=read !q.hl in let n=(old+1)land 255 in q:={!q with R.flags=flags n(old land 15=15)!q.flags.carry};put 0x041c !q.hl n;loop(remaining-1))in loop 256
 |0x0421->need(!q.bc land 255<16)"nibble domain";hl 0x2070;put 0x0424 !q.hl(!q.bc land 255);a 9;hl 0x2070;cmp(read !q.hl);
  if !q.flags.carry then(a(read 0x2070);add 0x41;sub 10;put 0x0435 0x2070 !q.a)
  else(a(read 0x2070);add 0x30;put 0x0440 0x2070 !q.a);
  pair 0x2070;c(!q.hl land 255);call 0x0447 0x0390
 |0x044b->hl 0x2071;put 0x044e !q.hl(!q.bc land 255);a(read 0x2071);ani 0xf8;rar();rar();rar();rar();c !q.a;call 0x0459 0x0421;
  a(read 0x2071);ani 0x0f;c !q.a;call 0x0462 0x0421
 |0x0466->hl 0x2073;put 0x0469 !q.hl(!q.bc lsr 8);hl(!q.hl-1);put 0x046b !q.hl(!q.bc land 255);
  pair 0x2072;a(!q.hl lsr 8);c !q.a;call 0x0471 0x044b;
  pair 0x2072;a(!q.hl land 255);c !q.a;call 0x0479 0x044b
 |0x05f8->external_call 0x05f8 0x05b2;call 0x05fb 0x03e9
 |0x05ff->hl 0x2080;put 0x0602 !q.hl(!q.bc lsr 8);hl(!q.hl-1);put 0x0604 !q.hl(!q.bc land 255);call 0x0605 0x05f8;
  pair 0x207f;bc !q.hl;call 0x060d 0x03f4
 |_->invalid_arg"resident console entry"in
 body offset;!q
