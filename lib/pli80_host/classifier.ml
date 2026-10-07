[@@@warning "-4-40-41-42"]
(** Bounded historical +239A/+2355 classifier family. *)
module R=Recursive_mapped
module S=State
module U=U16
module B=U8
type operation=Wrapper|Indexed|Interval|Predicate|Selected
let run ?(operation=Wrapper) memory ~entry ~write ~call ~push ~pop =
 let q=ref entry in
 let need b text=if not b then invalid_arg("Classifier: "^text)in
 let read=S.read memory and word=S.word memory in
 let put site address value=S.write memory address value;write ~site ~address ~value in
 let pair address=q:={!q with R.hl=word address}in
 let a n=q:={!q with R.a=n}and bc n=q:={!q with R.bc=n}and hl n=q:={!q with R.hl=n}in
 let c n=q:={!q with R.bc=(!q.bc land 0xff00)lor n}in
 let parity n=let n=n lxor(n lsr 4)in let n=n lxor(n lsr 2)in (n lxor(n lsr 1))land 1=0 in
 let flags n ac cy={R.sign=n>=128;zero=n=0;parity=parity n;auxiliary_carry=ac;carry=cy}in
 let cmp n=q:={!q with R.flags=R.comparison !q.a n}in
 let sub n=let old= !q.a in cmp n;a(B.wrap(old-n))in
 let add n=let old= !q.a in let sum=old+n in let v=B.wrap sum in q:={!q with R.a=v;flags=flags v((old land 15)+(n land 15)>15)(sum>255)}in
 let mask()=let cy= !q.flags.carry in let v=if cy then 255 else 0 in q:={!q with R.a=v;flags=flags v(not cy)cy}in
 let logical and_op n=let v=if and_op then !q.a land n else !q.a lor n in q:={!q with R.a=v;flags=flags v and_op false}in
 let rar()=let old= !q.a in q:={!q with R.a=(old lsr 1)lor(if !q.flags.carry then 128 else 0);flags={!q.flags with carry=old land 1<>0}}in
 let dad n=let sum= !q.hl+n in q:={!q with R.hl=U.wrap sum;flags={!q.flags with carry=sum>65535}}in
 let inc v=let n=B.wrap(v+1)in q:={!q with R.flags=flags n(v land 15=15)!q.flags.carry};n in
 let psw()=let f= !q.flags in (if f.sign then 128 else 0)lor(if f.zero then 64 else 0)lor(if f.auxiliary_carry then 16 else 0)lor(if f.parity then 4 else 0)lor 2 lor(if f.carry then 1 else 0)in
 let save_mask site=let v= !q.a lsl 8 lor psw()in push site v;v in
 let restore_mask v=pop();bc v;c(v lsr 8)in
 let overlay site=site+0x2200 in
 let call1 site target f=call(overlay site)(overlay target)f in
 (* Existing classifier family, kept as independent scratch/flag channels. *)
 let predicate02()=
  hl 0xa645;put(overlay 0x213f)!q.hl(!q.bc land 255);
  let rec tests=function []->a 0|k::ks->a(read 0xa645);cmp k;if !q.flags.zero then(need(k=2)"unvalidated classifier arm";a 1)else tests ks in
  tests[11;12;13;2;3;4]in
 let interval_predicate()=
  hl 0xa647;put(overlay 0x21b0)!q.hl(!q.bc land 255);a(read 0xa647);sub 0x30;add 255;mask();let carrier=save_mask(overlay 0x21b9)in
  a 0x31;hl 0xa647;sub(read !q.hl);mask();a(!q.a lxor 255);restore_mask carrier;logical true(!q.bc land 255);rar();
  if !q.flags.carry then a 1 else(pair 0xa647;c(!q.hl land 255);call1 0x21d0 0x213c predicate02) in
 let selected()=
  hl 0xa64b;put(overlay 0x22ce)!q.hl(!q.bc land 255);
  pair 0xa64b;hl(!q.hl land 255);bc 0xa628;dad !q.bc;a(read !q.hl);cmp 0x15;
  if !q.flags.zero then a 2 else(
   List.iter(fun k->pair 0xa64b;hl(!q.hl land 255);bc 0xa628;dad !q.bc;a(read !q.hl);cmp k;need(not !q.flags.zero)"classifier16/19")[0x16;0x19];a 2)in
 let indexed()=
   hl 0xa64d;put(overlay 0x2358)!q.hl(!q.bc land 255);pair 0xa64d;hl(!q.hl land 255);bc 0xa628;dad !q.bc;c(read !q.hl);
   (* Selector05 takes the established false predicate route as well. *)
   let selector=read !q.hl in
   ignore selector;call1 0x2363 0x21ad interval_predicate;
   rar();if not !q.flags.carry then a 5 else(
    pair 0xa64d;hl(!q.hl land 255);bc 0xa628;dad !q.bc;a(read !q.hl);cmp 0x31;if !q.flags.zero then a 6 else(
    pair 0xa64d;hl(!q.hl land 255);bc 0xa628;dad !q.bc;a(read !q.hl);cmp 0x2a;need(not !q.flags.zero)"selector2A";
    pair 0xa64d;c(!q.hl land 255);call1 0x2395 0x230e(fun()->
     hl 0xa64c;put(overlay 0x2311)!q.hl(!q.bc land 255);pair 0xa64c;hl(!q.hl land 255);bc 0xa628;dad !q.bc;
     a(read !q.hl);sub 0x24;sub 1;mask();let carrier=save_mask(overlay 0x2321)in
     a(read !q.hl);sub 0x25;sub 1;mask();restore_mask carrier;logical false(!q.bc land 255);rar();need(not !q.flags.carry)"classifier24/25";
     pair 0xa64c;hl(!q.hl land 255);bc 0xa628;dad !q.bc;a(read !q.hl);cmp 0x28;if !q.flags.zero then a 1 else(
     pair 0xa64c;c(!q.hl land 255);call1 0x2348 0x22cb(fun()->
      selected());
     a(inc !q.a);a(inc !q.a)))))in
 (match operation with Wrapper->c 0;call1 0x239c 0x2355 indexed|Indexed->indexed()|Interval->interval_predicate()|Predicate->predicate02()|Selected->selected()); !q
