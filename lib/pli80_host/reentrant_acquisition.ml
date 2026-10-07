[@@@warning "-4-40-41-42"]
(** Historical +6223 dispatcher and local +620C/+61A4 composition.
    Substantial acquisition is supplied as an internal host operation. A child
    rejection propagates through the enclosing staged root; there is no guest
    fallback, snapshot selection or semantic recursion guard here. *)
module R=Recursive_mapped
module S=State
module U=U16
module B=U8
module H=Acquisition_parent

type child=Acquisition_parent|Acquisition_frame|Saved_input|Attribute_dispatch
type route=Route_b|Route_a_early|Route_a_processing
type result={route:route;entry:R.returned;predicate:int;rotated_predicate:int;
 local_predicate:int option;rotated_local_predicate:int option;returned:R.returned}
let name=function Route_b->"B_5929_2511"|Route_a_early->"A_early"|Route_a_processing->"A_01E8_256C"
let run memory ~entry ~write ~compatibility ~child =
 B.check entry.R.a;List.iter U.check[entry.bc;entry.de;entry.hl];
 let q=ref entry in
 let read=S.read memory in
 let put site address value=S.write memory address value;write ~site ~address ~value in
 let a v=q:={!q with R.a=v}in
 let c v=q:={!q with R.bc=(!q.bc land 0xff00)lor v}in
 let parity n=let n=n lxor(n lsr 4)in let n=n lxor(n lsr 2)in(n lxor(n lsr 1))land 1=0 in
 let flags n ac cy={R.sign=n land 128<>0;zero=n=0;parity=parity n;auxiliary_carry=ac;carry=cy}in
 let sub v=let old= !q.a in q:={!q with R.a=B.wrap(old-v);flags=R.comparison old v}in
 let self_borrow()=let borrow= !q.flags.carry in let v=if borrow then 255 else 0 in q:={!q with R.a=v;flags=flags v(not borrow)borrow}in
 let rar()=let old= !q.a in q:={!q with R.a=(old lsr 1)lor(if !q.flags.carry then 128 else 0);flags={!q.flags with carry=old land 1<>0}}in
 let call site target fn=compatibility(H.Enter(site+0x2200,target+0x2200));fn();compatibility H.Leave in
 let nested site target operation=call site target(fun()->q:=child ~site:(site+0x2200)~operation !q)in
 let push site v=compatibility(H.Push(site,v))and pop()=compatibility H.Pop in
 call 0x6223 0x020e(fun()->q:=Input_gate.run memory ~entry:!q ~compatibility);
 let predicate= !q.a in rar();let rotated_predicate= !q.a in
 let route,local_predicate,rotated_local_predicate=
  if not !q.flags.carry then(
   nested 0x6240 0x5929 Acquisition_parent;
   call 0x6243 0x239a(fun()->q:=Classifier.run memory ~entry:!q ~write
    ~call:(fun site target fn->compatibility(H.Enter(site,target));fn();compatibility H.Leave)~push ~pop);
   let old= !q.a in let sum=old+0x13 in let v=B.wrap sum in
   q:={!q with R.a=v;flags=flags v((old land 15)+3>15)(sum>255)};c !q.a;
   nested 0x6249 0x2511 Saved_input;
   Route_b,None,None
  )else(
   call 0x622a 0x620c(fun()->
    call 0x620c 0x61a4(fun()->
     q:={!q with R.hl=0xa941};put 0x83a7 0xa941 0;
     nested 0x61a9 0x60e5 Acquisition_frame);
    put 0x840f 0xa945 !q.a;
    q:={!q with R.flags=R.comparison !q.a 0};
    if !q.flags.zero then a 1 else(a(read 0xa945);sub 4;sub 1;self_borrow()));
   let local= !q.a in rar();let rotated= !q.a in
   if not !q.flags.carry then Route_a_early,Some local,Some rotated else(
    call 0x6231 0x01e8(fun()->
     q:={!q with R.hl=2};put 0x23eb 0xa5b0 2;put 0x23eb 0xa5b1 0;
     a(read 0xa628);q:={!q with R.flags=R.comparison !q.a 0x70};
     if !q.flags.zero then invalid_arg"Reentrant_acquisition: unvalidated 01E8 selector70");
    call 0x6234 0x239a(fun()->q:=Classifier.run memory ~entry:!q ~write
     ~call:(fun site target fn->compatibility(H.Enter(site,target));fn();compatibility H.Leave)~push ~pop);
    let old= !q.a in let sum=old+0x13 in let v=B.wrap sum in
    q:={!q with R.a=v;flags=flags v((old land 15)+3>15)(sum>255)};c !q.a;
    nested 0x623a 0x256c Attribute_dispatch;
    Route_a_processing,Some local,Some rotated))in
 {route;entry;predicate;rotated_predicate;local_predicate;rotated_local_predicate;returned= !q}
