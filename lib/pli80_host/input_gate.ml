[@@@warning "-4-40-41-42"]
(** Complete +020E wrapping-mask gate; the two 20C3 reads remain distinct. *)
module R=Recursive_mapped
module H=Acquisition_parent
let run memory ~(entry:R.returned) ~compatibility =
 let q=ref entry in
 let parity n=let n=n lxor(n lsr 4)in let n=n lxor(n lsr 2)in(n lxor(n lsr 1))land 1=0 in
 let flags n ac cy={R.sign=n land 128<>0;zero=n=0;parity=parity n;auxiliary_carry=ac;carry=cy}in
 let sub v=let old= !q.a in q:={!q with R.a=U8.wrap(old-v);flags=R.comparison old v}in
 let mask()=let b= !q.flags.carry in let v=if b then 255 else 0 in q:={!q with R.a=v;flags=flags v(not b)b}in
 let psw f=(if f.R.sign then 128 else 0)lor(if f.zero then 64 else 0)lor(if f.auxiliary_carry then 16 else 0)lor(if f.parity then 4 else 0)lor 2 lor(if f.carry then 1 else 0)in
 q:={!q with R.a=State.read memory 0x20c3};sub 1;sub 1;mask();
 let carrier= !q.a lsl 8 lor psw !q.flags in compatibility(H.Push(0x2416,carrier));
 q:={!q with R.a=State.read memory 0x20c3};sub 0x81;mask();q:={!q with R.a= !q.a lxor 255};
 compatibility H.Pop;q:={!q with R.bc=(carrier land 0xff00)lor(carrier lsr 8)};
 let v= !q.a lor(!q.bc land 255)in {!q with R.a=v;flags=flags v false false}
