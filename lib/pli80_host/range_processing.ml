[@@@warning "-4-40-41-42"]
(** Bounded +7D53 composition. Branches depend only on fresh shared historical
    memory. Child operations are native historical operations, not guest steps. *)
module R=Recursive_mapped
module S=State
type operation=Mapping|Recursive|Balance|Emit|High_attribute|Primary|Secondary|Low_word|High_word|Recycle
type reverse={cursor:int;sentinel:int;mapped:int option;result:int option;stop:int option;psw:int}
type forward={cursor:int;mapped:int;attribute:int;channels:(string*int)list}
type result={path:string;returned:R.returned;reverse:reverse list;forward:forward list}
let reject message=invalid_arg("Range_processing: "^message)
let supported_attribute a=if not(List.mem a[2;3;4;6])then reject "unsupported transformed attribute"
let supported_forward_cursor c=if c=0 then reject "unobserved forward wrap"
let unary flags old increment =
 let n=U8.wrap(old+(if increment then 1 else -1))in
 let f=R.comparison n 0 in
 n,{f with R.carry=flags.R.carry;auxiliary_carry=(if increment then old land 15=15 else old land 15<>0)}
let psw f=(if f.R.sign then 128 else 0)lor(if f.zero then 64 else 0)
 lor(if f.auxiliary_carry then 16 else 0)lor(if f.parity then 4 else 0)lor 2 lor(if f.carry then 1 else 0)
let run memory ~entry ~write ~push_psw ~call =
 let q=ref entry and reverse=ref[]and forward=ref[]in
 let read=S.read memory in
 let put site address value=S.write memory address value;write ~site ~address ~value in
 let load address=q:={!q with R.a=read address}in
 let pair address=q:={!q with R.hl=S.word memory address}in
 let low_c()=q:={!q with R.bc=(!q.bc land 0xff00)lor(!q.hl land 255)}in
 let compare_a value=q:={!q with R.flags=R.comparison !q.a value}in
 let child site operation=q:=call ~site ~operation !q in
 let emit site channel value channels= q:={!q with R.bc=(!q.bc land 0xff00)lor value};
  child site Emit;channels:= !channels@[channel,value]in
 q:={!q with R.hl=0xae34};load 0xae35;compare_a(read 0xae34);
 if !q.flags.zero then {path="equal";returned= !q;reverse=[];forward=[]}
 else (
  load 0xaa1a;
  let gate= !q.a and incoming= !q.flags.carry in
  q:={!q with R.a=(gate lsr 1)lor(if incoming then 128 else 0);flags={!q.flags with carry=gate land 1<>0}};
  if !q.flags.carry then {path="gate";returned= !q;reverse=[];forward=[]}
  else (
   load 0xae35;put 0x7d69 0xae4f !q.a;
   load 0x202b;
   let old= !q.a in q:={!q with R.a=(old lsr 1)lor(if !q.flags.carry then 128 else 0);flags={!q.flags with carry=old land 1<>0}};
   if !q.flags.carry then reject "202B shortcut";
   load 0x2011;compare_a 0;if not !q.flags.zero then reject "2011 shortcut";
   let rec backwards()=
    load 0xae4f;
    let cursor,flags=unary !q.flags !q.a false in q:={!q with R.a=cursor;flags};
    put 0x7d7f 0xae4f cursor;
    let saved_psw=psw flags in push_psw ~a:cursor ~flags:saved_psw;
    load 0xae34;
    let sentinel,flags=unary !q.flags !q.a false in
    q:={!q with R.a=sentinel;flags;bc=cursor lor(cursor lsl 8)};compare_a cursor;
    if !q.flags.zero then reverse:={cursor;sentinel;mapped=None;result=None;stop=None;psw=saved_psw}::!reverse
    else (
     pair 0xae4f;low_c();child 0x7d91 Mapping;compare_a 0xf7;
     let mapped= !q.a in if not !q.flags.carry then reject "reverse mapped>=F7";
     pair 0xae4f;low_c();child 0x7d9d Recursive;
     let result= !q.a in put 0x7da0 0xae50 result;
     pair 0xae4f;low_c();child 0x7da7 Balance;
     let stop= !q.a in put 0x7daa 0xae4f stop;
     reverse:={cursor;sentinel;mapped=Some mapped;result=Some result;stop=Some stop;psw=saved_psw}::!reverse;
     backwards())in
   backwards();load 0xae34;put 0x7db3 0xae4f !q.a;
   let rec forwards()=
    load 0xae35;let endpoint,flags=unary !q.flags !q.a false in
    q:={!q with R.a=endpoint;flags;hl=0xae4f};compare_a(read 0xae4f);
    if not !q.flags.carry then (
     let cursor=read 0xae4f in
     pair 0xae4f;low_c();child 0x7dc5 Mapping;
     let mapped= !q.a in put 0x7dc8 0xae50 mapped;
     let channels=ref[]in emit 0x7dcc "mapped_byte" !q.a channels;
     load 0xae50;compare_a 0xf7;
     if not !q.flags.carry then reject "forward mapped>=F7 after emission";
     pair 0xae50;low_c();child 0x7ddb High_attribute;
     let attribute= !q.a in put 0x7dde 0xae50 attribute;
     compare_a 3;supported_attribute attribute;
     if !q.flags.carry then (
      child 0x7de6 Low_word;channels:= !channels@["mapped_word_low", read 0xae52];
      load 0xae50;compare_a 2;
      if not !q.flags.zero then reject "attribute changed after low emission";
      child 0x7df1 High_word;channels:= !channels@["mapped_word_high", read 0xae53])
     else (
      pair 0xae4f;low_c();child 0x7dfb Primary;put 0x7dfe 0xae51 !q.a;
      load 0xae50;compare_a 3;
      if !q.flags.zero then (pair 0xae4f;low_c();child 0x7e0d Secondary;emit 0x7e11 "secondary_auxiliary" !q.a channels);
      load 0xae50;compare_a 6;
      if not !q.flags.zero then (pair 0xae51;low_c();emit 0x7e20 "primary_auxiliary" (!q.hl land 255) channels);
      load 0xae50;compare_a 5;
      if not !q.flags.carry then (
       child 0x7e2b Low_word;channels:= !channels@["mapped_word_low", read 0xae52];
       child 0x7e2e High_word;channels:= !channels@["mapped_word_high", read 0xae53]));
     forward:={cursor;mapped;attribute;channels= !channels}::!forward;
     pair 0xae4f;low_c();child 0x7e35 Recycle;
     q:={!q with R.hl=0xae4f};
     let next,flags=unary !q.flags(read 0xae4f)true in q:={!q with R.flags=flags};
     put 0x7e3b 0xae4f next;supported_forward_cursor next;forwards())in
   forwards();load 0xae34;put 0x7e42 0xae35 !q.a;
   {path="work";returned= !q;reverse=List.rev !reverse;forward=List.rev !forward}))
