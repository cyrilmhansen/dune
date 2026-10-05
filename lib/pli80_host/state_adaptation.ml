(** Historical cached minimum, three independent channels, bounded adapter and
    one-byte parent. No CPU/Runner or snapshot-dependent path selection. *)
module R=Recursive_mapped
module S=State
type operation=Minimum|Publish|Adapt|Saved|Word_publish|Control_publish|Primary_publish|Secondary_publish|Input_process|Gate
type channel={name:string;source:int;position:int;value:int}
type result={route:string;input:int;selector:int option;channels:channel list;returned:R.returned}
let run op memory ~entry ~sp ~protected ~write ~frame ~call=
 U8.check entry.R.a; List.iter U16.check [entry.bc;entry.de;entry.hl;sp];
 let q=ref entry and channels=ref[]in
 let put site address value=S.write memory address value;write ~site ~address ~value in
 let guard addresses=List.iter U16.check addresses;
  if List.exists(fun a->List.mem a protected)addresses then invalid_arg"State_adaptation: protected alias"in
 let pair a=q:={!q with R.hl=S.word memory a}in
 let c_low()=q:={!q with R.bc=(!q.bc land 0xff00)lor(!q.hl land 255)}in
 let indexed base carrier=
  pair carrier;q:={!q with R.hl= !q.hl land 255;bc=base};
  let sum= !q.hl+ !q.bc in q:={!q with R.hl=U16.wrap sum;flags={!q.flags with carry=sum>65535}}in
 let child site operation=q:=call ~site ~operation !q in
 let input=entry.R.bc land 255 in
 let selector=ref None and route=ref""in
 (match op with
 |Minimum->
  guard[0xa64e;0xa64f];q:={!q with R.hl=0xa64f};put 0x23a3 0xa64f(!q.de land 255);
  q:={!q with R.hl=0xa64e};put 0x23a5 0xa64e(!q.bc land 255);
  q:={!q with R.hl=0xa64f;a=S.read memory 0xa64e};
  q:={!q with R.flags=R.comparison !q.a(S.read memory !q.hl)};
  route:=(if !q.flags.carry then "C<E"else"C>=E");
  q:={!q with R.a=S.read memory(if !q.flags.carry then 0xa64e else 0xa64f)}
 |Publish->
  guard[0xa652;0xa653;0xa628+input;0xa62b+input;0xa62e+input;0xae32;0xae33];
  q:={!q with R.hl=0xa652};put 0x23d5 0xa652 input;route:="three_channels";
  let channel name base read_site call_site operation=
   indexed base 0xa652;let source= !q.hl in
   q:={!q with R.de=(!q.de land 0xff00)lor(S.read memory source)};
   pair 0xae32;c_low();let position= !q.bc land 255 and value= !q.de land 255 in
   ignore read_site;child call_site operation;channels:={name;source;position;value}::!channels in
  channel"control"0xa628 0x23df 0x23e4 Control_publish;
  channel"primary"0xa62b 0x23f0 0x23f5 Primary_publish;
  channel"secondary"0xa62e 0x2401 0x2406 Secondary_publish
 |Adapt->
  guard[0xa653;0xa654;0xa628+input;0xa62b+input;0xa62e+input;0xa63b+2*input;0xa63c+2*input;0xa642;0xa643;0xae32;0xae33];
  q:={!q with R.hl=0xa653};put 0x240d 0xa653 input;
  indexed 0xa628 0xa653;q:={!q with R.a=S.read memory !q.hl};selector:=Some !q.a;
  q:={!q with R.flags=R.comparison !q.a 0x15};
  if !q.flags.zero then(
   route:="selector15_extra0";indexed 0xa62b 0xa653;
   q:={!q with R.de=(!q.de land 0xff00)lor(S.read memory !q.hl)};
   pair 0xa642;c_low();child 0x242b Minimum;
   indexed 0xa62b 0xa653;put 0x2437 !q.hl !q.a;
   indexed 0xa62e 0xa653;q:={!q with R.a=S.read memory !q.hl};
   q:={!q with R.flags=R.comparison !q.a 0};
   if not !q.flags.zero then invalid_arg"State_adaptation: selector15 nonzero extra"
  )else(
   route:="default_not15_16_19";indexed 0xa628 0xa653;q:={!q with R.a=S.read memory !q.hl};
   q:={!q with R.flags=R.comparison !q.a 0x16};
   if !q.flags.zero then invalid_arg"State_adaptation: unsupported selector16";
   indexed 0xa628 0xa653;q:={!q with R.a=S.read memory !q.hl};
   q:={!q with R.flags=R.comparison !q.a 0x19};
   if !q.flags.zero then invalid_arg"State_adaptation: unsupported selector19");
  pair 0xa653;q:={!q with R.hl= !q.hl land 255;bc=0xa63b};
  let doubled= !q.hl+ !q.hl in q:={!q with R.hl=U16.wrap doubled;flags={!q.flags with carry=doubled>65535}};
  let address= !q.hl+ !q.bc in q:={!q with R.hl=U16.wrap address;flags={!q.flags with carry=address>65535}};
  let low=S.read memory !q.hl in q:={!q with R.de=(!q.de land 0xff00)lor low;hl=U16.wrap(!q.hl+1)};
  q:={!q with R.de=(S.read memory !q.hl lsl 8)lor(!q.de land 255)};
  pair 0xae32;c_low();child 0x24e6 Word_publish;
  pair 0xa653;c_low();child 0x24ed Publish
 |Saved->
  let f=U16.wrap(sp-1)in route:="saved_frame";
  q:={!q with R.bc=input lsl 8 lor input};frame ~address:f ~value:input;
  q:={!q with R.hl=f;flags={!q.flags with carry=false}};
  q:={!q with R.bc=(!q.bc land 0xff00)lor(S.read memory f)};child 0x2519 Input_process;
  q:={!q with R.bc= !q.bc land 0xff00};child 0x251e Adapt;
  q:={!q with R.hl=f;flags={!q.flags with carry=false}};
  q:={!q with R.bc=(!q.bc land 0xff00)lor(S.read memory f)};child 0x2526 Gate
 |_->invalid_arg"State_adaptation: not a root operation");
 {route= !route;input;selector= !selector;channels=List.rev !channels;returned= !q}
