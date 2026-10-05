(** Bounded historical +8048 orchestration. Each channel reloads shared state. *)
module R=Recursive_mapped
module S=State
type operation=Range_publish|Range_process|Emit|Control_read|Control_publish|Primary_read|Primary_publish|Secondary_read|Secondary_publish
type channel={name:string;predecessor:int;position:int;value:int}
type result={route:string;input:int;gate:int option;rotated_gate:int option;channels:channel list;emitted:int option;returned:R.returned}
let run memory ~entry ~write ~call=
 let q=ref entry and channels=ref[]in
 let put site address value=S.write memory address value;write ~site ~address ~value in
 let pair a=q:={!q with R.hl=S.word memory a}in
 let low_c()=q:={!q with R.bc=(!q.bc land 0xff00)lor(!q.hl land 255)}in
 let child site operation=q:=call ~site ~operation !q in
 let input=entry.R.bc land 255 in
 q:={!q with R.hl=0xae6a};put 0x804b 0xae6a input;
 q:={!q with R.a=0xdd;flags=R.comparison 0xdd(S.read memory 0xae6a)};
 if not !q.flags.carry then (
  pair 0xae6a;low_c();q:={!q with R.de=0};child 0x807d Range_publish;
  let copy name read_site read_op publish_site publish_op=
   q:={!q with R.a=S.read memory 0xae32};
   let predecessor,flags=Range_processing.unary !q.flags !q.a false in
   q:={!q with R.a=predecessor;flags;bc=(!q.bc land 0xff00)lor predecessor};
   child read_site read_op;
   let value= !q.a in
   pair 0xae32;q:={!q with R.de=(!q.de land 0xff00)lor !q.a};low_c();
   let position= !q.bc land 255 in child publish_site publish_op;
   channels:={name;predecessor;position;value}::!channels in
  copy "control" 0x8085 Control_read 0x808d Control_publish;
  copy "primary" 0x8095 Primary_read 0x809d Primary_publish;
  copy "secondary" 0x80a5 Secondary_read 0x80ad Secondary_publish;
  {route="low";input;gate=None;rotated_gate=None;channels=List.rev !channels;emitted=None;returned= !q}
 )else(
  let gate=S.read memory 0xaa1a in
  let rotated_gate=(gate lsr 1)lor(if !q.flags.carry then 128 else 0)in
  q:={!q with R.a=rotated_gate;flags={!q.flags with carry=gate land 1<>0}};
  if !q.flags.carry then invalid_arg "Input_processing: unsupported high gate-set arm";
  child 0x8069 Range_process;
  pair 0xae6a;low_c();let emitted= !q.bc land 255 in
  child 0x8070 Emit;
  {route="high";input;gate=Some gate;rotated_gate=Some rotated_gate;channels=[];emitted=Some emitted;returned= !q})
