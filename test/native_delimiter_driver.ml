[@@@warning "-4-40-41-42"]
module I=Pli80_host.Initialization_parent
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
module H=Pli80_host.Acquisition_parent
let check b m=if not b then failwith m
let entry={R.a=0x55;bc=0xabcd;de=0x1357;hl=0x2468;flags={R.sign=true;zero=false;auxiliary_carry=false;parity=false;carry=true}}
let run count bad=
 let m=S.of_bytes(Bytes.make 65536 '\000')in
 S.write m 0x2015 1;S.write m 0xa863 0x23;S.write m 0xa864 0xab;
 let sp=ref 0xff00 and calls=ref[]and writes=ref[]and remaining=ref count in
 let compat=function H.Enter(_,_) ->sp:= !sp-2|Leave->sp:= !sp+2|_->failwith"unexpected driver frame"in
 let invoke ~site ~target q=
  calls:=site::!calls;
  match target with
  |0x240e->{q with R.a=(if bad=1 then 0 else 255)}
  |0x233d|0x67f0->q
  |0x9a4e when site=0x2e94->S.write m 0x20c3 0x3a;q
  |0x23af->let c=q.R.bc land 255 in
   let matched=c=S.read m 0x20c3 in
   if matched then S.write m 0x20c3(if c=0x3a then(if bad=2 then 0 else 0x9b)else if count=0 then 0x3b else 0xad);
   {q with R.a=(if matched then 1 else 0)}
  |0x2461->q
  |0xa2b7->check(List.mem(q.R.bc land 255)[0x8d;0x8e])"output policy channels";q
  |0x9a4e->decr remaining;S.write m 0x20c3(if !remaining=0 then 0x3b else 0xc0);q
  |0x2e1b->check(q.R.bc=0xab23)"fresh cached pointer argument";check(S.read m 0x20c3=0x3b)"delimiter consumed by canonical child";S.write m 0x20c3 0x1a;q
  |0x2346->S.write m 0x20c3(if bad=3 then 0x3b else 0x1a);{q with R.bc=0x1d8c;de=0xaaaa}
  |_->failwith"unexpected canonical child"in
 match I.run I.Driver m ~entry ~write:(fun ~site ~address ~value->writes:=(site,address,value)::!writes)~compatibility:compat ~sp:(fun()-> !sp)~invoke with
 |exception Invalid_argument _->check(bad<>0)"valid driver rejected"
 |q->check(bad=0)"unsupported driver accepted";
  check(q.a=0&&q.bc=0x1d8c&&q.de=0xaaaa&&q.hl=0xa5d9&& !sp=0xff00)"driver return channels";
  check(q.flags.zero&&q.flags.auxiliary_carry&&q.flags.parity&&not q.flags.sign&&not q.flags.carry)"EOF compare flags survive final RAR";
  check(List.rev !writes=[0x2e78,0xa5d9,1;0x2e91,0xa5da,0x23;0x2e91,0xa5db,0xab;0x2f06,0xa5d9,0])"visible lifetime publications";
  check(List.length(List.filter((=)0x2ecc)!calls)=count)"scan must follow changing state"
let ()=List.iter(fun n->run n 0)[0;1;4;7];List.iter(fun n->run 4 n)[1;2;3];print_endline"delimiter driver: varying scan lengths and unsupported gate/delimiter/EOF laws passed"
