[@@@warning "-4-40-41-42"]
module I=Pli80_host.Initialization_parent
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
module H=Pli80_host.Acquisition_parent
let check b m=if not b then failwith m
let parity v=let n=ref 0 in for bit=0 to 7 do if v land(1 lsl bit)<>0 then incr n done;!n mod 2=0
let entry={R.a=0x55;bc=0xabcd;de=0x1357;hl=0x2468;flags={R.sign=true;zero=false;auxiliary_carry=false;parity=false;carry=true}}
let run op m invoke=
 let sp=ref 0xff00 in
 let compat=function H.Enter(_,_) ->sp:= !sp-2|Leave->sp:= !sp+2|Push(_,v)->S.write m(!sp-1)(v lsr 8);S.write m(!sp-2)(v land 255);sp:= !sp-2|Pop->sp:= !sp+2|Exchange(_,v)->S.write m !sp(v land 255);S.write m(!sp+1)(v lsr 8)|Constructor_arguments _->failwith"unexpected software constructor"in
 I.run op m ~entry ~write:(fun ~site:_ ~address:_ ~value:_->())~compatibility:compat ~sp:(fun()-> !sp)~invoke
let ()=
 for old=0 to 255 do
  let m=S.of_bytes(Bytes.make 65536 '\000')in S.write m 0xa8eb old;let n=(old+1)land 255 in
  match run I.Index m (fun ~site:_ ~target:_ _->failwith"unexpected child")with
  |exception Invalid_argument _->check(n>30)"wrong index rejection"
  |q->check(n<=30&&S.read m 0xa8eb=n&&q.bc=(0xab00 lor n)&&q.a=30&&q.de=entry.de&&q.hl=entry.hl)"index channels";
   let d=(30-n)land 255 in check(q.flags.sign=(d>=128)&&q.flags.zero=(d=0)&&q.flags.parity=parity d&&not q.flags.carry&&q.flags.auxiliary_carry=(14>=(n land 15)))"index comparison flags"
 done;
 for byte=0 to 255 do
  let m=S.of_bytes(Bytes.make 65536 '\000')in S.write m 0xf003 byte;
  let q=run I.Bit40 m(fun ~site ~target q->check(site=0x69f7&&target=0x63a6)"bit40 child ancestry";{q with R.a=S.read m 0xf003;bc=3;hl=0xf003})in
  let set=byte land 64=0 in check(q.a=(if set then 255 else 0)&&q.bc=3&&q.hl=0xf003&&q.de=entry.de)"bit40 state law";
  check(q.flags.sign=set&&q.flags.zero=not set&&q.flags.parity&&q.flags.carry=set&&q.flags.auxiliary_carry=not set)"bit40 final SBB flags"
 done;
 print_endline"initialization parent: 512 discriminating index/mask states passed"
