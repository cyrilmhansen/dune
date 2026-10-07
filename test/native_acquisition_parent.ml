[@@@warning "-4-40-41-42"]
module H=Pli80_host.Acquisition_parent
module R=Pli80_host.Recursive_mapped
module S=Pli80_host.State
let rejects f=match f()with exception Invalid_argument _->()|_->failwith"unsupported acquisition accepted"
let base()=let m=S.of_bytes(Bytes.make 65536 '\000')in
 List.iter(fun(a,v)->S.write m a v)[0x20c3,2;0x20c5,1;0x20c6,65;0x7923,2;0xa8ac,255;0x1c36,0;0x1c37,0xf0];m
let entry:R.returned={a=7;bc=0x1234;de=0x5678;hl=0x9876;flags=R.comparison 3 4}
let run m q guard=H.run m ~entry:q ~write:(fun ~site:_ ~address:_ ~value:_->())
 ~compatibility:ignore ~guard_field:guard ~saved:(fun _->invalid_arg"synthetic saved boundary")
let ()=
 rejects(fun()->run(base()){entry with a=256}(fun _ _->()));
 rejects(fun()->run(base()){entry with bc=65536}(fun _ _->()));
 rejects(fun()->S.of_bytes Bytes.empty);
 let m=base()in S.write m 0x20c3 0;rejects(fun()->run m entry(fun _ _->()));
 let m=base()in
 (* A selected pointer aliases scratch. Rejection precedes traversal. *)
 S.write m(0xa761+130)0x0f;S.write m(0xa762+130)0xa9;
 let guarded=ref false in rejects(fun()->run m entry(fun p _->assert(p=0xa90f);guarded:=true;invalid_arg"scratch alias"));assert(!guarded);
 (* A null selection reaches the literal AE7A allocator guard; no floor fallback. *)
 let m=base()in S.write m 0x1c37 1;rejects(fun()->run m entry(fun _ _->()));
 print_endline"Bounded acquisition inputs, pointer aliases and allocator failure reject"
