[@@@warning "-4-40-41-42"]
let rejects f=match f()with exception Invalid_argument _->()|_->failwith"Unsupported state accepted"
let fails f=match f()with exception Failure _->()|_->failwith"Failed-open native proof"
let primitives () =
 let m=Pli80_host.State.of_bytes(Bytes.make 65536 '\000')in
 let put=Pli80_host.State.write m in
 for position=0 to 255 do
  put(0xaa1f+position)0;put 0xaab4 0;put 0xae37 0x55;
  let writes=ref[]in
  let r=Pli80_host.Mapped_lookup.mapped_byte m ~position ~protected:[] ~write:(fun w->writes:=w::!writes)in
  assert(r.position=position && r.index=0 && r.byte=0 && r.discarded_ae37=0x55);
  assert(List.map(fun(w:Pli80_host.Mapped_lookup.write)->w.address,w.value)!writes=[0xae36,position])
 done;
 for index=0 to 255 do
  put 0xaa1f index;put(0xaab4+index)((index*13)mod 256);
  let r=Pli80_host.Mapped_lookup.mapped_byte m ~position:0 ~protected:[] ~write:ignore in
  assert(r.index=index && r.byte=(index*13)mod 256)
 done;
 (* The two read tables can share the exact selected byte. *)
 put 0xaab5 1;
 let alias=Pli80_host.Mapped_lookup.mapped_byte m ~position:150 ~protected:[] ~write:ignore in
 assert(alias.index=1 && alias.byte=1);
 put 0xaa1f 0;put 0xaab4 2;
 for packed=0 to 255 do
  put 0x1b4d packed;put 0xae38 0x5a;
  let writes=ref[]in
  let r=Pli80_host.Mapped_lookup.low_attribute m ~position:0 ~protected:[] ~write:(fun w->writes:=w::!writes)in
  assert(r.packed_byte=packed && r.low3=packed mod 8 && r.discarded_ae38=0x5a && r.mapped.discarded_ae37=0);
  assert(List.rev_map(fun(w:Pli80_host.Mapped_lookup.write)->w.address,w.value)!writes=[0xae37,0;0xae36,0])
 done;
 for balance=0 to 255 do for attr=0 to 7 do
  let tmp,next=Pli80_host.Balance_scan.update_balance ~attribute:attr ~balance in
  assert(tmp=(balance+attr)mod 256 && next=(balance+attr+255)mod 256)
 done done;
 for cursor=0 to 255 do assert(Pli80_host.U8.wrap(cursor-1)=(cursor+255)mod 256)done;
 rejects(fun()->Pli80_host.Balance_scan.run m ~cursor:256 ~protected:[]);
 rejects(fun()->Pli80_host.Balance_scan.run m ~cursor:0 ~protected:[0xae48]);
 rejects(fun()->Pli80_host.Mapped_lookup.low_attribute m ~position:0 ~protected:[0x1b4d] ~write:ignore);
 rejects(fun()->Pli80_host.Mapped_lookup.mapped_byte m ~position:0 ~protected:[65536] ~write:ignore);
 (* Terminating wrap case, not a new PL/I source or a cycle-rejection rule. *)
 put 0xaa1f 0;put 0xab1e 1;put 0xaab4 1;put 0xaab5 2;put 0x1b4c 1;put 0x1b4d 0;
 let r=Pli80_host.Balance_scan.run m ~cursor:0 ~protected:[]in
 assert(r.stop_cursor=255 && List.length r.iterations=2 && (List.hd r.iterations).cursor_wrapped);
 (* 42 increments of6, then+2, then+1: 1 ->253 ->255 ->0. *)
 for pos=57 to 100 do put(0xaa1f+pos)0 done;
 put(0xaa1f+58)1;put(0xaa1f+57)2;put 0xaab4 1;put 0xaab5 2;put 0xaab6 3;
 put 0x1b4c 7;put 0x1b4d 3;put 0x1b4e 2;
 let r=Pli80_host.Balance_scan.run m ~cursor:100 ~protected:[]in
 assert(r.stop_cursor=57 && List.length r.iterations=44 && Pli80_host.State.read m 0xae49=0);
 let last=List.hd(List.rev r.iterations)in assert(last.balance_before=255 && last.temporary_sum=1 && last.balance_after=0)
let dispatcher_failures () =
 let empty:Runner.state_snapshot={a=0;b=0;c=0;d=0;e=0;h=0;l=0;sp=65534;pc=0x100;sign=false;zero=false;auxiliary_carry=false;parity=false;carry=false}in
 let input:Pli80.Experiment.input={pli_com=Bytes.of_string"\xc3\x00\x00";pli0_ovl=Bytes.empty;pli1_ovl=Bytes.empty;pli2_ovl=Bytes.empty;source_name="UNIT.PLI";source_bytes=Bytes.empty;module_name="UNIT";command_tail=Bytes.empty;max_steps=10}in
 let make entry oracles=Pli80.Native_dispatch.create ~image:"PLI.COM" ~entry_pc:entry ~end_pc:(entry+1) ~oracles ~records:[] ~prepare:(fun _ _ _->failwith"Should not prepare")in
 fails(fun()->Pli80.Native_dispatch.run input [make 0x100 []]);
 let oracle:Pli80.Native_dispatch.oracle={input=empty;output=empty;entry_memory=Bytes.empty;post_memory=Bytes.empty;logical_digest=""}in
 fails(fun()->Pli80.Native_dispatch.run input [make 0x200 [oracle]])
let bridge () = match Sys.getenv_opt"RUNES_HOST_IMAGES"with None->()|Some dir->
 let c=open_in_bin(Filename.concat dir "PLI1.OVL")in
 let raw=Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)in
 let module B=Pli80.Balance_scan_bridge in
 let t=B.create ~pli1:raw in
 rejects(fun()->B.create ~pli1:Bytes.empty);
 let memory=Bytes.make 65536 '\000'in Bytes.blit raw 0 memory 0x2200(Bytes.length raw);
 let image:Cpm.Filesystem.key={drive=0;user=0;name="PLI1.OVL"}in
 let origin offset=Analysis.Execution_map.Image_byte{image;offset}in
 let entry:Runner.state_snapshot={a=0;b=0;c=0;d=0x12;e=0x34;h=0;l=0;sp=0xf000;pc=0x9d7a;sign=false;zero=false;auxiliary_carry=false;parity=false;carry=false}in
 let site=0x7da7 and resume=0x9faa in Bytes.set memory 0xf000 '\xaa';Bytes.set memory 0xf001 '\x9f';
 let fetched=Bytes.sub raw site 3 in let decoded=match I8080.Decode.decode fetched ~offset:0 with Ok d->d|_->assert false in
 let step pc=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:pc ~pc_after:0x9d7a ~decoded ~fetched_bytes:fetched
   ~memory_accesses:[I8080.Step.Write{address=0xf000;value=0xaa};I8080.Step.Write{address=0xf001;value=0x9f}]
   ~control_flow:(I8080.Step.Call{target=0x9d7a;taken=true})in
 let noncall=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:0x9fa7 ~pc_after:0x9d7a ~decoded ~fetched_bytes:fetched ~memory_accesses:[] ~control_flow:I8080.Step.Sequential in
 let before={entry with pc=0x9fa7;sp=0xf002}in
 rejects(fun()->B.verify_call t ~origin:(origin site)~before ~after:entry noncall ~entry);
 let call=B.verify_call t ~origin:(origin site)~before ~after:entry(step before.pc)~entry in
 rejects(fun()->B.verify_call t ~origin:(origin(site-1))~before ~after:entry(step before.pc)~entry);
 rejects(fun()->B.verify_call t ~origin:Analysis.Execution_map.Unknown ~before ~after:entry(step before.pc)~entry);
 let p=B.prepare t ~call ~origin:(origin 0x7b7a)~state:entry ~memory in
 assert(p.state.pc=resume && p.state.sp=0xf002 && p.state.d=0x12 && p.state.e=0x34 && p.state.auxiliary_carry);
 rejects(fun()->B.prepare t ~call ~origin:(origin 0x7b7b)~state:entry ~memory);
 rejects(fun()->B.prepare t ~call ~origin:(origin 0x7b7a)~state:{entry with pc=0} ~memory);
 rejects(fun()->B.prepare t ~call ~origin:(origin 0x7b7a)~state:{entry with c=256} ~memory);
 rejects(fun()->B.prepare t ~call ~origin:(origin 0x7b7a)~state:entry ~memory:Bytes.empty);
 let bad=Bytes.copy memory in Bytes.set bad 0xf000 '\x00';rejects(fun()->B.prepare t ~call ~origin:(origin 0x7b7a)~state:entry ~memory:bad);
 let bad=Bytes.copy memory in Bytes.set bad 0x9c4d '\x00';rejects(fun()->B.prepare t ~call ~origin:(origin 0x7b7a)~state:entry ~memory:bad);
 let bad=Bytes.copy memory in Bytes.set bad 0xae48 '\xaa';Bytes.set bad 0xae49 '\x9f';rejects(fun()->B.prepare t ~call ~origin:(origin 0x7b7a)~state:{entry with sp=0xae48}~memory:bad)
let ()=primitives();dispatcher_failures();bridge();print_endline"Native mappings,2048 balance arithmetic pairs,256 cursor decrements,terminating wraps and fail-closed proofs passed"
