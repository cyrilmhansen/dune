[@@@warning "-4-40-41-42"]
module H=Pli80_host
let rejects f=match f()with exception Invalid_argument _->()|_->failwith"Unsupported state accepted"
let fails f=match f()with exception Failure _->()|_->failwith"Failed-open proof"
let primitives ()=
 let memory=H.State.of_bytes(Bytes.make 65536 '\000')in let put=H.State.write memory in
 for index=0 to 255 do for packed=0 to 255 do
  put(0x1b4b+index)packed;put 0xae48 0x56;
  let writes=ref[]in
  let q=H.Mapped_lookup.high_attribute memory ~byte_index:index ~protected:[] ~write:(fun w->writes:=w::!writes)in
  assert(q.address=0x1b4b+index&&q.packed_byte=packed&&q.discarded_ae48=0x56&&q.after_mask=packed land 0xfc);
  assert(q.shifts=[packed/2 land 0x7e;packed/4 land 0x3f;packed/8]);
  assert(q.shift_carries=[false;false;packed land 4<>0]&&q.high3=(packed/8)mod 8);
  assert(List.map(fun(w:H.Mapped_lookup.write)->w.address,w.value)!writes=[0xae47,index])
 done done;
 for index=0 to 255 do if index<>158&&index<>159 then for value=0 to 255 do
  put 0xaa1f index;put(0xad9d+index)value;put 0xae3c 0x71;
  let writes=ref[]in
  let q=H.Auxiliary.read_secondary memory ~position:0 ~protected:[] ~write:(fun w->writes:=w::!writes)in
  assert(q.index=index&&q.address=0xad9d+index&&q.value=value&&q.discarded_high=0x71);
  assert(List.map(fun(w:H.Mapped_lookup.write)->w.address,w.value)!writes=[0xae3b,0])
 done done;
 (* Current bytes, independent channels and real physical overlaps remain visible. *)
 put 0x1b4b 0x18;let high()=H.Mapped_lookup.high_attribute memory ~byte_index:0 ~protected:[] ~write:ignore in
 assert((high()).high3=3);put 0x1b4b 0x30;assert((high()).high3=6);
 put 0xaa1f 0;put 0xad08 0x42;put 0xad9d 0x42;
 let second()=H.Auxiliary.read_secondary memory ~position:0 ~protected:[] ~write:ignore in
 let primary=H.Auxiliary.read memory ~position:0 ~protected:[] ~write:ignore in
 let secondary=second()in assert(primary.value=secondary.value&&primary.address<>secondary.address);
 put 0xad08 0x11;assert((second()).value=0x42);
 put 0xad9d 0x37;assert((second()).value=0x37);
 put 0xaa1f 1;put 0xad9e 0x53;assert((second()).index=1&&(second()).value=0x53);
 put 0xaa1f 0;put 0xaa20 149;
 let overlapping=H.Auxiliary.read memory ~position:1 ~protected:[] ~write:ignore in
 assert(overlapping.address=(second()).address);
 put 0xad9d 0x21;
 assert((H.Auxiliary.read memory ~position:1 ~protected:[] ~write:ignore).value=0x21&&(second()).value=0x21);
 rejects(fun()->H.State.of_bytes Bytes.empty);
 rejects(fun()->H.Mapped_lookup.high_attribute memory ~byte_index:256 ~protected:[] ~write:ignore);
 rejects(fun()->H.Auxiliary.read_secondary memory ~position:(-1) ~protected:[] ~write:ignore);
 List.iter(fun a->rejects(fun()->H.Mapped_lookup.high_attribute memory ~byte_index:0 ~protected:[a] ~write:ignore))[0xae47;0xae48;0x1b4b;65536];
 List.iter(fun a->rejects(fun()->H.Auxiliary.read_secondary memory ~position:0 ~protected:[a] ~write:ignore))[0xae3b;0xae3c;0xaa1f;0xad9d;65536];
 List.iter(fun j->put 0xaa1f j;rejects(fun()->H.Auxiliary.read_secondary memory ~position:0 ~protected:[] ~write:ignore))[158;159];
 rejects(fun()->H.State.read memory 65536);rejects(fun()->H.State.write memory 0 256)
let bridge ()=match Sys.getenv_opt"RUNES_HOST_IMAGES"with None->()|Some dir->
 let channel=open_in_bin(Filename.concat dir "PLI1.OVL")in
 let raw=Fun.protect ~finally:(fun()->close_in channel)(fun()->let b=Bytes.create(in_channel_length channel)in really_input channel b 0(Bytes.length b);b)in
 let module B=Pli80.Attribute_auxiliary_bridge in let t=B.create ~pli1:raw in
 let bad=Bytes.copy raw in Bytes.set bad 0x7b64 '\x00';rejects(fun()->B.create ~pli1:bad);
 rejects(fun()->B.create ~pli1:Bytes.empty);
 let image:Cpm.Filesystem.key={drive=0;user=0;name="PLI1.OVL"}in
 let origin offset=Analysis.Execution_map.Image_byte{image;offset}in
 List.iter(fun(entry_offset,site)->
  let memory=Bytes.make 65536 '\000'in Bytes.blit raw 0 memory 0x2200(Bytes.length raw);
  let resume=site+0x2203 and pc=entry_offset+0x2200 in
  Bytes.set memory 0xf000(Char.chr(resume land 255));Bytes.set memory 0xf001(Char.chr(resume lsr 8));
  let fetched=Bytes.sub raw site 3 in let decoded=match I8080.Decode.decode fetched ~offset:0 with Ok d->d|_->assert false in
  let entry:Runner.state_snapshot={a=0x41;b=0x32;c=0;d=0x12;e=0x34;h=0x87;l=0x65;sp=0xf000;pc;
    sign=false;zero=false;auxiliary_carry=false;parity=false;carry=false}in
  let before={entry with pc=site+0x2200;sp=0xf002}in
  let step=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:before.pc ~pc_after:pc ~decoded ~fetched_bytes:fetched
    ~memory_accesses:[I8080.Step.Write{address=0xf000;value=resume land 255};I8080.Step.Write{address=0xf001;value=resume lsr 8}]
    ~control_flow:(I8080.Step.Call{target=pc;taken=true})in
  let noncall=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:before.pc ~pc_after:pc ~decoded ~fetched_bytes:fetched ~memory_accesses:[] ~control_flow:I8080.Step.Sequential in
  rejects(fun()->B.verify_call t ~origin:(origin site)~before ~after:entry noncall ~entry);
  rejects(fun()->B.verify_call t ~origin:Analysis.Execution_map.Unknown ~before ~after:entry step ~entry);
  let other=Analysis.Execution_map.Image_byte{image={image with name="PLI2.OVL"};offset=site}in
  rejects(fun()->B.verify_call t ~origin:other ~before ~after:entry step ~entry);
  rejects(fun()->B.verify_call t ~origin:(origin(site+1))~before ~after:entry step ~entry);
  let call=B.verify_call t ~origin:(origin site)~before ~after:entry step ~entry in
  for packed=0 to (if entry_offset=0x7b64 then 255 else 0) do
   Bytes.set memory 0x1b4b(Char.chr packed);
   for flags=0 to 31 do
    let state={entry with sign=flags land 16<>0;zero=flags land 8<>0;auxiliary_carry=flags land 4<>0;parity=flags land 2<>0;carry=flags land 1<>0}in
    let p=B.prepare t ~call ~origin:(origin entry_offset)~state ~memory in
    assert(p.state.sp=0xf002&&p.state.pc=resume&&p.compatibility_writes=[]&&p.state.d=entry.d&&p.state.e=entry.e);
    if entry_offset=0x7b64 then (
     let first=I8080.Alu.logand packed 0xfc in
     let s1,c1=I8080.Alu.rar ~carry:first.carry first.value in
     let s2,c2=I8080.Alu.rar ~carry:c1 s1 in
     let s3,_=I8080.Alu.rar ~carry:c2 s2 in
     let final=I8080.Alu.logand s3 7 in
     assert(p.state.a=final.value&&p.state.b=0x1b&&p.state.c=0x4b&&p.state.h=0x1b&&p.state.l=0x4b);
     assert(p.state.sign=final.status.szp.sign&&p.state.zero=final.status.szp.zero&&p.state.parity=final.status.szp.parity
      &&p.state.auxiliary_carry=final.status.auxiliary_carry&&p.state.carry=final.carry);
     (* Independent bit equation distinguishes equal finalA with differentAC. *)
     assert(p.state.auxiliary_carry=(packed land 64<>0)))
    else assert(p.state.sign=state.sign&&p.state.zero=state.zero&&p.state.auxiliary_carry=state.auxiliary_carry&&p.state.parity=state.parity&&not p.state.carry)
   done
  done;
  rejects(fun()->B.prepare t ~call ~origin:(origin(entry_offset+1))~state:entry ~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with pc=0}~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with c=256}~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:entry ~memory:Bytes.empty);
  List.iter(fun address->let bad=Bytes.copy memory in Bytes.set bad address '\xff';
    rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:entry ~memory:bad))[0xf000;0x9d64;0x9cbf];
  let scratch=if entry_offset=0x7b64 then 0xae47 else 0xae3b in
  let bad=Bytes.copy memory in Bytes.set bad scratch(Char.chr(resume land 255));Bytes.set bad(scratch+1)(Char.chr(resume lsr 8));
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with sp=scratch}~memory:bad)
 ) [0x7b64,0x7ddb;0x7abf,0x7e0d]
let dispatch_failures ()=
 let state:Runner.state_snapshot={a=0;b=0;c=0;d=0;e=0;h=0;l=0;sp=65534;pc=0x100;sign=false;zero=false;auxiliary_carry=false;parity=false;carry=false}in
 let input:Pli80.Experiment.input={pli_com=Bytes.of_string"\xc3\x00\x00";pli0_ovl=Bytes.empty;pli1_ovl=Bytes.empty;pli2_ovl=Bytes.empty;source_name="UNIT.PLI";source_bytes=Bytes.empty;module_name="UNIT";command_tail=Bytes.empty;max_steps=10}in
 let make pc oracles=Pli80.Native_dispatch.create ~image:"PLI.COM" ~entry_pc:pc ~end_pc:(pc+1)~oracles ~records:[] ~prepare:(fun _ _ _->failwith"Should not prepare")in
 fails(fun()->Pli80.Native_dispatch.run input[make 0x100 []]);
 let oracle:Pli80.Native_dispatch.oracle={input=state;output=state;entry_memory=Bytes.empty;post_memory=Bytes.empty;logical_digest=""}in
 fails(fun()->Pli80.Native_dispatch.run input[make 0x200 [oracle]]);
 (* A different image at the same runtime PC remains real guest execution. *)
 let collision=Pli80.Native_dispatch.create ~image:"PLI1.OVL" ~entry_pc:0x100 ~end_pc:0x101 ~oracles:[] ~records:[] ~prepare:(fun _ _ _->failwith"Wrong-image interception")in
 match Pli80.Native_dispatch.run input[collision]with
 |Ok([0],r)->assert(r.run.host_transitions=0 && r.run.steps>0)
 |_->failwith"Canonical image collision was not isolated"
let ()=primitives();bridge();dispatch_failures();print_endline"65536 high lookups,65024 secondary lookups,256x32 high return-flag cases,32 secondary flag cases and shared-memory/ABI/alias/count proofs passed"
