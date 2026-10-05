[@@@warning "-4-40-41-42"]
let rejects f=match f()with exception Invalid_argument _->()|_->failwith"Unsupported state accepted"
let fails f=match f()with exception Failure _->()|_->failwith"Failed-open proof"
let bridge ()=match Sys.getenv_opt"RUNES_HOST_IMAGES"with None->()|Some dir->
 let channel=open_in_bin(Filename.concat dir "PLI1.OVL")in
 let raw=Fun.protect ~finally:(fun()->close_in channel)(fun()->let b=Bytes.create(in_channel_length channel)in really_input channel b 0(Bytes.length b);b)in
 let module B=Pli80.Mapped_control_bridge in let t=B.create ~pli1:raw in
 let bad=Bytes.copy raw in Bytes.set bad 0x7a93 '\x00';rejects(fun()->B.create ~pli1:bad);
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
  for flags=0 to 31 do
    let state={entry with sign=flags land 16<>0;zero=flags land 8<>0;auxiliary_carry=flags land 4<>0;parity=flags land 2<>0;carry=flags land 1<>0}in
    let p=B.prepare t ~call ~origin:(origin entry_offset)~state ~memory in
    assert(p.state.sp=0xf002&&p.state.pc=resume&&p.compatibility_writes=[]&&p.state.d=entry.d&&p.state.e=entry.e);
    assert(p.state.sign=state.sign&&p.state.zero=state.zero&&p.state.auxiliary_carry=state.auxiliary_carry&&p.state.parity=state.parity&&not p.state.carry)
  done;
  rejects(fun()->B.prepare t ~call ~origin:(origin(entry_offset+1))~state:entry ~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with pc=0}~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with c=256}~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:entry ~memory:Bytes.empty);
  List.iter(fun address->let bad=Bytes.copy memory in Bytes.set bad address '\xff';
    rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:entry ~memory:bad))[0xf000;0x9c93;0x9d13];
  let scratch=if entry_offset=0x7a93 then 0xae39 else 0xae41 in
  let bad=Bytes.copy memory in Bytes.set bad scratch(Char.chr(resume land 255));Bytes.set bad(scratch+1)(Char.chr(resume lsr 8));
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with sp=scratch}~memory:bad)
 ) [0x7a93,0x8085;0x7b13,0x808d]
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

let ()=bridge();dispatch_failures();print_endline"AC73 flag, scratch/stack alias, code/image/CALL/continuation/count negatives passed"
