[@@@warning "-4-40-41-42"]
module H=Pli80_host
let rejects f=match f()with exception Invalid_argument _->()|_->failwith"Unsupported state accepted"
let fails f=match f()with exception Failure _->()|_->failwith"Failed-open proof"
let primitives ()=
 for ending=0 to 0x94 do
  let m=H.State.of_bytes(Bytes.make 65536 '\000')in
  H.State.write m 0xae35 ending;H.State.write m 0xae33 7;H.State.write m 0xaabb 4;
  let writes=ref[]and calls=ref[]and saved=ref[]in
  let q=H.Range_publication.run m ~input_c:0xab ~input_de:0xcdef ~protected:[]
   ~write:(fun ~site ~address ~value->writes:=(site,address,value)::!writes)
   ~call:(fun site->calls:=site::!calls)~save_destination:(fun a->saved:=a::!saved)in
  assert(q.end_before=ending&&q.end_after=ending+1&&q.old_index=7&&q.displaced=4&&q.word.word=0xcdef);
  assert(List.rev !calls=[0x7e95;0x7ea0;0x7ea9;0x7eb2]);assert(!saved=[0xab57]);
  assert(H.State.read m(0xaa1f+ending)=7&&H.State.read m 0xaabb=0xab&&H.State.read m 0xae33=4);
  assert(List.length !writes=21);assert(H.State.read m 0xae32=ending&&H.State.read m 0xae35=ending+1)
 done;
 List.iter(fun n->rejects(fun()->H.Range_publication.supported_end n))[149;255;256;-1]
let bridge ()=match Sys.getenv_opt"RUNES_HOST_IMAGES"with None->()|Some dir->
 let channel=open_in_bin(Filename.concat dir "PLI1.OVL")in
 let raw=Fun.protect ~finally:(fun()->close_in channel)(fun()->let b=Bytes.create(in_channel_length channel)in really_input channel b 0(Bytes.length b);b)in
 let module B=Pli80.Range_publication_bridge in let t=B.create ~pli1:raw in
 let bad=Bytes.copy raw in Bytes.set bad 0x7e5f '\x00';rejects(fun()->B.create ~pli1:bad);
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
  for ending=0 to 0x94 do for flags=0 to 31 do
   Bytes.set memory 0xae35(Char.chr ending);Bytes.set memory 0xae33 '\007';Bytes.set memory 0xaabb '\004';
   let state={entry with sign=flags land 16<>0;zero=flags land 8<>0;auxiliary_carry=flags land 4<>0;parity=flags land 2<>0;carry=flags land 1<>0}in
   let p=B.prepare t ~call ~origin:(origin entry_offset)~state ~memory in
   assert(p.state.sp=0xf002&&p.state.pc=resume&&p.state.a=ending&&p.state.b=0&&p.state.c=7&&p.state.d=0x12&&p.state.e=0&&p.state.h=0xae&&p.state.l=0x35);
   assert(p.compatibility_writes=[0xeffc,0x57;0xeffd,0xab;0xeffe,0xb5;0xefff,0xa0]);
   let n=ending+1 in
   assert(p.state.sign=(n>=128)&&p.state.zero=false&&p.state.parity=(List.fold_left(+)0(List.init 8(fun i->(n lsr i)land 1))mod 2=0)&&p.state.auxiliary_carry=(ending land 15=15)&&not p.state.carry)
  done done;
  let unchanged=Bytes.copy memory in
  let rejected memory=let before=Bytes.copy memory in rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:entry ~memory);assert(memory=before)in
  Bytes.set memory 0xae35 '\149';rejected memory;
  Bytes.blit unchanged 0 memory 0 65536;
  Bytes.set memory 0xae33 '\168';rejected memory;
  Bytes.blit unchanged 0 memory 0 65536;
  Bytes.set memory 0xae33 '\152';rejected memory;
  Bytes.blit unchanged 0 memory 0 65536;
  rejects(fun()->B.prepare t ~call ~origin:(origin(entry_offset+1))~state:entry ~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with pc=0}~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with c=256}~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with d=256}~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with sp=65536}~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:entry ~memory:Bytes.empty);
  List.iter(fun address->let bad=Bytes.copy memory in Bytes.set bad address '\xff';
    rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:entry ~memory:bad))[0xf000;0xa05f;0x9cf0;0x9d49];
  let scratch=0xae35 in
  let bad=Bytes.copy memory in Bytes.set bad scratch(Char.chr(resume land 255));Bytes.set bad(scratch+1)(Char.chr(resume lsr 8));
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with sp=scratch}~memory:bad)
 ) [0x7e5f,0x7fff]
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
let ()=primitives();bridge();dispatch_failures();print_endline"149 supported ends x32 flags, child order, residue, aliases, private rejection and dispatch negatives passed"
