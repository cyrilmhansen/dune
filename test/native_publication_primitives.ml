[@@@warning "-4-40-41-42"]
module H=Pli80_host
let rejects f=match f()with exception Invalid_argument _->()|_->failwith"Unsupported state accepted"
let fails f=match f()with exception Failure _->()|_->failwith"Failed-open proof"
let primitives ()=
 let m=H.State.of_bytes(Bytes.make 65536 '\000')in let put=H.State.write m in
 for j=0 to 255 do for value=0 to 255 do
  put 0xaa1f j;
  let writes=ref[]and stack=ref[]in
  let word=value lor((255-value)lsl 8)in
  let q=H.Mapped_word.publish m ~position:0 ~value:word ~protected:[] ~write:(fun(w:H.Mapped_word.write)->writes:=(w.address,w.value)::!writes)~save_destination:(fun a->stack:=a::!stack)in
  assert(q.index=j&&q.first_address=0xab49+j&&q.low_address=0xab49+2*j&&q.word=word&&q.discarded_ae3f=value);
  assert(List.rev !writes=[0xae40,255-value;0xae3f,value;0xae3e,0;q.low_address,value;q.high_address,255-value]);assert(!stack=[q.low_address]);
  assert((H.Mapped_word.lookup m ~position:0 ~protected:[] ~write:ignore).word=word);
  if j<>168&&j<>169 then (
   let ws=ref[]in let run()=H.Auxiliary.publish_secondary m ~position:0 ~value ~protected:[] ~write:(fun(w:H.Mapped_lookup.write)->ws:=(w.address,w.value)::!ws)in
   let q=run()in assert(q.index=j&&q.value=value&&q.discarded_high=value);
   assert(List.rev !ws=[0xae46,value;0xae45,0;0xad9d+j,value]);
   ws:=[];ignore(run());assert(List.length !ws=3);
   if j<>158&&j<>159 then assert((H.Auxiliary.read_secondary m ~position:0 ~protected:[] ~write:ignore).value=value))
 done done;
 (* The temporary ABI save occurs between scratch setup and final publication. *)
 let chronology=ref[]in put 0xaa1f 3;
 ignore(H.Mapped_word.publish m ~position:0 ~value:0xabcd ~protected:[]
  ~write:(fun(w:H.Mapped_word.write)->chronology:=w.phase::!chronology)
  ~save_destination:(fun a->assert(a=0xab4f);chronology:="destination_push_pop"::!chronology));
 assert(List.rev !chronology=["mapped_word_value_high";"mapped_word_value_low";"mapped_word_write_position";"destination_push_pop";"mapped_word_publication_low";"mapped_word_publication_high"]);
 for position=0 to 255 do for j=0 to 255 do
  put(0xaa1f+position)j;
  let q=H.Mapped_word.publish m ~position ~value:0x1234 ~protected:[] ~write:ignore ~save_destination:ignore in
  assert(q.position=position&&q.index=j&&q.word=0x1234)
 done done;
 put 0xaa1f 37;
 for value=0 to 65535 do
  let q=H.Mapped_word.publish m ~position:0 ~value ~protected:[] ~write:ignore ~save_destination:ignore in
  assert(q.word=value&&H.State.word m q.low_address=value)
 done;
 rejects(fun()->H.State.of_bytes Bytes.empty);
 let word ?(position=0) ?(value=0) protected=H.Mapped_word.publish m ~position ~value ~protected ~write:ignore ~save_destination:ignore in
 let secondary ?(position=0) ?(value=0) protected=H.Auxiliary.publish_secondary m ~position ~value ~protected ~write:ignore in
 put 0xaa1f 0;
 List.iter(fun a->rejects(fun()->word[a]))[0xae3e;0xae3f;0xae40;0xaa1f;0xab49;0xab4a;65536];
 List.iter(fun a->rejects(fun()->secondary[a]))[0xae45;0xae46;0xaa1f;0xad9d;65536];
 rejects(fun()->word ~position:256 []);rejects(fun()->word ~value:65536 []);
 rejects(fun()->secondary ~position:(-1) []);rejects(fun()->secondary ~value:256 []);
 List.iter(fun j->put 0xaa1f j;rejects(fun()->secondary[]))[168;169]
let bridge ()=match Sys.getenv_opt"RUNES_HOST_IMAGES"with None->()|Some dir->
 let channel=open_in_bin(Filename.concat dir "PLI1.OVL")in
 let raw=Fun.protect ~finally:(fun()->close_in channel)(fun()->let b=Bytes.create(in_channel_length channel)in really_input channel b 0(Bytes.length b);b)in
 let module B=Pli80.Publication_primitives_bridge in let t=B.create ~pli1:raw in
 let bad=Bytes.copy raw in Bytes.set bad 0x7af0 '\x00';rejects(fun()->B.create ~pli1:bad);
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
   assert(p.state.sp=0xf002&&p.state.pc=resume&&p.state.d=entry.d&&p.state.e=entry.e);
   assert(p.state.sign=state.sign&&p.state.zero=state.zero&&p.state.auxiliary_carry=state.auxiliary_carry&&p.state.parity=state.parity&&not p.state.carry);
   assert(p.state.b=0&&p.state.c=0);
   if entry_offset=0x7af0 then (assert(p.state.a=entry.a&&p.state.h=0xab&&p.state.l=0x4a);assert(p.compatibility_writes=[0xefff,0xab;0xeffe,0x49]))
   else assert(p.state.a=entry.e&&p.state.h=0xad&&p.state.l=0x9d&&p.compatibility_writes=[])
  done;
  rejects(fun()->B.prepare t ~call ~origin:(origin(entry_offset+1))~state:entry ~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with pc=0}~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with c=256}~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with d=256}~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with sp=65536}~memory);
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:entry ~memory:Bytes.empty);
  List.iter(fun address->let bad=Bytes.copy memory in Bytes.set bad address '\xff';
    rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:entry ~memory:bad))[0xf000;0x9cf0;0x9d49];
  let scratch=if entry_offset=0x7af0 then 0xae3e else 0xae45 in
  let bad=Bytes.copy memory in Bytes.set bad scratch(Char.chr(resume land 255));Bytes.set bad(scratch+1)(Char.chr(resume lsr 8));
  rejects(fun()->B.prepare t ~call ~origin:(origin entry_offset)~state:{entry with sp=scratch}~memory:bad)
 ) [0x7af0,0x7ea0;0x7b49,0x7eb2]
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
let ()=primitives();bridge();dispatch_failures();print_endline"publication width/order/ABI/alias/count tests passed"
