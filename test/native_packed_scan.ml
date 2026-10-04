[@@@warning "-4-40-41-42"]
let rejects f = match f() with exception Invalid_argument _->()|_->failwith"Unsupported input accepted"
let native_unit () =
  rejects(fun()->Pli80_host.State.of_bytes Bytes.empty);
  let m=Pli80_host.State.of_bytes(Bytes.make 65536 '\000') in
  List.iter(fun n->rejects(fun()->Pli80_host.State.read m n))[-1;65536];
  List.iter(fun n->rejects(fun()->Pli80_host.State.write m 0 n))[-1;256];
  List.iter(fun n->rejects(fun()->Pli80_host.Packed_scan.run m ~position:n ~protected:[]))[-1;256];
  rejects(fun()->Pli80_host.Packed_scan.run m ~position:0 ~protected:[0xae4d]);
  rejects(fun()->Pli80_host.Packed_scan.run m ~position:0 ~protected:[0xab49]);
  for original=0 to 65535 do
    Pli80_host.State.write m 0xab49 (original land 255);
    Pli80_host.State.write m 0xab4a (original lsr 8);
    Pli80_host.State.write m 0xae39 (original land 255);
    let r=Pli80_host.Packed_scan.run m ~position:0 ~protected:[] in
    (* Independent oracle: first unequal adjacent original bits, ending
       with an appended zero. No native shift implementation supplies it. *)
    let bit i=if i=16 then 0 else (original lsr (15-i))land 1 in
    let rec stop i=if i=16 || bit(i-1)<>bit i then i else stop(i+1) in
    let expected=stop 1 in
    assert(r.shifts=expected && r.counter=16-expected);
    assert(r.shifted_word=(original lsl expected)land 65535);
    assert(Pli80_host.State.read m 0xad08=r.counter);
    assert(r.discarded_ae39=original land 255);
    assert(List.length r.writes=3*expected+7);
    let decrements=List.filter(fun(w:Pli80_host.Packed_scan.write)->w.phase="counter_decrement")r.writes in
    assert(List.length decrements=expected-1)
  done
let boundary_view () =
  let observations=ref [] in
  let program=Bytes.of_string"\x3e\x07\x32\x00\x20\xc3\x00\x00" in
  let callback ~step_index b =
    let memory=b.Runner.copy_memory()in
    assert(Bytes.length memory=65536);Bytes.set memory 0x100 '\000';
    assert(b.read_memory 0x100=0x3e);
    observations:=(step_index,b.state.pc,b.read_memory 0x2000)::!observations in
  let r=Runner.run_bytes ~on_before_instruction:callback ~output:ignore program in
  assert(match r with Ok r->r.steps=3 && r.termination=Runner.Warm_boot|_->false);
  assert(List.rev !observations=[0,0x100,0;1,0x102,0;2,0x105,7])
let transitions () =
  let executed=ref [] and boundaries=ref [] in
  let intercept ~step_index:_ boundary =
    if boundary.Runner.state.pc=0x100 then
      Runner.Apply_host_transition{memory_writes=[0x2000,7];next_state={boundary.state with pc=0x101;b=0xab;carry=true}}
    else Runner.Continue_guest_execution in
  let on_before_instruction ~step_index b=boundaries:=(step_index,b.Runner.state.pc)::!boundaries in
  let r=Runner.run_bytes ~intercept ~on_before_instruction ~on_step:(fun s->executed:=I8080.Step.pc_before s::!executed)
      ~output:ignore(Bytes.of_string "\x00\xc3\x00\x00") in
  assert(match r with Ok r->r.steps=1 && r.t_states=10 && r.host_transitions=1|_->false);
  assert(!executed=[0x101] && List.rev !boundaries=[0,0x100;0,0x101]);
  List.iter(fun writes->
    let intercept ~step_index:_ b=Runner.Apply_host_transition{memory_writes=writes;next_state={b.Runner.state with pc=0}}in
    assert(match Runner.run_bytes ~intercept ~output:ignore(Bytes.of_string "\x00")with
      |Error(Runner.Invalid_host_transition _)->true|_->false)) [[-1,0];[65536,0];[0x2000,256];[0x2000,7;0x2001,(-1)]];
  let bad ~step_index:_ b=Runner.Apply_host_transition{memory_writes=[];next_state={b.Runner.state with a=256}} in
  assert(match Runner.run_bytes ~intercept:bad ~output:ignore(Bytes.of_string "\x00")with Error(Runner.Invalid_host_transition _)->true|_->false);
  let loop ~step_index:_ b=Runner.Apply_host_transition{memory_writes=[];next_state=b.Runner.state}in
  assert(match Runner.run_bytes ~max_steps:3 ~intercept:loop ~output:ignore(Bytes.of_string "\x00")with Error(Runner.Step_limit_exceeded{steps=0;max_steps=3})->true|_->false)

let bridge_negatives () =
  match Sys.getenv_opt "RUNES_HOST_IMAGES" with
  |None->print_endline "Bridge image tests available with RUNES_HOST_IMAGES"
  |Some directory->
    let read name=let c=open_in_bin(Filename.concat directory name)in Fun.protect ~finally:(fun()->close_in c)
      (fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)in
    let resident=read "PLI.COM"and overlay=read "PLI1.OVL"in
    let module B=Pli80.Packed_scan_bridge in
    rejects(fun()->B.create ~pli_com:Bytes.empty ~pli1:overlay);
    let changed=Bytes.copy overlay in Bytes.set changed 0 '\000';
    rejects(fun()->B.create ~pli_com:resident ~pli1:changed);
    let bridge=B.create ~pli_com:resident ~pli1:overlay in
    let memory=Bytes.make 65536 '\000'in Bytes.blit resident 0 memory 0x100(Bytes.length resident);Bytes.blit overlay 0 memory 0x2200(Bytes.length overlay);
    Bytes.set memory 0xf000 '\x3a';Bytes.set memory 0xf001 '\x9e';
    let state:Runner.state_snapshot={a=0;b=0;c=0;d=0;e=0;h=0;l=0;sp=0xf000;pc=0x9dbf;sign=false;zero=false;auxiliary_carry=false;parity=false;carry=false}in
    let image:Cpm.Filesystem.key={drive=0;user=0;name="PLI1.OVL"}in
    let origin=Analysis.Execution_map.Image_byte{image;offset=0x7bbf}in
    ignore(B.prepare bridge ~origin ~state ~memory);
    let fetched=Bytes.of_string "\xcd\xbf\x9d" in
    let decoded=match I8080.Decode.decode fetched ~offset:0 with Ok d->d|_->assert false in
    let fake=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:0x9e36 ~pc_after:0x9dbf ~decoded ~fetched_bytes:fetched
      ~memory_accesses:[I8080.Step.Write{address=state.sp;value=0x3a};I8080.Step.Write{address=state.sp+1;value=0x9e}]
      ~control_flow:(I8080.Step.Call{target=0x9dbf;taken=true}) in
    (* Same-valued return bytes at the correct slot still lack the required
       actual +7C37 CALL producer. Equality alone does not pass the bridge. *)
    rejects(fun()->B.verify_call ~before:{state with sp=state.sp+2;pc=0x9e36} ~after:state fake ~entry:state);
    rejects(fun()->B.prepare bridge ~origin ~state ~memory:Bytes.empty);
    rejects(fun()->B.prepare bridge ~origin ~state:{state with pc=0x9dc0} ~memory);
    rejects(fun()->B.prepare bridge ~origin:Analysis.Execution_map.Unknown ~state ~memory);
    rejects(fun()->B.prepare bridge ~origin:(Analysis.Execution_map.Image_byte{image={image with name="PLI2.OVL"};offset=0x7bbf})~state ~memory);
    let bad=Bytes.copy memory in Bytes.set bad 0xf000 '\000';rejects(fun()->B.prepare bridge ~origin ~state ~memory:bad);
    let bad=Bytes.copy memory in Bytes.set bad 0x9dbf '\000';rejects(fun()->B.prepare bridge ~origin ~state ~memory:bad);
    let bad=Bytes.copy memory in Bytes.set bad 0xae4d '\x3a';Bytes.set bad 0xae4e '\x9e';
    rejects(fun()->B.prepare bridge ~origin ~state:{state with sp=0xae4d} ~memory:bad);
    (* AC is not uniformly true: FFFF's sixteenth shift changes the top bit
       when the saved counter is already zero, so both ANA operands are zero. *)
    Bytes.set memory 0xab49 '\xff';Bytes.set memory 0xab4a '\xff';
    let p=B.prepare bridge ~origin ~state ~memory in
    assert(p.result.shifts=16 && p.result.counter=0 && not p.state.auxiliary_carry && p.state.zero && p.state.parity && not p.state.carry);
    Bytes.set memory 0xffff '\x3a';Bytes.set memory 0 '\x9e';
    let wrapped=B.prepare bridge ~origin ~state:{state with sp=65535} ~memory in
    assert(wrapped.state.sp=1 && Char.code(Bytes.get wrapped.memory 0xffff)=0x3a && Char.code(Bytes.get wrapped.memory 0)=0x9e);
    print_endline "Historical bridge identity/alias/continuation negatives and AC edge passed"

let () = native_unit();boundary_view();transitions();bridge_negatives();print_endline"Native algorithm exhaustive65536 and generic read-only boundary tests passed"
