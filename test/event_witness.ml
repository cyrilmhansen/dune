let expect = function Ok x->x|Error _->failwith"expected Runner success"
let at bytes address values=List.iteri(fun i b->Bytes.set bytes (address-0x100+i)(Char.chr b))values
let test_host_boundary_and_two_requesters ()=
  let program=Bytes.make 0x28 '\000' in
  at program 0x100 [0xcd;0x10;0x01;0xcd;0x20;0x01;0xc3;0x00;0x00];
  at program 0x110 [0x0e;0x0c;0xcd;0x05;0x00;0xc9];
  at program 0x120 [0x0e;0x0c;0xcd;0x05;0x00;0xc9];
  let w=Analysis.Event_witness.create ~run_id:"synthetic" ~origin_at:(fun ~pc:_ ~fetched:_->None) in
  let result=Runner.run_bytes ~max_steps:40
    ~on_step_state_pair:(fun ~step_index ~before ~after step->Analysis.Event_witness.observe_step w ~step_index ~before ~after step)
    ~on_bdos_call_state:(fun ~step_index ~state ~dma ~read_memory->Analysis.Event_witness.observe_bdos_call w ~step_index ~state ~dma ~read_memory)
    ~on_bdos_effect_at:(fun ~step_index external_effect->Analysis.Event_witness.observe_host_effect w ~step_index external_effect)
    ~on_bdos_resume:(fun ~step_index ~state->Analysis.Event_witness.observe_bdos_resume w ~step_index state)
    ~output:(fun _->()) program |> expect in
  assert(result.Runner.termination=Runner.Warm_boot);
  let events=Analysis.Event_witness.events w in
  let calls=List.filter_map(function Analysis.Event_witness.Bdos_call c->Some(c.step_index,c.function_number,c.bridge_step,c.frames,c.state)|_->None)events in
  assert(List.length calls=2);
  let first=List.nth calls 0 and second=List.nth calls 1 in
  let first_boundary,first_function,first_bridge,first_frames,first_state=first and _,second_function,second_bridge,second_frames,_=second in
  assert(first_function=12 && second_function=12);
  assert(first_bridge=Some 2 && second_bridge=Some 7);
  assert(List.length first_frames=2 && List.length second_frames=2);
  assert((List.hd first_frames).call_pc=0x112 && (List.hd second_frames).call_pc=0x122);
  assert((List.hd first_frames).return_address=0x115);
  assert((List.nth first_frames 1).return_address=0x103);
  let resume_steps=List.filter_map(function Analysis.Event_witness.Bdos_resume x->Some(x.step_index,x.state)|_->None)events in
  assert(List.length resume_steps=2);
  let resume_step,resume=List.hd resume_steps in
  assert(resume_step=first_boundary);
  assert(resume.a=0x22);
  let returned=List.find(function Analysis.Event_witness.Instruction i->i.step_index=resume_step && i.pc=5|_->false)events in
  (match returned with Analysis.Event_witness.Instruction i->assert(i.before.a=resume.a);assert(i.sp_before=resume.sp)|_->assert false);
  (* Host changes are not reconstructed from the prior instruction's post-state. *)
  let call_state=first_state in
  assert(call_state.a<>resume.a);
  let json=Buffer.create 512 in Analysis.Event_witness.write_json ~output:(Buffer.add_string json) w;
  let text=Buffer.contents json in
  assert(String.starts_with ~prefix:"RUNES_EVENT_WITNESSES 1\n" text);
  assert(String.contains text '"');
  let chunks=ref[]and index=Buffer.create 512 in
  Analysis.Event_witness.write_chunked_json ~chunk_size:2
    ~write_chunk:(fun id bytes->chunks:=(id,bytes)::!chunks)
    ~write_index:(Buffer.add_string index)w;
  assert(List.length !chunks>1);
  assert(String.starts_with ~prefix:"RUNES_EVENT_WITNESSES 1\n"(Buffer.contents index));
  assert(String.contains(Buffer.contents index)'i');
  List.iter(fun(_,chunk)->assert(String.starts_with ~prefix:"RUNES_EVENT_WITNESS_CHUNK 1\n"chunk);assert(String.contains chunk 's'))!chunks

let test_ordinary_instruction_snapshots ()=
  let program=Bytes.of_string "\x21\x00\x02\x36\x5a\x7e\xc3\x00\x00" in
  let w=Analysis.Event_witness.create ~run_id:"ordinary" ~origin_at:(fun ~pc:_ ~fetched:_->None) in
  ignore(Runner.run_bytes ~on_step_state_pair:(fun ~step_index ~before ~after step->Analysis.Event_witness.observe_step w ~step_index ~before ~after step)
    ~output:(fun _->())program |> expect);
  let find step=List.find_map(function Analysis.Event_witness.Instruction i when i.step_index=step->Some i|_->None)(Analysis.Event_witness.events w)|>Option.get in
  let store=find 1 and load=find 2 in
  assert(load.before.a=0 && load.after.a=0x5a && load.pc=0x105 && load.pc_after=0x106);
  (match store.writes with [{address=0x200;old_value=None;new_value=0x5a}]->()|_->assert false);
  (match load.reads with [{address=0x200;value=0x5a}]->()|_->assert false)

let test_instruction_old_memory_when_observed ()=
  let program=Bytes.of_string "\x21\x34\x12\x31\x00\x02\xe3\xc3\x00\x00" in
  let w=Analysis.Event_witness.create ~run_id:"old-memory" ~origin_at:(fun ~pc:_ ~fetched:_->None) in
  ignore(Runner.run_bytes ~on_step_state_pair:(fun ~step_index ~before ~after step->Analysis.Event_witness.observe_step w ~step_index ~before ~after step)
    ~output:(fun _->())program |> expect);
  let xthl=List.find_map(function Analysis.Event_witness.Instruction i when i.disassembly="XTHL"->Some i|_->None)(Analysis.Event_witness.events w)|>Option.get in
  (match xthl.reads,xthl.writes with
   |[{address=0x200;value=0};{address=0x201;value=0}],
    [{address=0x200;old_value=Some 0;new_value=0x34};{address=0x201;old_value=Some 0;new_value=0x12}]->()
   |_->assert false)

let test_unmatched_return_marks_context_uncertain ()=
  let program=Bytes.of_string"\xc9" in
  let w=Analysis.Event_witness.create ~run_id:"mismatch" ~origin_at:(fun ~pc:_ ~fetched:_->None) in
  ignore(Runner.run_bytes ~on_step_state_pair:(fun ~step_index ~before ~after step->Analysis.Event_witness.observe_step w ~step_index ~before ~after step)
    ~output:(fun _->())program |> expect);
  assert(Analysis.Event_witness.transfer_mismatch_count w=1);
  assert(List.exists(function Analysis.Event_witness.Call_mismatch{step_index=0;observed_target=Some 0;expected_frame=None}->true|_->false)(Analysis.Event_witness.events w))

let test_file_event_keeps_fcb_and_call_context ()=
  let fs=Cpm.Filesystem.create() in
  assert(Cpm.Filesystem.add_file fs ~name:"FOO.DAT" (Bytes.make 128 '\x44')=Ok());
  let program=Bytes.of_string"\x0e\x0f\x11\x5c\x00\xcd\x05\x00\xc3\x00\x00" in
  let w=Analysis.Event_witness.create ~run_id:"file" ~origin_at:(fun ~pc:_ ~fetched:_->None) in
  ignore(Runner.run_bytes ~filesystem:fs ~command_tail:(Bytes.of_string" FOO.DAT")
    ~on_step_state_pair:(fun ~step_index ~before ~after step->Analysis.Event_witness.observe_step w ~step_index ~before ~after step)
    ~on_bdos_call_state:(fun ~step_index ~state ~dma ~read_memory->Analysis.Event_witness.observe_bdos_call w ~step_index ~state ~dma ~read_memory)
    ~on_bdos_file_event:(fun ~step_index event->Analysis.Event_witness.observe_file_operation w ~step_index event)
    ~on_bdos_effect_at:(fun ~step_index external_effect->Analysis.Event_witness.observe_host_effect w ~step_index external_effect)
    ~on_bdos_resume:(fun ~step_index ~state->Analysis.Event_witness.observe_bdos_resume w ~step_index state)
    ~output:(fun _->())program |> expect);
  let events=Analysis.Event_witness.events w in
  let file=List.find(function Analysis.Event_witness.File_operation{operation="open";_}->true|_->false)events in
  let step=match file with Analysis.Event_witness.File_operation e->e.step_index|_->assert false in
  let call=List.find(function Analysis.Event_witness.Bdos_call c->c.step_index=step|_->false)events in
  (match call with Analysis.Event_witness.Bdos_call c->
    assert(c.function_number=15 && c.fcb_address=Some 0x5c && c.dma=0x80);
    assert(c.fcb_bytes<>None && c.frames<>[] && c.certainty=Analysis.Event_witness.Certain)
   |_->assert false);
  let resume_index=List.find_index(function Analysis.Event_witness.Bdos_resume e->e.step_index=step|_->false)events in
  let file_index=List.find_index(function Analysis.Event_witness.File_operation e->e.step_index=step|_->false)events in
  let call_index=List.find_index(function Analysis.Event_witness.Bdos_call e->e.step_index=step|_->false)events in
  let effect_indices=List.filter_map(fun(index,event)->match event with Analysis.Event_witness.Host_effect e when e.step_index=step->Some index|_->None)(List.mapi(fun i e->i,e)events) in
  assert(Option.get call_index<Option.get file_index && Option.get file_index<Option.get resume_index);
  assert(List.for_all(fun index->index>Option.get file_index && index<Option.get resume_index)effect_indices)

let ()=test_ordinary_instruction_snapshots();test_instruction_old_memory_when_observed();test_host_boundary_and_two_requesters();test_unmatched_return_marks_context_uncertain();test_file_event_keeps_fcb_and_call_context()
