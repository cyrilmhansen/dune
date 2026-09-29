let expect = function Ok x->x|Error _->failwith"expected Runner success"
let at bytes address values=List.iteri(fun i b->Bytes.set bytes (address-0x100+i)(Char.chr b))values
let contains text needle=
  let n=String.length text and m=String.length needle in
  let rec loop i=i+m<=n && (String.sub text i m=needle || loop(i+1))in loop 0
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
  assert((List.hd first_frames).stack_slot=0xfffa);
  assert((List.nth first_frames 1).return_address=0x103);
  assert((List.nth first_frames 1).stack_slot=0xfffc);
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

let test_sp_rebased_software_continuation ()=
  let program=Bytes.make 0x50 '\000' in
  at program 0x100 [0xcd;0x10;0x01;0xc3;0x00;0x00];
  at program 0x110 [0x21;0x00;0x02;0xf9;0x21;0x23;0x01;0xe5;0x21;0x30;0x01;0xe9];
  at program 0x123 [0x21;0xfc;0xff;0xf9;0x0e;0x0c;0xcd;0x05;0x00;0xc9];
  at program 0x130 [0xc9];
  let w=Analysis.Event_witness.create ~run_id:"software-continuation"
    ~origin_at:(fun ~pc:_ ~fetched:_->None) in
  ignore(Runner.run_bytes ~max_steps:40
    ~on_step_state_pair:(fun ~step_index ~before ~after step->
      Analysis.Event_witness.observe_step w ~step_index ~before ~after step)
    ~on_bdos_call_state:(fun ~step_index ~state ~dma ~read_memory->
      Analysis.Event_witness.observe_bdos_call w ~step_index ~state ~dma ~read_memory)
    ~output:(fun _->())program |> expect);
  let events=Analysis.Event_witness.events w in
  assert(Analysis.Event_witness.transfer_mismatch_count w=0);
  let software=List.find_map(function
    |Analysis.Event_witness.Software_continuation_return x->Some x|_->None)events|>Option.get in
  assert(software.stack_slot=0x01fe && software.return_address=0x0123);
  assert(software.low_byte_writer.writer_step=4 && software.low_byte_writer.written_value=0x23);
  assert(software.high_byte_writer.writer_step=4 && software.high_byte_writer.written_value=0x01);
  assert(software.low_byte_writer.writer_disassembly="PUSH H");
  assert(software.consumed_step=7 && software.consumer_pc=0x130);
  assert(List.exists(function Analysis.Event_witness.Instruction i when i.pc=0x11b && i.disassembly="PCHL"->true|_->false)events);
  (match List.find_opt(function Analysis.Event_witness.Bdos_call _->true|_->false)events with
   |Some(Analysis.Event_witness.Bdos_call call)->
       assert(call.function_number=12 && call.certainty=Analysis.Event_witness.Certain);
       assert(List.length call.frames=2);
       assert((List.nth call.frames 0).stack_slot=0xfffa);
       assert((List.nth call.frames 1).stack_slot=0xfffc);
       assert((List.nth call.frames 1).return_address=0x0103)
   |_->assert false);
  let json=Buffer.create 2048 in Analysis.Event_witness.write_json ~output:(Buffer.add_string json)w;
  let json=Buffer.contents json in
  assert(contains json "software_continuation_return");
  assert(contains json "\"stack_slot\":510");
  assert(contains json "\"kind\":\"hardware_call\"")

let test_return_matches_dormant_hardware_slot ()=
  let program=Bytes.make 0x60 '\000' in
  at program 0x100 [0xcd;0x10;0x01;0x0e;0x0c;0xcd;0x05;0x00;0xc3;0x00;0x00];
  at program 0x110 [0x21;0x00;0x02;0xf9;0xcd;0x40;0x01];
  at program 0x140 [0x21;0xfc;0xff;0xf9;0x0e;0x0c;0xcd;0x05;0x00;0xc9];
  let w=Analysis.Event_witness.create ~run_id:"dormant-hardware-frame"
    ~origin_at:(fun ~pc:_ ~fetched:_->None) in
  ignore(Runner.run_bytes ~max_steps:40
    ~on_step_state_pair:(fun ~step_index ~before ~after step->
      Analysis.Event_witness.observe_step w ~step_index ~before ~after step)
    ~on_bdos_call_state:(fun ~step_index ~state ~dma ~read_memory->
      Analysis.Event_witness.observe_bdos_call w ~step_index ~state ~dma ~read_memory)
    ~output:(fun _->())program |> expect);
  assert(Analysis.Event_witness.transfer_mismatch_count w=0);
  let calls=List.filter_map(function
    |Analysis.Event_witness.Bdos_call{frames;certainty;_}->Some(frames,certainty)|_->None)
      (Analysis.Event_witness.events w) in
  assert(List.length calls=2);
  (match List.nth calls 0 with
   |frames,Analysis.Event_witness.Certain->
       assert(List.length frames=3);
       assert((List.nth frames 0).stack_slot=0xfffa);
       assert((List.nth frames 1).stack_slot=0x01fe);
       assert((List.nth frames 2).stack_slot=0xfffc)
   |_->assert false);
  (match List.nth calls 1 with
   |frames,Analysis.Event_witness.Certain->
       assert(List.length frames=2);
       assert((List.hd frames).stack_slot=0xfffc);
       assert((List.nth frames 1).stack_slot=0x01fe)
   |_->assert false)

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

let read_file path=
  let ch=open_in_bin path in
  Fun.protect ~finally:(fun()->close_in ch)(fun()->let n=in_channel_length ch in let b=Bytes.create n in really_input ch b 0 n;b)

let test_historical_call_context_if_available ()=
  match Sys.getenv_opt "RUNES_HISTORICAL_DIR" with
  |None->()
  |Some directory->
      let find name=read_file(Filename.concat directory name) in
      let experiment=Pli80.Experiment.run ~event_witnesses:true ~analysis:Pli80.Experiment.Execution {
        Pli80.Experiment.pli_com=find "PLI.COM";pli0_ovl=find "PLI0.OVL";
        pli1_ovl=find "PLI1.OVL";pli2_ovl=find "PLI2.OVL";
        source_name="OPTIMIST.PLI";source_bytes=find "OPTIMIST.PLI";
        module_name="OPTIMIST";command_tail=Bytes.of_string " OPTIMIST";max_steps=3_000_000} in
      let experiment=match experiment with Ok x->x|Error _->failwith"historical event-witness run failed" in
      assert(experiment.run.Runner.termination=Runner.Warm_boot);
      assert(experiment.run.steps=2_535_509);
      assert(contains experiment.console "NO ERROR(S) IN PASS 1");
      assert(contains experiment.console "NO ERROR(S) IN PASS 2");
      assert(contains experiment.console "END  COMPILATION");
      assert(experiment.int_bytes=None);
      (match experiment.rel_bytes with
       |Some rel->assert(Bytes.length rel=1_408);
           assert(Pli80.Experiment.sha256_hex rel="5fca1ffe38d11c30d20cfb99a23fe2baf002c569790bda83e09151cf36032b15")
       |None->assert false);
      let witnesses=Option.get experiment.event_witnesses in
      let events=Analysis.Event_witness.events witnesses in
      assert(Analysis.Event_witness.transfer_mismatch_count witnesses=0);
      assert(Analysis.Event_witness.hardware_return_count witnesses=95_504);
      assert(Analysis.Event_witness.software_continuation_count witnesses=194);
      let mismatch_at step=List.exists(function Analysis.Event_witness.Call_mismatch m->m.step_index=step|_->false)events in
      assert(not(mismatch_at 1_681_339));
      assert(not(mismatch_at 1_681_418));
      let soft=List.find_map(function
        |Analysis.Event_witness.Software_continuation_return x when x.consumed_step=1_681_339->Some x
        |_->None)events|>Option.get in
      assert(soft.stack_slot=0xffe4 && soft.return_address=0x42b4);
      assert(List.exists(function
        |Analysis.Event_witness.Hardware_frame_return{step_index=1_681_418;frame}->
            frame.call_step=1_674_802 && frame.stack_slot=0xfff2 && frame.return_address=0x434c
        |_->false)events);
      let mismatches=List.filter_map(function
        |Analysis.Event_witness.Call_mismatch m->Some(m.observed_target,
            Option.map(fun (f:Analysis.Event_witness.frame)->f.return_address)m.expected_frame,m.step_index)
        |_->None)events in
      let exact_pair=List.filter(fun(observed,expected,_)->observed=Some 0x42b4 && expected=Some 0x434c)mismatches in
      assert(exact_pair=[]);
      Printf.printf "historical event-witness stack reconstruction: old mismatches=372; new mismatches=%d; hardware-frame returns=%d; software continuations=%d; remaining 42B4/434C mismatches=%d\n"
        (Analysis.Event_witness.transfer_mismatch_count witnesses)
        (Analysis.Event_witness.hardware_return_count witnesses)
        (Analysis.Event_witness.software_continuation_count witnesses)(List.length exact_pair);
      List.iter(fun step->match List.find_opt(function
        |Analysis.Event_witness.Bdos_call c->c.step_index=step|_->false)events with
        |Some(Analysis.Event_witness.Bdos_call c)->Printf.printf "BDOS step %d: function=%d certainty=%s hardware_frames=%d\n"
            step c.function_number (match c.certainty with Certain->"certain"|Uncertain _->"uncertain") (List.length c.frames);
            assert(c.certainty=Certain && c.frames<>[])
        |_->Printf.printf "BDOS step %d: no call witness\n"step)
        [840_539;1_668_911;1_671_945;1_987_517;2_533_978]

let ()=test_ordinary_instruction_snapshots();test_instruction_old_memory_when_observed();test_host_boundary_and_two_requesters();test_unmatched_return_marks_context_uncertain();test_sp_rebased_software_continuation();test_return_matches_dormant_hardware_slot();test_file_event_keeps_fcb_and_call_context();test_historical_call_context_if_available()
