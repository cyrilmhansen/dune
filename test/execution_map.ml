open Analysis.Execution_map

let get_result = function Ok value -> value | Error _ -> failwith "expected success"

let image filename =
  Analysis.Execution_map.image_id ~drive:0 ~user:0 ~filename |> get_result

let run_steps map memory state count =
  let cpu = I8080.Cpu.create ~state ~bus:(I8080.Bus.create memory) in
  for step_index = 0 to count - 1 do
    match I8080.Cpu.step cpu with
    | Error _ -> failwith "CPU step failed in execution map test"
    | Ok step ->
        (match Analysis.Execution_map.observe_step map ~step_index step with
        | Ok () -> ()
        | Error _ -> failwith "unexpected instruction-byte conflict")
  done

let test_seed_repeated_and_bytes () =
  let module Map = Analysis.Execution_map in
  let map = Map.create () in
  let program = Bytes.of_string "\x3e\x42\xc3\x00\x01" in
  let id = image "SEED.COM" in
  assert (Map.seed_image map ~image:id ~runtime_base:0x0100 program = Ok ());
  let memory = I8080.Memory.create () in
  I8080.Memory.load memory ~address:0x0100 program;
  let state = I8080.State.create () in
  I8080.State.set_pc state 0x0100;
  run_steps map memory state 3;
  let entry =
    List.find (fun (entry : Map.instruction) -> entry.offset = 0)
      (Map.instructions map)
  in
  assert (entry.execution_count = 2);
  assert (entry.first_step_index = 0 && entry.last_step_index = 2);
  assert (entry.runtime_pcs = [ 0x0100 ]);
  assert (entry.opcode = 0x3e && entry.bytes = Bytes.of_string "\x3e\x42");
  assert (Map.byte_fetch_count map ~image:id ~offset:0 = 2);
  assert (Map.byte_fetch_count map ~image:id ~offset:1 = 2);
  assert (Map.byte_fetch_count map ~image:id ~offset:2 = 1);
  assert (Map.instruction_start_count map ~image:id ~offset:1 = 0);
  let summary = Map.image_summary map ~image:id |> Option.get in
  assert (summary.known_size = Some 5);
  assert (summary.known_byte_count = 5);
  assert (summary.fetched_byte_count = 7);
  assert (summary.total_instruction_executions = 3);
  assert (summary.unique_instruction_starts = 2)

let test_overlapping_image_replacement () =
  let module Map = Analysis.Execution_map in
  let map = Map.create () in
  let image_a = image "IMAGE_A.BIN" and image_b = image "IMAGE_B.BIN" in
  let memory = I8080.Memory.create () in
  let state = I8080.State.create () in
  I8080.Memory.write memory 0x2200 0x00;
  assert (Map.seed_image map ~image:image_a ~runtime_base:0x2200 (Bytes.of_string "\x00") = Ok ());
  I8080.State.set_pc state 0x2200;
  run_steps map memory state 1;
  assert (Map.seed_image map ~image:image_b ~runtime_base:0x2200 (Bytes.of_string "\x00") = Ok ());
  I8080.State.set_pc state 0x2200;
  run_steps map memory state 1;
  assert (Map.instruction_start_count map ~image:image_a ~offset:0 = 1);
  assert (Map.instruction_start_count map ~image:image_b ~offset:0 = 1);
  assert (List.length (Map.instructions map) = 2)

let test_write_invalidation_and_mixed_fetch () =
  let module Map = Analysis.Execution_map in
  let map = Map.create () in
  let image_a = image "WRITER.COM" and image_b = image "OPERAND.BIN" in
  let bytes = Bytes.of_string "\x36\x55" in (* MVI M,55 *)
  assert (Map.seed_image map ~image:image_a ~runtime_base:0x0100 bytes = Ok ());
  let memory = I8080.Memory.create () in
  I8080.Memory.load memory ~address:0x0100 bytes;
  let state = I8080.State.create () in
  I8080.State.set_pc state 0x0100;
  I8080.State.set_hl state 0x0101;
  run_steps map memory state 1;
  assert (Map.instruction_start_count map ~image:image_a ~offset:0 = 1);
  assert (Map.byte_fetch_count map ~image:image_a ~offset:1 = 1);
  assert (Map.origin_at map 0x0101 = Map.Unknown);
  assert (I8080.Memory.read memory 0x0101 = 0x55);
  let mixed = Map.create () in
  let mem = I8080.Memory.create () in
  I8080.Memory.load mem ~address:0x2200 (Bytes.of_string "\x3e\x42");
  assert (Map.seed_image mixed ~image:image_a ~runtime_base:0x2200 (Bytes.of_string "\x3e") = Ok ());
  assert (Map.seed_image mixed ~image:image_b ~runtime_base:0x2201 (Bytes.of_string "\x42") = Ok ());
  let st = I8080.State.create () in
  I8080.State.set_pc st 0x2200;
  run_steps mixed mem st 1;
  let result = Map.summary mixed in
  assert (result.mixed_or_unresolved_executions = 1);
  assert (result.attributed_instruction_executions = 0);
  assert (Map.byte_fetch_count mixed ~image:image_a ~offset:0 = 1);
  assert (Map.byte_fetch_count mixed ~image:image_b ~offset:0 = 1)

let test_control_flow_cross_image () =
  let module Map = Analysis.Execution_map in
  let map = Map.create () in
  let source = image "CALLER.COM" and target = image "OVERLAY.OVL" in
  let memory = I8080.Memory.create () in
  I8080.Memory.load memory ~address:0x0100 (Bytes.of_string "\xc3\x00\x22");
  I8080.Memory.write memory 0x2200 0x00;
  assert (Map.seed_image map ~image:source ~runtime_base:0x0100 (Bytes.of_string "\xc3\x00\x22") = Ok ());
  assert (Map.seed_image map ~image:target ~runtime_base:0x2200 (Bytes.of_string "\x00") = Ok ());
  let state = I8080.State.create () in
  I8080.State.set_pc state 0x0100;
  run_steps map memory state 1;
  let edges = Map.cross_image_transitions map in
  assert (List.length edges = 1);
  let edge = List.hd edges in
  assert (edge.source = Map.Image_instruction { image = source; offset = 0 });
  assert (edge.kind = Map.Jump && edge.taken = Some true);
  assert (edge.runtime_target = Some 0x2200);
  assert (edge.target_origin = Some (Map.Image_byte { image = target; offset = 0 }));
  assert (edge.count = 1);
  let call_map = Map.create () in
  let call_memory = I8080.Memory.create () in
  I8080.Memory.load call_memory ~address:0x0100 (Bytes.of_string "\xcd\x00\x22");
  I8080.Memory.write call_memory 0x2200 0x00;
  assert (Map.seed_image call_map ~image:source ~runtime_base:0x0100 (Bytes.of_string "\xcd\x00\x22") = Ok ());
  assert (Map.seed_image call_map ~image:target ~runtime_base:0x2200 (Bytes.of_string "\x00") = Ok ());
  let call_state = I8080.State.create () in
  I8080.State.set_pc call_state 0x0100;
  run_steps call_map call_memory call_state 1;
  match Map.control_flow_observations call_map with
  | [ call ] ->
      assert (call.kind = Map.Call && call.runtime_target = Some 0x2200);
      assert (call.target_origin = Some (Map.Image_byte { image = target; offset = 0 }))
  | _ -> failwith "expected CALL target observation"

let test_bdos_sites_call_and_jump () =
  let module Map = Analysis.Execution_map in
  let test program filename expected_pc =
    let map = Map.create () in
    let id = image filename in
    let filesystem = Cpm.Filesystem.create () in
    assert (Map.seed_image map ~image:id ~runtime_base:0x0100 program = Ok ());
    let result =
      Runner.run_bytes ~filesystem ~max_steps:100
        ~on_event:(Map.observe_runner_event map)
        ~output:(fun _ -> ()) program
    in
    (match result with Ok _ -> () | Error _ -> failwith "tiny BDOS transfer failed");
    match Map.bdos_sites map with
    | [ site ] ->
        assert (site.source = Map.Image_instruction { image = id; offset = expected_pc - 0x0100 });
        assert (site.source_pc = Some expected_pc);
        assert (site.function_number = 0 && site.count = 1)
    | _ -> failwith "expected one attributed BDOS site"
  in
  test (Bytes.of_string "\x0e\x00\xcd\x05\x00") "BDOSCALL.COM" 0x0102;
  test (Bytes.of_string "\x0e\x00\xc3\x05\x00") "BDOSJMP.COM" 0x0102

let test_bdos_record_events () =
  let memory = I8080.Memory.create () in
  let filesystem = Cpm.Filesystem.create () in
  let data = Bytes.init 128 (fun index -> Char.chr index) in
  assert (Cpm.Filesystem.add_file filesystem ~name:"RECORD.BIN" data = Ok ());
  let runtime = Cpm.Bdos.create ~filesystem in
  let fcb = Cpm.Fcb.at memory ~address:0x3000 in
  Cpm.Fcb.set_drive fcb 0;
  String.iteri (fun i c -> Cpm.Fcb.set fcb ~offset:(1 + i) (Char.code c)) "RECORD  ";
  String.iteri (fun i c -> Cpm.Fcb.set fcb ~offset:(9 + i) (Char.code c)) "BIN";
  let state = I8080.State.create () in
  I8080.State.set_c state 15;
  I8080.State.set_de state 0x3000;
  ignore (Cpm.Bdos.dispatch ~runtime ~memory ~state ~output:(fun _ -> ()) |> get_result);
  let seen = ref None in
  I8080.State.set_c state 20;
  ignore
    (Cpm.Bdos.dispatch_instrumented ~runtime ~memory ~state ~output:(fun _ -> ())
       ~on_event:(fun event -> seen := Some event)
    |> get_result);
  (match !seen with
  | Some (Cpm.Bdos.Read_record { logical_record = 0; dma = 0x0080; data = event_data; _ }) ->
      assert (Bytes.equal data event_data);
      Bytes.set event_data 0 '\xff';
      assert (I8080.Memory.read memory 0x0080 = 0)
  | _ -> failwith "missing successful BDOS read event");
  let output_fcb = Cpm.Fcb.at memory ~address:0x3100 in
  Cpm.Fcb.set_drive output_fcb 0;
  String.iteri (fun i c -> Cpm.Fcb.set output_fcb ~offset:(1 + i) (Char.code c)) "OUTPUT  ";
  String.iteri (fun i c -> Cpm.Fcb.set output_fcb ~offset:(9 + i) (Char.code c)) "BIN";
  I8080.State.set_c state 22;
  I8080.State.set_de state 0x3100;
  ignore (Cpm.Bdos.dispatch ~runtime ~memory ~state ~output:(fun _ -> ()) |> get_result);
  let output_record = Bytes.init 128 (fun index -> Char.chr (255 - index)) in
  I8080.Memory.load memory ~address:0x4000 output_record;
  I8080.State.set_c state 26;
  I8080.State.set_de state 0x4000;
  ignore (Cpm.Bdos.dispatch ~runtime ~memory ~state ~output:(fun _ -> ()) |> get_result);
  let write_event = ref None in
  I8080.State.set_c state 21;
  I8080.State.set_de state 0x3100;
  ignore
    (Cpm.Bdos.dispatch_instrumented ~runtime ~memory ~state ~output:(fun _ -> ())
       ~on_event:(fun event -> write_event := Some event)
    |> get_result);
  (match !write_event with
  | Some (Cpm.Bdos.Write_record { file; logical_record = 0; dma = 0x4000; data = event_data }) ->
      assert (file.name = "OUTPUT.BIN");
      assert (Bytes.equal output_record event_data);
      Bytes.set event_data 0 '\x00';
      assert (Cpm.Filesystem.get_file filesystem ~name:"OUTPUT.BIN" ()
              = Ok (Some output_record))
  | _ -> failwith "missing successful BDOS write event")

let test_runner_bdos_transfer_bridge () =
  let module Map = Analysis.Execution_map in
  let program =
    Bytes.of_string
      "\x0e\x0f\x11\x5c\x00\xcd\x05\x00\x0e\x1a\x11\x00\x20\xcd\x05\x00\x0e\x14\x11\x5c\x00\xcd\x05\x00\xc3\x00\x00"
  in
  let id = image "BRIDGE.COM" in
  let map = Map.create () in
  assert (Map.seed_image map ~image:id ~runtime_base:0x0100 program = Ok ());
  let filesystem = Cpm.Filesystem.create () in
  let bytes = Bytes.init 128 (fun index -> Char.chr ((index * 3) land 0xff)) in
  assert (Cpm.Filesystem.add_file filesystem ~name:"RECORD.BIN" bytes = Ok ());
  let read_index = ref None in
  let result =
    Runner.run_bytes ~filesystem ~command_tail:(Bytes.of_string " RECORD.BIN")
      ~max_steps:100 ~on_event:(Map.observe_runner_event map)
      ~on_bdos_event:(fun ~step_index event ->
        Map.observe_bdos_event map event;
        match event with Cpm.Bdos.Read_record _ -> read_index := Some step_index | Cpm.Bdos.Write_record _ -> ())
      ~output:(fun _ -> ()) program
  in
  (match result with Ok _ -> () | Error _ -> failwith "BDOS record bridge program failed");
  assert (!read_index = Some 11);
  assert (Map.byte_at map ~image:(image "RECORD.BIN") ~offset:0 = Some 0x00);
  assert (Map.origin_at map 0x2000 = Map.Image_byte { image = image "RECORD.BIN"; offset = 0 });
  let sites = Map.bdos_sites map in
  assert (List.length sites = 3);
  assert (List.for_all (fun site -> match site.source with Map.Image_instruction _ -> true | _ -> false) sites)

let test_conflicting_instruction_bytes () =
  let module Map = Analysis.Execution_map in
  let map = Map.create () in
  let id = image "CONFLICT.COM" in
  let original = Bytes.of_string "\x00" in
  assert (Map.seed_image map ~image:id ~runtime_base:0x0100 original = Ok ());
  let memory = I8080.Memory.create () in
  I8080.Memory.write memory 0x0100 0x00;
  let state = I8080.State.create () in
  I8080.State.set_pc state 0x0100;
  let cpu = I8080.Cpu.create ~state ~bus:(I8080.Bus.create memory) in
  let first = I8080.Cpu.step cpu |> get_result in
  assert (Map.observe_step map ~step_index:0 first = Ok ());
  I8080.State.set_pc state 0x0100;
  I8080.Memory.write memory 0x0100 0x76;
  let second = I8080.Cpu.step cpu |> get_result in
  assert (Map.observe_step map ~step_index:1 second = Error (Map.Conflicting_instruction_bytes { image = id; offset = 0 }))

let test_interrupt_origin_not_counted_as_memory_fetch () =
  let module Map = Analysis.Execution_map in
  let map = Map.create () in
  let id = image "INTRPT.COM" in
  let bytes = Bytes.of_string "\xfb\x00\x3e\x42" in
  assert (Map.seed_image map ~image:id ~runtime_base:0x0100 bytes = Ok ());
  let memory = I8080.Memory.create () in
  I8080.Memory.load memory ~address:0x0100 bytes;
  let state = I8080.State.create () in
  I8080.State.set_pc state 0x0100;
  let cpu = I8080.Cpu.create ~state ~bus:(I8080.Bus.create memory) in
  for step_index = 0 to 1 do
    let step = I8080.Cpu.step cpu |> get_result in
    assert (Map.observe_step map ~step_index step = Ok ())
  done;
  let injected = I8080.Cpu.step ~interrupt:(Bytes.of_string "\x00") cpu |> get_result in
  assert (Map.observe_step map ~step_index:2 injected = Ok ());
  assert (Map.byte_fetch_count map ~image:id ~offset:2 = 0);
  assert ((Map.summary map).interrupt_acknowledge_executions = 1)

let () =
  test_seed_repeated_and_bytes ();
  test_overlapping_image_replacement ();
  test_write_invalidation_and_mixed_fetch ();
  test_control_flow_cross_image ();
  test_bdos_sites_call_and_jump ();
  test_bdos_record_events ();
  test_runner_bdos_transfer_bridge ();
  test_conflicting_instruction_bytes ();
  test_interrupt_origin_not_counted_as_memory_fetch ()
