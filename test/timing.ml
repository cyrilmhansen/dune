let step opcode bytes flow =
  let fetched = Bytes.of_string bytes in
  let decoded =
    match I8080.Decode.decode fetched ~offset:0 with
    | Ok decoded -> decoded
    | Error _ -> failwith "test instruction failed to decode"
  in
  assert (decoded.opcode = opcode);
  I8080.Step.create ~source:I8080.Step.Memory ~pc_before:0x100 ~pc_after:0x100
    ~decoded ~fetched_bytes:fetched ~memory_accesses:[] ~control_flow:flow

let expect opcode bytes flow cycles =
  let actual = I8080.Timing.cost (step opcode bytes flow) in
  if actual <> cycles then
    failwith
      (Printf.sprintf "opcode %02X: expected %d T-states, got %d" opcode cycles actual)

let test_fixed_costs () =
  List.iter
    (fun (opcode, bytes, flow, cycles) -> expect opcode bytes flow cycles)
    [
      (0x00, "\x00", I8080.Step.Sequential, 4); (* NOP *)
      (0x41, "\x41", I8080.Step.Sequential, 5); (* MOV B,C *)
      (0x46, "\x46", I8080.Step.Sequential, 7); (* MOV B,M *)
      (0x36, "\x36\x42", I8080.Step.Sequential, 10); (* MVI M,42H *)
      (0x21, "\x21\x34\x12", I8080.Step.Sequential, 10); (* LXI H,1234H *)
      (0x3a, "\x3a\x34\x12", I8080.Step.Sequential, 13); (* LDA *)
      (0x2a, "\x2a\x34\x12", I8080.Step.Sequential, 16); (* LHLD *)
      (0x34, "\x34", I8080.Step.Sequential, 10); (* INR M *)
      (0x09, "\x09", I8080.Step.Sequential, 10); (* DAD B *)
      (0xc5, "\xc5", I8080.Step.Sequential, 11); (* PUSH B *)
      (0xc1, "\xc1", I8080.Step.Sequential, 10); (* POP B *)
      (0xe3, "\xe3", I8080.Step.Sequential, 18); (* XTHL *)
      (0xd3, "\xd3\x10", I8080.Step.Sequential, 10); (* OUT *)
      (0x76, "\x76", I8080.Step.Halt, 7);
    ]

let test_conditional_costs () =
  let jump taken = I8080.Step.Jump { target = 0x1234; taken } in
  let call taken = I8080.Step.Call { target = 0x1234; taken } in
  let return taken = I8080.Step.Return { target = (if taken then Some 0x103 else None); taken } in
  expect 0xc2 "\xc2\x34\x12" (jump true) 10;
  expect 0xc2 "\xc2\x34\x12" (jump false) 10;
  expect 0xc4 "\xc4\x34\x12" (call true) 17;
  expect 0xc4 "\xc4\x34\x12" (call false) 11;
  expect 0xc0 "\xc0" (return true) 11;
  expect 0xc0 "\xc0" (return false) 5

let test_aliases_and_complete_opcode_domain () =
  List.iter
    (fun opcode ->
      let info = I8080.Decode.opcode_info opcode in
      assert (info.encoding_status = I8080.Decode.Undocumented_alias);
      let bytes = Bytes.make info.instruction_length '\000' in
      Bytes.set bytes 0 (Char.chr opcode);
      let decoded = Result.get_ok (I8080.Decode.decode bytes ~offset:0) in
      let flow =
        match decoded.instr with
        | I8080.Instr.Jump (Some _, target) -> I8080.Step.Jump { target; taken = false }
        | I8080.Instr.Jump (None, target) -> I8080.Step.Jump { target; taken = true }
        | I8080.Instr.Call (Some _, target) -> I8080.Step.Call { target; taken = false }
        | I8080.Instr.Call (None, target) -> I8080.Step.Call { target; taken = true }
        | I8080.Instr.Return (Some _) -> I8080.Step.Return { target = None; taken = false }
        | I8080.Instr.Return None -> I8080.Step.Return { target = Some 0x100; taken = true }
        | I8080.Instr.Rst target -> I8080.Step.Restart { target = target * 8 }
        | I8080.Instr.Hlt -> I8080.Step.Halt
        | _ -> I8080.Step.Sequential
      in
      let constructed = I8080.Step.create ~source:I8080.Step.Memory ~pc_before:0
          ~pc_after:0 ~decoded ~fetched_bytes:bytes ~memory_accesses:[] ~control_flow:flow in
      assert (I8080.Timing.cost constructed > 0))
    [ 0x08; 0x10; 0x18; 0x20; 0x28; 0x30; 0x38; 0xcb; 0xd9; 0xdd; 0xed; 0xfd ];
  List.iter
    (fun (opcode, expected) ->
      let length = (I8080.Decode.opcode_info opcode).instruction_length in
      let bytes = Bytes.make length '\000' in
      Bytes.set bytes 0 (Char.chr opcode);
      let decoded = Result.get_ok (I8080.Decode.decode bytes ~offset:0) in
      let flow = match decoded.instr with
        | I8080.Instr.Jump (_, target) -> I8080.Step.Jump { target; taken = true }
        | I8080.Instr.Call (_, target) -> I8080.Step.Call { target; taken = true }
        | I8080.Instr.Return _ -> I8080.Step.Return { target = Some 0; taken = true }
        | _ -> I8080.Step.Sequential in
      assert (I8080.Timing.cost (step opcode (Bytes.to_string bytes) flow) = expected))
    [ (0x08, 4); (0x38, 4); (0xcb, 10); (0xd9, 10); (0xdd, 17); (0xed, 17); (0xfd, 17) ];
  for opcode = 0 to 255 do
    let length = (I8080.Decode.opcode_info opcode).instruction_length in
    let bytes = Bytes.make length '\000' in
    Bytes.set bytes 0 (Char.chr opcode);
    let decoded = Result.get_ok (I8080.Decode.decode bytes ~offset:0) in
    let flow =
      match decoded.instr with
      | I8080.Instr.Jump (_, target) -> I8080.Step.Jump { target; taken = false }
      | I8080.Instr.Call (_, target) -> I8080.Step.Call { target; taken = false }
      | I8080.Instr.Return _ -> I8080.Step.Return { target = None; taken = false }
      | I8080.Instr.Rst target -> I8080.Step.Restart { target = target * 8 }
      | I8080.Instr.Hlt -> I8080.Step.Halt
      | _ -> I8080.Step.Sequential
    in
    let executed = I8080.Step.create ~source:I8080.Step.Memory ~pc_before:0 ~pc_after:0
        ~decoded ~fetched_bytes:bytes ~memory_accesses:[] ~control_flow:flow in
    assert (I8080.Timing.cost executed > 0)
  done

let test_runner_total () =
  let program = Bytes.of_string "\x0e\x09\x11\x0d\x01\xcd\x05\x00\x0e\x00\xcd\x05\x00HELLO$" in
  let callback_total = ref 0 in
  let result =
    Runner.run_bytes ~output:(fun _ -> ())
      ~on_step:(fun step -> callback_total := !callback_total + I8080.Timing.cost step)
      program
    |> function Ok result -> result | Error _ -> failwith "HELLO timing run failed"
  in
  assert (result.steps = 6);
  assert (result.t_states = 68);
  assert (result.t_states = !callback_total)

let () =
  test_fixed_costs ();
  test_conditional_costs ();
  test_aliases_and_complete_opcode_domain ();
  test_runner_total ()
