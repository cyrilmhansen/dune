open Cpm.Loader

let expect_result = function
  | Ok value -> value
  | Error _ -> failwith "expected operation to succeed"

let test_loader () =
  let memory = I8080.Memory.create () in
  let program = Bytes.of_string "\x0e\x09\xcd\x05\x00" in
  let loaded = expect_result (Cpm.Loader.load_bytes memory program) in
  assert (loaded.entry_point = 0x0100);
  assert (loaded.size = 5);
  assert (I8080.Memory.read memory 0x0100 = 0x0e);
  assert (I8080.Memory.read memory 0x0104 = 0x00);
  assert (I8080.Memory.read memory 0x00ff = 0x00);
  let too_large = Bytes.make (I8080.Memory.size - Cpm.Loader.load_address + 1) '\xaa' in
  (match Cpm.Loader.load_bytes memory too_large with
  | Error (Cpm.Loader.Program_too_large { size; maximum }) ->
      assert (size = Bytes.length too_large);
      assert (maximum = I8080.Memory.size - Cpm.Loader.load_address)
  | Error (Cpm.Loader.File_error _) -> failwith "unexpected loader file error"
  | Ok _ -> failwith "oversized COM program unexpectedly loaded");
  assert (I8080.Memory.read memory 0x0100 = 0x0e);
  (match Cpm.Loader.load_file memory ~path:"/no/such/pli80-com-file" with
  | Error (Cpm.Loader.File_error _) -> ()
  | Error (Cpm.Loader.Program_too_large _) -> failwith "unexpected size error"
  | Ok _ -> failwith "missing host file unexpectedly loaded")

let state_with_bdos_args ~function_number ~de =
  let state = I8080.State.create () in
  I8080.State.set_c state function_number;
  I8080.State.set_de state de;
  state

let test_bdos_print_string () =
  let memory = I8080.Memory.create () in
  I8080.Memory.load memory ~address:0x2000 (Bytes.of_string "HELLO$");
  let state = state_with_bdos_args ~function_number:9 ~de:0x2000 in
  I8080.State.set_a state 0xa7;
  I8080.Flags.set_carry (I8080.State.flags state) true;
  let output = Buffer.create 16 in
  assert
    (Cpm.Bdos.dispatch ~memory ~state ~output:(Buffer.add_char output)
    = Ok Cpm.Bdos.Continue);
  assert (Buffer.contents output = "HELLO");
  assert (I8080.State.a state = 0xa7);
  assert (I8080.Flags.carry (I8080.State.flags state));
  let empty_state = state_with_bdos_args ~function_number:9 ~de:0x2100 in
  I8080.Memory.write memory 0x2100 0x24;
  let empty_output = Buffer.create 1 in
  assert
    (Cpm.Bdos.dispatch ~memory ~state:empty_state ~output:(Buffer.add_char empty_output)
    = Ok Cpm.Bdos.Continue);
  assert (Buffer.contents empty_output = "")

let test_bdos_wrap_and_errors () =
  let memory = I8080.Memory.create () in
  I8080.Memory.write memory 0xffff (Char.code 'O');
  I8080.Memory.write memory 0x0000 (Char.code 'K');
  I8080.Memory.write memory 0x0001 0x24;
  let state = state_with_bdos_args ~function_number:9 ~de:0xffff in
  let output = Buffer.create 2 in
  assert
    (Cpm.Bdos.dispatch ~memory ~state ~output:(Buffer.add_char output)
    = Ok Cpm.Bdos.Continue);
  assert (Buffer.contents output = "OK");
  let empty_memory = I8080.Memory.create () in
  let unterminated = state_with_bdos_args ~function_number:9 ~de:0 in
  let output_count = ref 0 in
  (match
     Cpm.Bdos.dispatch ~memory:empty_memory ~state:unterminated
       ~output:(fun _ -> incr output_count)
   with
  | Error (Cpm.Bdos.Unterminated_string { start_address = 0; scanned = 65536 }) -> ()
  | Error (Cpm.Bdos.Unterminated_string _) -> failwith "wrong unterminated string bounds"
  | Error (Cpm.Bdos.Unsupported_function _) -> failwith "wrong BDOS error"
  | Ok _ -> failwith "unterminated string unexpectedly succeeded");
  assert (!output_count = 65536);
  let unsupported = state_with_bdos_args ~function_number:7 ~de:0 in
  (match Cpm.Bdos.dispatch ~memory ~state:unsupported ~output:(fun _ -> ()) with
  | Error (Cpm.Bdos.Unsupported_function 7) -> ()
  | Error (Cpm.Bdos.Unsupported_function _) -> failwith "wrong BDOS function reported"
  | Error (Cpm.Bdos.Unterminated_string _) -> failwith "wrong BDOS error"
  | Ok _ -> failwith "unsupported BDOS function unexpectedly succeeded");
  let terminate = state_with_bdos_args ~function_number:0 ~de:0 in
  assert (Cpm.Bdos.dispatch ~memory ~state:terminate ~output:(fun _ -> ()) = Ok Cpm.Bdos.Terminate)

let hello_com = Bytes.of_string
    "\x0e\x09\x11\x0d\x01\xcd\x05\x00\x0e\x00\xcd\x05\x00\x48\x45\x4c\x4c\x4f\x24"

let test_hello_integration () =
  assert (Bytes.length hello_com = 19);
  let output = Buffer.create 8 in
  let observed = ref [] in
  let result =
    Runner.run_bytes ~output:(Buffer.add_char output)
      ~on_step:(fun step -> observed := step :: !observed) hello_com
  in
  let result = expect_result result in
  assert (Buffer.contents output = "HELLO");
  assert (result.Runner.termination = Runner.Bdos_function 0);
  assert (result.Runner.steps = 6);
  let steps = List.rev !observed in
  assert (List.length steps = 6);
  let expected =
    [
      (0x0e, I8080.Instr.Mvi (I8080.Instr.Register I8080.Instr.C, 9), 0x0100, 0x0102, "\x0e\x09");
      (0x11, I8080.Instr.Lxi (I8080.Instr.DE, 0x010d), 0x0102, 0x0105, "\x11\x0d\x01");
      (0xcd, I8080.Instr.Call (None, 0x0005), 0x0105, 0x0005, "\xcd\x05\x00");
      (0xc9, I8080.Instr.Return None, 0x0005, 0x0108, "\xc9");
      (0x0e, I8080.Instr.Mvi (I8080.Instr.Register I8080.Instr.C, 0), 0x0108, 0x010a, "\x0e\x00");
      (0xcd, I8080.Instr.Call (None, 0x0005), 0x010a, 0x0005, "\xcd\x05\x00");
    ]
  in
  List.iter2
    (fun step (opcode, instruction, pc_before, pc_after, fetched) ->
      let decoded = I8080.Step.decoded step in
      assert (decoded.I8080.Decode.opcode = opcode);
      assert (decoded.I8080.Decode.instr = instruction);
      assert (I8080.Step.pc_before step = pc_before);
      assert (I8080.Step.pc_after step = pc_after);
      assert (Bytes.equal (I8080.Step.fetched_bytes step) (Bytes.of_string fetched)))
    steps expected;
  assert (I8080.Step.memory_accesses (List.nth steps 0) = []);
  assert (I8080.Step.memory_accesses (List.nth steps 1) = []);
  assert
    (I8080.Step.memory_accesses (List.nth steps 2)
    =
    [
      I8080.Step.Write { address = 0xfffd; value = 0x01 };
      I8080.Step.Write { address = 0xfffc; value = 0x08 };
    ]);
  assert
    (I8080.Step.memory_accesses (List.nth steps 3)
    =
    [
      I8080.Step.Read { address = 0xfffc; value = 0x08 };
      I8080.Step.Read { address = 0xfffd; value = 0x01 };
    ]);
  assert (I8080.Step.memory_accesses (List.nth steps 4) = []);
  assert
    (I8080.Step.memory_accesses (List.nth steps 5)
    =
    [
      I8080.Step.Write { address = 0xfffd; value = 0x01 };
      I8080.Step.Write { address = 0xfffc; value = 0x0d };
    ]);
  assert
    (I8080.Step.control_flow (List.nth steps 2)
    = I8080.Step.Call { target = 0x0005; taken = true });
  assert
    (I8080.Step.control_flow (List.nth steps 3)
    = I8080.Step.Return { target = Some 0x0108; taken = true })

let test_runner_errors () =
  let steps = ref 0 in
  (match
     Runner.run_bytes ~max_steps:3 ~output:(fun _ -> ())
       ~on_step:(fun _ -> incr steps) (Bytes.of_string "\x00")
   with
  | Error (Runner.Step_limit_exceeded { max_steps = 3; steps = 3 }) -> ()
  | Error (Runner.Step_limit_exceeded _) -> failwith "wrong step limit details"
  | Error (Runner.Load_error _) -> failwith "unexpected loader error"
  | Error (Runner.Cpu_error _) -> failwith "wrong error for infinite NOP program"
  | Error (Runner.Bdos_error _) -> failwith "wrong error for infinite NOP program"
  | Error (Runner.Invalid_step_limit _) -> failwith "wrong error for infinite NOP program"
  | Ok _ -> failwith "infinite NOP program unexpectedly terminated");
  assert (!steps = 3);
  (match Runner.run_bytes ~output:(fun _ -> ()) (Bytes.of_string "\x40") with
  | Error (Runner.Cpu_error (I8080.Cpu.Unsupported_instruction _)) -> ()
  | Error (Runner.Load_error _) -> failwith "unexpected loader error"
  | Error (Runner.Cpu_error (I8080.Cpu.Decode_error _)) -> failwith "wrong CPU error"
  | Error (Runner.Bdos_error _) -> failwith "wrong runner error for unsupported CPU instruction"
  | Error (Runner.Step_limit_exceeded _) -> failwith "wrong runner error for unsupported CPU instruction"
  | Error (Runner.Invalid_step_limit _) -> failwith "wrong runner error for unsupported CPU instruction"
  | Ok _ -> failwith "unsupported CPU instruction unexpectedly ran");
  (match
     Runner.run_bytes ~output:(fun _ -> ()) (Bytes.of_string "\x0e\x07\xcd\x05\x00")
  with
  | Error (Runner.Bdos_error (Cpm.Bdos.Unsupported_function 7)) -> ()
  | Error (Runner.Load_error _) -> failwith "unexpected loader error"
  | Error (Runner.Cpu_error _) -> failwith "wrong runner error for unsupported BDOS function"
  | Error (Runner.Bdos_error (Cpm.Bdos.Unsupported_function _)) -> failwith "wrong BDOS function"
  | Error (Runner.Bdos_error (Cpm.Bdos.Unterminated_string _)) -> failwith "wrong BDOS error"
  | Error (Runner.Step_limit_exceeded _) -> failwith "wrong runner error for unsupported BDOS function"
  | Error (Runner.Invalid_step_limit _) -> failwith "wrong runner error for unsupported BDOS function"
  | Ok _ -> failwith "unsupported BDOS function unexpectedly ran");
  (match Runner.run_bytes ~max_steps:0 ~output:(fun _ -> ()) hello_com with
  | Error (Runner.Invalid_step_limit 0) -> ()
  | Error (Runner.Load_error _) -> failwith "unexpected loader error"
  | Error (Runner.Cpu_error _) -> failwith "wrong invalid step limit error"
  | Error (Runner.Bdos_error _) -> failwith "wrong invalid step limit error"
  | Error (Runner.Step_limit_exceeded _) -> failwith "wrong invalid step limit error"
  | Error (Runner.Invalid_step_limit _) -> failwith "wrong invalid step limit error"
  | Ok _ -> failwith "zero instruction limit unexpectedly ran")

let () =
  test_loader ();
  test_bdos_print_string ();
  test_bdos_wrap_and_errors ();
  test_hello_integration ();
  test_runner_errors ()
