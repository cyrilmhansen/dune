open Cpm.Loader

let expect_result = function
  | Ok value -> value
  | Error _ -> failwith "expected operation to succeed"

let dispatch_bdos ~memory ~state ~output =
  let filesystem = Cpm.Filesystem.create () in
  let runtime = Cpm.Bdos.create ~filesystem in
  Cpm.Bdos.dispatch ~runtime ~memory ~state ~output

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
    (dispatch_bdos ~memory ~state ~output:(Buffer.add_char output)
    = Ok Cpm.Bdos.Continue);
  assert (Buffer.contents output = "HELLO");
  assert (I8080.State.a state = 0xa7);
  assert (I8080.Flags.carry (I8080.State.flags state));
  let empty_state = state_with_bdos_args ~function_number:9 ~de:0x2100 in
  I8080.Memory.write memory 0x2100 0x24;
  let empty_output = Buffer.create 1 in
  assert
    (dispatch_bdos ~memory ~state:empty_state ~output:(Buffer.add_char empty_output)
    = Ok Cpm.Bdos.Continue);
  assert (Buffer.contents empty_output = "")

let test_bdos_console_output () =
  let memory = I8080.Memory.create () in
  I8080.Memory.write memory 0x2345 0xa6;
  let memory_before =
    I8080.Memory.read_range memory ~address:0 ~length:I8080.Memory.size
  in
  List.iter
    (fun byte ->
      let state = state_with_bdos_args ~function_number:2 ~de:0 in
      I8080.State.set_e state byte;
      let emitted = ref [] in
      let calls = ref 0 in
      let output char = incr calls; emitted := char :: !emitted in
      assert (dispatch_bdos ~memory ~state ~output = Ok Cpm.Bdos.Continue);
      assert (!calls = 1);
      assert (List.rev !emitted = [ Char.chr byte ]))
    [ Char.code 'A'; 13; 10; 0xff ];
  assert
    (I8080.Memory.read_range memory ~address:0 ~length:I8080.Memory.size
    = memory_before)

let test_bdos_wrap_and_errors () =
  let memory = I8080.Memory.create () in
  I8080.Memory.write memory 0xffff (Char.code 'O');
  I8080.Memory.write memory 0x0000 (Char.code 'K');
  I8080.Memory.write memory 0x0001 0x24;
  let state = state_with_bdos_args ~function_number:9 ~de:0xffff in
  let output = Buffer.create 2 in
  assert
    (dispatch_bdos ~memory ~state ~output:(Buffer.add_char output)
    = Ok Cpm.Bdos.Continue);
  assert (Buffer.contents output = "OK");
  let empty_memory = I8080.Memory.create () in
  let unterminated = state_with_bdos_args ~function_number:9 ~de:0 in
  let output_count = ref 0 in
  (match
     dispatch_bdos ~memory:empty_memory ~state:unterminated
       ~output:(fun _ -> incr output_count)
   with
  | Error (Cpm.Bdos.Unterminated_string { start_address = 0; scanned = 65536 }) -> ()
  | Error (Cpm.Bdos.Unterminated_string _) -> failwith "wrong unterminated string bounds"
  | Error (Cpm.Bdos.Unsupported_function _) -> failwith "wrong BDOS error"
  | Ok _ -> failwith "unterminated string unexpectedly succeeded");
  assert (!output_count = 65536);
  let unsupported = state_with_bdos_args ~function_number:7 ~de:0 in
  (match dispatch_bdos ~memory ~state:unsupported ~output:(fun _ -> ()) with
  | Error (Cpm.Bdos.Unsupported_function 7) -> ()
  | Error (Cpm.Bdos.Unsupported_function _) -> failwith "wrong BDOS function reported"
  | Error (Cpm.Bdos.Unterminated_string _) -> failwith "wrong BDOS error"
  | Ok _ -> failwith "unsupported BDOS function unexpectedly succeeded");
  let terminate = state_with_bdos_args ~function_number:0 ~de:0 in
  assert (dispatch_bdos ~memory ~state:terminate ~output:(fun _ -> ()) = Ok Cpm.Bdos.Terminate)

let fcb_for_name memory ~address name =
  for offset = 0 to 35 do I8080.Memory.write memory (address + offset) 0 done;
  let base, extension =
    match String.index_opt name '.' with
    | None -> name, ""
    | Some dot -> String.sub name 0 dot, String.sub name (dot + 1) (String.length name - dot - 1)
  in
  I8080.Memory.write memory address 0;
  String.iteri (fun i c -> I8080.Memory.write memory (address + i + 1) (Char.code c)) base;
  for i = String.length base to 7 do I8080.Memory.write memory (address + i + 1) 0x20 done;
  String.iteri (fun i c -> I8080.Memory.write memory (address + i + 9) (Char.code c)) extension;
  for i = String.length extension to 2 do I8080.Memory.write memory (address + i + 9) 0x20 done

let call_bdos runtime memory ~function_number ~de =
  let state = I8080.State.create () in
  I8080.State.set_c state function_number;
  I8080.State.set_de state de;
  let result =
    Cpm.Bdos.dispatch ~runtime ~memory ~state ~output:(fun _ -> ())
  in
  result, state

let test_cpm22_scalar_bdos () =
  let memory = I8080.Memory.create () in
  let filesystem = Cpm.Filesystem.create () in
  assert (Cpm.Filesystem.add_file filesystem ~drive:10 ~user:3 ~name:"case.bin" (Bytes.of_string "M") = Ok ());
  assert (Cpm.Filesystem.list_files filesystem ~drive:10 ~user:3 () = [ "CASE.BIN" ]);
  assert (Cpm.Filesystem.list_files filesystem ~drive:0 ~user:3 () = []);
  let runtime = Cpm.Bdos.create ~filesystem in
  let result, state = call_bdos runtime memory ~function_number:12 ~de:0 in
  assert (result = Ok Cpm.Bdos.Continue);
  assert (I8080.State.a state = 0x22);
  assert (I8080.State.b state = 0);
  assert (I8080.State.h state = 0);
  assert (I8080.State.l state = 0x22);
  let result, state = call_bdos runtime memory ~function_number:11 ~de:0 in
  assert (result = Ok Cpm.Bdos.Continue && I8080.State.a state = 0);
  let result, state = call_bdos runtime memory ~function_number:108 ~de:0 in
  assert (result = Ok Cpm.Bdos.Continue);
  assert (I8080.State.a state = 0 && I8080.State.b state = 0 && I8080.State.hl state = 0);
  let result, _ = call_bdos runtime memory ~function_number:7 ~de:0 in
  assert (result = Error (Cpm.Bdos.Unsupported_function 7));
  let result, _ = call_bdos runtime memory ~function_number:26 ~de:0x4321 in
  assert (result = Ok Cpm.Bdos.Continue);
  assert (Cpm.Bdos.dma runtime = 0x4321);
  assert (Cpm.Bdos.current_drive runtime = 0 && Cpm.Bdos.current_user runtime = 0)

let test_cpm_sequential_files () =
  let memory = I8080.Memory.create () in
  let filesystem = Cpm.Filesystem.create () in
  let runtime = Cpm.Bdos.create ~filesystem in
  let key = Cpm.Filesystem.key_of_name ~drive:0 ~user:0 ~name:"source.dat" |> expect_result in
  let source = Bytes.init (260 * 128) (fun index -> Char.chr ((index / 128 + index) land 0xff)) in
  assert (Cpm.Filesystem.add_file filesystem ~name:"SoUrCe.DaT" source = Ok ());
  assert (Cpm.Filesystem.list_files filesystem () = [ "SOURCE.DAT" ]);
  fcb_for_name memory ~address:0x2000 "SOURCE.DAT";
  let result, state = call_bdos runtime memory ~function_number:15 ~de:0x2000 in
  assert (result = Ok Cpm.Bdos.Continue && I8080.State.a state = 0);
  let fcb = Cpm.Fcb.at memory ~address:0x2000 in
  assert (Cpm.Fcb.record_count fcb = 128);
  assert (Cpm.Fcb.extent fcb = 0 && Cpm.Fcb.current_record fcb = 0);
  let missing, missing_state = call_bdos runtime memory ~function_number:15 ~de:0x2100 in
  assert (missing = Ok Cpm.Bdos.Continue && I8080.State.a missing_state = 0xff);
  let result, state = call_bdos runtime memory ~function_number:26 ~de:0x3210 in
  assert (result = Ok Cpm.Bdos.Continue && I8080.State.a state = 0);
  assert (Cpm.Bdos.dma runtime = 0x3210);
  for record_number = 0 to 259 do
    let result, state = call_bdos runtime memory ~function_number:20 ~de:0x2000 in
    assert (result = Ok Cpm.Bdos.Continue && I8080.State.a state = 0);
    let actual = I8080.Memory.read_range memory ~address:0x3210 ~length:128 in
    let expected = Bytes.sub source (record_number * 128) 128 in
    assert (Bytes.equal actual expected);
    if record_number = 127 then (
      assert (Cpm.Fcb.extent fcb = 1);
      assert (Cpm.Fcb.current_record fcb = 0);
      assert (Cpm.Fcb.record_count fcb = 128));
    if record_number = 255 then (
      assert (Cpm.Fcb.extent fcb = 2);
      assert (Cpm.Fcb.current_record fcb = 0);
      assert (Cpm.Fcb.record_count fcb = 4))
  done;
  assert (Cpm.Fcb.extent fcb = 2 && Cpm.Fcb.current_record fcb = 4);
  assert (Cpm.Fcb.record_count fcb = 4);
  let eof, eof_state = call_bdos runtime memory ~function_number:20 ~de:0x2000 in
  assert (eof = Ok Cpm.Bdos.Continue && I8080.State.a eof_state = 1);
  assert (Cpm.Filesystem.record_count filesystem key = Some 260);
  let result, state = call_bdos runtime memory ~function_number:19 ~de:0x2000 in
  assert (result = Ok Cpm.Bdos.Continue && I8080.State.a state = 0);
  let result, state = call_bdos runtime memory ~function_number:19 ~de:0x2000 in
  assert (result = Ok Cpm.Bdos.Continue && I8080.State.a state = 0xff)

let test_cpm_make_write_close () =
  let memory = I8080.Memory.create () in
  let filesystem = Cpm.Filesystem.create () in
  let runtime = Cpm.Bdos.create ~filesystem in
  fcb_for_name memory ~address:0x2200 "OUTPUT.REL";
  let result, state = call_bdos runtime memory ~function_number:22 ~de:0x2200 in
  assert (result = Ok Cpm.Bdos.Continue && I8080.State.a state = 0);
  assert (Cpm.Filesystem.get_file filesystem ~name:"OUTPUT.REL" () = Ok (Some Bytes.empty));
  let fcb = Cpm.Fcb.at memory ~address:0x2200 in
  assert (Cpm.Fcb.record_count fcb = 0);
  let expected = Bytes.create (130 * 128) in
  for record = 0 to 129 do
    let data = Bytes.init 128 (fun index -> Char.chr ((record * 17 + index) land 0xff)) in
    Bytes.blit data 0 expected (record * 128) 128;
    I8080.Memory.load memory ~address:0x4000 data;
    let set_dma, dma_state = call_bdos runtime memory ~function_number:26 ~de:0x4000 in
    assert (set_dma = Ok Cpm.Bdos.Continue && I8080.State.a dma_state = 0);
    let write, write_state = call_bdos runtime memory ~function_number:21 ~de:0x2200 in
    assert (write = Ok Cpm.Bdos.Continue && I8080.State.a write_state = 0);
    if record = 127 then (
      assert (Cpm.Fcb.extent fcb = 1 && Cpm.Fcb.current_record fcb = 0);
      assert (Cpm.Fcb.record_count fcb = 0))
  done;
  let close, close_state = call_bdos runtime memory ~function_number:16 ~de:0x2200 in
  assert (close = Ok Cpm.Bdos.Continue && I8080.State.a close_state = 0);
  assert (Cpm.Filesystem.get_file filesystem ~name:"OUTPUT.REL" () = Ok (Some expected));
  assert (Cpm.Fcb.extent fcb = 1 && Cpm.Fcb.current_record fcb = 2);
  assert (Cpm.Fcb.record_count fcb = 2)

let test_cpm_launch_state () =
  let tail = Bytes.of_string " OPTIMIST" in
  let checked = ref false in
  let result =
    Runner.run_bytes ~command_tail:tail ~output:(fun _ -> ())
      ~on_start:(fun page_zero ->
        checked := true;
        let read address = Char.code (Bytes.get page_zero address) in
        let range address length = Bytes.sub page_zero address length in
        assert (read 0x0080 = 9);
        assert (range 0x0081 9 = tail);
        assert (read 0x008a = 0);
        let fcb1 = range 0x005c 16 in
        assert
          (Bytes.to_string fcb1
          = "\000OPTIMIST   \000\000\000\000");
        let fcb2 = range 0x006c 16 in
        let expected_fcb2 = Bytes.make 16 '\000' in
        Bytes.fill expected_fcb2 1 11 ' ';
        assert (Bytes.equal fcb2 expected_fcb2))
      (Bytes.of_string "\xc3\x00\x00")
    |> expect_result
  in
  assert !checked;
  assert (result.Runner.termination = Runner.Warm_boot)

let hello_com = Bytes.of_string
    "\x0e\x09\x11\x0d\x01\xcd\x05\x00\x0e\x00\xcd\x05\x00\x48\x45\x4c\x4c\x4f\x24"

let test_hello_integration () =
  assert (Bytes.length hello_com = 19);
  let output = Buffer.create 8 in
  let observed = ref [] in
  let trace_output = Buffer.create 512 in
  let writer = Trace.Writer.create ~output:(Buffer.add_string trace_output) in
  let trace_step_index = ref 0 in
  let result =
    Runner.run_bytes ~output:(Buffer.add_char output)
      ~on_step:(fun step -> observed := step :: !observed) hello_com
      ~on_event:(fun event ->
        Trace.Writer.write writer
          (Trace.Event.of_runner_event ~step_index:!trace_step_index event);
        (match event with
        | Runner.Step _ -> incr trace_step_index
        | Runner.Bdos_call _ | Runner.Termination _ -> ()))
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
    = I8080.Step.Return { target = Some 0x0108; taken = true });
  let expected_trace =
    "AT8TRACE\t1\n"
    ^ "STEP\t0\t0100\t0102\t0E\t0E09\tdocumented\tsequential\n"
    ^ "STEP\t1\t0102\t0105\t11\t110D01\tdocumented\tsequential\n"
    ^ "STEP\t2\t0105\t0005\tCD\tCD0500\tdocumented\tcall:1:0005\n"
    ^ "MEMW\t2\tFFFD\t01\nMEMW\t2\tFFFC\t08\n"
    ^ "BDOS\t3\t9\t010D\n"
    ^ "STEP\t3\t0005\t0108\tC9\tC9\tdocumented\treturn:1:0108\n"
    ^ "MEMR\t3\tFFFC\t08\nMEMR\t3\tFFFD\t01\n"
    ^ "STEP\t4\t0108\t010A\t0E\t0E00\tdocumented\tsequential\n"
    ^ "STEP\t5\t010A\t0005\tCD\tCD0500\tdocumented\tcall:1:0005\n"
    ^ "MEMW\t5\tFFFD\t01\nMEMW\t5\tFFFC\t0D\n"
    ^ "BDOS\t6\t0\t010D\nTERM\t6\tbdos:0\n"
  in
  let actual_trace = Buffer.contents trace_output in
  if actual_trace <> expected_trace then
    failwith (Printf.sprintf "unexpected HELLO trace:\n%s" actual_trace)

let test_warm_boot_and_page_zero () =
  let events = ref [] in
  let steps = ref [] in
  let warm =
    Runner.run_bytes ~output:(fun _ -> ()) ~on_step:(fun step -> steps := step :: !steps)
      ~on_event:(fun event -> events := event :: !events)
      (Bytes.of_string "\xc3\x00\x00")
    |> expect_result
  in
  assert (warm.Runner.termination = Runner.Warm_boot);
  assert (warm.Runner.steps = 1);
  assert (List.length !steps = 1);
  assert (I8080.Step.pc_after (List.hd !steps) = 0);
  (match List.rev !events with
  | [ Runner.Step _; Runner.Termination { step_index = 1; reason = Runner.Warm_boot } ] -> ()
  | _ -> failwith "JMP 0 did not terminate at the warm-boot trap");
  let via_restart =
    Runner.run_bytes ~output:(fun _ -> ()) (Bytes.of_string "\xc7") |> expect_result
  in
  assert (via_restart.Runner.termination = Runner.Warm_boot);
  assert (via_restart.Runner.steps = 1);
  let observed = ref [] in
  let page_zero_program =
    (* LHLD 0006 / SPHL / PUSH B / JMP 0000. The PUSH write addresses prove
       that the guest loaded the page-zero word as SP=FFFEh. *)
    Bytes.of_string "\x2a\x06\x00\xf9\xc5\xc3\x00\x00"
  in
  let result =
    Runner.run_bytes ~output:(fun _ -> ())
      ~on_step:(fun step -> observed := step :: !observed) page_zero_program
    |> expect_result
  in
  assert (result.Runner.termination = Runner.Warm_boot);
  assert (result.Runner.steps = 4);
  let observed = List.rev !observed in
  assert (List.length observed = 4);
  assert
    (I8080.Step.memory_accesses (List.nth observed 2)
    =
    [
      I8080.Step.Write { address = 0xfffd; value = 0x00 };
      I8080.Step.Write { address = 0xfffc; value = 0x00 };
    ])

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
  | Error (Runner.Invalid_command_tail _) -> failwith "wrong error for infinite NOP program"
  | Ok _ -> failwith "infinite NOP program unexpectedly terminated");
  assert (!steps = 3);
  (match Runner.run_bytes ~output:(fun _ -> ()) (Bytes.of_string "\xfb\x76") with
  | Error (Runner.Cpu_error I8080.Cpu.Cpu_halted) -> ()
  | Error (Runner.Load_error _) -> failwith "unexpected loader error"
  | Error (Runner.Cpu_error (I8080.Cpu.Decode_error _)) -> failwith "wrong CPU error"
  | Error (Runner.Cpu_error (I8080.Cpu.Bus_io_error _)) -> failwith "wrong CPU error"
  | Error (Runner.Cpu_error (I8080.Cpu.Interrupt_acknowledge_length _)) -> failwith "wrong CPU error"
  | Error (Runner.Cpu_error (I8080.Cpu.Unsupported_instruction _)) -> failwith "wrong CPU error"
  | Error (Runner.Bdos_error _) -> failwith "wrong runner error for halted CPU"
  | Error (Runner.Step_limit_exceeded _) -> failwith "wrong runner error for halted CPU"
  | Error (Runner.Invalid_step_limit _) -> failwith "wrong runner error for halted CPU"
  | Error (Runner.Invalid_command_tail _) -> failwith "wrong runner error for halted CPU"
  | Ok _ -> failwith "halted CPU unexpectedly terminated");
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
  | Error (Runner.Invalid_command_tail _) -> failwith "wrong runner error for unsupported BDOS function"
  | Ok _ -> failwith "unsupported BDOS function unexpectedly ran");
  (match Runner.run_bytes ~max_steps:0 ~output:(fun _ -> ()) hello_com with
  | Error (Runner.Invalid_step_limit 0) -> ()
  | Error (Runner.Load_error _) -> failwith "unexpected loader error"
  | Error (Runner.Cpu_error _) -> failwith "wrong invalid step limit error"
  | Error (Runner.Bdos_error _) -> failwith "wrong invalid step limit error"
  | Error (Runner.Step_limit_exceeded _) -> failwith "wrong invalid step limit error"
  | Error (Runner.Invalid_step_limit _) -> failwith "wrong invalid step limit error"
  | Error (Runner.Invalid_command_tail _) -> failwith "wrong invalid step limit error"
  | Ok _ -> failwith "zero instruction limit unexpectedly ran")

let () =
  test_loader ();
  test_bdos_print_string ();
  test_bdos_console_output ();
  test_bdos_wrap_and_errors ();
  test_cpm22_scalar_bdos ();
  test_cpm_sequential_files ();
  test_cpm_make_write_close ();
  test_cpm_launch_state ();
  test_hello_integration ();
  test_warm_boot_and_page_zero ();
  test_runner_errors ()
