let make_cpu ?(pc = 0x0100) ?(sp = 0x9000) program =
  let memory = I8080.Memory.create () in
  I8080.Memory.load memory ~address:pc program;
  let state = I8080.State.create () in
  I8080.State.set_pc state pc;
  I8080.State.set_sp state sp;
  let cpu = I8080.Cpu.create ~state ~bus:(I8080.Bus.create memory) in
  (cpu, state, memory)

let step ?interrupt cpu =
  match I8080.Cpu.step ?interrupt cpu with
  | Ok step -> step
  | Error _ -> failwith "expected a CPU step"

let expect_error expected = function
  | Error error when error = expected -> ()
  | Error _ -> failwith "unexpected CPU error"
  | Ok _ -> failwith "expected a CPU error"

let assert_origin expected step =
  assert (I8080.Step.source step = expected)

let instr step = (I8080.Step.decoded step).I8080.Decode.instr

let psw state = I8080.Flags.to_psw_byte (I8080.State.flags state)

let enable_interrupts cpu =
  ignore (step cpu);
  ignore (step cpu)

let test_ei_nop_delay () =
  let cpu, state, _ = make_cpu (Bytes.of_string "\xfb\x00\x00") in
  let flags = psw state in
  let ei = step cpu in
  assert (instr ei = I8080.Instr.Ei);
  assert_origin I8080.Step.Memory ei;
  assert (I8080.State.pc state = 0x0101);
  let request = Bytes.of_string "\x3e\x42" in
  let nop = step ~interrupt:request cpu in
  assert (instr nop = I8080.Instr.Nop);
  assert_origin I8080.Step.Memory nop;
  assert (I8080.State.pc state = 0x0102);
  assert (I8080.State.a state = 0);
  let injected = step ~interrupt:request cpu in
  assert
    (instr injected
    = I8080.Instr.Mvi (I8080.Instr.Register I8080.Instr.A, 0x42));
  assert_origin I8080.Step.Interrupt_acknowledge injected;
  assert (I8080.Step.pc_before injected = 0x0102);
  assert (I8080.Step.pc_after injected = 0x0102);
  assert (I8080.State.a state = 0x42);
  assert (psw state = flags)

let test_ei_di_and_immediate_di () =
  let cpu, state, _ = make_cpu (Bytes.of_string "\xfb\xf3\x00\x00") in
  I8080.State.set_a state 0x56;
  I8080.State.set_bc state 0x1234;
  I8080.State.set_de state 0x5678;
  I8080.State.set_hl state 0x9abc;
  I8080.State.set_sp state 0xdef0;
  I8080.Flags.restore_from_psw_byte (I8080.State.flags state) 0xd7;
  let initial_flags = psw state in
  let initial_regs =
    ( I8080.State.a state,
      I8080.State.bc state,
      I8080.State.de state,
      I8080.State.hl state,
      I8080.State.sp state )
  in
  ignore (step cpu);
  let ignored_at_di = step ~interrupt:(Bytes.of_string "\x00") cpu in
  assert (instr ignored_at_di = I8080.Instr.Di);
  assert_origin I8080.Step.Memory ignored_at_di;
  let still_disabled = step ~interrupt:Bytes.empty cpu in
  assert_origin I8080.Step.Memory still_disabled;
  assert (instr still_disabled = I8080.Instr.Nop);
  assert (I8080.State.pc state = 0x0103);
  assert (psw state = initial_flags);
  assert
    (( I8080.State.a state,
       I8080.State.bc state,
       I8080.State.de state,
       I8080.State.hl state,
       I8080.State.sp state )
    = initial_regs);
  (* Re-enable, then verify DI disables at its own instruction boundary. *)
  let cpu2, state2, _ = make_cpu (Bytes.of_string "\xfb\x00\xf3\x00") in
  I8080.State.set_a state2 0x6a;
  I8080.State.set_bc state2 0x1357;
  I8080.State.set_de state2 0x2468;
  I8080.State.set_hl state2 0xabcd;
  I8080.State.set_sp state2 0x8765;
  I8080.Flags.restore_from_psw_byte (I8080.State.flags state2) 0x95;
  let before_di =
    ( I8080.State.a state2,
      I8080.State.bc state2,
      I8080.State.de state2,
      I8080.State.hl state2,
      I8080.State.sp state2,
      psw state2 )
  in
  enable_interrupts cpu2;
  let di = step cpu2 in
  assert (instr di = I8080.Instr.Di);
  assert
    (( I8080.State.a state2,
       I8080.State.bc state2,
       I8080.State.de state2,
       I8080.State.hl state2,
       I8080.State.sp state2,
       psw state2 )
    = before_di);
  let after_di = step ~interrupt:(Bytes.of_string "\x00") cpu2 in
  assert_origin I8080.Step.Memory after_di;
  assert (I8080.State.pc state2 = 0x0104)

let test_ei_ei_restarts_delay () =
  let cpu, state, _ = make_cpu (Bytes.of_string "\xfb\xfb\x00\x00") in
  ignore (step cpu);
  let request = Bytes.of_string "\x3e\x99" in
  let ei2 = step ~interrupt:request cpu in
  assert (instr ei2 = I8080.Instr.Ei);
  assert_origin I8080.Step.Memory ei2;
  let nop = step ~interrupt:request cpu in
  assert (instr nop = I8080.Instr.Nop);
  assert_origin I8080.Step.Memory nop;
  assert (I8080.State.pc state = 0x0103);
  let injected = step ~interrupt:request cpu in
  assert_origin I8080.Step.Interrupt_acknowledge injected;
  assert (I8080.State.a state = 0x99);
  assert (I8080.State.pc state = 0x0103)

let test_injected_instruction_semantics () =
  let cpu, state, memory = make_cpu (Bytes.of_string "\xfb\x00\x3e\x77") in
  enable_interrupts cpu;
  I8080.State.set_pc state 0x1234;
  I8080.State.set_b state 0x55;
  I8080.Memory.write memory 0x1234 0x3e;
  I8080.Memory.write memory 0x1235 0x77;
  (* An injected NOP supersedes distinguishable program memory and does not
     create a memory data access or advance PC. *)
  let nop = step ~interrupt:(Bytes.of_string "\x00") cpu in
  assert_origin I8080.Step.Interrupt_acknowledge nop;
  assert ((I8080.Step.decoded nop).I8080.Decode.opcode = 0x00);
  assert (Bytes.equal (I8080.Step.fetched_bytes nop) (Bytes.of_string "\x00"));
  assert (I8080.Step.pc_before nop = 0x1234 && I8080.Step.pc_after nop = 0x1234);
  assert (I8080.Step.memory_accesses nop = []);
  assert (I8080.State.b state = 0x55);
  (* Re-enable after the acknowledge and its protected successor. *)
  I8080.Memory.write memory 0x1234 0xfb;
  I8080.Memory.write memory 0x1235 0x00;
  ignore (step cpu);
  ignore (step cpu);
  I8080.State.set_pc state 0x1234;
  let mvi = step ~interrupt:(Bytes.of_string "\x3e\x42") cpu in
  assert_origin I8080.Step.Interrupt_acknowledge mvi;
  assert (I8080.State.a state = 0x42);
  assert (I8080.State.pc state = 0x1234);
  assert (I8080.Step.memory_accesses mvi = []);
  (* A multi-byte sequential instruction consumes its acknowledge operands but
     still leaves the interrupted PC unchanged. *)
  I8080.Memory.write memory 0x1234 0xfb;
  I8080.Memory.write memory 0x1235 0x00;
  I8080.State.set_pc state 0x1234;
  ignore (step cpu);
  ignore (step cpu);
  I8080.State.set_pc state 0x2345;
  let lxi = step ~interrupt:(Bytes.of_string "\x01\x34\x12") cpu in
  assert_origin I8080.Step.Interrupt_acknowledge lxi;
  assert (I8080.State.bc state = 0x1234);
  assert (I8080.State.pc state = 0x2345);
  assert (I8080.Step.memory_accesses lxi = []);
  assert (I8080.Memory.read memory 0x1234 = 0xfb)

let test_injected_call_and_rst () =
  let cpu, state, memory = make_cpu ~sp:0x1000 (Bytes.of_string "\xfb\x00") in
  enable_interrupts cpu;
  I8080.State.set_pc state 0x1234;
  let rst = step ~interrupt:(Bytes.of_string "\xcf") cpu in
  assert_origin I8080.Step.Interrupt_acknowledge rst;
  assert (I8080.Step.control_flow rst = I8080.Step.Restart { target = 8 });
  assert (I8080.State.pc state = 8);
  assert (I8080.State.sp state = 0x0ffe);
  assert
    (I8080.Step.memory_accesses rst
    =
    [
      I8080.Step.Write { address = 0x0fff; value = 0x12 };
      I8080.Step.Write { address = 0x0ffe; value = 0x34 };
    ]);
  assert (I8080.Memory.read memory 0x0fff = 0x12);
  assert (I8080.Memory.read memory 0x0ffe = 0x34);
  (* The acknowledge itself cleared INTE: a second request is ignored. *)
  I8080.Memory.write memory 8 0x00;
  let handler_nop = step ~interrupt:(Bytes.of_string "\x3e\x66") cpu in
  assert_origin I8080.Step.Memory handler_nop;
  assert (I8080.Step.pc_after handler_nop = 9);
  assert (I8080.State.a state = 0);
  (* A CALL supplied as the interrupt instruction pushes interrupted PC, not
     PC plus the three acknowledge bytes. *)
  let cpu2, state2, memory2 = make_cpu ~pc:0x0300 ~sp:0x2000 (Bytes.of_string "\xfb\x00") in
  enable_interrupts cpu2;
  I8080.State.set_pc state2 0x4567;
  let call = step ~interrupt:(Bytes.of_string "\xcd\x78\x56") cpu2 in
  assert_origin I8080.Step.Interrupt_acknowledge call;
  assert (I8080.Step.pc_after call = 0x5678);
  assert (I8080.State.sp state2 = 0x1ffe);
  assert
    (I8080.Step.memory_accesses call
    =
    [
      I8080.Step.Write { address = 0x1fff; value = 0x45 };
      I8080.Step.Write { address = 0x1ffe; value = 0x67 };
    ]);
  assert (I8080.Memory.read memory2 0x1fff = 0x45);
  assert (I8080.Memory.read memory2 0x1ffe = 0x67)

let test_injected_ei_and_di () =
  let cpu, state, _ = make_cpu (Bytes.of_string "\xfb\x00\x00\x00") in
  enable_interrupts cpu;
  I8080.State.set_pc state 0x1111;
  let injected_ei = step ~interrupt:(Bytes.of_string "\xfb") cpu in
  assert (instr injected_ei = I8080.Instr.Ei);
  assert_origin I8080.Step.Interrupt_acknowledge injected_ei;
  let protected = step ~interrupt:(Bytes.of_string "\x00") cpu in
  assert_origin I8080.Step.Memory protected;
  assert (I8080.State.pc state = 0x1112);
  let accepted = step ~interrupt:(Bytes.of_string "\x00") cpu in
  assert_origin I8080.Step.Interrupt_acknowledge accepted;
  let cpu2, state2, _ = make_cpu (Bytes.of_string "\xfb\x00\x00") in
  enable_interrupts cpu2;
  I8080.State.set_pc state2 0x2222;
  let injected_di = step ~interrupt:(Bytes.of_string "\xf3") cpu2 in
  assert (instr injected_di = I8080.Instr.Di);
  let disabled = step ~interrupt:(Bytes.of_string "\x00") cpu2 in
  assert_origin I8080.Step.Memory disabled;
  assert (I8080.State.pc state2 = 0x2223)

let test_halt_resume_and_disabled_halt () =
  let cpu, state, memory = make_cpu ~sp:0x4000 (Bytes.of_string "\xfb\x76") in
  ignore (step cpu);
  let halt = step cpu in
  assert (I8080.Step.control_flow halt = I8080.Step.Halt);
  assert (I8080.State.pc state = 0x0102);
  assert (I8080.Cpu.is_halted cpu);
  expect_error I8080.Cpu.Cpu_halted (I8080.Cpu.step cpu);
  let wake = step ~interrupt:(Bytes.of_string "\xcf") cpu in
  assert_origin I8080.Step.Interrupt_acknowledge wake;
  assert (I8080.Step.pc_before wake = 0x0102);
  assert (I8080.Step.pc_after wake = 8);
  assert (I8080.State.sp state = 0x3ffe);
  assert (I8080.Memory.read memory 0x3ffe = 0x02);
  assert (I8080.Memory.read memory 0x3fff = 0x01);
  assert (not (I8080.Cpu.is_halted cpu));
  I8080.Memory.write memory 8 0xfb;
  I8080.Memory.write memory 9 0x00;
  ignore (step cpu);
  ignore (step cpu);
  let halted_again = step ~interrupt:(Bytes.of_string "\x76") cpu in
  assert_origin I8080.Step.Interrupt_acknowledge halted_again;
  assert (I8080.Step.pc_after halted_again = 10);
  assert (I8080.Cpu.is_halted cpu);
  let disabled, disabled_state, _ = make_cpu (Bytes.of_string "\x76") in
  ignore (step disabled);
  let pc = I8080.State.pc disabled_state in
  expect_error I8080.Cpu.Cpu_halted
    (I8080.Cpu.step ~interrupt:Bytes.empty disabled);
  assert (I8080.State.pc disabled_state = pc);
  assert (I8080.Cpu.is_halted disabled)

let test_malformed_acknowledge_atomicity () =
  let malformed =
    [
      (Bytes.empty, None, None, 0);
      (Bytes.of_string "\x3e", Some 0x3e, Some 2, 1);
      (Bytes.of_string "\xc3\x34", Some 0xc3, Some 3, 2);
      (Bytes.of_string "\x00\x00", Some 0x00, Some 1, 2);
    ]
  in
  List.iter
    (fun (payload, expected_opcode, expected_required, expected_provided) ->
      let cpu, state, memory = make_cpu ~sp:0x7000 (Bytes.of_string "\xfb\x00") in
      enable_interrupts cpu;
      I8080.State.set_a state 0xa5;
      I8080.State.set_bc state 0x1234;
      I8080.State.set_de state 0x5678;
      I8080.State.set_hl state 0x9abc;
      let before =
        ( I8080.State.pc state,
          I8080.State.sp state,
          I8080.State.a state,
          I8080.State.bc state,
          I8080.State.de state,
          I8080.State.hl state,
          psw state,
          I8080.Memory.read_range memory ~address:0 ~length:I8080.Memory.size )
      in
      (match I8080.Cpu.step ~interrupt:payload cpu with
      | Error
          (I8080.Cpu.Interrupt_acknowledge_length
            { opcode; required; provided }) ->
          assert (opcode = expected_opcode);
          assert (required = expected_required);
          assert (provided = expected_provided)
      | Error (I8080.Cpu.Unsupported_instruction _) -> failwith "decoded opcode unsupported"
      | Error (I8080.Cpu.Decode_error _) -> failwith "complete acknowledge failed to decode"
      | Error (I8080.Cpu.Bus_io_error _) -> failwith "unexpected bus error"
      | Error I8080.Cpu.Cpu_halted -> failwith "unexpected halt"
      | Ok _ -> failwith "malformed acknowledge unexpectedly accepted");
      assert
        (before
        =
        ( I8080.State.pc state,
          I8080.State.sp state,
          I8080.State.a state,
          I8080.State.bc state,
          I8080.State.de state,
          I8080.State.hl state,
          psw state,
          I8080.Memory.read_range memory ~address:0 ~length:I8080.Memory.size ));
      assert (not (I8080.Cpu.is_halted cpu));
      let accepted = step ~interrupt:(Bytes.of_string "\x00") cpu in
      assert_origin I8080.Step.Interrupt_acknowledge accepted)
    malformed;
  let halted, state, _ = make_cpu (Bytes.of_string "\xfb\x76") in
  ignore (step halted);
  ignore (step halted);
  let before_pc = I8080.State.pc state in
  (match I8080.Cpu.step ~interrupt:(Bytes.of_string "\x3e") halted with
  | Error (I8080.Cpu.Interrupt_acknowledge_length _) -> ()
  | Error (I8080.Cpu.Unsupported_instruction _) -> failwith "decoded opcode unsupported"
  | Error (I8080.Cpu.Decode_error _) -> failwith "valid prefix failed to decode"
  | Error (I8080.Cpu.Bus_io_error _) -> failwith "unexpected bus error"
  | Error I8080.Cpu.Cpu_halted -> failwith "halt blocked eligible interrupt"
  | Ok _ -> failwith "truncated interrupt instruction was accepted");
  assert (I8080.Cpu.is_halted halted && I8080.State.pc state = before_pc);
  let accepted = step ~interrupt:(Bytes.of_string "\x00") halted in
  assert_origin I8080.Step.Interrupt_acknowledge accepted;
  assert (not (I8080.Cpu.is_halted halted))

let test_nested_interrupt_requires_new_ei () =
  let cpu, state, memory = make_cpu ~sp:0x8000 (Bytes.of_string "\xfb\x00") in
  enable_interrupts cpu;
  I8080.State.set_pc state 0x1234;
  I8080.Memory.write memory 8 0xfb;
  I8080.Memory.write memory 9 0x00;
  ignore (step ~interrupt:(Bytes.of_string "\xcf") cpu);
  let ei = step ~interrupt:(Bytes.of_string "\x00") cpu in
  assert_origin I8080.Step.Memory ei;
  assert (instr ei = I8080.Instr.Ei);
  let protected = step ~interrupt:(Bytes.of_string "\x00") cpu in
  assert_origin I8080.Step.Memory protected;
  let nested = step ~interrupt:(Bytes.of_string "\x00") cpu in
  assert_origin I8080.Step.Interrupt_acknowledge nested

let () =
  test_ei_nop_delay ();
  test_ei_di_and_immediate_di ();
  test_ei_ei_restarts_delay ();
  test_injected_instruction_semantics ();
  test_injected_call_and_rst ();
  test_injected_ei_and_di ();
  test_halt_resume_and_disabled_halt ();
  test_malformed_acknowledge_atomicity ();
  test_nested_interrupt_requires_new_ei ()
