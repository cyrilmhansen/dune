let machine ?input ?output program =
  let memory = I8080.Memory.create () in
  I8080.Memory.load memory ~address:0x0100 program;
  let state = I8080.State.create () in
  I8080.State.set_pc state 0x0100;
  I8080.State.set_sp state 0x9000;
  let bus = I8080.Bus.create ?input ?output memory in
  (I8080.Cpu.create ~state ~bus, state, memory)

let step_ok cpu =
  match I8080.Cpu.step cpu with
  | Ok step -> step
  | Error _ -> failwith "expected instruction to execute"

let flags_snapshot state =
  let copy = I8080.Flags.create () in
  I8080.Flags.restore_from_psw_byte copy
    (I8080.Flags.to_psw_byte (I8080.State.flags state));
  copy

let assert_flags_unchanged state before =
  assert (I8080.Flags.equal (I8080.State.flags state) before)

let get_register state = function
  | I8080.Instr.A -> I8080.State.a state
  | I8080.Instr.B -> I8080.State.b state
  | I8080.Instr.C -> I8080.State.c state
  | I8080.Instr.D -> I8080.State.d state
  | I8080.Instr.E -> I8080.State.e state
  | I8080.Instr.H -> I8080.State.h state
  | I8080.Instr.L -> I8080.State.l state

let set_register state register value =
  match register with
  | I8080.Instr.A -> I8080.State.set_a state value
  | I8080.Instr.B -> I8080.State.set_b state value
  | I8080.Instr.C -> I8080.State.set_c state value
  | I8080.Instr.D -> I8080.State.set_d state value
  | I8080.Instr.E -> I8080.State.set_e state value
  | I8080.Instr.H -> I8080.State.set_h state value
  | I8080.Instr.L -> I8080.State.set_l state value

let register_of_code = function
  | 0 -> I8080.Instr.B
  | 1 -> I8080.Instr.C
  | 2 -> I8080.Instr.D
  | 3 -> I8080.Instr.E
  | 4 -> I8080.Instr.H
  | 5 -> I8080.Instr.L
  | 7 -> I8080.Instr.A
  | _ -> invalid_arg "register_of_code"

let test_mov_matrix () =
  for opcode = 0x40 to 0x7f do
    if opcode <> 0x76 then (
      let destination = (opcode lsr 3) land 7 in
      let source = opcode land 7 in
      let cpu, state, memory = machine (Bytes.make 1 (Char.chr opcode)) in
      I8080.State.set_a state 0x77;
      I8080.State.set_bc state 0x1122;
      I8080.State.set_de state 0x3344;
      I8080.State.set_hl state 0x2000;
      I8080.Memory.write memory 0x2000 0xc3;
      let before = flags_snapshot state in
      let source_value =
        if source = 6 then I8080.Memory.read memory 0x2000
        else get_register state (register_of_code source)
      in
      let previous_registers =
        [|
          I8080.State.b state;
          I8080.State.c state;
          I8080.State.d state;
          I8080.State.e state;
          I8080.State.h state;
          I8080.State.l state;
          -1;
          I8080.State.a state;
        |]
      in
      let step = step_ok cpu in
      assert (I8080.Step.pc_before step = 0x0100);
      assert (I8080.Step.pc_after step = 0x0101);
      let expected_accesses =
        (if source = 6 then [ I8080.Step.Read { address = 0x2000; value = 0xc3 } ]
         else [])
        @ if destination = 6 then
            [ I8080.Step.Write { address = 0x2000; value = source_value } ]
          else []
      in
      assert (I8080.Step.memory_accesses step = expected_accesses);
      if destination = 6 then assert (I8080.Memory.read memory 0x2000 = source_value)
      else set_register state (register_of_code destination) source_value;
      Array.iteri
        (fun index previous ->
          if index <> destination && index <> 6 then
            assert (get_register state (register_of_code index) = previous))
        previous_registers;
      if destination <> 6 then
        assert (get_register state (register_of_code destination) = source_value);
      assert_flags_unchanged state before)
  done

let test_inx_dcx () =
  let cases =
    [
      (0x03, I8080.State.bc, I8080.State.set_bc, 0xffff, 0x0000);
      (0x13, I8080.State.de, I8080.State.set_de, 0xffff, 0x0000);
      (0x23, I8080.State.hl, I8080.State.set_hl, 0xffff, 0x0000);
      (0x33, I8080.State.sp, I8080.State.set_sp, 0xffff, 0x0000);
      (0x0b, I8080.State.bc, I8080.State.set_bc, 0x0000, 0xffff);
      (0x1b, I8080.State.de, I8080.State.set_de, 0x0000, 0xffff);
      (0x2b, I8080.State.hl, I8080.State.set_hl, 0x0000, 0xffff);
      (0x3b, I8080.State.sp, I8080.State.set_sp, 0x0000, 0xffff);
    ]
  in
  List.iter
    (fun (opcode, get, set, initial, expected) ->
      let cpu, state, _ = machine (Bytes.make 1 (Char.chr opcode)) in
      set state initial;
      let before = flags_snapshot state in
      let step = step_ok cpu in
      assert (get state = expected);
      assert (I8080.State.pc state = 0x0101);
      assert (I8080.Step.memory_accesses step = []);
      assert_flags_unchanged state before)
    cases

let test_memory_transfer_family () =
  List.iter
    (fun (opcode, set_pair) ->
      let cpu, state, memory = machine (Bytes.make 1 (Char.chr opcode)) in
      set_pair state 0x2345;
      I8080.Memory.write memory 0x2345 0xa6;
      let before = flags_snapshot state in
      let step = step_ok cpu in
      assert (I8080.State.a state = 0xa6);
      assert
        (I8080.Step.memory_accesses step
        = [ I8080.Step.Read { address = 0x2345; value = 0xa6 } ]);
      assert_flags_unchanged state before)
    [ (0x0a, I8080.State.set_bc); (0x1a, I8080.State.set_de) ];
  List.iter
    (fun (opcode, pair_address) ->
      let cpu, state, memory = machine (Bytes.make 1 (Char.chr opcode)) in
      I8080.State.set_a state 0xa6;
      (if opcode = 0x02 then I8080.State.set_bc state pair_address
       else I8080.State.set_de state pair_address);
      let before = flags_snapshot state in
      let step = step_ok cpu in
      assert (I8080.Memory.read memory pair_address = 0xa6);
      assert
        (I8080.Step.memory_accesses step
        = [ I8080.Step.Write { address = pair_address; value = 0xa6 } ]);
      assert_flags_unchanged state before)
    [ (0x02, 0x2345); (0x12, 0x3456) ];
  let direct_cases =
    [
      (0x3a, 0x1234, `Load_a);
      (0x32, 0x1234, `Store_a);
      (0x2a, 0x1234, `Load_hl);
      (0x22, 0x1234, `Store_hl);
    ]
  in
  List.iter
    (fun (opcode, address, operation) ->
      let program =
        Bytes.of_string
          (String.make 1 (Char.chr opcode) ^ "\x34\x12")
      in
      let cpu, state, memory = machine program in
      I8080.State.set_a state 0xb7;
      I8080.State.set_hl state 0x9abc;
      I8080.Memory.write memory address 0x34;
      I8080.Memory.write memory (address + 1) 0x12;
      let before = flags_snapshot state in
      let step = step_ok cpu in
      assert (Bytes.equal (I8080.Step.fetched_bytes step) program);
      (match operation with
      | `Load_a ->
          assert (I8080.State.a state = 0x34);
          assert
            (I8080.Step.memory_accesses step
            = [ I8080.Step.Read { address; value = 0x34 } ])
      | `Store_a ->
          assert (I8080.Memory.read memory address = 0xb7);
          assert
            (I8080.Step.memory_accesses step
            = [ I8080.Step.Write { address; value = 0xb7 } ])
      | `Load_hl ->
          assert (I8080.State.hl state = 0x1234);
          assert
            (I8080.Step.memory_accesses step
            =
            [
              I8080.Step.Read { address; value = 0x34 };
              I8080.Step.Read { address = address + 1; value = 0x12 };
            ])
      | `Store_hl ->
          assert (I8080.Memory.read memory address = 0xbc);
          assert (I8080.Memory.read memory (address + 1) = 0x9a);
          assert
            (I8080.Step.memory_accesses step
            =
            [
              I8080.Step.Write { address; value = 0xbc };
              I8080.Step.Write { address = address + 1; value = 0x9a };
            ]));
      assert_flags_unchanged state before)
    direct_cases;
  List.iter
    (fun (opcode, load) ->
      let program = Bytes.of_string (String.make 1 (Char.chr opcode) ^ "\xff\xff") in
      let cpu, state, memory = machine program in
      I8080.State.set_hl state 0xabcd;
      I8080.Memory.write memory 0xffff 0x78;
      I8080.Memory.write memory 0x0000 0x56;
      let step = step_ok cpu in
      if load then assert (I8080.State.hl state = 0x5678)
      else (
        assert (I8080.Memory.read memory 0xffff = 0xcd);
        assert (I8080.Memory.read memory 0x0000 = 0xab));
      assert
        (I8080.Step.memory_accesses step
        =
        if load then
          [
            I8080.Step.Read { address = 0xffff; value = 0x78 };
            I8080.Step.Read { address = 0x0000; value = 0x56 };
          ]
        else
          [
            I8080.Step.Write { address = 0xffff; value = 0xcd };
            I8080.Step.Write { address = 0x0000; value = 0xab };
          ]))
    [ (0x2a, true); (0x22, false) ]

let test_stack_pairs_and_wrap () =
  let pairs =
    [
      (0xc5, 0xc1, I8080.Instr.Stack_BC, 0x1234);
      (0xd5, 0xd1, I8080.Instr.Stack_DE, 0x5678);
      (0xe5, 0xe1, I8080.Instr.Stack_HL, 0x9abc);
      (0xf5, 0xf1, I8080.Instr.PSW, 0x5a83);
    ]
  in
  List.iter
    (fun (push_opcode, pop_opcode, pair, value) ->
      let cpu, state, memory =
        machine (Bytes.of_string (String.make 1 (Char.chr push_opcode) ^ String.make 1 (Char.chr pop_opcode)))
      in
      I8080.State.set_a state 0x5a;
      I8080.State.set_bc state 0x1234;
      I8080.State.set_de state 0x5678;
      I8080.State.set_hl state 0x9abc;
      I8080.Flags.restore_from_psw_byte (I8080.State.flags state) 0x83;
      let push_value =
        match pair with
        | I8080.Instr.Stack_BC -> I8080.State.bc state
        | I8080.Instr.Stack_DE -> I8080.State.de state
        | I8080.Instr.Stack_HL -> I8080.State.hl state
        | I8080.Instr.PSW ->
            (I8080.State.a state lsl 8)
            lor I8080.Flags.to_psw_byte (I8080.State.flags state)
      in
      assert (push_value = value);
      let before_flags = flags_snapshot state in
      let push = step_ok cpu in
      assert (I8080.State.sp state = 0x8ffe);
      assert
        (I8080.Step.memory_accesses push
        =
        [
          I8080.Step.Write { address = 0x8fff; value = (value lsr 8) land 0xff };
          I8080.Step.Write { address = 0x8ffe; value = value land 0xff };
        ]);
      assert_flags_unchanged state before_flags;
      if pair = I8080.Instr.PSW then I8080.Memory.write memory 0x8ffe 0xab;
      let pop = step_ok cpu in
      assert (I8080.State.sp state = 0x9000);
      assert
        (I8080.Step.memory_accesses pop
        =
        [
          I8080.Step.Read { address = 0x8ffe; value = if pair = I8080.Instr.PSW then 0xab else value land 0xff };
          I8080.Step.Read { address = 0x8fff; value = value lsr 8 };
        ]);
      (match pair with
      | I8080.Instr.Stack_BC -> assert (I8080.State.bc state = value)
      | I8080.Instr.Stack_DE -> assert (I8080.State.de state = value)
      | I8080.Instr.Stack_HL -> assert (I8080.State.hl state = value)
      | I8080.Instr.PSW ->
          assert (I8080.State.a state = 0x5a);
          assert (I8080.Flags.to_psw_byte (I8080.State.flags state) = 0x83));
      if pair <> I8080.Instr.PSW then assert_flags_unchanged state before_flags)
    pairs;
  let push_cpu, push_state, push_memory = machine (Bytes.of_string "\xc5") in
  I8080.State.set_sp push_state 0x0001;
  I8080.State.set_bc push_state 0x1234;
  let push = step_ok push_cpu in
  assert (I8080.State.sp push_state = 0xffff);
  assert (I8080.Memory.read push_memory 0x0000 = 0x12);
  assert (I8080.Memory.read push_memory 0xffff = 0x34);
  assert
    (I8080.Step.memory_accesses push
    =
    [
      I8080.Step.Write { address = 0x0000; value = 0x12 };
      I8080.Step.Write { address = 0xffff; value = 0x34 };
    ]);
  let pop_cpu, pop_state, pop_memory = machine (Bytes.of_string "\xc1") in
  I8080.State.set_sp pop_state 0xffff;
  I8080.Memory.write pop_memory 0xffff 0x34;
  I8080.Memory.write pop_memory 0x0000 0x12;
  let pop = step_ok pop_cpu in
  assert (I8080.State.bc pop_state = 0x1234);
  assert (I8080.State.sp pop_state = 0x0001);
  assert
    (I8080.Step.memory_accesses pop
    =
    [
      I8080.Step.Read { address = 0xffff; value = 0x34 };
      I8080.Step.Read { address = 0x0000; value = 0x12 };
    ])

let set_flags_mask flags mask =
  I8080.Flags.set_sign flags (mask land 0x10 <> 0);
  I8080.Flags.set_zero flags (mask land 0x08 <> 0);
  I8080.Flags.set_auxiliary_carry flags (mask land 0x04 <> 0);
  I8080.Flags.set_parity flags (mask land 0x02 <> 0);
  I8080.Flags.set_carry flags (mask land 0x01 <> 0)

let psw_byte_of_mask mask =
  (if mask land 0x10 <> 0 then 0x80 else 0)
  lor (if mask land 0x08 <> 0 then 0x40 else 0)
  lor (if mask land 0x04 <> 0 then 0x10 else 0)
  lor (if mask land 0x02 <> 0 then 0x04 else 0)
  lor (if mask land 0x01 <> 0 then 0x01 else 0)

let assert_flags_mask flags mask =
  assert (I8080.Flags.sign flags = (mask land 0x10 <> 0));
  assert (I8080.Flags.zero flags = (mask land 0x08 <> 0));
  assert (I8080.Flags.auxiliary_carry flags = (mask land 0x04 <> 0));
  assert (I8080.Flags.parity flags = (mask land 0x02 <> 0));
  assert (I8080.Flags.carry flags = (mask land 0x01 <> 0))

let test_psw_stack_exhaustive () =
  let reserved_patterns = [ 0x00; 0x02; 0x08; 0x0a; 0x20; 0x22; 0x28; 0x2a ] in
  for mask = 0 to 31 do
    let packed = psw_byte_of_mask mask in
    let push_cpu, push_state, push_memory = machine (Bytes.of_string "\xf5") in
    I8080.State.set_sp push_state 0x2000;
    I8080.State.set_a push_state 0xa5;
    set_flags_mask (I8080.State.flags push_state) mask;
    let push = step_ok push_cpu in
    let psw = packed lor 0x02 in
    assert (I8080.Memory.read push_memory 0x1fff = 0xa5);
    assert (I8080.Memory.read push_memory 0x1ffe = psw);
    assert
      (I8080.Step.memory_accesses push
      =
      [
        I8080.Step.Write { address = 0x1fff; value = 0xa5 };
        I8080.Step.Write { address = 0x1ffe; value = psw };
      ]);
    assert_flags_mask (I8080.State.flags push_state) mask;
    List.iter
      (fun reserved ->
        let pop_cpu, pop_state, pop_memory = machine (Bytes.of_string "\xf1") in
        I8080.State.set_sp pop_state 0x3000;
        I8080.Memory.write pop_memory 0x3000 (packed lor reserved);
        I8080.Memory.write pop_memory 0x3001 0x6d;
        let pop = step_ok pop_cpu in
        assert (I8080.State.a pop_state = 0x6d);
        assert_flags_mask (I8080.State.flags pop_state) mask;
        assert
          (I8080.Step.memory_accesses pop
          =
          [
            I8080.Step.Read { address = 0x3000; value = packed lor reserved };
            I8080.Step.Read { address = 0x3001; value = 0x6d };
          ]))
      reserved_patterns
  done

let set_condition state code taken =
  let flags = I8080.State.flags state in
  I8080.Flags.reset flags;
  match code with
  | 0 -> I8080.Flags.set_zero flags (not taken)
  | 1 -> I8080.Flags.set_zero flags taken
  | 2 -> I8080.Flags.set_carry flags (not taken)
  | 3 -> I8080.Flags.set_carry flags taken
  | 4 -> I8080.Flags.set_parity flags (not taken)
  | 5 -> I8080.Flags.set_parity flags taken
  | 6 -> I8080.Flags.set_sign flags (not taken)
  | 7 -> I8080.Flags.set_sign flags taken
  | _ -> invalid_arg "condition code"

let test_conditions () =
  for code = 0 to 7 do
    List.iter
      (fun taken ->
      let jmp_opcode = 0xc2 + (code * 8) in
      let jmp, jmp_state, _ =
        machine (Bytes.of_string (String.make 1 (Char.chr jmp_opcode) ^ "\x34\x12"))
      in
      set_condition jmp_state code taken;
      let before = flags_snapshot jmp_state in
      let step = step_ok jmp in
      assert (I8080.State.pc jmp_state = if taken then 0x1234 else 0x0103);
      assert (I8080.Step.memory_accesses step = []);
      assert
        (I8080.Step.control_flow step
        = I8080.Step.Jump { target = 0x1234; taken });
      assert_flags_unchanged jmp_state before;
      let call_opcode = 0xc4 + (code * 8) in
      let call, call_state, _ =
        machine (Bytes.of_string (String.make 1 (Char.chr call_opcode) ^ "\x34\x12"))
      in
      set_condition call_state code taken;
      let before = flags_snapshot call_state in
      let step = step_ok call in
      assert (I8080.State.pc call_state = if taken then 0x1234 else 0x0103);
      assert (I8080.State.sp call_state = if taken then 0x8ffe else 0x9000);
      assert
        (I8080.Step.memory_accesses step
        =
        if taken then
          [
            I8080.Step.Write { address = 0x8fff; value = 0x01 };
            I8080.Step.Write { address = 0x8ffe; value = 0x03 };
          ]
        else []);
      assert
        (I8080.Step.control_flow step
        = I8080.Step.Call { target = 0x1234; taken });
      assert_flags_unchanged call_state before;
      let ret_opcode = 0xc0 + (code * 8) in
      let ret, ret_state, ret_memory =
        machine (Bytes.make 1 (Char.chr ret_opcode))
      in
      I8080.State.set_sp ret_state 0x4567;
      I8080.Memory.write ret_memory 0x4567 0x34;
      I8080.Memory.write ret_memory 0x4568 0x12;
      set_condition ret_state code taken;
      let before = flags_snapshot ret_state in
      let step = step_ok ret in
      assert (I8080.State.pc ret_state = if taken then 0x1234 else 0x0101);
      assert (I8080.State.sp ret_state = if taken then 0x4569 else 0x4567);
      assert
        (I8080.Step.memory_accesses step
        =
        if taken then
          [
            I8080.Step.Read { address = 0x4567; value = 0x34 };
            I8080.Step.Read { address = 0x4568; value = 0x12 };
          ]
        else []);
      assert
        (I8080.Step.control_flow step
        = I8080.Step.Return { target = (if taken then Some 0x1234 else None); taken });
      assert_flags_unchanged ret_state before)
      [ false; true ]
  done

let test_restarts () =
  for number = 0 to 7 do
    let cpu, state, _ = machine (Bytes.make 1 (Char.chr (0xc7 + (number * 8)))) in
    let before = flags_snapshot state in
    let step = step_ok cpu in
    let target = number * 8 in
    assert (I8080.State.pc state = target);
    assert (I8080.State.sp state = 0x8ffe);
    assert
      (I8080.Step.memory_accesses step
      =
      [
        I8080.Step.Write { address = 0x8fff; value = 0x01 };
        I8080.Step.Write { address = 0x8ffe; value = 0x01 };
      ]);
    assert (I8080.Step.control_flow step = I8080.Step.Restart { target });
    assert_flags_unchanged state before
  done

let test_exchange_and_special_transfers () =
  let xchg, state, _ = machine (Bytes.of_string "\xeb") in
  I8080.State.set_de state 0x1234;
  I8080.State.set_hl state 0xabcd;
  let before = flags_snapshot state in
  let step = step_ok xchg in
  assert (I8080.State.de state = 0xabcd);
  assert (I8080.State.hl state = 0x1234);
  assert (I8080.Step.memory_accesses step = []);
  assert_flags_unchanged state before;
  let xthl, state, memory = machine (Bytes.of_string "\xe3") in
  I8080.State.set_sp state 0xffff;
  I8080.State.set_hl state 0x1234;
  I8080.Memory.write memory 0xffff 0x56;
  I8080.Memory.write memory 0x0000 0x78;
  let before = flags_snapshot state in
  let step = step_ok xthl in
  assert (I8080.State.hl state = 0x7856);
  assert (I8080.Memory.read memory 0xffff = 0x34);
  assert (I8080.Memory.read memory 0x0000 = 0x12);
  assert
    (I8080.Step.memory_accesses step
    =
    [
      I8080.Step.Read { address = 0xffff; value = 0x56 };
      I8080.Step.Read { address = 0x0000; value = 0x78 };
      I8080.Step.Write { address = 0xffff; value = 0x34 };
      I8080.Step.Write { address = 0x0000; value = 0x12 };
    ]);
  assert_flags_unchanged state before;
  let pchl, state, _ = machine (Bytes.of_string "\xe9") in
  I8080.State.set_hl state 0x2468;
  let before = flags_snapshot state in
  let step = step_ok pchl in
  assert (I8080.State.pc state = 0x2468);
  assert (I8080.Step.control_flow step = I8080.Step.Jump { target = 0x2468; taken = true });
  assert_flags_unchanged state before;
  let sphl, state, _ = machine (Bytes.of_string "\xf9") in
  I8080.State.set_hl state 0x1357;
  let before = flags_snapshot state in
  let step = step_ok sphl in
  assert (I8080.State.sp state = 0x1357);
  assert (I8080.State.pc state = 0x0101);
  assert (I8080.Step.control_flow step = I8080.Step.Sequential);
  assert_flags_unchanged state before

let test_io_atomicity () =
  let emitted = ref None in
  let input_cpu, input_state, _ =
    machine ~input:(fun ~port -> port lxor 0xa5) (Bytes.of_string "\xdb\x42")
  in
  I8080.State.set_a input_state 0x5a;
  let before = flags_snapshot input_state in
  let input_step = step_ok input_cpu in
  assert (I8080.State.a input_state = 0xe7);
  assert (I8080.State.pc input_state = 0x0102);
  assert (I8080.Step.memory_accesses input_step = []);
  assert_flags_unchanged input_state before;
  let output_cpu, output_state, _ =
    machine
      ~output:(fun ~port ~value -> emitted := Some (port, value))
      (Bytes.of_string "\xd3\x24")
  in
  I8080.State.set_a output_state 0x96;
  let before = flags_snapshot output_state in
  let output_step = step_ok output_cpu in
  assert (!emitted = Some (0x24, 0x96));
  assert (I8080.State.pc output_state = 0x0102);
  assert (I8080.Step.memory_accesses output_step = []);
  assert_flags_unchanged output_state before;
  let missing_input, input_state, _ = machine (Bytes.of_string "\xdb\x42") in
  I8080.State.set_a input_state 0x55;
  I8080.Flags.set_carry (I8080.State.flags input_state) true;
  let before = flags_snapshot input_state in
  (match I8080.Cpu.step missing_input with
  | Error (I8080.Cpu.Bus_io_error (I8080.Bus.Input_port_not_configured 0x42)) -> ()
  | Error
      (I8080.Cpu.Bus_io_error
        (I8080.Bus.Input_port_not_configured _ | I8080.Bus.Output_port_not_configured _))
    -> failwith "wrong error for unconfigured IN port"
  | Error (I8080.Cpu.Decode_error _) -> failwith "unexpected decode error for IN"
  | Error (I8080.Cpu.Unsupported_instruction _) -> failwith "IN is unsupported"
  | Error (I8080.Cpu.Interrupt_acknowledge_length _) -> failwith "unexpected interrupt error"
  | Error I8080.Cpu.Cpu_halted -> failwith "fresh CPU unexpectedly halted"
  | Ok _ -> failwith "unconfigured IN unexpectedly succeeded");
  assert (I8080.State.pc input_state = 0x0100);
  assert (I8080.State.a input_state = 0x55);
  assert_flags_unchanged input_state before;
  let missing_output, output_state, _ = machine (Bytes.of_string "\xd3\x24") in
  I8080.State.set_a output_state 0x96;
  let before = flags_snapshot output_state in
  (match I8080.Cpu.step missing_output with
  | Error (I8080.Cpu.Bus_io_error (I8080.Bus.Output_port_not_configured 0x24)) -> ()
  | Error
      (I8080.Cpu.Bus_io_error
        (I8080.Bus.Input_port_not_configured _ | I8080.Bus.Output_port_not_configured _))
    -> failwith "wrong error for unconfigured OUT port"
  | Error (I8080.Cpu.Decode_error _) -> failwith "unexpected decode error for OUT"
  | Error (I8080.Cpu.Unsupported_instruction _) -> failwith "OUT is unsupported"
  | Error (I8080.Cpu.Interrupt_acknowledge_length _) -> failwith "unexpected interrupt error"
  | Error I8080.Cpu.Cpu_halted -> failwith "fresh CPU unexpectedly halted"
  | Ok _ -> failwith "unconfigured OUT unexpectedly succeeded");
  assert (I8080.State.pc output_state = 0x0100);
  assert (I8080.State.a output_state = 0x96);
  assert_flags_unchanged output_state before

let test_halt () =
  let cpu, state, _ = machine (Bytes.of_string "\x76\x00") in
  assert (not (I8080.Cpu.is_halted cpu));
  let before = flags_snapshot state in
  let step = step_ok cpu in
  assert (I8080.Cpu.is_halted cpu);
  assert (I8080.State.pc state = 0x0101);
  assert (I8080.Step.control_flow step = I8080.Step.Halt);
  assert (I8080.Step.memory_accesses step = []);
  assert_flags_unchanged state before;
  (match I8080.Cpu.step cpu with
  | Error I8080.Cpu.Cpu_halted -> ()
  | Error (I8080.Cpu.Decode_error _) -> failwith "second HLT step decoded again"
  | Error (I8080.Cpu.Unsupported_instruction _) -> failwith "second HLT step decoded again"
  | Error (I8080.Cpu.Bus_io_error _) -> failwith "second HLT step performed I/O"
  | Error (I8080.Cpu.Interrupt_acknowledge_length _) -> failwith "second HLT step decoded acknowledge"
  | Ok _ -> failwith "halted CPU fetched another instruction");
  assert (I8080.State.pc state = 0x0101)

let is_deferred = function
  | I8080.Instr.Ei
  | I8080.Instr.Di -> false
  | I8080.Instr.Inr _
  | I8080.Instr.Dcr _
  | I8080.Instr.Dad _
  | I8080.Instr.Alu _
  | I8080.Instr.Alu_immediate _
  | I8080.Instr.Rotate _
  | I8080.Instr.Daa
  | I8080.Instr.Cma
  | I8080.Instr.Stc
  | I8080.Instr.Cmc
  | I8080.Instr.Nop
  | I8080.Instr.Mov _
  | I8080.Instr.Mvi _
  | I8080.Instr.Lxi _
  | I8080.Instr.Ldax _
  | I8080.Instr.Stax _
  | I8080.Instr.Lda _
  | I8080.Instr.Sta _
  | I8080.Instr.Lhld _
  | I8080.Instr.Shld _
  | I8080.Instr.Inx _
  | I8080.Instr.Dcx _
  | I8080.Instr.Push _
  | I8080.Instr.Pop _
  | I8080.Instr.Jump _
  | I8080.Instr.Call _
  | I8080.Instr.Return _
  | I8080.Instr.Rst _
  | I8080.Instr.Input _
  | I8080.Instr.Output _
  | I8080.Instr.Xthl
  | I8080.Instr.Xchg
  | I8080.Instr.Pchl
  | I8080.Instr.Sphl
  | I8080.Instr.Hlt -> false

let test_all_opcodes_classified () =
  let open I8080.Decode in
  let deferred_count = ref 0 in
  let implemented_count = ref 0 in
  for opcode = 0 to 255 do
    let program = Bytes.make 3 '\000' in
    Bytes.set program 0 (Char.chr opcode);
    let decoded =
      match I8080.Decode.decode program ~offset:0 with
      | Ok decoded -> decoded
      | Error _ -> failwith "complete opcode buffer failed to decode"
    in
    let expected_deferred = is_deferred decoded.instr in
    assert (not expected_deferred);
    if expected_deferred then incr deferred_count else incr implemented_count;
    let cpu, _, _ = machine program in
    match I8080.Cpu.step cpu with
    | Error (I8080.Cpu.Unsupported_instruction unsupported) ->
        failwith (Printf.sprintf "opcode 0x%02X remains unsupported" unsupported.opcode)
    | Error (I8080.Cpu.Bus_io_error _) -> assert (opcode = 0xdb || opcode = 0xd3)
    | Error (I8080.Cpu.Decode_error _) -> failwith "complete opcode unexpectedly truncated"
    | Error (I8080.Cpu.Interrupt_acknowledge_length _) -> failwith "unexpected acknowledge error"
    | Error I8080.Cpu.Cpu_halted -> failwith "fresh CPU unexpectedly halted"
    | Ok _ -> assert (not expected_deferred)
  done;
  assert (!deferred_count = 0);
  assert (!implemented_count = 256);
  print_endline "Opcode coverage: 256 supported, none intentionally unsupported"

let () =
  test_mov_matrix ();
  test_inx_dcx ();
  test_memory_transfer_family ();
  test_stack_pairs_and_wrap ();
  test_psw_stack_exhaustive ();
  test_conditions ();
  test_restarts ();
  test_exchange_and_special_transfers ();
  test_io_atomicity ();
  test_halt ();
  test_all_opcodes_classified ()
