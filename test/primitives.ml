open I8080.Decode

let expect_invalid_argument f =
  match f () with
  | () -> failwith "expected Invalid_argument"
  | exception Invalid_argument _ -> ()

let test_flags () =
  let flags = I8080.Flags.create () in
  let all_clear () =
    not (I8080.Flags.sign flags)
    && not (I8080.Flags.zero flags)
    && not (I8080.Flags.auxiliary_carry flags)
    && not (I8080.Flags.parity flags)
    && not (I8080.Flags.carry flags)
  in
  assert (all_clear ());
  I8080.Flags.set_sign flags true;
  assert (I8080.Flags.sign flags);
  assert (not (I8080.Flags.zero flags));
  I8080.Flags.set_zero flags true;
  assert (I8080.Flags.zero flags);
  assert (I8080.Flags.sign flags);
  I8080.Flags.set_auxiliary_carry flags true;
  assert (I8080.Flags.auxiliary_carry flags);
  assert (I8080.Flags.zero flags);
  I8080.Flags.set_parity flags true;
  assert (I8080.Flags.parity flags);
  assert (I8080.Flags.auxiliary_carry flags);
  I8080.Flags.set_carry flags true;
  assert (I8080.Flags.carry flags);
  assert (I8080.Flags.parity flags);
  let same = I8080.Flags.create () in
  I8080.Flags.set_sign same true;
  I8080.Flags.set_zero same true;
  I8080.Flags.set_auxiliary_carry same true;
  I8080.Flags.set_parity same true;
  I8080.Flags.set_carry same true;
  assert (I8080.Flags.equal flags same);
  I8080.Flags.reset flags;
  assert (all_clear ());
  assert (not (I8080.Flags.equal flags same))

let test_state () =
  let state = I8080.State.create () in
  assert (I8080.State.a state = 0);
  assert (I8080.State.b state = 0);
  assert (I8080.State.c state = 0);
  assert (I8080.State.d state = 0);
  assert (I8080.State.e state = 0);
  assert (I8080.State.h state = 0);
  assert (I8080.State.l state = 0);
  assert (I8080.State.sp state = 0);
  assert (I8080.State.pc state = 0);
  assert (not (I8080.Flags.carry (I8080.State.flags state)));
  I8080.State.set_a state 0xff;
  I8080.State.set_b state 0x12;
  I8080.State.set_c state 0x34;
  I8080.State.set_d state 0x56;
  I8080.State.set_e state 0x78;
  I8080.State.set_h state 0x9a;
  I8080.State.set_l state 0xbc;
  I8080.State.set_sp state 0xffff;
  I8080.State.set_pc state 0x8001;
  assert (I8080.State.a state = 0xff);
  assert (I8080.State.b state = 0x12);
  assert (I8080.State.c state = 0x34);
  assert (I8080.State.d state = 0x56);
  assert (I8080.State.e state = 0x78);
  assert (I8080.State.h state = 0x9a);
  assert (I8080.State.l state = 0xbc);
  assert (I8080.State.sp state = 0xffff);
  assert (I8080.State.pc state = 0x8001);
  assert (I8080.State.bc state = 0x1234);
  assert (I8080.State.de state = 0x5678);
  assert (I8080.State.hl state = 0x9abc);
  I8080.State.set_bc state 0xabcd;
  I8080.State.set_de state 0x0123;
  I8080.State.set_hl state 0xfedc;
  assert (I8080.State.b state = 0xab && I8080.State.c state = 0xcd);
  assert (I8080.State.d state = 0x01 && I8080.State.e state = 0x23);
  assert (I8080.State.h state = 0xfe && I8080.State.l state = 0xdc);
  I8080.State.set_a state 0x10;
  assert (I8080.State.b state = 0xab && I8080.State.c state = 0xcd);
  I8080.Flags.set_carry (I8080.State.flags state) true;
  assert (I8080.Flags.carry (I8080.State.flags state));
  expect_invalid_argument (fun () -> I8080.State.set_a state (-1));
  expect_invalid_argument (fun () -> I8080.State.set_l state 0x100);
  expect_invalid_argument (fun () -> I8080.State.set_sp state (-1));
  expect_invalid_argument (fun () -> I8080.State.set_pc state 0x10000);
  expect_invalid_argument (fun () -> I8080.State.set_bc state 0x10000);
  assert (I8080.State.a state = 0x10);
  assert (I8080.State.sp state = 0xffff);
  assert (I8080.State.pc state = 0x8001)

let test_memory () =
  let memory = I8080.Memory.create () in
  assert (I8080.Memory.size = 65536);
  assert (I8080.Memory.read memory 0 = 0);
  assert (I8080.Memory.read memory 0xffff = 0);
  I8080.Memory.write memory 0 0x12;
  I8080.Memory.write memory 0xffff 0x34;
  assert (I8080.Memory.read memory 0 = 0x12);
  assert (I8080.Memory.read memory 0xffff = 0x34);
  let source = Bytes.of_string "\xaa\xbb\xcc" in
  I8080.Memory.load memory ~address:0x0100 source;
  assert (I8080.Memory.read_range memory ~address:0x0100 ~length:3 = source);
  Bytes.set source 0 '\000';
  assert (I8080.Memory.read memory 0x0100 = 0xaa);
  I8080.Memory.write16 memory 0x2000 0x1234;
  assert (I8080.Memory.read memory 0x2000 = 0x34);
  assert (I8080.Memory.read memory 0x2001 = 0x12);
  assert (I8080.Memory.read16 memory 0x2000 = 0x1234);
  I8080.Memory.write memory 0xffff 0x78;
  I8080.Memory.write memory 0 0x56;
  assert (I8080.Memory.read16 memory 0xffff = 0x5678);
  I8080.Memory.write16 memory 0xffff 0xabcd;
  assert (I8080.Memory.read memory 0xffff = 0xcd);
  assert (I8080.Memory.read memory 0 = 0xab);
  expect_invalid_argument (fun () -> ignore (I8080.Memory.read memory (-1)));
  expect_invalid_argument (fun () -> ignore (I8080.Memory.read memory 0x10000));
  expect_invalid_argument (fun () -> I8080.Memory.write memory 0 (-1));
  expect_invalid_argument (fun () -> I8080.Memory.write memory 0 0x100);
  expect_invalid_argument (fun () -> I8080.Memory.load memory ~address:0xffff source);
  expect_invalid_argument (fun () ->
      ignore (I8080.Memory.read_range memory ~address:0xffff ~length:2));
  expect_invalid_argument (fun () -> ignore (I8080.Memory.read16 memory 0x10000));
  expect_invalid_argument (fun () -> I8080.Memory.write16 memory 0 (-1));
  expect_invalid_argument (fun () -> I8080.Memory.write16 memory 0 0x10000)

let expected_length opcode =
  let three_byte =
    [
      0x01; 0x11; 0x21; 0x31; 0x22; 0x2a; 0x32; 0x3a;
      0xc2; 0xca; 0xd2; 0xda; 0xe2; 0xea; 0xf2; 0xfa;
      0xc3; 0xcb; 0xc4; 0xcc; 0xd4; 0xdc; 0xe4; 0xec; 0xf4; 0xfc;
      0xcd; 0xdd; 0xed; 0xfd;
    ]
  in
  let two_byte =
    [
      0x06; 0x0e; 0x16; 0x1e; 0x26; 0x2e; 0x36; 0x3e;
      0xd3; 0xdb; 0xc6; 0xce; 0xd6; 0xde; 0xe6; 0xee; 0xf6; 0xfe;
    ]
  in
  if List.mem opcode three_byte then 3
  else if List.mem opcode two_byte then 2
  else 1

let decode_ok bytes offset =
  match I8080.Decode.decode bytes ~offset with
  | Ok decoded -> decoded
  | Error (I8080.Decode.Invalid_offset _) -> failwith "expected valid buffer offset"
  | Error (I8080.Decode.Truncated _) -> failwith "expected complete instruction"

let test_decoder_coverage () =
  let seen = Array.make 256 false in
  let documented = ref 0 in
  let aliases = ref 0 in
  let uncertain = ref 0 in
  for opcode = 0 to 255 do
    assert (not seen.(opcode));
    seen.(opcode) <- true;
    let expected = expected_length opcode in
    let info = I8080.Decode.opcode_info opcode in
    if info.instruction_length <> expected then
      failwith
        (Printf.sprintf "opcode 0x%02x: expected length %d, got %d" opcode expected
           info.instruction_length);
    assert (List.mem info.instruction_length [ 1; 2; 3 ]);
    let bytes = Bytes.make 3 '\000' in
    Bytes.set bytes 0 (Char.chr opcode);
    let decoded = decode_ok bytes 0 in
    assert (decoded.opcode = opcode);
    assert (decoded.length = expected);
    assert (decoded.status = info.encoding_status);
    (match decoded.status with
    | I8080.Decode.Documented -> incr documented
    | I8080.Decode.Undocumented_alias -> incr aliases
    | I8080.Decode.Uncertain _ -> incr uncertain);
    let short = Bytes.make 1 (Char.chr opcode) in
    (match expected with
    | 1 -> (
        match I8080.Decode.decode short ~offset:0 with
        | Ok _ -> ()
        | Error (I8080.Decode.Invalid_offset _) -> failwith "opcode byte was present"
        | Error (I8080.Decode.Truncated _) -> failwith "one-byte opcode was truncated")
    | 2 | 3 -> (
        match I8080.Decode.decode short ~offset:0 with
        | Error (I8080.Decode.Truncated { opcode = found; required; available }) ->
            assert (found = opcode);
            assert (required = expected);
            assert (available = 1)
        | Ok _ -> failwith "immediate instruction unexpectedly decoded"
        | Error (I8080.Decode.Invalid_offset _) -> failwith "opcode byte was present")
    | _ -> failwith "invalid expected instruction length")
  done;
  assert (Array.for_all Fun.id seen);
  assert (!documented = 244);
  assert (!aliases = 12);
  assert (!uncertain = 0)

let test_instruction_lengths_and_truncation () =
  for opcode = 0 to 255 do
    let length = expected_length opcode in
    let bytes = Bytes.make length '\000' in
    Bytes.set bytes 0 (Char.chr opcode);
    let decoded = decode_ok bytes 0 in
    assert (decoded.length = length)
  done;
  (match I8080.Decode.decode Bytes.empty ~offset:0 with
  | Error (I8080.Decode.Invalid_offset 0) -> ()
  | Error (I8080.Decode.Invalid_offset _) -> failwith "unexpected invalid offset"
  | Error (I8080.Decode.Truncated _) -> failwith "empty buffer has no opcode"
  | Ok _ -> failwith "empty buffer unexpectedly decoded");
  (match I8080.Decode.decode (Bytes.of_string "\000") ~offset:(-1) with
  | Error (I8080.Decode.Invalid_offset (-1)) -> ()
  | Error (I8080.Decode.Invalid_offset _) -> failwith "wrong negative offset reported"
  | Error (I8080.Decode.Truncated _) -> failwith "negative offset has no opcode"
  | Ok _ -> failwith "negative offset unexpectedly decoded");
  let bytes = Bytes.of_string "\000\xc3\x34\x12" in
  let decoded = decode_ok bytes 1 in
  assert (decoded.opcode = 0xc3);
  assert (decoded.instr = I8080.Instr.Jump (None, 0x1234));
  (match I8080.Decode.decode bytes ~offset:(Bytes.length bytes) with
  | Error (I8080.Decode.Invalid_offset offset) -> assert (offset = Bytes.length bytes)
  | Error (I8080.Decode.Truncated _) -> failwith "no opcode at end of buffer"
  | Ok _ -> failwith "offset at end of buffer unexpectedly decoded");
  expect_invalid_argument (fun () -> ignore (I8080.Decode.opcode_info (-1)));
  expect_invalid_argument (fun () -> ignore (I8080.Decode.opcode_info 0x100))

let test_instruction_families () =
  let decode_one opcode tail =
    let bytes = Bytes.make (1 + Bytes.length tail) '\000' in
    Bytes.set bytes 0 (Char.chr opcode);
    Bytes.blit tail 0 bytes 1 (Bytes.length tail);
    decode_ok bytes 0
  in
  assert
    ((decode_one 0x7e Bytes.empty).instr
    = I8080.Instr.Mov (I8080.Instr.Register I8080.Instr.A, I8080.Instr.Memory_at_HL));
  assert
    ((decode_one 0x36 (Bytes.of_string "\xa5")).instr
    = I8080.Instr.Mvi (I8080.Instr.Memory_at_HL, 0xa5));
  assert
    ((decode_one 0x01 (Bytes.of_string "\x34\x12")).instr
    = I8080.Instr.Lxi (I8080.Instr.BC, 0x1234));
  assert ((decode_one 0x02 Bytes.empty).instr = I8080.Instr.Stax I8080.Instr.Indirect_BC);
  assert ((decode_one 0x1a Bytes.empty).instr = I8080.Instr.Ldax I8080.Instr.Indirect_DE);
  assert ((decode_one 0x34 Bytes.empty).instr = I8080.Instr.Inr I8080.Instr.Memory_at_HL);
  assert ((decode_one 0x2b Bytes.empty).instr = I8080.Instr.Dcx I8080.Instr.HL);
  assert
    ((decode_one 0x22 (Bytes.of_string "\x34\x12")).instr
    = I8080.Instr.Shld 0x1234);
  assert ((decode_one 0x3a (Bytes.of_string "\x34\x12")).instr = I8080.Instr.Lda 0x1234);
  assert
    ((decode_one 0x86 Bytes.empty).instr
    = I8080.Instr.Alu (I8080.Instr.Add, I8080.Instr.Memory_at_HL));
  assert
    ((decode_one 0xfe (Bytes.of_string "\x7f")).instr
    = I8080.Instr.Alu_immediate (I8080.Instr.Compare, 0x7f));
  assert
    ((decode_one 0x17 Bytes.empty).instr
    = I8080.Instr.Rotate I8080.Instr.Rotate_left_through_carry);
  assert ((decode_one 0x27 Bytes.empty).instr = I8080.Instr.Daa);
  assert ((decode_one 0x2f Bytes.empty).instr = I8080.Instr.Cma);
  assert ((decode_one 0x37 Bytes.empty).instr = I8080.Instr.Stc);
  assert ((decode_one 0x3f Bytes.empty).instr = I8080.Instr.Cmc);
  assert ((decode_one 0xf5 Bytes.empty).instr = I8080.Instr.Push I8080.Instr.PSW);
  assert ((decode_one 0xe1 Bytes.empty).instr = I8080.Instr.Pop I8080.Instr.Stack_HL);
  assert
    ((decode_one 0xc2 (Bytes.of_string "\x34\x12")).instr
    = I8080.Instr.Jump (Some I8080.Instr.Not_zero, 0x1234));
  assert
    ((decode_one 0xcd (Bytes.of_string "\x34\x12")).instr
    = I8080.Instr.Call (None, 0x1234));
  assert
    ((decode_one 0xc4 (Bytes.of_string "\x34\x12")).instr
    = I8080.Instr.Call (Some I8080.Instr.Not_zero, 0x1234));
  assert ((decode_one 0xc0 Bytes.empty).instr = I8080.Instr.Return (Some I8080.Instr.Not_zero));
  assert ((decode_one 0xff Bytes.empty).instr = I8080.Instr.Rst 7);
  assert ((decode_one 0xdb (Bytes.of_string "\x42")).instr = I8080.Instr.Input 0x42);
  assert ((decode_one 0xd3 (Bytes.of_string "\x42")).instr = I8080.Instr.Output 0x42);
  assert ((decode_one 0xe3 Bytes.empty).instr = I8080.Instr.Xthl);
  assert ((decode_one 0xeb Bytes.empty).instr = I8080.Instr.Xchg);
  assert ((decode_one 0xe9 Bytes.empty).instr = I8080.Instr.Pchl);
  assert ((decode_one 0xf9 Bytes.empty).instr = I8080.Instr.Sphl);
  assert ((decode_one 0xfb Bytes.empty).instr = I8080.Instr.Ei);
  assert ((decode_one 0xf3 Bytes.empty).instr = I8080.Instr.Di);
  assert ((decode_one 0x76 Bytes.empty).instr = I8080.Instr.Hlt)

let test_undocumented_aliases () =
  let aliases = [ 0x08; 0x10; 0x18; 0x20; 0x28; 0x30; 0x38; 0xcb; 0xd9; 0xdd; 0xed; 0xfd ] in
  for opcode = 0 to 255 do
    let expected_alias = List.mem opcode aliases in
    let info = I8080.Decode.opcode_info opcode in
    assert
      (info.encoding_status
      = if expected_alias then I8080.Decode.Undocumented_alias else I8080.Decode.Documented)
  done;
  List.iter
    (fun opcode ->
      let bytes = Bytes.of_string (String.make 1 (Char.chr opcode) ^ "\x34\x12") in
      let decoded = decode_ok bytes 0 in
      assert (decoded.status = I8080.Decode.Undocumented_alias);
      if opcode <= 0x38 then assert (decoded.instr = I8080.Instr.Nop)
      else
        match opcode with
        | 0xcb -> assert (decoded.instr = I8080.Instr.Jump (None, 0x1234))
        | 0xd9 -> assert (decoded.instr = I8080.Instr.Return None)
        | 0xdd | 0xed | 0xfd -> assert (decoded.instr = I8080.Instr.Call (None, 0x1234))
        | _ -> assert false)
    aliases;
  let documented_jump = decode_ok (Bytes.of_string "\xc3\x34\x12") 0 in
  let alias_jump = decode_ok (Bytes.of_string "\xcb\x34\x12") 0 in
  assert (documented_jump.instr = alias_jump.instr);
  assert (documented_jump.opcode = 0xc3);
  assert (alias_jump.opcode = 0xcb);
  assert (documented_jump.status = I8080.Decode.Documented);
  assert (alias_jump.status = I8080.Decode.Undocumented_alias)

let flags_from_pattern flags pattern =
  I8080.Flags.set_sign flags (pattern land 0x01 <> 0);
  I8080.Flags.set_zero flags (pattern land 0x02 <> 0);
  I8080.Flags.set_auxiliary_carry flags (pattern land 0x04 <> 0);
  I8080.Flags.set_parity flags (pattern land 0x08 <> 0);
  I8080.Flags.set_carry flags (pattern land 0x10 <> 0)

let psw_from_pattern pattern =
  (if pattern land 0x01 <> 0 then 0x80 else 0)
  lor (if pattern land 0x02 <> 0 then 0x40 else 0)
  lor (if pattern land 0x04 <> 0 then 0x10 else 0)
  lor (if pattern land 0x08 <> 0 then 0x04 else 0)
  lor (if pattern land 0x10 <> 0 then 0x01 else 0)
  lor 0x02

let test_psw_flags () =
  let reserved_mask = 0x2a in
  for pattern = 0 to 31 do
    let flags = I8080.Flags.create () in
    flags_from_pattern flags pattern;
    let packed = I8080.Flags.to_psw_byte flags in
    assert (packed = psw_from_pattern pattern);
    assert (packed land reserved_mask = 0x02);
    let restored = I8080.Flags.create () in
    I8080.Flags.restore_from_psw_byte restored packed;
    assert (I8080.Flags.equal restored flags);
    for fill = 0 to 7 do
      let reserved_value =
        ((fill land 1) lsl 1)
        lor (((fill lsr 1) land 1) lsl 3)
        lor (((fill lsr 2) land 1) lsl 5)
      in
      let arbitrary_byte = (packed land lnot reserved_mask) lor reserved_value in
      I8080.Flags.restore_from_psw_byte restored arbitrary_byte;
      assert (I8080.Flags.equal restored flags)
    done
  done;
  expect_invalid_argument (fun () -> I8080.Flags.restore_from_psw_byte (I8080.Flags.create ()) (-1));
  expect_invalid_argument (fun () -> I8080.Flags.restore_from_psw_byte (I8080.Flags.create ()) 0x100)

let test_bus () =
  let memory = I8080.Memory.create () in
  let bus = I8080.Bus.create memory in
  (match I8080.Bus.input bus ~port:0x42 with
  | Error (I8080.Bus.Input_port_not_configured 0x42) -> ()
  | Error (I8080.Bus.Input_port_not_configured _) -> failwith "wrong input port reported"
  | Error (I8080.Bus.Output_port_not_configured _) -> failwith "wrong I/O error reported"
  | Ok _ -> failwith "unconfigured input port must fail explicitly");
  (match I8080.Bus.output bus ~port:0x24 ~value:0x81 with
  | Error (I8080.Bus.Output_port_not_configured 0x24) -> ()
  | Error (I8080.Bus.Output_port_not_configured _) -> failwith "wrong output port reported"
  | Error (I8080.Bus.Input_port_not_configured _) -> failwith "wrong I/O error reported"
  | Ok () -> failwith "unconfigured output port must fail explicitly");
  let emitted = ref None in
  let configured =
    I8080.Bus.create ~input:(fun ~port -> port lxor 0xff)
      ~output:(fun ~port ~value -> emitted := Some (port, value)) memory
  in
  assert (I8080.Bus.input configured ~port:0x12 = Ok 0xed);
  assert (I8080.Bus.output configured ~port:0x34 ~value:0x56 = Ok ());
  assert (!emitted = Some (0x34, 0x56));
  expect_invalid_argument (fun () -> ignore (I8080.Bus.input bus ~port:(-1)));
  expect_invalid_argument (fun () -> ignore (I8080.Bus.output bus ~port:0x100 ~value:0));
  expect_invalid_argument (fun () -> ignore (I8080.Bus.output bus ~port:0 ~value:0x100))

let set_all_flags flags = I8080.Flags.restore_from_psw_byte flags 0xd7

let make_cpu ~pc ~sp program =
  let memory = I8080.Memory.create () in
  I8080.Memory.load memory ~address:pc program;
  let state = I8080.State.create () in
  I8080.State.set_pc state pc;
  I8080.State.set_sp state sp;
  set_all_flags (I8080.State.flags state);
  let bus = I8080.Bus.create memory in
  let cpu = I8080.Cpu.create ~state ~bus in
  (cpu, state, memory, bus)

let step_ok cpu =
  match I8080.Cpu.step cpu with
  | Ok step -> step
  | Error _ -> failwith "expected Cpu.step to succeed"

let assert_preserved_flags state =
  let expected = I8080.Flags.create () in
  set_all_flags expected;
  assert (I8080.Flags.equal (I8080.State.flags state) expected)

let test_cpu_nop_and_mvi () =
  let cpu, state, memory, _bus =
    make_cpu ~pc:0x1000 ~sp:0x9000 (Bytes.of_string "\x00\x3e\xa5\x36\x5a")
  in
  let nop = step_ok cpu in
  assert (I8080.Step.pc_before nop = 0x1000);
  assert (I8080.Step.pc_after nop = 0x1001);
  assert ((I8080.Step.decoded nop).opcode = 0x00);
  assert (Bytes.equal (I8080.Step.fetched_bytes nop) (Bytes.of_string "\x00"));
  assert (I8080.Step.memory_accesses nop = []);
  assert (I8080.Step.control_flow nop = I8080.Step.Sequential);
  assert_preserved_flags state;
  let mvi_register = step_ok cpu in
  assert (Bytes.equal (I8080.Step.fetched_bytes mvi_register) (Bytes.of_string "\x3e\xa5"));
  assert (I8080.Step.pc_before mvi_register = 0x1001);
  assert (I8080.Step.pc_after mvi_register = 0x1003);
  assert (I8080.State.a state = 0xa5);
  assert (I8080.Step.memory_accesses mvi_register = []);
  assert_preserved_flags state;
  I8080.State.set_hl state 0x4567;
  (* Set HL before MVI M below; this also proves the destination is resolved
     from the register pair rather than from a fixed or opcode-derived address. *)
  let mvi_memory = step_ok cpu in
  let access = I8080.Step.Write { address = 0x4567; value = 0x5a } in
  assert (I8080.Step.pc_after mvi_memory = 0x1005);
  assert (I8080.Step.memory_accesses mvi_memory = [ access ]);
  assert (I8080.Memory.read memory 0x4567 = 0x5a);
  assert_preserved_flags state

let test_cpu_lxi () =
  let cases =
    [
      (0x01, fun state -> I8080.State.bc state);
      (0x11, fun state -> I8080.State.de state);
      (0x21, fun state -> I8080.State.hl state);
      (0x31, fun state -> I8080.State.sp state);
    ]
  in
  List.iter
    (fun (opcode, read_pair) ->
      let program = Bytes.of_string (String.make 1 (Char.chr opcode) ^ "\x34\x12") in
      let cpu, state, _memory, _bus = make_cpu ~pc:0x2000 ~sp:0x9000 program in
      let step = step_ok cpu in
      assert (read_pair state = 0x1234);
      assert (I8080.Step.pc_after step = 0x2003);
      assert (Bytes.equal (I8080.Step.fetched_bytes step) program);
      assert (I8080.Step.memory_accesses step = []);
      assert_preserved_flags state)
    cases

let test_cpu_call_ret () =
  let cpu, state, memory, _bus =
    make_cpu ~pc:0x2000 ~sp:0x3000 (Bytes.of_string "\xcd\x34\x12")
  in
  let call = step_ok cpu in
  assert (I8080.Step.pc_before call = 0x2000);
  assert (I8080.Step.pc_after call = 0x1234);
  assert (I8080.State.sp state = 0x2ffe);
  assert (I8080.Memory.read memory 0x2fff = 0x20);
  assert (I8080.Memory.read memory 0x2ffe = 0x03);
  assert
    (I8080.Step.memory_accesses call
    =
    [
      I8080.Step.Write { address = 0x2fff; value = 0x20 };
      I8080.Step.Write { address = 0x2ffe; value = 0x03 };
    ]);
  assert (I8080.Step.control_flow call = I8080.Step.Call { target = 0x1234; taken = true });
  assert_preserved_flags state;
  I8080.Memory.write memory 0x1234 0xc9;
  let ret = step_ok cpu in
  assert (I8080.Step.pc_before ret = 0x1234);
  assert (I8080.Step.pc_after ret = 0x2003);
  assert (I8080.State.sp state = 0x3000);
  assert
    (I8080.Step.memory_accesses ret
    =
    [
      I8080.Step.Read { address = 0x2ffe; value = 0x03 };
      I8080.Step.Read { address = 0x2fff; value = 0x20 };
    ]);
  assert (I8080.Step.control_flow ret = I8080.Step.Return { target = Some 0x2003; taken = true });
  assert_preserved_flags state

let test_cpu_stack_wrap () =
  let cpu, state, memory, _bus =
    make_cpu ~pc:0x0200 ~sp:0x0001 (Bytes.of_string "\xcd\x34\x12")
  in
  let call = step_ok cpu in
  assert (I8080.State.sp state = 0xffff);
  assert
    (I8080.Step.memory_accesses call
    =
    [
      I8080.Step.Write { address = 0x0000; value = 0x02 };
      I8080.Step.Write { address = 0xffff; value = 0x03 };
    ]);
  assert (I8080.Memory.read memory 0 = 0x02);
  assert (I8080.Memory.read memory 0xffff = 0x03);
  let ret_pc = 0x0400 in
  I8080.Memory.write memory ret_pc 0xc9;
  I8080.Memory.write memory 0xffff 0xcd;
  I8080.Memory.write memory 0 0xab;
  I8080.State.set_pc state ret_pc;
  I8080.State.set_sp state 0xffff;
  let ret = step_ok cpu in
  assert (I8080.State.pc state = 0xabcd);
  assert (I8080.State.sp state = 0x0001);
  assert
    (I8080.Step.memory_accesses ret
    =
    [
      I8080.Step.Read { address = 0xffff; value = 0xcd };
      I8080.Step.Read { address = 0x0000; value = 0xab };
    ]);
  assert_preserved_flags state

let test_cpu_alias_and_fetch_wrap () =
  List.iter
    (fun opcode ->
      let cpu, state, _memory, _bus =
        make_cpu ~pc:0x0180 ~sp:0x8000 (Bytes.make 1 (Char.chr opcode))
      in
      let step = step_ok cpu in
      assert ((I8080.Step.decoded step).opcode = opcode);
      assert ((I8080.Step.decoded step).status = I8080.Decode.Undocumented_alias);
      assert ((I8080.Step.decoded step).instr = I8080.Instr.Nop);
      assert (I8080.Step.pc_after step = 0x0181);
      assert_preserved_flags state)
    [ 0x08; 0x10; 0x18; 0x20; 0x28; 0x30; 0x38 ];
  let program = Bytes.of_string "\xdd\x04\x01\x00\xd9" in
  let cpu, state, _memory, _bus = make_cpu ~pc:0x0100 ~sp:0x8000 program in
  let call = step_ok cpu in
  let decoded = I8080.Step.decoded call in
  assert (decoded.opcode = 0xdd);
  assert (decoded.status = I8080.Decode.Undocumented_alias);
  assert (decoded.instr = I8080.Instr.Call (None, 0x0104));
  assert (I8080.Step.pc_after call = 0x0104);
  assert_preserved_flags state;
  let ret = step_ok cpu in
  assert ((I8080.Step.decoded ret).opcode = 0xd9);
  assert ((I8080.Step.decoded ret).status = I8080.Decode.Undocumented_alias);
  assert (I8080.Step.pc_after ret = 0x0103);
  assert (I8080.State.sp state = 0x8000);
  assert_preserved_flags state;
  List.iter
    (fun opcode ->
      let program = Bytes.of_string (String.make 1 (Char.chr opcode) ^ "\x34\x12") in
      let cpu, _state, _memory, _bus = make_cpu ~pc:0x0300 ~sp:0x9000 program in
      let step = step_ok cpu in
      assert ((I8080.Step.decoded step).opcode = opcode);
      assert ((I8080.Step.decoded step).instr = I8080.Instr.Call (None, 0x1234));
      assert (I8080.Step.pc_after step = 0x1234))
    [ 0xdd; 0xed; 0xfd ];
  let memory = I8080.Memory.create () in
  I8080.Memory.write memory 0xffff 0x3e;
  I8080.Memory.write memory 0x0000 0x7b;
  let wrap_state = I8080.State.create () in
  I8080.State.set_pc wrap_state 0xffff;
  set_all_flags (I8080.State.flags wrap_state);
  let wrap_cpu = I8080.Cpu.create ~state:wrap_state ~bus:(I8080.Bus.create memory) in
  let mvi = step_ok wrap_cpu in
  assert (Bytes.equal (I8080.Step.fetched_bytes mvi) (Bytes.of_string "\x3e\x7b"));
  assert (I8080.Step.pc_before mvi = 0xffff);
  assert (I8080.Step.pc_after mvi = 0x0001);
  assert (I8080.State.a wrap_state = 0x7b);
  assert_preserved_flags wrap_state

let test_cpu_ei_executes () =
  let cpu, state, _memory, _bus =
    make_cpu ~pc:0x5000 ~sp:0x7000 (Bytes.of_string "\xfb\x00")
  in
  I8080.State.set_a state 0xa5;
  I8080.State.set_bc state 0x1234;
  let before_pc = I8080.State.pc state in
  let before_flags = I8080.Flags.to_psw_byte (I8080.State.flags state) in
  (match I8080.Cpu.step cpu with
  | Ok step ->
      assert ((I8080.Step.decoded step).opcode = 0xfb);
      assert ((I8080.Step.decoded step).instr = I8080.Instr.Ei);
      assert (I8080.Step.pc_after step = before_pc + 1)
  | Error (I8080.Cpu.Decode_error _) -> failwith "valid instruction bytes failed to decode"
  | Error (I8080.Cpu.Bus_io_error _) -> failwith "unexpected I/O error"
  | Error (I8080.Cpu.Interrupt_acknowledge_length _) -> failwith "unexpected interrupt error"
  | Error I8080.Cpu.Cpu_halted -> failwith "CPU unexpectedly halted"
  | Error (I8080.Cpu.Unsupported_instruction _) -> failwith "EI should execute");
  assert (I8080.State.pc state = before_pc + 1);
  assert (I8080.State.a state = 0xa5);
  assert (I8080.State.bc state = 0x1234);
  assert (I8080.Flags.to_psw_byte (I8080.State.flags state) = before_flags)

let () =
  test_flags ();
  test_state ();
  test_memory ();
  test_decoder_coverage ();
  test_instruction_lengths_and_truncation ();
  test_instruction_families ();
  test_undocumented_aliases ();
  test_psw_flags ();
  test_bus ();
  test_cpu_nop_and_mvi ();
  test_cpu_lxi ();
  test_cpu_call_ret ();
  test_cpu_stack_wrap ();
  test_cpu_alias_and_fetch_wrap ();
  test_cpu_ei_executes ()
