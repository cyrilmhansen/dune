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

let () =
  test_flags ();
  test_state ();
  test_memory ();
  test_decoder_coverage ();
  test_instruction_lengths_and_truncation ();
  test_instruction_families ();
  test_undocumented_aliases ()
