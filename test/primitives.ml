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

let () =
  test_flags ();
  test_state ();
  test_memory ()
