module H = Pli80_host.K123_child_16b3
module M = I8080.Memory
module S = I8080.State

let read path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in channel) (fun () ->
    let bytes = Bytes.create (in_channel_length channel) in
    really_input channel bytes 0 (Bytes.length bytes); bytes)

let flags state : Pli80_host.Recursive_mapped.flags = {
  sign = I8080.Flags.sign (S.flags state);
  zero = I8080.Flags.zero (S.flags state);
  auxiliary_carry = I8080.Flags.auxiliary_carry (S.flags state);
  parity = I8080.Flags.parity (S.flags state);
  carry = I8080.Flags.carry (S.flags state);
}

let psw flags =
  (if flags.Pli80_host.Recursive_mapped.sign then 128 else 0) lor
  (if flags.zero then 64 else 0) lor
  (if flags.auxiliary_carry then 16 else 0) lor
  (if flags.parity then 4 else 0) lor 2 lor
  (if flags.carry then 1 else 0)

let () =
  let ram = ref "" and expected_ram = ref "" and output = ref "" in
  let pc = ref 0 and sp = ref 0 and a = ref 0 and bc = ref 0 in
  let de = ref 0 and hl = ref 0 and psw_in = ref 0 in
  let expected = Array.make 7 0 in
  let arg name value = name, Arg.Set_int value, "captured state" in
  Arg.parse ([
    "--ram", Arg.Set_string ram, "leaf entry RAM";
    "--expected-ram", Arg.Set_string expected_ram, "natural leaf exit RAM";
    "--output", Arg.Set_string output, "proof summary";
    arg "--pc" pc; arg "--sp" sp; arg "--a" a;
    arg "--bc" bc; arg "--de" de; arg "--hl" hl; arg "--psw" psw_in;
    "--expected-pc", Arg.Int (fun v -> expected.(0) <- v), "captured exit";
    "--expected-sp", Arg.Int (fun v -> expected.(1) <- v), "captured exit";
    "--expected-a", Arg.Int (fun v -> expected.(2) <- v), "captured exit";
    "--expected-bc", Arg.Int (fun v -> expected.(3) <- v), "captured exit";
    "--expected-de", Arg.Int (fun v -> expected.(4) <- v), "captured exit";
    "--expected-hl", Arg.Int (fun v -> expected.(5) <- v), "captured exit";
    "--expected-psw", Arg.Int (fun v -> expected.(6) <- v), "captured exit";
  ]) ignore "Independent +16B3 leaf CPU shadow";
  let seed = read !ram and captured_exit = read !expected_ram in
  if Bytes.length seed <> 65536 || Bytes.length captured_exit <> 65536 then
    failwith "RAM size";
  let natural = ref false and synthetic = ref 0 in
  let check carrier operand stack natural_case =
    let input = Bytes.copy seed in
    if not natural_case then
      Bytes.set input (Pli80_host.U16.wrap (carrier+3)) (Char.chr operand);
    let memory = M.create () in
    M.load memory ~address:0 input;
    let cpu_state = S.create () in
    S.set_pc cpu_state !pc; S.set_sp cpu_state stack;
    S.set_a cpu_state !a; S.set_bc cpu_state carrier;
    S.set_de cpu_state !de; S.set_hl cpu_state !hl;
    I8080.Flags.restore_from_psw_byte (S.flags cpu_state) !psw_in;
    let host_memory = Pli80_host.State.of_bytes input in
    let entry : H.state = {
      pc = !pc; sp = stack; a = !a; bc = carrier;
      de = !de; hl = !hl; flags = flags cpu_state;
    } in
    let host_accesses = ref [] in
    let host = H.run host_memory ~entry
      ~observe:(fun access -> host_accesses := access :: !host_accesses) in
    let cpu = I8080.Cpu.create ~state:cpu_state
      ~bus:(I8080.Bus.create memory) in
    let cpu_accesses = ref [] and steps = ref 0 and finished = ref false in
    while not !finished do
      incr steps;
      if !steps > 14 then failwith "leaf did not RET";
      match I8080.Cpu.step cpu with
      | Error _ -> failwith "leaf CPU"
      | Ok step ->
        List.iter (function
          | I8080.Step.Read {address; value} ->
            cpu_accesses := H.Read (address,value) :: !cpu_accesses
          | Write {address; value} ->
            cpu_accesses := H.Write (address,value) :: !cpu_accesses)
          (I8080.Step.memory_accesses step);
        if I8080.Step.pc_before step = 0x38cb then finished := true
    done;
    let actual : H.state = {
      pc = S.pc cpu_state; sp = S.sp cpu_state; a = S.a cpu_state;
      bc = S.bc cpu_state; de = S.de cpu_state; hl = S.hl cpu_state;
      flags = flags cpu_state;
    } in
    if host <> actual then failwith "leaf registers, flags, PC or SP";
    if List.rev !host_accesses <> List.rev !cpu_accesses then
      failwith "leaf ordered accesses";
    let actual_ram = M.read_range memory ~address:0 ~length:65536 in
    if Pli80_host.State.copy host_memory <> actual_ram then
      failwith "leaf full RAM";
    if natural_case then (
      if actual_ram <> captured_exit then failwith "natural exit RAM";
      if [|host.pc;host.sp;host.a;host.bc;host.de;host.hl;psw host.flags|]
         <> expected then failwith "natural exit state";
      natural := true)
    else incr synthetic in
  check !bc 0 !sp true;
  List.iter (fun carrier ->
    List.iter (fun operand ->
      List.iter (fun stack -> check carrier operand stack false)
        [!sp;0xacee;0xac9f])
      [0;1;8;255])
    [0;0xfffe;0xacec;0xac9c];
  let channel = open_out !output in
  Fun.protect ~finally:(fun () -> close_out channel) (fun () ->
    Printf.fprintf channel
      "{\"natural_passed\":%b,\"synthetic_cases\":%d,\"all_passed\":true,\"scope\":\"complete +16B3 leaf through actual RET\"}\n"
      !natural !synthetic)
