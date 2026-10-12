module H = Pli80_host.K123_child_245d_tail
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
  let ram = ref "" and tail_ram = ref "" and next_ram = ref "" in
  let output = ref "" and next_target = ref 0 in
  let pc = ref 0 and sp = ref 0 and a = ref 0 and bc = ref 0 in
  let de = ref 0 and hl = ref 0 and psw_in = ref 0 in
  let expected_tail = Array.make 7 0 in
  let arg name value = name, Arg.Set_int value, "captured state" in
  Arg.parse ([
    "--ram", Arg.Set_string ram, "tail entry RAM";
    "--tail-ram", Arg.Set_string tail_ram, "natural tail exit RAM";
    "--next-ram", Arg.Set_string next_ram, "natural branch child entry RAM";
    "--output", Arg.Set_string output, "proof summary";
    "--next-target", Arg.Set_int next_target, "natural next child";
    arg "--pc" pc; arg "--sp" sp; arg "--a" a;
    arg "--bc" bc; arg "--de" de; arg "--hl" hl; arg "--psw" psw_in;
    "--expected-pc", Arg.Int (fun v -> expected_tail.(0) <- v), "tail exit";
    "--expected-sp", Arg.Int (fun v -> expected_tail.(1) <- v), "tail exit";
    "--expected-a", Arg.Int (fun v -> expected_tail.(2) <- v), "tail exit";
    "--expected-bc", Arg.Int (fun v -> expected_tail.(3) <- v), "tail exit";
    "--expected-de", Arg.Int (fun v -> expected_tail.(4) <- v), "tail exit";
    "--expected-hl", Arg.Int (fun v -> expected_tail.(5) <- v), "tail exit";
    "--expected-psw", Arg.Int (fun v -> expected_tail.(6) <- v), "tail exit";
  ]) ignore "Independent +245D tail and +24BC composition shadow";
  let seed = read !ram and captured_tail = read !tail_ram in
  let captured_next = read !next_ram in
  if List.exists (fun bytes -> Bytes.length bytes <> 65536)
       [seed;captured_tail;captured_next] then failwith "RAM size";
  let natural_tail = ref false and natural_composed = ref false in
  let synthetic_tail = ref 0 and synthetic_composed = ref 0 in
  let check carrier operand stack compose natural =
    let input = Bytes.copy seed in
    if not natural then
      Bytes.set input (Pli80_host.U16.wrap (carrier+3)) (Char.chr operand);
    let memory = M.create () in
    M.load memory ~address:0 input;
    let cpu_state = S.create () in
    S.set_pc cpu_state !pc; S.set_sp cpu_state stack;
    S.set_a cpu_state !a; S.set_bc cpu_state !bc;
    S.set_de cpu_state !de; S.set_hl cpu_state carrier;
    I8080.Flags.restore_from_psw_byte (S.flags cpu_state) !psw_in;
    let host_memory = Pli80_host.State.of_bytes input in
    let entry : H.state = {
      pc = !pc; sp = stack; a = !a; bc = !bc;
      de = !de; hl = carrier; flags = flags cpu_state;
    } in
    let host_accesses = ref [] in
    let observe access = host_accesses := access :: !host_accesses in
    let host : H.state =
      if compose then (
        let result = H.through_branch host_memory ~entry ~observe in
        {pc=result.pc;sp=result.sp;a=result.a;bc=result.bc;
         de=result.de;hl=result.hl;flags=result.flags})
      else H.run host_memory ~entry ~observe in
    let cpu = I8080.Cpu.create ~state:cpu_state
      ~bus:(I8080.Bus.create memory) in
    let cpu_accesses = ref [] and steps = ref 0 and finished = ref false in
    while not !finished do
      incr steps;
      if !steps > 20 then failwith "tail/branch did not terminate";
      match I8080.Cpu.step cpu with
      | Error _ -> failwith "tail/branch CPU"
      | Ok step ->
        List.iter (function
          | I8080.Step.Read {address;value} ->
            cpu_accesses := H.Read (address,value) :: !cpu_accesses
          | Write {address;value} ->
            cpu_accesses := H.Write (address,value) :: !cpu_accesses)
          (I8080.Step.memory_accesses step);
        if compose then
          finished := List.mem (S.pc cpu_state) [0xa3aa;0xa5dc]
        else if I8080.Step.pc_before step = 0x467a then
          finished := true
    done;
    let actual : H.state = {
      pc=S.pc cpu_state;sp=S.sp cpu_state;a=S.a cpu_state;
      bc=S.bc cpu_state;de=S.de cpu_state;hl=S.hl cpu_state;
      flags=flags cpu_state;
    } in
    if host <> actual then failwith "tail/branch registers, flags, PC or SP";
    if List.rev !host_accesses <> List.rev !cpu_accesses then
      failwith "tail/branch ordered accesses";
    let actual_ram = M.read_range memory ~address:0 ~length:65536 in
    if Pli80_host.State.copy host_memory <> actual_ram then
      failwith "tail/branch full RAM";
    if natural then (
      if compose then (
        if actual_ram <> captured_next || host.pc <> !next_target then
          failwith "natural next child";
        natural_composed := true)
      else (
        if actual_ram <> captured_tail then failwith "natural tail exit RAM";
        if [|host.pc;host.sp;host.a;host.bc;host.de;host.hl;psw host.flags|]
           <> expected_tail then failwith "natural tail exit state";
        natural_tail := true))
    else if compose then incr synthetic_composed
    else incr synthetic_tail in
  check !hl 0 !sp false true;
  check !hl 0 !sp true true;
  List.iter (fun carrier ->
    List.iter (fun operand ->
      List.iter (fun stack -> check carrier operand stack false false)
        [!sp;0xac9f;0xad0d];
      check carrier operand !sp true false)
      [0;0x7f;0x80;0xff])
    [0;0xfffe;0xac9c;0xfbbd];
  let channel = open_out !output in
  Fun.protect ~finally:(fun () -> close_out channel) (fun () ->
    Printf.fprintf channel
      "{\"natural_tail\":%b,\"natural_composed\":%b,\"synthetic_tail\":%d,\"synthetic_composed\":%d,\"all_passed\":true}\n"
      !natural_tail !natural_composed !synthetic_tail !synthetic_composed)
