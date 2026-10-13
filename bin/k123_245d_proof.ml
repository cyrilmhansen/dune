module H = Pli80_host.K123_child_7d05_front
module C = Pli80_host.K123_child_245d
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
let psw f =
  (if f.Pli80_host.Recursive_mapped.sign then 128 else 0) lor
  (if f.zero then 64 else 0) lor
  (if f.auxiliary_carry then 16 else 0) lor
  (if f.parity then 4 else 0) lor 2 lor
  (if f.carry then 1 else 0)

let () =
  let journal_path = ref "" and pli2_path = ref "" and ram = ref "" and expected_ram = ref "" and output = ref "" in
  let pc = ref 0 and sp = ref 0 and a = ref 0 and bc = ref 0 in
  let de = ref 0 and hl = ref 0 and psw_in = ref 0 in
  let expected = Array.make 7 0 in
  let arg name value = name, Arg.Set_int value, "captured state" in
  Arg.parse [
    "--journal", Arg.Set_string journal_path, "natural CPU access journal";
    "--pli2", Arg.Set_string pli2_path, "historical PLI2 image";
    "--ram", Arg.Set_string ram, "child entry RAM";
    "--expected-ram", Arg.Set_string expected_ram, "natural return RAM";
    "--output", Arg.Set_string output, "proof summary";
    arg "--pc" pc; arg "--sp" sp; arg "--a" a;
    arg "--bc" bc; arg "--de" de; arg "--hl" hl; arg "--psw" psw_in;
    "--expected-pc", Arg.Int (fun v -> expected.(0) <- v), "captured return";
    "--expected-sp", Arg.Int (fun v -> expected.(1) <- v), "captured return";
    "--expected-a", Arg.Int (fun v -> expected.(2) <- v), "captured return";
    "--expected-bc", Arg.Int (fun v -> expected.(3) <- v), "captured return";
    "--expected-de", Arg.Int (fun v -> expected.(4) <- v), "captured return";
    "--expected-hl", Arg.Int (fun v -> expected.(5) <- v), "captured return";
    "--expected-psw", Arg.Int (fun v -> expected.(6) <- v), "captured return";
  ] ignore "Pass84 complete +245D composition";
  let seed = read !ram and natural_exit = read !expected_ram in
  let pli2 = read !pli2_path in
  if Bytes.length seed <> 65536 || Bytes.length natural_exit <> 65536 then
    failwith "RAM size";
  let synthetic = ref 0 and natural = ref false in
  let check selector natural_case =
    let input = Bytes.copy seed in
    let memory = M.create () in M.load memory ~address:0 input;
    let cpu_state = S.create () in
    S.set_pc cpu_state !pc; S.set_sp cpu_state !sp; S.set_a cpu_state !a;
    S.set_bc cpu_state ((!bc land 0xff00) lor selector);
    S.set_de cpu_state !de; S.set_hl cpu_state !hl;
    I8080.Flags.restore_from_psw_byte (S.flags cpu_state) !psw_in;
    let host_memory = Pli80_host.State.of_bytes input in
    let entry : H.state = {pc= !pc;sp= !sp;a= !a;
      bc=(!bc land 0xff00) lor selector;de= !de;hl= !hl;
      flags=flags cpu_state} in
    let host_events = ref [] in
    let host = C.run host_memory ~pli2 ~entry
      ~observe:(fun event -> host_events := event :: !host_events) in
    let cpu = I8080.Cpu.create ~state:cpu_state ~bus:(I8080.Bus.create memory) in
    let cpu_events = ref [] and steps = ref 0 in
    while S.pc cpu_state <> 0x46bc do
      incr steps;
      if !steps > 5000 then failwith "composition did not return";
      match I8080.Cpu.step cpu with
      | Error _ -> failwith "composition CPU"
      | Ok step ->
        List.iter (function
          | I8080.Step.Read {address;value} ->
            cpu_events := H.Read (address,value) :: !cpu_events
          | Write {address;value} ->
            cpu_events := H.Write (address,value) :: !cpu_events)
          (I8080.Step.memory_accesses step)
    done;
    let actual : H.state = {pc=S.pc cpu_state;sp=S.sp cpu_state;
      a=S.a cpu_state;bc=S.bc cpu_state;de=S.de cpu_state;
      hl=S.hl cpu_state;flags=flags cpu_state} in
    if host <> actual then failwith "registers, flags, PC or SP";
    let writes xs = List.filter (function H.Write _ -> true | _ -> false) xs in
    if writes (List.rev !host_events) <> writes (List.rev !cpu_events) then
      failwith "ordered writes";
    let actual_ram = M.read_range memory ~address:0 ~length:65536 in
    if Pli80_host.State.copy host_memory <> actual_ram then
      failwith "full RAM";
    if natural_case then (
      if actual_ram <> natural_exit then failwith "natural return RAM";
      if [|host.pc;host.sp;host.a;host.bc;host.de;host.hl;psw host.flags|]
         <> expected then failwith "natural return state";
      let channel=open_out !journal_path in
      Fun.protect ~finally:(fun()->close_out channel)(fun()->
        List.iter(function H.Read(a,v)->Printf.fprintf channel "R,%d,%d\n" a v
          |H.Write(a,v)->Printf.fprintf channel "W,%d,%d\n" a v)(List.rev !cpu_events));
      natural := true)
    else incr synthetic in
  check (!bc land 255) true;
  List.iter (fun selector -> check selector false) [0;1;255];
  let channel = open_out !output in
  Fun.protect ~finally:(fun () -> close_out channel) (fun () ->
    Printf.fprintf channel
      "{\"natural_passed\":%b,\"synthetic_cases\":%d,\"all_passed\":true}\n"
      !natural !synthetic)
