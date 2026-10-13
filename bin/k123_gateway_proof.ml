[@@@warning "-4-40-41-42"]
module H = Pli80_host.K123_child_7d05_front
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
  let com_path = ref "" and journal_path = ref "" and pli2_path = ref "" and ram = ref "" and expected_ram = ref "" and output = ref "" in
  let call_site=ref 0 and discriminant_address=ref 0 and handler_c0=ref 0 in
  let pc = ref 0 and sp = ref 0 and a = ref 0 and bc = ref 0 in
  let de = ref 0 and hl = ref 0 and psw_in = ref 0 in
  let expected = Array.make 7 0 in
  let arg name value = name, Arg.Set_int value, "captured state" in
  Arg.parse [
    "--com", Arg.Set_string com_path, "historical resident image";
    "--journal", Arg.Set_string journal_path, "natural CPU access journal";
    "--pli2", Arg.Set_string pli2_path, "historical PLI2 image";
    "--ram", Arg.Set_string ram, "child entry RAM";
    "--expected-ram", Arg.Set_string expected_ram, "natural return RAM";
    "--output", Arg.Set_string output, "proof summary";
    arg "--handler-c0" handler_c0; arg "--discriminant-address" discriminant_address; arg "--call-site" call_site; arg "--pc" pc; arg "--sp" sp; arg "--a" a;
    arg "--bc" bc; arg "--de" de; arg "--hl" hl; arg "--psw" psw_in;
    "--expected-pc", Arg.Int (fun v -> expected.(0) <- v), "captured return";
    "--expected-sp", Arg.Int (fun v -> expected.(1) <- v), "captured return";
    "--expected-a", Arg.Int (fun v -> expected.(2) <- v), "captured return";
    "--expected-bc", Arg.Int (fun v -> expected.(3) <- v), "captured return";
    "--expected-de", Arg.Int (fun v -> expected.(4) <- v), "captured return";
    "--expected-hl", Arg.Int (fun v -> expected.(5) <- v), "captured return";
    "--expected-psw", Arg.Int (fun v -> expected.(6) <- v), "captured return";
  ] ignore "Pass86 complete staged k123 gateway and scope proof";
  let seed = read !ram and natural_exit = read !expected_ram in
  let pli2 = read !pli2_path and pli_com=read !com_path in
  if Bytes.length seed <> 65536 || Bytes.length natural_exit <> 65536 then
    failwith "RAM size";
  let synthetic = ref 0 and natural = ref false in
  let check selector natural_case =
    let input = Bytes.copy seed in
    let incoming_a= !a in
    if not natural_case then (
      let address= !discriminant_address in
      let old=Char.code(Bytes.get input address) in
      Bytes.set input address(Char.chr((old land 127)lor selector)));
    let memory = M.create () in M.load memory ~address:0 input;
    let cpu_state = S.create () in
    S.set_pc cpu_state !pc; S.set_sp cpu_state !sp; S.set_a cpu_state incoming_a;
    S.set_bc cpu_state !bc;
    S.set_de cpu_state !de; S.set_hl cpu_state !hl;
    I8080.Flags.restore_from_psw_byte (S.flags cpu_state) !psw_in;
    let host_memory = Pli80_host.State.of_bytes input in
    let entry : H.state = {pc= !pc;sp= !sp;a=incoming_a;
      bc= !bc;de= !de;hl= !hl;
      flags=flags cpu_state} in
    let host_events = ref [] in
    let gateway_reads=ref [] in
    let prepared,host = Pli80_host.K123_gateway_transaction.prepare host_memory ~pli2 ~pli_com ~call_site: !call_site ~entry ~gateway_read:(fun a v->gateway_reads:=(a,v)::!gateway_reads) ~observe:(fun event -> host_events := event :: !host_events) in
    if Pli80_host.State.copy host_memory <> input then failwith "preparation mutated input";
    if not(Pli80_host.K123_gateway_transaction.eligible host_memory ~pli2 ~pli_com ~call_site: !call_site ~entry) then failwith "natural eligibility";
    let cpu = I8080.Cpu.create ~state:cpu_state ~bus:(I8080.Bus.create memory) in
    let cpu_events = ref [] and cpu_gateway_reads=ref [] and in_handler=ref false and steps = ref 0 in
    while S.pc cpu_state <> expected.(0) do
      if S.pc cpu_state=0x476e then in_handler:=true;
      if S.pc cpu_state=0x42b4 then in_handler:=false;
      incr steps;
      if !steps > 10000 then failwith "composition did not return";
      match I8080.Cpu.step cpu with
      | Error _ -> failwith "composition CPU"
      | Ok step ->
        List.iter (function
          | I8080.Step.Read {address;value} ->
            if not !in_handler then cpu_gateway_reads:=(address,value)::!cpu_gateway_reads;
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
    if List.rev !gateway_reads<>List.rev !cpu_gateway_reads then(
      let dump name rows=let c=open_out(!journal_path^name)in
       Fun.protect ~finally:(fun()->close_out c)(fun()->List.iter(fun(a,v)->Printf.fprintf c "%d,%d\n" a v)rows)in
      dump ".host-reads"(List.rev !gateway_reads);dump ".cpu-reads"(List.rev !cpu_gateway_reads);
      failwith "gateway logical read order");
    let actual_ram = M.read_range memory ~address:0 ~length:65536 in
    if Pli80_host.State.copy prepared <> actual_ram then
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
  check 0 true;
  let rejection_tests = ref [] in
  let seed_entry : H.state = {pc= !pc;sp= !sp;a= !a;bc= !bc;de= !de;hl= !hl;
    flags={sign= !psw_in land 128<>0;zero= !psw_in land 64<>0;
      auxiliary_carry= !psw_in land 16<>0;parity= !psw_in land 4<>0;carry= !psw_in land 1<>0}}in
  let reject name alter =
    let memory=Pli80_host.State.of_bytes seed in
    let entry=alter memory seed_entry in
    let before=Pli80_host.State.copy memory in
    if Pli80_host.K123_gateway_transaction.eligible memory ~pli2 ~pli_com ~call_site: !call_site ~entry then failwith("accepted "^name);
    if Pli80_host.State.copy memory<>before then failwith("rejection mutated "^name);
    rejection_tests:=name::!rejection_tests in
  let byte name address value=reject name(fun m q->Pli80_host.State.write m address value;q)in
  reject "unsupported canonical index"(fun _ q->{q with bc=0});
  byte "invalid descriptor" (0x3c21+2*123) 0;
  byte "invalid handler" (0x3ddd+2*123) 0;
  byte "gateway code" 0x41b5 0;
  byte "software PUSH code" 0x42af 0;
  byte "software PCHL code" 0x42b3 0;
  byte "predicate code" 0x3fff 0;
  byte "handler code" 0x476e 0;
  byte "corrupted hardware continuation" !sp 0;
  byte "trace gate" 0x202e 1;
  byte "unsupported predicate token" 0x3bf7 0xed;
  byte "unsupported descriptor scan" 0x4357 1;
  reject "scratch pointer alias"(fun m q->Pli80_host.State.write m 0x2155 0x15;Pli80_host.State.write m 0x2156 0xad;q);
  reject "stack pointer alias"(fun m q->Pli80_host.State.write m 0x2155 ((q.sp-20)land 255);Pli80_host.State.write m 0x2156 ((q.sp-20)lsr 8);q);
  byte "code/table alias" (0x3c21+2*123) 0xb5;
  byte "output error domain" 0x2029 1;
  byte "output bit boundary" 0x1d8b 8;
  reject "output record boundary"(fun m q->Pli80_host.State.write m 0x1c2c 254;Pli80_host.State.write m 0x1c2d 255;q);
  reject "unsupported handler zero difference"(fun m q->
    let i=Pli80_host.State.read m(0xaab0+ !handler_c0) in
    Pli80_host.State.write m(0xa795+i)0;
    Pli80_host.State.write m(0xa7f8+i)0;q);
  byte "output boundary" 0x1d8a 255;
  reject "stack/scratch alias"(fun _ q->{q with sp=0xad15});
  (* Eligibility is a probe of this immutable state, not a try/prepare fallback.
     A changed snapshot after acceptance causes preparation to propagate. *)
  let late=Pli80_host.State.of_bytes seed in
  if not(Pli80_host.K123_gateway_transaction.eligible late ~pli2 ~pli_com ~call_site: !call_site ~entry:seed_entry) then failwith "late eligibility";
  Pli80_host.State.write late 0x476e 0;
  let before=Pli80_host.State.copy late in
  (match Pli80_host.K123_gateway_transaction.prepare late ~pli2 ~pli_com ~call_site: !call_site ~entry:seed_entry ~observe:(fun _->()) with
   |_->failwith "late error disguised"
   |exception Invalid_argument _->());
  if Pli80_host.State.copy late<>before then failwith "late error mutation";
  (* Predicate walk termination is a proof assertion, not a declining scope
     branch. Force a nonterminating canonical walk without changing k123 lookup. *)
  let error=Pli80_host.State.of_bytes seed in
  for i=0 to 255 do Pli80_host.State.write error (0xa6cf+i) 255 done;
  let before=Pli80_host.State.copy error in
  (match Pli80_host.K123_gateway_transaction.eligible error ~pli2 ~pli_com ~call_site: !call_site ~entry:seed_entry with
   |_->failwith "probe proof error disguised"
   |exception Invalid_argument text->
      if text<>"Acquisition_family: 0992 bounded byte walk termination" then raise(Invalid_argument text));
  if Pli80_host.State.copy error<>before then failwith "probe error mutation";
  List.iter (fun selector -> check selector false)
    [0;128];
  let channel = open_out !output in
  Fun.protect ~finally:(fun () -> close_out channel) (fun () ->
    Printf.fprintf channel
      "{\"natural_passed\":%b,\"synthetic_cases\":%d,\"rejections\":[%s],\"preparation_error_propagates\":true,\"input_unchanged\":true,\"gateway_ordered_reads_match_CPU\":true,\"all_passed\":true}\n"
      !natural !synthetic (String.concat ","(List.map(Printf.sprintf "%S")(List.rev !rejection_tests))))
