type termination = Bdos_function of int | Warm_boot

type run_result = { termination : termination; steps : int }

type event =
  | Step of I8080.Step.t
  | Bdos_call of { step_index : int; function_number : int; de : int }
  | Termination of { step_index : int; reason : termination }

type error =
  | Load_error of Cpm.Loader.error
  | Cpu_error of I8080.Cpu.error
  | Bdos_error of Cpm.Bdos.error
  | Step_limit_exceeded of { max_steps : int; steps : int }
  | Invalid_step_limit of int
  | Invalid_command_tail of int

let default_max_steps = 100_000

let warm_boot_address = 0x0000
let bdos_entry_address = 0x0005
let transient_stack_word_address = 0x0006
let initial_stack_pointer = 0xfffe

let command_operands tail =
  let text = Bytes.to_string tail in
  String.split_on_char ' ' text
  |> List.concat_map (String.split_on_char '\t')
  |> List.filter (fun token -> token <> "")

let write_default_fcb memory ~address token =
  let write offset value = I8080.Memory.write memory (address + offset) value in
  let clear_name () =
    for offset = 0 to 10 do write (offset + 1) 0x20 done
  in
  clear_name ();
  write 0 0;
  for offset = 12 to 35 do write offset 0 done;
  match token with
  | None -> ()
  | Some token ->
      let token = String.uppercase_ascii token in
      let token =
        match String.index_opt token ':' with
        | Some colon when colon = 1 ->
            let drive = Char.code token.[0] - Char.code 'A' + 1 in
            (if drive >= 1 && drive <= 16 then write 0 drive);
            String.sub token 2 (String.length token - 2)
        | _ -> token
      in
      let base, extension =
        match String.index_opt token '.' with
        | None -> token, ""
        | Some dot -> String.sub token 0 dot, String.sub token (dot + 1) (String.length token - dot - 1)
      in
      String.iteri (fun index char -> if index < 8 then write (index + 1) (Char.code char)) base;
      String.iteri (fun index char -> if index < 3 then write (index + 9) (Char.code char)) extension

let install_page_zero memory command_tail =
  I8080.Memory.write memory bdos_entry_address 0xc9;
  I8080.Memory.write memory transient_stack_word_address
    (initial_stack_pointer land 0xff);
  I8080.Memory.write memory (transient_stack_word_address + 1)
    ((initial_stack_pointer lsr 8) land 0xff);
  for address = 0x005c to 0x008f do I8080.Memory.write memory address 0 done;
  for address = 0x0080 to 0x00ff do I8080.Memory.write memory address 0 done;
  let operands = command_operands command_tail in
  (* FCB2's 16-byte default prefix occupies FCB1's allocation area.  Write
     the two directory/name prefixes, not two independent 36-byte FCBs. *)
  write_default_fcb memory ~address:0x005c (List.nth_opt operands 0);
  write_default_fcb memory ~address:0x006c (List.nth_opt operands 1);
  let tail_length = Bytes.length command_tail in
  I8080.Memory.write memory 0x0080 tail_length;
  Bytes.iteri
    (fun index byte -> I8080.Memory.write memory (0x0081 + index) (Char.code byte))
    command_tail

let run_loaded ~max_steps ~on_step ~on_event ~on_start ~output ~filesystem ~command_tail memory loaded =
  (* 0005h remains a synthetic RET userspace trap, not the historical BDOS
     jump instruction. The 0006h word is a deterministic compatibility value
     for exercisers that use LHLD 6 / SPHL, not historical CP/M low memory. *)
  install_page_zero memory command_tail;
  let bdos = Cpm.Bdos.create ~filesystem in
  let state = I8080.State.create () in
  I8080.State.set_pc state loaded.Cpm.Loader.entry_point;
  (* Choose a stable initial stack location without asserting a universal
     historical CP/M value. *)
  I8080.State.set_sp state initial_stack_pointer;
  on_start (I8080.Memory.read_range memory ~address:0 ~length:0x100);
  let bus = I8080.Bus.create memory in
  let cpu = I8080.Cpu.create ~state ~bus in
  let rec run steps =
    if I8080.State.pc state = warm_boot_address then (
      on_event (Termination { step_index = steps; reason = Warm_boot });
      Ok { termination = Warm_boot; steps })
    else if I8080.State.pc state = bdos_entry_address then
      let function_number = I8080.State.c state in
      on_event
        (Bdos_call
           { step_index = steps; function_number; de = I8080.State.de state });
      (match Cpm.Bdos.dispatch ~runtime:bdos ~memory ~state ~output with
      | Error error -> Error (Bdos_error error)
      | Ok Cpm.Bdos.Terminate ->
          let reason = Bdos_function function_number in
          on_event (Termination { step_index = steps; reason });
          Ok { termination = reason; steps }
      | Ok Cpm.Bdos.Continue -> execute_step steps)
    else execute_step steps
  and execute_step steps =
    if steps >= max_steps then Error (Step_limit_exceeded { max_steps; steps })
    else
      match I8080.Cpu.step cpu with
      | Error error -> Error (Cpu_error error)
      | Ok step ->
          on_step step;
          on_event (Step step);
          run (steps + 1)
  in
  run 0

let run_with_loader ~max_steps ~on_step ~on_event ~on_start ~output ~filesystem ~command_tail load =
  if max_steps <= 0 then Error (Invalid_step_limit max_steps)
  else if Bytes.length command_tail > 127 then Error (Invalid_command_tail (Bytes.length command_tail))
  else
    let memory = I8080.Memory.create () in
    let filesystem = Option.value filesystem ~default:(Cpm.Filesystem.create ()) in
    match load memory with
    | Error error -> Error (Load_error error)
    | Ok loaded ->
        run_loaded ~max_steps ~on_step ~on_event ~on_start ~output ~filesystem ~command_tail memory loaded

let run_bytes ?(max_steps = default_max_steps) ?(on_step = fun _ -> ())
    ?(on_event = fun _ -> ()) ?(on_start = fun _ -> ()) ?filesystem
    ?(command_tail = Bytes.empty) ~output bytes =
  run_with_loader ~max_steps ~on_step ~on_event ~on_start ~output ~filesystem ~command_tail (fun memory ->
      Cpm.Loader.load_bytes memory bytes)

let run_file ?(max_steps = default_max_steps) ?(on_step = fun _ -> ())
    ?(on_event = fun _ -> ()) ?(on_start = fun _ -> ()) ?filesystem
    ?(command_tail = Bytes.empty) ~output ~path () =
  run_with_loader ~max_steps ~on_step ~on_event ~on_start ~output ~filesystem ~command_tail (fun memory ->
      Cpm.Loader.load_file memory ~path)
