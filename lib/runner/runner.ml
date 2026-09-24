type termination = Bdos_function of int

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

let default_max_steps = 100_000

let run_loaded ~max_steps ~on_step ~on_event ~output memory loaded =
  (* The synthetic RET at BDOS entry is a userspace trap convention. It does
     not model the actual low-memory contents of a historical CP/M system. *)
  I8080.Memory.write memory 0x0005 0xc9;
  let state = I8080.State.create () in
  I8080.State.set_pc state loaded.Cpm.Loader.entry_point;
  (* Choose a stable initial stack location without asserting a universal
     historical CP/M value. *)
  I8080.State.set_sp state 0xfffe;
  let bus = I8080.Bus.create memory in
  let cpu = I8080.Cpu.create ~state ~bus in
  let rec run steps =
    if I8080.State.pc state = 0x0005 then
      let function_number = I8080.State.c state in
      on_event
        (Bdos_call
           { step_index = steps; function_number; de = I8080.State.de state });
      (match Cpm.Bdos.dispatch ~memory ~state ~output with
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

let run_with_loader ~max_steps ~on_step ~on_event ~output load =
  if max_steps <= 0 then Error (Invalid_step_limit max_steps)
  else
    let memory = I8080.Memory.create () in
    match load memory with
    | Error error -> Error (Load_error error)
    | Ok loaded -> run_loaded ~max_steps ~on_step ~on_event ~output memory loaded

let run_bytes ?(max_steps = default_max_steps) ?(on_step = fun _ -> ())
    ?(on_event = fun _ -> ()) ~output bytes =
  run_with_loader ~max_steps ~on_step ~on_event ~output (fun memory ->
      Cpm.Loader.load_bytes memory bytes)

let run_file ?(max_steps = default_max_steps) ?(on_step = fun _ -> ())
    ?(on_event = fun _ -> ()) ~output ~path () =
  run_with_loader ~max_steps ~on_step ~on_event ~output (fun memory ->
      Cpm.Loader.load_file memory ~path)
