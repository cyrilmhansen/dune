type termination = Bdos_function of int | Warm_boot

type run_result = { termination : termination; steps : int; t_states : int }

type state_snapshot = {
  a : int; b : int; c : int; d : int; e : int; h : int; l : int;
  sp : int; pc : int; sign : bool; zero : bool; auxiliary_carry : bool;
  parity : bool; carry : bool;
}

let snapshot state =
  let flags = I8080.State.flags state in
  { a = I8080.State.a state; b = I8080.State.b state; c = I8080.State.c state;
    d = I8080.State.d state; e = I8080.State.e state; h = I8080.State.h state;
    l = I8080.State.l state; sp = I8080.State.sp state; pc = I8080.State.pc state;
    sign = I8080.Flags.sign flags; zero = I8080.Flags.zero flags;
    auxiliary_carry = I8080.Flags.auxiliary_carry flags;
    parity = I8080.Flags.parity flags; carry = I8080.Flags.carry flags }

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

let default_personality = Cpm.Personality.cpm22

let run_loaded ~personality ~max_steps ~on_step ~on_step_state ~on_event ~on_bdos_event ~on_bdos_effect ~on_start ~on_start_state ~output ~filesystem ~command_tail memory loaded =
  let process = Cpm.Personality.launch personality ~filesystem ~command_tail memory in
  let state = I8080.State.create () in
  I8080.State.set_pc state (Cpm.Personality.entry_point personality loaded);
  I8080.State.set_sp state (Cpm.Personality.initial_stack_pointer personality);
  on_start (I8080.Memory.read_range memory ~address:0 ~length:0x100);
  on_start_state (snapshot state);
  let bus = I8080.Bus.create memory in
  let cpu = I8080.Cpu.create ~state ~bus in
  let rec run steps t_states =
    if I8080.State.pc state = Cpm.Personality.warm_boot_address personality then (
      on_event (Termination { step_index = steps; reason = Warm_boot });
      Ok { termination = Warm_boot; steps; t_states })
    else if I8080.State.pc state = Cpm.Personality.bdos_entry_address personality then
      let function_number = I8080.State.c state in
      on_event
        (Bdos_call
           { step_index = steps; function_number; de = I8080.State.de state });
      (match Cpm.Personality.dispatch_with_effects personality process
               ~on_event:(fun event -> on_bdos_event ~step_index:steps event)
               ~on_effect:on_bdos_effect
               ~memory ~state ~output with
      | Error error -> Error (Bdos_error error)
      | Ok Cpm.Bdos.Terminate ->
          let reason = Bdos_function function_number in
          on_event (Termination { step_index = steps; reason });
          Ok { termination = reason; steps; t_states }
      | Ok Cpm.Bdos.Continue -> execute_step steps t_states)
    else execute_step steps t_states
  and execute_step steps t_states =
    if steps >= max_steps then Error (Step_limit_exceeded { max_steps; steps })
    else
      match I8080.Cpu.step cpu with
      | Error error -> Error (Cpu_error error)
      | Ok step ->
          on_step step;
          on_step_state ~step_index:steps (snapshot state) step;
          on_event (Step step);
          run (steps + 1) (t_states + I8080.Timing.cost step)
  in
  run 0 0

let run_with_loader ~personality ~max_steps ~on_step ~on_step_state ~on_event ~on_bdos_event ~on_bdos_effect ~on_start ~on_start_state ~output ~filesystem ~command_tail load =
  if max_steps <= 0 then Error (Invalid_step_limit max_steps)
  else if Bytes.length command_tail > Cpm.Personality.maximum_command_tail_length personality then Error (Invalid_command_tail (Bytes.length command_tail))
  else
    let memory = I8080.Memory.create () in
    let filesystem = Option.value filesystem ~default:(Cpm.Filesystem.create ()) in
    match load memory with
    | Error error -> Error (Load_error error)
    | Ok loaded ->
        run_loaded ~personality ~max_steps ~on_step ~on_step_state ~on_event ~on_bdos_event ~on_bdos_effect ~on_start ~on_start_state ~output ~filesystem ~command_tail memory loaded

let run_bytes ?(personality = default_personality) ?(max_steps = default_max_steps) ?(on_step = fun _ -> ())
    ?(on_step_state = fun ~step_index:_ _ _ -> ())
    ?(on_event = fun _ -> ()) ?(on_bdos_event = fun ~step_index:_ _ -> ())
    ?(on_bdos_effect = fun _ -> ())
    ?(on_start = fun _ -> ()) ?filesystem
    ?(on_start_state = fun _ -> ())
    ?(command_tail = Bytes.empty) ~output bytes =
  run_with_loader ~personality ~max_steps ~on_step ~on_step_state ~on_event ~on_bdos_event ~on_bdos_effect ~on_start ~on_start_state ~output ~filesystem ~command_tail (fun memory ->
      Cpm.Personality.load_bytes personality memory bytes)

let run_file ?(personality = default_personality) ?(max_steps = default_max_steps) ?(on_step = fun _ -> ())
    ?(on_step_state = fun ~step_index:_ _ _ -> ())
    ?(on_event = fun _ -> ()) ?(on_bdos_event = fun ~step_index:_ _ -> ())
    ?(on_bdos_effect = fun _ -> ())
    ?(on_start = fun _ -> ()) ?filesystem
    ?(on_start_state = fun _ -> ())
    ?(command_tail = Bytes.empty) ~output ~path () =
  run_with_loader ~personality ~max_steps ~on_step ~on_step_state ~on_event ~on_bdos_event ~on_bdos_effect ~on_start ~on_start_state ~output ~filesystem ~command_tail (fun memory ->
      Cpm.Personality.load_file personality memory ~path)
