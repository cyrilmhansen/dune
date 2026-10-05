type termination = Bdos_function of int | Warm_boot

type run_result = {
  termination : termination;
  steps : int;
  t_states : int;
  data_bytes_read : int;
  data_bytes_written : int;
  data_bytes_total : int;
  host_transitions : int;
  host_bdos_services : int;
}

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

type host_service = {
  call_state : state_snapshot;
  resume_state : state_snapshot;
  dma_before : int;
  dma_after : int;
  events : Cpm.Bdos.event list;
  file_events : Cpm.Bdos.file_event list;
  effects : Cpm.Bdos.external_effect list;
  memory_before : bytes;
  memory_after : bytes;
}
type host_program_result = {
  memory : bytes;
  filesystem : Cpm.Filesystem.t;
  dma : int;
  services : host_service list;
}
type host_effect =
  | Memory_write of int * int
  | Dispatch_bdos of { call_state : state_snapshot; expected_resume : state_snapshot }
type host_program = {
  effects : host_effect list;
  next_state : state_snapshot;
  validate : host_program_result -> (unit, string) result;
  on_commit : host_program_result -> unit;
}
type instruction_boundary = {
  state : state_snapshot;
  read_memory : int -> int;
  copy_memory : unit -> bytes;
  copy_filesystem : unit -> Cpm.Filesystem.t;
  dma : int;
  preview_host_program : host_program -> (host_program_result, string) result;
}
type host_transition = { memory_writes : (int * int) list; next_state : state_snapshot }
type instruction_action = Continue_guest_execution | Apply_host_transition of host_transition
  | Apply_host_program of host_program

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
  | Invalid_host_transition of string

let valid_state s =
  let valid maximum n=n>=0 && n<=maximum in
  List.for_all(valid 255)[s.a;s.b;s.c;s.d;s.e;s.h;s.l]
  && valid 65535 s.sp && valid 65535 s.pc
let apply_state state s =
  I8080.State.set_a state s.a;I8080.State.set_b state s.b;I8080.State.set_c state s.c;
  I8080.State.set_d state s.d;I8080.State.set_e state s.e;
  I8080.State.set_h state s.h;I8080.State.set_l state s.l;
  I8080.State.set_sp state s.sp;I8080.State.set_pc state s.pc;
  let flags=I8080.State.flags state in
  I8080.Flags.set_sign flags s.sign;I8080.Flags.set_zero flags s.zero;
  I8080.Flags.set_auxiliary_carry flags s.auxiliary_carry;
  I8080.Flags.set_parity flags s.parity;I8080.Flags.set_carry flags s.carry

type notification = Record of Cpm.Bdos.event | File of Cpm.Bdos.file_event
  | Effect of Cpm.Bdos.external_effect | Console of char

(* No live mutation or observer calls occur in this staging function. All host
   services execute the existing personality on owned PRE-state copies. *)
let stage_host_program ~personality ~process ~memory (program:host_program) =
  try
    if not(valid_state program.next_state && List.for_all(function
      |Memory_write(a,v)->a>=0 && a<=65535 && v>=0 && v<=255
      |Dispatch_bdos q->valid_state q.call_state && valid_state q.expected_resume)program.effects)
    then invalid_arg "host program register, address or byte out of bounds";
    let staged=Cpm.Personality.copy personality process in
    let ram=I8080.Memory.create () in
    I8080.Memory.load ram ~address:0 (I8080.Memory.read_range memory ~address:0 ~length:65536);
    let notices=ref [] and services=ref [] in
    let notice n=notices:=n::!notices in
    List.iter(function
      |Memory_write(a,v)->I8080.Memory.write ram a v
      |Dispatch_bdos q->
        let state=I8080.State.create () in apply_state state q.call_state;
        let dma_before=Cpm.Personality.dma personality staged in
        let memory_before=I8080.Memory.read_range ram ~address:0 ~length:65536 in
        let events=ref [] and files=ref [] and effects=ref [] in
        (match Cpm.Personality.dispatch_with_file_events personality staged ~memory:ram ~state
          ~on_event:(fun e->events:=e::!events;notice(Record e))
          ~on_file_event:(fun e->files:=e::!files;notice(File e))
          ~on_effect:(fun e->effects:=e::!effects;notice(Effect e))
          ~output:(fun c->notice(Console c)) with
        |Error _->invalid_arg "host BDOS service error"
        |Ok Cpm.Bdos.Terminate->invalid_arg "host BDOS termination unsupported in resumable program"
        |Ok Cpm.Bdos.Continue->());
        let resume_state=snapshot state in
        if resume_state<>q.expected_resume then invalid_arg "host BDOS resume state outside supported scope";
        services:={call_state=q.call_state;resume_state;dma_before;
          dma_after=Cpm.Personality.dma personality staged;
          events=List.rev !events;file_events=List.rev !files;effects=List.rev !effects;
          memory_before;memory_after=I8080.Memory.read_range ram ~address:0 ~length:65536}::!services
    )program.effects;
    let result={memory=I8080.Memory.read_range ram ~address:0 ~length:65536;
      filesystem=Cpm.Filesystem.copy(Cpm.Personality.filesystem personality staged);
      dma=Cpm.Personality.dma personality staged;services=List.rev !services} in
    match program.validate result with
    |Error e->Error e
    |Ok ()->Ok(result,ram,staged,List.rev !notices)
  with Invalid_argument e | Failure e ->Error e

let default_max_steps = 100_000

let default_personality = Cpm.Personality.cpm22

let data_access_counts step =
  List.fold_left
    (fun (reads, writes) -> function
      | I8080.Step.Read _ -> reads + 1, writes
      | I8080.Step.Write _ -> reads, writes + 1)
    (0, 0) (I8080.Step.memory_accesses step)

let completed_run ~termination ~steps ~t_states ~data_bytes_read ~data_bytes_written ~host_transitions ~host_bdos_services =
  { termination; steps; t_states; data_bytes_read; data_bytes_written;
    data_bytes_total = data_bytes_read + data_bytes_written; host_transitions; host_bdos_services }

let run_loaded ~personality ~max_steps ~on_step ~on_step_state ~on_step_state_pair ~on_before_instruction ~intercept ~on_event ~on_bdos_event ~on_bdos_file_event ~on_bdos_effect ~on_bdos_effect_at ~on_bdos_call_state ~on_bdos_resume ~on_start ~on_start_state ~on_console_output ~output ~filesystem ~command_tail memory loaded =
  let process = Cpm.Personality.launch personality ~filesystem ~command_tail memory in
  let state = I8080.State.create () in
  I8080.State.set_pc state (Cpm.Personality.entry_point personality loaded);
  I8080.State.set_sp state (Cpm.Personality.initial_stack_pointer personality);
  on_start (I8080.Memory.read_range memory ~address:0 ~length:0x100);
  on_start_state (snapshot state);
  let bus = I8080.Bus.create memory in
  let cpu = I8080.Cpu.create ~state ~bus in
  let host_transitions = ref 0 and host_bdos_services = ref 0 in
  let rec run steps t_states data_bytes_read data_bytes_written =
    if I8080.State.pc state = Cpm.Personality.warm_boot_address personality then (
      on_event (Termination { step_index = steps; reason = Warm_boot });
      Ok (completed_run ~termination:Warm_boot ~steps ~t_states
            ~data_bytes_read ~data_bytes_written ~host_transitions:!host_transitions ~host_bdos_services:!host_bdos_services))
    else if I8080.State.pc state = Cpm.Personality.bdos_entry_address personality then
      let function_number = I8080.State.c state in
      let dma = Cpm.Personality.dma personality process in
      on_bdos_call_state ~step_index:steps ~state:(snapshot state) ~dma
        ~read_memory:(fun address -> I8080.Memory.read memory (address land 0xffff));
      on_event
        (Bdos_call
           { step_index = steps; function_number; de = I8080.State.de state });
      (match Cpm.Personality.dispatch_with_file_events personality process
               ~on_event:(fun event -> on_bdos_event ~step_index:steps event)
               ~on_file_event:(fun event -> on_bdos_file_event ~step_index:steps event)
               ~on_effect:(fun external_effect -> on_bdos_effect external_effect; on_bdos_effect_at ~step_index:steps external_effect)
               ~memory ~state ~output:(fun char -> output char; on_console_output ~step_index:steps char) with
      | Error error -> Error (Bdos_error error)
      | Ok Cpm.Bdos.Terminate ->
          on_bdos_resume ~step_index:steps ~state:(snapshot state);
          let reason = Bdos_function function_number in
          on_event (Termination { step_index = steps; reason });
          Ok (completed_run ~termination:reason ~steps ~t_states
                ~data_bytes_read ~data_bytes_written ~host_transitions:!host_transitions ~host_bdos_services:!host_bdos_services)
      | Ok Cpm.Bdos.Continue ->
          on_bdos_resume ~step_index:steps ~state:(snapshot state);
          execute_step steps t_states data_bytes_read data_bytes_written)
    else execute_step steps t_states data_bytes_read data_bytes_written
  and execute_step steps t_states data_bytes_read data_bytes_written =
    if steps + !host_transitions >= max_steps then Error (Step_limit_exceeded { max_steps; steps })
    else
      let before = snapshot state in
      let boundary={state=before;
        read_memory=(fun a -> I8080.Memory.read memory a);
        copy_memory=(fun () -> I8080.Memory.read_range memory ~address:0 ~length:65536);
        copy_filesystem=(fun ()->Cpm.Filesystem.copy filesystem);
        dma=Cpm.Personality.dma personality process;
        preview_host_program=(fun p->match stage_host_program ~personality ~process ~memory p with
          |Error e->Error e|Ok(r,_,_,_)->Ok r)} in
      on_before_instruction ~step_index:steps boundary;
      match intercept ~step_index:steps boundary with
      |Apply_host_transition transition->
        let s=transition.next_state in
        let valid maximum n=n>=0 && n<=maximum in
        if not(List.for_all(valid 255)[s.a;s.b;s.c;s.d;s.e;s.h;s.l]
          && valid 65535 s.sp && valid 65535 s.pc
          && List.for_all(fun(a,v)->valid 65535 a && valid 255 v)transition.memory_writes)
        then Error(Invalid_host_transition "register, address or byte out of bounds")
        else (
          List.iter(fun(a,v)->I8080.Memory.write memory a v)transition.memory_writes;
          apply_state state s;
          incr host_transitions;
          run steps t_states data_bytes_read data_bytes_written)
      |Apply_host_program program->
        (match stage_host_program ~personality ~process ~memory program with
        |Error e->Error(Invalid_host_transition e)
        |Ok(result,ram,staged,notices)->
          (* Commit only after all services AND final validation succeed. Observer
             delivery follows commit; callback failures are not transaction failures. *)
          Cpm.Personality.copy_into personality ~source:staged ~destination:process;
          I8080.Memory.load memory ~address:0 (I8080.Memory.read_range ram ~address:0 ~length:65536);
          apply_state state program.next_state;
          incr host_transitions;
          host_bdos_services := !host_bdos_services + List.length result.services;
          program.on_commit result;
          List.iter(function
            |Record e->on_bdos_event ~step_index:steps e
            |File e->on_bdos_file_event ~step_index:steps e
            |Effect e->on_bdos_effect e;on_bdos_effect_at ~step_index:steps e
            |Console c->output c;on_console_output ~step_index:steps c)notices;
          run steps t_states data_bytes_read data_bytes_written)
      |Continue_guest_execution->
      match I8080.Cpu.step cpu with
      | Error error -> Error (Cpu_error error)
      | Ok step ->
          let step_reads, step_writes = data_access_counts step in
          on_step step;
          let after = snapshot state in
          on_step_state_pair ~step_index:steps ~before ~after step;
          on_step_state ~step_index:steps after step;
          on_event (Step step);
          run (steps + 1) (t_states + I8080.Timing.cost step)
            (data_bytes_read + step_reads) (data_bytes_written + step_writes)
  in
  run 0 0 0 0

let run_with_loader ~personality ~max_steps ~on_step ~on_step_state ~on_step_state_pair ~on_before_instruction ~intercept ~on_event ~on_bdos_event ~on_bdos_file_event ~on_bdos_effect ~on_bdos_effect_at ~on_bdos_call_state ~on_bdos_resume ~on_start ~on_start_state ~on_console_output ~output ~filesystem ~command_tail load =
  if max_steps <= 0 then Error (Invalid_step_limit max_steps)
  else if Bytes.length command_tail > Cpm.Personality.maximum_command_tail_length personality then Error (Invalid_command_tail (Bytes.length command_tail))
  else
    let memory = I8080.Memory.create () in
    let filesystem = Option.value filesystem ~default:(Cpm.Filesystem.create ()) in
    match load memory with
    | Error error -> Error (Load_error error)
    | Ok loaded ->
        run_loaded ~personality ~max_steps ~on_step ~on_step_state ~on_step_state_pair ~on_before_instruction ~intercept ~on_event ~on_bdos_event ~on_bdos_file_event ~on_bdos_effect ~on_bdos_effect_at ~on_bdos_call_state ~on_bdos_resume ~on_start ~on_start_state ~on_console_output ~output ~filesystem ~command_tail memory loaded

let run_bytes ?(personality = default_personality) ?(max_steps = default_max_steps) ?(on_step = fun _ -> ())
    ?(on_step_state = fun ~step_index:_ _ _ -> ())
    ?(on_step_state_pair = fun ~step_index:_ ~before:_ ~after:_ _ -> ())
    ?(on_before_instruction = fun ~step_index:_ _ -> ())
    ?(intercept = fun ~step_index:_ _ -> Continue_guest_execution)
    ?(on_event = fun _ -> ()) ?(on_bdos_event = fun ~step_index:_ _ -> ())
    ?(on_bdos_file_event = fun ~step_index:_ _ -> ())
    ?(on_console_output = fun ~step_index:_ _ -> ())
    ?(on_bdos_effect = fun _ -> ())
    ?(on_bdos_effect_at = fun ~step_index:_ _ -> ())
    ?(on_bdos_call_state = fun ~step_index:_ ~state:_ ~dma:_ ~read_memory:_ -> ())
    ?(on_bdos_resume = fun ~step_index:_ ~state:_ -> ())
    ?(on_start = fun _ -> ()) ?filesystem
    ?(on_start_state = fun _ -> ())
    ?(command_tail = Bytes.empty) ~output bytes =
  run_with_loader ~personality ~max_steps ~on_step ~on_step_state ~on_step_state_pair ~on_before_instruction ~intercept ~on_event ~on_bdos_event ~on_bdos_file_event ~on_bdos_effect ~on_bdos_effect_at ~on_bdos_call_state ~on_bdos_resume ~on_start ~on_start_state ~on_console_output ~output ~filesystem ~command_tail (fun memory ->
      Cpm.Personality.load_bytes personality memory bytes)

let run_file ?(personality = default_personality) ?(max_steps = default_max_steps) ?(on_step = fun _ -> ())
    ?(on_step_state = fun ~step_index:_ _ _ -> ())
    ?(on_step_state_pair = fun ~step_index:_ ~before:_ ~after:_ _ -> ())
    ?(on_before_instruction = fun ~step_index:_ _ -> ())
    ?(intercept = fun ~step_index:_ _ -> Continue_guest_execution)
    ?(on_event = fun _ -> ()) ?(on_bdos_event = fun ~step_index:_ _ -> ())
    ?(on_bdos_file_event = fun ~step_index:_ _ -> ())
    ?(on_console_output = fun ~step_index:_ _ -> ())
    ?(on_bdos_effect = fun _ -> ())
    ?(on_bdos_effect_at = fun ~step_index:_ _ -> ())
    ?(on_bdos_call_state = fun ~step_index:_ ~state:_ ~dma:_ ~read_memory:_ -> ())
    ?(on_bdos_resume = fun ~step_index:_ ~state:_ -> ())
    ?(on_start = fun _ -> ()) ?filesystem
    ?(on_start_state = fun _ -> ())
    ?(command_tail = Bytes.empty) ~output ~path () =
  run_with_loader ~personality ~max_steps ~on_step ~on_step_state ~on_step_state_pair ~on_before_instruction ~intercept ~on_event ~on_bdos_event ~on_bdos_file_event ~on_bdos_effect ~on_bdos_effect_at ~on_bdos_call_state ~on_bdos_resume ~on_start ~on_start_state ~on_console_output ~output ~filesystem ~command_tail (fun memory ->
      Cpm.Personality.load_file personality memory ~path)
