type encoding_status = Documented | Undocumented_alias | Uncertain

type memory_access =
  | Read of { address : int; value : int }
  | Write of { address : int; value : int }

type control_flow =
  | Sequential
  | Jump of { target : int; taken : bool }
  | Call of { target : int; taken : bool }
  | Return of { target : int option; taken : bool }
  | Restart of { target : int }
  | Halt

type cpu_step = {
  step_index : int;
  pc_before : int;
  pc_after : int;
  opcode : int;
  encoding_status : encoding_status;
  instruction_bytes : string;
  control_flow : control_flow;
  memory_accesses : memory_access list;
}

type termination_reason = Bdos_function of int

type t =
  | Cpu_step of cpu_step
  | Bdos_call of { step_index : int; function_number : int; de : int }
  | Termination of { step_index : int; reason : termination_reason }

let encoding_status_of_decode = function
  | I8080.Decode.Documented -> Documented
  | I8080.Decode.Undocumented_alias -> Undocumented_alias
  | I8080.Decode.Uncertain _ -> Uncertain

let control_flow_of_live = function
  | I8080.Step.Sequential -> Sequential
  | I8080.Step.Jump { target; taken } -> Jump { target; taken }
  | I8080.Step.Call { target; taken } -> Call { target; taken }
  | I8080.Step.Return { target; taken } -> Return { target; taken }
  | I8080.Step.Restart { target } -> Restart { target }
  | I8080.Step.Halt -> Halt

let memory_access_of_live = function
  | I8080.Step.Read { address; value } -> Read { address; value }
  | I8080.Step.Write { address; value } -> Write { address; value }

let cpu_step_of_live ~step_index live =
  let decoded = I8080.Step.decoded live in
  Cpu_step
    {
      step_index;
      pc_before = I8080.Step.pc_before live;
      pc_after = I8080.Step.pc_after live;
      opcode = decoded.I8080.Decode.opcode;
      encoding_status = encoding_status_of_decode decoded.I8080.Decode.status;
      instruction_bytes = Bytes.to_string (I8080.Step.fetched_bytes live);
      control_flow = control_flow_of_live (I8080.Step.control_flow live);
      memory_accesses =
        List.map memory_access_of_live (I8080.Step.memory_accesses live);
    }

let bdos_call ~step_index ~function_number ~de =
  Bdos_call { step_index; function_number; de }

let termination ~step_index reason = Termination { step_index; reason }

let of_runner_event ~step_index = function
  | Runner.Step live -> cpu_step_of_live ~step_index live
  | Runner.Bdos_call { step_index; function_number; de } ->
      bdos_call ~step_index ~function_number ~de
  | Runner.Termination { step_index; reason = Runner.Bdos_function number } ->
      termination ~step_index (Bdos_function number)
