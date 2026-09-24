(** Stable persistent event model. This is deliberately separate from the live
    [I8080.Step.t] representation. *)

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

(** Explicitly snapshot the stable fields needed by trace v1 from a live step. *)
val cpu_step_of_live : step_index:int -> I8080.Step.t -> t
val bdos_call : step_index:int -> function_number:int -> de:int -> t
val termination : step_index:int -> termination_reason -> t
val of_runner_event : step_index:int -> Runner.event -> t
