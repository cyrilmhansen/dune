(** One deterministic userspace CP/M experiment. *)

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

(* Default instruction budget for a run. *)
val default_max_steps : int

(** Build a fresh machine, load COM bytes at [0x0100], initialize CP/M page zero,
    and start with [SP = 0xfffe]. [filesystem] may be supplied by the caller
    to insert input files and retrieve generated files. [command_tail] is the
    raw byte sequence placed at [0081h] (its length is stored at [0080h]); the
    first two operands initialize the default FCB prefixes. [on_start] receives
    a copy of the initialized 256-byte page zero immediately before the first
    CPU instruction.
    The initial SP is a deterministic runner convention, not a claim about
    every historical CP/M launch environment. *)
val run_bytes :
  ?max_steps:int ->
  ?on_step:(I8080.Step.t -> unit) ->
  ?on_event:(event -> unit) ->
  ?on_bdos_event:(step_index:int -> Cpm.Bdos.event -> unit) ->
  ?on_start:(bytes -> unit) ->
  ?filesystem:Cpm.Filesystem.t ->
  ?command_tail:bytes ->
  output:(char -> unit) ->
  bytes ->
  (run_result, error) Stdlib.result

val run_file :
  ?max_steps:int ->
  ?on_step:(I8080.Step.t -> unit) ->
  ?on_event:(event -> unit) ->
  ?on_bdos_event:(step_index:int -> Cpm.Bdos.event -> unit) ->
  ?on_start:(bytes -> unit) ->
  ?filesystem:Cpm.Filesystem.t ->
  ?command_tail:bytes ->
  output:(char -> unit) ->
  path:string ->
  unit ->
  (run_result, error) Stdlib.result
