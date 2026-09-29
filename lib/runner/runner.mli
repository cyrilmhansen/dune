(** One deterministic userspace CP/M experiment. *)

type termination = Bdos_function of int | Warm_boot

type run_result = {
  termination : termination;
  steps : int;
  t_states : int;
  (** Byte-sized CPU data reads recorded by executed Steps. Instruction fetch
      bytes and port operations are excluded. *)
  data_bytes_read : int;
  (** Byte-sized CPU data writes recorded by executed Steps. *)
  data_bytes_written : int;
  (** [data_bytes_read + data_bytes_written]. *)
  data_bytes_total : int;
}

type state_snapshot = {
  a : int; b : int; c : int; d : int; e : int; h : int; l : int;
  sp : int; pc : int; sign : bool; zero : bool; auxiliary_carry : bool;
  parity : bool; carry : bool;
}

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

(** The currently implemented process personality. Runes currently provides
    only [Cpm.Personality.cpm22]; CP/M Plus is retained as historical
    differential evidence, not as an implemented runtime profile. *)
val default_personality : Cpm.Personality.t

(* Default instruction budget for a run. *)
val default_max_steps : int

(** Build a fresh machine, load COM bytes at [0x0100], initialize CP/M page zero,
    and start with [SP = 0xfffe]. [filesystem] may be supplied by the caller
    to insert input files and retrieve generated files. [command_tail] is the
    raw byte sequence placed at [0081h] (its length is stored at [0080h]); the
    first two operands initialize the default FCB prefixes. [on_start] receives
    a copy of the initialized 256-byte page zero immediately before the first
    CPU instruction. [on_start_state] receives an immutable initial register
    and flag snapshot; [on_step_state] receives the post-step snapshot and
    index alongside the live [Step]. [on_bdos_effect] exposes host-side
    register/FCB mutations separately from record-transfer events.
    [on_bdos_file_event] reports factual file operations at BDOS dispatch and
    preserves the CP/M file key. [on_console_output] receives BDOS-emitted
    characters with the current zero-based step boundary; it does not add
    anything to [Runner.event].
    The initial SP is a deterministic runner convention, not a claim about
    every historical CP/M launch environment. *)
val run_bytes :
  ?personality:Cpm.Personality.t ->
  ?max_steps:int ->
  ?on_step:(I8080.Step.t -> unit) ->
  ?on_step_state:(step_index:int -> state_snapshot -> I8080.Step.t -> unit) ->
  ?on_event:(event -> unit) ->
  ?on_bdos_event:(step_index:int -> Cpm.Bdos.event -> unit) ->
  ?on_bdos_file_event:(step_index:int -> Cpm.Bdos.file_event -> unit) ->
  ?on_console_output:(step_index:int -> char -> unit) ->
  ?on_bdos_effect:(Cpm.Bdos.external_effect -> unit) ->
  ?on_start:(bytes -> unit) ->
  ?filesystem:Cpm.Filesystem.t ->
  ?on_start_state:(state_snapshot -> unit) ->
  ?command_tail:bytes ->
  output:(char -> unit) ->
  bytes ->
  (run_result, error) Stdlib.result

val run_file :
  ?personality:Cpm.Personality.t ->
  ?max_steps:int ->
  ?on_step:(I8080.Step.t -> unit) ->
  ?on_step_state:(step_index:int -> state_snapshot -> I8080.Step.t -> unit) ->
  ?on_event:(event -> unit) ->
  ?on_bdos_event:(step_index:int -> Cpm.Bdos.event -> unit) ->
  ?on_bdos_file_event:(step_index:int -> Cpm.Bdos.file_event -> unit) ->
  ?on_console_output:(step_index:int -> char -> unit) ->
  ?on_bdos_effect:(Cpm.Bdos.external_effect -> unit) ->
  ?on_start:(bytes -> unit) ->
  ?filesystem:Cpm.Filesystem.t ->
  ?on_start_state:(state_snapshot -> unit) ->
  ?command_tail:bytes ->
  output:(char -> unit) ->
  path:string ->
  unit ->
  (run_result, error) Stdlib.result
