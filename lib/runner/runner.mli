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
  host_transitions : int;
  (** Actual committed native services; excluded from guest BDOS entry and
      instruction/t-state accounting. *)
  host_bdos_services : int;
  (** Native transitions are counted separately. Steps/t-states/data accesses
      count only instructions actually executed by Cpu; no synthetic Steps. *)
}

type state_snapshot = {
  a : int; b : int; c : int; d : int; e : int; h : int; l : int;
  sp : int; pc : int; sign : bool; zero : bool; auxiliary_carry : bool;
  parity : bool; carry : bool;
}

(** Factual service executions on a staged process. Memory snapshots are owned
    copies at each service boundary, before and after dispatch. No CPU RET runs. *)
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
(** Ordered writes/services. Both callback arguments are owned snapshots:
    [validate] is read-only and runs before any live commit or observer delivery;
    [on_commit] is an observer after successful commit. Observer exceptions do not
    undo a committed transaction. Preview invokes neither commit nor observers. *)
type host_program = {
  effects : host_effect list;
  next_state : state_snapshot;
  validate : host_program_result -> (unit, string) result;
  on_commit : host_program_result -> unit;
}
(* Read-only pre-instruction view. State and copied memory/filesystems are
    owned snapshots. Read/preview closures observe the live process; use them
    during the callback, or after the run has returned for final validation,
    never concurrently with continued execution. *)
type instruction_boundary = {
  state : state_snapshot;
  read_memory : int -> int;
  copy_memory : unit -> bytes;
  copy_filesystem : unit -> Cpm.Filesystem.t;
  dma : int;
  (** Preview clones live RAM, DMA and the complete filesystem. Unsupported
      service/status/validation outcomes discard all staged effects. *)
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
    index alongside the live [Step]. [on_step_state_pair] receives immutable
    snapshots immediately before and after that CPU instruction, before any
    subsequent BDOS dispatch. BDOS boundaries retain the current zero-based
    step count without incrementing it: [on_bdos_call_state] runs at guest PC
    0005H before dispatch and [on_bdos_resume] after the host effects and before
    another guest instruction. This distinction is needed because the previous
    post-step state may differ from the resumed guest state. [on_bdos_effect]
    exposes host-side register/FCB mutations separately from record-transfer events.
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
  ?on_step_state_pair:(step_index:int -> before:state_snapshot -> after:state_snapshot -> I8080.Step.t -> unit) ->
  ?on_before_instruction:(step_index:int -> instruction_boundary -> unit) ->
  ?intercept:(step_index:int -> instruction_boundary -> instruction_action) ->
  ?on_event:(event -> unit) ->
  ?on_bdos_event:(step_index:int -> Cpm.Bdos.event -> unit) ->
  ?on_bdos_file_event:(step_index:int -> Cpm.Bdos.file_event -> unit) ->
  ?on_console_output:(step_index:int -> char -> unit) ->
  ?on_bdos_effect:(Cpm.Bdos.external_effect -> unit) ->
  ?on_bdos_effect_at:(step_index:int -> Cpm.Bdos.external_effect -> unit) ->
  ?on_bdos_call_state:(step_index:int -> state:state_snapshot -> dma:int -> read_memory:(int -> int) -> unit) ->
  ?on_bdos_resume:(step_index:int -> state:state_snapshot -> unit) ->
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
  ?on_step_state_pair:(step_index:int -> before:state_snapshot -> after:state_snapshot -> I8080.Step.t -> unit) ->
  ?on_before_instruction:(step_index:int -> instruction_boundary -> unit) ->
  ?intercept:(step_index:int -> instruction_boundary -> instruction_action) ->
  ?on_event:(event -> unit) ->
  ?on_bdos_event:(step_index:int -> Cpm.Bdos.event -> unit) ->
  ?on_bdos_file_event:(step_index:int -> Cpm.Bdos.file_event -> unit) ->
  ?on_console_output:(step_index:int -> char -> unit) ->
  ?on_bdos_effect:(Cpm.Bdos.external_effect -> unit) ->
  ?on_bdos_effect_at:(step_index:int -> Cpm.Bdos.external_effect -> unit) ->
  ?on_bdos_call_state:(step_index:int -> state:state_snapshot -> dma:int -> read_memory:(int -> int) -> unit) ->
  ?on_bdos_resume:(step_index:int -> state:state_snapshot -> unit) ->
  ?on_start:(bytes -> unit) ->
  ?filesystem:Cpm.Filesystem.t ->
  ?on_start_state:(state_snapshot -> unit) ->
  ?command_tail:bytes ->
  output:(char -> unit) ->
  path:string ->
  unit ->
  (run_result, error) Stdlib.result
