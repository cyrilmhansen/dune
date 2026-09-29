(** Full chronological concrete execution witnesses, including host-side BDOS
    boundaries. This is observational data, not procedure recovery. *)

type origin = { image : Cpm.Filesystem.key; offset : int }
type memory_read = { address : int; value : int }
type memory_write = { address : int; old_value : int option; new_value : int }
type hardware_transfer = Call_frame | Restart_frame
type frame = { hardware_transfer : hardware_transfer; call_step : int; callsite : origin option; call_pc : int;
               return_address : int; stack_slot : int; target_pc : int; target : origin option }
type written_byte = { writer_step : int; writer_pc : int; writer_origin : origin option;
                      writer_disassembly : string; written_value : int }
type software_continuation = { stack_slot : int; return_address : int;
  low_byte_writer : written_byte; high_byte_writer : written_byte;
  consumed_step : int; consumer_pc : int; consumer_origin : origin option }
type certainty = Certain | Uncertain of string list

type instruction = {
  step_index : int; pc : int; pc_after : int; origin : origin option; target_origin : origin option; runtime_pc : int;
  bytes : bytes; disassembly : string; source : I8080.Step.instruction_source;
  before : Runner.state_snapshot; after : Runner.state_snapshot;
  reads : memory_read list; writes : memory_write list;
  flow : I8080.Step.control_flow; sp_before : int; sp_after : int;
}

type event =
  | Instruction of instruction
  | Bdos_call of { step_index : int; function_number : int; state : Runner.state_snapshot;
                   dma : int; fcb_address : int option; fcb_bytes : bytes option;
                   bridge_step : int option; bridge_origin : origin option;
                   frames : frame list; recent_transfers : instruction list; certainty : certainty }
  | Bdos_record of { step_index : int; operation : string; file : Cpm.Filesystem.key;
                     logical_record : int; dma : int; data : bytes }
  | File_operation of { step_index : int; operation : string; file : Cpm.Filesystem.key;
                        succeeded : bool; logical_record : int option }
  | Host_effect of { step_index : int; old_value : int option; detail : Cpm.Bdos.external_effect }
  | Bdos_resume of { step_index : int; state : Runner.state_snapshot }
  | Call_mismatch of { step_index : int; observed_target : int option; expected_frame : frame option }
  | Hardware_frame_return of { step_index : int; frame : frame }
  | Software_continuation_return of software_continuation
  | Termination of { step_index : int; reason : string }

type t

val create : run_id:string -> origin_at:(pc:int -> fetched:bytes -> origin option) -> t
val observe_step : t -> step_index:int -> before:Runner.state_snapshot ->
  after:Runner.state_snapshot -> I8080.Step.t -> unit
val observe_bdos_call : t -> step_index:int -> state:Runner.state_snapshot -> dma:int ->
  read_memory:(int -> int) -> unit
val observe_bdos_record : t -> step_index:int -> Cpm.Bdos.event -> unit
val observe_file_operation : t -> step_index:int -> Cpm.Bdos.file_event -> unit
val observe_host_effect : t -> step_index:int -> Cpm.Bdos.external_effect -> unit
val observe_bdos_resume : t -> step_index:int -> Runner.state_snapshot -> unit
val observe_termination : t -> step_index:int -> Runner.termination -> unit
val run_id : t -> string
val events : t -> event list
val instruction_count : t -> int
val file_event_count : t -> int
val transfer_mismatch_count : t -> int
val hardware_return_count : t -> int
val software_continuation_count : t -> int
(** Stream a deterministic report. Per-step writes have [old_value = null]:
    the live Step boundary reports the concrete new byte but not the overwritten
    byte. *)
val write_json : output:(string -> unit) -> t -> unit
(** Write an indexed master report and independently addressable chronological
    event chunks. All instruction and host-event witnesses remain represented. *)
val write_chunked_json : chunk_size:int -> write_chunk:(int -> string -> unit) ->
  write_index:(string -> unit) -> t -> unit
