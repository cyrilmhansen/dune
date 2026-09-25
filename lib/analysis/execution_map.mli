type t
type image_id = Cpm.Filesystem.key

type origin = Unknown | Image_byte of { image : image_id; offset : int }

type instruction_origin =
  | Image_instruction of { image : image_id; offset : int }
  | Unknown_runtime
  | Mixed_or_unresolved
  | Interrupt_acknowledge

type flow_kind = Jump | Call | Return | Restart | Halt

type control_flow_observation = {
  source : instruction_origin;
  source_pc : int;
  kind : flow_kind;
  taken : bool option;
  runtime_target : int option;
  target_origin : origin option;
  count : int;
}

type instruction = {
  image : image_id;
  offset : int;
  execution_count : int;
  first_step_index : int;
  last_step_index : int;
  runtime_pcs : int list;
  opcode : int;
  bytes : bytes;
}

type image_summary = {
  image : image_id;
  known_size : int option;
  known_byte_count : int;
  observed_records : int list;
  fetched_byte_count : int;
  unique_instruction_starts : int;
  total_instruction_executions : int;
  (** First (runtime PC, image offset, step index). *)
  first_execution : (int * int * int) option;
  last_execution_step : int option;
}

type bdos_site = {
  source : instruction_origin;
  source_pc : int option;
  function_number : int;
  count : int;
}

type summary = {
  total_instruction_executions : int;
  attributed_instruction_executions : int;
  unknown_executions : int;
  mixed_or_unresolved_executions : int;
  interrupt_acknowledge_executions : int;
}

type error = Conflicting_instruction_bytes of { image : image_id; offset : int }
exception Analysis_error of error

val create : unit -> t
val image_id : drive:int -> user:int -> filename:string -> (image_id, Cpm.Filesystem.error) result
val seed_image : t -> image:image_id -> runtime_base:int -> bytes -> (unit, string) result
val observe_step : t -> step_index:int -> I8080.Step.t -> (unit, error) result
val observe_bdos_event : t -> Cpm.Bdos.event -> unit
val observe_runner_event : t -> Runner.event -> unit

val origin_at : t -> int -> origin
val byte_at : t -> image:image_id -> offset:int -> int option
val byte_fetch_count : t -> image:image_id -> offset:int -> int
val instruction_start_count : t -> image:image_id -> offset:int -> int
val images : t -> image_id list
val image_summary : t -> image:image_id -> image_summary option
val image_summaries : t -> image_summary list
val instructions : t -> instruction list
val hot_instructions : t -> limit:int -> instruction list
val control_flow_observations : t -> control_flow_observation list
val cross_image_transitions : t -> control_flow_observation list
val bdos_sites : t -> bdos_site list
val summary : t -> summary
