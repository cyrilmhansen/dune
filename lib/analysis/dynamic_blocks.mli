(** Dynamic-only observed instruction graph and post-run basic-block map. *)

type origin =
  | Image_byte of { image : Execution_map.image_id; offset : int }
  | Unknown_origin
  | Mixed_origin
  | Interrupt_origin

type instruction_representation = Image_source | Observed_bytes

type instruction_tag = Unresolved_origin | Mixed_bytes | Interrupt_supplied
  | Byte_variant | Origin_variant | Image_bytes_disagree

type instruction = {
  id : int;
  routine_id : Dynamic_structure.routine_id;
  origin : origin;
  runtime_pc : int;
  bytes : bytes;
  decoded : I8080.Instr.t;
  text : string;
  representation : instruction_representation;
  variant : int;
  tags : instruction_tag list;
  first_step : int;
  last_step : int;
  execution_count : int;
}

type instruction_transition_kind = Sequential | Branch_taken | Branch_fallthrough
  | Call | Return | Restart | Other

type instruction_transition = {
  source_instruction : int;
  target_instruction : int;
  kind : instruction_transition_kind;
  occurrence_count : int;
  first_step : int;
  last_step : int;
}

type block_tag = Routine_entry | Branch_target | Branch_fallthrough_tag
  | Call_continuation | Return_continuation | Control_continuation
  | Multi_predecessor | Backward_edge_target | Unresolved_block_origin
  | Mixed_block_origin | Interrupt_block_origin | Variant_boundary | Observed_bytes_block

type block = {
  routine_id : Dynamic_structure.routine_id;
  id : int;
  display_name : string;
  image : Execution_map.image_id option;
  start_offset : int option;
  byte_length : int;
  runtime_start : int;
  origin : origin;
  tags : block_tag list;
  representation : instruction_representation;
  first_execution_step : int;
  last_execution_step : int;
  entry_count : int;
  instruction_count : int;
  predecessor_block_count : int;
  successor_block_count : int;
  instruction_ids : int list;
}

type block_transition = {
  source_routine : Dynamic_structure.routine_id;
  source_block : int;
  target_routine : Dynamic_structure.routine_id;
  target_block : int;
  occurrence_count : int;
  first_step : int;
  last_step : int;
  kinds : instruction_transition_kind list;
}

type narrative_entry = {
  ordinal : int;
  source_routine : Dynamic_structure.routine_id;
  source_block : int;
  target_routine : Dynamic_structure.routine_id;
  target_block : int;
  first_step : int;
  first_kind : instruction_transition_kind;
}

type anomaly_kind = Instruction_bytes_changed | Instruction_origin_changed
  | Decoded_length_mismatch | Instruction_image_bytes_disagree

type anomaly = {
  kind : anomaly_kind;
  routine_id : Dynamic_structure.routine_id;
  runtime_pc : int;
  first_step : int;
  last_step : int;
  occurrence_count : int;
  detail : string;
}

type summary = {
  instruction_count : int;
  block_count : int;
  transition_count : int;
  backward_edge_target_count : int;
  anomaly_count : int;
  anomaly_observation_count : int;
}

type report
type t

val create : unit -> t
val observe_step : t -> Execution_map.t -> routine_id:Dynamic_structure.routine_id ->
  routine_entry:bool -> step_index:int -> I8080.Step.t -> unit
val materialize : t -> Dynamic_structure.routine list -> report
val instructions : report -> instruction list
val instruction_transitions : report -> instruction_transition list
val blocks : report -> block list
val transitions : report -> block_transition list
val narrative : report -> narrative_entry list
val anomalies : report -> anomaly list
val summary : report -> summary
val instruction_transition_kind_name : instruction_transition_kind -> string
val instruction_tag_name : instruction_tag -> string
val block_tag_name : block_tag -> string
val anomaly_kind_name : anomaly_kind -> string
val to_json_string : report -> string
val write_json : output:(string -> unit) -> report -> unit
val to_text : ?routine_limit:int -> ?blocks_per_routine:int -> ?instructions_per_block:int -> report -> string
