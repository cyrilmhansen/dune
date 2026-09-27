(** Owner-neutral view of observed image-backed instructions and blocks.

    The existing [Dynamic_blocks] report remains owner-qualified. This view
    interns ordinary immutable code by image coordinate and uses the union of
    observed block boundaries. Owner-specific observations remain available
    as separate context relations. *)

type instruction_context = {
  routine_id : int;
  observed_instruction_ids : int list;
  runtime_pcs : int list;
  execution_count : int;
  first_step : int;
  last_step : int;
}

type instruction = {
  image : Execution_map.image_id;
  offset : int;
  bytes : bytes;
  decoded : I8080.Instr.t;
  text : string;
  execution_count : int;
  first_step : int;
  last_step : int;
  contexts : instruction_context list;
}

type block = {
  id : int;
  image : Execution_map.image_id;
  start_offset : int;
  end_offset : int;
  instruction_offsets : int list;
}

(** A routine's observed relationship to a canonical block. Tags and metrics
    remain contextual facts; they are not properties of the canonical block. *)
type block_context = {
  routine_id : int;
  canonical_block_id : int;
  owner_block_id : int;
  tags : Dynamic_blocks.block_tag list;
  runtime_start : int;
  first_step : int;
  last_step : int;
  execution_count : int;
  instruction_count : int;
  entry_count : int;
  split_from_owner_block : bool;
}

type exceptional_instruction = {
  owner_routine_id : int;
  observed_instruction_id : int;
  origin : Dynamic_blocks.origin;
  runtime_pc : int;
  bytes : bytes;
  text : string;
  tags : Dynamic_blocks.instruction_tag list;
  first_step : int;
  last_step : int;
  execution_count : int;
  reason : string;
}

type exceptional_block = {
  owner_routine_id : int;
  owner_block_id : int;
  origin : Dynamic_blocks.origin;
  runtime_start : int;
  byte_length : int;
  tags : Dynamic_blocks.block_tag list;
  instruction_ids : int list;
}

type partition_anomaly = {
  image : Execution_map.image_id;
  start_offset : int;
  end_offset : int;
  reason : string;
}

type summary = {
  canonical_instruction_count : int;
  exceptional_instruction_count : int;
  canonical_block_count : int;
  block_context_count : int;
  exceptional_block_count : int;
  partition_anomaly_count : int;
}

type report

val materialize : Dynamic_blocks.report -> report
val instructions : report -> instruction list
val blocks : report -> block list
val block_contexts : report -> block_context list
val exceptional_instructions : report -> exceptional_instruction list
val exceptional_blocks : report -> exceptional_block list
val partition_anomalies : report -> partition_anomaly list
val summary : report -> summary
val block_at : report -> image:Execution_map.image_id -> offset:int -> block option
val to_json_string : report -> string
val to_text : report -> string
