type t

type summary = {
  known_entry_jmp_sites : int;
  known_entry_jmp_observations : int;
  source_target_candidate_pairs : int;
  multi_owner_coordinate_count : int;
  affected_routine_ids : int list;
  ownership_conflict_observations : int;
  return_mismatch_observations : int;
}

type routine_impact = {
  routine_id : int;
  multi_owner_instructions : int;
  multi_owner_blocks : int option;
}

val create : ?max_examples:int -> unit -> t

val observe_step :
  t ->
  Execution_map.t ->
  routine_id:int ->
  step_index:int ->
  I8080.Step.t ->
  Dynamic_structure.audit_event list ->
  unit

val summary : t -> summary
val multi_owner_coordinates : t -> (Execution_map.image_id * int * int list) list
val routine_impacts : t -> Dynamic_blocks.report option -> routine_impact list
val to_json_string : ?blocks:Dynamic_blocks.report -> t -> string
val example_events : t -> Dynamic_structure.audit_event list
