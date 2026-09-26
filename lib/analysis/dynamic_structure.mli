(** Conservative dynamic routine candidates and first-observed routine
    relationships. This is not static function or basic-block recovery. *)

type routine_id = int

type transition_kind = Call | Return | Restart | Image_entry | Other_observed

type tag = Entry | Image_entry_tag | Called | Returns | Recursive | Unresolved_origin

type routine = {
  id : routine_id;
  image : Execution_map.image_id option;
  entry_offset : int option;
  runtime_entry_pc : int;
  display_name : string;
  tags : tag list;
  first_execution_step : int option;
  last_execution_step : int option;
  instruction_executions : int;
  distinct_instruction_starts : int;
  incoming_routine_count : int;
  outgoing_routine_count : int;
  call_count : int;
  return_count : int;
  self_call_count : int;
  recursive : bool;
}

type transition = {
  source : routine_id;
  target : routine_id;
  occurrence_count : int;
  first_step : int;
  last_step : int;
  kinds : transition_kind list;
}

type narrative_entry = {
  ordinal : int;
  source : routine_id;
  target : routine_id;
  first_step : int;
  first_kind : transition_kind;
}

type anomaly_kind =
  | Return_without_call
  | Return_target_mismatch
  | Jump_into_known_entry
  | Image_entry_without_transfer
  | Image_change_without_new_entry
  | Unknown_instruction_origin

type anomaly = { step : int; last_step : int; occurrence_count : int;
  kind : anomaly_kind; runtime_pc : int; detail : string }

type t

type summary = {
  routine_count : int;
  narrative_transition_count : int;
  aggregate_pair_count : int;
  recursive_candidate_count : int;
  anomaly_count : int;
  anomaly_observation_count : int;
}

val create : unit -> t
val observe_step : t -> Execution_map.t -> step_index:int -> I8080.Step.t -> unit
val routines : t -> routine list
val transitions : t -> transition list
val narrative : t -> narrative_entry list
val anomalies : t -> anomaly list
val summary : t -> summary
val transition_kind_name : transition_kind -> string
val tag_name : tag -> string
val routine_name : routine -> string
val to_json_string : t -> string
val write_json : output:(string -> unit) -> t -> unit
val to_text : ?limit:int -> t -> string
