type classification = Program_input | Intermediate | Program_image | Output | Other of string
type classifier = Cpm.Filesystem.key -> classification
type sink = { file : Cpm.Filesystem.key; offset : int; generation : int option }
type offset_range = { first : int; last : int }
type output_byte = {
  offset : int; value : int; write_step : int option; root_present : bool;
  rewrite_count : int; projection_embedded : bool;
}
type source_leaf = {
  node_id : Provenance.node_id; kind : string; identity : string;
  classification : classification option; offset : int option;
  virtual_offset : int option; value : int;
}
type source_group = {
  kind : string; identity : string; classification : classification option;
  distinct_offsets : int list; ranges : offset_range list;
  leaf_occurrences : int;
}
type producer = {
  id : string; image : Cpm.Filesystem.key; image_offset : int;
  virtual_offset : int option; runtime_pc : int; operation_kind : string;
  operation_nodes : int; producer_steps : int; operation_kinds : string list;
  value_edges : int; address_edges : int; flag_edges : int; control_edges : int;
  first_step : int option; last_step : int option;
}
type operation_summary = {
  kind : string; node_count : int; producer_locations : int;
  producer_steps : int; value_edges : int; address_edges : int;
  flag_edges : int; control_edges : int;
}
type preview_node = {
  id : Provenance.node_id; label : string; value : int; width : int;
  step : int option; origin : Provenance.producer_origin option; depth : int;
}
type preview_edge = { from_id : int; to_id : int; role : Provenance.edge_role }
type preview = {
  nodes : preview_node list; edges : preview_edge list;
  max_depth : int; max_nodes : int; omitted_frontier_count : int;
}
type role_counts = { value : int; address : int; flag : int; control : int }
type projection = {
  sink : sink; sink_value : int option; write_step : int option;
  root : Provenance.root; full_node_count : int; source_leaf_count : int;
  producers : producer list; producer_location_count : int;
  distinct_producer_steps : int; unlocated_operation_nodes : int;
  operations : operation_summary list; roles : role_counts;
  sources : source_group list; source_leaves : source_leaf list;
  preview : preview;
}
type t
type error = Missing_output_byte of sink

type control_decision_row = {
  image : Cpm.Filesystem.key option;
  image_offset : int option;
  runtime_pc : int;
  condition : string;
  taken : bool;
  decision_count : int;
  first_step : int;
  last_step : int;
  distinct_flag_roots : int;
}
type path_control_projection = {
  sink : sink;
  context_depth : int;
  distinct_branch_locations : int;
  earliest_decision_step : int option;
  latest_decision_step : int option;
  additional_context_nodes : int;
  additional_decision_nodes : int;
  additional_flag_ancestors : int;
  combined_reachable_nodes : int;
  control_relations : int;
  locations : control_decision_row list;
  preview : preview;
}
type control_report = {
  decisions : control_decision_row list;
  paths : path_control_projection list;
}

val report_of_provenance :
  ?preview_depth:int -> ?preview_nodes:int ->
  provenance:Provenance.t -> execution:Execution_report.t ->
  classify:classifier -> output_file:Cpm.Filesystem.key -> output_bytes:bytes ->
  selected:sink list -> unit -> (t, error) result
val output_file : t -> Cpm.Filesystem.key
val output_bytes : t -> output_byte list
val projections : t -> projection list
val execution : t -> Execution_report.t
val ranges_of_offsets : int list -> offset_range list
val to_json_string : t -> string
val write_json : output:(string -> unit) -> t -> unit
val path_control_report_of_provenance : provenance:Provenance.t -> selected:sink list -> (control_report, error) result
val control_report_to_json_string : control_report -> string
val write_control_report_json : output:(string -> unit) -> control_report -> unit
