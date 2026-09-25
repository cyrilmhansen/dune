type byte = {
  image_offset : int;
  virtual_offset : int;
  value : int option;
  dynamic_fetch_count : int;
  instruction_start_count : int;
  fetched : bool;
  instruction : Execution_map.instruction option;
}

type image = {
  id : Execution_map.image_id;
  virtual_base : int;
  span : int;
  bytes : byte array;
  known_byte_count : int;
  unique_fetched_byte_count : int;
  unique_fetched_percentage : float;
  dynamic_fetched_byte_count : int;
  unique_instruction_starts : int;
  total_instruction_executions : int;
  first_execution_step : int option;
  last_execution_step : int option;
  first_record_read_step : int option;
  last_record_read_step : int option;
}

type transition = {
  source_image : Execution_map.image_id;
  source_offset : int;
  source_virtual_offset : int;
  source_runtime_pc : int;
  kind : Execution_map.flow_kind;
  target_image : Execution_map.image_id;
  target_offset : int;
  target_virtual_offset : int;
  runtime_target : int;
  count : int;
}

type dynamic_edge = {
  source_image : Execution_map.image_id option;
  source_offset : int option;
  source_virtual_offset : int option;
  source_runtime_pc : int;
  kind : Execution_map.flow_kind;
  taken : bool option;
  target_image : Execution_map.image_id option;
  target_offset : int option;
  target_virtual_offset : int option;
  runtime_target : int option;
  count : int;
}

type bdos_site = {
  image : Execution_map.image_id option;
  offset : int option;
  virtual_offset : int option;
  runtime_pc : int option;
  function_number : int;
  count : int;
}

type t
type error = Missing_image of Execution_map.image_id

val report_of_map : ?top_n:int -> Execution_map.t -> images:Execution_map.image_id list -> (t, error) result
val images : t -> image list
val virtual_span : t -> int
val execution_summary : t -> Execution_map.summary
val transitions : t -> transition list
val dynamic_edges : t -> dynamic_edge list
val bdos_sites : t -> bdos_site list
val hottest_instructions : t -> (Execution_map.instruction * int) list
val heat_value : maximum:int -> int -> float
val to_json_string : t -> string
val write_json : output:(string -> unit) -> t -> unit
val to_html_string : ?row_width:int -> t -> string
val write_html : ?row_width:int -> output:(string -> unit) -> t -> unit
