(** Online byte-level semantic provenance, independent of concrete CPU state. *)

type t
type node_id = int
type edge_role = Value | Address | Flag | Control
type producer_origin = { image : Cpm.Filesystem.key; offset : int; runtime_pc : int }
type origin_resolver = pc:int -> fetched:bytes -> producer_origin option
type initial_class = System | Runner | Unclassified
type source =
  | File_byte of { file : Cpm.Filesystem.key; offset : int; value : int }
  | Command_tail_byte of { offset : int; value : int }
  | Initial_memory_byte of { address : int; value : int; class_ : initial_class }
  | Initial_register of { register : string; value : int }
  | External_result of { subsystem : string; operation : string; value : int }
type node_kind = Source of source | Operation of string
type node = {
  id : node_id; kind : node_kind; value : int; width : int;
  step_index : int option; origin : producer_origin option;
  inputs : (edge_role * node_id) list;
}
type root = Untracked | Node of node_id
type output_observation = {
  file : Cpm.Filesystem.key; offset : int; value : int;
  write_step_index : int; root : root;
}
type branch_observation = {
  step_index : int;
  pc : int;
  origin : producer_origin option;
  condition : I8080.Instr.condition;
  taken : bool;
  target : int option;
  flag_inputs : root list;
  decision_node : node_id;
  context_node : node_id;
  parent_context : root;
  depth : int;
}
type slice = { roots : root list; nodes : node list }
type source_group =
  | File_input of Cpm.Filesystem.key
  | Command_tail_input
  | Initial_memory_input of initial_class
  | Initial_register_input of string
  | External_input of string * string
type source_summary = { group : source_group; distinct_bytes : int }
type error = Concrete_mismatch of {
  step_index : int; instruction : string; location : string;
  predicted : int; concrete : int;
}
exception Provenance_error of error

val create : ?path_control:bool -> unit -> t
val seed_image : t -> image:Cpm.Filesystem.key -> runtime_base:int -> bytes -> unit
val seed_command_tail : t -> address:int -> bytes -> unit
val seed_command_tail_mapping : t -> address:int -> tail_offset:int -> bytes -> unit
val seed_memory : t -> class_:initial_class -> address:int -> bytes -> unit
val seed_initial_registers : t -> Runner.state_snapshot -> unit
val observe_step : ?origin_at:origin_resolver -> t ->
  step_index:int -> Runner.state_snapshot -> I8080.Step.t -> unit
val observe_bdos_event : t -> step_index:int -> Cpm.Bdos.event -> unit
val observe_bdos_effect : t -> Cpm.Bdos.external_effect -> unit
val output_byte_history : t -> file:Cpm.Filesystem.key -> offset:int -> output_observation list
val final_output_byte : t -> file:Cpm.Filesystem.key -> offset:int -> output_observation option
val branch_observations : t -> branch_observation list
val current_control_context : t -> root
val control_decision_count : t -> int
val control_context_count : t -> int
val controlled_operation_count : t -> int
val control_relation_count : t -> int
val control_decisions_of_context : t -> root -> branch_observation list
val output_control_context : t -> output_observation -> root
val node_count : t -> int
val edge_count : t -> int
val logical_control_node_count : t -> int
val node : t -> node_id -> node
val memory_root : t -> address:int -> root
val register_root : t -> register:I8080.Instr.register -> root
val flag_root : t -> flag:[ `Sign | `Zero | `Auxiliary_carry | `Parity | `Carry ] -> root
val memory_value : t -> address:int -> int
val data_edge_roles : edge_role list
val all_edge_roles : edge_role list
val slice : ?roles:edge_role list -> t -> root list -> slice
(** Deterministic depth-first fold over each node reachable from [roots]. Unlike
    [slice], this does not materialize a second full [node list]. *)
val fold_reachable : ?roles:edge_role list -> t -> roots:root list -> init:'a -> f:('a -> node -> 'a) -> 'a
val source_leaves : slice -> source list
val producer_nodes : slice -> node list
val source_summary : slice -> source_summary list
val output_byte_count : t -> file:Cpm.Filesystem.key -> int
val output_bytes_with_roots : t -> file:Cpm.Filesystem.key -> int
val output_bytes_untracked : t -> file:Cpm.Filesystem.key -> int
val output_bytes_rewritten : t -> file:Cpm.Filesystem.key -> int
val slice_json : t -> roots:root list -> string
val write_slice_json : out_channel -> t -> roots:root list -> unit
