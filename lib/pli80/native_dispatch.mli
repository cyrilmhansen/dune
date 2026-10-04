(** Small shared comparison/dispatch loop for explicitly supplied proven operations.
    No procedure discovery, ABI inference or synthetic execution events. *)
type previous = { origin : Analysis.Execution_map.origin;
  before : Runner.state_snapshot; after : Runner.state_snapshot; step : I8080.Step.t }
type oracle = { input : Runner.state_snapshot; output : Runner.state_snapshot;
  entry_memory : bytes; post_memory : bytes; logical_digest : string }
type prepared = { state : Runner.state_snapshot; memory : bytes;
  logical_writes : (int * int) list; compatibility_writes : (int * int) list }
type t
val write_digest : (int * int) list -> string
val create : image:string -> entry_pc:int -> end_pc:int -> oracles:oracle list ->
  records:(string * int * bytes) list ->
  prepare:(previous -> Analysis.Execution_map.origin -> Runner.instruction_boundary -> prepared) -> t
val run : Experiment.input -> t list -> (int list * Experiment.result, Experiment.error) result
