type t
type call = private { coordinate : string; runtime_site : int; resume : int }
type prepared = {
  result : Pli80_host.Balance_scan.result; memory : bytes;
  state : Runner.state_snapshot; compatibility_writes : (int * int) list;
}
val create : pli1:bytes -> t
val verify_call : t -> origin:Analysis.Execution_map.origin ->
  before:Runner.state_snapshot -> after:Runner.state_snapshot ->
  I8080.Step.t -> entry:Runner.state_snapshot -> call
val prepare : t -> call:call -> origin:Analysis.Execution_map.origin ->
  state:Runner.state_snapshot -> memory:bytes -> prepared

(** Construct only a verified immutable internal CALL; no synthetic Step. *)
val internal_call : t -> int -> call
