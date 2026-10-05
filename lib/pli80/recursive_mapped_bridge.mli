module R = Pli80_host.Recursive_mapped
type t
type call = private { coordinate:string; runtime_site:int; resume:int }
type residue = { address:int; value:int; writer:int; depth:int; kind:string }
type prepared = { result:R.result; memory:bytes; state:Runner.state_snapshot;
                  compatibility_writes:(int*int)list; final_writers:residue list; journal:residue list }
val create : pli_com:bytes -> pli1:bytes -> t
val verify_call : t -> origin:Analysis.Execution_map.origin -> before:Runner.state_snapshot -> after:Runner.state_snapshot -> I8080.Step.t -> entry:Runner.state_snapshot -> call
val prepare : t -> call:call -> origin:Analysis.Execution_map.origin -> state:Runner.state_snapshot -> memory:bytes -> prepared

(** Construct only a verified immutable internal CALL; no synthetic Step. *)
val internal_call : t -> int -> call
