type t
type operation = Mapped_word | Secondary
type result = Word of Pli80_host.Mapped_word.publication | Byte of Pli80_host.Auxiliary.access
type call = private { coordinate:string; runtime_site:int; resume:int; operation:operation }
type prepared = { result:result; writes:Pli80_host.Mapped_lookup.write list;
  memory:bytes; state:Runner.state_snapshot; compatibility_writes:(int*int)list; residue_writer:int option }
val create : pli1:bytes -> t
val verify_call : t -> origin:Analysis.Execution_map.origin -> before:Runner.state_snapshot -> after:Runner.state_snapshot -> I8080.Step.t -> entry:Runner.state_snapshot -> call
val prepare : t -> call:call -> origin:Analysis.Execution_map.origin -> state:Runner.state_snapshot -> memory:bytes -> prepared

val extent : operation -> int * int

(** Verified immutable historical internal CALL; no synthetic Step. *)
val internal_call : t -> int -> call
