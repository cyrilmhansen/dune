(** Live result of one concrete instruction execution. This is not a persistent
    trace format. *)
type t

type memory_access =
  | Read of { address : int; value : int }
  | Write of { address : int; value : int }

type control_flow =
  | Sequential
  | Jump of { target : int; taken : bool }
  | Call of { target : int; taken : bool }
  | Return of { target : int option; taken : bool }
  | Restart of { target : int }
  | Halt

val create :
  pc_before:int ->
  pc_after:int ->
  decoded:Decode.decoded ->
  fetched_bytes:bytes ->
  memory_accesses:memory_access list ->
  control_flow:control_flow ->
  t

val pc_before : t -> int
val pc_after : t -> int
val decoded : t -> Decode.decoded
(* Return a copy of the bytes fetched for this instruction. *)
val fetched_bytes : t -> bytes
val memory_accesses : t -> memory_access list
val control_flow : t -> control_flow
