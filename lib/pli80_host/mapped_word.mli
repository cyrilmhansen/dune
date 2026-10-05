(** Complete +7A79. The two historical DADs and neighboring-byte read remain explicit. *)
type write = { address:int; value:int; phase:string }
type result = {position:int;discarded_ae39:int;index:int;offset:int;
 low_address:int;high_address:int;low:int;high:int;word:int}
val addresses : State.t -> int -> int * int * int * int
val lookup : State.t -> position:int -> protected:int list -> write:(write -> unit) -> result
