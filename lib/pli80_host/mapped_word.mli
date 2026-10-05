(** Complete +7A79. The two historical DADs and neighboring-byte read remain explicit. *)
type write = { address:int; value:int; phase:string }
type result = {position:int;discarded_ae39:int;index:int;offset:int;
 low_address:int;high_address:int;low:int;high:int;word:int}
val addresses : State.t -> int -> int * int * int * int
val lookup : State.t -> position:int -> protected:int list -> write:(write -> unit) -> result

(** Complete +7AF0. Destination save is an explicit proven ABI bridge effect;
    the compiler operation retains scratch/read/publication chronology.
    old_word is pre-publication diagnostic metadata, not an algorithm input. *)
type publication={position:int;discarded_ae3f:int;index:int;first_address:int;
 low_address:int;high_address:int;low:int;high:int;word:int;old_word:int}
val publish : State.t -> position:int -> value:int -> protected:int list ->
 write:(write -> unit) -> save_destination:(int -> unit) -> publication
