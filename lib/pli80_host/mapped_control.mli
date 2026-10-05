type access={position:int;index:int;address:int;value:int;discarded_high:int}
val read : State.t -> position:int -> protected:int list -> write:(Mapped_lookup.write -> unit) -> access
val publish : State.t -> position:int -> value:int -> protected:int list -> write:(Mapped_lookup.write -> unit) -> access
