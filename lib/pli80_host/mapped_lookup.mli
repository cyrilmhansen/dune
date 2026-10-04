(** Complete logical +7A4D/+7A63 operations; table storage remains byte-addressed. *)
type write = { address : int; value : int; phase : string }
type mapped = { position : int; index : int; byte : int; discarded_ae37 : int }
type attribute = { mapped : mapped; packed_byte : int; low3 : int; discarded_ae38 : int }
val mapped_byte : State.t -> position:int -> protected:int list ->
  write:(write -> unit) -> mapped
val low_attribute : State.t -> position:int -> protected:int list ->
  write:(write -> unit) -> attribute
