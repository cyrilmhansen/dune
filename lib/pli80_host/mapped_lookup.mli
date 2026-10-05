(** Complete logical +7A4D/+7A63 operations; table storage remains byte-addressed. *)
type write = { address : int; value : int; phase : string }
type mapped = { position : int; index : int; byte : int; discarded_ae37 : int }
type attribute = { mapped : mapped; packed_byte : int; low3 : int; discarded_ae38 : int }
type high_attribute = { byte_index:int; address:int; packed_byte:int;
  after_mask:int; shifts:int list; shift_carries:bool list; high3:int;
  discarded_ae48:int }
val mapped_byte : State.t -> position:int -> protected:int list ->
  write:(write -> unit) -> mapped
val low_attribute : State.t -> position:int -> protected:int list ->
  write:(write -> unit) -> attribute
(** Complete +7B64, a separate scratch/read path from low_attribute. *)
val high_attribute : State.t -> byte_index:int -> protected:int list ->
  write:(write -> unit) -> high_attribute
