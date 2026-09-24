(** CP/M 2.2 File Control Block fields visible in guest memory. *)

type t

val at : I8080.Memory.t -> address:int -> t
val address : t -> int
val get : t -> offset:int -> int
val set : t -> offset:int -> int -> unit
val drive : t -> int
val set_drive : t -> int -> unit
val filename : t -> string
val extension : t -> string
val extent : t -> int
val set_extent : t -> int -> unit
val s1 : t -> int
val set_s1 : t -> int -> unit
val s2 : t -> int
val set_s2 : t -> int -> unit
val record_count : t -> int
val set_record_count : t -> int -> unit
val current_record : t -> int
val set_current_record : t -> int -> unit
val allocation : t -> bytes
val set_allocation : t -> bytes -> unit
val random_record : t -> int
val set_random_record : t -> int -> unit
