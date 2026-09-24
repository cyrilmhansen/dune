(** Canonical text writer for AT8TRACE v1. [create] writes the header once. *)
type t

val create : output:(string -> unit) -> t
val write : t -> Event.t -> unit
