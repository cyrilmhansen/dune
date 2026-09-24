(** Concrete Intel 8080 condition flags. *)
type t

val create : unit -> t
(** [create ()] returns all flags cleared. *)

val reset : t -> unit
(** Clear all flags. *)

val sign : t -> bool
val zero : t -> bool
val auxiliary_carry : t -> bool
val parity : t -> bool
val carry : t -> bool

val set_sign : t -> bool -> unit
val set_zero : t -> bool -> unit
val set_auxiliary_carry : t -> bool -> unit
val set_parity : t -> bool -> unit
val set_carry : t -> bool -> unit

val equal : t -> t -> bool
