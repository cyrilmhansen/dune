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

val to_psw_byte : t -> int
(** Pack the five flags into the Intel 8080 PSW flags byte. Reserved bits 5
    and 3 are zero and bit 1 is one. *)

val restore_from_psw_byte : t -> int -> unit
(** Restore the five flags from a PSW byte. The byte must be in [0..255];
    reserved bits 5, 3, and 1 are ignored. *)
