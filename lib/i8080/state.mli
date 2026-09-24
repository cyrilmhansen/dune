(** Mutable concrete register state for an Intel 8080. *)
type t

val create : unit -> t
(** [create ()] initializes all registers and flags to zero/cleared. *)

val a : t -> int
val b : t -> int
val c : t -> int
val d : t -> int
val e : t -> int
val h : t -> int
val l : t -> int
val sp : t -> int
val pc : t -> int

val set_a : t -> int -> unit
val set_b : t -> int -> unit
val set_c : t -> int -> unit
val set_d : t -> int -> unit
val set_e : t -> int -> unit
val set_h : t -> int -> unit
val set_l : t -> int -> unit
val set_sp : t -> int -> unit
val set_pc : t -> int -> unit

val bc : t -> int
val de : t -> int
val hl : t -> int
val set_bc : t -> int -> unit
val set_de : t -> int -> unit
val set_hl : t -> int -> unit
(** Pair setters accept a 16-bit value. The first register in each pair is
    the high byte: [BC = B: C], [DE = D: E], [HL = H: L]. *)

val flags : t -> Flags.t
(** Return the mutable flags belonging to this state. *)
