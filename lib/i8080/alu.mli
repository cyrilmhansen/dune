(** Pure Intel 8080 arithmetic. No machine state or mutable flags are involved.
    Byte/word inputs must be in range; otherwise [Invalid_argument] is raised.
    See [docs/i8080-flags.md] for the audited flag rules. *)

type szp = { sign : bool; zero : bool; parity : bool }
type status = { szp : szp; auxiliary_carry : bool }
type result8 = { value : int; status : status; carry : bool }

val szp : int -> szp
val add : carry:bool -> int -> int -> result8
val subtract : borrow:bool -> int -> int -> result8
(** CY is borrow, AC is complement-add carry (not half-borrow).
    CMP uses [subtract ~borrow:false] and discards the value. *)

val logand : int -> int -> result8
val logxor : int -> int -> result8
val logor : int -> int -> result8

val increment : int -> int * status
val decrement : int -> int * status
(** No CY result: the caller must preserve CY. *)

val dad : int -> int -> int * bool
(** Reduced 16-bit sum and new CY only. *)

val rlc : int -> int * bool
val rrc : int -> int * bool
val ral : carry:bool -> int -> int * bool
val rar : carry:bool -> int -> int * bool
(** Reduced byte and new CY only. *)

val complement : int -> int
val daa : auxiliary_carry:bool -> carry:bool -> int -> result8
