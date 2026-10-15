(** Optional documented PL/I MOD, full signed numerator range. No historical
    runtime equivalence claim; host i64 is wider than PL/I precision 15. *)
type signed15
type divisor = Three | Five | Fifteen
type engine = Interpreter | Jit
val of_int : int -> signed15
val to_int : signed15 -> int
val divisor_of_int : int -> divisor
val modulo : engine -> signed15 -> divisor -> signed15
(** Inputs outside -32768..32767 or divisors outside 3/5/15 raise
    Invalid_argument before MIR initialization. No buffers or global state. *)
