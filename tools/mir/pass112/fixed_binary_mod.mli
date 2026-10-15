(** Optional, bounded PL/I semantic operation using real upstream MIR.
    FIXED BINARY(15) has documented signed range -32768..32767, two-byte
    storage. This experiment admits only its nonnegative subset, using a wider
    host representation without changing the language precision. *)
type nonnegative15
type divisor = Three | Five | Fifteen
type engine = Interpreter | Jit
val of_int : int -> nonnegative15
val to_int : nonnegative15 -> int
val divisor_of_int : int -> divisor
val modulo : engine -> nonnegative15 -> divisor -> nonnegative15
(** Unsupported inputs raise Invalid_argument. No global compiler/runtime state,
    persistent JIT context, buffers, machine representation or type conversion. *)
