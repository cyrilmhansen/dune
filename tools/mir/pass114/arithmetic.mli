(** Manually selected ARITH.PLI composition, not a parser or general frontend.
    Inputs and all intermediates must fit signed FIXED BINARY(15). *)
type input
type engine = Interpreter | Jit
val make : a:int -> b:int -> input
(** Rejects out-of-range inputs, 2*a, or 2*a+b with Invalid_argument. *)
val evaluate : engine -> input -> int
(** Real upstream MIR scalar result; no mutable input state or persistent JIT. *)
