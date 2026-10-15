type nonnegative15 = int
type divisor = Three | Five | Fifteen
type engine = Interpreter | Jit
external execute : int -> int -> bool -> int = "runes_mir_mod_positive"
let of_int n =
  if n < 0 || n > 32767 then invalid_arg "nonnegative FIXED BINARY(15)";
  n
let to_int n = n
let divisor_of_int = function
  | 3 -> Three | 5 -> Five | 15 -> Fifteen
  | _ -> invalid_arg "Pass112 divisor domain"
let modulo engine numerator divisor =
  let b = match divisor with Three -> 3 | Five -> 5 | Fifteen -> 15 in
  execute numerator b (engine = Jit)
