type input = { a:int; b:int }
type engine = Interpreter | Jit
external execute : int -> int -> bool -> int = "runes_mir_arithmetic"
let fits n = n >= -32768 && n <= 32767
let make ~a ~b =
  if not(fits a && fits b) then invalid_arg "Pass114 operand range";
  let product = a*2 in
  if not(fits product && fits(product+b)) then invalid_arg "Pass114 intermediate range";
  {a;b}
let evaluate engine input = execute input.a input.b (engine=Jit)
