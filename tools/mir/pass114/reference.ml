(* Independent selected mathematical law; no MIR/FFI call or production guard.
   Doubling uses addition, branch uses comparison ordering, decrement uses pred. *)
type result = { product:int; before_if:int; take_then:bool; final:int }
let evaluate a b =
  let product = a+a in
  let before_if = product+b in
  let take_then = Int.compare before_if 50 = 1 in
  let final = if take_then then pred before_if else before_if in
  let fits x = -32768 <= x && x <= 32767 in
  if not(List.for_all fits [a;b;product;before_if;final]) then invalid_arg "reference range";
  {product;before_if;take_then;final}
