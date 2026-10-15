(* Documentary floor-quotient reference for a>=0, b>0. No remainder or division
   instruction, MIR call, production wrapper, or historical output fixture. *)
let quotient_and_remainder a b =
  if a < 0 || a > 32767 || not (List.mem b [3;5;15]) then invalid_arg "reference domain";
  let rec subtract q r = if r < b then q,r else subtract (q+1) (r-b) in
  let q,r = subtract 0 a in
  if a <> q*b+r || r < 0 || r >= b then failwith "floor quotient invariant";
  q,r
(* A separate ascending-multiples check for the FIZZBUZ equality predicates. *)
let is_multiple a b =
  let rec advance n = if n >= a then n=a else advance (n+b) in
  advance 0
