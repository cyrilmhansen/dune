(* Construct floor quotient directly, without signed remainder/correction.
   For negative a, descend through whole multiples until q*b <= a.
   For nonnegative a, subtract whole divisors until the residual is below b. *)
let quotient_and_remainder a b =
  if a < -32768 || a > 32767 || not (List.mem b [3;5;15]) then invalid_arg "reference domain";
  let q =
    if a < 0 then
      let rec descend q multiple =
        if multiple <= a then q else descend (q-1) (multiple-b)
      in descend 0 0
    else
      let rec subtract q r = if r < b then q else subtract (q+1) (r-b)
      in subtract 0 a
  in
  let r = a - b*q in
  if q*b > a || a >= (q+1)*b || r < 0 || r >= b then failwith "floor quotient invariant";
  q,r
(* Independent positive FIZZBUZ predicate, retained from Pass112. *)
let is_multiple a b =
  let rec advance n = if n >= a then n=a else advance (n+b) in
  advance 0
