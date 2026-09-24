type t = {
  mutable sign : bool;
  mutable zero : bool;
  mutable auxiliary_carry : bool;
  mutable parity : bool;
  mutable carry : bool;
}

let create () =
  {
    sign = false;
    zero = false;
    auxiliary_carry = false;
    parity = false;
    carry = false;
  }

let reset flags =
  flags.sign <- false;
  flags.zero <- false;
  flags.auxiliary_carry <- false;
  flags.parity <- false;
  flags.carry <- false

let sign flags = flags.sign
let zero flags = flags.zero
let auxiliary_carry flags = flags.auxiliary_carry
let parity flags = flags.parity
let carry flags = flags.carry

let set_sign flags value = flags.sign <- value
let set_zero flags value = flags.zero <- value
let set_auxiliary_carry flags value = flags.auxiliary_carry <- value
let set_parity flags value = flags.parity <- value
let set_carry flags value = flags.carry <- value

let equal left right =
  left.sign = right.sign
  && left.zero = right.zero
  && left.auxiliary_carry = right.auxiliary_carry
  && left.parity = right.parity
  && left.carry = right.carry
