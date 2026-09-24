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

let to_psw_byte flags =
  (if flags.sign then 0x80 else 0)
  lor (if flags.zero then 0x40 else 0)
  lor (if flags.auxiliary_carry then 0x10 else 0)
  lor (if flags.parity then 0x04 else 0)
  lor 0x02
  lor (if flags.carry then 0x01 else 0)

let restore_from_psw_byte flags value =
  if value < 0 || value > 0xff then invalid_arg "Flags.restore_from_psw_byte";
  flags.sign <- value land 0x80 <> 0;
  flags.zero <- value land 0x40 <> 0;
  flags.auxiliary_carry <- value land 0x10 <> 0;
  flags.parity <- value land 0x04 <> 0;
  flags.carry <- value land 0x01 <> 0
