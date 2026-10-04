let check n = if n < 0 || n > 65535 then invalid_arg "U16: word/address out of bounds"
let wrap n = n land 65535
