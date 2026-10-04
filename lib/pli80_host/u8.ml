let check n = if n < 0 || n > 255 then invalid_arg "U8: byte out of bounds"
let wrap n = n land 255
