type t = bytes
let of_bytes b =
  if Bytes.length b <> 65536 then invalid_arg "Historical_state: missing 64KiB memory";
  Bytes.copy b
let copy = Bytes.copy
let read b a = U16.check a; Char.code (Bytes.get b a)
let write b a v = U16.check a; U8.check v; Bytes.set b a (Char.chr v)
let word b a = read b a lor (read b (U16.wrap (a+1)) lsl 8)
