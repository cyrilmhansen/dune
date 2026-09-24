type szp = { sign : bool; zero : bool; parity : bool }
type status = { szp : szp; auxiliary_carry : bool }
type result8 = { value : int; status : status; carry : bool }

let check maximum value =
  if value < 0 || value > maximum then invalid_arg "Alu: operand out of range"

let byte value = check 0xff value
let bit flag = if flag then 1 else 0

let szp value =
  byte value;
  let folded = value lxor (value lsr 4) in
  let folded = folded lxor (folded lsr 2) in
  let folded = folded lxor (folded lsr 1) in
  { sign = value land 0x80 <> 0; zero = value = 0; parity = folded land 1 = 0 }

let result value auxiliary_carry carry =
  { value; status = { szp = szp value; auxiliary_carry }; carry }

let add ~carry a b =
  byte a;
  byte b;
  let c = bit carry in
  let sum = a + b + c in
  result (sum land 0xff) ((a land 15) + (b land 15) + c > 15) (sum > 0xff)

let subtract ~borrow a b =
  (* The 8080 complements the full carry into borrow, but leaves AC alone. *)
  byte a;
  byte b;
  let added = add ~carry:(not borrow) a (b lxor 0xff) in
  { added with carry = not added.carry }

let logand a b =
  byte a;
  byte b;
  result (a land b) ((a lor b) land 8 <> 0) false

let logxor a b =
  byte a;
  byte b;
  result (a lxor b) false false

let logor a b =
  byte a;
  byte b;
  result (a lor b) false false

let increment value =
  byte value;
  let next = (value + 1) land 0xff in
  (next, { szp = szp next; auxiliary_carry = value land 15 = 15 })

let decrement value =
  byte value;
  let next = (value - 1) land 0xff in
  (next, { szp = szp next; auxiliary_carry = value land 15 <> 0 })

let dad a b =
  check 0xffff a;
  check 0xffff b;
  let sum = a + b in
  (sum land 0xffff, sum > 0xffff)

let rlc value =
  byte value;
  (((value lsl 1) lor (value lsr 7)) land 0xff, value land 0x80 <> 0)

let rrc value =
  byte value;
  ((value lsr 1) lor ((value land 1) lsl 7), value land 1 <> 0)

let ral ~carry value =
  byte value;
  (((value lsl 1) lor bit carry) land 0xff, value land 0x80 <> 0)

let rar ~carry value =
  byte value;
  ((value lsr 1) lor (bit carry lsl 7), value land 1 <> 0)

let complement value =
  byte value;
  value lxor 0xff

let daa ~auxiliary_carry ~carry a =
  byte a;
  let low_correction = if auxiliary_carry || a land 15 > 9 then 6 else 0 in
  let high_carry = carry || a > 0x99 in
  let correction = low_correction + (if high_carry then 0x60 else 0) in
  let adjusted = add ~carry:false a correction in
  (* CY remains set if it was set on entry, even without binary overflow. *)
  { adjusted with carry = high_carry }
