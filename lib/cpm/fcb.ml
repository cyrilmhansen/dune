type t = { memory : I8080.Memory.t; address : int }

let at memory ~address =
  if address < 0 || address > 0xffff then invalid_arg "Fcb.at";
  { memory; address }

let address fcb = fcb.address

let check_offset offset =
  if offset < 0 || offset > 35 then invalid_arg "Fcb offset"

let get fcb ~offset =
  check_offset offset;
  I8080.Memory.read fcb.memory ((fcb.address + offset) land 0xffff)

let set fcb ~offset value =
  check_offset offset;
  I8080.Memory.write fcb.memory ((fcb.address + offset) land 0xffff) value

let drive fcb = get fcb ~offset:0
let set_drive fcb value = set fcb ~offset:0 value

let field_string fcb ~offset ~length =
  String.init length (fun index -> Char.chr (get fcb ~offset:(offset + index)))

let filename fcb = field_string fcb ~offset:1 ~length:8
let extension fcb = field_string fcb ~offset:9 ~length:3

let extent fcb =
  (get fcb ~offset:12 land 0x1f) lor ((get fcb ~offset:14 land 0x3f) lsl 5)
let set_extent fcb extent =
  if extent < 0 || extent > 0x7ff then invalid_arg "Fcb.set_extent";
  set fcb ~offset:12 (extent land 0x1f);
  set fcb ~offset:14 ((extent lsr 5) land 0x3f)

let s1 fcb = get fcb ~offset:13
let set_s1 fcb value = set fcb ~offset:13 value
let s2 fcb = get fcb ~offset:14
let set_s2 fcb value = set fcb ~offset:14 value
let record_count fcb = get fcb ~offset:15
let set_record_count fcb value = set fcb ~offset:15 value
let current_record fcb = get fcb ~offset:32
let set_current_record fcb value = set fcb ~offset:32 value

let allocation fcb =
  let bytes = Bytes.create 16 in
  for index = 0 to 15 do
    Bytes.set bytes index (Char.chr (get fcb ~offset:(16 + index)))
  done;
  bytes

let set_allocation fcb bytes =
  if Bytes.length bytes <> 16 then invalid_arg "Fcb.set_allocation";
  for index = 0 to 15 do
    set fcb ~offset:(16 + index) (Char.code (Bytes.get bytes index))
  done

let random_record fcb =
  get fcb ~offset:33 lor (get fcb ~offset:34 lsl 8) lor (get fcb ~offset:35 lsl 16)

let set_random_record fcb record =
  if record < 0 || record > 0xffffff then invalid_arg "Fcb.set_random_record";
  set fcb ~offset:33 (record land 0xff);
  set fcb ~offset:34 ((record lsr 8) land 0xff);
  set fcb ~offset:35 ((record lsr 16) land 0xff)
