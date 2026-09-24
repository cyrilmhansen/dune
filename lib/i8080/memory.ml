type t = bytes

let size = 0x10000

let create () = Bytes.make size '\000'

let check_address name address =
  if address < 0 || address >= size then invalid_arg name

let check_range name address length =
  check_address name address;
  if length < 0 || length > size - address then invalid_arg name

let read memory address =
  check_address "Memory.read" address;
  Char.code (Bytes.get memory address)

let write memory address value =
  check_address "Memory.write" address;
  if value < 0 || value > 0xff then invalid_arg "Memory.write";
  Bytes.set memory address (Char.chr value)

let load memory ~address source =
  check_range "Memory.load" address (Bytes.length source);
  Bytes.blit source 0 memory address (Bytes.length source)

let read_range memory ~address ~length =
  check_range "Memory.read_range" address length;
  Bytes.sub memory address length

let next_address address = (address + 1) land 0xffff

let read16 memory address =
  check_address "Memory.read16" address;
  let low = read memory address in
  let high = read memory (next_address address) in
  low lor (high lsl 8)

let write16 memory address value =
  check_address "Memory.write16" address;
  if value < 0 || value > 0xffff then invalid_arg "Memory.write16";
  write memory address (value land 0xff);
  write memory (next_address address) ((value lsr 8) land 0xff)
