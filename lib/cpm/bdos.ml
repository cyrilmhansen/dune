type action = Continue | Terminate

type error =
  | Unsupported_function of int
  | Unterminated_string of { start_address : int; scanned : int }

let print_string memory ~start_address output =
  let address = ref start_address in
  let scanned = ref 0 in
  let terminated = ref false in
  while !scanned < I8080.Memory.size && not !terminated do
    let byte = I8080.Memory.read memory !address in
    if byte = 0x24 then terminated := true
    else (
      output (Char.chr byte);
      incr scanned;
      address := (!address + 1) land 0xffff)
  done;
  if !terminated then Ok Continue
  else Error (Unterminated_string { start_address; scanned = !scanned })

let dispatch ~memory ~state ~output =
  match I8080.State.c state with
  | 0 -> Ok Terminate
  | 9 -> print_string memory ~start_address:(I8080.State.de state) output
  | function_number -> Error (Unsupported_function function_number)
