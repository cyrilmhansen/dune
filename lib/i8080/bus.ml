type t = {
  memory : Memory.t;
  input_handler : (port:int -> int) option;
  output_handler : (port:int -> value:int -> unit) option;
}

type io_error =
  | Input_port_not_configured of int
  | Output_port_not_configured of int

let create ?input ?output memory =
  { memory; input_handler = input; output_handler = output }

let check_port port =
  if port < 0 || port > 0xff then invalid_arg "Bus port"

let read_memory bus ~address = Memory.read bus.memory address
let write_memory bus ~address ~value = Memory.write bus.memory address value

let input bus ~port =
  check_port port;
  match bus.input_handler with
  | None -> Error (Input_port_not_configured port)
  | Some handler ->
      let value = handler ~port in
      if value < 0 || value > 0xff then invalid_arg "Bus input handler returned a non-byte";
      Ok value

let output bus ~port ~value =
  check_port port;
  if value < 0 || value > 0xff then invalid_arg "Bus output value";
  match bus.output_handler with
  | None -> Error (Output_port_not_configured port)
  | Some handler ->
      handler ~port ~value;
      Ok ()
