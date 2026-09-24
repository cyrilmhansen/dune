type t = { output : string -> unit; mutable next_step_index : int }

open Event

let create ~output =
  output "AT8TRACE\t1\n";
  { output; next_step_index = 0 }

let check_range label maximum value =
  if value < 0 || value > maximum then invalid_arg ("Trace.Writer: invalid " ^ label)

let hex width value =
  let maximum = (1 lsl (width * 4)) - 1 in
  check_range "numeric field" maximum value;
  Printf.sprintf "%0*X" width value

let bytes_hex bytes =
  let result = Buffer.create (String.length bytes * 2) in
  String.iter
    (fun byte -> Buffer.add_string result (Printf.sprintf "%02X" (Char.code byte)))
    bytes;
  Buffer.contents result

let status = function
  | Event.Documented -> "documented"
  | Event.Undocumented_alias -> "undocumented_alias"
  | Event.Uncertain -> "uncertain"

let bool_field value = if value then "1" else "0"

let control_flow = function
  | Event.Sequential -> "sequential"
  | Event.Jump { target; taken } ->
      Printf.sprintf "jump:%s:%s" (bool_field taken) (hex 4 target)
  | Event.Call { target; taken } ->
      Printf.sprintf "call:%s:%s" (bool_field taken) (hex 4 target)
  | Event.Return { target = Some target; taken } ->
      Printf.sprintf "return:%s:%s" (bool_field taken) (hex 4 target)
  | Event.Return { target = None; taken } ->
      Printf.sprintf "return:%s:none" (bool_field taken)
  | Event.Restart { target } -> Printf.sprintf "restart:%s" (hex 4 target)
  | Event.Halt -> "halt"

let emit_memory output step_index = function
  | Event.Read { address; value } ->
      output
        (Printf.sprintf "MEMR\t%d\t%s\t%s\n" step_index (hex 4 address) (hex 2 value))
  | Event.Write { address; value } ->
      output
        (Printf.sprintf "MEMW\t%d\t%s\t%s\n" step_index (hex 4 address) (hex 2 value))

let write writer = function
  | Event.Cpu_step step ->
      if step.step_index <> writer.next_step_index then
        invalid_arg "Trace.Writer: non-sequential CPU step index";
      check_range "opcode" 0xff step.opcode;
      check_range "PC before" 0xffff step.pc_before;
      check_range "PC after" 0xffff step.pc_after;
      if String.length step.instruction_bytes = 0 then
        invalid_arg "Trace.Writer: empty instruction bytes";
      let first_byte = Char.code step.instruction_bytes.[0] in
      if first_byte <> step.opcode then
        invalid_arg "Trace.Writer: opcode differs from first instruction byte";
      writer.output
        (Printf.sprintf "STEP\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n" step.step_index
           (hex 4 step.pc_before) (hex 4 step.pc_after) (hex 2 step.opcode)
           (bytes_hex step.instruction_bytes) (status step.encoding_status)
           (control_flow step.control_flow));
      List.iter (emit_memory writer.output step.step_index) step.memory_accesses;
      writer.next_step_index <- writer.next_step_index + 1
  | Event.Bdos_call { step_index; function_number; de } ->
      if step_index <> writer.next_step_index then
        invalid_arg "Trace.Writer: BDOS index does not match executed steps";
      check_range "BDOS function number" 0xff function_number;
      writer.output
        (Printf.sprintf "BDOS\t%d\t%d\t%s\n" step_index function_number (hex 4 de))
  | Event.Termination { step_index; reason = Event.Bdos_function number } ->
      if step_index <> writer.next_step_index then
        invalid_arg "Trace.Writer: termination index does not match executed steps";
      check_range "termination function number" 0xff number;
      writer.output (Printf.sprintf "TERM\t%d\tbdos:%d\n" step_index number)
