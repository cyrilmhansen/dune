let usage =
  "Usage: pli80-run [--trace FILE] [--max-steps N] PROGRAM.COM\n       pli80-run --help\n\nN must be a positive decimal instruction count. Options may appear in either order."

type cli_options = { trace_path : string option; max_steps : int option; program : string }

let positive_decimal text =
  let decimal =
    String.length text > 0
    && String.for_all (fun char -> char >= '0' && char <= '9') text
  in
  if not decimal then None
  else
    match int_of_string_opt text with
    | Some number when number > 0 -> Some number
    | Some _ | None -> None

let parse_arguments arguments =
  let rec parse trace_path max_steps program = function
    | [] ->
        (match program with
        | None -> Error "missing PROGRAM.COM"
        | Some program -> Ok { trace_path; max_steps; program })
    | "--trace" :: [] -> Error "missing value after --trace"
    | "--trace" :: value :: _rest when String.starts_with ~prefix:"--" value ->
        Error "missing value after --trace"
    | "--trace" :: value :: rest ->
        (match trace_path with
        | Some _ -> Error "--trace specified more than once"
        | None -> parse (Some value) max_steps program rest)
    | "--max-steps" :: [] -> Error "missing value after --max-steps"
    | "--max-steps" :: value :: _rest when String.starts_with ~prefix:"--" value ->
        Error "missing value after --max-steps"
    | "--max-steps" :: value :: rest ->
        (match (max_steps, positive_decimal value) with
        | Some _, _ -> Error "--max-steps specified more than once"
        | None, None -> Error "--max-steps requires a positive decimal integer"
        | None, Some value -> parse trace_path (Some value) program rest)
    | option :: _ when String.starts_with ~prefix:"--" option ->
        Error (Printf.sprintf "unknown option %s" option)
    | path :: rest ->
        (match program with
        | Some _ -> Error "more than one PROGRAM.COM was provided"
        | None -> parse trace_path max_steps (Some path) rest)
  in
  parse None None None arguments

let string_of_loader_error = function
  | Cpm.Loader.Program_too_large { size; maximum } ->
      Printf.sprintf "COM program is too large (%d bytes; maximum %d)" size maximum
  | Cpm.Loader.File_error { path; message } ->
      Printf.sprintf "cannot read %s: %s" path message

let string_of_cpu_error = function
  | I8080.Cpu.Unsupported_instruction decoded ->
      Printf.sprintf "unsupported instruction opcode 0x%02X" decoded.I8080.Decode.opcode
  | I8080.Cpu.Decode_error (I8080.Decode.Invalid_offset offset) ->
      Printf.sprintf "instruction decode received invalid buffer offset %d" offset
  | I8080.Cpu.Decode_error
      (I8080.Decode.Truncated { opcode; required; available }) ->
      Printf.sprintf
        "truncated opcode 0x%02X (need %d bytes, have %d)"
        opcode required available
  | I8080.Cpu.Bus_io_error (I8080.Bus.Input_port_not_configured port) ->
      Printf.sprintf "input port 0x%02X is not configured" port
  | I8080.Cpu.Bus_io_error (I8080.Bus.Output_port_not_configured port) ->
      Printf.sprintf "output port 0x%02X is not configured" port
  | I8080.Cpu.Interrupt_acknowledge_length { opcode; required; provided } ->
      let opcode =
        match opcode with None -> "empty payload" | Some byte -> Printf.sprintf "opcode 0x%02X" byte
      in
      let required = match required with None -> "an opcode" | Some n -> Printf.sprintf "%d bytes" n in
      Printf.sprintf "interrupt acknowledge %s requires %s, got %d bytes" opcode required provided
  | I8080.Cpu.Cpu_halted -> "CPU is halted"

let string_of_bdos_error = function
  | Cpm.Bdos.Unsupported_function number ->
      Printf.sprintf "unsupported BDOS function %d" number
  | Cpm.Bdos.Unterminated_string { start_address; scanned } ->
      Printf.sprintf "BDOS function 9 found no '$' after %d bytes from 0x%04X" scanned
        start_address

let string_of_runner_error = function
  | Runner.Load_error error -> string_of_loader_error error
  | Runner.Cpu_error error -> string_of_cpu_error error
  | Runner.Bdos_error error -> string_of_bdos_error error
  | Runner.Step_limit_exceeded { max_steps; steps } ->
      Printf.sprintf "instruction limit exceeded after %d steps (limit %d)" steps max_steps
  | Runner.Invalid_step_limit limit ->
      Printf.sprintf "invalid instruction limit %d (must be positive)" limit
  | Runner.Invalid_command_tail length ->
      Printf.sprintf "invalid CP/M command tail length %d (maximum 127)" length

let run ?trace_path ?max_steps path =
  let output = Buffer.create 32 in
  let execute on_event =
    match
      Runner.run_file ?max_steps ~on_event ~output:(Buffer.add_char output) ~path ()
    with
    | Ok _ ->
        output_string stdout (Buffer.contents output);
        flush stdout
    | Error error ->
        prerr_endline ("pli80-run: " ^ string_of_runner_error error);
        exit 1
  in
  match trace_path with
  | None -> execute (fun _ -> ())
  | Some trace_path ->
      (try
         let channel = open_out_bin trace_path in
         Fun.protect
           ~finally:(fun () -> close_out channel)
           (fun () ->
             let writer =
               Trace.Writer.create ~output:(output_string channel)
             in
             let step_index = ref 0 in
             execute (fun event ->
                 let persistent =
                   Trace.Event.of_runner_event ~step_index:!step_index event
                 in
                 Trace.Writer.write writer persistent;
                 (match event with
                 | Runner.Step _ -> incr step_index
                 | Runner.Bdos_call _ | Runner.Termination _ -> ())))
      with Sys_error message ->
        prerr_endline ("pli80-run: cannot write trace: " ^ message);
        exit 1
      | Invalid_argument message ->
          prerr_endline ("pli80-run: trace error: " ^ message);
          exit 1)

let () =
  match Array.to_list Sys.argv with
  | [ _; "--help" ] -> print_endline usage
  | _ :: arguments ->
      (match parse_arguments arguments with
      | Error message ->
          prerr_endline ("pli80-run: " ^ message);
          prerr_endline usage;
          exit 2
      | Ok { trace_path; max_steps; program } ->
          run ?trace_path ?max_steps program)
  | [] -> assert false
