let usage =
  "Usage: pli80-run [--trace FILE] PROGRAM.COM\n       pli80-run --help"

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

let run ?trace_path path =
  let output = Buffer.create 32 in
  let execute on_event =
    match Runner.run_file ~on_event ~output:(Buffer.add_char output) ~path () with
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
         exit 1)

let () =
  match Array.to_list Sys.argv with
  | [ _; "--help" ] -> print_endline usage
  | [ _; path ] -> run path
  | [ _; "--trace"; trace_path; path ] -> run ~trace_path path
  | _ ->
      prerr_endline usage;
      exit 2
