let load_address = 0x0100

let maximum_size = I8080.Memory.size - load_address

type loaded = { entry_point : int; size : int }

type error =
  | Program_too_large of { size : int; maximum : int }
  | File_error of { path : string; message : string }

let load_bytes memory bytes =
  let size = Bytes.length bytes in
  if size > maximum_size then Error (Program_too_large { size; maximum = maximum_size })
  else (
    I8080.Memory.load memory ~address:load_address bytes;
    Ok { entry_point = load_address; size })

let load_file memory ~path =
  try
    let channel = open_in_bin path in
    let contents =
      Fun.protect
        ~finally:(fun () -> close_in_noerr channel)
        (fun () ->
          let size = in_channel_length channel in
          if size > maximum_size then
            Error (Program_too_large { size; maximum = maximum_size })
          else
            let bytes = Bytes.create size in
            really_input channel bytes 0 size;
            Ok bytes)
    in
    match contents with
    | Error error -> Error error
    | Ok bytes -> load_bytes memory bytes
  with
  | Sys_error message -> Error (File_error { path; message })
  | End_of_file ->
      Error (File_error { path; message = "unexpected end of file while reading" })
