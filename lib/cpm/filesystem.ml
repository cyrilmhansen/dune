type key = { drive : int; user : int; name : string }
type error = Invalid_name of string | Invalid_drive of int | Invalid_user of int

type file = { mutable data : bytes; mutable logical_size : int }
type t = (string, file) Hashtbl.t

let record_size = 128
let create () = Hashtbl.create 31

let check_drive drive = if drive < 0 || drive > 15 then Error (Invalid_drive drive) else Ok ()
let check_user user = if user < 0 || user > 31 then Error (Invalid_user user) else Ok ()

let valid_name_char char =
  let code = Char.code char in
  code >= 0x21 && code <= 0x7e && char <> ':' && char <> '.' && char <> '*' && char <> '?'

let canonical_name name =
  let base, extension =
    match String.index_opt name '.' with
    | None -> name, ""
    | Some dot ->
        if String.index_from_opt name (dot + 1) '.' <> None then "", "!invalid!"
        else String.sub name 0 dot, String.sub name (dot + 1) (String.length name - dot - 1)
  in
  if base = "" || String.length base > 8 || String.length extension > 3
     || not (String.for_all valid_name_char base)
     || not (String.for_all valid_name_char extension)
  then Error (Invalid_name name)
  else Ok (String.uppercase_ascii base ^ if extension = "" then "" else "." ^ String.uppercase_ascii extension)

let key_string key = Printf.sprintf "%02X:%02X:%s" key.drive key.user key.name

let key_of_name ~drive ~user ~name =
  match check_drive drive, check_user user, canonical_name name with
  | Error error, _, _ | _, Error error, _ | _, _, Error error -> Error error
  | Ok (), Ok (), Ok name -> Ok { drive; user; name }

let key_of_fcb ~memory ~fcb_address ~current_drive ~current_user =
  let fcb = Fcb.at memory ~address:fcb_address in
  let drive_byte = Fcb.drive fcb in
  let drive = if drive_byte = 0 then current_drive else drive_byte - 1 in
  let base = Fcb.filename fcb in
  let extension = String.map (fun c -> Char.chr (Char.code c land 0x7f)) (Fcb.extension fcb) in
  let trim_right_spaces text = String.trim (String.map (fun c -> if c = '\000' then ' ' else c) text) in
  let base = trim_right_spaces base and extension = trim_right_spaces extension in
  let name = if extension = "" then base else base ^ "." ^ extension in
  key_of_name ~drive ~user:current_user ~name

let add_file filesystem ?(drive = 0) ?(user = 0) ~name bytes =
  match key_of_name ~drive ~user ~name with
  | Error error -> Error error
  | Ok key ->
      let size = Bytes.length bytes in
      let records = (size + record_size - 1) / record_size in
      let data = Bytes.make (records * record_size) '\000' in
      Bytes.blit bytes 0 data 0 size;
      Hashtbl.replace filesystem (key_string key) { data; logical_size = size };
      Ok ()

let lookup filesystem ~drive ~user ~name =
  match key_of_name ~drive ~user ~name with
  | Error error -> Error error
  | Ok key -> Ok (Hashtbl.find_opt filesystem (key_string key))

let get_file filesystem ?(drive = 0) ?(user = 0) ~name () =
  match lookup filesystem ~drive ~user ~name with
  | Error error -> Error error
  | Ok None -> Ok None
  | Ok (Some file) -> Ok (Some (Bytes.sub file.data 0 file.logical_size))

let list_files filesystem ?(drive = 0) ?(user = 0) () =
  Hashtbl.fold
    (fun encoded _ names ->
      match String.split_on_char ':' encoded with
      | [ drive_text; user_text; name ]
        when int_of_string ("0x" ^ drive_text) = drive
             && int_of_string ("0x" ^ user_text) = user -> name :: names
      | _ -> names)
    filesystem []
  |> List.sort String.compare

let delete filesystem key =
  let key = key_string key in
  let existed = Hashtbl.mem filesystem key in
  Hashtbl.remove filesystem key;
  existed

let make filesystem key =
  Hashtbl.replace filesystem (key_string key) { data = Bytes.empty; logical_size = 0 }

let record_count filesystem key =
  Option.map (fun file -> (file.logical_size + record_size - 1) / record_size)
    (Hashtbl.find_opt filesystem (key_string key))

let read_record filesystem key ~record =
  if record < 0 then None
  else
    match Hashtbl.find_opt filesystem (key_string key) with
    | None -> None
    | Some file when record * record_size >= file.logical_size -> None
    | Some file -> Some (Bytes.sub file.data (record * record_size) record_size)

let write_record filesystem key ~record bytes =
  if record < 0 then invalid_arg "Filesystem.write_record: negative record";
  if Bytes.length bytes <> record_size then
    invalid_arg "Filesystem.write_record: record must be 128 bytes";
  let file =
    match Hashtbl.find_opt filesystem (key_string key) with
    | Some file -> file
    | None -> let file = { data = Bytes.empty; logical_size = 0 } in
              Hashtbl.add filesystem (key_string key) file;
              file
  in
  let end_offset = (record + 1) * record_size in
  if Bytes.length file.data < end_offset then (
    let expanded = Bytes.make end_offset '\000' in
    Bytes.blit file.data 0 expanded 0 (Bytes.length file.data);
    file.data <- expanded);
  Bytes.blit bytes 0 file.data (record * record_size) record_size;
  file.logical_size <- max file.logical_size end_offset
