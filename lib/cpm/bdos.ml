type action = Continue | Terminate

type error =
  | Unsupported_function of int
  | Unterminated_string of { start_address : int; scanned : int }
  | Filesystem_model_limit of Filesystem.error

type event =
  | Read_record of {
      file : Filesystem.key;
      logical_record : int;
      dma : int;
      data : bytes;
    }
  | Write_record of {
      file : Filesystem.key;
      logical_record : int;
      dma : int;
      data : bytes;
    }

type t = {
  filesystem : Filesystem.t;
  mutable dma : int;
  current_drive : int;
  current_user : int;
}

let create ~filesystem =
  { filesystem; dma = 0x0080; current_drive = 0; current_user = 0 }

let filesystem runtime = runtime.filesystem
let dma runtime = runtime.dma
let current_drive runtime = runtime.current_drive
let current_user runtime = runtime.current_user

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

let set_a state value = I8080.State.set_a state value

let set_result state value =
  set_a state value;
  I8080.State.set_b state 0;
  Ok Continue

let set_fcb_position memory ~fcb_address ~record_count record =
  let fcb = Fcb.at memory ~address:fcb_address in
  let extent, current =
    if record >= Filesystem.maximum_records then
      (Filesystem.maximum_records / 128) - 1, 128
    else record / 128, record mod 128
  in
  Fcb.set_extent fcb extent;
  Fcb.set_current_record fcb current;
  let extent_start = extent * 128 in
  Fcb.set_record_count fcb (max 0 (min 128 (record_count - extent_start)))

let set_fcb_read_position memory ~fcb_address ~record_count ~extent ~current_record =
  let fcb = Fcb.at memory ~address:fcb_address in
  let next_extent, next_record =
    match current_record with
    | 127 -> extent, 128
    | 128 -> extent + 1, 1
    | record -> extent, record + 1
  in
  Fcb.set_extent fcb next_extent;
  Fcb.set_current_record fcb next_record;
  let extent_start = next_extent * 128 in
  Fcb.set_record_count fcb
    (max 0 (min 128 (record_count - extent_start)))

let position_of_fcb memory ~fcb_address =
  let fcb = Fcb.at memory ~address:fcb_address in
  (Fcb.extent fcb * 128) + Fcb.current_record fcb

let resolve_fcb runtime memory fcb_address =
  Filesystem.key_of_fcb ~memory ~fcb_address
    ~current_drive:runtime.current_drive ~current_user:runtime.current_user

let read_byte memory address = I8080.Memory.read memory (address land 0xffff)
let write_byte memory address value = I8080.Memory.write memory (address land 0xffff) value

let transfer_record_to_memory memory ~dma record =
  for index = 0 to 127 do
    write_byte memory (dma + index) (Char.code (Bytes.get record index))
  done

let transfer_record_from_memory memory ~dma =
  Bytes.init 128 (fun index -> Char.chr (read_byte memory (dma + index)))

let bdos_function_limit = 40

let dispatch_inner ~runtime ~memory ~state ~output ~on_event =
  let function_number = I8080.State.c state in
  match function_number with
  | 0 -> Ok Terminate
  | 2 ->
      output (Char.chr (I8080.State.e state));
      Ok Continue
  | 9 -> print_string memory ~start_address:(I8080.State.de state) output
  | 11 -> set_result state 0
  | 12 ->
      I8080.State.set_a state 0x22;
      I8080.State.set_b state 0;
      I8080.State.set_hl state 0x0022;
      Ok Continue
  | 15 ->
      (match resolve_fcb runtime memory (I8080.State.de state) with
      | Error _ -> set_result state 0xff
      | Ok key ->
          (match Filesystem.record_count runtime.filesystem key with
          | None -> set_result state 0xff
          | Some records ->
              let fcb = Fcb.at memory ~address:(I8080.State.de state) in
              Fcb.set_s1 fcb 0;
              (* CP/M 2 clears the caller's module field for OPEN, then marks
                 a successful opened FCB with the file-write flag. *)
              Fcb.set_s2 fcb 0;
              Fcb.set_allocation fcb (Bytes.make 16 '\000');
              let extent_start = Fcb.extent fcb * 128 in
              Fcb.set_record_count fcb (max 0 (min 128 (records - extent_start)));
              Fcb.set_file_write_flag fcb true;
              set_result state 0))
  | 16 ->
      (match resolve_fcb runtime memory (I8080.State.de state) with
      | Error _ -> set_result state 0xff
      | Ok key ->
          if Filesystem.record_count runtime.filesystem key = None then set_result state 0xff
          else set_result state 0)
  | 19 ->
      (match resolve_fcb runtime memory (I8080.State.de state) with
      | Error _ -> set_result state 0xff
      | Ok key ->
          let found = Filesystem.record_count runtime.filesystem key <> None in
          if found then ignore (Filesystem.delete runtime.filesystem key);
          set_result state (if found then 0 else 0xff))
  | 20 ->
      (match resolve_fcb runtime memory (I8080.State.de state) with
      | Error _ -> set_result state 1
      | Ok key ->
          let fcb_address = I8080.State.de state in
          let fcb = Fcb.at memory ~address:fcb_address in
          let extent = Fcb.extent fcb in
          let current_record = Fcb.current_record fcb in
          let record_number = position_of_fcb memory ~fcb_address in
          (match Filesystem.record_count runtime.filesystem key with
          | None -> set_result state 1
          | Some records when current_record > 128 || record_number >= records ->
              (* EOF leaves the caller-visible cursor and extent untouched. *)
              set_result state 1
          | Some records ->
              (match Filesystem.read_record runtime.filesystem key ~record:record_number with
              | Error error -> Error (Filesystem_model_limit error)
              | Ok None -> set_result state 1
              | Ok (Some record) ->
                  transfer_record_to_memory memory ~dma:runtime.dma record;
                  set_fcb_read_position memory ~fcb_address ~record_count:records
                    ~extent ~current_record;
                  on_event
                    (Read_record
                       { file = key; logical_record = record_number; dma = runtime.dma;
                         data = Bytes.copy record });
                  set_result state 0)))
  | 21 ->
      (match resolve_fcb runtime memory (I8080.State.de state) with
      | Error _ -> set_result state 1
      | Ok key ->
          (match Filesystem.record_count runtime.filesystem key with
          | None -> set_result state 1
          | Some _ ->
              let record_number = position_of_fcb memory ~fcb_address:(I8080.State.de state) in
              if record_number >= Filesystem.maximum_records then
                Error (Filesystem_model_limit (Filesystem.Record_out_of_range record_number))
              else
                let record = transfer_record_from_memory memory ~dma:runtime.dma in
                (match Filesystem.write_record runtime.filesystem key ~record:record_number record with
                | Error error -> Error (Filesystem_model_limit error)
                | Ok () ->
                    let records = Option.value (Filesystem.record_count runtime.filesystem key) ~default:0 in
                    set_fcb_position memory ~fcb_address:(I8080.State.de state) ~record_count:records
                      (record_number + 1);
                    let fcb = Fcb.at memory ~address:(I8080.State.de state) in
                    (* A write dirties the active FCB (clearing FWF).  At a
                       sequential extent boundary CP/M opens/makes the next
                       extent before returning, which sets FWF on that FCB. *)
                    Fcb.set_file_write_flag fcb (record_number mod 128 = 127);
                    on_event
                      (Write_record
                         { file = key; logical_record = record_number; dma = runtime.dma;
                           data = Bytes.copy record });
                    set_result state 0)))
  | 22 ->
      (match resolve_fcb runtime memory (I8080.State.de state) with
      | Error _ -> set_result state 0xff
      | Ok key ->
          Filesystem.make runtime.filesystem key;
          let fcb = Fcb.at memory ~address:(I8080.State.de state) in
          Fcb.set_s1 fcb 0;
          Fcb.set_s2 fcb 0;
          Fcb.set_extent fcb 0;
          Fcb.set_current_record fcb 0;
          Fcb.set_record_count fcb 0;
          Fcb.set_allocation fcb (Bytes.make 16 '\000');
          Fcb.set_file_write_flag fcb true;
          set_result state 0)
  | 26 ->
      runtime.dma <- I8080.State.de state;
      set_result state 0
  | number when number > bdos_function_limit ->
      I8080.State.set_a state 0;
      I8080.State.set_b state 0;
      I8080.State.set_hl state 0;
      Ok Continue
  | number -> Error (Unsupported_function number)

let dispatch_instrumented ~on_event ~runtime ~memory ~state ~output =
  match dispatch_inner ~runtime ~memory ~state ~output ~on_event with
  | Ok Continue ->
      (* CP/M's compatibility convention aliases the byte return in A to L
         and the high byte in B to H, including calls without a modeled
         service-specific return value. *)
      I8080.State.set_l state (I8080.State.a state);
      I8080.State.set_h state (I8080.State.b state);
      Ok Continue
  | Ok Terminate -> Ok Terminate
  | Error error -> Error error

let dispatch ~runtime ~memory ~state ~output =
  dispatch_instrumented ~on_event:(fun _ -> ()) ~runtime ~memory ~state ~output
