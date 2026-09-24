type action = Continue | Terminate

type error =
  | Unsupported_function of int
  | Unterminated_string of { start_address : int; scanned : int }

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
  Ok Continue

let set_fcb_position memory ~fcb_address ~record_count record =
  let fcb = Fcb.at memory ~address:fcb_address in
  let extent = record / 128 in
  let current = record mod 128 in
  Fcb.set_extent fcb extent;
  Fcb.set_current_record fcb current;
  let extent_start = extent * 128 in
  Fcb.set_record_count fcb (max 0 (min 128 (record_count - extent_start)))

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

let dispatch ~runtime ~memory ~state ~output =
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
              Fcb.set_extent fcb 0;
              Fcb.set_current_record fcb 0;
              Fcb.set_allocation fcb (Bytes.make 16 '\000');
              Fcb.set_record_count fcb (min 128 records);
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
          let record_number = position_of_fcb memory ~fcb_address:(I8080.State.de state) in
          (match Filesystem.read_record runtime.filesystem key ~record:record_number with
          | None -> set_result state 1
          | Some record ->
              transfer_record_to_memory memory ~dma:runtime.dma record;
              set_fcb_position memory ~fcb_address:(I8080.State.de state)
                ~record_count:(Option.value (Filesystem.record_count runtime.filesystem key) ~default:0)
                (record_number + 1);
              set_result state 0))
  | 21 ->
      (match resolve_fcb runtime memory (I8080.State.de state) with
      | Error _ -> set_result state 1
      | Ok key ->
          (match Filesystem.record_count runtime.filesystem key with
          | None -> set_result state 1
          | Some _ ->
              let record_number = position_of_fcb memory ~fcb_address:(I8080.State.de state) in
              let record = transfer_record_from_memory memory ~dma:runtime.dma in
              Filesystem.write_record runtime.filesystem key ~record:record_number record;
              let records = Option.value (Filesystem.record_count runtime.filesystem key) ~default:0 in
              set_fcb_position memory ~fcb_address:(I8080.State.de state) ~record_count:records
                (record_number + 1);
              set_result state 0))
  | 22 ->
      (match resolve_fcb runtime memory (I8080.State.de state) with
      | Error _ -> set_result state 0xff
      | Ok key ->
          Filesystem.make runtime.filesystem key;
          let fcb = Fcb.at memory ~address:(I8080.State.de state) in
          Fcb.set_s1 fcb 0;
          Fcb.set_extent fcb 0;
          Fcb.set_current_record fcb 0;
          Fcb.set_record_count fcb 0;
          Fcb.set_allocation fcb (Bytes.make 16 '\000');
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
