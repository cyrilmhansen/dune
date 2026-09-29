type t = Cpm22

let cpm22 = Cpm22

type process = { bdos : Bdos.t }

let warm_boot_address Cpm22 = 0x0000
let bdos_entry_address Cpm22 = 0x0005
let transient_stack_word_address Cpm22 = 0x0006
let initial_stack_pointer Cpm22 = 0xfffe
let maximum_command_tail_length Cpm22 = 127
let dma Cpm22 process = Bdos.dma process.bdos

let load_bytes Cpm22 = Loader.load_bytes
let load_file Cpm22 = Loader.load_file
let entry_point Cpm22 loaded = loaded.Loader.entry_point

let command_operands tail =
  Bytes.to_string tail
  |> String.split_on_char ' '
  |> List.concat_map (String.split_on_char '\t')
  |> List.filter (fun token -> token <> "")

let write_default_fcb memory ~address token =
  let write offset value = I8080.Memory.write memory (address + offset) value in
  for offset = 1 to 11 do write offset 0x20 done;
  write 0 0;
  for offset = 12 to 35 do write offset 0 done;
  match token with
  | None -> ()
  | Some token ->
      let token = String.uppercase_ascii token in
      let token =
        match String.index_opt token ':' with
        | Some colon when colon = 1 ->
            let drive = Char.code token.[0] - Char.code 'A' + 1 in
            if drive >= 1 && drive <= 16 then write 0 drive;
            String.sub token 2 (String.length token - 2)
        | _ -> token
      in
      let base, extension =
        match String.index_opt token '.' with
        | None -> token, ""
        | Some dot ->
            String.sub token 0 dot,
            String.sub token (dot + 1) (String.length token - dot - 1)
      in
      String.iteri
        (fun index char -> if index < 8 then write (index + 1) (Char.code char))
        base;
      String.iteri
        (fun index char -> if index < 3 then write (index + 9) (Char.code char))
        extension

let install_page_zero Cpm22 memory command_tail =
  let bdos_entry = bdos_entry_address Cpm22 in
  let stack_word = transient_stack_word_address Cpm22 in
  let stack_pointer = initial_stack_pointer Cpm22 in
  (* 0005h is the synthetic RET userspace trap. 0006h is the stable
     compatibility word used by existing exercisers. *)
  I8080.Memory.write memory bdos_entry 0xc9;
  I8080.Memory.write memory stack_word (stack_pointer land 0xff);
  I8080.Memory.write memory (stack_word + 1) ((stack_pointer lsr 8) land 0xff);
  for address = 0x005c to 0x008f do I8080.Memory.write memory address 0 done;
  for address = 0x0080 to 0x00ff do I8080.Memory.write memory address 0 done;
  let operands = command_operands command_tail in
  (* FCB2's 16-byte prefix overlaps FCB1's allocation area. *)
  write_default_fcb memory ~address:0x005c (List.nth_opt operands 0);
  write_default_fcb memory ~address:0x006c (List.nth_opt operands 1);
  I8080.Memory.write memory 0x0080 (Bytes.length command_tail);
  Bytes.iteri
    (fun index byte -> I8080.Memory.write memory (0x0081 + index) (Char.code byte))
    command_tail

let launch Cpm22 ~filesystem ~command_tail memory =
  install_page_zero Cpm22 memory command_tail;
  { bdos = Bdos.create ~filesystem }

let dispatch_with_effects Cpm22 process =
  Bdos.dispatch_with_effects ~runtime:process.bdos

let dispatch_with_file_events Cpm22 process =
  Bdos.dispatch_with_effects_and_file_events ~runtime:process.bdos
