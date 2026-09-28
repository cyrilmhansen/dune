type instruction = { address : int; bytes : bytes; mnemonic : string }

type t = {
  id : string;
  question : string option;
  toolchain : (string * string) list;
  toolchain_version : string;
  source : string;
  code_size : int;
  variable_size : int;
  maximum_stack : int;
  code_start : string;
  code_end_inclusive : string;
  data_range : string option;
  code_bytes : bytes;
  disassembly : instruction list;
  documented_expectation : string option;
  observations : string list;
  comparison : (string * string) list;
  unresolved_questions : string list;
}

exception Invalid_manifest of string

let fail message = raise (Invalid_manifest message)
let whitespace = function ' ' | '\n' | '\r' | '\t' -> true | _ -> false

let skip_space text index =
  let rec loop i = if i < String.length text && whitespace text.[i] then loop (i + 1) else i in
  loop index

let hex_digit = function
  | '0' .. '9' as c -> Char.code c - Char.code '0'
  | 'a' .. 'f' as c -> Char.code c - Char.code 'a' + 10
  | 'A' .. 'F' as c -> Char.code c - Char.code 'A' + 10
  | _ -> fail "invalid hex escape in manifest JSON"

let add_utf8 buffer codepoint =
  if codepoint <= 0x7f then Buffer.add_char buffer (Char.chr codepoint)
  else if codepoint <= 0x7ff then (
    Buffer.add_char buffer (Char.chr (0xc0 lor (codepoint lsr 6)));
    Buffer.add_char buffer (Char.chr (0x80 lor (codepoint land 0x3f))) )
  else if codepoint <= 0xffff then (
    Buffer.add_char buffer (Char.chr (0xe0 lor (codepoint lsr 12)));
    Buffer.add_char buffer (Char.chr (0x80 lor ((codepoint lsr 6) land 0x3f)));
    Buffer.add_char buffer (Char.chr (0x80 lor (codepoint land 0x3f))) )
  else (
    Buffer.add_char buffer (Char.chr (0xf0 lor (codepoint lsr 18)));
    Buffer.add_char buffer (Char.chr (0x80 lor ((codepoint lsr 12) land 0x3f)));
    Buffer.add_char buffer (Char.chr (0x80 lor ((codepoint lsr 6) land 0x3f)));
    Buffer.add_char buffer (Char.chr (0x80 lor (codepoint land 0x3f))) )

let json_string text start =
  let length = String.length text in
  if start >= length || text.[start] <> '"' then fail "expected JSON string";
  let buffer = Buffer.create 64 in
  let rec loop i =
    if i >= length then fail "unterminated JSON string";
    match text.[i] with
    | '"' -> (Buffer.contents buffer, i + 1)
    | '\\' ->
        if i + 1 >= length then fail "truncated JSON escape";
        (match text.[i + 1] with
        | '"' -> Buffer.add_char buffer '"'; loop (i + 2)
        | '\\' -> Buffer.add_char buffer '\\'; loop (i + 2)
        | '/' -> Buffer.add_char buffer '/'; loop (i + 2)
        | 'b' -> Buffer.add_char buffer '\b'; loop (i + 2)
        | 'f' -> Buffer.add_char buffer '\012'; loop (i + 2)
        | 'n' -> Buffer.add_char buffer '\n'; loop (i + 2)
        | 'r' -> Buffer.add_char buffer '\r'; loop (i + 2)
        | 't' -> Buffer.add_char buffer '\t'; loop (i + 2)
        | 'u' ->
            if i + 6 > length then fail "truncated JSON unicode escape";
            let code = ref 0 in
            for j = i + 2 to i + 5 do code := (!code lsl 4) lor hex_digit text.[j] done;
            add_utf8 buffer !code;
            loop (i + 6)
        | _ -> fail "invalid JSON escape")
    | c -> Buffer.add_char buffer c; loop (i + 1)
  in
  loop (start + 1)

let value_end text start =
  let length = String.length text in
  if start >= length then fail "missing JSON value";
  match text.[start] with
  | '"' -> snd (json_string text start)
  | '{' | '[' as opening ->
      let stack = ref [ if opening = '{' then '}' else ']' ] in
      let in_string = ref false and escaped = ref false and i = ref (start + 1) in
      while !i < length && !stack <> [] do
        let c = text.[!i] in
        if !in_string then (
          if !escaped then escaped := false
          else if c = '\\' then escaped := true
          else if c = '"' then in_string := false )
        else (
          match c with
          | '"' -> in_string := true
          | '{' -> stack := '}' :: !stack
          | '[' -> stack := ']' :: !stack
          | '}' | ']' ->
              (match !stack with
              | close :: rest when close = c -> stack := rest
              | _ -> fail "mismatched JSON container")
          | _ -> ());
        incr i
      done;
      if !stack <> [] || !in_string then fail "unterminated JSON container";
      !i
  | _ ->
      let i = ref start in
      while !i < length && not (whitespace text.[!i] || List.mem text.[!i] [ ','; '}'; ']' ]) do incr i done;
      if !i = start then fail "empty JSON value";
      !i

let object_members raw =
  let length = String.length raw in
  let start = skip_space raw 0 in
  if start >= length || raw.[start] <> '{' then fail "expected JSON object";
  let rec loop index acc =
    let index = skip_space raw index in
    if index >= length then fail "unterminated JSON object";
    if raw.[index] = '}' then List.rev acc
    else
      let key, after_key = json_string raw index in
      let colon = skip_space raw after_key in
      if colon >= length || raw.[colon] <> ':' then fail "expected colon in JSON object";
      let value_start = skip_space raw (colon + 1) in
      let value_stop = value_end raw value_start in
      let value = String.sub raw value_start (value_stop - value_start) in
      let next = skip_space raw value_stop in
      if next >= length then fail "unterminated JSON object";
      match raw.[next] with
      | ',' -> loop (next + 1) ((key, value) :: acc)
      | '}' -> List.rev ((key, value) :: acc)
      | _ -> fail "expected comma or close brace in JSON object"
  in
  loop (start + 1) []

let object_member raw key = List.assoc_opt key (object_members raw)

let string_value raw =
  let start = skip_space raw 0 in
  let value, stop = json_string raw start in
  if skip_space raw stop <> String.length raw then fail "trailing data after JSON string";
  value

let int_value raw =
  let value = String.trim raw in
  match int_of_string_opt value with Some n -> n | None -> fail ("expected integer, got " ^ value)

let required_member object_raw key =
  match object_member object_raw key with Some value -> value | None -> fail ("missing manifest field " ^ key)

let required_string object_raw key = string_value (required_member object_raw key)
let optional_string object_raw key = Option.map string_value (object_member object_raw key)
let first_string object_raw keys =
  let rec loop = function [] -> None | key :: rest -> (match optional_string object_raw key with Some _ as x -> x | None -> loop rest) in
  loop keys

let optional_nested root path =
  let rec loop object_raw = function
    | [] -> Some object_raw
    | key :: rest -> (match object_member object_raw key with None -> None | Some next -> loop next rest)
  in
  loop root path

let optional_nested_string root path key = Option.bind (optional_nested root path) (fun obj -> optional_string obj key)

let array_strings raw =
  let length = String.length raw in
  let start = skip_space raw 0 in
  if start >= length || raw.[start] <> '[' then fail "expected JSON string array";
  let rec loop index acc =
    let index = skip_space raw index in
    if index >= length then fail "unterminated JSON array";
    if raw.[index] = ']' then List.rev acc
    else
      let value, stop = json_string raw index in
      let next = skip_space raw stop in
      if next >= length then fail "unterminated JSON array";
      match raw.[next] with
      | ',' -> loop (next + 1) (value :: acc)
      | ']' -> List.rev (value :: acc)
      | _ -> fail "expected comma or close bracket in JSON array"
  in
  loop (start + 1) []

let hex_bytes text =
  let digits = String.to_seq text |> Seq.filter (fun c -> not (whitespace c)) |> String.of_seq in
  if String.length digits mod 2 <> 0 then fail "odd number of digits in code hex";
  let bytes = Bytes.create (String.length digits / 2) in
  for i = 0 to Bytes.length bytes - 1 do
    let value = (hex_digit digits.[2 * i] lsl 4) lor hex_digit digits.[(2 * i) + 1] in
    Bytes.set bytes i (Char.chr value)
  done;
  bytes

let parse_address text =
  let text = String.trim text in
  let text = if String.starts_with ~prefix:"0x" text || String.starts_with ~prefix:"0X" text then String.sub text 2 (String.length text - 2) else text in
  try int_of_string ("0x" ^ text) with Failure _ -> fail ("invalid located address " ^ text)

let format_bytes bytes =
  let result = Buffer.create (Bytes.length bytes * 3) in
  Bytes.iteri
    (fun i value ->
      if i > 0 then Buffer.add_char result ' ';
      Buffer.add_string result (Printf.sprintf "%02X" (Char.code value)))
    bytes;
  Buffer.contents result

let disassemble code start =
  let rec loop offset acc =
    if offset = Bytes.length code then List.rev acc
    else
      match I8080.Decode.decode code ~offset with
      | Error _ -> fail (Printf.sprintf "truncated 8080 instruction at code offset %d" offset)
      | Ok (decoded : I8080.Decode.decoded) ->
          let length = decoded.I8080.Decode.length in
          let instr = decoded.I8080.Decode.instr in
          let bytes = Bytes.sub code offset length in
          let address = (start + offset) land 0xffff in
          let instruction = { address; bytes; mnemonic = I8080.Instr_format.format instr } in
          loop (offset + length) (instruction :: acc)
  in
  loop 0 []

let source_from_manifest root directory =
  match optional_nested_string root [ "input" ] "source" with
  | Some source -> source
  | None ->
      let input_basename =
        match optional_nested root [ "input" ] with
        | Some input -> first_string input [ "basename"; "guest_basename" ]
        | None -> None
      in
      let hashed_source_basename =
        match object_member root "input_hashes" with
        | None -> None
        | Some hashes ->
            object_members hashes
            |> List.find_map (fun (name, _) ->
                   if Filename.check_suffix (String.uppercase_ascii name) ".PLM" then Some (Filename.remove_extension name) else None)
      in
      let basename =
        match first_string root [ "guest_basename" ] with
        | Some name -> name
        | None -> (match input_basename, hashed_source_basename with
            | Some name, _ -> name
            | None, Some name -> name
            | None, None -> fail "manifest has no source basename")
      in
      let files = Sys.readdir directory |> Array.to_list |> List.sort String.compare in
      let source_file =
        match List.find_opt (fun name -> Filename.check_suffix (String.uppercase_ascii name) ".PLM" && String.uppercase_ascii (Filename.remove_extension name) = String.uppercase_ascii basename) files with
        | Some name -> Filename.concat directory name
        | None -> fail "manifest source missing and guest PLM file not found"
      in
      let channel = open_in_bin source_file in
      Fun.protect ~finally:(fun () -> close_in channel) (fun () -> really_input_string channel (in_channel_length channel))

let first_object_member root names =
  let rec loop = function
    | [] -> fail ("manifest has none of the expected fields: " ^ String.concat ", " names)
    | key :: rest -> (match object_member root key with Some value -> value | None -> loop rest)
  in
  loop names

let load directory =
  try
    let path = Filename.concat directory "manifest.json" in
    let channel = open_in_bin path in
    let manifest = Fun.protect ~finally:(fun () -> close_in channel) (fun () -> really_input_string channel (in_channel_length channel)) in
    let id = match optional_string manifest "experiment_id" with Some id -> id | None -> Filename.basename (Filename.dirname (Filename.concat directory "x")) in
    let toolchain = required_member manifest "toolchain" in
    let toolchain_fields =
      [ "simulator", "simulator"; "operating_system", "operating_system";
        "compiler", "compiler_reported"; "linker", "linker"; "locator", "locator" ]
      |> List.filter_map (fun (label, key) -> Option.map (fun value -> (label, value)) (optional_string toolchain key))
    in
    let toolchain_version =
      match first_string toolchain [ "compiler_reported"; "compiler_console_banner" ] with
      | Some version -> version
      | None -> fail "manifest has no compiler version"
    in
    let source = source_from_manifest manifest directory in
    let code_object = first_object_member manifest [ "observed_code"; "observed_code_range" ] in
    let code_start = required_string code_object "start" in
    let code_end_inclusive = required_string code_object "end_inclusive" in
    let declared_code_bytes = int_value (required_member code_object "bytes") in
    let code_bytes = hex_bytes (required_string code_object "hex") in
    if Bytes.length code_bytes <> declared_code_bytes then fail "manifest code byte count does not match code hex";
    let sizes = object_member manifest "sizes" in
    let metric name fallback =
      match sizes with
      | Some sizes -> int_value (required_member sizes name)
      | None -> int_value (required_member (required_member manifest "compiler_result") fallback)
    in
    let code_size = metric "code" "code_bytes" in
    if code_size <> declared_code_bytes then fail "CODE size disagrees with located code byte count";
    let variable_size = metric "variable" "variable_bytes" in
    let maximum_stack = metric "maximum_stack" "maximum_stack_bytes" in
    let data_range =
      match optional_string code_object "data_range" with
      | Some range -> Some range
      | None -> optional_string code_object "variable_area"
    in
    let expectation = optional_nested_string manifest [ "documented_expectation" ] "expected_for_this_signature" in
    let observations =
      match object_member manifest "observations" with
      | Some raw -> array_strings raw
      | None -> (match object_member manifest "direct_observations" with Some raw -> array_strings raw | None -> [])
    in
    let comparison =
      match object_member manifest "comparison" with
      | None -> []
      | Some raw -> object_members raw |> List.filter_map (fun (key, value) ->
          if String.starts_with ~prefix:"\"" (String.trim value) then Some (key, string_value value) else None)
    in
    let unresolved_questions = Option.fold ~none:[] ~some:array_strings (object_member manifest "unresolved_questions") in
    let question = optional_string manifest "question" in
    let code_start_int = parse_address code_start in
    let code_size = Bytes.length code_bytes in
    let disassembly = disassemble code_bytes code_start_int in
    Ok { id; question; toolchain = toolchain_fields; toolchain_version; source; code_size; variable_size; maximum_stack; code_start; code_end_inclusive; data_range; code_bytes; disassembly; documented_expectation = expectation; observations; comparison; unresolved_questions }
  with
  | Invalid_manifest message -> Error message
  | Sys_error message -> Error message
  | Failure message -> Error message

let source_for_display source =
  let buffer = Buffer.create (String.length source) in
  let rec loop index =
    if index < String.length source then
      if source.[index] = '\r' && index + 1 < String.length source && source.[index + 1] = '\n' then loop (index + 1)
      else (Buffer.add_char buffer source.[index]; loop (index + 1))
  in
  loop 0;
  Buffer.contents buffer

let to_text fixture =
  let result = Buffer.create 4096 in
  let add = Buffer.add_string result in
  Printf.bprintf result "PL/M-80 oracle fixture: %s\nToolchain: %s\nCODE: %d bytes  VARIABLE: %d bytes  maximum STACK: %d bytes\n"
    fixture.id fixture.toolchain_version fixture.code_size fixture.variable_size fixture.maximum_stack;
  Option.iter (fun question -> Printf.bprintf result "Question: %s\n" question) fixture.question;
  List.iter (fun (label, value) -> Printf.bprintf result "  %s: %s\n" label value) fixture.toolchain;
  Printf.bprintf result "Located CODE: %s..%s (inclusive)\n" fixture.code_start fixture.code_end_inclusive;
  Option.iter (fun range -> Printf.bprintf result "Located DATA: %s\n" range) fixture.data_range;
  add "\nSource (CRLF displayed as LF):\n```plm\n";
  add (source_for_display fixture.source);
  if not (String.ends_with ~suffix:"\n" fixture.source) then add "\n";
  add "```\n\nExact code bytes:\n";
  add (format_bytes fixture.code_bytes);
  add "\n\n8080 disassembly (decoded from manifest bytes):\n";
  List.iter
    (fun instruction ->
      Printf.bprintf result "%04X  %-8s %s\n" instruction.address (format_bytes instruction.bytes) instruction.mnemonic)
    fixture.disassembly;
  Option.iter (fun expectation -> Printf.bprintf result "\nDocumented expectation (not an inferred ABI rule): %s\n" expectation) fixture.documented_expectation;
  if fixture.observations <> [] then (
    add "\nPreserved manifest observations:\n";
    List.iter (fun observation -> Printf.bprintf result "- %s\n" observation) fixture.observations);
  if fixture.unresolved_questions <> [] then (
    add "\nUnresolved questions recorded in the manifest:\n";
    List.iter (fun question -> Printf.bprintf result "- %s\n" question) fixture.unresolved_questions);
  Buffer.contents result

let signed_delta value = if value >= 0 then Printf.sprintf "+%d" value else string_of_int value

type instruction_alignment =
  | Aligned of instruction * instruction
  | Removed of instruction
  | Added of instruction

let opcode instruction = Char.code (Bytes.get instruction.bytes 0)

let align_instructions left right =
  let left = Array.of_list left and right = Array.of_list right in
  let n = Array.length left and m = Array.length right in
  let lcs = Array.make_matrix (n + 1) (m + 1) 0 in
  for i = n - 1 downto 0 do
    for j = m - 1 downto 0 do
      lcs.(i).(j) <-
        if opcode left.(i) = opcode right.(j) then 1 + lcs.(i + 1).(j + 1)
        else max lcs.(i + 1).(j) lcs.(i).(j + 1)
    done
  done;
  let aligned = ref [] and gap_left = ref [] and gap_right = ref [] in
  let emit row = aligned := row :: !aligned in
  let flush_gaps () =
    let a = List.rev !gap_left and b = List.rev !gap_right in
    gap_left := [];
    gap_right := [];
    let rec pair a b =
      match a, b with
      | left :: a, right :: b -> emit (Aligned (left, right)); pair a b
      | left :: a, [] -> emit (Removed left); pair a []
      | [], right :: b -> emit (Added right); pair [] b
      | [], [] -> ()
    in
    pair a b
  in
  let i = ref 0 and j = ref 0 in
  while !i < n || !j < m do
    if !i < n && !j < m && opcode left.(!i) = opcode right.(!j)
       && lcs.(!i).(!j) = 1 + lcs.(!i + 1).(!j + 1) then (
      flush_gaps ();
      emit (Aligned (left.(!i), right.(!j)));
      incr i;
      incr j)
    else if !i < n && (!j = m || lcs.(!i + 1).(!j) > lcs.(!i).(!j + 1)) then (
      gap_left := left.(!i) :: !gap_left;
      incr i)
    else (
      gap_right := right.(!j) :: !gap_right;
      incr j)
  done;
  flush_gaps ();
  List.rev !aligned

let instruction_text instruction =
  Printf.sprintf "%04X  %-8s %s" instruction.address (format_bytes instruction.bytes) instruction.mnemonic

let format_instruction_alignment left right =
  let rows = align_instructions left right in
  if rows = [] then "  (no instructions)\n"
  else
    let result = Buffer.create (List.length rows * 64) in
    List.iter
      (function
        | Aligned (a, b) ->
            let marker = if Bytes.equal a.bytes b.bytes && a.mnemonic = b.mnemonic then '=' else '~' in
            Printf.bprintf result "%c A %-30s | B %s\n" marker (instruction_text a) (instruction_text b)
        | Removed instruction -> Printf.bprintf result "- A %s\n" (instruction_text instruction)
        | Added instruction -> Printf.bprintf result "+ B %s\n" (instruction_text instruction))
      rows;
    Buffer.contents result

let brief_question text =
  let limit = 112 in
  if String.length text <= limit then text else String.sub text 0 limit ^ "..."

let compare_to_text ?(full_evidence = false) left right =
  let result = Buffer.create 4096 in
  let add = Buffer.add_string result in
  let line label value = Printf.bprintf result "%s: %s\n" label value in
  add "PL/M-80 oracle fixture comparison (recorded evidence only)\n";
  line "A" left.id;
  line "B" right.id;
  Option.iter (line "A question") left.question;
  Option.iter (line "B question") right.question;
  if left.toolchain = right.toolchain then (
    add "Common toolchain:\n";
    List.iter (fun (label, value) -> Printf.bprintf result "  %s: %s\n" label value) left.toolchain)
  else (
    List.iter (fun (label, value) -> Printf.bprintf result "A toolchain %s: %s\n" label value) left.toolchain;
    List.iter (fun (label, value) -> Printf.bprintf result "B toolchain %s: %s\n" label value) right.toolchain);
  Printf.bprintf result "Sizes (B - A): CODE %d -> %d (%s), VARIABLE %d -> %d (%s), maximum STACK %d -> %d (%s)\n"
    left.code_size right.code_size (signed_delta (right.code_size - left.code_size))
    left.variable_size right.variable_size (signed_delta (right.variable_size - left.variable_size))
    left.maximum_stack right.maximum_stack (signed_delta (right.maximum_stack - left.maximum_stack));
  Printf.bprintf result "Located CODE: A %s..%s; B %s..%s (inclusive)\n"
    left.code_start left.code_end_inclusive right.code_start right.code_end_inclusive;
  Printf.bprintf result "Located DATA: A %s; B %s\n"
    (Option.value left.data_range ~default:"not recorded") (Option.value right.data_range ~default:"not recorded");
  add "\nInstruction-level disassembly alignment (keyed by opcode; operands and addresses remain exact):\n";
  add "  = same instruction encoding/text; ~ aligned instructions differ; - only in A; + only in B\n";
  add (format_instruction_alignment left.disassembly right.disassembly);
  if full_evidence then (
    List.iter
      (fun (label, fixture) ->
        Printf.bprintf result "\n%s source (CRLF displayed as LF):\n```plm\n%s" label (source_for_display fixture.source);
        if not (String.ends_with ~suffix:"\n" fixture.source) then add "\n";
        add "```\n")
      [ "A", left; "B", right ];
    Printf.bprintf result "\nA exact code (%d bytes):\n%s\n" left.code_size (format_bytes left.code_bytes);
    Printf.bprintf result "B exact code (%d bytes):\n%s\n" right.code_size (format_bytes right.code_bytes);
    add "\nPreserved manifest evidence:\n";
    List.iter
      (fun (label, fixture) ->
        Option.iter (fun expectation -> Printf.bprintf result "\n%s documented expectation: %s\n" label expectation) fixture.documented_expectation;
        if fixture.observations <> [] then (
          Printf.bprintf result "\n%s manifest observations:\n" label;
          List.iter (fun observation -> Printf.bprintf result "- %s\n" observation) fixture.observations);
        if fixture.comparison <> [] then (
          Printf.bprintf result "\n%s preserved manifest comparison fields:\n" label;
          List.iter (fun (key, value) -> Printf.bprintf result "- %s: %s\n" key value) fixture.comparison);
        if fixture.unresolved_questions <> [] then (
          Printf.bprintf result "\n%s unresolved questions:\n" label;
          List.iter (fun question -> Printf.bprintf result "- %s\n" question) fixture.unresolved_questions))
      [ "A", left; "B", right ])
  else (
    add "\nUnresolved questions (brief recorded excerpts):\n";
    List.iter
      (fun (label, fixture) ->
        Printf.bprintf result "%s: %d recorded\n" label (List.length fixture.unresolved_questions);
        List.iter (fun question -> Printf.bprintf result "  - %s\n" (brief_question question)) fixture.unresolved_questions)
      [ "A", left; "B", right ];
    add "Use --full-evidence for verbatim source, complete byte dumps, and manifest text.\n");
  add "\nAlignment uses decoded opcode identity; all displayed addresses, bytes, and operands remain fixture-exact. No PL/M ABI semantics are inferred.\n";
  Buffer.contents result
