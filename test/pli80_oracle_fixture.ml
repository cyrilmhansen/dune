[@@@warning "-40-42"]

let fixture path =
  match Pli80.Oracle_fixture.load path with
  | Ok fixture -> fixture
  | Error message -> failwith message

let fixture_path name =
  let path = "research/plm80-oracle/" ^ name in
  let candidates = [ "../" ^ path; path ] in
  match List.find_opt Sys.file_exists candidates with Some found -> found | None -> failwith ("fixture not found: " ^ path)

let contains text needle =
  let rec loop offset =
    offset + String.length needle <= String.length text
    && (String.sub text offset (String.length needle) = needle || loop (offset + 1))
  in
  loop 0

let test_four_byte_fixture () =
  let report = fixture (fixture_path "v4-four-byte-parameters") in
  assert (report.id = "v4-four-byte-parameters");
  assert (report.question <> None);
  assert (report.toolchain_version = "ISIS-II PL/M-80 Compiler V4.0");
  assert (List.mem ("operating_system", "ISIS-II V4.3") report.toolchain);
  assert (report.code_size = 33 && report.variable_size = 4 && report.maximum_stack = 6);
  assert (report.code_start = "0x3680" && report.code_end_inclusive = "0x36A0");
  assert (report.data_range = Some "0x36B3-0x36B6");
  assert (Bytes.length report.code_bytes = 33);
  assert (List.length report.disassembly = 23);
  assert (((List.hd report.disassembly : Pli80.Oracle_fixture.instruction).mnemonic = "LXI SP,36B3H"));
  assert (List.exists (fun (instruction : Pli80.Oracle_fixture.instruction) -> instruction.mnemonic = "PUSH B") report.disassembly);
  assert (List.length report.observations > 0);
  assert (List.length report.unresolved_questions > 0);
  let text = Pli80.Oracle_fixture.to_text report in
  assert (contains text "Observed caller order");
  assert (contains text "36A0  C9       RET")

let test_address_return_fixture () =
  let report = fixture (fixture_path "v4-address-return") in
  assert (report.id = "v4-address-return");
  assert (report.question <> None);
  assert (report.code_size = 15 && report.variable_size = 3 && report.maximum_stack = 2);
  assert (report.code_start = "0x3680" && report.code_end_inclusive = "0x368E");
  assert (report.data_range = Some "0x369D-0x369F");
  assert (Bytes.length report.code_bytes = 15);
  assert (List.exists (fun (instruction : Pli80.Oracle_fixture.instruction) -> instruction.mnemonic = "SHLD 369EH") report.disassembly);
  assert (List.exists (fun (instruction : Pli80.Oracle_fixture.instruction) -> instruction.mnemonic = "RET") report.disassembly);
  assert (report.documented_expectation = None);
  assert (List.length report.observations > 0 && List.length report.unresolved_questions > 0)

let test_comparisons () =
  let load name = fixture (fixture_path name) in
  let three = load "v4-three-byte-parameters" and four = load "v4-four-byte-parameters" in
  let three_four = Pli80.Oracle_fixture.compare_to_text three four in
  assert (contains three_four "v4-three-byte-parameters");
  assert (contains three_four "v4-four-byte-parameters");
  assert (contains three_four "CODE 27 -> 33 (+6)");
  assert (contains three_four "maximum STACK 4 -> 6 (+2)");
  assert (contains three_four "W and X stack-passed");
  assert (contains three_four "Disassembly difference by byte alignment");
  let byte = load "v4-byte-return" and address = load "v4-address-return" in
  let returns = Pli80.Oracle_fixture.compare_to_text byte address in
  assert (contains returns "CODE 14 -> 15 (+1)");
  assert (contains returns "VARIABLE 1 -> 3 (+2)");
  assert (contains returns "low byte first");
  assert (contains returns "does not infer parameter semantics or a generalized ABI")

let () = test_four_byte_fixture (); test_address_return_fixture (); test_comparisons ()
