[@@@warning "-4-40-41-42"]

let expect_bytes expected actual = assert(Bytes.to_string actual=expected)

let test_module_names () =
  assert(Pli80.Experiment.derive_module_name "FIZZBUZ.PLI"=Ok"FIZZBUZ");
  assert(Pli80.Experiment.derive_module_name "/some/path/fizzbuz.pli"=Ok"FIZZBUZ");
  assert(match Pli80.Experiment.derive_module_name "TOO-LONG-NAME.PLI" with Error _->true|_->false);
  assert(match Pli80.Experiment.validate_module_name "BAD.NAME" with Error _->true|_->false);
  assert(match Pli80.Experiment.validate_module_name "A/B" with Error _->true|_->false);
  assert(Pli80.Experiment.validate_module_name "a_2"=Ok"A_2");
  assert(Pli80.Experiment.output_names "fizzbuz"=Ok("FIZZBUZ.REL","FIZZBUZ.INT"))

let test_source_normalization () =
  expect_bytes "a\r\nb\r\nc\r\n\026" (Pli80.Experiment.normalize_cpm_source(Bytes.of_string"a\nb\r\nc\n"));
  expect_bytes "a\r\nb\r\n\026" (Pli80.Experiment.normalize_cpm_source(Bytes.of_string"a\r\nb\r\n\026\026"));
  expect_bytes "\026" (Pli80.Experiment.normalize_cpm_source Bytes.empty)
  ;
  let raw=Bytes.of_string"x\ny\026\026" in
  expect_bytes (Bytes.to_string raw) (Pli80.Experiment.prepare_source ~normalize:false raw)

let test_sha256 () =
  assert(Pli80.Experiment.sha256_hex(Bytes.of_string"abc")=
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

let test_offsets_and_selection () =
  assert(Pli80.Experiment.parse_offset "0"=Ok 0);
  assert(Pli80.Experiment.parse_offset "0x2c0"=Ok 0x2c0);
  assert(Pli80.Experiment.parse_offset "2C0h"=Ok 0x2c0);
  assert(match Pli80.Experiment.parse_offset "-1" with Error _->true|_->false);
  assert(Pli80.Experiment.select_rel_offsets 0=Ok[]);
  assert(Pli80.Experiment.select_rel_offsets 1=Ok[0]);
  assert(Pli80.Experiment.select_rel_offsets 2=Ok[0;1]);
  assert(Pli80.Experiment.select_rel_offsets 10=Ok[0;5;9]);
  assert(Pli80.Experiment.select_rel_offsets ~requested:[2;2;8] 10=Ok[2;8]);
  assert(match Pli80.Experiment.select_rel_offsets ~requested:[10] 10 with Error _->true|_->false)

let test_cli_options () =
  let module O=Pli80.Analyze_options in
  (match O.parse[] with Ok options->
    assert(options.max_steps=10_000_000 && options.analysis=Pli80.Experiment.Run);
    assert(options.report=Pli80.Experiment.Summary && options.source_text=O.Cpm)
   |Error _->assert false);
  (match O.parse["--analysis";"path";"--report";"explorer";"--source-text";"raw";
      "--select-rel";"0x20";"--select-rel";"44";"--raw-slice";"0x2c0";"--raw-slice";"704";"--max-steps";"42"] with
   |Ok options->assert(options.analysis=Pli80.Experiment.Path && options.report=Pli80.Experiment.Explorer);
     assert(options.source_text=O.Raw && options.selected_rel=[0x20;44] && options.raw_slices=[0x2c0] && options.max_steps=42)
   |Error _->assert false);
  List.iter(fun args->assert(match O.parse args with Error _->true|_->false))
    [["--max-steps";"0"];["--max-steps";"-1"];["--max-steps";"abc"];
     ["--source"];["--report";"wat"];["--analysis";"symbolic"]];
  assert(match O.parse["--source";"x";"--source";"y"] with Error _->true|_->false)

let () = test_module_names(); test_source_normalization(); test_sha256(); test_offsets_and_selection(); test_cli_options()
