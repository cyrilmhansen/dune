[@@@warning "-40-41-42"]

module Map = Analysis.Execution_map
module Report = Analysis.Execution_report

let get = function Ok value -> value | Error _ -> failwith "unexpected result error"

let image filename =
  Map.image_id ~drive:0 ~user:0 ~filename |> get

let observe_nop map memory address count step_index =
  let state = I8080.State.create () in
  let cpu = I8080.Cpu.create ~state ~bus:(I8080.Bus.create memory) in
  for index = 0 to count - 1 do
    I8080.State.set_pc state address;
    let step = I8080.Cpu.step cpu |> get in
    assert (Map.observe_step map ~step_index:(step_index + index) step = Ok ());
  done

let contains text fragment =
  let rec search start =
    start + String.length fragment <= String.length text
    && (String.sub text start (String.length fragment) = fragment || search (start + 1))
  in
  search 0

let test_heat () =
  assert (Report.heat_value ~maximum:0 0 = 0.);
  assert (Report.heat_value ~maximum:10 0 = 0.);
  let expected = log 2. /. log 11. in
  assert (abs_float (Report.heat_value ~maximum:10 1 -. expected) < 1e-12);
  assert (Report.heat_value ~maximum:10 10 = 1.);
  assert (Report.heat_value ~maximum:10 100 = 1.)

let test_order_coverage_json_html () =
  let map = Map.create () in
  let first = image "<A>.COM" and second = image "OVERLAY.BIN" and empty = image "EMPTY.BIN" in
  let memory = I8080.Memory.create () in
  let bytes_a = Bytes.of_string "\x00\x00" in
  let bytes_b = Bytes.of_string "\x00" in
  I8080.Memory.load memory ~address:0x2200 bytes_a;
  assert (Map.seed_image map ~image:first ~runtime_base:0x2200 bytes_a = Ok ());
  observe_nop map memory 0x2200 2 0;
  (* Replacing the same runtime byte must produce a distinct linear image. *)
  I8080.Memory.load memory ~address:0x2200 bytes_b;
  assert (Map.seed_image map ~image:second ~runtime_base:0x2200 bytes_b = Ok ());
  observe_nop map memory 0x2200 1 2;
  assert (Map.seed_image map ~image:empty ~runtime_base:0x3000 Bytes.empty = Ok ());
  let report = Report.report_of_map map ~images:[ second; first; empty ] |> get in
  assert (Report.virtual_span report = 3);
  (match Report.images report with
  | [ b; a; z ] ->
      assert (b.id = second && b.virtual_base = 0 && b.span = 1);
      assert (a.id = first && a.virtual_base = 1 && a.span = 2);
      assert (z.id = empty && z.virtual_base = 3 && z.span = 0);
      assert (a.unique_fetched_byte_count = 1);
      assert (a.dynamic_fetched_byte_count = 2);
      assert (a.unique_fetched_percentage = 50.);
      assert (a.bytes.(0).instruction_start_count = 2);
      assert (a.bytes.(0).fetched && a.bytes.(0).value = Some 0);
      assert (a.bytes.(1).instruction_start_count = 0 && not a.bytes.(1).fetched);
      assert (b.unique_fetched_byte_count = 1 && b.dynamic_fetched_byte_count = 1);
      assert (z.unique_fetched_percentage = 0.)
  | _ -> failwith "image order was not preserved");
  let json = Report.to_json_string report in
  assert (String.starts_with ~prefix:"{\"schema\":\"RUNES_EXECUTION_MAP_REPORT 1\"" json);
  assert (json = Report.to_json_string report);
  assert (not (contains json "<"));
  let html = Report.to_html_string report in
  assert (contains html "&lt;A&gt;.COM");
  assert (contains json "virtual_base");
  assert (not (contains json "NaN"));
  assert (contains html "canvas")

let test_dynamic_edges_export () =
  let map = Map.create () in
  let source = image "CALLER.COM" and target = image "OVERLAY.BIN" in
  let source_bytes = Bytes.of_string "\xc3\x00\x22" in
  let target_bytes = Bytes.of_string "\x00" in
  let memory = I8080.Memory.create () in
  I8080.Memory.load memory ~address:0x0100 source_bytes;
  I8080.Memory.load memory ~address:0x2200 target_bytes;
  assert (Map.seed_image map ~image:source ~runtime_base:0x0100 source_bytes = Ok ());
  assert (Map.seed_image map ~image:target ~runtime_base:0x2200 target_bytes = Ok ());
  let state = I8080.State.create () in
  I8080.State.set_pc state 0x0100;
  let cpu = I8080.Cpu.create ~state ~bus:(I8080.Bus.create memory) in
  let step = I8080.Cpu.step cpu |> get in
  assert (Map.observe_step map ~step_index:0 step = Ok ());
  let report = Report.report_of_map map ~images:[ source; target ] |> get in
  (match Report.dynamic_edges report with
  | [ edge ] ->
      assert (edge.source_image = Some source && edge.source_offset = Some 0);
      assert (edge.target_image = Some target && edge.target_offset = Some 0);
      assert (edge.source_virtual_offset = Some 0 && edge.target_virtual_offset = Some 3);
      assert (edge.runtime_target = Some 0x2200 && edge.count = 1)
  | _ -> failwith "all dynamic edges should be retained in machine output");
  assert (contains (Report.to_json_string report) "dynamic_edges")

let test_record_read_timeline () =
  let map = Map.create () in
  let id = image "LOAD.BIN" in
  let data = Bytes.make 128 '\x00' in
  Map.observe_bdos_event ~step_index:12 map
    (Cpm.Bdos.Read_record { file = id; logical_record = 0; dma = 0x4000; data });
  Map.observe_bdos_event ~step_index:31 map
    (Cpm.Bdos.Read_record { file = id; logical_record = 1; dma = 0x4000; data });
  let report = Report.report_of_map map ~images:[ id ] |> get in
  match Report.images report with
  | [ image ] ->
      assert (image.first_record_read_step = Some 12);
      assert (image.last_record_read_step = Some 31);
      assert (image.span = 256)
  | _ -> failwith "expected one record-observed image"

let () =
  test_heat ();
  test_order_coverage_json_html ();
  test_dynamic_edges_export ();
  test_record_read_timeline ()
