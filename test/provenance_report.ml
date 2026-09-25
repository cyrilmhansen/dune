[@@@warning "-40-41-42-4"]

module P = Analysis.Provenance
module R = Analysis.Provenance_report

let file name = match Analysis.Execution_map.image_id ~drive:0 ~user:0 ~filename:name with
  | Ok id -> id | Error _ -> failwith "bad test file name"

let snapshot (s : I8080.State.t) =
  let f=I8080.State.flags s in
  { Runner.a=I8080.State.a s; b=I8080.State.b s; c=I8080.State.c s;
    d=I8080.State.d s; e=I8080.State.e s; h=I8080.State.h s;
    l=I8080.State.l s; sp=I8080.State.sp s; pc=I8080.State.pc s;
    sign=I8080.Flags.sign f; zero=I8080.Flags.zero f;
    auxiliary_carry=I8080.Flags.auxiliary_carry f; parity=I8080.Flags.parity f;
    carry=I8080.Flags.carry f }

let test_ranges () =
  let ranges=R.ranges_of_offsets [1;2;3;7;9;10] in
  assert(ranges=[{R.first=1;last=3};{first=7;last=7};{first=9;last=10}])

let test_projection () =
  let prov=P.create() and map=Analysis.Execution_map.create() in
  let memory=I8080.Memory.create() and fs=Cpm.Filesystem.create() in
  let input=Bytes.make 128 '\000' in Bytes.set input 0 '\003';
  assert(Cpm.Filesystem.add_file fs ~name:"INPUT.BIN" input=Ok());
  let runtime=Cpm.Bdos.create ~filesystem:fs in
  let state=I8080.State.create() in
  let call fn de =
    I8080.State.set_c state fn; I8080.State.set_de state de;
    match Cpm.Bdos.dispatch_with_effects ~runtime ~memory ~state ~output:(fun _->())
      ~on_event:(P.observe_bdos_event prov ~step_index:0)
      ~on_effect:(P.observe_bdos_effect prov) with
    | Ok _ -> () | Error _ -> failwith "test BDOS dispatch failed"
  in
  let input_fcb=Cpm.Fcb.at memory ~address:0x3000 in
  Cpm.Fcb.set_drive input_fcb 0;
  String.iteri(fun i c->Cpm.Fcb.set input_fcb ~offset:(i+1)(Char.code c))"INPUT   ";
  String.iteri(fun i c->Cpm.Fcb.set input_fcb ~offset:(i+9)(Char.code c))"BIN";
  call 15 0x3000; call 26 0x4000; call 20 0x3000;
  Cpm.Fcb.set_current_record input_fcb 0;
  call 26 0x4100; call 20 0x3000;
  let program=Bytes.of_string "\x21\x00\x40\x46\x21\x00\x41\x7e\x88\x27\x57\x3e\x00\x0e\x00\x0c\x79\xfe\x02\xc2\x0f\x01\x7a\x81\x32\x00\x50\x76" in
  let image=file "TEST.COM" in
  I8080.Memory.load memory ~address:0x100 program;
  assert(Analysis.Execution_map.seed_image map ~image ~runtime_base:0x100 program=Ok());
  P.seed_image prov ~image ~runtime_base:0x100 program;
  let state=state in I8080.State.set_pc state 0x100; I8080.State.set_sp state 0xfffe;
  P.seed_initial_registers prov (snapshot state);
  let cpu=I8080.Cpu.create ~state ~bus:(I8080.Bus.create memory) in
  for step_index=0 to 20 do
    match I8080.Cpu.step cpu with
    | Error _ -> failwith "test CPU instruction failed"
    | Ok step ->
      P.observe_step ~origin_at:(fun ~pc ~fetched:_ -> if pc=0x10f then Some{P.image=file "UNLISTED.BIN";offset=7;runtime_pc=pc} else match Analysis.Execution_map.origin_at map pc with
        | Analysis.Execution_map.Image_byte {image;offset}->Some{P.image;offset;runtime_pc=pc}|_->None)
        prov ~step_index (snapshot state) step;
      assert(Analysis.Execution_map.observe_step map ~step_index step=Ok())
  done;
  let out_fcb=Cpm.Fcb.at memory ~address:0x3100 in
  Cpm.Fcb.set_drive out_fcb 0;
  String.iteri(fun i c->Cpm.Fcb.set out_fcb ~offset:(i+1)(Char.code c))"OUT     ";
  String.iteri(fun i c->Cpm.Fcb.set out_fcb ~offset:(i+9)(Char.code c))"REL";
  call 22 0x3100; call 26 0x5000; call 21 0x3100;
  Cpm.Fcb.set_current_record out_fcb 0; call 21 0x3100;
  let output_file=match Cpm.Filesystem.key_of_name ~drive:0 ~user:0 ~name:"OUT.REL" with Ok k->k|_->assert false in
  let output_bytes=match Cpm.Filesystem.get_file fs ~name:"OUT.REL" () with Ok(Some b)->b|_->failwith "output not found" in
  let execution=match Analysis.Execution_report.report_of_map map ~images:[image] with Ok r->r|_->failwith "execution report failed" in
  let report=match R.report_of_provenance ~provenance:prov ~execution
    ~classify:(fun _->R.Other "<img src=x onerror=alert(1)>") ~output_file ~output_bytes
    ~selected:[{R.file=output_file;offset=0;generation=None}] () with
    |Ok r->r|Error _->failwith "provenance report failed" in
  let projection=List.hd(R.projections report) in
  let input_group=List.find(fun s->String.ends_with ~suffix:"INPUT.BIN" s.R.identity)projection.sources in
  assert(input_group.leaf_occurrences=2 && input_group.distinct_offsets=[0]);
  assert(projection.roles.value>0 && projection.roles.address>0 && projection.roles.flag>0);
  assert(List.exists(fun p->List.mem "ALU.ADC" p.R.operation_kinds)projection.producers);
  assert(List.exists(fun (p:R.producer)->p.R.image_offset=7 && p.image.name="UNLISTED.BIN" && p.virtual_offset=None && p.producer_steps=2)projection.producers);
  let truncated=match R.report_of_provenance ~preview_nodes:3 ~provenance:prov ~execution
    ~classify:(fun _->R.Program_input) ~output_file ~output_bytes
    ~selected:[{R.file=output_file;offset=0;generation=None}] () with Ok r->List.hd(R.projections r)|_->assert false in
  assert(List.length truncated.preview.nodes<=3 && truncated.preview.omitted_frontier_count>0);
  assert(projection.preview.max_nodes=250 && List.length projection.preview.nodes<=250);
  let json=R.to_json_string report in
  assert(json=R.to_json_string report);
  assert(String.starts_with ~prefix:"RUNES_PROVENANCE_REPORT 1\n{" json);
  assert(String.ends_with ~suffix:"}\n" json);
  assert(List.length(R.output_bytes report)=128);
  assert((List.nth(R.output_bytes report)0).rewrite_count=1);
  assert(List.exists(fun s->s.R.classification=Some(R.Other "<img src=x onerror=alert(1)>"))projection.sources);
  let path_report=match R.path_control_report_of_provenance ~provenance:prov
    ~selected:[{R.file=output_file;offset=0;generation=None}] with
    |Ok x->x|Error _->failwith "path-control report failed" in
  let path=List.hd path_report.paths in
  assert(path.context_depth>0 && path.distinct_branch_locations>0);
  assert(path.additional_context_nodes=path.additional_decision_nodes);
  assert(List.length path.preview.nodes<=120 && path.preview.omitted_frontier_count>=0);
  let control_json=R.control_report_to_json_string path_report in
  assert(control_json=R.control_report_to_json_string path_report);
  assert(String.starts_with ~prefix:"RUNES_PROVENANCE_CONTROL_REPORT 1\n{" control_json);
  Option.iter(fun path->let ch=open_out_bin path in output_string ch json;close_out ch)(Sys.getenv_opt "RUNES_REPORT_TEST_OUT")

let () = test_ranges(); test_projection()
